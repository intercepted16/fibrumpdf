package table

import (
	"sort"

	"github.com/fibrumpdf/go/internal/geometry"
	rawdata "github.com/fibrumpdf/go/internal/raw"
)

type cellKey struct{ row, col int }

func detectBorderlessTables(raw *rawdata.PageData, pageRect geometry.Rect) *TableArray {
	if len(raw.Chars) < 50 {
		Logger.Debug("borderless: insufficient chars", "chars", len(raw.Chars))
		return nil
	}

	avgCharWidth := computeAvgCharWidth(raw.Chars)
	pageArea := pageRect.Width() * pageRect.Height()
	charDensity := float32(len(raw.Chars)) / pageArea
	tolCfg := NewDefaultToleranceConfig()

	xTol := ComputeColumnAnchorTolerance(avgCharWidth, charDensity, tolCfg)
	yTol := ComputeRowClusterTolerance(pageRect.Height(), charDensity, tolCfg)
	wordGap := ComputeWordGap(avgCharWidth, tolCfg)

	if charDensity > 0.010 && len(raw.Edges) < 3 {
		Logger.Debug("borderless: skipping dense text page", "charDensity", charDensity)
		return nil
	}

	Logger.Debug("borderless: tolerances",
		"xTol", xTol, "yTol", yTol,
		"avgCharWidth", avgCharWidth, "charDensity", charDensity)

	type rowCluster struct {
		center float32
		chars  []int
	}
	rows := make([]rowCluster, 0, len(raw.Chars)/20)
	rowTol := ComputeRowYTolerance(yTol, 1.1)
	yCluster := NewCluster1D(rowTol)
	for i, ch := range raw.Chars {
		cy := (ch.BBox.Y0 + ch.BBox.Y1) / 2
		idx := yCluster.Add(cy)
		if idx >= len(rows) {
			rows = append(rows, rowCluster{center: yCluster.Centers[idx], chars: make([]int, 0, 20)})
		}
		rows[idx].chars = append(rows[idx].chars, i)
		rows[idx].center = yCluster.Centers[idx]
	}
	if len(rows) < 2 {
		Logger.Debug("borderless: not enough rows", "found", len(rows))
		return nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].center < rows[j].center })

	rowSorted := make([][]int, len(rows))
	for ri := range rows {
		idxs := make([]int, len(rows[ri].chars))
		copy(idxs, rows[ri].chars)
		sorter := charXSorter{indices: idxs, chars: raw.Chars}
		sort.Sort(sorter)
		rowSorted[ri] = idxs
	}

	type interval struct{ x0, x1 float32 }
	rowSegs := make([][]interval, len(rows))

	for ri := range rows {
		idxs := rowSorted[ri]
		if len(idxs) == 0 {
			continue
		}
		cur := interval{x0: raw.Chars[idxs[0]].BBox.X0, x1: raw.Chars[idxs[0]].BBox.X1}
		for _, ci := range idxs[1:] {
			ch := raw.Chars[ci]
			if ch.BBox.X0-cur.x1 > wordGap {
				rowSegs[ri] = append(rowSegs[ri], cur)
				cur = interval{x0: ch.BBox.X0, x1: ch.BBox.X1}
			} else {
				if ch.BBox.X1 > cur.x1 {
					cur.x1 = ch.BBox.X1
				}
			}
		}
		rowSegs[ri] = append(rowSegs[ri], cur)
	}

	type gapInfo struct{ mid, width float32 }
	allGaps := make([]gapInfo, 0, len(rows)*2)
	minGapWidth := avgCharWidth * 1.4
	for _, segs := range rowSegs {
		for i := 1; i < len(segs); i++ {
			w := segs[i].x0 - segs[i-1].x1
			if w >= minGapWidth {
				allGaps = append(allGaps, gapInfo{
					mid:   (segs[i-1].x1 + segs[i].x0) / 2,
					width: w,
				})
			}
		}
	}

	if len(allGaps) == 0 {
		Logger.Debug("borderless: no significant inter-segment gaps")
		return nil
	}

	midCluster := NewCluster1D(xTol * 2)
	type clusterAcc struct{ widths []float32 }
	clusterAccs := map[int]*clusterAcc{}
	for _, g := range allGaps {
		idx := midCluster.Add(g.mid)
		if clusterAccs[idx] == nil {
			clusterAccs[idx] = &clusterAcc{}
		}
		clusterAccs[idx].widths = append(clusterAccs[idx].widths, g.width)
	}

	const minBandFraction = 0.12
	nRowsF := float32(len(rows))

	type wsBand struct {
		center float32
	}
	var bands []wsBand
	for idx, acc := range clusterAccs {
		if idx >= len(midCluster.Centers) {
			continue
		}
		rowFrac := float32(len(acc.widths)) / nRowsF
		if rowFrac < minBandFraction && len(acc.widths) < 4 {
			continue
		}
		bands = append(bands, wsBand{center: midCluster.Centers[idx]})
	}
	if len(bands) == 0 {
		Logger.Debug("borderless: no consistent whitespace bands")
		return nil
	}
	sort.Slice(bands, func(i, j int) bool { return bands[i].center < bands[j].center })
	Logger.Debug("borderless: whitespace bands", "count", len(bands))

	dividers := make([]float32, 0, len(bands)+2)
	dividers = append(dividers, pageRect.X0)
	for _, b := range bands {
		dividers = append(dividers, b.center)
	}
	dividers = append(dividers, pageRect.X1)

	minColWidth := avgCharWidth * tolCfg.ColumnMergeMultiplier
	dividers = blMergeNarrowColumns(dividers, minColWidth)
	for len(dividers)-1 > tolCfg.MaxColumnCount {
		minColWidth *= tolCfg.ColumnMergeGrowthFactor
		dividers = blMergeNarrowColumns(dividers, minColWidth)
	}
	nCols := len(dividers) - 1
	if nCols < 2 {
		Logger.Debug("borderless: not enough columns after merging", "cols", nCols)
		return nil
	}

	colLeftSamples := make([][]float32, nCols)
	for _, segs := range rowSegs {
		for _, seg := range segs {
			col := blDividerCol(seg.x0, dividers)
			if col >= 0 {
				colLeftSamples[col] = append(colLeftSamples[col], seg.x0)
			}
		}
	}
	colPositions := make([]float32, nCols)
	for c := 0; c < nCols; c++ {
		if len(colLeftSamples[c]) == 0 {
			colPositions[c] = (dividers[c] + dividers[c+1]) / 2
			continue
		}
		s := colLeftSamples[c]
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		colPositions[c] = s[len(s)/2]
	}

	cellChars := make(map[cellKey][]int, len(rows)*2)
	segmentGap := ComputeSegmentGap(avgCharWidth, tolCfg)

	for ri := range rows {
		idxs := rowSorted[ri]
		if len(idxs) == 0 {
			continue
		}
		segStart := 0
		prevX1 := raw.Chars[idxs[0]].BBox.X1
		for i := 1; i < len(idxs); i++ {
			ci := idxs[i]
			ch := raw.Chars[ci]
			if ch.BBox.X0-prevX1 > segmentGap {
				seg := idxs[segStart:i]
				if len(seg) > 0 {
					first := raw.Chars[seg[0]]
					last := raw.Chars[seg[len(seg)-1]]
					col := columnForRange(first.BBox.X0, last.BBox.X1, colPositions, pageRect)
					if col >= 0 {
						k := cellKey{row: ri, col: col}
						cellChars[k] = append(cellChars[k], seg...)
					}
				}
				segStart = i
			}
			if ch.BBox.X1 > prevX1 {
				prevX1 = ch.BBox.X1
			}
		}
		seg := idxs[segStart:]
		if len(seg) > 0 {
			first := raw.Chars[seg[0]]
			last := raw.Chars[seg[len(seg)-1]]
			col := columnForRange(first.BBox.X0, last.BBox.X1, colPositions, pageRect)
			if col >= 0 {
				k := cellKey{row: ri, col: col}
				cellChars[k] = append(cellChars[k], seg...)
			}
		}
	}

	cellBBoxes := make(map[cellKey]geometry.Rect, len(cellChars))
	for k, chars := range cellChars {
		if len(chars) == 0 {
			continue
		}
		cellBBoxes[k] = blBBoxOfChars(raw, chars)
	}

	rowUsable := make([]bool, len(rows))
	for i := range rowUsable {
		rowUsable[i] = true
	}
	filteredRows := 0

	multiColRows, totalContentRows, col0OnlyRows := 0, 0, 0
	for ri := range rows {
		occupied, hasCol0 := 0, false
		for c := 0; c < nCols; c++ {
			if _, ok := cellChars[cellKey{row: ri, col: c}]; ok {
				occupied++
				if c == 0 {
					hasCol0 = true
				}
			}
		}
		if occupied == 0 {
			continue
		}
		totalContentRows++
		if occupied >= 2 {
			multiColRows++
		} else {
			if hasCol0 {
				col0OnlyRows++
			}
		}
	}

	if totalContentRows == 0 {
		return nil
	}
	multiColFrac := float32(multiColRows) / float32(totalContentRows)
	Logger.Debug("borderless: fill stats",
		"multiColFrac", multiColFrac,
		"multiColRows", multiColRows, "totalRows", totalContentRows,
		"filteredRows", filteredRows)

	const minMultiColFrac = 0.07
	if multiColFrac < minMultiColFrac && multiColRows < 2 {
		Logger.Debug("borderless: rejected — insufficient multi-column rows", "frac", multiColFrac)
		return nil
	}

	col0Frac := float32(col0OnlyRows) / float32(totalContentRows)
	if col0Frac > 0.80 && multiColFrac < 0.20 {
		Logger.Debug("borderless: rejected — heavily col-0 prose", "col0Frac", col0Frac)
		return nil
	}

	rowsOut := make([]Row, 0, len(rows))
	for r := 0; r < len(rows); r++ {
		if !rowUsable[r] {
			continue
		}
		rowCells := make([]Cell, nCols)
		var rowBBox geometry.Rect
		for c := 0; c < nCols; c++ {
			k := cellKey{row: r, col: c}
			if bbox, ok := cellBBoxes[k]; ok {
				rowCells[c] = Cell{BBox: bbox}
				if rowBBox.IsEmpty() {
					rowBBox = bbox
				} else {
					rowBBox = rowBBox.Union(bbox)
				}
			}
		}
		rowsOut = append(rowsOut, Row{BBox: rowBBox, Cells: rowCells})
	}
	if len(rowsOut) < 2 {
		return nil
	}

	assembler := NewDefaultTableAssembler(NewDefaultTableAssemblyConfig())
	assembled := assembler.AssembleFromRows(rowsOut, pageRect)
	if assembled == nil || len(assembled.Tables) == 0 {
		Logger.Debug("borderless: no assembled tables")
		return nil
	}
	assembled.normalizeColumns(pageRect)

	var finalTables TableArray
	for _, t := range assembled.Tables {
		tCols := 0
		if len(t.Rows) > 0 {
			tCols = len(t.Rows[0].Cells)
		}
		heightFrac := t.BBox.Height() / pageRect.Height()
		widthFrac := t.BBox.Width() / pageRect.Width()

		if heightFrac > 0.35 && len(t.Rows) > 6 && tCols <= 2 {
			Logger.Debug("borderless: rejected tall narrow column layout")
			continue
		}
		fillRatio := blTableFillRatio(t)
		if widthFrac > 0.80 && tCols == 2 && len(t.Rows) > 12 {
			if fillRatio < 0.50 {
				Logger.Debug("borderless: rejected wide 2-col prose layout")
				continue
			}
		}
		if (len(t.Rows) >= 10 && fillRatio < 0.34) || (len(t.Rows) < 10 && fillRatio < 0.25) {
			Logger.Debug("borderless: rejected sparse table",
				"fill", fillRatio)
			continue
		}

		finalTables.Tables = append(finalTables.Tables, t)
	}

	if len(finalTables.Tables) == 0 {
		Logger.Debug("borderless: no valid tables after final validation")
		return nil
	}
	Logger.Debug("borderless tables detected", "count", len(finalTables.Tables))
	return &finalTables
}

type charXSorter struct {
	indices []int
	chars   []rawdata.Char
}

func (s charXSorter) Len() int      { return len(s.indices) }
func (s charXSorter) Swap(i, j int) { s.indices[i], s.indices[j] = s.indices[j], s.indices[i] }
func (s charXSorter) Less(i, j int) bool {
	return s.chars[s.indices[i]].BBox.X0 < s.chars[s.indices[j]].BBox.X0
}

func blBBoxOfChars(raw *rawdata.PageData, charIndices []int) geometry.Rect {
	var bbox geometry.Rect
	for _, ci := range charIndices {
		ch := &raw.Chars[ci]
		r := geometry.Rect{X0: ch.BBox.X0, Y0: ch.BBox.Y0, X1: ch.BBox.X1, Y1: ch.BBox.Y1}
		if bbox.IsEmpty() {
			bbox = r
		} else {
			bbox = bbox.Union(r)
		}
	}
	return bbox
}

func blDividerCol(x float32, dividers []float32) int {
	for i := 0; i < len(dividers)-1; i++ {
		if x >= dividers[i] && x < dividers[i+1] {
			return i
		}
	}
	return -1
}

func blMergeNarrowColumns(dividers []float32, minWidth float32) []float32 {
	if len(dividers) <= 2 {
		return dividers
	}
	out := []float32{dividers[0]}
	for i := 1; i < len(dividers)-1; i++ {
		if dividers[i]-out[len(out)-1] >= minWidth {
			out = append(out, dividers[i])
		}
	}
	out = append(out, dividers[len(dividers)-1])
	return out
}

func blTableFillRatio(t Table) float32 {
	pop, tot := 0, 0
	for _, row := range t.Rows {
		for _, cell := range row.Cells {
			tot++
			if !cell.BBox.IsEmpty() {
				pop++
			}
		}
	}
	if tot == 0 {
		return 0
	}
	return float32(pop) / float32(tot)
}

func columnForRange(x0, x1 float32, colPositions []float32, pageRect geometry.Rect) int {
	if x1 < x0 {
		x0, x1 = x1, x0
	}
	bestCol, bestOverlap := -1, float32(0)
	bestCenterDist := float32(1e9)
	rangeCenter := (x0 + x1) * 0.5

	for i, pos := range colPositions {
		var left, right float32
		if i > 0 {
			left = (colPositions[i-1] + pos) * 0.5
		} else {
			left = pageRect.X0
		}
		if i < len(colPositions)-1 {
			right = (pos + colPositions[i+1]) * 0.5
		} else {
			right = pageRect.X1
		}
		overlap := geometry.Max32(0, geometry.Min32(x1, right)-geometry.Max32(x0, left))
		centerDist := geometry.Abs32(rangeCenter - (left+right)*0.5)
		if overlap > bestOverlap || (overlap == bestOverlap && centerDist < bestCenterDist) {
			bestOverlap, bestCenterDist, bestCol = overlap, centerDist, i
		}
	}
	if bestCol >= 0 {
		return bestCol
	}
	// Fallback: find column for range center
	for i, pos := range colPositions {
		var left, right float32
		if i > 0 {
			left = (colPositions[i-1] + pos) * 0.5
		} else {
			left = pageRect.X0
		}
		if i < len(colPositions)-1 {
			right = (pos + colPositions[i+1]) * 0.5
		} else {
			right = pageRect.X1
		}
		if rangeCenter >= left && rangeCenter < right {
			return i
		}
	}
	return -1
}
