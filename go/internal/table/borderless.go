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
	xTol := geometry.Max32(avgCharWidth*(2+charDensity*50), 12)
	yTol := geometry.Max32(pageRect.Height()*0.005*(1+charDensity*20), 3)
	wordGap := geometry.Max32(avgCharWidth*1.6, 6)

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
	yCluster := newCluster1D(yTol * 1.1)
	for i, ch := range raw.Chars {
		cy := (ch.BBox.Y0 + ch.BBox.Y1) / 2
		idx := yCluster.add(cy)
		if idx >= len(rows) {
			rows = append(rows, rowCluster{center: yCluster.centers[idx], chars: make([]int, 0, 20)})
		}
		rows[idx].chars = append(rows[idx].chars, i)
		rows[idx].center = yCluster.centers[idx]
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
		sort.Slice(idxs, func(i, j int) bool {
			return raw.Chars[idxs[i]].BBox.X0 < raw.Chars[idxs[j]].BBox.X0
		})
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

	midCluster := newCluster1D(xTol * 2)
	clusterWidths := make(map[int][]float32)
	for _, g := range allGaps {
		idx := midCluster.add(g.mid)
		clusterWidths[idx] = append(clusterWidths[idx], g.width)
	}

	const minBandFraction = 0.12
	nRowsF := float32(len(rows))

	var bands []float32
	for idx, widths := range clusterWidths {
		if idx >= len(midCluster.centers) {
			continue
		}
		rowFrac := float32(len(widths)) / nRowsF
		if rowFrac < minBandFraction && len(widths) < 4 {
			continue
		}
		bands = append(bands, midCluster.centers[idx])
	}
	if len(bands) == 0 {
		Logger.Debug("borderless: no consistent whitespace bands")
		return nil
	}
	sort.Slice(bands, func(i, j int) bool { return bands[i] < bands[j] })
	Logger.Debug("borderless: whitespace bands", "count", len(bands))

	dividers := make([]float32, 0, len(bands)+2)
	dividers = append(dividers, pageRect.X0)
	for _, center := range bands {
		dividers = append(dividers, center)
	}
	dividers = append(dividers, pageRect.X1)

	minColWidth := avgCharWidth * 3.8
	dividers = blMergeNarrowColumns(dividers, minColWidth)
	for len(dividers)-1 > 16 {
		minColWidth *= 1.35
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
	segmentGap := geometry.Max32(avgCharWidth*1.8, 4)

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

	occupiedColumns := make([]int, len(rows))
	tableRows := make([]bool, len(rows))
	multiColRows := 0
	for ri := range rows {
		for c := 0; c < nCols; c++ {
			if _, ok := cellChars[cellKey{row: ri, col: c}]; ok {
				occupiedColumns[ri]++
			}
		}
		if occupiedColumns[ri] >= 2 {
			tableRows[ri] = true
			multiColRows++
		}
	}
	if multiColRows < 2 {
		Logger.Debug("borderless: rejected — insufficient multi-column rows", "rows", multiColRows)
		return nil
	}
	for left := 0; left < len(tableRows); {
		if !tableRows[left] {
			left++
			continue
		}
		right := left + 1
		for right < len(tableRows) && !tableRows[right] && occupiedColumns[right] > 0 && right-left <= 3 {
			right++
		}
		if right < len(tableRows) && tableRows[right] {
			for row := left + 1; row < right; row++ {
				tableRows[row] = true
			}
		}
		left = right
	}

	var tables []Table
	for start := 0; start < len(tableRows); {
		for start < len(tableRows) && !tableRows[start] {
			start++
		}
		end := start
		for end < len(tableRows) && tableRows[end] {
			end++
		}
		if end-start >= 2 {
			rowsOut := make([]Row, 0, end-start)
			proseRows := 0
			for r := start; r < end; r++ {
				rowCells := make([]Cell, nCols)
				var rowBBox geometry.Rect
				longCell := false
				for c := range rowCells {
					key := cellKey{row: r, col: c}
					if len(cellChars[key]) > 40 {
						longCell = true
					}
					if bbox, ok := cellBBoxes[key]; ok {
						rowCells[c] = Cell{BBox: bbox}
						rowBBox = rowBBox.Union(bbox)
					}
				}
				if longCell {
					proseRows++
				}
				rowsOut = append(rowsOut, Row{BBox: rowBBox, Cells: rowCells})
			}
			if proseRows*2 > len(rowsOut) {
				Logger.Debug("borderless: rejected wrapped prose columns")
			} else if assembled := assembleRows(rowsOut, pageRect); assembled != nil {
				tables = append(tables, assembled.Tables...)
			}
		}
		start = end + 1
	}
	if len(tables) == 0 {
		Logger.Debug("borderless: no assembled tables")
		return nil
	}

	var finalTables TableArray
	for _, t := range tables {
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
	return bestCol
}
