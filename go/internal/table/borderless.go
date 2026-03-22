package table

import (
	"slices"
	"sort"

	"github.com/pymupdf4llm-c/go/internal/geometry"
	rawdata "github.com/pymupdf4llm-c/go/internal/raw"
)

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
	Logger.Debug("borderless: tolerances", "xTol", xTol, "yTol", yTol, "avgCharWidth", avgCharWidth, "charDensity", charDensity)

	if charDensity > 0.008 && len(raw.Edges) < 5 {
		Logger.Debug("borderless: skipping dense text page", "charDensity", charDensity)
		return nil
	}

	xScores := make(map[float32]int)
	wordGap := ComputeWordGap(avgCharWidth, tolCfg)
	for li := range raw.Lines {
		line := &raw.Lines[li]
		if line.CharCount <= 0 {
			continue
		}
		indices := raw.LineCharIndices(line, nil)
		if len(indices) == 0 {
			continue
		}
		sort.Slice(indices, func(i, j int) bool {
			return raw.Chars[indices[i]].BBox.X0 < raw.Chars[indices[j]].BBox.X0
		})
		prevX1 := float32(-1e6)
		for i, idx := range indices {
			ch := raw.Chars[idx]
			if i == 0 || ch.BBox.X0-prevX1 > wordGap {
				left := float32(int(ch.BBox.X0/xTol+0.5)) * xTol
				xScores[left]++
			}
			if ch.BBox.X1 > prevX1 {
				prevX1 = ch.BBox.X1
			}
		}
	}

	type colScore struct {
		pos   float32
		score int
	}
	var candidates []colScore
	for p, s := range xScores {
		candidates = append(candidates, colScore{p, s})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].score > candidates[j].score })

	var colPositions []float32
	totalAnchors := 0
	for _, c := range candidates {
		totalAnchors += c.score
	}
	if totalAnchors == 0 {
		Logger.Debug("borderless: no column anchors")
		return nil
	}
	cumScore := 0
	for _, c := range candidates {
		colPositions = append(colPositions, c.pos)
		cumScore += c.score
		if float32(cumScore)/float32(totalAnchors) >= 0.85 || len(colPositions) >= 14 {
			break
		}
	}
	slices.Sort(colPositions)
	mergeTol := avgCharWidth * tolCfg.ColumnMergeMultiplier
	colPositions = NewCluster1D(mergeTol).MergeSorted(colPositions)
	for len(colPositions) > tolCfg.MaxColumnCount {
		mergeTol *= tolCfg.ColumnMergeGrowthFactor
		colPositions = NewCluster1D(mergeTol).MergeSorted(colPositions)
	}

	if len(colPositions) < 2 {
		Logger.Debug("borderless: not enough columns", "found", len(colPositions))
		return nil
	}

	type rowCluster struct {
		center float32
		chars  []int
	}
	var rows []rowCluster
	rowTol := ComputeRowYTolerance(yTol, 1.1)
	cluster := NewCluster1D(rowTol)
	for i, ch := range raw.Chars {
		cy := (ch.BBox.Y0 + ch.BBox.Y1) / 2
		idx := cluster.Add(cy)
		if idx >= len(rows) {
			rows = append(rows, rowCluster{center: cluster.Centers[idx], chars: []int{i}})
			continue
		}
		rows[idx].chars = append(rows[idx].chars, i)
		rows[idx].center = cluster.Centers[idx]
	}
	if len(rows) < 2 {
		Logger.Debug("borderless: not enough rows", "found", len(rows))
		return nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].center < rows[j].center })

	type cellKey struct {
		row int
		col int
	}
	cellChars := make(map[cellKey][]int)
	for ri, row := range rows {
		if len(row.chars) == 0 {
			continue
		}
		indices := append([]int(nil), row.chars...)
		if len(indices) == 0 {
			continue
		}
		sort.Slice(indices, func(i, j int) bool {
			return raw.Chars[indices[i]].BBox.X0 < raw.Chars[indices[j]].BBox.X0
		})
		segmentGap := ComputeSegmentGap(avgCharWidth, tolCfg)
		segments := make([][]int, 0, len(indices)/3+1)
		curSegment := []int{indices[0]}
		prevIdx := indices[0]
		for i := 1; i < len(indices); i++ {
			idx := indices[i]
			gap := raw.Chars[idx].BBox.X0 - raw.Chars[prevIdx].BBox.X1
			if gap > segmentGap {
				segments = append(segments, curSegment)
				curSegment = []int{idx}
			} else {
				curSegment = append(curSegment, idx)
			}
			prevIdx = idx
		}
		segments = append(segments, curSegment)
		for _, segment := range segments {
			if len(segment) == 0 {
				continue
			}
			first := raw.Chars[segment[0]]
			last := raw.Chars[segment[len(segment)-1]]
			cx := (first.BBox.X0 + last.BBox.X1) * 0.5
			col := columnForX(cx, colPositions, pageRect)
			if col >= 0 {
				cellChars[cellKey{row: ri, col: col}] = append(cellChars[cellKey{row: ri, col: col}], segment...)
			}
		}
	}

	rowsOut := make([]Row, 0, len(rows))
	for r := 0; r < len(rows); r++ {
		var rowCells []Cell
		var rowBBox geometry.Rect
		for c := 0; c < len(colPositions); c++ {
			k := cellKey{row: r, col: c}
			if chars, ok := cellChars[k]; ok && len(chars) > 0 {
				var bbox geometry.Rect
				for _, ci := range chars {
					ch := &raw.Chars[ci]
					r := geometry.Rect{X0: ch.BBox.X0, Y0: ch.BBox.Y0, X1: ch.BBox.X1, Y1: ch.BBox.Y1}
					if bbox.IsEmpty() {
						bbox = r
					} else {
						bbox = bbox.Union(r)
					}
				}
				rowCells = append(rowCells, Cell{BBox: bbox})
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
		Logger.Debug("borderless: no row candidates")
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
		cols := 0
		if len(t.Rows) > 0 {
			cols = len(t.Rows[0].Cells)
		}
		if t.BBox.Height() > pageRect.Height()*0.35 && len(t.Rows) > 6 && cols <= 3 {
			Logger.Debug("borderless: rejected full-page text column layout")
			continue
		}
		finalTables.Tables = append(finalTables.Tables, t)
	}
	assembled.Tables = finalTables.Tables

	if len(assembled.Tables) == 0 {
		Logger.Debug("borderless: no valid tables after strict layout filtering")
		return nil
	}

	Logger.Debug("borderless tables detected", "count", len(assembled.Tables))
	return assembled
}

func columnForX(x float32, colPositions []float32, pageRect geometry.Rect) int {
	for ci := 0; ci < len(colPositions); ci++ {
		left := pageRect.X0
		if ci > 0 {
			left = (colPositions[ci-1] + colPositions[ci]) * 0.5
		}
		right := pageRect.X1
		if ci < len(colPositions)-1 {
			right = (colPositions[ci] + colPositions[ci+1]) * 0.5
		}
		if x >= left && x < right {
			return ci
		}
	}
	return -1
}
