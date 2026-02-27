package table

import (
	"sort"

	"github.com/pymupdf4llm-c/go/internal/bridge"
	"github.com/pymupdf4llm-c/go/internal/geometry"
)

func detectBorderlessTables(raw *bridge.RawPageData, pageRect geometry.Rect) *TableArray {
	if len(raw.Chars) < 50 {
		Logger.Debug("borderless: insufficient chars", "chars", len(raw.Chars))
		return nil
	}

	avgCharWidth := computeAvgCharWidth(raw.Chars)
	pageArea := pageRect.Width() * pageRect.Height()
	charDensity := float32(len(raw.Chars)) / pageArea
	xTol := geometry.Max32(avgCharWidth*(2.0+charDensity*50.0), 12)
	yTol := geometry.Max32(pageRect.Height()*0.005*(1.0+charDensity*20.0), 3)
	Logger.Debug("borderless: tolerances", "xTol", xTol, "yTol", yTol, "avgCharWidth", avgCharWidth, "charDensity", charDensity)

	if charDensity > 0.008 && len(raw.Edges) < 5 {
		if !hasStructuredDataPattern(raw, pageRect, avgCharWidth) {
			Logger.Debug("borderless: skipping dense text page", "charDensity", charDensity)
			return nil
		}
	}

	// --- Step 2: collect candidate column positions from word-start anchors ---
	xScores := make(map[float32]int)
	wordGap := geometry.Max32(avgCharWidth*1.6, 6)
	for _, line := range raw.Lines {
		if line.CharCount <= 0 {
			continue
		}
		indices := make([]int, 0, line.CharCount)
		for i := 0; i < line.CharCount; i++ {
			idx := line.CharStart + i
			if idx < 0 || idx >= len(raw.Chars) {
				continue
			}
			if raw.Chars[idx].Codepoint == 0 {
				continue
			}
			indices = append(indices, idx)
		}
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
				left := snapToGrid(ch.BBox.X0, xTol)
				xScores[left]++
			}
			if ch.BBox.X1 > prevX1 {
				prevX1 = ch.BBox.X1
			}
		}
	}

	// sort and select columns dynamically based on coverage
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
	sortSlice(colPositions)
	mergeTol := avgCharWidth * 7.0
	colPositions = mergeNearbyPositionsAdaptive(colPositions, mergeTol)
	for len(colPositions) > 10 {
		mergeTol *= 1.35
		colPositions = mergeNearbyPositionsAdaptive(colPositions, mergeTol)
	}

	if len(colPositions) < 2 {
		Logger.Debug("borderless: not enough columns", "found", len(colPositions))
		return nil
	}

	// --- Step 3: cluster characters into rows ---
	type rowCluster struct {
		center float32
		chars  []int
	}
	var rows []rowCluster
	for i, ch := range raw.Chars {
		if ch.Codepoint == 0 {
			continue
		}
		cy := (ch.BBox.Y0 + ch.BBox.Y1) / 2
		found := false
		for ri := range rows {
			if geometry.Abs32(cy-rows[ri].center) <= yTol*1.1 {
				rows[ri].chars = append(rows[ri].chars, i)
				rows[ri].center = (rows[ri].center*float32(len(rows[ri].chars)-1) + cy) / float32(len(rows[ri].chars))
				found = true
				break
			}
		}
		if !found {
			rows = append(rows, rowCluster{center: cy, chars: []int{i}})
		}
	}
	if len(rows) < 2 {
		Logger.Debug("borderless: not enough rows", "found", len(rows))
		return nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].center < rows[j].center })

	// --- Step 4: build cells ---
	type cellKey struct {
		row int
		col int
	}
	cellChars := make(map[cellKey][]int)
	for ri, row := range rows {
		if len(row.chars) == 0 {
			continue
		}
		indices := make([]int, 0, len(row.chars))
		for _, ci := range row.chars {
			if ci < 0 || ci >= len(raw.Chars) || raw.Chars[ci].Codepoint == 0 {
				continue
			}
			indices = append(indices, ci)
		}
		if len(indices) == 0 {
			continue
		}
		sort.Slice(indices, func(i, j int) bool {
			return raw.Chars[indices[i]].BBox.X0 < raw.Chars[indices[j]].BBox.X0
		})
		segmentGap := geometry.Max32(avgCharWidth*1.8, 4.0)
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

	// --- Step 5: assemble tables ---
	var tables TableArray
	currentTable := &Table{}
	prevRow := -100
	for r := 0; r < len(rows); r++ {
		if prevRow >= 0 && r > prevRow+10 {
			if len(currentTable.Rows) >= 2 {
				tables.Tables = append(tables.Tables, *currentTable)
			}
			currentTable = &Table{}
		}
		prevRow = r
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
		if len(rowCells) > 0 {
			currentTable.Rows = append(currentTable.Rows, Row{BBox: rowBBox, Cells: rowCells})
			currentTable.BBox = currentTable.BBox.Union(rowBBox)
		}
	}
	if len(currentTable.Rows) >= 2 {
		tables.Tables = append(tables.Tables, *currentTable)
	}

	filterValid(&tables, pageRect)
	if len(tables.Tables) == 0 {
		Logger.Debug("borderless: no valid tables after filtering")
		return nil
	}

	var finalTables TableArray
	for _, t := range tables.Tables {
		cols := 0
		if len(t.Rows) > 0 {
			cols = len(t.Rows[0].Cells)
		}
		if t.BBox.Height() > pageRect.Height()*0.35 && len(t.Rows) > 6 && cols <= 3 {
			if !hasStrongTabularPattern(&t) {
				Logger.Debug("borderless: rejected full-page text column layout")
				continue
			}
		}
		finalTables.Tables = append(finalTables.Tables, t)
	}
	tables.Tables = finalTables.Tables

	if len(tables.Tables) == 0 {
		Logger.Debug("borderless: no valid tables after strict layout filtering")
		return nil
	}

	Logger.Debug("borderless tables detected", "count", len(tables.Tables))
	return &tables
}

func mergeNearbyPositionsAdaptive(positions []float32, tol float32) []float32 {
	if len(positions) < 2 {
		return positions
	}
	result := []float32{positions[0]}
	for i := 1; i < len(positions); i++ {
		if positions[i]-result[len(result)-1] > tol {
			result = append(result, positions[i])
		}
	}
	return result
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

func hasStrongTabularPattern(t *Table) bool {
	if t == nil || len(t.Rows) < 4 {
		return false
	}
	if hasCompactCodeTablePattern(t) {
		return true
	}
	numericRows := 0
	for _, row := range t.Rows {
		numericCells := 0
		for _, cell := range row.Cells {
			if hasNumericContent(cell.Text) {
				numericCells++
			}
		}
		if numericCells >= 2 {
			numericRows++
		}
	}
	if float32(numericRows)/float32(len(t.Rows)) > 0.5 {
		return true
	}
	return false
}

func hasNumericContent(s string) bool {
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits >= 2 && float32(digits)/float32(len(s)+1) > 0.2
}

func hasStructuredDataPattern(raw *bridge.RawPageData, pageRect geometry.Rect, avgCharWidth float32) bool {
	if len(raw.Lines) < 5 {
		return false
	}
	rowAligned := 0
	yPositions := make(map[float32]int)
	for _, line := range raw.Lines {
		yCenter := (line.BBox.Y0 + line.BBox.Y1) / 2
		key := float32(int(yCenter / 5.0))
		yPositions[key]++
	}
	for _, count := range yPositions {
		if count >= 2 {
			rowAligned++
		}
	}
	if rowAligned >= 3 {
		return true
	}
	xPositions := make(map[float32]int)
	for _, ch := range raw.Chars {
		if ch.Codepoint == 0 {
			continue
		}
		xLeft := float32(int(ch.BBox.X0 / avgCharWidth))
		xPositions[xLeft]++
	}
	significantCols := 0
	for _, count := range xPositions {
		if count >= 5 {
			significantCols++
		}
	}
	if significantCols >= 3 {
		return true
	}
	return false
}
