package table

import (
	"math"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pymupdf4llm-c/go/internal/bridge"
	"github.com/pymupdf4llm-c/go/internal/geometry"
	"github.com/pymupdf4llm-c/go/internal/logger"
	"github.com/pymupdf4llm-c/go/internal/models"
	"github.com/tidwall/rtree"
)

var Logger = logger.GetLogger("table")

func coordToInt(x float64) int { return int(x*coordScale + 0.5) }

func hasEdge(edges []Edge, x0, y0, x1, y1, eps float64) bool {
	for _, e := range edges {
		if e.Orientation == 'h' {
			if math.Abs(e.Y0-y0) < eps && math.Abs(e.Y1-y1) < eps &&
				e.X0-eps <= math.Min(x0, x1) && e.X1+eps >= math.Max(x0, x1) {
				return true
			}
		} else {
			if math.Abs(e.X0-x0) < eps && math.Abs(e.X1-x1) < eps &&
				e.Y0-eps <= math.Min(y0, y1) && e.Y1+eps >= math.Max(y0, y1) {
				return true
			}
		}
	}
	return false
}

func findCells(points []geometry.Point, tr *rtree.RTreeG[geometry.Point], pageRect geometry.Rect, hEdges, vEdges []Edge, avgEdgeSpacing float64) []geometry.Rect {
	if len(points) < 4 {
		return nil
	}
	pw, ph := pageRect.Width(), pageRect.Height()
	minSize, maxW, maxH := geometry.Min32(pw, ph)*minCellRatio, pw*maxCellWRatio, ph*maxCellHRatio
	snapDist := pw * snapTolRatio
	eps := avgEdgeSpacing * 0.3
	if eps < 1.0 {
		eps = 1.0
	}
	gridCols, gridRows := findGridLines(hEdges, vEdges, eps, pageRect)
	if len(gridCols) < 2 || len(gridRows) < 2 {
		return nil
	}
	sorted := make([]geometry.Point, len(points))
	copy(sorted, points)
	sort.Slice(sorted, func(i, j int) bool {
		if dy := sorted[i].Y - sorted[j].Y; math.Abs(float64(dy)) > 0.1 {
			return dy < 0
		}
		return sorted[i].X < sorted[j].X
	})
	var snapped []geometry.Point
	for _, p := range sorted {
		merged := false
		for i := range snapped {
			if geometry.Abs32(p.X-snapped[i].X) < snapDist && geometry.Abs32(p.Y-snapped[i].Y) < snapDist {
				snapped[i].X, snapped[i].Y = (snapped[i].X+p.X)/2, (snapped[i].Y+p.Y)/2
				merged = true
				break
			}
		}
		if !merged {
			snapped = append(snapped, p)
		}
	}
	gridPoints := filterPointsToGrid(snapped, gridCols, gridRows, eps)
	var cells []geometry.Rect
	for i, p1 := range gridPoints {
		for j := i + 1; j < len(gridPoints); j++ {
			if float64(gridPoints[j].Y-p1.Y) > eps {
				break
			}
			p2 := gridPoints[j]
			if p2.X <= p1.X+minSize {
				continue
			}
			topEdgeOk := hasEdge(hEdges, float64(p1.X), float64(p1.Y), float64(p2.X), float64(p1.Y), eps)
			for _, p3 := range gridPoints {
				if p3.Y <= p1.Y+minSize || math.Abs(float64(p3.X-p1.X)) > eps {
					continue
				}
				leftEdgeOk := hasEdge(vEdges, float64(p1.X), float64(p1.Y), float64(p1.X), float64(p3.Y), eps)
				found := false
				tr.Search([2]float64{float64(p2.X) - eps, float64(p3.Y) - eps}, [2]float64{float64(p2.X) + eps, float64(p3.Y) + eps}, func(_, _ [2]float64, _ geometry.Point) bool {
					rightEdgeOk := hasEdge(vEdges, float64(p2.X), float64(p2.Y), float64(p2.X), float64(p3.Y), eps)
					bottomEdgeOk := hasEdge(hEdges, float64(p3.X), float64(p3.Y), float64(p2.X), float64(p3.Y), eps)
					edgeCount := 0
					if topEdgeOk {
						edgeCount++
					}
					if leftEdgeOk {
						edgeCount++
					}
					if rightEdgeOk {
						edgeCount++
					}
					if bottomEdgeOk {
						edgeCount++
					}
					if edgeCount >= 2 {
						found = true
						return false
					}
					return true
				})
				if found {
					cell := geometry.Rect{X0: p1.X, Y0: p1.Y, X1: p2.X, Y1: p3.Y}
					if w, h := cell.Width(), cell.Height(); w > minSize && w < maxW && h > minSize && h < maxH {
						cells = append(cells, cell)
					}
				}
			}
		}
	}
	if len(cells) >= 4 {
		return cells
	}
	cells = cells[:0]
	for ri := 0; ri < len(gridRows)-1; ri++ {
		for ci := 0; ci < len(gridCols)-1; ci++ {
			cell := geometry.Rect{X0: gridCols[ci], Y0: gridRows[ri], X1: gridCols[ci+1], Y1: gridRows[ri+1]}
			if w, h := cell.Width(), cell.Height(); w > minSize && w < maxW && h > minSize && h < maxH {
				cells = append(cells, cell)
			}
		}
	}
	return cells
}

func findGridLines(hEdges, vEdges []Edge, eps float64, pageRect geometry.Rect) ([]float32, []float32) {
	xPositions := make(map[float64]int)
	yPositions := make(map[float64]int)
	minVLen := float64(pageRect.Height()) * 0.02
	minHLen := float64(pageRect.Width()) * 0.02
	for _, e := range vEdges {
		edgeLen := math.Abs(e.Y1 - e.Y0)
		if edgeLen < minVLen {
			continue
		}
		key := math.Round(e.X0/eps) * eps
		xPositions[key]++
	}
	for _, e := range hEdges {
		edgeLen := math.Abs(e.X1 - e.X0)
		if edgeLen < minHLen {
			continue
		}
		key := math.Round(e.Y0/eps) * eps
		yPositions[key]++
	}
	minXCount := 1
	minYCount := 1
	var gridCols []float32
	for x, count := range xPositions {
		if count >= minXCount {
			gridCols = append(gridCols, float32(x))
		}
	}
	var gridRows []float32
	for y, count := range yPositions {
		if count >= minYCount {
			gridRows = append(gridRows, float32(y))
		}
	}
	sort.Slice(gridCols, func(i, j int) bool { return gridCols[i] < gridCols[j] })
	sort.Slice(gridRows, func(i, j int) bool { return gridRows[i] < gridRows[j] })
	return gridCols, gridRows
}

func filterPointsToGrid(points []geometry.Point, gridCols, gridRows []float32, eps float64) []geometry.Point {
	var result []geometry.Point
	for _, p := range points {
		onCol := false
		for _, x := range gridCols {
			if math.Abs(float64(p.X-x)) < eps {
				onCol = true
				break
			}
		}
		if !onCol {
			continue
		}
		onRow := false
		for _, y := range gridRows {
			if math.Abs(float64(p.Y-y)) < eps {
				onRow = true
				break
			}
		}
		if onRow {
			result = append(result, p)
		}
	}
	return result
}

func deduplicateCells(cells []geometry.Rect) []geometry.Rect {
	if len(cells) <= 1 {
		return cells
	}
	keep := make([]bool, len(cells))
	for i := range keep {
		keep[i] = true
	}
	for i := 0; i < len(cells); i++ {
		if !keep[i] {
			continue
		}
		areaI := cells[i].Area()
		for j := i + 1; j < len(cells); j++ {
			if !keep[j] {
				continue
			}
			areaJ, inter := cells[j].Area(), cells[i].IntersectArea(cells[j])
			if inter == 0 {
				continue
			}
			if contain := inter / geometry.Min32(areaI, areaJ); contain > 0.9 {
				if areaI >= areaJ {
					keep[i] = false
					break
				}
				keep[j] = false
			} else if iou := inter / (areaI + areaJ - inter); iou > 0.6 {
				if areaI >= areaJ {
					keep[j] = false
				} else {
					keep[i] = false
					break
				}
			}
		}
	}
	result := make([]geometry.Rect, 0, len(cells))
	for i, k := range keep {
		if k {
			result = append(result, cells[i])
		}
	}
	return result
}

func groupCellsIntoTables(cells []geometry.Rect, pageRect geometry.Rect) *TableArray {
	if len(cells) == 0 {
		return nil
	}
	var avgH float32
	for _, c := range cells {
		avgH += c.Height()
	}
	avgH /= float32(len(cells))
	rowGroupTol := adaptiveRowGroupingTolerance(avgH, pageRect)
	splitGap := geometry.Max32(pageRect.Height()*0.03, avgH*2.4)
	if splitGap > pageRect.Height()*splitGapRatio {
		splitGap = pageRect.Height() * splitGapRatio
	}

	rowHeights := make(map[float32][]geometry.Rect)
	rowTol := avgH * 0.3
	for _, c := range cells {
		foundKey := float32(-1)
		for key := range rowHeights {
			if geometry.Abs32(c.Y0-key) < rowTol {
				foundKey = key
				break
			}
		}
		if foundKey >= 0 {
			rowHeights[foundKey] = append(rowHeights[foundKey], c)
		} else {
			rowHeights[c.Y0] = []geometry.Rect{c}
		}
	}

	var rowYPositions []float32
	for y := range rowHeights {
		rowYPositions = append(rowYPositions, y)
	}
	sort.Slice(rowYPositions, func(i, j int) bool { return rowYPositions[i] < rowYPositions[j] })

	var heights []float32
	for _, y := range rowYPositions {
		if len(rowHeights[y]) > 0 {
			h := rowHeights[y][0].Height()
			for _, c := range rowHeights[y][1:] {
				h = geometry.Max32(h, c.Height())
			}
			heights = append(heights, h)
		}
	}
	if len(heights) >= 2 {
		var sumH float32
		for _, h := range heights {
			sumH += h
		}
		avgRowH := sumH / float32(len(heights))
		var filteredCells []geometry.Rect
		for _, y := range rowYPositions {
			rowCells := rowHeights[y]
			var rowH float32
			for _, c := range rowCells {
				rowH = geometry.Max32(rowH, c.Height())
			}
			if avgRowH > 0 && rowH > 0 {
				ratio := rowH / avgRowH
				if ratio < 2.5 && ratio > 0.4 {
					filteredCells = append(filteredCells, rowCells...)
				} else {
					Logger.Debug("filtered row by height consistency", "rowH", rowH, "avgRowH", avgRowH, "ratio", ratio)
				}
			} else {
				filteredCells = append(filteredCells, rowCells...)
			}
		}
		if len(filteredCells) < len(cells)*3/4 {
			cells = filteredCells
		}
	}

	sortTol := avgH * 0.2
	sort.Slice(cells, func(i, j int) bool {
		if dy := cells[i].Y0 - cells[j].Y0; geometry.Abs32(dy) > sortTol {
			return dy < 0
		}
		return cells[i].X0 < cells[j].X0
	})
	tables := &TableArray{}
	var cur *Table
	prevY1 := float32(-1000)
	for i := 0; i < len(cells); {
		rowY0, yTol := cells[i].Y0, rowGroupTol
		j := i + 1
		for j < len(cells) && math.Abs(float64(cells[j].Y0-rowY0)) <= float64(yTol) {
			j++
		}
		gap := rowY0 - prevY1
		if i > 0 {
			if g := rowY0 - cells[i-1].Y1; g > gap {
				gap = g
			}
		}
		if cur == nil || gap > splitGap {
			if cur != nil && len(cur.Rows) >= 2 {
				tableHeight := cur.BBox.Height()
				if tableHeight/pageRect.Height() > 0.9 && len(cur.Rows) > 10 {
					Logger.Debug("rejected overly full-page table", "tableHeight", tableHeight, "pageHeight", pageRect.Height(), "rows", len(cur.Rows))
					tables.Tables = tables.Tables[:len(tables.Tables)-1]
				}
			}
			tables.Tables = append(tables.Tables, Table{})
			cur = &tables.Tables[len(tables.Tables)-1]
			prevY1 = -1000
		}
		rowCells := make([]Cell, j-i)
		for k := 0; k < j-i; k++ {
			rowCells[k].BBox = cells[i+k]
		}
		sort.Slice(rowCells, func(k1, k2 int) bool { return rowCells[k1].BBox.X0 < rowCells[k2].BBox.X0 })
		row := Row{Cells: rowCells, BBox: rowCells[0].BBox}
		for k := 1; k < len(rowCells); k++ {
			row.BBox = row.BBox.Union(rowCells[k].BBox)
		}
		cur.BBox = cur.BBox.Union(row.BBox)
		cur.Rows = append(cur.Rows, row)
		prevY1 = row.BBox.Y1
		i = j
	}
	if cur != nil && len(cur.Rows) >= 2 {
		tableHeight := cur.BBox.Height()
		if tableHeight/pageRect.Height() > 0.9 && len(cur.Rows) > 10 {
			Logger.Debug("rejected overly full-page table (final)", "tableHeight", tableHeight, "pageHeight", pageRect.Height(), "rows", len(cur.Rows))
			tables.Tables = tables.Tables[:len(tables.Tables)-1]
		}
	}
	splitTablesByStructuralSeparators(tables, pageRect)
	normalizeColumns(tables, pageRect)
	filterValid(tables, pageRect)
	if len(tables.Tables) == 0 {
		return nil
	}
	return tables
}

func adaptiveRowGroupingTolerance(avgH float32, pageRect geometry.Rect) float32 {
	base := geometry.Max32(avgH*0.45, pageRect.Height()*0.004)
	minTol := pageRect.Height() * 0.0025
	maxTol := pageRect.Height() * rowYTolRatio
	if base < minTol {
		base = minTol
	}
	if base > maxTol {
		base = maxTol
	}
	return base
}

func splitTablesByStructuralSeparators(tables *TableArray, pageRect geometry.Rect) {
	if tables == nil || len(tables.Tables) == 0 {
		return
	}
	out := make([]Table, 0, len(tables.Tables))
	for _, tbl := range tables.Tables {
		parts := splitTableOnSparseRowRuns(tbl, pageRect)
		out = append(out, parts...)
	}
	tables.Tables = out
}

func splitTableOnSparseRowRuns(tbl Table, pageRect geometry.Rect) []Table {
	if len(tbl.Rows) < 10 {
		return []Table{tbl}
	}
	dominantCols := dominantRowCellCount(tbl.Rows)
	if dominantCols < 4 {
		return []Table{tbl}
	}
	tableWidth := tbl.BBox.Width()
	if tableWidth <= 0 {
		return []Table{tbl}
	}
	gapThreshold := adaptiveIntraTableGapThreshold(tbl.Rows, pageRect)
	start := 0
	var segments []Table
	for i := 2; i < len(tbl.Rows)-2; {
		if !isSparseSeparatorRow(tbl.Rows[i], dominantCols, tableWidth) {
			i++
			continue
		}
		j := i
		for j < len(tbl.Rows)-1 && isSparseSeparatorRow(tbl.Rows[j], dominantCols, tableWidth) {
			j++
		}
		leftStart := i - 4
		if leftStart < start {
			leftStart = start
		}
		rightEnd := j + 4
		if rightEnd > len(tbl.Rows) {
			rightEnd = len(tbl.Rows)
		}
		leftDense := denseRowRatio(tbl.Rows[leftStart:i], dominantCols) >= 0.55
		rightDense := denseRowRatio(tbl.Rows[j:rightEnd], dominantCols) >= 0.55
		gapBefore := float32(0)
		if i > 0 {
			gapBefore = tbl.Rows[i].BBox.Y0 - tbl.Rows[i-1].BBox.Y1
		}
		gapAfter := float32(0)
		if j < len(tbl.Rows) {
			gapAfter = tbl.Rows[j].BBox.Y0 - tbl.Rows[j-1].BBox.Y1
		}
		gapAround := geometry.Max32(gapBefore, gapAfter)
		separatorRun := j - i
		if leftDense && rightDense && (separatorRun >= 2 || gapAround >= gapThreshold) {
			if i-start >= 2 {
				rows := append([]Row(nil), tbl.Rows[start:i]...)
				segments = append(segments, Table{Rows: rows, BBox: tableBBoxFromRowsForTrim(rows)})
			}
			start = j
			i = j + 1
			continue
		}
		i = j + 1
	}
	if len(tbl.Rows)-start >= 2 {
		rows := append([]Row(nil), tbl.Rows[start:]...)
		segments = append(segments, Table{Rows: rows, BBox: tableBBoxFromRowsForTrim(rows)})
	}
	if len(segments) <= 1 {
		return []Table{tbl}
	}
	Logger.Debug("split table on sparse separator rows", "parts", len(segments), "rows", len(tbl.Rows), "dominantCols", dominantCols)
	return segments
}

func dominantRowCellCount(rows []Row) int {
	counts := make(map[int]int)
	bestCols := 0
	bestCount := 0
	for _, row := range rows {
		cols := len(row.Cells)
		if cols <= 0 {
			continue
		}
		counts[cols]++
		if counts[cols] > bestCount {
			bestCount = counts[cols]
			bestCols = cols
		}
	}
	return bestCols
}

func adaptiveIntraTableGapThreshold(rows []Row, pageRect geometry.Rect) float32 {
	gaps := make([]float32, 0, len(rows)-1)
	for i := 1; i < len(rows); i++ {
		gap := rows[i].BBox.Y0 - rows[i-1].BBox.Y1
		if gap > 0 {
			gaps = append(gaps, gap)
		}
	}
	base := pageRect.Height() * 0.009
	if len(gaps) == 0 {
		return base
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	medianGap := gaps[len(gaps)/2]
	threshold := geometry.Max32(base, medianGap*2.2)
	maxThreshold := pageRect.Height() * 0.055
	if threshold > maxThreshold {
		threshold = maxThreshold
	}
	return threshold
}

func isSparseSeparatorRow(row Row, dominantCols int, tableWidth float32) bool {
	rowCols := len(row.Cells)
	if rowCols <= 0 {
		return true
	}
	maxCols := dominantCols / 3
	if maxCols < 1 {
		maxCols = 1
	}
	if rowCols > maxCols {
		return false
	}
	return row.BBox.Width()/tableWidth >= 0.35
}

func denseRowRatio(rows []Row, dominantCols int) float32 {
	if len(rows) == 0 {
		return 0
	}
	minDense := dominantCols - 1
	if minDense < 2 {
		minDense = 2
	}
	dense := 0
	for _, row := range rows {
		if len(row.Cells) >= minDense {
			dense++
		}
	}
	return float32(dense) / float32(len(rows))
}

func normalizeColumns(tables *TableArray, pageRect geometry.Rect) {
	for ti := range tables.Tables {
		tbl := &tables.Tables[ti]
		xCoords := make(map[int]bool)
		for _, row := range tbl.Rows {
			for _, cell := range row.Cells {
				if !cell.BBox.IsEmpty() {
					xCoords[coordToInt(float64(cell.BBox.X0))] = true
					xCoords[coordToInt(float64(cell.BBox.X1))] = true
				}
			}
		}
		sortedX := make([]int, 0, len(xCoords))
		for x := range xCoords {
			sortedX = append(sortedX, x)
		}
		sort.Ints(sortedX)
		var cols [][2]float32
		if len(sortedX) > 0 {
			colTol := int(pageRect.Width() * colXTolRatio * coordScale)
			if colTol < 2000 {
				colTol = 2000
			}
			for i := 0; i < len(sortedX)-1; {
				c0 := sortedX[i]
				j := i + 1
				for j < len(sortedX) && sortedX[j]-c0 < colTol {
					j++
				}
				if j < len(sortedX) {
					cols = append(cols, [2]float32{float32(c0) / coordScale, float32(sortedX[j]) / coordScale})
					i = j
				} else {
					break
				}
			}
		}
		if len(cols) == 0 {
			continue
		}
		for r := range tbl.Rows {
			row := &tbl.Rows[r]
			newCells := make([]Cell, len(cols))
			for _, cell := range row.Cells {
				if cell.BBox.IsEmpty() {
					continue
				}
				bestCol, maxOvr := -1, float32(0)
				for ci, col := range cols {
					ovr := geometry.Min32(cell.BBox.X1, col[1]) - geometry.Max32(cell.BBox.X0, col[0])
					if ovr > maxOvr {
						maxOvr, bestCol = ovr, ci
					}
				}
				if bestCol >= 0 && (newCells[bestCol].BBox.IsEmpty() || maxOvr > newCells[bestCol].BBox.Width()*0.5) {
					newCells[bestCol] = cell
				}
			}
			row.Cells = newCells
		}
		pruneEmpty(tbl)
	}
}

func pruneEmpty(tbl *Table) {
	validRows := tbl.Rows[:0]
	for _, row := range tbl.Rows {
		for _, c := range row.Cells {
			if !c.BBox.IsEmpty() {
				validRows = append(validRows, row)
				break
			}
		}
	}
	tbl.Rows = validRows
	if len(tbl.Rows) == 0 || len(tbl.Rows[0].Cells) == 0 {
		return
	}
	keepCols := make([]bool, len(tbl.Rows[0].Cells))
	for c := range tbl.Rows[0].Cells {
		if !tbl.Rows[0].Cells[c].BBox.IsEmpty() {
			keepCols[c] = true
		}
	}
	newColCount := 0
	for _, k := range keepCols {
		if k {
			newColCount++
		}
	}
	if newColCount > 0 && newColCount < len(tbl.Rows[0].Cells) {
		for r := range tbl.Rows {
			oldCells := tbl.Rows[r].Cells
			newCells := make([]Cell, 0, newColCount)
			for c, cell := range oldCells {
				if c < len(keepCols) && keepCols[c] {
					newCells = append(newCells, cell)
				}
			}
			tbl.Rows[r].Cells = newCells
		}
	}
	if len(tbl.Rows) > 0 {
		colCount := len(tbl.Rows[0].Cells)
		for r := 1; r < len(tbl.Rows); r++ {
			row := &tbl.Rows[r]
			if len(row.Cells) > colCount {
				row.Cells = row.Cells[:colCount]
			} else if len(row.Cells) < colCount {
				padded := make([]Cell, colCount)
				copy(padded, row.Cells)
				row.Cells = padded
			}
		}
	}
}

func checkAlignmentCoverage(t *Table) bool {
	if len(t.Rows) < 2 {
		return true
	}
	xPositions := make(map[float32]int)
	yPositions := make(map[float32]int)
	tol := float32(3.0)
	for _, row := range t.Rows {
		for _, cell := range row.Cells {
			if cell.BBox.IsEmpty() {
				continue
			}
			matchedX0, matchedX1 := cell.BBox.X0, cell.BBox.X1
			for x := range xPositions {
				if geometry.Abs32(cell.BBox.X0-x) < tol {
					matchedX0 = x
					break
				}
			}
			for x := range xPositions {
				if geometry.Abs32(cell.BBox.X1-x) < tol {
					matchedX1 = x
					break
				}
			}
			xPositions[matchedX0]++
			xPositions[matchedX1]++
		}
		matchedY0, matchedY1 := row.BBox.Y0, row.BBox.Y1
		for y := range yPositions {
			if geometry.Abs32(row.BBox.Y0-y) < tol {
				matchedY0 = y
				break
			}
		}
		for y := range yPositions {
			if geometry.Abs32(row.BBox.Y1-y) < tol {
				matchedY1 = y
				break
			}
		}
		yPositions[matchedY0]++
		yPositions[matchedY1]++
	}
	alignedXCount := 0
	for _, count := range xPositions {
		if count >= 2 {
			alignedXCount++
		}
	}
	totalX := len(xPositions)
	minXCoverage := float32(0.5)
	if len(t.Rows) <= 3 {
		minXCoverage = 0.35
	}
	if totalX > 0 && float32(alignedXCount)/float32(totalX) < minXCoverage {
		Logger.Debug("table rejected: low horizontal alignment coverage", "aligned", alignedXCount, "total", totalX)
		return false
	}
	alignedYCount := 0
	for _, count := range yPositions {
		if count >= 2 {
			alignedYCount++
		}
	}
	if len(t.Rows) >= 8 && len(t.Rows[0].Cells) >= 3 && hasRegularRowSpacing(t) {
		return true
	}
	totalY := len(yPositions)
	minYCoverage := float32(0.5)
	if len(t.Rows) <= 3 {
		minYCoverage = 0.25
	}
	if totalY > 0 && float32(alignedYCount)/float32(totalY) < minYCoverage {
		if !hasRegularRowSpacing(t) {
			Logger.Debug("table rejected: low vertical alignment coverage", "aligned", alignedYCount, "total", totalY)
			return false
		}
	}
	return true
}

func hasRegularRowSpacing(t *Table) bool {
	if t == nil || len(t.Rows) < 4 {
		return false
	}
	centers := make([]float32, 0, len(t.Rows))
	for _, row := range t.Rows {
		h := row.BBox.Height()
		if h <= 0 {
			continue
		}
		centers = append(centers, (row.BBox.Y0+row.BBox.Y1)*0.5)
	}
	if len(centers) < 4 {
		return false
	}
	sort.Slice(centers, func(i, j int) bool { return centers[i] < centers[j] })
	gaps := make([]float32, 0, len(centers)-1)
	for i := 1; i < len(centers); i++ {
		gap := centers[i] - centers[i-1]
		if gap > 0.5 {
			gaps = append(gaps, gap)
		}
	}
	if len(gaps) < 3 {
		return false
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	medianGap := gaps[len(gaps)/2]
	if medianGap <= 0 {
		return false
	}
	tol := geometry.Max32(1.5, medianGap*0.45)
	stable := 0
	for _, gap := range gaps {
		if geometry.Abs32(gap-medianGap) <= tol {
			stable++
		}
	}
	return float32(stable)/float32(len(gaps)) >= 0.55
}

func hasConsistentColumnWidths(t *Table) bool {
	if len(t.Rows) < 2 {
		return true
	}
	colWidths := make([][]float32, 0)
	for _, row := range t.Rows {
		if len(row.Cells) == 0 {
			continue
		}
		widths := make([]float32, 0, len(row.Cells))
		for _, cell := range row.Cells {
			if !cell.BBox.IsEmpty() {
				widths = append(widths, cell.BBox.Width())
			}
		}
		if len(widths) >= 2 {
			colWidths = append(colWidths, widths)
		}
	}
	if len(colWidths) < 2 {
		return true
	}
	reference := colWidths[0]
	for i := 1; i < len(colWidths); i++ {
		widths := colWidths[i]
		if len(widths) != len(reference) {
			continue
		}
		var totalDiff, totalWidth float32
		for j := 0; j < len(widths); j++ {
			diff := geometry.Abs32(widths[j] - reference[j])
			totalDiff += diff
			totalWidth += reference[j]
		}
		if totalWidth > 0 && totalDiff/totalWidth > 0.4 {
			return false
		}
	}
	return true
}

func hasRegularGrid(t *Table) bool {
	if len(t.Rows) < 2 {
		return true
	}
	colCount := len(t.Rows[0].Cells)
	if colCount < 2 {
		return true
	}
	var x0Positions []float32
	var x1Positions []float32
	for _, row := range t.Rows {
		for _, cell := range row.Cells {
			if !cell.BBox.IsEmpty() {
				x0Positions = append(x0Positions, cell.BBox.X0)
				x1Positions = append(x1Positions, cell.BBox.X1)
			}
		}
	}
	if len(x0Positions) < 4 {
		return true
	}
	sort.Slice(x0Positions, func(i, j int) bool { return x0Positions[i] < x0Positions[j] })
	sort.Slice(x1Positions, func(i, j int) bool { return x1Positions[i] < x1Positions[j] })
	uniqueX0 := geometry.MergeNearby(x0Positions, 5.0)
	uniqueX1 := geometry.MergeNearby(x1Positions, 5.0)
	expectedColCount := colCount
	if len(uniqueX0) > expectedColCount*2 || len(uniqueX1) > expectedColCount*2 {
		return false
	}
	return true
}

func isLowerLetter(r rune) bool {
	return unicode.IsLower(r)
}

func ShrinkCellsToContent(tables *TableArray, chars []bridge.RawChar) {
	if tables == nil || len(chars) == 0 {
		return
	}
	for ti := range tables.Tables {
		tbl := &tables.Tables[ti]
		rect := tbl.BBox
		var tblChars []bridge.RawChar
		for _, ch := range chars {
			if ch.BBox.X0 < rect.X1+2 && ch.BBox.X1 > rect.X0-2 && ch.BBox.Y0 < rect.Y1+2 && ch.BBox.Y1 > rect.Y0-2 {
				tblChars = append(tblChars, ch)
			}
		}
		if len(tblChars) == 0 {
			continue
		}
		for ri := range tbl.Rows {
			for ci := range tbl.Rows[ri].Cells {
				cell := &tbl.Rows[ri].Cells[ci]
				if cell.BBox.IsEmpty() {
					continue
				}
				search := geometry.Rect{X0: cell.BBox.X0 - 2, Y0: cell.BBox.Y0 - 2, X1: cell.BBox.X1 + 2, Y1: cell.BBox.Y1 + 2}
				var content geometry.Rect
				first := true
				for _, ch := range tblChars {
					if ch.BBox.X0 < search.X1 && ch.BBox.X1 > search.X0 && ch.BBox.Y0 < search.Y1 && ch.BBox.Y1 > search.Y0 {
						cr := geometry.Rect{X0: ch.BBox.X0, Y0: ch.BBox.Y0, X1: ch.BBox.X1, Y1: ch.BBox.Y1}
						if first {
							content, first = cr, false
						} else {
							content = content.Union(cr)
						}
					}
				}
				if !first {
					cell.BBox.X0 = geometry.Max32(cell.BBox.X0, content.X0)
					cell.BBox.Y0 = geometry.Max32(cell.BBox.Y0, content.Y0)
					cell.BBox.X1 = geometry.Min32(cell.BBox.X1, content.X1)
					cell.BBox.Y1 = geometry.Min32(cell.BBox.Y1, content.Y1)
				}
			}
		}
	}
}

func mergeEdges(edges []Edge, snapTol, joinTol float64) []Edge {
	if len(edges) == 0 {
		return nil
	}
	orientation := edges[0].Orientation
	if orientation == 'h' {
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].Y0 != edges[j].Y0 {
				return edges[i].Y0 < edges[j].Y0
			}
			return edges[i].X0 < edges[j].X0
		})
	} else {
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].X0 != edges[j].X0 {
				return edges[i].X0 < edges[j].X0
			}
			return edges[i].Y0 < edges[j].Y0
		})
	}
	var result []Edge
	snapInt, joinInt := coordToInt(snapTol), coordToInt(joinTol)
	for i := 0; i < len(edges); {
		cur := edges[i]
		posSum := coordToInt(cur.Y0)
		if orientation == 'v' {
			posSum = coordToInt(cur.X0)
		}
		count := 1
		i++
		for i < len(edges) {
			next := edges[i]
			nextPos := coordToInt(next.Y0)
			if orientation == 'v' {
				nextPos = coordToInt(next.X0)
			}
			if int(math.Abs(float64(nextPos-posSum/count))) <= snapInt {
				posSum += nextPos
				count++
				i++
			} else {
				break
			}
		}
		snapped := float64(posSum/count) / coordScale
		joined := cur
		if orientation == 'h' {
			joined.Y0, joined.Y1 = snapped, snapped
		} else {
			joined.X0, joined.X1 = snapped, snapped
		}
		start := i - count
		for j := start + 1; j < i; j++ {
			next := edges[j]
			if orientation == 'h' {
				next.Y0, next.Y1 = snapped, snapped
				if coordToInt(next.X0)-coordToInt(joined.X1) <= joinInt {
					joined.X1 = math.Max(joined.X1, next.X1)
				} else {
					result = append(result, joined)
					joined = next
				}
			} else {
				next.X0, next.X1 = snapped, snapped
				if coordToInt(next.Y0)-coordToInt(joined.Y1) <= joinInt {
					joined.Y1 = math.Max(joined.Y1, next.Y1)
				} else {
					result = append(result, joined)
					joined = next
				}
			}
		}
		result = append(result, joined)
	}
	return result
}

func findIntersections(vEdges, hEdges []Edge, tr *rtree.RTreeG[geometry.Point], eps float64) {
	tolInt := coordToInt(eps)
	for _, v := range vEdges {
		vXInt, vY0Int, vY1Int := coordToInt(v.X0), coordToInt(v.Y0), coordToInt(v.Y1)
		for _, h := range hEdges {
			hYInt := coordToInt(h.Y0)
			if hYInt < vY0Int-tolInt || hYInt > vY1Int+tolInt {
				continue
			}
			hX0Int, hX1Int := coordToInt(h.X0), coordToInt(h.X1)
			if hX0Int-tolInt <= vXInt && hX1Int+tolInt >= vXInt {
				p := geometry.Point{X: float32(v.X0), Y: float32(h.Y0)}
				exists := false
				tr.Search([2]float64{float64(p.X - 0.1), float64(p.Y - 0.1)}, [2]float64{float64(p.X + 0.1), float64(p.Y + 0.1)}, func(_, _ [2]float64, _ geometry.Point) bool {
					exists = true
					return false
				})
				if !exists {
					tr.Insert([2]float64{float64(p.X), float64(p.Y)}, [2]float64{float64(p.X), float64(p.Y)}, p)
				}
			}
		}
	}
}

func isPunctOrDigit(r rune) bool {
	return r == '.' || r == ',' || r == '$' || r == '%' || r == ':' || r == ';' || r == '\'' || r == '"' || r == '-' || r == '(' || r == ')' || (r >= '0' && r <= '9')
}

func extractTextInRect(raw *bridge.RawPageData, rect geometry.Rect) string {
	indices := make([]int, 0, 64)
	for i := range raw.Chars {
		ch := &raw.Chars[i]
		if ch.Codepoint == 0 || ch.Codepoint == 0xFEFF {
			continue
		}
		cx, cy := (ch.BBox.X0+ch.BBox.X1)/2, (ch.BBox.Y0+ch.BBox.Y1)/2
		if cx < rect.X0-2 || cx > rect.X1+2 || cy < rect.Y0-2 || cy > rect.Y1+2 {
			continue
		}
		indices = append(indices, i)
	}
	if len(indices) == 0 {
		return ""
	}
	sort.SliceStable(indices, func(i, j int) bool {
		a := raw.Chars[indices[i]]
		b := raw.Chars[indices[j]]
		ay, by := (a.BBox.Y0+a.BBox.Y1)*0.5, (b.BBox.Y0+b.BBox.Y1)*0.5
		lineTol := geometry.Max32(geometry.Max32(a.Size, b.Size)*0.45, 0.8)
		if geometry.Abs32(ay-by) > lineTol {
			return ay < by
		}
		if geometry.Abs32(a.BBox.X0-b.BBox.X0) > 0.3 {
			return a.BBox.X0 < b.BBox.X0
		}
		return indices[i] < indices[j]
	})

	var buf strings.Builder
	prevIdx := -1
	var prevR rune
	for _, idx := range indices {
		ch := raw.Chars[idx]
		if prevIdx >= 0 {
			prev := raw.Chars[prevIdx]
			prevCY := (prev.BBox.Y0 + prev.BBox.Y1) * 0.5
			currCY := (ch.BBox.Y0 + ch.BBox.Y1) * 0.5
			lineTol := geometry.Max32(geometry.Max32(prev.Size, ch.Size)*0.5, 1.5)
			needSpace := false
			if geometry.Abs32(currCY-prevCY) > lineTol {
				needSpace = true
			} else {
				gap := ch.BBox.X0 - prev.BBox.X1
				spaceGap := geometry.Max32(geometry.Max32(prev.Size, ch.Size)*0.33, 1.2)
				if gap > spaceGap {
					needSpace = true
				}
			}
			if needSpace && buf.Len() > 0 && prevR != ' ' && !unicode.IsSpace(prevR) && !isPunctOrDigit(ch.Codepoint) {
				buf.WriteByte(' ')
				prevR = ' '
			}
		}
		buf.WriteRune(ch.Codepoint)
		prevR = ch.Codepoint
		prevIdx = idx
	}
	res := buf.String()
	res = strings.TrimSpace(res)
	res = strings.ReplaceAll(res, "\u00A0", " ")
	var prev rune
	var cleaned strings.Builder
	for _, r := range res {
		if r == ' ' && prev == ' ' {
			continue
		}
		cleaned.WriteRune(r)
		prev = r
	}
	return cleaned.String()
}

func extractTextIntoCells(raw *bridge.RawPageData, tables *TableArray) {
	if tables == nil {
		return
	}
	for ti := range tables.Tables {
		for ri := range tables.Tables[ti].Rows {
			for ci := range tables.Tables[ti].Rows[ri].Cells {
				tables.Tables[ti].Rows[ri].Cells[ci].Text = extractTextInRect(raw, tables.Tables[ti].Rows[ri].Cells[ci].BBox)
			}
		}
	}
}

func trimOversizedLowSignalRows(tables *TableArray) {
	if tables == nil {
		return
	}
	const maxScoringCells = 200
	for ti := range tables.Tables {
		tbl := &tables.Tables[ti]
		if len(tbl.Rows) < 6 || len(tbl.Rows[0].Cells) < 2 {
			continue
		}
		colCount := len(tbl.Rows[0].Cells)
		trimmed := false
		for len(tbl.Rows)*colCount > maxScoringCells {
			bestIdx := -1
			bestScore := 1 << 30
			overflow := len(tbl.Rows)*colCount - maxScoringCells
			for i := 1; i < len(tbl.Rows); i++ {
				row := tbl.Rows[i]
				nonEmpty := 0
				numericCells := 0
				for _, cell := range row.Cells {
					txt := strings.TrimSpace(cell.Text)
					if txt == "" {
						continue
					}
					nonEmpty++
					if hasTableNumericContent(txt) {
						numericCells++
					}
				}
				if nonEmpty > 2 && !(nonEmpty <= 3 && numericCells <= 1) {
					continue
				}
				score := nonEmpty*10 + numericCells*5 + i/8
				if score < bestScore {
					bestScore = score
					bestIdx = i
				}
			}
			if bestIdx < 0 {
				if overflow > colCount*2 {
					break
				}
				fallbackIdx := -1
				fallbackScore := 1 << 30
				for i := 1; i < len(tbl.Rows); i++ {
					row := tbl.Rows[i]
					nonEmpty := 0
					numericCells := 0
					for _, cell := range row.Cells {
						txt := strings.TrimSpace(cell.Text)
						if txt == "" {
							continue
						}
						nonEmpty++
						if hasTableNumericContent(txt) {
							numericCells++
						}
					}
					if nonEmpty > colCount/2+1 {
						continue
					}
					score := nonEmpty*20 + numericCells*8 + i/6
					if score < fallbackScore {
						fallbackScore = score
						fallbackIdx = i
					}
				}
				if fallbackIdx < 0 {
					break
				}
				bestIdx = fallbackIdx
			}
			tbl.Rows = append(tbl.Rows[:bestIdx], tbl.Rows[bestIdx+1:]...)
			trimmed = true
			if len(tbl.Rows) < 3 {
				break
			}
		}
		if trimmed {
			tbl.BBox = tableBBoxFromRowsForTrim(tbl.Rows)
			Logger.Debug("trimmed oversized low-signal rows", "rows", len(tbl.Rows), "cols", colCount)
		}
	}
}

func tableBBoxFromRowsForTrim(rows []Row) geometry.Rect {
	var bbox geometry.Rect
	for _, row := range rows {
		if bbox.IsEmpty() {
			bbox = row.BBox
		} else {
			bbox = bbox.Union(row.BBox)
		}
	}
	return bbox
}

func trimProseTailRows(tables *TableArray) {
	if tables == nil {
		return
	}
	for ti := range tables.Tables {
		tbl := &tables.Tables[ti]
		if len(tbl.Rows) < 3 {
			continue
		}
		colCount := 0
		if len(tbl.Rows) > 0 {
			colCount = len(tbl.Rows[0].Cells)
		}
		trimmed := false
		for len(tbl.Rows) >= 3 {
			last := tbl.Rows[len(tbl.Rows)-1]
			nonEmpty := 0
			numeric := 0
			chars := 0
			for _, cell := range last.Cells {
				txt := strings.TrimSpace(cell.Text)
				if txt == "" {
					continue
				}
				nonEmpty++
				chars += len([]rune(txt))
				if hasTableNumericContent(txt) {
					numeric++
				}
			}
			if nonEmpty <= 1 && chars >= 60 && (numeric == 0 || chars >= 120) {
				tbl.Rows = tbl.Rows[:len(tbl.Rows)-1]
				trimmed = true
				continue
			}
			if colCount >= 4 && nonEmpty <= 2 && chars >= 75 && numeric == 0 {
				tbl.Rows = tbl.Rows[:len(tbl.Rows)-1]
				trimmed = true
				continue
			}
			break
		}
		if trimmed {
			tbl.BBox = tableBBoxFromRowsForTrim(tbl.Rows)
			Logger.Debug("trimmed prose tail rows", "rows", len(tbl.Rows))
		}
	}
}

func splitLargeTablesOnSeparatorRows(tables *TableArray) {
	if tables == nil {
		return
	}
	out := make([]Table, 0, len(tables.Tables))
	for _, tbl := range tables.Tables {
		if len(tbl.Rows) < 12 || len(tbl.Rows[0].Cells) < 2 {
			out = append(out, tbl)
			continue
		}
		colCount := len(tbl.Rows[0].Cells)
		if len(tbl.Rows)*colCount <= 180 {
			out = append(out, tbl)
			continue
		}
		signals, medianFilled := computeTableRowSignals(tbl.Rows)
		if medianFilled < 2 {
			out = append(out, tbl)
			continue
		}
		sepMaxFilled := int(math.Round(float64(medianFilled) * 0.45))
		if sepMaxFilled < 1 {
			sepMaxFilled = 1
		}
		if halfCols := colCount / 2; sepMaxFilled > halfCols {
			sepMaxFilled = halfCols
		}
		denseMinFilled := medianFilled - 1
		if denseMinFilled < 2 {
			denseMinFilled = 2
		}
		splitStart := -1
		splitEnd := -1
		for i := 4; i < len(tbl.Rows)-4; {
			sig := signals[i]
			if sig.nonEmpty > sepMaxFilled || sig.chars < 12 {
				i++
				continue
			}
			if sig.numeric > sig.nonEmpty/2+1 {
				i++
				continue
			}
			j := i
			for j < len(tbl.Rows)-3 {
				next := signals[j]
				if next.nonEmpty <= sepMaxFilled && next.chars >= 8 && next.numeric <= next.nonEmpty/2+1 {
					j++
					continue
				}
				break
			}
			leftStart := i - 4
			if leftStart < 0 {
				leftStart = 0
			}
			rightEnd := j + 4
			if rightEnd > len(tbl.Rows) {
				rightEnd = len(tbl.Rows)
			}
			leftDense := denseSignalRatio(signals[leftStart:i], denseMinFilled)
			rightDense := denseSignalRatio(signals[j:rightEnd], denseMinFilled)
			if leftDense >= 0.5 && rightDense >= 0.5 && j-i <= 4 {
				splitStart = i
				splitEnd = j
				break
			}
			i = j + 1
		}
		if splitStart <= 3 || splitEnd <= splitStart || len(tbl.Rows)-splitEnd < 3 {
			out = append(out, tbl)
			continue
		}
		leftRows := append([]Row(nil), tbl.Rows[:splitStart]...)
		rightRows := append([]Row(nil), tbl.Rows[splitEnd:]...)
		if len(leftRows) < 2 || len(rightRows) < 2 {
			out = append(out, tbl)
			continue
		}
		left := Table{Rows: leftRows, BBox: tableBBoxFromRowsForTrim(leftRows)}
		right := Table{Rows: rightRows, BBox: tableBBoxFromRowsForTrim(rightRows)}
		out = append(out, left, right)
		Logger.Debug("split large table on adaptive separator rows", "rowsLeft", len(leftRows), "rowsRight", len(rightRows), "cols", colCount, "medianFilled", medianFilled)
	}
	tables.Tables = out
}

type tableRowSignal struct {
	nonEmpty int
	numeric  int
	chars    int
}

func computeTableRowSignals(rows []Row) ([]tableRowSignal, int) {
	signals := make([]tableRowSignal, len(rows))
	filled := make([]int, 0, len(rows))
	for i, row := range rows {
		sig := tableRowSignal{}
		for _, cell := range row.Cells {
			txt := strings.TrimSpace(cell.Text)
			if txt == "" {
				continue
			}
			sig.nonEmpty++
			sig.chars += len([]rune(txt))
			if hasTableNumericContent(txt) {
				sig.numeric++
			}
		}
		signals[i] = sig
		if sig.nonEmpty > 0 {
			filled = append(filled, sig.nonEmpty)
		}
	}
	if len(filled) == 0 {
		return signals, 0
	}
	sort.Ints(filled)
	return signals, filled[len(filled)/2]
}

func denseSignalRatio(signals []tableRowSignal, minFilled int) float32 {
	if len(signals) == 0 {
		return 0
	}
	dense := 0
	for _, sig := range signals {
		if sig.nonEmpty >= minFilled {
			dense++
		}
	}
	return float32(dense) / float32(len(signals))
}

func convertTableRows(tbl Table) ([]models.TableRow, int) {
	tbl = maybeExpandCollapsedRangeColumns(tbl)
	preserveEmptyCols := shouldPreserveEmptyColumns(tbl)
	var rows []models.TableRow
	visibleRows := 0
	for _, r := range tbl.Rows {
		var cells []models.TableCell
		hasVisible := false
		for _, c := range r.Cells {
			if c.BBox.IsEmpty() && !preserveEmptyCols {
				continue
			}
			var spans []models.Span
			if trimmed := strings.TrimSpace(c.Text); trimmed != "" {
				spans, hasVisible = append(spans, models.Span{Text: trimmed}), true
			}
			cells = append(cells, models.TableCell{BBox: models.BBox{c.BBox.X0, c.BBox.Y0, c.BBox.X1, c.BBox.Y1}, Spans: spans})
		}
		if len(cells) > 0 {
			rows = append(rows, models.TableRow{BBox: models.BBox{r.BBox.X0, r.BBox.Y0, r.BBox.X1, r.BBox.Y1}, Cells: cells})
			if hasVisible {
				visibleRows++
			}
		}
	}
	if len(rows) > 0 {
		normalizeHeaderRow(&rows)
	}
	return rows, visibleRows
}

func shouldPreserveEmptyColumns(tbl Table) bool {
	if len(tbl.Rows) < 4 || len(tbl.Rows[0].Cells) < 5 {
		return false
	}
	colCount := len(tbl.Rows[0].Cells)
	if colCount == 0 {
		return false
	}
	headerTrailingEmpty := colCount-1 < len(tbl.Rows[0].Cells) && tbl.Rows[0].Cells[colCount-1].BBox.IsEmpty()
	if !headerTrailingEmpty {
		return false
	}
	trailingDataRows := 0
	for _, row := range tbl.Rows[1:] {
		if len(row.Cells) < colCount {
			continue
		}
		last := row.Cells[colCount-1]
		if !last.BBox.IsEmpty() || strings.TrimSpace(last.Text) != "" {
			trailingDataRows++
		}
	}
	return trailingDataRows > 0
}

func maybeExpandCollapsedRangeColumns(tbl Table) Table {
	if len(tbl.Rows) < 4 || len(tbl.Rows) > 12 {
		return tbl
	}
	if len(tbl.Rows[0].Cells) < 4 || len(tbl.Rows[0].Cells) > 6 {
		return tbl
	}
	colCount := len(tbl.Rows[0].Cells)
	maxParts := make([]int, colCount)
	multiPartCells := 0
	rowsWithRangeLikeData := 0
	for _, row := range tbl.Rows {
		rowHasRangeLikeData := false
		for ci := 0; ci < colCount && ci < len(row.Cells); ci++ {
			txt := strings.TrimSpace(row.Cells[ci].Text)
			if txt == "" {
				continue
			}
			parts := splitRangeLikeParts(txt)
			if len(parts) > maxParts[ci] {
				maxParts[ci] = len(parts)
			}
			if len(parts) >= 2 {
				multiPartCells++
				rowHasRangeLikeData = true
			} else if isRangeLikeToken(txt) {
				rowHasRangeLikeData = true
			}
		}
		if rowHasRangeLikeData {
			rowsWithRangeLikeData++
		}
	}
	if multiPartCells < 2 || rowsWithRangeLikeData < 3 {
		return tbl
	}
	plan := make([]int, colCount)
	expandedCols := 0
	totalCols := 0
	for ci := 0; ci < colCount; ci++ {
		k := 1
		if maxParts[ci] >= 3 {
			k = maxParts[ci]
			expandedCols++
		}
		plan[ci] = k
		totalCols += k
	}
	if expandedCols == 0 || totalCols > 16 {
		return tbl
	}
	newRows := make([]Row, 0, len(tbl.Rows))
	for _, row := range tbl.Rows {
		newCells := make([]Cell, 0, totalCols)
		var rowBBox geometry.Rect
		for ci := 0; ci < colCount; ci++ {
			var cell Cell
			if ci < len(row.Cells) {
				cell = row.Cells[ci]
			}
			k := plan[ci]
			if k == 1 {
				newCells = append(newCells, cell)
				if !cell.BBox.IsEmpty() {
					if rowBBox.IsEmpty() {
						rowBBox = cell.BBox
					} else {
						rowBBox = rowBBox.Union(cell.BBox)
					}
				}
				continue
			}
			parts := splitRangeLikeParts(cell.Text)
			if len(parts) == 0 {
				txt := strings.TrimSpace(cell.Text)
				if txt != "" && (isRangeLikeToken(txt) || isDashRun(txt) || txt == "-") {
					parts = []string{txt}
				}
			}
			for pi := 0; pi < k; pi++ {
				nc := Cell{}
				if !cell.BBox.IsEmpty() {
					w := cell.BBox.Width() / float32(k)
					nc.BBox = geometry.Rect{
						X0: cell.BBox.X0 + float32(pi)*w,
						Y0: cell.BBox.Y0,
						X1: cell.BBox.X0 + float32(pi+1)*w,
						Y1: cell.BBox.Y1,
					}
				}
				if pi < len(parts) {
					nc.Text = parts[pi]
				} else if len(parts) > 0 {
					nc.Text = "-"
				}
				newCells = append(newCells, nc)
				if !nc.BBox.IsEmpty() {
					if rowBBox.IsEmpty() {
						rowBBox = nc.BBox
					} else {
						rowBBox = rowBBox.Union(nc.BBox)
					}
				}
			}
		}
		if rowBBox.IsEmpty() {
			rowBBox = row.BBox
		}
		newRows = append(newRows, Row{BBox: rowBBox, Cells: newCells})
	}
	tbl.Rows = newRows
	tbl.BBox = tableBBoxFromRowsForTrim(newRows)
	Logger.Debug("expanded collapsed range columns", "rows", len(newRows), "colsBefore", colCount, "colsAfter", totalCols)
	return tbl
}

func splitRangeLikeParts(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	parts := make([]string, 0, 6)
	for _, tok := range strings.Fields(text) {
		tok = strings.Trim(tok, ",;:")
		if tok == "" {
			continue
		}
		if tok == "-" || isDashRun(tok) || isRangeLikeToken(tok) {
			parts = append(parts, tok)
		}
	}
	if len(parts) < 2 {
		return nil
	}
	if len(parts) > 10 {
		parts = parts[:10]
	}
	return parts
}

func isDashRun(tok string) bool {
	if tok == "" {
		return false
	}
	for _, r := range tok {
		if r != '-' {
			return false
		}
	}
	return true
}

func isRangeLikeToken(tok string) bool {
	if tok == "" {
		return false
	}
	hasDigit := false
	hasHyphen := false
	for _, r := range tok {
		switch {
		case unicode.IsDigit(r):
			hasDigit = true
		case r == '-':
			hasHyphen = true
		case r == '.' || r == ',':
			continue
		default:
			return false
		}
	}
	return hasDigit && hasHyphen
}

func normalizeHeaderRow(rows *[]models.TableRow) {
	if len(*rows) == 0 {
		return
	}
	header := &(*rows)[0]
	nonEmpty := make([]models.TableCell, 0, len(header.Cells))
	for _, cell := range header.Cells {
		if hasVisibleTableCellText(cell) {
			nonEmpty = append(nonEmpty, cell)
		}
	}
	trimmedCols := len(nonEmpty)
	keepWideHeader := false
	if trimmedCols > 0 && trimmedCols < len(header.Cells) {
		for i := 1; i < len(*rows) && !keepWideHeader; i++ {
			row := (*rows)[i]
			for c := trimmedCols; c < len(row.Cells); c++ {
				if hasVisibleTableCellText(row.Cells[c]) {
					keepWideHeader = true
					break
				}
			}
		}
	}
	colCount := len(header.Cells)
	if trimmedCols > 0 && !keepWideHeader && trimmedCols == len(header.Cells) {
		header.Cells = nonEmpty
		colCount = trimmedCols
	}
	for i := 1; i < len(*rows); i++ {
		row := &(*rows)[i]
		if len(row.Cells) > colCount {
			row.Cells = row.Cells[:colCount]
		} else if len(row.Cells) < colCount {
			padded := make([]models.TableCell, colCount)
			copy(padded, row.Cells)
			row.Cells = padded
		}
	}
}

func hasVisibleTableCellText(cell models.TableCell) bool {
	for _, span := range cell.Spans {
		if strings.TrimSpace(span.Text) != "" {
			return true
		}
	}
	return false
}

func computeAvgCharWidth(chars []bridge.RawChar) float32 {
	var total float32
	var count int
	for _, ch := range chars {
		if ch.Codepoint == 0 {
			continue
		}
		w := ch.BBox.X1 - ch.BBox.X0
		if w > 1 && w < 100 {
			total += w
			count++
		}
	}
	if count == 0 {
		return 5.0
	}
	return total / float32(count)
}

func snapToGrid(val, tol float32) float32 {
	return float32(int(val/tol+0.5)) * tol
}

func sortSlice(s []float32) {
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
}

func filterByContentDensity(tables *TableArray) {
	if tables == nil {
		return
	}
	valid := tables.Tables[:0]
	for _, t := range tables.Tables {
		highConfidence := hasHighTabularConfidence(&t)
		if len(t.Rows) < 2 {
			continue
		}
		var densities []float64
		var emptyCells, totalCells int
		for _, row := range t.Rows {
			for _, cell := range row.Cells {
				if cell.BBox.IsEmpty() {
					continue
				}
				totalCells++
				area := float64(cell.BBox.Width() * cell.BBox.Height())
				if area < 1 {
					continue
				}
				textLen := len(strings.TrimSpace(cell.Text))
				if textLen == 0 {
					emptyCells++
					continue
				}
				density := float64(textLen) / area
				densities = append(densities, density)
			}
		}
		if totalCells > 0 && float64(emptyCells)/float64(totalCells) > 0.7 && !highConfidence {
			Logger.Debug("table rejected: too many empty cells", "emptyCells", emptyCells, "totalCells", totalCells)
			continue
		}
		if len(densities) >= 3 {
			var sumD, minD, maxD float64
			minD, maxD = 1e9, 0
			for _, d := range densities {
				sumD += d
				if d < minD {
					minD = d
				}
				if d > maxD {
					maxD = d
				}
			}
			avgD := sumD / float64(len(densities))
			if avgD > 0 && maxD/minD > 20.0 && !highConfidence {
				Logger.Debug("table rejected: uneven text density", "avgDensity", avgD, "ratio", maxD/minD)
				continue
			}
		}
		valid = append(valid, t)
	}
	tables.Tables = valid
}

// rejectBrokenTextTables removes tables whose cells contain broken/split words,
// indicating the "table" is actually flowing prose falsely detected.
func rejectBrokenTextTables(tables *TableArray) {
	if tables == nil {
		return
	}
	valid := tables.Tables[:0]
	for _, t := range tables.Tables {
		if hasHighTabularConfidence(&t) {
			valid = append(valid, t)
			continue
		}
		if isBrokenProseTable(&t) {
			Logger.Debug("table rejected: broken prose detected", "rows", len(t.Rows))
			continue
		}
		valid = append(valid, t)
	}
	tables.Tables = valid
}

func isBrokenProseTable(tbl *Table) bool {
	if tbl == nil || len(tbl.Rows) < 3 {
		return false
	}
	if hasStrongStructuredIdentifiers(tbl) {
		return false
	}

	// Count cells with text that looks like a broken word fragment
	// (ends with a lowercase letter that would continue in the next cell)
	var totalCells, brokenCells, shortFragCells int
	for ri, row := range tbl.Rows {
		for ci, cell := range row.Cells {
			txt := strings.TrimSpace(cell.Text)
			if txt == "" {
				continue
			}
			totalCells++

			// Check if this cell text is a short fragment (likely a split word)
			words := strings.Fields(txt)
			if len(words) <= 2 && len(txt) <= 8 {
				shortFragCells++
			}

			// Check if text ends mid-word and next cell starts mid-word
			if ci < len(row.Cells)-1 {
				nextTxt := strings.TrimSpace(row.Cells[ci+1].Text)
				if nextTxt != "" && len(txt) > 0 && len(nextTxt) > 0 {
					lastR, _ := utf8.DecodeLastRuneInString(txt)
					firstR, _ := utf8.DecodeRuneInString(nextTxt)
					if lastR != utf8.RuneError && firstR != utf8.RuneError && isLowerLetter(lastR) && isLowerLetter(firstR) {
						brokenCells++
					}
				}
			}
			_ = ri
		}
	}

	if totalCells < 4 {
		return false
	}

	// If more than 15% of cell boundaries look like broken words
	brokenRatio := float32(brokenCells) / float32(totalCells)
	if brokenRatio > 0.15 {
		Logger.Debug("broken prose: high broken ratio", "broken", brokenCells, "total", totalCells, "ratio", brokenRatio)
		return true
	}

	// If most cells are very short fragments (typical of word-split tables)
	shortRatio := float32(shortFragCells) / float32(totalCells)
	if shortRatio > 0.65 && totalCells > 10 {
		Logger.Debug("broken prose: too many short fragments", "short", shortFragCells, "total", totalCells, "ratio", shortRatio)
		return true
	}

	return false
}

func hasStrongStructuredIdentifiers(tbl *Table) bool {
	if tbl == nil || len(tbl.Rows) < 3 {
		return false
	}
	rowCount := 0
	codeRows := 0
	numericRows := 0
	richRows := 0
	for _, row := range tbl.Rows {
		if len(row.Cells) == 0 {
			continue
		}
		var texts []string
		for _, cell := range row.Cells {
			t := strings.TrimSpace(cell.Text)
			if t != "" {
				texts = append(texts, t)
			}
		}
		if len(texts) == 0 {
			continue
		}
		rowCount++
		if len(texts) >= 3 {
			richRows++
		}
		rowHasCode := false
		rowNumericCells := 0
		for _, txt := range texts {
			parts := strings.Fields(txt)
			if len(parts) > 0 && looksStructuredIdentifier(parts[0]) {
				rowHasCode = true
			}
			if hasTableNumericContent(txt) {
				rowNumericCells++
			}
		}
		if rowHasCode {
			codeRows++
		}
		if rowNumericCells >= 2 {
			numericRows++
		}
	}
	if rowCount < 3 {
		return false
	}
	codeRatio := float32(codeRows) / float32(rowCount)
	numericRatio := float32(numericRows) / float32(rowCount)
	richRatio := float32(richRows) / float32(rowCount)
	if codeRatio >= 0.30 {
		return true
	}
	return numericRatio >= 0.55 && richRatio >= 0.45
}

func hasHighTabularConfidence(tbl *Table) bool {
	if tbl == nil || len(tbl.Rows) < 3 {
		return false
	}
	if hasStrongStructuredIdentifiers(tbl) {
		return true
	}
	if hasCompactCodeTablePattern(tbl) {
		return true
	}
	rowCount := 0
	numericRows := 0
	multiCellRows := 0
	for _, row := range tbl.Rows {
		nonEmpty := 0
		numericCells := 0
		for _, cell := range row.Cells {
			text := strings.TrimSpace(cell.Text)
			if text == "" {
				continue
			}
			nonEmpty++
			if hasTableNumericContent(text) {
				numericCells++
			}
		}
		if nonEmpty == 0 {
			continue
		}
		rowCount++
		if nonEmpty >= 3 {
			multiCellRows++
		}
		if numericCells >= 2 {
			numericRows++
		}
	}
	if rowCount < 3 {
		return false
	}
	if rowCount > 28 {
		return false
	}
	return float32(multiCellRows)/float32(rowCount) >= 0.5 && float32(numericRows)/float32(rowCount) >= 0.45
}

func hasCompactCodeTablePattern(tbl *Table) bool {
	if tbl == nil || len(tbl.Rows) < 8 || len(tbl.Rows) > 35 {
		return false
	}
	nonEmptyCells := 0
	codeLikeCells := 0
	shortCells := 0
	for _, row := range tbl.Rows {
		for _, cell := range row.Cells {
			txt := strings.TrimSpace(cell.Text)
			if txt == "" {
				continue
			}
			nonEmptyCells++
			if len([]rune(txt)) <= 18 {
				shortCells++
			}
			if isCompactCodeLikeText(txt) {
				codeLikeCells++
			}
		}
	}
	if nonEmptyCells < 12 {
		return false
	}
	codeRatio := float32(codeLikeCells) / float32(nonEmptyCells)
	shortRatio := float32(shortCells) / float32(nonEmptyCells)
	return codeRatio >= 0.28 && shortRatio >= 0.55
}

func isCompactCodeLikeText(text string) bool {
	text = strings.TrimSpace(text)
	if text == "" || len([]rune(text)) > 24 {
		return false
	}
	if len(strings.Fields(text)) > 3 {
		return false
	}
	hasDigit := false
	hasSep := false
	upper := 0
	for _, r := range text {
		switch {
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsUpper(r):
			upper++
		case r == '/' || r == '-' || r == '_':
			hasSep = true
		}
	}
	if hasSep && (hasDigit || upper >= 2) {
		return true
	}
	return hasDigit && upper >= 2
}

func looksStructuredIdentifier(tok string) bool {
	if tok == "" {
		return false
	}
	letters, digits, separators := 0, 0, 0
	hasStrongSep := false
	for _, r := range tok {
		switch {
		case unicode.IsLetter(r):
			letters++
		case unicode.IsDigit(r):
			digits++
		case r == '_' || r == '-' || r == '/':
			hasStrongSep = true
			separators++
		case r == '.':
			separators++
		default:
			return false
		}
	}
	return letters >= 3 && digits >= 1 && separators >= 1 && hasStrongSep
}

func removeColumnLikeTables(tables *TableArray, pageRect geometry.Rect) {
	if tables == nil {
		return
	}
	filtered := tables.Tables[:0]
	for _, t := range tables.Tables {
		if isColumnStyleLayout(&t, pageRect) {
			Logger.Debug("skipping column-style layout as table", "rows", len(t.Rows), "cols", len(t.Rows[0].Cells), "bbox", t.BBox)
			continue
		}
		filtered = append(filtered, t)
	}
	tables.Tables = filtered
}

func isColumnStyleLayout(tbl *Table, pageRect geometry.Rect) bool {
	if tbl == nil || pageRect.Height() <= 0 || pageRect.Width() <= 0 {
		return false
	}
	rowCount := len(tbl.Rows)
	if rowCount < 25 {
		return false
	}
	colCount := 0
	if rowCount > 0 {
		colCount = len(tbl.Rows[0].Cells)
	}
	if colCount < 3 {
		return false
	}
	if float32(rowCount)/float32(colCount) < 8.0 {
		return false
	}
	heightRatio := tbl.BBox.Height() / pageRect.Height()
	widthRatio := tbl.BBox.Width() / pageRect.Width()
	if heightRatio < 0.55 || widthRatio < 0.4 {
		return false
	}
	var totalHeight float32
	validRows := 0
	for _, row := range tbl.Rows {
		height := row.BBox.Height()
		if height <= 0 {
			continue
		}
		totalHeight += height
		validRows++
	}
	if validRows == 0 {
		return false
	}
	avgRowHeight := totalHeight / float32(validRows)
	if avgRowHeight/pageRect.Height() > 0.05 {
		return false
	}
	filledRows := 0
	for _, row := range tbl.Rows {
		cellCount := 0
		for _, cell := range row.Cells {
			if !cell.BBox.IsEmpty() {
				cellCount++
			}
		}
		if cellCount >= 2 {
			filledRows++
		}
	}
	if float32(filledRows)/float32(rowCount) < 0.6 {
		return false
	}
	if hasTabularDataContent(tbl) {
		return false
	}
	maxColWidth := float32(0)
	narrowCols := 0
	for _, cell := range tbl.Rows[0].Cells {
		w := cell.BBox.Width()
		if w > maxColWidth {
			maxColWidth = w
		}
	}
	if maxColWidth <= 0 {
		return false
	}
	for _, cell := range tbl.Rows[0].Cells {
		w := cell.BBox.Width()
		if w > 0 && w <= maxColWidth*0.1 {
			narrowCols++
		}
	}
	if narrowCols < 2 {
		return false
	}
	return true
}

func hasTabularDataContent(tbl *Table) bool {
	if tbl == nil || len(tbl.Rows) < 3 {
		return false
	}
	colCounts := make(map[int]int)
	for _, row := range tbl.Rows {
		nonEmpty := 0
		for _, cell := range row.Cells {
			if !cell.BBox.IsEmpty() && len(cell.Text) > 0 {
				nonEmpty++
			}
		}
		colCounts[nonEmpty]++
	}
	dominantColCount, dominantCount := 0, 0
	for cols, cnt := range colCounts {
		if cnt > dominantCount && cols > 0 {
			dominantColCount, dominantCount = cols, cnt
		}
	}
	if dominantColCount == 0 {
		return false
	}
	consistency := float32(dominantCount) / float32(len(tbl.Rows))
	if consistency < 0.5 {
		return false
	}
	numericRows := 0
	for _, row := range tbl.Rows {
		hasNum := false
		for _, cell := range row.Cells {
			if hasTableNumericContent(cell.Text) {
				hasNum = true
				break
			}
		}
		if hasNum {
			numericRows++
		}
	}
	if float32(numericRows)/float32(len(tbl.Rows)) > 0.25 {
		return true
	}
	return false
}

func hasTableNumericContent(s string) bool {
	if len(s) == 0 {
		return false
	}
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits >= 2
}

func ExtractAndConvertTables(raw *bridge.RawPageData) []models.Block {
	pageRect := geometry.Rect{X0: raw.PageBounds.X0, Y0: raw.PageBounds.Y0, X1: raw.PageBounds.X1, Y1: raw.PageBounds.Y1}
	var tables *TableArray
	Logger.Debug("ExtractAndConvertTables", "page", raw.PageNumber, "edges", len(raw.Edges), "lines", len(raw.Lines), "chars", len(raw.Chars))
	skipEdgeTables := len(raw.Edges) > maxEdgesForGrid && len(raw.Chars) > heavyCharCount
	if skipEdgeTables {
		Logger.Debug("skipping edge-based detection (too many edges)", "page", raw.PageNumber, "edges", len(raw.Edges), "chars", len(raw.Chars))
	} else if len(raw.Edges) >= 5 {
		Logger.Debug("extracting tables from edges", "page", raw.PageNumber, "edges", len(raw.Edges))
		tables = detectTables(raw.Edges, pageRect, raw.PageNumber)
	}
	if tables == nil || len(tables.Tables) == 0 {
		Logger.Debug("no edge-based tables detected, attempting borderless detection")
		tables = detectBorderlessTables(raw, pageRect)
	}
	if tables == nil || len(tables.Tables) == 0 {
		Logger.Debug("no tables detected")
		return nil
	}
	Logger.Debug("detected tables", "count", len(tables.Tables))
	ShrinkCellsToContent(tables, raw.Chars)
	extractTextIntoCells(raw, tables)
	trimOversizedLowSignalRows(tables)
	trimProseTailRows(tables)
	filterByContentDensity(tables)
	rejectBrokenTextTables(tables)
	removeColumnLikeTables(tables, pageRect)
	splitLargeTablesOnSeparatorRows(tables)
	if len(tables.Tables) == 0 {
		Logger.Debug("table extraction complete", "blocks", 0)
		return nil
	}
	var blocks []models.Block
	for _, tbl := range tables.Tables {
		rows, visibleRows := convertTableRows(tbl)
		if visibleRows > 0 && len(rows) > 0 && len(rows[0].Cells) > 0 {
			blocks = append(blocks, models.Block{
				Type:      models.BlockTable,
				BBox:      models.BBox{tbl.BBox.X0, tbl.BBox.Y0, tbl.BBox.X1, tbl.BBox.Y1},
				RowCount:  visibleRows,
				ColCount:  len(rows[0].Cells),
				CellCount: visibleRows * len(rows[0].Cells),
				Rows:      rows,
			})
		}
	}
	Logger.Debug("table extraction complete", "blocks", len(blocks))
	return blocks
}

func computeAvgEdgeSpacing(hEdges, vEdges []Edge) float64 {
	var totalDist float64
	var count int
	sort.Slice(hEdges, func(i, j int) bool { return hEdges[i].Y0 < hEdges[j].Y0 })
	for i := 1; i < len(hEdges); i++ {
		dist := math.Abs(hEdges[i].Y0 - hEdges[i-1].Y0)
		if dist > 1.0 {
			totalDist += dist
			count++
		}
	}
	sort.Slice(vEdges, func(i, j int) bool { return vEdges[i].X0 < vEdges[j].X0 })
	for i := 1; i < len(vEdges); i++ {
		dist := math.Abs(vEdges[i].X0 - vEdges[i-1].X0)
		if dist > 1.0 {
			totalDist += dist
			count++
		}
	}
	if count == 0 {
		return 10.0
	}
	return totalDist / float64(count)
}

func detectTables(bridgeEdges []bridge.Edge, pageRect geometry.Rect, pageNum int) *TableArray {
	if len(bridgeEdges) == 0 {
		return nil
	}
	var hEdges, vEdges []Edge
	for _, e := range bridgeEdges {
		edge := Edge{X0: e.X0, Y0: e.Y0, X1: e.X1, Y1: e.Y1, Orientation: e.Orientation}
		if e.Orientation == 'h' {
			hEdges = append(hEdges, edge)
		} else {
			vEdges = append(vEdges, edge)
		}
	}
	pw := float64(pageRect.Width())
	snapTol, joinTol := pw*snapTolRatio, pw*joinTolRatio
	hEdges = mergeEdges(hEdges, snapTol, joinTol)
	vEdges = mergeEdges(vEdges, snapTol, joinTol)
	Logger.Debug("merged edges", "page", pageNum, "hEdges", len(hEdges), "vEdges", len(vEdges))
	if len(hEdges) < minHEdges || len(vEdges) < minVEdges {
		return nil
	}
	avgEdgeSpacing := computeAvgEdgeSpacing(hEdges, vEdges)
	Logger.Debug("avg edge spacing", "page", pageNum, "spacing", avgEdgeSpacing)
	ph := float64(pageRect.Height())
	eps := math.Sqrt(pw*pw+ph*ph) * intersectRatio
	var tr rtree.RTreeG[geometry.Point]
	findIntersections(vEdges, hEdges, &tr, eps)
	var points []geometry.Point
	tr.Scan(func(_, _ [2]float64, value geometry.Point) bool {
		points = append(points, value)
		return true
	})
	Logger.Debug("found intersection points", "page", pageNum, "count", len(points))
	if len(points) < 4 {
		return nil
	}
	cells := findCells(points, &tr, pageRect, hEdges, vEdges, avgEdgeSpacing)
	Logger.Debug("found cells", "page", pageNum, "count", len(cells))
	if len(cells) == 0 {
		return nil
	}
	var valid []geometry.Rect
	for _, cell := range cells {
		outTop := math.Max(0, float64(pageRect.Y0-cell.Y0))
		outBot := math.Max(0, float64(cell.Y1-pageRect.Y1))
		outL := math.Max(0, float64(pageRect.X0-cell.X0))
		outR := math.Max(0, float64(cell.X1-pageRect.X1))
		maxOut := math.Max(math.Max(outTop, outBot), math.Max(outL, outR))
		if maxOut > 10.0 {
			continue
		}
		if maxOut > 0 {
			cell = cell.Intersect(pageRect)
		}
		valid = append(valid, cell)
	}
	if len(valid) == 0 {
		return nil
	}
	valid = deduplicateCells(valid)
	Logger.Debug("deduplicated cells", "page", pageNum, "validCells", len(valid))
	return groupCellsIntoTables(valid, pageRect)
}
