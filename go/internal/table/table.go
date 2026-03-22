package table

import (
	"math"
	"slices"
	"sort"

	"github.com/pymupdf4llm-c/go/internal/geometry"
	"github.com/pymupdf4llm-c/go/internal/logger"
	rawdata "github.com/pymupdf4llm-c/go/internal/raw"
	"github.com/tidwall/rtree"
)

var Logger = logger.GetLogger("table")

func cordToInt(x float64) int { return int(x*cordScale + 0.5) }

func hasEdge(edges []Edge, x0, y0, x1, y1, eps float64) bool {
	for _, e := range edges {
		if e.Orientation == rawdata.EdgeHorizontal {
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
	gridPoints := filterPointsToGrid(snapped, gridCols, gridRows, float32(eps))
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
	xCluster := NewCluster1D(float32(eps))
	yCluster := NewCluster1D(float32(eps))
	minVLen := float64(pageRect.Height()) * 0.02
	minHLen := float64(pageRect.Width()) * 0.02
	for _, e := range vEdges {
		edgeLen := math.Abs(e.Y1 - e.Y0)
		if edgeLen < minVLen {
			continue
		}
		xCluster.Add(float32(e.X0))
	}
	for _, e := range hEdges {
		edgeLen := math.Abs(e.X1 - e.X0)
		if edgeLen < minHLen {
			continue
		}
		yCluster.Add(float32(e.Y0))
	}
	minXCount := 1
	minYCount := 1
	var gridCols []float32
	for i, count := range xCluster.Counts {
		if count >= minXCount {
			gridCols = append(gridCols, xCluster.Centers[i])
		}
	}
	var gridRows []float32
	for i, count := range yCluster.Counts {
		if count >= minYCount {
			gridRows = append(gridRows, yCluster.Centers[i])
		}
	}
	slices.Sort(gridCols)
	slices.Sort(gridRows)
	return gridCols, gridRows
}

func filterPointsToGrid(points []geometry.Point, gridCols, gridRows []float32, eps float32) []geometry.Point {
	var result []geometry.Point
	for _, p := range points {
		onCol := false
		for _, x := range gridCols {
			if IsNearby(p.X, x, eps) {
				onCol = true
				break
			}
		}
		if !onCol {
			continue
		}
		onRow := false
		for _, y := range gridRows {
			if IsNearby(p.Y, y, eps) {
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
	assembler := NewDefaultTableAssembler(NewDefaultTableAssemblyConfig())
	tables := assembler.AssembleFromCells(cells, pageRect)
	if tables == nil || tables.isEmpty() {
		return nil
	}
	tables.normalizeColumns(pageRect)
	if tables.isEmpty() {
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

func shouldPreserveEmptyColumns(tbl Table) bool {
	if len(tbl.Rows) < 2 {
		return false
	}
	lastCol := len(tbl.Rows[0].Cells) - 1
	if lastCol <= 0 {
		return false
	}
	for _, row := range tbl.Rows {
		if len(row.Cells) <= lastCol {
			return false
		}
		if row.Cells[lastCol].BBox.IsEmpty() {
			return false
		}
	}
	return true
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
		leftStart = max(leftStart, start)
		rightEnd := j + 4
		rightEnd = min(rightEnd, len(tbl.Rows))
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
	slices.Sort(gaps)
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
	minDense = max(minDense, 2)
	dense := 0
	for _, row := range rows {
		if len(row.Cells) >= minDense {
			dense++
		}
	}
	return float32(dense) / float32(len(rows))
}

func (tables *TableArray) normalizeColumns(pageRect geometry.Rect) {
	if tables.isEmpty() {
		return
	}
	for ti := range tables.Tables {
		tbl := &tables.Tables[ti]
		grid := NewTableGrid(tbl)
		grid.Normalize(GridNormalizeOptions{NormalizeColumns: true, PreserveEmptyColumns: shouldPreserveEmptyColumns(*tbl), PageRect: pageRect})
	}
}

func mergeEdges(edges []Edge, snapTol, joinTol float64) []Edge {
	if len(edges) == 0 {
		return nil
	}
	orientation := edges[0].Orientation
	if orientation == rawdata.EdgeHorizontal {
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
	snapInt, joinInt := cordToInt(snapTol), cordToInt(joinTol)
	for i := 0; i < len(edges); {
		cur := edges[i]
		posSum := cordToInt(cur.Y0)
		if orientation == rawdata.EdgeVertical {
			posSum = cordToInt(cur.X0)
		}
		count := 1
		i++
		for i < len(edges) {
			next := edges[i]
			nextPos := cordToInt(next.Y0)
			if orientation == rawdata.EdgeVertical {
				nextPos = cordToInt(next.X0)
			}
			if int(math.Abs(float64(nextPos-posSum/count))) <= snapInt {
				posSum += nextPos
				count++
				i++
			} else {
				break
			}
		}
		snapped := float64(posSum/count) / cordScale
		joined := cur
		if orientation == rawdata.EdgeHorizontal {
			joined.Y0, joined.Y1 = snapped, snapped
		} else {
			joined.X0, joined.X1 = snapped, snapped
		}
		start := i - count
		for j := start + 1; j < i; j++ {
			next := edges[j]
			if orientation == rawdata.EdgeHorizontal {
				next.Y0, next.Y1 = snapped, snapped
				if cordToInt(next.X0)-cordToInt(joined.X1) <= joinInt {
					joined.X1 = math.Max(joined.X1, next.X1)
				} else {
					result = append(result, joined)
					joined = next
				}
			} else {
				next.X0, next.X1 = snapped, snapped
				if cordToInt(next.Y0)-cordToInt(joined.Y1) <= joinInt {
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
	tolInt := cordToInt(eps)
	for _, v := range vEdges {
		vXInt, vY0Int, vY1Int := cordToInt(v.X0), cordToInt(v.Y0), cordToInt(v.Y1)
		for _, h := range hEdges {
			hYInt := cordToInt(h.Y0)
			if hYInt < vY0Int-tolInt || hYInt > vY1Int+tolInt {
				continue
			}
			hX0Int, hX1Int := cordToInt(h.X0), cordToInt(h.X1)
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

func computeAvgCharWidth(chars []rawdata.Char) float32 {
	var total float32
	var count int
	for _, ch := range chars {
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

func detectTables(bridgeEdges []rawdata.Edge, pageRect geometry.Rect, pageNum int) *TableArray {
	if len(bridgeEdges) == 0 {
		return nil
	}
	var hEdges, vEdges []Edge
	for _, e := range bridgeEdges {
		if e.Orientation == rawdata.EdgeHorizontal {
			hEdges = append(hEdges, e)
		} else if e.Orientation == rawdata.EdgeVertical {
			vEdges = append(vEdges, e)
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
