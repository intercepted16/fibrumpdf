package table

import (
	"math"
	"sort"
	"strings"

	"github.com/fibrumpdf/go/internal/bridge"
	"github.com/fibrumpdf/go/internal/geometry"
	"github.com/fibrumpdf/go/internal/logger"
	"github.com/fibrumpdf/go/internal/models"
	"github.com/tidwall/rtree"
)

var Logger = logger.GetLogger("table")

const (
	snapTolRatio   = 0.005
	joinTolRatio   = 0.005
	minCellRatio   = 0.005
	maxCellWRatio  = 0.95
	maxCellHRatio  = 0.20
	splitGapRatio  = 0.10
	rowYTolRatio   = 0.015
	colXTolRatio   = 0.003
	intersectRatio = 0.0015
	coordScale     = 1000.0
)

type Edge struct {
	X0, Y0, X1, Y1 float64
	Orientation    byte
}

type Cell struct {
	BBox geometry.Rect
	Text string
}

type Row struct {
	BBox  geometry.Rect
	Cells []Cell
}

type Table struct {
	BBox geometry.Rect
	Rows []Row
}

type TableArray struct{ Tables []Table }

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

func findCells(points []geometry.Point, tr *rtree.RTreeG[geometry.Point], pageRect geometry.Rect, hEdges, vEdges []Edge) []geometry.Rect {
	if len(points) < 4 {
		return nil
	}
	pw, ph := pageRect.Width(), pageRect.Height()
	diag := float32(math.Sqrt(float64(pw*pw + ph*ph)))
	minSize, maxW, maxH := geometry.Min32(pw, ph)*minCellRatio, pw*maxCellWRatio, ph*maxCellHRatio
	snapDist, eps := pw*snapTolRatio, float64(diag*intersectRatio)
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
	var cells []geometry.Rect
	for i, p1 := range snapped {
		for j := i + 1; j < len(snapped); j++ {
			if float64(snapped[j].Y-p1.Y) > eps {
				break
			}
			p2 := snapped[j]
			if p2.X <= p1.X+minSize || !hasEdge(hEdges, float64(p1.X), float64(p1.Y), float64(p2.X), float64(p2.Y), eps) {
				continue
			}
			for _, p3 := range snapped {
				if p3.Y <= p1.Y+minSize || math.Abs(float64(p3.X-p1.X)) > eps || !hasEdge(vEdges, float64(p1.X), float64(p1.Y), float64(p3.X), float64(p3.Y), eps) {
					continue
				}
				found := false
				tr.Search([2]float64{float64(p2.X) - eps, float64(p3.Y) - eps}, [2]float64{float64(p2.X) + eps, float64(p3.Y) + eps}, func(_, _ [2]float64, _ geometry.Point) bool {
					if hasEdge(vEdges, float64(p2.X), float64(p2.Y), float64(p2.X), float64(p3.Y), eps) && hasEdge(hEdges, float64(p3.X), float64(p3.Y), float64(p2.X), float64(p3.Y), eps) {
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
	return cells
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
	splitGap := pageRect.Height() * splitGapRatio
	var avgH float32
	for _, c := range cells {
		avgH += c.Height()
	}
	avgH /= float32(len(cells))
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
		rowY0, yTol := cells[i].Y0, pageRect.Height()*rowYTolRatio
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
	normalizeColumns(tables, pageRect)
	filterValid(tables, pageRect)
	if len(tables.Tables) == 0 {
		return nil
	}
	return tables
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

func filterValid(tables *TableArray, pageRect geometry.Rect) {
	valid := tables.Tables[:0]
	for _, t := range tables.Tables {
		pruneEmpty(&t)
		if len(t.Rows) < 2 || len(t.Rows[0].Cells) < 2 {
			colsDesc := "0"
			if len(t.Rows) > 0 {
				colsDesc = string(rune('0' + len(t.Rows[0].Cells)))
			}
			Logger.Debug("table rejected: too few rows/cols", "rows", len(t.Rows), "cols", colsDesc)
			continue
		}
		hRatio, wRatio := t.BBox.Height()/pageRect.Height(), t.BBox.Width()/pageRect.Width()
		if hRatio > 0.95 || wRatio > 0.98 {
			Logger.Debug("table rejected: too large", "hRatio", hRatio, "wRatio", wRatio)
			continue
		}
		garbage := false
		for ri, row := range t.Rows {
			if len(row.Cells) < 2 {
				continue
			}
			var minH, maxH float32 = 1e6, 0
			cellCount := 0
			for _, cell := range row.Cells {
				if !cell.BBox.IsEmpty() {
					h := cell.BBox.Height()
					if h < minH {
						minH = h
					}
					if h > maxH {
						maxH = h
					}
					cellCount++
				}
			}
			if cellCount < 2 || minH <= 0 {
				continue
			}
			ratio := maxH / minH
			// Tables often have cells with multi-line text content
			// Header rows can have merged cells with varying heights
			// Allow higher ratio for header (ri==0) and second row which may contain sub-headers
			threshold := float32(6.0)
			if ri <= 1 {
				threshold = 8.0
			}
			if ratio > threshold {
				Logger.Debug("table rejected: garbage row", "rowIndex", ri, "minH", minH, "maxH", maxH)
				garbage = true
				break
			}
		}
		if garbage {
			continue
		}
		totalCells := 0
		for _, row := range t.Rows {
			for _, cell := range row.Cells {
				if !cell.BBox.IsEmpty() {
					totalCells++
				}
			}
		}
		if len(t.Rows) > 10 && totalCells < len(t.Rows)*2 {
			Logger.Debug("table rejected: too sparse", "rows", len(t.Rows), "totalCells", totalCells)
			continue
		}
		validRows, expectedCols, missingRows := 0, -1, 0
		for _, row := range t.Rows {
			if len(row.Cells) == 0 {
				continue
			}
			validRows++
			if expectedCols < 0 {
				expectedCols = len(row.Cells)
			} else if len(row.Cells) < expectedCols {
				missingRows++
			}
		}
		if validRows > 0 && float32(missingRows) > float32(validRows)*0.4 {
			Logger.Debug("table rejected: too many missing rows", "missingRows", missingRows, "validRows", validRows)
			continue
		}
		if validRows >= 2 && expectedCols >= 2 {
			valid = append(valid, t)
		} else {
			Logger.Debug("table rejected: final check failed", "validRows", validRows, "expectedCols", expectedCols)
		}
	}
	tables.Tables = valid
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
	var buf strings.Builder
	var prevX1, prevY0 float32 = -1000, -1000
	var prevR rune
	for i := range raw.Chars {
		ch := &raw.Chars[i]
		cx, cy := (ch.BBox.X0+ch.BBox.X1)/2, (ch.BBox.Y0+ch.BBox.Y1)/2
		if cx < rect.X0-2 || cx > rect.X1+2 || cy < rect.Y0-2 || cy > rect.Y1+2 || ch.Codepoint == 0 || ch.Codepoint == 0xFEFF {
			continue
		}
		if buf.Len() > 0 {
			yDiff, xGap := math.Abs(float64(ch.BBox.Y0-prevY0)), float64(ch.BBox.X0-prevX1)
			xTol, yTol := math.Max(float64(ch.Size*0.5), 3.0), math.Max(float64(ch.Size*0.3), 2.0)
			if isPunctOrDigit(ch.Codepoint) || isPunctOrDigit(prevR) {
				xTol, yTol = math.Max(xTol, 8.0), math.Max(yTol, 10.0)
			}
			if yDiff > yTol || xGap > xTol {
				buf.WriteByte(' ')
			}
		}
		buf.WriteRune(ch.Codepoint)
		prevX1, prevY0, prevR = ch.BBox.X1, ch.BBox.Y0, ch.Codepoint
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

func convertTableRows(tbl Table) ([]models.TableRow, int) {
	var rows []models.TableRow
	visibleRows := 0
	for _, r := range tbl.Rows {
		var cells []models.TableCell
		hasVisible := false
		for _, c := range r.Cells {
			if c.BBox.IsEmpty() {
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

func normalizeHeaderRow(rows *[]models.TableRow) {
	if len(*rows) == 0 {
		return
	}
	header := &(*rows)[0]
	nonEmpty := make([]models.TableCell, 0, len(header.Cells))
	for _, cell := range header.Cells {
		for _, span := range cell.Spans {
			if strings.TrimSpace(span.Text) != "" {
				nonEmpty = append(nonEmpty, cell)
				break
			}
		}
	}
	header.Cells = nonEmpty
	colCount := len(nonEmpty)
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

func ExtractAndConvertTables(raw *bridge.RawPageData) []models.Block {
	if len(raw.Edges) == 0 {
		return nil
	}
	Logger.Debug("extracting tables", "page", raw.PageNumber, "edges", len(raw.Edges))
	pageRect := geometry.Rect{X0: raw.PageBounds.X0, Y0: raw.PageBounds.Y0, X1: raw.PageBounds.X1, Y1: raw.PageBounds.Y1}
	tables := detectTables(raw.Edges, pageRect, raw.PageNumber)
	if tables == nil || len(tables.Tables) == 0 {
		Logger.Debug("no tables detected")
		return nil
	}
	Logger.Debug("detected tables", "count", len(tables.Tables))
	ShrinkCellsToContent(tables, raw.Chars)
	extractTextIntoCells(raw, tables)
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
	if len(hEdges) < 3 || len(vEdges) < 3 {
		return nil
	}
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
	cells := findCells(points, &tr, pageRect, hEdges, vEdges)
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
