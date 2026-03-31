package table

import (
	"sort"
	"strings"

	"github.com/pymupdf4llm-c/go/internal/geometry"
	"github.com/pymupdf4llm-c/go/internal/models"
	rawdata "github.com/pymupdf4llm-c/go/internal/raw"
	"github.com/pymupdf4llm-c/go/internal/textutil"
)

// ExtractAndConvertTables runs a linear extraction flow with boundary checks only.
func ExtractAndConvertTables(raw *rawdata.PageData) []models.Block {
	if raw == nil {
		return nil
	}
	pipeline := newTableExtractionPipeline()
	return pipeline.run(raw)
}

type tableExtractionPipeline struct {
	detector     tableDetector
	materializer tableMaterializer
	selector     tableSelector
	converter    tableConverter
}

type detectedTables struct{ tables []Table }
type materializedTables struct{ tables []Table }
type selectedTables struct{ tables []Table }

func newTableExtractionPipeline() tableExtractionPipeline {
	return tableExtractionPipeline{}
}

func (p tableExtractionPipeline) run(raw *rawdata.PageData) []models.Block {
	detected := p.detector.run(raw)
	if len(detected.tables) == 0 {
		return nil
	}
	materialized := p.materializer.run(raw, detected)
	selected := p.selector.run(raw.PageRect(), materialized)
	if len(selected.tables) == 0 {
		borderlessDetected := p.detector.runBorderless(raw)
		if len(borderlessDetected.tables) == 0 {
			return nil
		}
		borderlessMaterialized := p.materializer.run(raw, borderlessDetected)
		selected = p.selector.run(raw.PageRect(), borderlessMaterialized)
		if len(selected.tables) == 0 {
			return nil
		}
	}
	return p.converter.run(selected)
}

type tableDetector struct{}

func (s tableDetector) run(raw *rawdata.PageData) detectedTables {
	pageRect := raw.PageRect()
	// Reduced edge threshold from 5 to 3 to detect tables with fewer borders
	if len(raw.Edges) >= 3 && !(len(raw.Edges) > maxEdgesForGrid && len(raw.Chars) > heavyCharCount) {
		tables := detectTables(raw.Edges, pageRect, raw.PageNumber)
		if tables != nil && !tables.isEmpty() {
			return detectedTables{tables: tables.Tables}
		}
	}
	return s.runBorderless(raw)
}

func (s tableDetector) runBorderless(raw *rawdata.PageData) detectedTables {
	pageRect := raw.PageRect()
	tables := detectBorderlessTables(raw, pageRect)
	if tables == nil || tables.isEmpty() {
		return detectedTables{}
	}
	return detectedTables{tables: tables.Tables}
}

type tableMaterializer struct{}

func (s tableMaterializer) run(raw *rawdata.PageData, in detectedTables) materializedTables {
	if len(in.tables) == 0 {
		return materializedTables{}
	}
	tables := in.tables
	for ti := range tables {
		tbl := &tables[ti]
		tableChars := charsNearRect(raw.Chars, tbl.BBox)
		if len(tableChars) == 0 {
			continue
		}
		for ri := range tbl.Rows {
			for ci := range tbl.Rows[ri].Cells {
				cell := &tbl.Rows[ri].Cells[ci]
				if cell.BBox.IsEmpty() {
					continue
				}
				cell.BBox = shrinkCellToContent(cell.BBox, tableChars)
				cell.Text = extractTextInRect(raw, cell.BBox)
			}
		}
		cleanupMaterializedTable(tbl)
	}
	return materializedTables{tables: tables}
}

type tableSelector struct{}

func (s tableSelector) run(pageRect geometry.Rect, in materializedTables) selectedTables {
	if len(in.tables) == 0 {
		return selectedTables{}
	}
	candidates := make([]Table, 0, len(in.tables))
	for _, tbl := range in.tables {
		if !hasTableShape(tbl) || isTableOversized(tbl.BBox, pageRect) {
			continue
		}
		candidates = append(candidates, tbl)
	}
	if len(candidates) == 0 {
		return selectedTables{}
	}
	return selectedTables{tables: deduplicateTables(candidates)}
}

type tableConverter struct{}

func (s tableConverter) run(in selectedTables) []models.Block {
	blocks := make([]models.Block, 0, len(in.tables))
	for _, tbl := range in.tables {
		rows, visibleRows := convertTableRows(tbl)
		if visibleRows == 0 || len(rows) < 2 || len(rows[0].Cells) < 2 {
			continue
		}
		colCount := len(rows[0].Cells)
		blocks = append(blocks, models.Block{
			Type:      models.BlockTable,
			BBox:      models.BBox{tbl.BBox.X0, tbl.BBox.Y0, tbl.BBox.X1, tbl.BBox.Y1},
			RowCount:  visibleRows,
			ColCount:  colCount,
			CellCount: visibleRows * colCount,
			Rows:      rows,
		})
	}
	return blocks
}

func hasTableShape(tbl Table) bool {
	if len(tbl.Rows) < 2 {
		return false
	}
	return len(tbl.Rows[0].Cells) >= 2
}

func isTableOversized(tableRect, pageRect geometry.Rect) bool {
	if tableRect.IsEmpty() || pageRect.IsEmpty() {
		return true
	}
	return tableRect.Height()/pageRect.Height() > 0.97 || tableRect.Width()/pageRect.Width() > 0.99
}

func deduplicateTables(tables []Table) []Table {
	keep := make([]bool, len(tables))
	for i := range keep {
		keep[i] = true
	}
	for i := 0; i < len(tables); i++ {
		if !keep[i] {
			continue
		}
		for j := i + 1; j < len(tables); j++ {
			if !keep[j] {
				continue
			}
			if tables[i].BBox.IoU(tables[j].BBox) <= 0.95 {
				continue
			}
			if tableScore(tables[i]) >= tableScore(tables[j]) {
				keep[j] = false
			} else {
				keep[i] = false
				break
			}
		}
	}
	out := make([]Table, 0, len(tables))
	for i, ok := range keep {
		if ok {
			out = append(out, tables[i])
		}
	}
	return out
}

func tableScore(tbl Table) int {
	if len(tbl.Rows) == 0 {
		return 0
	}
	return len(tbl.Rows)*100 + len(tbl.Rows[0].Cells)
}

func charsNearRect(chars []rawdata.Char, rect geometry.Rect) []rawdata.Char {
	out := make([]rawdata.Char, 0, 256)
	for _, ch := range chars {
		if ch.BBox.X0 < rect.X1+2 && ch.BBox.X1 > rect.X0-2 && ch.BBox.Y0 < rect.Y1+2 && ch.BBox.Y1 > rect.Y0-2 {
			out = append(out, ch)
		}
	}
	return out
}

func shrinkCellToContent(cell geometry.Rect, chars []rawdata.Char) geometry.Rect {
	search := geometry.Rect{X0: cell.X0 - 2, Y0: cell.Y0 - 2, X1: cell.X1 + 2, Y1: cell.Y1 + 2}
	content := geometry.Empty
	for _, ch := range chars {
		if ch.BBox.X0 < search.X1 && ch.BBox.X1 > search.X0 && ch.BBox.Y0 < search.Y1 && ch.BBox.Y1 > search.Y0 {
			content = content.Union(geometry.Rect{X0: ch.BBox.X0, Y0: ch.BBox.Y0, X1: ch.BBox.X1, Y1: ch.BBox.Y1})
		}
	}
	if content.IsEmpty() {
		return cell
	}
	return geometry.Rect{
		X0: geometry.Max32(cell.X0, content.X0),
		Y0: geometry.Max32(cell.Y0, content.Y0),
		X1: geometry.Min32(cell.X1, content.X1),
		Y1: geometry.Min32(cell.Y1, content.Y1),
	}
}

func extractTextInRect(raw *rawdata.PageData, rect geometry.Rect) string {
	indices := raw.CharIndicesInRect(rect, nil)
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

	chars := make([]rawdata.Char, len(indices))
	for i, idx := range indices {
		chars[i] = raw.Chars[idx]
	}
	assembler := textutil.NewTextAssembler(textutil.AssembleOptions{
		InsertSpaces:       true,
		Normalize:          true,
		MergeNumericSpaces: true,
	})
	return assembler.AssembleOrderedChars(chars)
}

func convertTableRows(tbl Table) ([]models.TableRow, int) {
	preserveEmptyCols := shouldPreserveEmptyColumns(tbl)
	rows := make([]models.TableRow, 0, len(tbl.Rows))
	visibleRows := 0
	for _, r := range tbl.Rows {
		cells := make([]models.TableCell, 0, len(r.Cells))
		hasVisible := false
		for _, c := range r.Cells {
			if c.BBox.IsEmpty() && !preserveEmptyCols {
				continue
			}
			text := strings.TrimSpace(c.Text)
			var spans []models.Span
			if text != "" {
				hasVisible = true
				spans = []models.Span{{Text: text}}
			}
			cells = append(cells, models.TableCell{BBox: models.BBox{c.BBox.X0, c.BBox.Y0, c.BBox.X1, c.BBox.Y1}, Spans: spans})
		}
		if len(cells) == 0 {
			continue
		}
		if hasVisible {
			visibleRows++
		}
		rows = append(rows, models.TableRow{BBox: models.BBox{r.BBox.X0, r.BBox.Y0, r.BBox.X1, r.BBox.Y1}, Cells: cells})
	}
	return rows, visibleRows
}

func cleanupMaterializedTable(tbl *Table) {
	if tbl == nil || len(tbl.Rows) == 0 {
		return
	}
	maxCols := 0
	for _, row := range tbl.Rows {
		if len(row.Cells) > maxCols {
			maxCols = len(row.Cells)
		}
	}
	if maxCols == 0 {
		return
	}
	for i := range tbl.Rows {
		if len(tbl.Rows[i].Cells) >= maxCols {
			continue
		}
		padded := make([]Cell, maxCols)
		copy(padded, tbl.Rows[i].Cells)
		tbl.Rows[i].Cells = padded
	}
	dropTextEmptyColumns(tbl)
	mergeCurrencyValueColumns(tbl)
}

func dropTextEmptyColumns(tbl *Table) {
	if tbl == nil || len(tbl.Rows) == 0 || len(tbl.Rows[0].Cells) == 0 {
		return
	}
	colCount := len(tbl.Rows[0].Cells)
	keep := make([]bool, colCount)
	for _, row := range tbl.Rows {
		for ci := 0; ci < min(colCount, len(row.Cells)); ci++ {
			if strings.TrimSpace(row.Cells[ci].Text) != "" {
				keep[ci] = true
			}
		}
	}
	newCount := 0
	for _, ok := range keep {
		if ok {
			newCount++
		}
	}
	if newCount == 0 || newCount == colCount {
		return
	}
	for ri := range tbl.Rows {
		newCells := make([]Cell, 0, newCount)
		for ci, ok := range keep {
			if ok && ci < len(tbl.Rows[ri].Cells) {
				newCells = append(newCells, tbl.Rows[ri].Cells[ci])
			}
		}
		tbl.Rows[ri].Cells = newCells
	}
}

func mergeCurrencyValueColumns(tbl *Table) {
	if tbl == nil || len(tbl.Rows) == 0 || len(tbl.Rows[0].Cells) < 2 {
		return
	}
	colCount := len(tbl.Rows[0].Cells)
	for ci := 0; ci < colCount-1; ci++ {
		prefixRows := 0
		for _, row := range tbl.Rows {
			if ci+1 >= len(row.Cells) {
				continue
			}
			left := strings.TrimSpace(row.Cells[ci].Text)
			right := strings.TrimSpace(row.Cells[ci+1].Text)
			if isCurrencyPrefix(left) && looksNumericValue(right) {
				prefixRows++
			}
		}
		if prefixRows == 0 {
			continue
		}
		for ri := range tbl.Rows {
			if ci+1 >= len(tbl.Rows[ri].Cells) {
				continue
			}
			left := strings.TrimSpace(tbl.Rows[ri].Cells[ci].Text)
			right := strings.TrimSpace(tbl.Rows[ri].Cells[ci+1].Text)
			if !isCurrencyPrefix(left) || !looksNumericValue(right) {
				continue
			}
			tbl.Rows[ri].Cells[ci+1].Text = left + right
			tbl.Rows[ri].Cells[ci+1].BBox = tbl.Rows[ri].Cells[ci].BBox.Union(tbl.Rows[ri].Cells[ci+1].BBox)
			tbl.Rows[ri].Cells[ci] = Cell{}
		}
		dropTextEmptyColumns(tbl)
		colCount = len(tbl.Rows[0].Cells)
		ci--
	}
}

func isCurrencyPrefix(s string) bool {
	switch s {
	case "$", "€", "£", "¥":
		return true
	default:
		return false
	}
}

func looksNumericValue(s string) bool {
	hasDigit := false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			hasDigit = true
			continue
		}
		switch r {
		case ',', '.', ' ', '-', '(', ')':
		default:
			return false
		}
	}
	return hasDigit
}
