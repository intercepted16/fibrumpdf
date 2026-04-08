package table

import (
	"math"
	"sort"
	"strings"

	"github.com/fibrumpdf/go/internal/geometry"
	"github.com/fibrumpdf/go/internal/models"
	rawdata "github.com/fibrumpdf/go/internal/raw"
	"github.com/fibrumpdf/go/internal/textutil"
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
	selected := selectedTables{}
	if len(detected.tables) > 0 {
		materialized := p.materializer.run(raw, detected)
		selected = p.selector.run(raw.PageRect(), raw, materialized)
		if len(selected.tables) > 0 && shouldTryBorderlessFallback(selected.tables) {
			borderlessDetected := p.detector.runBorderless(raw)
			if len(borderlessDetected.tables) > 0 {
				borderlessMaterialized := p.materializer.run(raw, borderlessDetected)
				borderlessSelected := p.selector.run(raw.PageRect(), raw, borderlessMaterialized)
				if chooseBetterTables(borderlessSelected.tables, selected.tables) {
					selected = borderlessSelected
				}
			}
		}
	}
	if len(selected.tables) == 0 {
		borderlessDetected := p.detector.runBorderless(raw)
		if len(borderlessDetected.tables) == 0 {
			return nil
		}
		borderlessMaterialized := p.materializer.run(raw, borderlessDetected)
		selected = p.selector.run(raw.PageRect(), raw, borderlessMaterialized)
		if len(selected.tables) == 0 {
			return nil
		}
	}
	return p.converter.run(selected)
}

func shouldTryBorderlessFallback(tables []Table) bool {
	for _, tbl := range tables {
		if !tbl.RuledTable {
			continue
		}
		if ruledTableLooksOversegmented(tbl) {
			return true
		}
	}
	return false
}

func ruledTableLooksOversegmented(tbl Table) bool {
	if len(tbl.Rows) < 2 {
		return false
	}
	fragmentCells := 0
	nonEmpty := 0
	for _, row := range tbl.Rows {
		for _, cell := range row.Cells {
			text := strings.TrimSpace(cell.Text)
			if text == "" {
				continue
			}
			nonEmpty++
			runes := []rune(strings.ReplaceAll(text, "<br>", " "))
			if len(runes) > 0 && len(runes) <= 3 {
				letters := 0
				for _, r := range runes {
					if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= 0xC0 && r <= 0x02AF) {
						letters++
					}
				}
				if letters >= 2 {
					fragmentCells++
				}
			}
		}
	}
	if nonEmpty == 0 {
		return false
	}
	return float32(fragmentCells)/float32(nonEmpty) >= 0.22
}

func chooseBetterTables(candidate, current []Table) bool {
	if len(candidate) == 0 {
		return false
	}
	if len(current) == 0 {
		return true
	}
	return tableSetQualityScore(candidate) > tableSetQualityScore(current)
}

func tableSetQualityScore(tables []Table) float32 {
	score := float32(0)
	for _, tbl := range tables {
		populated := 0
		total := 0
		for _, row := range tbl.Rows {
			for _, cell := range row.Cells {
				total++
				if strings.TrimSpace(cell.Text) != "" {
					populated++
				}
			}
		}
		if total == 0 {
			continue
		}
		fill := float32(populated) / float32(total)
		score += fill * float32(len(tbl.Rows)+1)
	}
	return score
}

type tableDetector struct{}

func (s tableDetector) run(raw *rawdata.PageData) detectedTables {
	pageRect := raw.PageRect()
	// Try grid-based detection first (requires edges)
	if len(raw.Edges) >= 3 && (len(raw.Edges) <= maxEdgesForGrid || len(raw.Chars) <= heavyCharCount) {
		tables := detectTables(raw.Edges, pageRect, raw.PageNumber)
		if tables != nil && !tables.isEmpty() {
			return detectedTables{tables: tables.Tables}
		}
	}
	// No grid tables found - return empty, let pipeline try borderless
	return detectedTables{}
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
				cell.Text = extractTextInRectFromChars(tableChars, cell.BBox, !tbl.RuledTable)
				if cell.Text == "" {
					cell.Text = extractTextInRect(raw, cell.BBox)
				}
			}
		}
		cleanupMaterializedTable(tbl)
	}
	return materializedTables{tables: tables}
}

type tableSelector struct{}

func (s tableSelector) run(pageRect geometry.Rect, raw *rawdata.PageData, in materializedTables) selectedTables {
	if len(in.tables) == 0 {
		return selectedTables{}
	}
	candidates := make([]Table, 0, len(in.tables))
	for _, tbl := range in.tables {
		if !hasTableShape(tbl) || isTableOversized(tbl.BBox, pageRect) {
			continue
		}
		// Skip content validation for now - too risky for recall
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
		if len(rows) < 2 {
			continue
		}
		activeCols := make(map[int]struct{})
		maxCols := 0
		rowsWithTwoPopulated := 0
		for _, row := range rows {
			if len(row.Cells) > maxCols {
				maxCols = len(row.Cells)
			}
			populated := 0
			for ci, cell := range row.Cells {
				if len(cell.Spans) > 0 && strings.TrimSpace(cell.Spans[0].Text) != "" {
					populated++
					activeCols[ci] = struct{}{}
				}
			}
			if populated >= 2 {
				rowsWithTwoPopulated++
			}
		}
		colCount := len(activeCols)
		if tbl.RuledTable {
			if colCount < 2 {
				colCount = maxCols
			}
			if visibleRows == 0 {
				if maxCols < 3 || len(rows) < 3 {
					continue
				}
				visibleRows = len(rows)
			}
			if colCount < 2 || rowsWithTwoPopulated == 0 {
				if maxCols < 3 || len(rows) < 3 {
					continue
				}
			}
		} else {
			if visibleRows == 0 || colCount < 2 || rowsWithTwoPopulated < 2 {
				continue
			}
			if float32(rowsWithTwoPopulated)/float32(visibleRows) < 0.25 {
				continue
			}
			if looksLikeCaptionContaminatedTable(rows, rowsWithTwoPopulated, visibleRows) {
				continue
			}
		}

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

func looksLikeCaptionContaminatedTable(rows []models.TableRow, rowsWithTwoPopulated, visibleRows int) bool {
	if len(rows) == 0 || visibleRows < 2 {
		return false
	}
	if float32(rowsWithTwoPopulated)/float32(visibleRows) >= 0.60 {
		return false
	}
	for i := 0; i < len(rows) && i < 2; i++ {
		for _, cell := range rows[i].Cells {
			if len(cell.Spans) == 0 {
				continue
			}
			if looksLikeTableCaption(cell.Spans[0].Text) {
				return true
			}
		}
	}
	return false
}

func looksLikeTableCaption(text string) bool {
	t := strings.ToLower(strings.TrimSpace(text))
	if t == "" {
		return false
	}
	hasDigit := false
	for _, r := range t {
		if r >= '0' && r <= '9' {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		return false
	}
	keywords := []string{"table", "tabla", "tabela", "tabelle", "tabella", "tablo", "таблица"}
	for _, kw := range keywords {
		if strings.HasPrefix(t, kw+" ") || strings.HasPrefix(t, kw+".") || strings.HasPrefix(t, kw+":") {
			return true
		}
	}
	return false
}

func hasTableShape(tbl Table) bool {
	if len(tbl.Rows) < 2 {
		return false
	}
	rowsWithTwoCols := 0
	activeCols := make(map[int]struct{})
	for _, row := range tbl.Rows {
		if len(row.Cells) >= 2 {
			rowsWithTwoCols++
		}
		for ci, cell := range row.Cells {
			if strings.TrimSpace(cell.Text) != "" {
				activeCols[ci] = struct{}{}
			}
		}
	}
	return rowsWithTwoCols >= 1 && len(activeCols) >= 2
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
	if len(chars) == 0 {
		return nil
	}
	out := make([]rawdata.Char, 0, min(256, len(chars)))
	x0, y0, x1, y1 := rect.X0-2, rect.Y0-2, rect.X1+2, rect.Y1+2
	for i := range chars {
		ch := &chars[i]
		if ch.BBox.X0 < x1 && ch.BBox.X1 > x0 && ch.BBox.Y0 < y1 && ch.BBox.Y1 > y0 {
			out = append(out, *ch)
		}
	}
	return out
}

func shrinkCellToContent(cell geometry.Rect, chars []rawdata.Char) geometry.Rect {
	x0, y0, x1, y1 := cell.X0-2, cell.Y0-2, cell.X1+2, cell.Y1+2
	content := geometry.Empty
	for i := range chars {
		ch := &chars[i]
		if ch.BBox.X0 < x1 && ch.BBox.X1 > x0 && ch.BBox.Y0 < y1 && ch.BBox.Y1 > y0 {
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

type charRectSorter struct {
	indices []int
	chars   []rawdata.Char
}

func (s charRectSorter) Len() int      { return len(s.indices) }
func (s charRectSorter) Swap(i, j int) { s.indices[i], s.indices[j] = s.indices[j], s.indices[i] }
func (s charRectSorter) Less(i, j int) bool {
	a := &s.chars[s.indices[i]]
	b := &s.chars[s.indices[j]]
	ay, by := (a.BBox.Y0+a.BBox.Y1)*0.5, (b.BBox.Y0+b.BBox.Y1)*0.5
	lineTol := geometry.Max32(geometry.Max32(a.Size, b.Size)*0.45, 0.8)
	dyDiff := ay - by
	if dyDiff < -lineTol {
		return true
	}
	if dyDiff > lineTol {
		return false
	}
	dx := a.BBox.X0 - b.BBox.X0
	if dx < -0.3 {
		return true
	}
	if dx > 0.3 {
		return false
	}
	return s.indices[i] < s.indices[j]
}

func extractTextInRect(raw *rawdata.PageData, rect geometry.Rect) string {
	indices := raw.CharIndicesInRect(rect, nil)
	if len(indices) == 0 {
		return ""
	}
	sorter := charRectSorter{indices: indices, chars: raw.Chars}
	sort.Stable(sorter)

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

func extractTextInRectFromChars(chars []rawdata.Char, rect geometry.Rect, allowOverlapFallback bool) string {
	if len(chars) == 0 || rect.IsEmpty() {
		return ""
	}
	selected := make([]rawdata.Char, 0, 16)
	xMin, xMax := rect.X0+0.1, rect.X1-0.1
	yMin, yMax := rect.Y0+0.1, rect.Y1-0.1
	for i := range chars {
		ch := chars[i]
		cx := (ch.BBox.X0 + ch.BBox.X1) * 0.5
		cy := (ch.BBox.Y0 + ch.BBox.Y1) * 0.5
		if cx >= xMin && cx <= xMax && cy >= yMin && cy <= yMax {
			selected = append(selected, ch)
		}
	}
	if allowOverlapFallback && len(selected) == 0 {
		for i := range chars {
			ch := chars[i]
			if ch.BBox.X0 < rect.X1 && ch.BBox.X1 > rect.X0 && ch.BBox.Y0 < rect.Y1 && ch.BBox.Y1 > rect.Y0 {
				selected = append(selected, ch)
			}
		}
	}
	if len(selected) == 0 {
		return ""
	}
	indices := make([]int, len(selected))
	for i := range selected {
		indices[i] = i
	}
	sorter := charRectSorter{indices: indices, chars: selected}
	sort.Stable(sorter)
	ordered := make([]rawdata.Char, len(indices))
	for i, idx := range indices {
		ordered[i] = selected[idx]
	}

	lines := splitCharsIntoLines(ordered)
	assembler := textutil.NewTextAssembler(textutil.AssembleOptions{
		InsertSpaces:       true,
		Normalize:          true,
		MergeNumericSpaces: true,
	})
	if len(lines) <= 1 {
		return assembler.AssembleOrderedChars(ordered)
	}
	parts := make([]string, 0, len(lines))
	for _, line := range lines {
		lineText := strings.TrimSpace(assembler.AssembleOrderedChars(line))
		if lineText != "" {
			parts = append(parts, lineText)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "<br>")
}

func splitCharsIntoLines(chars []rawdata.Char) [][]rawdata.Char {
	if len(chars) == 0 {
		return nil
	}
	lines := make([][]rawdata.Char, 0, 4)
	cur := make([]rawdata.Char, 0, 16)
	lineY := float32(0)
	hasLine := false
	for _, ch := range chars {
		cy := (ch.BBox.Y0 + ch.BBox.Y1) * 0.5
		lineTol := geometry.Max32(ch.Size*0.7, 1.2)
		if !hasLine {
			cur = append(cur, ch)
			lineY = cy
			hasLine = true
			continue
		}
		if geometry.Abs32(cy-lineY) > lineTol {
			sort.SliceStable(cur, func(i, j int) bool { return cur[i].BBox.X0 < cur[j].BBox.X0 })
			lines = append(lines, cur)
			cur = make([]rawdata.Char, 0, 16)
			lineY = cy
		}
		cur = append(cur, ch)
	}
	if len(cur) > 0 {
		sort.SliceStable(cur, func(i, j int) bool { return cur[i].BBox.X0 < cur[j].BBox.X0 })
		lines = append(lines, cur)
	}
	return lines
}

func convertTableRows(tbl Table) ([]models.TableRow, int) {
	preserveEmptyCols := tbl.RuledTable || shouldPreserveEmptyColumns(tbl)
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
	if tbl.RuledTable {
		dropFullyEmptyColumns(tbl)
		splitPairedLineRows(tbl)
	} else {
		dropTextEmptyColumns(tbl)
		mergeCurrencyValueColumns(tbl)
	}
	mergeContinuationRows(tbl)
}

func dropFullyEmptyColumns(tbl *Table) {
	if tbl == nil || len(tbl.Rows) == 0 || len(tbl.Rows[0].Cells) == 0 {
		return
	}
	colCount := len(tbl.Rows[0].Cells)
	keep := make([]bool, colCount)
	for _, row := range tbl.Rows {
		for ci := 0; ci < min(colCount, len(row.Cells)); ci++ {
			if !row.Cells[ci].BBox.IsEmpty() || strings.TrimSpace(row.Cells[ci].Text) != "" {
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

func mergeContinuationRows(tbl *Table) {
	if tbl == nil || len(tbl.Rows) < 2 {
		return
	}

	gapLimit := continuationGapLimit(tbl.Rows)
	keep := make([]Row, 0, len(tbl.Rows))
	keep = append(keep, tbl.Rows[0])

	for ri := 1; ri < len(tbl.Rows); ri++ {
		curr := tbl.Rows[ri]
		prev := &keep[len(keep)-1]

		currCount, currCol := populatedCellInfo(curr)
		prevCount, _ := populatedCellInfo(*prev)
		if currCount != 1 || prevCount < 2 || currCol < 0 || currCol >= len(prev.Cells) {
			keep = append(keep, curr)
			continue
		}

		currText := strings.TrimSpace(curr.Cells[currCol].Text)
		if currText == "" || looksLikeTableCaption(currText) {
			keep = append(keep, curr)
			continue
		}
		if textHasDigit(currText) || len([]rune(currText)) > 24 {
			keep = append(keep, curr)
			continue
		}

		gap := curr.BBox.Y0 - prev.BBox.Y1
		if gap > gapLimit {
			keep = append(keep, curr)
			continue
		}

		if curr.BBox.X0 > prev.BBox.X1 || curr.BBox.X1 < prev.BBox.X0 {
			keep = append(keep, curr)
			continue
		}

		mergedText := strings.TrimSpace(prev.Cells[currCol].Text)
		if mergedText == "" {
			prev.Cells[currCol].Text = currText
		} else {
			prev.Cells[currCol].Text = mergedText + " " + currText
		}
		if prev.Cells[currCol].BBox.IsEmpty() {
			prev.Cells[currCol].BBox = curr.Cells[currCol].BBox
		} else {
			prev.Cells[currCol].BBox = prev.Cells[currCol].BBox.Union(curr.Cells[currCol].BBox)
		}
		if !curr.BBox.IsEmpty() {
			if prev.BBox.IsEmpty() {
				prev.BBox = curr.BBox
			} else {
				prev.BBox = prev.BBox.Union(curr.BBox)
			}
		}
	}

	tbl.Rows = keep
}

func continuationGapLimit(rows []Row) float32 {
	var heights []float32
	for _, row := range rows {
		h := row.BBox.Height()
		if h > 0 {
			heights = append(heights, h)
		}
	}
	if len(heights) == 0 {
		return 0
	}
	sort.Slice(heights, func(i, j int) bool { return heights[i] < heights[j] })
	median := heights[len(heights)/2]
	return float32(math.Max(float64(median*0.45), 1.5))
}

func populatedCellInfo(row Row) (count int, lastCol int) {
	lastCol = -1
	for ci := range row.Cells {
		if strings.TrimSpace(row.Cells[ci].Text) == "" {
			continue
		}
		count++
		lastCol = ci
	}
	return count, lastCol
}

func textHasDigit(text string) bool {
	for _, r := range text {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
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

func splitPairedLineRows(tbl *Table) {
	if tbl == nil || len(tbl.Rows) == 0 {
		return
	}
	rows := make([]Row, 0, len(tbl.Rows))
	for _, row := range tbl.Rows {
		populated := 0
		paired := 0
		for ci := range row.Cells {
			text := strings.TrimSpace(row.Cells[ci].Text)
			if text == "" {
				continue
			}
			populated++
			parts := splitLineParts(text)
			if len(parts) != 2 {
				continue
			}
			if len([]rune(parts[0])) > 24 || len([]rune(parts[1])) > 24 {
				continue
			}
			paired++
		}
		if populated < 3 || paired < 3 || paired*2 < populated {
			rows = append(rows, row)
			continue
		}

		top := Row{Cells: make([]Cell, len(row.Cells))}
		bottom := Row{Cells: make([]Cell, len(row.Cells))}
		for ci := range row.Cells {
			cell := row.Cells[ci]
			parts := splitLineParts(cell.Text)
			if len(parts) == 2 {
				top.Cells[ci].Text = parts[0]
				bottom.Cells[ci].Text = parts[1]
			} else {
				top.Cells[ci].Text = strings.TrimSpace(cell.Text)
			}
			if cell.BBox.IsEmpty() {
				continue
			}
			mid := (cell.BBox.Y0 + cell.BBox.Y1) * 0.5
			topBBox := geometry.Rect{X0: cell.BBox.X0, Y0: cell.BBox.Y0, X1: cell.BBox.X1, Y1: mid}
			bottomBBox := geometry.Rect{X0: cell.BBox.X0, Y0: mid, X1: cell.BBox.X1, Y1: cell.BBox.Y1}
			top.Cells[ci].BBox = topBBox
			if len(parts) == 2 {
				bottom.Cells[ci].BBox = bottomBBox
			}
			if top.BBox.IsEmpty() {
				top.BBox = topBBox
			} else {
				top.BBox = top.BBox.Union(topBBox)
			}
			if len(parts) == 2 {
				if bottom.BBox.IsEmpty() {
					bottom.BBox = bottomBBox
				} else {
					bottom.BBox = bottom.BBox.Union(bottomBBox)
				}
			}
		}
		rows = append(rows, top)
		if !bottom.BBox.IsEmpty() {
			rows = append(rows, bottom)
		}
	}
	tbl.Rows = rows
}

func splitLineParts(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	raw := strings.Split(text, "<br>")
	parts := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
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
