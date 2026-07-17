package table

import (
	"sort"
	"strings"
	"unicode"

	"github.com/fibrumpdf/go/internal/geometry"
	"github.com/fibrumpdf/go/internal/models"
	rawdata "github.com/fibrumpdf/go/internal/raw"
	"github.com/fibrumpdf/go/internal/textutil"
)

func ExtractAndConvertTables(raw *rawdata.PageData) []models.Block {
	if raw == nil {
		return nil
	}
	pageRect := raw.PageRect()
	selected := selectTables(pageRect, materializeTables(raw, detectRuledTables(raw)))
	if len(selected) == 0 || needsBorderlessFallback(selected) {
		borderless := selectTables(pageRect, materializeTables(raw, detectBorderless(raw)))
		if chooseBetterTables(borderless, selected) {
			selected = borderless
		}
	}
	return convertTables(selected)
}

func detectRuledTables(raw *rawdata.PageData) []Table {
	if len(raw.Edges) >= 3 && (len(raw.Edges) <= maxEdgesForGrid || len(raw.Chars) <= heavyCharCount) {
		tables := detectTables(raw.Edges, raw.PageRect(), raw.PageNumber)
		if tables != nil && !tables.isEmpty() {
			return tables.Tables
		}
	}
	return nil
}

func detectBorderless(raw *rawdata.PageData) []Table {
	tables := detectBorderlessTables(raw, raw.PageRect())
	if tables == nil || tables.isEmpty() {
		return nil
	}
	return tables.Tables
}

func needsBorderlessFallback(tables []Table) bool {
	for _, tbl := range tables {
		if tbl.RuledTable && ruledTableLooksOversegmented(tbl) {
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

func materializeTables(raw *rawdata.PageData, detectedTables []Table) []Table {
	tables := make([]Table, 0, len(detectedTables))
	for _, detected := range detectedTables {
		tbl := detected
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
		cleanupMaterializedTable(&tbl)
		tables = append(tables, tbl)
	}
	return tables
}

func selectTables(pageRect geometry.Rect, tables []Table) []Table {
	candidates := make([]Table, 0, len(tables))
	for _, tbl := range tables {
		if !hasTableShape(tbl) || isTableOversized(tbl.BBox, pageRect) {
			continue
		}
		candidates = append(candidates, tbl)
	}
	return deduplicateTables(candidates)
}

func convertTables(tables []Table) []models.Block {
	blocks := make([]models.Block, 0, len(tables))
	for _, tbl := range tables {
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
	return tableRect.Width()/pageRect.Width() > 0.99
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
	var content geometry.Rect
	for i := range chars {
		ch := &chars[i]
		if ch.BBox.X0 < x1 && ch.BBox.X1 > x0 && ch.BBox.Y0 < y1 && ch.BBox.Y1 > y0 {
			r := geometry.Rect{X0: ch.BBox.X0, Y0: ch.BBox.Y0, X1: ch.BBox.X1, Y1: ch.BBox.Y1}
			if content.IsEmpty() {
				content = r
			} else {
				content = content.Union(r)
			}
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

func charReadingOrderLess(a, b rawdata.Char) bool {
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
	return false
}

func extractTextInRect(raw *rawdata.PageData, rect geometry.Rect) string {
	indices := raw.CharIndicesInRect(rect, nil)
	if len(indices) == 0 {
		return ""
	}
	chars := make([]rawdata.Char, len(indices))
	for i, idx := range indices {
		chars[i] = raw.Chars[idx]
	}
	sort.SliceStable(chars, func(i, j int) bool { return charReadingOrderLess(chars[i], chars[j]) })
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
		cx, cy := (ch.BBox.X0+ch.BBox.X1)*0.5, (ch.BBox.Y0+ch.BBox.Y1)*0.5
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
	sort.SliceStable(selected, func(i, j int) bool { return charReadingOrderLess(selected[i], selected[j]) })

	lines := splitCharsIntoLines(selected)
	assembler := textutil.NewTextAssembler(textutil.AssembleOptions{
		InsertSpaces:       true,
		Normalize:          true,
		MergeNumericSpaces: true,
	})
	if len(lines) <= 1 {
		return assembler.AssembleOrderedChars(selected)
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
	for i, ch := range chars {
		if i == 0 {
			cur = append(cur, ch)
			lineY = (ch.BBox.Y0 + ch.BBox.Y1) * 0.5
			continue
		}
		cy := (ch.BBox.Y0 + ch.BBox.Y1) * 0.5
		lineTol := geometry.Max32(ch.Size*0.7, 1.2)
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
	rows := make([]models.TableRow, 0, len(tbl.Rows))
	visibleRows := 0
	for _, r := range tbl.Rows {
		cells := make([]models.TableCell, 0, len(r.Cells))
		hasVisible := false
		for _, c := range r.Cells {
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

func cleanupMaterializedTable(table *Table) {
	if table == nil || len(table.Rows) == 0 {
		return
	}
	padRows(table)
	if table.RuledTable {
		mergeJoinedColumns(table)
	}
	dropTextEmptyColumns(table)
}

func mergeJoinedColumns(table *Table) {
	for column := 0; column+1 < len(table.Rows[0].Cells); {
		if !columnsContainJoinedText(table, column) {
			column++
			continue
		}
		for rowIndex := range table.Rows {
			row := &table.Rows[rowIndex]
			left, right := row.Cells[column], row.Cells[column+1]
			if strings.TrimSpace(left.Text) == "" {
				left = right
			} else if strings.TrimSpace(right.Text) != "" {
				left.Text = strings.TrimSpace(left.Text) + strings.TrimSpace(right.Text)
				left.BBox = left.BBox.Union(right.BBox)
			}
			row.Cells[column] = left
			row.Cells = append(row.Cells[:column+1], row.Cells[column+2:]...)
		}
		if column > 0 {
			column--
		}
	}
}

func columnsContainJoinedText(table *Table, column int) bool {
	found := false
	for _, row := range table.Rows {
		left, right := row.Cells[column], row.Cells[column+1]
		leftText, rightText := strings.TrimSpace(left.Text), strings.TrimSpace(right.Text)
		if leftText == "" || rightText == "" {
			continue
		}
		if gap := right.BBox.X0 - left.BBox.X1; gap < -1 || gap > 2 {
			return false
		}
		leftRunes, rightRunes := []rune(leftText), []rune(rightText)
		joinedWord := unicode.IsLetter(leftRunes[len(leftRunes)-1]) && unicode.IsLower(rightRunes[0])
		joinedNumber := rightRunes[0] == '.' && strings.ContainsAny(leftText, "0123456789")
		if !joinedWord && !joinedNumber {
			return false
		}
		found = true
	}
	return found
}

func dropTextEmptyColumns(table *Table) {
	columns := len(table.Rows[0].Cells)
	keep := make([]bool, columns)
	for _, row := range table.Rows {
		for column, cell := range row.Cells {
			keep[column] = keep[column] || strings.TrimSpace(cell.Text) != ""
		}
	}
	for rowIndex := range table.Rows {
		cells := table.Rows[rowIndex].Cells[:0]
		for column, cell := range table.Rows[rowIndex].Cells {
			if keep[column] {
				cells = append(cells, cell)
			}
		}
		table.Rows[rowIndex].Cells = cells
	}
}
