package table

import (
	"strings"

	"github.com/pymupdf4llm-c/go/internal/geometry"
)

// detectAndMergeMultiRowHeaders scans for consecutive header rows (rows where all cells have text)
// and merges them into single header cells. Returns the number of header rows detected.
func (g *Grid) detectAndMergeMultiRowHeaders() int {
	if g == nil || g.Table == nil || len(g.Table.Rows) < 2 {
		return 0
	}

	headerRowCount := 0
	for i := 0; i < len(g.Table.Rows); i++ {
		if !isHeaderRow(g.Table.Rows[i]) {
			break
		}
		headerRowCount++
	}

	if headerRowCount < 2 {
		// Mark single header if all cells have text
		if headerRowCount == 1 {
			g.Table.Rows[0].IsHeader = true
		}
		return headerRowCount
	}

	// Merge consecutive header rows (rows 0..headerRowCount-1)
	mergedHeader := mergeHeaderRows(g.Table.Rows[:headerRowCount])
	mergedHeader.IsHeader = true

	// Replace the header rows with the merged header
	newRows := make([]Row, 0, len(g.Table.Rows)-headerRowCount+1)
	newRows = append(newRows, mergedHeader)
	newRows = append(newRows, g.Table.Rows[headerRowCount:]...)
	g.Table.Rows = newRows

	return 1 // Now a single merged header row
}

// isHeaderRow returns true if all non-empty cells in the row have text content.
func isHeaderRow(row Row) bool {
	if len(row.Cells) == 0 {
		return false
	}

	hasContent := false
	for _, cell := range row.Cells {
		if cell.BBox.IsEmpty() {
			continue
		}
		text := strings.TrimSpace(cell.Text)
		if text == "" {
			return false // Non-empty cell with no text → not a header
		}
		hasContent = true
	}
	return hasContent
}

// mergeHeaderRows combines multiple header rows into a single row by merging
// vertically-adjacent cells in the same column. Cells are merged into the topmost row's cell.
func mergeHeaderRows(headerRows []Row) Row {
	if len(headerRows) == 0 {
		return Row{}
	}

	// Get the column structure from the first header row
	colCount := len(headerRows[0].Cells)
	if colCount == 0 {
		return headerRows[0]
	}

	// Determine target column count (may vary across header rows)
	for i := 1; i < len(headerRows); i++ {
		if len(headerRows[i].Cells) > colCount {
			colCount = len(headerRows[i].Cells)
		}
	}

	// Pad header rows to same column count
	for i := range headerRows {
		for len(headerRows[i].Cells) < colCount {
			headerRows[i].Cells = append(headerRows[i].Cells, Cell{})
		}
	}

	// Merge: for each column, collect text from all header rows
	mergedCells := make([]Cell, colCount)
	colBBoxes := make([]geometry.Rect, colCount)

	for col := 0; col < colCount; col++ {
		var texts []string
		for row := 0; row < len(headerRows); row++ {
			cell := headerRows[row].Cells[col]
			if !cell.BBox.IsEmpty() {
				text := strings.TrimSpace(cell.Text)
				if text != "" {
					texts = append(texts, text)
				}
				// Expand bounding box to include all header cells in column
				if colBBoxes[col].IsEmpty() {
					colBBoxes[col] = cell.BBox
				} else {
					colBBoxes[col] = colBBoxes[col].Union(cell.BBox)
				}
			}
		}

		// Merge text with newlines
		if len(texts) > 0 {
			mergedCells[col] = Cell{
				BBox: colBBoxes[col],
				Text: strings.Join(texts, "\n"),
			}
		} else {
			mergedCells[col] = Cell{BBox: colBBoxes[col]}
		}
	}

	// Build merged header row bounding box
	mergedBBox := headerRows[0].BBox
	for i := 1; i < len(headerRows); i++ {
		mergedBBox = mergedBBox.Union(headerRows[i].BBox)
	}

	return Row{
		BBox:     mergedBBox,
		Cells:    mergedCells,
		IsHeader: true,
	}
}
