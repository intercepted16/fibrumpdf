package table

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fibrumpdf/go/internal/bridge"
	"github.com/fibrumpdf/go/internal/geometry"
	"github.com/fibrumpdf/go/internal/testutil"
)

func loadTestPDFPages(t *testing.T, pdfName string) []*bridge.RawPageData {
	t.Helper()
	if testutil.TestDataDir == "" {
		t.Fatal("could not find project root")
	}
	pdfPath := filepath.Join(testutil.TestDataDir, pdfName)
	if _, err := os.Stat(pdfPath); err != nil {
		t.Fatalf("test pdf not found: %s", pdfPath)
	}

	tempDir, err := bridge.ExtractAllPagesRaw(pdfPath)
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("failed to read temp dir: %v", err)
	}

	var pages []*bridge.RawPageData
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".raw") {
			continue
		}
		raw, err := bridge.ReadRawPage(filepath.Join(tempDir, f.Name()))
		if err != nil {
			continue
		}
		pages = append(pages, raw)
	}
	return pages
}

func TestExtractAndConvertTablesSimple(t *testing.T) {
	pages := loadTestPDFPages(t, "sample_with_table.pdf")

	var totalTables int
	for _, raw := range pages {
		blocks := ExtractAndConvertTables(raw)
		totalTables += len(blocks)

		for _, b := range blocks {
			if b.RowCount < 2 || b.ColCount < 2 {
				t.Errorf("table too small: %dx%d", b.RowCount, b.ColCount)
			}
			if len(b.Rows) == 0 {
				t.Error("table has no rows")
			}
		}
	}

	if totalTables == 0 {
		t.Error("no tables extracted from sample_with_table.pdf")
	}
	t.Logf("found %d tables", totalTables)
}

func TestExtractTablesFromNIST(t *testing.T) {
	pages := loadTestPDFPages(t, "nist.pdf")

	var tablesWithText int
	for _, raw := range pages {
		blocks := ExtractAndConvertTables(raw)
		for _, b := range blocks {
			hasText := false
			for _, row := range b.Rows {
				for _, cell := range row.Cells {
					for _, span := range cell.Spans {
						if strings.TrimSpace(span.Text) != "" {
							hasText = true
							break
						}
					}
				}
			}
			if hasText {
				tablesWithText++
			}
		}
	}

	t.Logf("found %d tables with text content", tablesWithText)
}

func TestTableCellsHaveValidBBox(t *testing.T) {
	pages := loadTestPDFPages(t, "sample_with_table.pdf")

	for _, raw := range pages {
		blocks := ExtractAndConvertTables(raw)
		for _, b := range blocks {
			for ri, row := range b.Rows {
				for ci, cell := range row.Cells {
					if cell.BBox.IsEmpty() {
						continue
					}
					if cell.BBox.X0() < 0 || cell.BBox.Y0() < 0 {
						t.Errorf("cell[%d][%d] has negative coords", ri, ci)
					}
				}
			}
		}
	}
}

func TestDeduplicateCells(t *testing.T) {
	cells := []geometry.Rect{
		{X0: 0, Y0: 0, X1: 100, Y1: 50},
		{X0: 5, Y0: 5, X1: 95, Y1: 45},
		{X0: 200, Y0: 0, X1: 300, Y1: 50},
	}

	result := deduplicateCells(cells)
	if len(result) != 2 {
		t.Errorf("expected 2 cells after dedup, got %d", len(result))
	}
}

func TestGroupCellsIntoTables(t *testing.T) {
	pageRect := geometry.Rect{X0: 0, Y0: 0, X1: 612, Y1: 792}
	cells := []geometry.Rect{
		{X0: 50, Y0: 100, X1: 150, Y1: 130},
		{X0: 150, Y0: 100, X1: 250, Y1: 130},
		{X0: 50, Y0: 130, X1: 150, Y1: 160},
		{X0: 150, Y0: 130, X1: 250, Y1: 160},
	}

	tables := groupCellsIntoTables(cells, pageRect)
	if tables == nil || len(tables.Tables) == 0 {
		t.Fatal("no tables grouped")
	}

	tbl := tables.Tables[0]
	if len(tbl.Rows) < 2 {
		t.Errorf("expected at least 2 rows, got %d", len(tbl.Rows))
	}
}

func TestMergeEdges(t *testing.T) {
	edges := []Edge{
		{X0: 100, Y0: 50, X1: 200, Y1: 50, Orientation: 'h'},
		{X0: 200, Y0: 50, X1: 300, Y1: 50, Orientation: 'h'},
		{X0: 100, Y0: 51, X1: 200, Y1: 51, Orientation: 'h'},
	}

	merged := mergeEdges(edges, 3.0, 5.0)
	if len(merged) > 2 {
		t.Errorf("expected fewer merged edges, got %d", len(merged))
	}

	for _, e := range merged {
		if e.X1-e.X0 < 100 {
			t.Error("merged edge too short")
		}
	}
}

func TestExtractTablesFromLargeDoc(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large doc test in short mode")
	}

	pages := loadTestPDFPages(t, "nist.pdf")

	var totalTables, totalCells int
	for _, raw := range pages {
		blocks := ExtractAndConvertTables(raw)
		for _, b := range blocks {
			totalTables++
			totalCells += b.CellCount
		}
	}

	t.Logf("large doc: %d tables, %d total cells", totalTables, totalCells)
}
