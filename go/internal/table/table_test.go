package table_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pymupdf4llm-c/go/internal/raw"
	"github.com/pymupdf4llm-c/go/internal/table"
	"github.com/pymupdf4llm-c/go/internal/testutil"
)

func loadTestPDFPages(t *testing.T, pdfName string) []*raw.PageData {
	t.Helper()
	tempDir, err := testutil.ExtractRawFromTestData(pdfName)
	if err != nil {
		t.Fatalf("failed to extract raw pages from %s: %v", pdfName, err)
	}

	t.Cleanup(func() {
		defer os.RemoveAll(tempDir)
	})

	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("failed to read temp dir: %v", err)
	}

	var pages []*raw.PageData
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".raw") {
			continue
		}
		page, err := raw.ReadRawPage(filepath.Join(tempDir, f.Name()))
		if err != nil {
			continue
		}
		pages = append(pages, page)
	}
	return pages
}

func TestExtractTables(t *testing.T) {
	pages := loadTestPDFPages(t, "sample.pdf")

	var totalTables int
	for _, page := range pages {
		blocks := table.ExtractAndConvertTables(page)
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
		t.Error("no tables extracted from sample.pdf")
	}
	t.Logf("found %d tables", totalTables)
}
