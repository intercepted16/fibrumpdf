package extractor_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fibrumpdf/go/internal/extractor"
	"github.com/fibrumpdf/go/internal/models"
	"github.com/fibrumpdf/go/internal/raw"
	"github.com/fibrumpdf/go/internal/testutil"
)

func extractTestPDF(t *testing.T, pdfName string) []models.Page {
	t.Helper()

	tempDir, err := testutil.ExtractRawFromTestData(pdfName)
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("failed to read temp dir: %v", err)
	}

	var pages []models.Page
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".raw") {
			continue
		}
		raw, err := raw.ReadRawPage(filepath.Join(tempDir, f.Name()))
		if err != nil {
			t.Logf("warning: failed to read page %s: %v", f.Name(), err)
			continue
		}
		pages = append(pages, extractor.ExtractPageFromRaw(raw))
	}
	return pages
}

func TestExtractPageProducesBlocks(t *testing.T) {
	pages := extractTestPDF(t, "nist.pdf")

	if len(pages) == 0 {
		t.Fatal("no pages extracted")
	}

	totalBlocks := 0
	for _, p := range pages {
		totalBlocks += len(p.Data)
	}

	if totalBlocks == 0 {
		t.Error("no blocks extracted from document")
	}
	t.Logf("extracted %d pages with %d total blocks", len(pages), totalBlocks)
}

func TestExtractHeadings(t *testing.T) {
	pages := extractTestPDF(t, "sample.pdf")

	var headings []models.Block
	for _, p := range pages {
		for _, b := range p.Data {
			if b.Type == models.BlockHeading {
				headings = append(headings, b)
			}
		}
	}

	if len(headings) == 0 {
		t.Error("no headings detected")
	}

	for _, h := range headings {
		if h.Level < 1 || h.Level > 4 {
			t.Errorf("heading has invalid level: %d", h.Level)
		}
		if len(h.Spans) == 0 {
			t.Error("heading has no spans")
		}
	}
	t.Logf("found %d headings", len(headings))
}

func TestExtractLists(t *testing.T) {
	pages := extractTestPDF(t, "sample.pdf")

	var lists []models.Block
	for _, p := range pages {
		for _, b := range p.Data {
			if b.Type == models.BlockList {
				lists = append(lists, b)
			}
		}
	}

	if len(lists) == 0 {
		t.Error("no lists detected")
	}

	for _, l := range lists {
		if len(l.Items) == 0 {
			t.Error("list block has no items")
		}
		for _, item := range l.Items {
			if item.ListType != "bulleted" && item.ListType != "numbered" {
				t.Errorf("unexpected list type: %s", item.ListType)
			}
		}
	}
	t.Logf("found %d list blocks", len(lists))
}

func TestExtractTables(t *testing.T) {
	pages := extractTestPDF(t, "sample.pdf")

	var tables []models.Block
	for _, p := range pages {
		for _, b := range p.Data {
			if b.Type == models.BlockTable {
				tables = append(tables, b)
			}
		}
	}

	if len(tables) == 0 {
		t.Error("no tables detected")
	}

	for _, tbl := range tables {
		if tbl.RowCount < 2 {
			t.Errorf("table has too few rows: %d", tbl.RowCount)
		}
		if tbl.ColCount < 2 {
			t.Errorf("table has too few cols: %d", tbl.ColCount)
		}
		if len(tbl.Rows) == 0 {
			t.Error("table has no row data")
		}
	}
	t.Logf("found %d tables", len(tables))
}

func TestExtractFormatting(t *testing.T) {
	pages := extractTestPDF(t, "sample.pdf")

	var boldFound, italicFound bool
	for _, p := range pages {
		for _, b := range p.Data {
			for _, span := range b.Spans {
				if span.Style.Bold {
					boldFound = true
				}
				if span.Style.Italic {
					italicFound = true
				}
			}
		}
	}

	if !boldFound {
		t.Error("no bold text detected")
	}
	if !italicFound {
		t.Error("no italic text detected")
	}
}
