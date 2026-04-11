package extractor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fibrumpdf/go/internal/bridge"
	"github.com/fibrumpdf/go/internal/models"
	"github.com/fibrumpdf/go/internal/testutil"
)

func extractTestPDF(t *testing.T, pdfName string) []models.Page {
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
	t.Cleanup(func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("warning: failed to cleanup temp dir %s: %v", tempDir, err)
		}
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
		raw, err := bridge.ReadRawPage(filepath.Join(tempDir, f.Name()))
		if err != nil {
			t.Logf("warning: failed to read page %s: %v", f.Name(), err)
			continue
		}
		pages = append(pages, ExtractPageFromRaw(raw))
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
	pages := extractTestPDF(t, "sample_with_headings.pdf")

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
	pages := extractTestPDF(t, "sample_with_lists.pdf")

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
	pages := extractTestPDF(t, "sample_with_table.pdf")

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
	pages := extractTestPDF(t, "sample_with_formatting.pdf")

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

func TestExtractLargeDocument(t *testing.T) {
	pages := extractTestPDF(t, "nist.pdf")

	if len(pages) < 100 {
		t.Errorf("expected many pages, got %d", len(pages))
	}

	blockTypes := make(map[models.BlockType]int)
	for _, p := range pages {
		for _, b := range p.Data {
			blockTypes[b.Type]++
		}
	}

	if blockTypes[models.BlockText] == 0 {
		t.Error("no text blocks in large document")
	}
	if blockTypes[models.BlockHeading] == 0 {
		t.Error("no headings in large document")
	}

	t.Logf("large doc: %d pages, block types: %v", len(pages), blockTypes)
}

func TestBlocksHaveValidBBox(t *testing.T) {
	pages := extractTestPDF(t, "nist.pdf")

	for _, p := range pages {
		for i, b := range p.Data {
			if b.BBox.IsEmpty() && b.Type != models.BlockOther {
				continue
			}
			if b.BBox.X0() < 0 || b.BBox.Y0() < 0 {
				t.Errorf("page %d block %d has negative bbox coords", p.Number, i)
			}
			if b.BBox.Width() <= 0 && b.Type != models.BlockOther {
				t.Errorf("page %d block %d has zero/negative width", p.Number, i)
			}
			if b.BBox.Height() <= 0 && b.Type != models.BlockOther {
				t.Errorf("page %d block %d has zero/negative height", p.Number, i)
			}
		}
	}
}

func TestSpansHaveContent(t *testing.T) {
	pages := extractTestPDF(t, "nist.pdf")

	emptyCount := 0
	totalSpans := 0
	for _, p := range pages {
		for _, b := range p.Data {
			if b.Type == models.BlockTable || b.Type == models.BlockList {
				continue
			}
			for _, span := range b.Spans {
				totalSpans++
				if strings.TrimSpace(span.Text) == "" {
					emptyCount++
				}
			}
		}
	}

	emptyRatio := float64(emptyCount) / float64(totalSpans)
	if emptyRatio > 0.1 {
		t.Errorf("too many empty spans: %d/%d (%.2f%%)", emptyCount, totalSpans, emptyRatio*100)
	}
	t.Logf("spans: %d total, %d empty (%.2f%%)", totalSpans, emptyCount, emptyRatio*100)
}
