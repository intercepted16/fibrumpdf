package bridge

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pymupdf4llm-c/go/internal/testutil"
)

var testPdfPath = filepath.Join(testutil.TestDataDir, "nist.pdf")

const deleteTempDir = true


func TestExtractAndAnalyze(t *testing.T) {
	if testPdfPath == "" {
		t.Fatal("could not find project root (.root file)")
	}

	if _, err := os.Stat(testPdfPath); err != nil {
		t.Fatalf("test PDF not found at %s: %v", testPdfPath, err)
	}

	tempDir, err := ExtractAllPagesRaw(testPdfPath)
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	Logger.Info("extraction temp dir", "path", tempDir)

	if deleteTempDir {
		defer os.RemoveAll(tempDir)
	}

	pageFiles, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("failed to read temp dir: %v", err)
	}

	if len(pageFiles) == 0 {
		t.Fatal("no .raw files extracted")
	}

	var totalChars, totalEdges int

	for _, pageFile := range pageFiles {
		data, err := ReadRawPage(filepath.Join(tempDir, pageFile.Name()))
		if err != nil {
			Logger.Info("warning: failed to read page", "file", pageFile.Name(), "error", err)
			continue
		}
		totalChars += len(data.Chars)
		totalEdges += len(data.Edges)

	}

	Logger.Info("file", "name", filepath.Base(testPdfPath))
	Logger.Info("pages", "count", len(pageFiles))
	Logger.Info("total characters", "count", totalChars)
	Logger.Info("total edges", "count", totalEdges)

	if totalChars == 0 {
		t.Error("no characters extracted")
	}
	if totalEdges == 0 {
		t.Error("no edges extracted")
	}
}
