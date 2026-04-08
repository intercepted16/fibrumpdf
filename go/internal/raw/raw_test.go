package raw_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fibrumpdf/go/internal/logger"
	"github.com/fibrumpdf/go/internal/raw"
	"github.com/fibrumpdf/go/internal/testutil"
)

var Logger = logger.GetLogger("rawTest")

func TestRawExtraction(t *testing.T) {
	tempDir, err := testutil.ExtractRawFromTestData("nist.pdf")
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	Logger.Info("extraction temp dir", "path", tempDir)

	pageFiles, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("failed to read temp dir: %v", err)
	}

	t.Cleanup(func() {
		defer os.RemoveAll(tempDir)
	})

	if len(pageFiles) == 0 {
		t.Fatal("no .raw files extracted")
	}

	var totalChars, totalEdges int

	for _, pageFile := range pageFiles {
		data, err := raw.ReadRawPage(filepath.Join(tempDir, pageFile.Name()))
		if err != nil {
			Logger.Info("warning: failed to read page", "file", pageFile.Name(), "error", err)
			continue
		}
		totalChars += len(data.Chars)
		totalEdges += len(data.Edges)

	}

	Logger.Info("file", "name", "nist.pdf")
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
