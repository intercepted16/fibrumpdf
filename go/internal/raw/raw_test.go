package raw_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fibrumpdf/go/internal/raw"
	"github.com/fibrumpdf/go/internal/testutil"
)

func TestRawExtraction(t *testing.T) {
	tempDir, err := testutil.ExtractRawFromTestData("nist.pdf")
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	pageFiles, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("failed to read temp dir: %v", err)
	}

	if len(pageFiles) == 0 {
		t.Fatal("no .raw files extracted")
	}
	var totalChars, totalWords int

	for _, pageFile := range pageFiles {
		data, err := raw.ReadRawPage(filepath.Join(tempDir, pageFile.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", pageFile.Name(), err)
		}

		totalChars += len(data.Chars)
		inWord := false
		for _, ch := range data.Chars {
			if ch.Codepoint == ' ' || ch.Codepoint == '\n' || ch.Codepoint == '\t' {
				inWord = false
			} else if !inWord {
				totalWords++
				inWord = true
			}
		}
	}

	if totalChars == 0 {
		t.Fatal("no characters extracted")
	}
	if totalWords == 0 {
		t.Fatal("no words extracted")
	}
}
