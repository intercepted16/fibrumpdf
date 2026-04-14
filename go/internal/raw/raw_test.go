package raw_test

import (
	"os"
	"path/filepath"
	"strings"
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
	Logger.Info("extracted pages", "count", len(pageFiles))

	var totalChars, totalWords, totalEdges, totalBoldChars, totalItalicChars int
	var medianPageData *raw.PageData

	for _, pageFile := range pageFiles {
		data, err := raw.ReadRawPage(filepath.Join(tempDir, pageFile.Name()))
		if err != nil {
			Logger.Info("warning: failed to read page", "file", pageFile, "error", err)
			continue
		}

		totalChars += len(data.Chars)
		totalEdges += len(data.Edges)

		for _, ch := range data.Chars {
			if ch.IsBold {
				totalBoldChars++
			}
			if ch.IsItalic {
				totalItalicChars++
			}
		}

		wordCount := 0
		inWord := false
		for _, ch := range data.Chars {
			if ch.Codepoint == ' ' || ch.Codepoint == '\n' || ch.Codepoint == '\t' {
				inWord = false
			} else if !inWord {
				wordCount++
				inWord = true
			}
		}
		totalWords += wordCount
	}

	var boldPercent, italicPercent float64
	if totalChars > 0 {
		boldPercent = (float64(totalBoldChars) / float64(totalChars)) * 100
		italicPercent = (float64(totalItalicChars) / float64(totalChars)) * 100
	}

	textSnippet := ""
	if medianPageData != nil && len(medianPageData.Chars) > 0 {
		snippetLen := 100
		snippetLen = min(snippetLen, len(medianPageData.Chars))
		var sb strings.Builder
		for i := 0; i < snippetLen; i++ {
			sb.WriteRune(medianPageData.Chars[i].Codepoint)
		}
		textSnippet = strings.TrimSpace(sb.String())
		if len(textSnippet) > 80 {
			textSnippet = textSnippet[:80] + "..."
		}
	}

	Logger.Info("file", "name", "nist.pdf")
	Logger.Info("content stats")
	Logger.Info("total characters", "count", totalChars)
	Logger.Info("total words", "count", totalWords)
	Logger.Info("total edges", "count", totalEdges)
	Logger.Info("formatting stats")
	Logger.Info("bold characters", "percent", boldPercent)
	Logger.Info("italic characters", "percent", italicPercent)
	Logger.Info("median snippet", "text", textSnippet)

	if totalChars == 0 {
		t.Error("no characters extracted")
	}
	if totalWords == 0 {
		t.Error("no words extracted")
	}
}
