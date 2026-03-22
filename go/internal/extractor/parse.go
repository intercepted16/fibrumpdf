package extractor

import (
	"math"
	"strings"
	"unicode"

	"github.com/pymupdf4llm-c/go/internal/geometry"
	"github.com/pymupdf4llm-c/go/internal/models"
	rawdata "github.com/pymupdf4llm-c/go/internal/raw"
	"github.com/pymupdf4llm-c/go/internal/textutil"
)

type fontStats struct {
	counts     [128]int
	totalSize  float64
	totalChars int
}

func (f *fontStats) add(size float32) {
	if size <= 0 {
		return
	}
	idx := geometry.Clamp(int(math.Round(float64(size))), 0, 127)
	f.counts[idx]++
	f.totalSize += float64(size)
	f.totalChars++
}

func (f *fontStats) mode(cfg ExtractionConfig) float32 {
	if f.totalChars == 0 {
		return cfg.DefaultFontSize
	}
	bestIdx, bestCount := 0, 0
	for i, c := range f.counts {
		if c > bestCount {
			bestCount, bestIdx = c, i
		}
	}
	if bestIdx == 0 && bestCount == 0 {
		return float32(f.totalSize / float64(f.totalChars))
	}
	return float32(bestIdx)
}

func (f *fontStats) median(cfg ExtractionConfig) float32 {
	if f.totalChars == 0 {
		return cfg.DefaultFontSize
	}
	mid, cum := f.totalChars/2, 0
	for i, c := range f.counts {
		if cum += c; cum > mid {
			return float32(i)
		}
	}
	return float32(f.totalSize / float64(f.totalChars))
}

type parseOutput struct {
	raw            *rawdata.PageData
	lines          []parsedLine
	bodyFontSize   float32
	medianFontSize float32
	cfg            ExtractionConfig
}

type parsedLine struct {
	bbox        models.BBox
	rawText     string
	spans       []models.Span
	avgSize     float32
	fontSizeSum float32
	charCount   int
	boldCount   int
	italicCount int
	monoCount   int
}

type parserStage struct{}

func (s parserStage) Run(raw *rawdata.PageData, cfg ExtractionConfig) parseOutput {
	stats := &fontStats{}
	for _, ch := range raw.Chars {
		stats.add(ch.Size)
	}
	bodySize, medianSize := stats.mode(cfg), stats.median(cfg)
	lines := make([]parsedLine, len(raw.Lines))
	for i := range raw.Lines {
		lines[i] = s.parseLine(raw, &raw.Lines[i], cfg)
	}
	Logger.Debug("font stats", "bodySize", bodySize, "medianSize", medianSize)
	return parseOutput{
		raw:            raw,
		lines:          lines,
		bodyFontSize:   bodySize,
		medianFontSize: medianSize,
		cfg:            cfg,
	}
}

func (s parserStage) parseLine(raw *rawdata.PageData, line *rawdata.Line, cfg ExtractionConfig) parsedLine {
	indices := raw.SortedLineCharIndices(line, nil)
	if len(indices) == 0 {
		return parsedLine{bbox: models.BBox{line.BBox.X0, line.BBox.Y0, line.BBox.X1, line.BBox.Y1}, avgSize: cfg.DefaultFontSize}
	}
	ordered := make([]rawdata.Char, 0, len(indices))
	spans := make([]models.Span, 0, 4)
	var (
		fontSizeSum float32
		boldCount   int
		italicCount int
		monoCount   int
		prev        *rawdata.Char
	)
	for _, idx := range indices {
		ch := raw.Chars[idx]
		ordered = append(ordered, ch)
		fontSizeSum += ch.Size
		if ch.IsBold {
			boldCount++
		}
		if ch.IsItalic {
			italicCount++
		}
		if ch.IsMonospaced {
			monoCount++
		}

		style := models.TextStyle{Bold: ch.IsBold, Italic: ch.IsItalic, Monospace: ch.IsMonospaced}
		uri := raw.ResolveCharURI(&ch)
		if len(spans) == 0 || spans[len(spans)-1].Style != style || spans[len(spans)-1].URI != uri {
			spans = append(spans, models.Span{Style: style, URI: uri})
		}
		if prev != nil && s.shouldInsertSyntheticSpace(*prev, ch) && !strings.HasSuffix(spans[len(spans)-1].Text, " ") {
			spans[len(spans)-1].Text += " "
		}
		spans[len(spans)-1].Text += string(ch.Codepoint)
		prev = &ch
	}

	rawText := textutil.NewTextAssembler(textutil.AssembleOptions{InsertSpaces: false}).AssembleOrderedChars(ordered)
	charCount := len(ordered)
	avg := cfg.DefaultFontSize
	if charCount > 0 {
		avg = fontSizeSum / float32(charCount)
	}
	return parsedLine{
		bbox:        models.BBox{line.BBox.X0, line.BBox.Y0, line.BBox.X1, line.BBox.Y1},
		rawText:     rawText,
		spans:       spans,
		avgSize:     avg,
		fontSizeSum: fontSizeSum,
		charCount:   charCount,
		boldCount:   boldCount,
		italicCount: italicCount,
		monoCount:   monoCount,
	}
}

func (s parserStage) shouldInsertSyntheticSpace(prev, curr rawdata.Char) bool {
	if unicode.IsSpace(prev.Codepoint) || unicode.IsSpace(curr.Codepoint) {
		return false
	}
	if !isWordLikeRune(prev.Codepoint) || !isWordLikeRune(curr.Codepoint) {
		return false
	}
	gap := curr.BBox.X0 - prev.BBox.X1
	return gap > geometry.Max32(prev.Size, curr.Size)*0.28
}

func isWordLikeRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}
