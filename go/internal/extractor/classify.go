package extractor

import (
	"strings"

	"github.com/fibrumpdf/go/internal/geometry"
	"github.com/fibrumpdf/go/internal/models"
)

type classifiedBlock struct {
	text         string
	bbox         models.BBox
	lineCount    int
	avgFontSize  float32
	textChars    int
	typ          models.BlockType
	headingLevel int
	spans        []models.Span
}

type classifyStage struct{}

func (s classifyStage) Run(ctx parseOutput, blocks []splitBlock) []classifiedBlock {
	out := make([]classifiedBlock, 0, len(blocks))
	for _, b := range blocks {
		boldRatio := float32(b.boldCount) / float32(b.charCount)
		monoRatio := float32(b.monoCount) / float32(b.charCount)
		typ, level := s.classifyTextBlock(b.text, b.runeCount, b.lineCount, b.avgFontSize, boldRatio, b.isList, ctx.medianFontSize, ctx.cfg)
		if monoRatio >= 0.8 && typ == models.BlockText && b.lineCount >= 2 {
			typ = models.BlockCode
		}
		spans := b.spans
		if typ == models.BlockHeading {
			for i := range spans {
				spans[i].Style.Bold = false
			}
		}
		out = append(out, classifiedBlock{
			text:         b.text,
			bbox:         b.bbox,
			lineCount:    b.lineCount,
			avgFontSize:  b.avgFontSize,
			textChars:    b.runeCount,
			typ:          typ,
			headingLevel: level,
			spans:        spans,
		})
	}
	return out
}

func (s classifyStage) classifyTextBlock(text string, textChars, lineCount int, avgFontSize, boldRatio float32, isList bool, medianSize float32, cfg ExtractionConfig) (models.BlockType, int) {
	if lineCount > 1 && isList {
		return models.BlockList, 0
	}
	wordCount := len(strings.Fields(text))
	fontBased := avgFontSize >= medianSize*cfg.HeadingMultiplier && textChars > 0 && textChars <= 140
	numericHeading := startsWithNumericHeading(text) && lineCount <= 2 && textChars <= 100
	allCapsHeading := isAllCaps(text) && textChars > 0 && textChars <= 90 && lineCount <= 2 && avgFontSize >= medianSize*cfg.AllCapsHeadingMultiplier
	styledShortTitle := boldRatio >= cfg.StyledShortTitleRatioBold && textChars > 0 && textChars <= cfg.StyledShortTitleMaxChars && wordCount > 0 && wordCount <= 10 && lineCount <= 2 && !endsWithPunctuation(text)
	heading := fontBased || numericHeading || allCapsHeading || styledShortTitle
	if fontBased && boldRatio >= cfg.BoldRatioThreshold {
		heading = true
	}
	if heading {
		level := 4
		if avgFontSize >= geometry.Max32(18.0, medianSize*1.7) {
			level = 1
		} else if avgFontSize >= geometry.Max32(14.0, medianSize*1.4) {
			level = 2
		} else if avgFontSize >= geometry.Max32(12.0, medianSize*1.15) {
			level = 3
		}
		return models.BlockHeading, level
	}
	if isList {
		return models.BlockList, 0
	}
	if textChars == 0 {
		return models.BlockOther, 0
	}
	return models.BlockText, 0
}
