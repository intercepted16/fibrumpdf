package extractor

import (
	"math"
	"strings"

	"github.com/fibrumpdf/go/internal/models"
	"github.com/fibrumpdf/go/internal/raw"
	"github.com/fibrumpdf/go/internal/textutil"
)

type splitBlock struct {
	text        string
	bbox        models.BBox
	lineCount   int
	charCount   int
	fontSizeSum float32
	boldCount   int
	italicCount int
	monoCount   int
	isList      bool
	listLines   []parsedListLine
	spans       []models.Span
}

type parsedListLine struct {
	text   string
	spans  []models.Span
	x      float32
	indent int
}

type splitStage struct{}

func (s splitStage) Run(ctx parseOutput) []splitBlock {
	blocks := make([]splitBlock, 0, len(ctx.raw.Blocks))
	for i := range ctx.raw.Blocks {
		rawBlock := &ctx.raw.Blocks[i]
		if rawBlock.Type != raw.BlockText {
			continue
		}
		blocks = append(blocks, s.splitRawBlock(ctx, rawBlock.LineStart, rawBlock.LineCount)...)
	}
	return blocks
}

func (s splitStage) splitRawBlock(ctx parseOutput, lineStart, lineCount int) []splitBlock {
	var result []splitBlock
	lineIdx := 0
	for lineIdx < lineCount {
		var textStr strings.Builder
		spans := make([]models.Span, 0, 8)
		var subBBox models.BBox
		var totalChars, boldChars, italicChars, monoChars int
		var fontSizeSum, lastLineFontSize float32 = 0, -1
		linesInSubBlock := 0
		var listLines []parsedListLine
		firstLine := ctx.lines[lineStart+lineIdx]
		subBlockIsList := startsWithListMarker(firstLine.rawText)
		for lineIdx < lineCount {
			lineAbsIdx := lineStart + lineIdx
			lineInfo := ctx.lines[lineAbsIdx]
			lineIsList := startsWithListMarker(lineInfo.rawText)
			avgLineFontSize := lineInfo.avgSize
			if linesInSubBlock > 0 {
				if lineIsList != subBlockIsList {
					break
				}
				prevLine := ctx.raw.Lines[lineAbsIdx-1]
				currLine := ctx.raw.Lines[lineAbsIdx]
				gap := currLine.BBox.Y0 - prevLine.BBox.Y1
				if s.shouldStartNewBlock(lastLineFontSize, avgLineFontSize, gap) {
					break
				}
				sep := "\n"
				if !subBlockIsList && gap < avgLineFontSize*1.4 {
					sep = " "
				}
				textStr.WriteString(sep)
				spans = s.appendSeparator(spans, sep)
			}
			lastLineFontSize = avgLineFontSize
			lb := lineInfo.bbox
			if linesInSubBlock == 0 {
				subBBox = lb
			} else {
				subBBox = subBBox.Union(lb)
			}
			linesInSubBlock++
			totalChars += lineInfo.charCount
			fontSizeSum += lineInfo.fontSizeSum
			boldChars += lineInfo.boldCount
			italicChars += lineInfo.italicCount
			monoChars += lineInfo.monoCount
			textStr.WriteString(lineInfo.rawText)
			spans = append(spans, lineInfo.spans...)
			if subBlockIsList {
				listLines = append(listLines, parsedListLine{
					text: lineInfo.rawText, spans: lineInfo.spans, x: lineInfo.bbox.X0(),
				})
			}
			lineIdx++
		}
		if totalChars == 0 {
			continue
		}
		text := textutil.NormalizeText(textStr.String())
		if len(spans) == 0 {
			continue
		}
		s.normalizeListIndents(listLines, fontSizeSum/float32(totalChars))
		result = append(result, splitBlock{
			text:        text,
			bbox:        subBBox,
			lineCount:   linesInSubBlock,
			charCount:   totalChars,
			fontSizeSum: fontSizeSum,
			boldCount:   boldChars,
			italicCount: italicChars,
			monoCount:   monoChars,
			isList:      subBlockIsList,
			listLines:   listLines,
			spans:       spans,
		})
	}
	return result
}

func (s splitStage) normalizeListIndents(lines []parsedListLine, fontSize float32) {
	if len(lines) == 0 {
		return
	}
	minX := lines[0].x
	for _, line := range lines[1:] {
		minX = min(minX, line.x)
	}
	indentWidth := max(fontSize*1.5, 1)
	for i := range lines {
		lines[i].indent = max(0, int(math.Round(float64((lines[i].x-minX)/indentWidth))))
	}
}

func (s splitStage) shouldStartNewBlock(prevSize, currSize, gap float32) bool {
	if prevSize > 0 && math.Abs(float64(currSize-prevSize)) > 0.5 {
		return true
	}
	return gap > currSize*1.8
}

func (s splitStage) appendSeparator(spans []models.Span, sep string) []models.Span {
	if sep == "" {
		return spans
	}
	if len(spans) == 0 {
		return []models.Span{{Text: sep}}
	}
	spans[len(spans)-1].Text += sep
	return spans
}
