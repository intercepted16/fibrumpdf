package extractor

import (
	"math"
	"sort"
	"strings"

	"github.com/fibrumpdf/go/internal/bridge"
	"github.com/fibrumpdf/go/internal/column"
	"github.com/fibrumpdf/go/internal/geometry"
	"github.com/fibrumpdf/go/internal/logger"
	"github.com/fibrumpdf/go/internal/models"
	"github.com/fibrumpdf/go/internal/table"
	"github.com/fibrumpdf/go/internal/text"
)

var Logger = logger.GetLogger("extractor")

type blockInfo struct {
	Text, Prefix                                   string
	BBox                                           models.BBox
	Type                                           models.BlockType
	AvgFontSize, BoldRatio, ItalicRatio, MonoRatio float32
	TextChars, LineCount, HeadingLevel, ColIdx     int
	Spans                                          []models.Span
	ListItems                                      []models.ListItem
}

func (b *blockInfo) GetBBox() models.BBox   { return b.BBox }
func (b *blockInfo) SetColumnIndex(idx int) { b.ColIdx = idx }

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

func (f *fontStats) mode() float32 {
	if f.totalChars == 0 {
		return 12.0
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

func (f *fontStats) median() float32 {
	if f.totalChars == 0 {
		return 12.0
	}
	mid, cum := f.totalChars/2, 0
	for i, c := range f.counts {
		if cum += c; cum > mid {
			return float32(i)
		}
	}
	return float32(f.totalSize / float64(f.totalChars))
}

func classifyBlock(info *blockInfo, medianSize float32) {
	headingThreshold, tLen, txt := medianSize*1.25, info.TextChars, info.Text
	if info.LineCount > 1 && text.StartsWithBullet(txt) {
		info.Type = models.BlockList
		return
	}
	fontBased := info.AvgFontSize >= headingThreshold && tLen > 0 && tLen <= 160
	numericOrKeyword := text.StartsWithNumericHeading(txt) || text.StartsWithHeadingKeyword(txt)
	heading := fontBased || numericOrKeyword || (text.IsAllCaps(txt) && tLen > 0 && tLen <= 200)
	if fontBased && info.BoldRatio >= 0.35 {
		heading = true
	}
	if !heading && info.BoldRatio >= 0.8 && tLen > 0 && tLen <= 80 && info.LineCount <= 2 {
		heading = true
	}
	if heading && text.EndsWithPunctuation(txt) && !fontBased && !numericOrKeyword {
		heading = false
	}
	if heading {
		info.Type, info.HeadingLevel = models.BlockHeading, 4
		if info.AvgFontSize >= 18.0 {
			info.HeadingLevel = 1
		} else if info.AvgFontSize >= 14.0 {
			info.HeadingLevel = 2
		} else if info.AvgFontSize >= 12.0 {
			info.HeadingLevel = 3
		}
		return
	}
	if text.StartsWithBullet(txt) {
		info.Type = models.BlockList
	} else if tLen == 0 {
		info.Type = models.BlockOther
	} else {
		info.Type = models.BlockText
	}
}

func finalizeBlockInfo(info *blockInfo, pageBounds bridge.Rect) {
	if info == nil {
		return
	}
	if w, h := info.BBox.Width(), info.BBox.Height(); w < 30.0 && h > 200.0 {
		info.Text, info.TextChars, info.Spans = "", 0, nil
	}
	pageBBox := [4]float32{pageBounds.X0, pageBounds.Y0, pageBounds.X1, pageBounds.Y1}
	if text.IsInMarginArea(info.BBox, pageBBox, 0.08) && info.TextChars > 0 && info.TextChars < 200 {
		if text.IsLonePageNumber(info.Text) || (info.BBox.Y0() < pageBounds.Y0+(pageBounds.Y1-pageBounds.Y0)*0.08 && (info.Type == models.BlockHeading || text.IsAllCaps(info.Text)) && info.AvgFontSize < 18.0) {
			info.Text, info.TextChars, info.Spans = "", 0, nil
		}
	}
}

func ExtractPageFromRaw(raw *bridge.RawPageData) models.Page {
	Logger.Debug("extracting page", "pageNum", raw.PageNumber, "blocks", len(raw.Blocks), "chars", len(raw.Chars))
	stats := &fontStats{}
	for _, ch := range raw.Chars {
		stats.add(ch.Size)
	}
	bodySize, medianSize := stats.mode(), stats.median()
	Logger.Debug("font stats", "bodySize", bodySize, "medianSize", medianSize)
	var allBlocks []*blockInfo
	var tableBlocks []models.Block
	if tblBlocks := table.ExtractAndConvertTables(raw); len(tblBlocks) > 0 {
		Logger.Debug("extracted tables", "count", len(tblBlocks))
		tableBlocks = tblBlocks
		for i := range tblBlocks {
			allBlocks = append(allBlocks, &blockInfo{Type: models.BlockTable, BBox: tblBlocks[i].BBox})
		}
	}
	var textBlocks []*blockInfo
	for _, rawBlock := range raw.Blocks {
		if rawBlock.Type == 0 {
			textBlocks = append(textBlocks, splitAndProcessBlock(raw, &rawBlock, medianSize)...)
		}
	}
	for _, tb := range textBlocks {
		tbRect := geometry.Rect{X0: tb.BBox[0], Y0: tb.BBox[1], X1: tb.BBox[2], Y1: tb.BBox[3]}
		if tbRect.Area() <= 0 {
			continue
		}
		overlaps := false
		for _, b := range allBlocks {
			if b.Type == models.BlockTable {
				tableRect := geometry.Rect{X0: b.BBox[0], Y0: b.BBox[1], X1: b.BBox[2], Y1: b.BBox[3]}
				if tbRect.IntersectArea(tableRect)/tbRect.Area() > 0.85 {
					overlaps = true
					break
				}
			}
		}
		if !overlaps {
			allBlocks = append(allBlocks, tb)
		}
	}
	if len(allBlocks) > 0 {
		colBlocks := make([]column.BlockWithColumn, len(allBlocks))
		for i, b := range allBlocks {
			colBlocks[i] = b
		}
		column.DetectAndAssignColumns(colBlocks, bodySize)
		sortBlocks(allBlocks)
	}
	var finalBlocks []models.Block
	tableIdx := 0
	for i := 0; i < len(allBlocks); i++ {
		info := allBlocks[i]
		if info.Type == models.BlockTable {
			if tableIdx < len(tableBlocks) {
				finalBlocks = append(finalBlocks, tableBlocks[tableIdx])
				tableIdx++
			}
			continue
		}
		if info.Type == models.BlockList {
			info, i = mergeListBlocks(allBlocks, i)
		}
		finalizeBlockInfo(info, raw.PageBounds)
		if (info.Type == models.BlockList && len(info.ListItems) > 0) || text.HasVisibleContent(info.Text) {
			finalBlocks = append(finalBlocks, models.Block{Type: info.Type, BBox: info.BBox, Length: info.TextChars, Level: info.HeadingLevel, FontSize: info.AvgFontSize, Lines: info.LineCount, Spans: info.Spans, Items: info.ListItems})
		}
	}

	CleanupPage(finalBlocks)
	Logger.Debug("page extraction complete", "pageNum", raw.PageNumber, "finalBlocks", len(finalBlocks))

	return models.Page{Number: raw.PageNumber, Data: finalBlocks}
}

func sortBlocks(blocks []*blockInfo) {
	sort.SliceStable(blocks, func(i, j int) bool {
		bi, bj := blocks[i], blocks[j]
		if bi.ColIdx == bj.ColIdx {
			if math.Abs(float64(bi.BBox.Y0()-bj.BBox.Y0())) > 2.0 {
				return bi.BBox.Y0() < bj.BBox.Y0()
			}
			return bi.BBox.X0() < bj.BBox.X0()
		}
		if bi.ColIdx == 0 || bj.ColIdx == 0 {
			if math.Abs(float64(bi.BBox.Y0()-bj.BBox.Y0())) > 2.0 {
				return bi.BBox.Y0() < bj.BBox.Y0()
			}
			return bi.ColIdx == 0
		}
		return bi.ColIdx < bj.ColIdx
	})
}

func mergeListBlocks(blocks []*blockInfo, startIdx int) (*blockInfo, int) {
	info := blocks[startIdx]
	combinedBBox := info.BBox
	var listItems []models.ListItem
	var totalFontSize, totalBoldRatio float32
	var totalLines int
	var textParts []string
	baseX, baseFontSize := info.BBox.X0(), info.AvgFontSize
	if baseFontSize < 8.0 {
		baseFontSize = 12.0
	}
	endIdx := startIdx
	for j := startIdx; j < len(blocks); j++ {
		next := blocks[j]
		if next.Type != models.BlockList || next.ColIdx != info.ColIdx {
			break
		}
		if j > startIdx {
			if gap := next.BBox.Y0() - blocks[j-1].BBox.Y1(); gap > blocks[j-1].AvgFontSize*2.5 && gap > 20.0 {
				break
			}
		}
		combinedBBox = combinedBBox.Union(next.BBox)
		totalFontSize += next.AvgFontSize
		totalBoldRatio += next.BoldRatio
		totalLines += next.LineCount
		for _, line := range strings.Split(next.Text, "\n") {
			if line = strings.TrimSpace(line); line == "" {
				continue
			}
			isNum, prefix := text.StartsWithNumber(line)
			listType := "bulleted"
			if isNum {
				listType = "numbered"
			}
			indent := geometry.Clamp(int((next.BBox.X0()-baseX)/(baseFontSize*2)), 0, 6)
			cleanedText := line
			if isNum {
				cleanedText = strings.TrimPrefix(cleanedText, prefix)
			} else if r := []rune(line); len(r) > 0 && text.IsBullet(r[0]) {
				cleanedText = string(r[1:])
			}
			if cleanedText = strings.TrimSpace(cleanedText); cleanedText == "" {
				continue
			}
			marker := "- "
			if isNum {
				marker = prefix + " "
			}
			textParts = append(textParts, marker+cleanedText)
			listItems = append(listItems, models.ListItem{Spans: []models.Span{{Text: marker + cleanedText}}, ListType: listType, Indent: indent, Prefix: prefix})
		}
		endIdx = j
	}
	if len(listItems) > 0 {
		txt := strings.Join(textParts, "\n")
		info = &blockInfo{Type: models.BlockList, BBox: combinedBBox, AvgFontSize: totalFontSize / float32(endIdx-startIdx+1), BoldRatio: totalBoldRatio / float32(endIdx-startIdx+1), LineCount: totalLines, ColIdx: info.ColIdx, ListItems: listItems, Text: txt, TextChars: text.CountUnicodeChars(txt)}
	}
	return info, endIdx
}

func splitAndProcessBlock(raw *bridge.RawPageData, rawBlock *bridge.RawBlock, medianSize float32) []*blockInfo {
	var result []*blockInfo
	lineIdx := 0
	for lineIdx < rawBlock.LineCount {
		var textStr strings.Builder
		var spans []models.Span
		var subBBox models.BBox
		var totalChars, boldChars, italicChars, monoChars int
		var fontSizeSum, lastLineFontSize float32 = 0, -1
		linesInSubBlock := 0
		firstLine := &raw.Lines[rawBlock.LineStart+lineIdx]
		subBlockIsList, firstLineIsBold := lineStartsWithBullet(raw, firstLine), rawLineIsBold(raw, firstLine)
		for lineIdx < rawBlock.LineCount {
			line := &raw.Lines[rawBlock.LineStart+lineIdx]
			avgLineFontSize := computeLineFontSize(raw, line)
			if linesInSubBlock > 0 {
				if lineStartsWithBullet(raw, line) != subBlockIsList {
					break
				}
				prevLine := &raw.Lines[rawBlock.LineStart+lineIdx-1]
				gap, currentIsBold := line.BBox.Y0-prevLine.BBox.Y1, rawLineIsBold(raw, line)
				if (!firstLineIsBold && currentIsBold) || (firstLineIsBold && !currentIsBold && gap > avgLineFontSize*1.2) || (lastLineFontSize > 0 && math.Abs(float64(avgLineFontSize-lastLineFontSize)) > 0.5) || gap > avgLineFontSize*1.5 {
					break
				}
				sep := "\n"
				if gap < avgLineFontSize*0.2 {
					sep = " "
				}
				textStr.WriteString(sep)
				if len(spans) > 0 {
					spans[len(spans)-1].Text += sep
				}
			}
			lastLineFontSize = avgLineFontSize
			lb := models.BBox{line.BBox.X0, line.BBox.Y0, line.BBox.X1, line.BBox.Y1}
			if linesInSubBlock == 0 {
				subBBox = lb
			} else {
				subBBox = subBBox.Union(lb)
			}
			linesInSubBlock++
			for ci := 0; ci < line.CharCount; ci++ {
				ch := &raw.Chars[line.CharStart+ci]
				if ch.Codepoint == 0 {
					continue
				}
				totalChars++
				fontSizeSum += ch.Size
				if ch.IsBold {
					boldChars++
				}
				if ch.IsItalic {
					italicChars++
				}
				if ch.IsMonospaced {
					monoChars++
				}
				textStr.WriteRune(ch.Codepoint)
				style := models.TextStyle{Bold: ch.IsBold, Italic: ch.IsItalic, Monospace: ch.IsMonospaced}
				if len(spans) > 0 && spans[len(spans)-1].Style == style {
					spans[len(spans)-1].Text += string(ch.Codepoint)
				} else {
					spans = append(spans, models.Span{Text: string(ch.Codepoint), Style: style})
				}
			}
			lineIdx++
		}
		if totalChars == 0 {
			continue
		}
		info := &blockInfo{Text: text.NormalizeText(textStr.String()), BBox: subBBox, LineCount: linesInSubBlock, AvgFontSize: fontSizeSum / float32(totalChars), BoldRatio: float32(boldChars) / float32(totalChars), ItalicRatio: float32(italicChars) / float32(totalChars), MonoRatio: float32(monoChars) / float32(totalChars)}
		info.TextChars = text.CountUnicodeChars(info.Text)
		classifyBlock(info, medianSize)
		if info.MonoRatio >= 0.8 && info.Type == models.BlockText && info.LineCount >= 2 {
			info.Type = models.BlockCode
		}
		if info.Spans = processSpans(spans); len(info.Spans) > 0 {
			result = append(result, info)
		}
	}
	return result
}

func computeLineFontSize(raw *bridge.RawPageData, line *bridge.RawLine) float32 {
	var sum float32
	count := 0
	for ci := 0; ci < line.CharCount; ci++ {
		if ch := &raw.Chars[line.CharStart+ci]; ch.Codepoint != 0 {
			sum += ch.Size
			count++
		}
	}
	if count == 0 {
		return 12.0
	}
	return sum / float32(count)
}

func lineStartsWithBullet(raw *bridge.RawPageData, line *bridge.RawLine) bool {
	var buf strings.Builder
	for i := 0; i < line.CharCount && i < 12; i++ {
		buf.WriteRune(raw.Chars[line.CharStart+i].Codepoint)
	}
	return text.StartsWithBullet(buf.String())
}

func rawLineIsBold(raw *bridge.RawPageData, line *bridge.RawLine) bool {
	boldChars, totalChars := 0, 0
	for i := 0; i < line.CharCount; i++ {
		if r := raw.Chars[line.CharStart+i].Codepoint; r != 0 && r != ' ' && r != '\t' && r != '\n' {
			totalChars++
			if raw.Chars[line.CharStart+i].IsBold {
				boldChars++
			}
		}
	}
	return totalChars > 0 && float32(boldChars)/float32(totalChars) > 0.70
}

func processSpans(spans []models.Span) []models.Span {
	var filtered []models.Span
	for _, s := range spans {
		if s.Text != "" {
			filtered = append(filtered, s)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	for i := 0; i < len(filtered)-1; i++ {
		s := &filtered[i]
		if s.Style.Bold || s.Style.Italic {
			if trimmed := strings.TrimRight(s.Text, " \t\n\r\u00A0"); len(trimmed) < len(s.Text) {
				filtered[i+1].Text = s.Text[len(trimmed):] + filtered[i+1].Text
				s.Text = trimmed
			}
		}
	}
	filtered[0].Text = strings.TrimLeft(filtered[0].Text, " \t\n\r\u00A0")
	filtered[len(filtered)-1].Text = strings.TrimRight(filtered[len(filtered)-1].Text, " \t\n\r\u00A0")
	var final []models.Span
	for _, s := range filtered {
		if s.Text == "" {
			continue
		}
		if len(final) > 0 && final[len(final)-1].Style == s.Style {
			final[len(final)-1].Text += s.Text
			continue
		}
		final = append(final, s)
	}
	return final
}
