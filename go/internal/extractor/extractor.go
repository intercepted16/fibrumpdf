package extractor

import (
	"math"
	"sort"
	"strings"
	"unicode"

	"github.com/pymupdf4llm-c/go/internal/bridge"
	"github.com/pymupdf4llm-c/go/internal/column"
	"github.com/pymupdf4llm-c/go/internal/geometry"
	"github.com/pymupdf4llm-c/go/internal/logger"
	"github.com/pymupdf4llm-c/go/internal/models"
	"github.com/pymupdf4llm-c/go/internal/table"
	"github.com/pymupdf4llm-c/go/internal/text"
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

type spanChunk struct {
	Text     string
	Style    models.TextStyle
	URI      string
	BBox     models.BBox
	FontSize float32
}

type lineStats struct {
	Text      string
	Chars     int
	Words     int
	BoldRatio float32
	AvgSize   float32
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
	wordCount := len(strings.Fields(txt))
	if info.LineCount > 1 && text.StartsWithBullet(txt) {
		info.Type = models.BlockList
		return
	}
	fontBased := info.AvgFontSize >= headingThreshold && tLen > 0 && tLen <= 140
	numericHeading := text.StartsWithNumericHeading(txt)
	numericOrKeyword := (numericHeading && (info.BoldRatio >= 0.25 || info.AvgFontSize >= medianSize*1.07)) && info.LineCount <= 2 && tLen <= 100
	allCapsHeading := text.IsAllCaps(txt) && tLen > 0 && tLen <= 90 && info.LineCount <= 2 && info.AvgFontSize >= medianSize*1.08
	styledShortTitle := info.BoldRatio >= 0.6 && tLen > 0 && tLen <= 80 && wordCount > 0 && wordCount <= 10 && info.LineCount <= 2 && !text.EndsWithPunctuation(txt)
	heading := fontBased || numericOrKeyword || allCapsHeading || styledShortTitle
	if fontBased && info.BoldRatio >= 0.35 {
		heading = true
	}
	if !heading && info.BoldRatio >= 0.8 && tLen > 0 && tLen <= 70 && info.LineCount <= 2 && info.AvgFontSize >= medianSize*1.05 {
		heading = true
	}
	if heading && wordCount >= 14 && !fontBased && !numericOrKeyword {
		heading = false
	}
	if heading && (countNumericTokens(txt) >= 3 && wordCount <= 12) {
		heading = false
	}
	if heading && text.EndsWithPunctuation(txt) && !fontBased && !numericOrKeyword {
		heading = false
	}
	if heading {
		info.Type, info.HeadingLevel = models.BlockHeading, 4
		if info.AvgFontSize >= geometry.Max32(18.0, medianSize*1.7) {
			info.HeadingLevel = 1
		} else if info.AvgFontSize >= geometry.Max32(14.0, medianSize*1.4) {
			info.HeadingLevel = 2
		} else if info.AvgFontSize >= geometry.Max32(12.0, medianSize*1.15) {
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
		info.Text, info.TextChars, info.Spans, info.ListItems = "", 0, nil, nil
	}
	pageBBox := [4]float32{pageBounds.X0, pageBounds.Y0, pageBounds.X1, pageBounds.Y1}
	if text.IsInMarginArea(info.BBox, pageBBox, 0.08) && info.TextChars > 0 && info.TextChars < 200 {
		topMargin := info.BBox.Y0() < pageBounds.Y0+(pageBounds.Y1-pageBounds.Y0)*0.08
		shortLoudLine := (info.Type == models.BlockHeading || text.IsAllCaps(info.Text)) && info.AvgFontSize < 18.0 && info.LineCount <= 1 && info.TextChars <= 42
		if text.IsLonePageNumber(info.Text) || (topMargin && shortLoudLine) {
			info.Text, info.TextChars, info.Spans, info.ListItems = "", 0, nil, nil
		}
	}
	if isNoiseLine(info.Text) {
		if marker, ok := normalizeNumberMarker(info.Text); ok {
			info.Text = marker
			info.TextChars = text.CountUnicodeChars(marker)
			info.Spans = []models.Span{{Text: marker}}
			info.ListItems = nil
			if info.Type == models.BlockList {
				info.Type = models.BlockText
			}
		} else {
			info.Text, info.TextChars, info.Spans, info.ListItems = "", 0, nil, nil
		}
	}
}

func isNoiseLine(s string) bool {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return false
	}
	parts := strings.Fields(trimmed)
	if len(parts) >= 2 && len(parts) <= 4 {
		allBullets := true
		for _, p := range parts {
			r := []rune(p)
			if len(r) != 1 || !text.IsBullet(r[0]) {
				allBullets = false
				break
			}
		}
		if allBullets {
			return true
		}
	}
	hasDigit := false
	bullish := 0
	for _, r := range trimmed {
		switch {
		case unicode.IsSpace(r):
			continue
		case text.IsBullet(r) || r == '-' || r == '–' || r == '—' || r == '•' || r == '.':
			bullish++
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == ')' || r == '(' || r == ':':
			continue
		default:
			return false
		}
	}
	return bullish >= 2 || (hasDigit && bullish >= 1)
}

func normalizeNumberMarker(s string) (string, bool) {
	runes := []rune(strings.TrimSpace(s))
	if len(runes) == 0 {
		return "", false
	}
	digits := make([]rune, 0, 3)
	for _, r := range runes {
		if r >= '0' && r <= '9' {
			digits = append(digits, r)
			continue
		}
		if unicode.IsSpace(r) || text.IsBullet(r) || r == '-' || r == '–' || r == '—' || r == '•' || r == '.' || r == ')' || r == '(' || r == ':' {
			continue
		}
		return "", false
	}
	if len(digits) == 0 || len(digits) > 3 {
		return "", false
	}
	return string(digits) + ".", true
}

func isNumericMarker(s string) bool {
	_, ok := normalizeNumberMarker(s)
	return ok
}

func countNumericTokens(s string) int {
	count := 0
	for _, tok := range strings.Fields(s) {
		hasDigit := false
		for _, r := range tok {
			if r >= '0' && r <= '9' {
				hasDigit = true
				break
			}
		}
		if hasDigit {
			count++
		}
	}
	return count
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
		sortBlocks(allBlocks, shouldSortRowWise(allBlocks))
	}
	var finalBlocks []models.Block
	tableIdx := 0
	for i := 0; i < len(allBlocks); i++ {
		info := allBlocks[i]
		if isNumericMarker(info.Text) && i+1 < len(allBlocks) {
			next := allBlocks[i+1]
			if next != nil && next.Type == models.BlockHeading && next.ColIdx == info.ColIdx {
				gap := next.BBox.Y0() - info.BBox.Y1()
				if gap <= geometry.Max32(info.AvgFontSize*1.8, 18.0) {
					prefix := strings.TrimSpace(info.Text)
					nextText := strings.TrimSpace(next.Text)
					if prefix != "" && nextText != "" {
						next.Text = prefix + " " + nextText
						next.TextChars = text.CountUnicodeChars(next.Text)
						next.BBox = info.BBox.Union(next.BBox)
						next.Spans = []models.Span{{Text: next.Text}}
						continue
					}
				}
			}
		}
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
		if info.Type == models.BlockList {
			if len(info.ListItems) == 0 {
				continue
			}
			finalBlocks = append(finalBlocks, models.Block{Type: info.Type, BBox: info.BBox, Length: info.TextChars, Level: info.HeadingLevel, FontSize: info.AvgFontSize, Lines: info.LineCount, Spans: info.Spans, Items: info.ListItems})
			continue
		}
		if text.HasVisibleContent(info.Text) {
			finalBlocks = append(finalBlocks, models.Block{Type: info.Type, BBox: info.BBox, Length: info.TextChars, Level: info.HeadingLevel, FontSize: info.AvgFontSize, Lines: info.LineCount, Spans: info.Spans, Items: info.ListItems})
		}
	}
	CleanupPage(finalBlocks)
	Logger.Debug("page extraction complete", "pageNum", raw.PageNumber, "finalBlocks", len(finalBlocks))

	return models.Page{Number: raw.PageNumber, Data: finalBlocks}
}

func sortBlocks(blocks []*blockInfo, rowWise bool) {
	sort.SliceStable(blocks, func(i, j int) bool {
		bi, bj := blocks[i], blocks[j]
		if rowWise {
			if math.Abs(float64(bi.BBox.Y0()-bj.BBox.Y0())) > 2.0 {
				return bi.BBox.Y0() < bj.BBox.Y0()
			}
			return bi.BBox.X0() < bj.BBox.X0()
		}
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

func shouldSortRowWise(blocks []*blockInfo) bool {
	if len(blocks) < 16 {
		return false
	}
	var textBlocks []*blockInfo
	for _, b := range blocks {
		if b == nil || b.Type == models.BlockTable || !text.HasVisibleContent(b.Text) {
			continue
		}
		textBlocks = append(textBlocks, b)
	}
	if len(textBlocks) < 14 {
		return false
	}
	minX, maxX := float32(1e9), float32(-1e9)
	numericHeavy := 0
	for _, b := range textBlocks {
		x0 := b.BBox.X0()
		if x0 < minX {
			minX = x0
		}
		if x0 > maxX {
			maxX = x0
		}
		t := strings.TrimSpace(b.Text)
		if len([]rune(t)) <= 140 && countNumericTokens(t) >= 2 {
			numericHeavy++
		}
	}
	if maxX-minX < 120 {
		return false
	}
	if numericHeavy*100 < len(textBlocks)*25 {
		return false
	}
	center := (minX + maxX) * 0.5
	left := make([]*blockInfo, 0, len(textBlocks)/2)
	right := make([]*blockInfo, 0, len(textBlocks)/2)
	for _, b := range textBlocks {
		if b.BBox.X0() <= center {
			left = append(left, b)
		} else {
			right = append(right, b)
		}
	}
	if len(left) < 4 || len(right) < 4 {
		return false
	}
	rowAligned := 0
	for _, a := range left {
		if !isTabularLikeTextBlock(a) {
			continue
		}
		for _, b := range right {
			if !isTabularLikeTextBlock(b) {
				continue
			}
			if shareVisualRow(a.BBox, b.BBox) {
				rowAligned++
				break
			}
		}
	}
	need := int(geometry.Min32(float32(len(left)), float32(len(right))) * 0.16)
	if need < 4 {
		need = 4
	}
	return rowAligned >= need
}

func shareVisualRow(a, b models.BBox) bool {
	hA, hB := a.Height(), b.Height()
	if hA <= 0 || hB <= 0 {
		return false
	}
	overlap := geometry.Min32(a.Y1(), b.Y1()) - geometry.Max32(a.Y0(), b.Y0())
	if overlap > geometry.Min32(hA, hB)*0.45 {
		return true
	}
	avgH := (hA + hB) * 0.5
	return geometry.Abs32(a.Y0()-b.Y0()) <= avgH*0.32+1.0
}

func isTabularLikeTextBlock(b *blockInfo) bool {
	if b == nil {
		return false
	}
	if b.Type == models.BlockTable {
		return true
	}
	t := strings.TrimSpace(b.Text)
	if t == "" {
		return false
	}
	words := strings.Fields(t)
	if len(words) < 2 {
		return false
	}
	numTokens := countNumericTokens(t)
	if numTokens >= 3 {
		return true
	}
	if numTokens >= 2 && len(words) >= 5 {
		return true
	}
	if hasCourseLikeCode(words[0]) && len(words) >= 4 {
		return true
	}
	return false
}

func hasCourseLikeCode(tok string) bool {
	if tok == "" {
		return false
	}
	let, dig := 0, 0
	for _, r := range tok {
		switch {
		case unicode.IsLetter(r):
			let++
		case unicode.IsDigit(r):
			dig++
		case r == '_' || r == '-' || r == '/' || r == '.':
		default:
			return false
		}
	}
	return let >= 3 && dig >= 1
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
		var spanChunks []spanChunk
		var subBBox models.BBox
		var totalChars, boldChars, italicChars, monoChars int
		var fontSizeSum, lastLineFontSize float32 = 0, -1
		linesInSubBlock := 0
		firstLine := &raw.Lines[rawBlock.LineStart+lineIdx]
		subBlockIsList := lineStartsWithBullet(raw, firstLine)
		for lineIdx < rawBlock.LineCount {
			line := &raw.Lines[rawBlock.LineStart+lineIdx]
			avgLineFontSize := computeLineFontSize(raw, line)
			currStats := computeLineStats(raw, line)
			if linesInSubBlock > 0 {
				if lineStartsWithBullet(raw, line) != subBlockIsList {
					break
				}
				prevLine := &raw.Lines[rawBlock.LineStart+lineIdx-1]
				gap := line.BBox.Y0 - prevLine.BBox.Y1
				if (lastLineFontSize > 0 && math.Abs(float64(avgLineFontSize-lastLineFontSize)) > 0.5) || gap > avgLineFontSize*1.8 {
					break
				}
				prevStats := computeLineStats(raw, prevLine)
				if shouldSplitLineBySemantics(prevStats, currStats, gap, medianSize) {
					break
				}
				sep := "\n"
				if gap < avgLineFontSize*0.2 || gap < avgLineFontSize*1.4 {
					sep = " "
				}
				textStr.WriteString(sep)
				if len(spanChunks) > 0 {
					spanChunks[len(spanChunks)-1].Text += sep
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
			var prevLineChar *bridge.RawChar
			for _, idx := range sortedLineCharIndices(raw, line) {
				ch := &raw.Chars[idx]
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
				uri := resolveCharURI(ch, raw.Links)
				if len(spanChunks) > 0 && uri == "" && unicode.IsSpace(ch.Codepoint) {
					uri = spanChunks[len(spanChunks)-1].URI
				}
				charBBox := models.BBox{ch.BBox.X0, ch.BBox.Y0, ch.BBox.X1, ch.BBox.Y1}
				if len(spanChunks) > 0 && canMergeCharIntoChunk(spanChunks[len(spanChunks)-1], prevLineChar, ch, style, uri) {
					if shouldInsertSyntheticSpace(prevLineChar, ch) && !strings.HasSuffix(spanChunks[len(spanChunks)-1].Text, " ") {
						spanChunks[len(spanChunks)-1].Text += " "
					}
					spanChunks[len(spanChunks)-1].Text += string(ch.Codepoint)
					spanChunks[len(spanChunks)-1].BBox = spanChunks[len(spanChunks)-1].BBox.Union(charBBox)
				} else {
					spanChunks = append(spanChunks, spanChunk{Text: string(ch.Codepoint), Style: style, URI: uri, BBox: charBBox, FontSize: ch.Size})
				}
				prevLineChar = ch
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
		if info.Spans = processSpans(spanChunks); len(info.Spans) > 0 {
			if info.Type == models.BlockHeading {
				for si := range info.Spans {
					info.Spans[si].Style.Bold = false
				}
			}
			info.Spans = sanitizeSpanLinks(info.Spans, info.LineCount)
			result = append(result, info)
		}
	}
	return result
}

func sanitizeSpanLinks(spans []models.Span, lineCount int) []models.Span {
	if len(spans) == 0 {
		return spans
	}
	linked := 0
	for _, s := range spans {
		if s.URI == "" {
			continue
		}
		linked++
	}
	if linked == 0 {
		return spans
	}
	denseLinkBlock := (lineCount >= 4 && linked >= 5) || linked >= 10
	for i := range spans {
		if spans[i].URI == "" {
			continue
		}
		spans[i].URI = strings.TrimSpace(spans[i].URI)
		if !isExternalURI(spans[i].URI) {
			spans[i].URI = ""
			continue
		}
		if looksIdentifierLikeLinkText(spans[i].Text) && (!looksCitationLikeLinkText(spans[i].Text) || denseLinkBlock) {
			spans[i].URI = ""
		}
	}
	for i := 1; i < len(spans); i++ {
		if spans[i].Text == "" {
			continue
		}
		if spans[i-1].Style == spans[i].Style && spans[i-1].URI == spans[i].URI {
			spans[i-1].Text += spans[i].Text
			spans[i].Text = ""
		}
	}
	out := spans[:0]
	for _, s := range spans {
		if s.Text != "" {
			out = append(out, s)
		}
	}
	return out
}

func isExternalURI(uri string) bool {
	u := strings.ToLower(strings.TrimSpace(uri))
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "mailto:")
}

func looksIdentifierLikeLinkText(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len([]rune(s)) > 28 || strings.ContainsRune(s, ' ') {
		return false
	}
	letters, digits, punct := 0, 0, 0
	for _, r := range s {
		switch {
		case unicode.IsLetter(r):
			letters++
		case unicode.IsDigit(r):
			digits++
		case r == '_' || r == '-' || r == '/' || r == '.':
			punct++
		default:
			return false
		}
	}
	return letters >= 2 && digits >= 1 && punct >= 0
}

func looksCitationLikeLinkText(s string) bool {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "http") || strings.Contains(s, "www.") {
		return true
	}
	if len([]rune(s)) < 14 {
		return false
	}
	if len(strings.Fields(s)) >= 3 {
		return true
	}
	return false
}

func computeLineStats(raw *bridge.RawPageData, line *bridge.RawLine) lineStats {
	var b strings.Builder
	chars, boldChars := 0, 0
	var sizeSum float32
	for _, idx := range sortedLineCharIndices(raw, line) {
		ch := &raw.Chars[idx]
		chars++
		sizeSum += ch.Size
		if ch.IsBold {
			boldChars++
		}
		b.WriteRune(ch.Codepoint)
	}
	txt := text.NormalizeText(b.String())
	avg := float32(12.0)
	if chars > 0 {
		avg = sizeSum / float32(chars)
	}
	br := float32(0)
	if chars > 0 {
		br = float32(boldChars) / float32(chars)
	}
	return lineStats{Text: txt, Chars: chars, Words: len(strings.Fields(txt)), BoldRatio: br, AvgSize: avg}
}

func shouldSplitLineBySemantics(prev, curr lineStats, gap, medianSize float32) bool {
	if prev.Text == "" || curr.Text == "" {
		return false
	}
	if strings.HasSuffix(strings.TrimSpace(prev.Text), ":") && curr.Words >= 4 && gap > curr.AvgSize*0.12 {
		return true
	}
	return gap > curr.AvgSize*0.12
}

func canMergeCharIntoChunk(chunk spanChunk, prevChar, currChar *bridge.RawChar, currStyle models.TextStyle, currURI string) bool {
	if prevChar == nil || chunk.Style != currStyle || chunk.URI != currURI {
		return false
	}
	baseTol := geometry.Max32(prevChar.Size, currChar.Size)*0.32 + 0.75
	if geometry.Abs32(prevChar.BBox.Y0-currChar.BBox.Y0) > baseTol {
		return false
	}
	if geometry.Abs32(prevChar.BBox.Y1-currChar.BBox.Y1) > baseTol {
		return false
	}
	if geometry.Abs32(prevChar.Size-currChar.Size) > 1.25 {
		return false
	}
	gap := currChar.BBox.X0 - prevChar.BBox.X1
	threshold := geometry.Max32(prevChar.Size, currChar.Size) * 0.62
	if unicode.IsSpace(prevChar.Codepoint) || unicode.IsSpace(currChar.Codepoint) {
		threshold *= 2.2
	}
	if isWordLikeRune(prevChar.Codepoint) && isWordLikeRune(currChar.Codepoint) {
		threshold *= 1.2
	}
	if isIntraWordConnectorRune(prevChar.Codepoint) || isIntraWordConnectorRune(currChar.Codepoint) {
		threshold *= 1.25
	}
	return gap <= threshold && gap >= -threshold
}

func resolveCharURI(ch *bridge.RawChar, links []bridge.RawLink) string {
	if len(links) == 0 {
		return ""
	}
	charRect := geometry.Rect{X0: ch.BBox.X0, Y0: ch.BBox.Y0, X1: ch.BBox.X1, Y1: ch.BBox.Y1}
	charArea := charRect.Area()
	cx, cy := (ch.BBox.X0+ch.BBox.X1)/2, (ch.BBox.Y0+ch.BBox.Y1)/2
	bestURI, bestScore := "", float32(0)
	for _, l := range links {
		if l.URI == "" {
			continue
		}
		linkRect := geometry.Rect{X0: l.Rect.X0, Y0: l.Rect.Y0, X1: l.Rect.X1, Y1: l.Rect.Y1}
		if linkRect.IsEmpty() {
			continue
		}
		centerInside := cx >= linkRect.X0 && cx <= linkRect.X1 && cy >= linkRect.Y0 && cy <= linkRect.Y1
		if !centerInside && (cx < linkRect.X0-1.0 || cx > linkRect.X1+1.0 || cy < linkRect.Y0-1.0 || cy > linkRect.Y1+1.0) {
			continue
		}
		overlap := charRect.IntersectArea(linkRect)
		score := float32(0)
		if charArea > 0 {
			score = overlap / charArea
		}
		if centerInside {
			score += 0.35
		}
		if score > bestScore {
			bestScore = score
			bestURI = l.URI
		}
	}
	if bestScore >= 0.08 {
		return bestURI
	}
	for _, l := range links {
		if l.URI == "" {
			continue
		}
		linkRect := geometry.Rect{X0: l.Rect.X0, Y0: l.Rect.Y0, X1: l.Rect.X1, Y1: l.Rect.Y1}
		if linkRect.IsEmpty() {
			continue
		}
		if charArea <= 0 {
			if cx >= linkRect.X0-1.0 && cx <= linkRect.X1+1.0 && cy >= linkRect.Y0-1.0 && cy <= linkRect.Y1+1.0 {
				return l.URI
			}
		}
	}
	return ""
}

func shouldInsertSyntheticSpace(prevChar, currChar *bridge.RawChar) bool {
	if prevChar == nil {
		return false
	}
	if unicode.IsSpace(prevChar.Codepoint) || unicode.IsSpace(currChar.Codepoint) {
		return false
	}
	if !isWordLikeRune(prevChar.Codepoint) || !isWordLikeRune(currChar.Codepoint) {
		return false
	}
	gap := currChar.BBox.X0 - prevChar.BBox.X1
	return gap > geometry.Max32(prevChar.Size, currChar.Size)*0.28
}

func isWordLikeRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

func isIntraWordConnectorRune(r rune) bool {
	switch r {
	case '-', '/', '\\', '_', '\'', '’', '.':
		return true
	default:
		return false
	}
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
	for i, idx := range sortedLineCharIndices(raw, line) {
		if i >= 12 {
			break
		}
		buf.WriteRune(raw.Chars[idx].Codepoint)
	}
	return text.StartsWithBullet(buf.String())
}

func sortedLineCharIndices(raw *bridge.RawPageData, line *bridge.RawLine) []int {
	if line == nil || line.CharCount <= 0 {
		return nil
	}
	indices := make([]int, 0, line.CharCount)
	for i := 0; i < line.CharCount; i++ {
		idx := line.CharStart + i
		if raw.Chars[idx].Codepoint != 0 {
			indices = append(indices, idx)
		}
	}
	sort.SliceStable(indices, func(i, j int) bool {
		a := raw.Chars[indices[i]]
		b := raw.Chars[indices[j]]
		if geometry.Abs32(a.BBox.X0-b.BBox.X0) > 0.5 {
			return a.BBox.X0 < b.BBox.X0
		}
		if geometry.Abs32(a.BBox.Y0-b.BBox.Y0) > 0.5 {
			return a.BBox.Y0 < b.BBox.Y0
		}
		return indices[i] < indices[j]
	})
	return indices
}

func processSpans(spans []spanChunk) []models.Span {
	var filtered []spanChunk
	for _, s := range spans {
		if s.Text != "" {
			filtered = append(filtered, s)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	filtered = mergeStyledSpanRuns(filtered)
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
		if len(final) > 0 && final[len(final)-1].Style == s.Style && final[len(final)-1].URI == s.URI {
			final[len(final)-1].Text += s.Text
			continue
		}
		final = append(final, models.Span{Text: s.Text, Style: s.Style, URI: s.URI})
	}
	return final
}

func mergeStyledSpanRuns(spans []spanChunk) []spanChunk {
	out := make([]spanChunk, 0, len(spans))
	for i := 0; i < len(spans); {
		curr := spans[i]
		if !(curr.Style.Bold || curr.Style.Italic || curr.Style.Monospace || curr.URI != "") {
			out = append(out, curr)
			i++
			continue
		}
		j := i + 1
		for j < len(spans) {
			k := j
			connector := ""
			var connectorBBox models.BBox
			hasConnector := false
			for k < len(spans) && isNeutralConnectorChunk(spans[k]) {
				if strings.ContainsRune(spans[k].Text, '\n') {
					break
				}
				if !hasConnector {
					connectorBBox = spans[k].BBox
				} else {
					connectorBBox = connectorBBox.Union(spans[k].BBox)
				}
				hasConnector = true
				connector += spans[k].Text
				k++
			}
			if !hasConnector || k >= len(spans) || !isConnectorSpanText(connector) {
				break
			}
			next := spans[k]
			if next.Style != curr.Style || next.URI != curr.URI {
				break
			}
			curr.Text += connector + next.Text
			if hasConnector {
				curr.BBox = curr.BBox.Union(connectorBBox)
			}
			curr.BBox = curr.BBox.Union(next.BBox)
			j = k + 1
		}
		out = append(out, curr)
		i = j
	}
	return out
}

func isNeutralConnectorChunk(s spanChunk) bool {
	if s.URI != "" || s.Style.Bold || s.Style.Italic || s.Style.Monospace {
		return false
	}
	return isConnectorSpanText(s.Text)
}

func isConnectorSpanText(s string) bool {
	if s == "" || strings.ContainsRune(s, '\n') {
		return false
	}
	runeCount := 0
	for _, r := range s {
		runeCount++
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return false
		}
	}
	return runeCount <= 6
}
