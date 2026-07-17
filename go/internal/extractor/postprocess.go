package extractor

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/fibrumpdf/go/internal/models"
	"github.com/fibrumpdf/go/internal/textutil"
)

type postProcessStage struct{}

type postBlock struct {
	layoutBlock
	listItems []models.ListItem
}

type orderedBlock struct {
	bbox   models.BBox
	colIdx int
	block  models.Block
}

func (s postProcessStage) Run(ctx parseOutput, blocks []layoutBlock, tables []models.Block) []models.Block {
	ordered := make([]orderedBlock, 0, len(blocks)+len(tables))
	for _, b := range blocks {
		pb := postBlock{layoutBlock: b}
		if pb.typ == models.BlockList {
			items, listText := s.parseListItems(pb.listLines)
			if len(items) == 0 {
				continue
			}
			pb.listItems = items
			pb.text = listText
			pb.textChars = utf8.RuneCountInString(listText)
			pb.spans = []models.Span{{Text: listText}}
		}
		if s.isBoundaryNoise(ctx, pb) {
			continue
		}
		if !s.hasVisibleContent(pb.text) {
			continue
		}
		ordered = append(ordered, orderedBlock{bbox: pb.bbox, colIdx: pb.colIdx, block: pb.toBlock()})
	}
	for _, tbl := range tables {
		ordered = append(ordered, orderedBlock{bbox: tbl.BBox, colIdx: 0, block: tbl})
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return ReadingOrderLess(ordered[i].bbox, ordered[j].bbox, ordered[i].colIdx, ordered[j].colIdx)
	})
	out := make([]models.Block, 0, len(ordered))
	for _, b := range ordered {
		blk := b.block
		s.cleanBlockSpans(&blk)
		out = append(out, blk)
	}
	return out
}

func (s postProcessStage) parseListItems(lines []parsedListLine) ([]models.ListItem, string) {
	items := make([]models.ListItem, 0, len(lines))
	outLines := make([]string, 0, len(lines))
	for _, line := range lines {
		text := strings.TrimSpace(line.text)
		if text == "" {
			continue
		}
		kind, prefix, body := s.parseListLine(text)
		if kind == listNone || body == "" {
			continue
		}
		itemType := models.ListTypeBulleted
		marker := "-"
		if kind == listNumbered {
			itemType = models.ListTypeNumbered
			marker = prefix
		}
		itemText := strings.TrimSpace(marker + " " + body)
		items = append(items, models.ListItem{
			Spans: s.listBodySpans(line.spans, text, body), ListType: itemType,
			Indent: line.indent, Prefix: prefix,
		})
		outLines = append(outLines, itemText)
	}
	return items, strings.Join(outLines, "\n")
}

func (s postProcessStage) listBodySpans(spans []models.Span, line, body string) []models.Span {
	bodyAt := strings.Index(line, body)
	if bodyAt < 0 {
		return []models.Span{{Text: body}}
	}
	drop := utf8.RuneCountInString(line[:bodyAt])
	out := make([]models.Span, 0, len(spans))
	for _, span := range spans {
		runes := []rune(span.Text)
		if drop >= len(runes) {
			drop -= len(runes)
			continue
		}
		span.Text = string(runes[drop:])
		drop = 0
		out = append(out, span)
	}
	if len(out) == 0 {
		return []models.Span{{Text: body}}
	}
	out[len(out)-1].Text = strings.TrimRightFunc(out[len(out)-1].Text, unicode.IsSpace)
	return out
}

type listKind uint8

const (
	listNone listKind = iota
	listBullet
	listNumbered
)

func (s postProcessStage) parseListLine(line string) (listKind, string, string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return listNone, "", ""
	}
	runes := []rune(line)
	if len(runes) > 1 && isBulletRune(runes[0]) && unicode.IsSpace(runes[1]) {
		return listBullet, "", strings.TrimSpace(string(runes[1:]))
	}
	if numbered, prefix := startsWithNumberMarker(line); numbered {
		return listNumbered, prefix, strings.TrimSpace(strings.TrimPrefix(line, prefix))
	}
	return listNone, "", ""
}

func (s postProcessStage) isBoundaryNoise(ctx parseOutput, b postBlock) bool {
	if b.textChars == 0 {
		return true
	}
	if !s.isLonePageNumber(b.text) {
		return false
	}
	pb := ctx.raw.PageBounds
	height := pb.Y1 - pb.Y0
	margin := height * ctx.cfg.MarginThreshold
	return b.bbox.Y0() <= pb.Y0+margin || b.bbox.Y1() >= pb.Y1-margin
}

func (s postProcessStage) isLonePageNumber(text string) bool {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return false
	}
	for _, r := range trimmed {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return len(trimmed) <= 4
}

func (s postProcessStage) hasVisibleContent(text string) bool {
	for _, r := range text {
		if unicode.IsSpace(r) {
			continue
		}
		if unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsPunct(r) || unicode.IsSymbol(r) {
			return true
		}
	}
	return false
}

func (b postBlock) toBlock() models.Block {
	return models.Block{
		Type:     b.typ,
		BBox:     b.bbox,
		Length:   b.textChars,
		Level:    b.headingLevel,
		FontSize: b.avgFontSize,
		Lines:    b.lineCount,
		Spans:    b.spans,
		Items:    b.listItems,
	}
}

func (s postProcessStage) cleanBlockSpans(block *models.Block) {
	switch block.Type {
	case models.BlockTable:
		for i := range block.Rows {
			for j := range block.Rows[i].Cells {
				block.Rows[i].Cells[j].Spans = s.cleanSpans(block.Rows[i].Cells[j].Spans)
			}
		}
	case models.BlockList:
		for i := range block.Items {
			block.Items[i].Spans = s.cleanSpans(block.Items[i].Spans)
		}
	default:
		block.Spans = s.cleanSpans(block.Spans)
	}
}

func (s postProcessStage) cleanSpans(spans []models.Span) []models.Span {
	if len(spans) == 0 {
		return nil
	}
	out := make([]models.Span, 0, len(spans))
	for i := range spans {
		spans[i].Text = textutil.NormalizeTextFragment(spans[i].Text)
		if spans[i].Text == "" {
			continue
		}
		if len(out) > 0 {
			last := len(out) - 1
			if startsWithSpace(spans[i].Text) && endsWithSpace(out[last].Text) {
				spans[i].Text = strings.TrimLeftFunc(spans[i].Text, unicode.IsSpace)
				if spans[i].Text == "" {
					continue
				}
			}
			if out[last].Style == spans[i].Style && out[last].URI == spans[i].URI {
				out[last].Text += spans[i].Text
				continue
			}
		}
		out = append(out, spans[i])
	}
	if len(out) > 0 {
		out[len(out)-1].Text = strings.TrimRightFunc(out[len(out)-1].Text, unicode.IsSpace)
	}
	return out
}

func startsWithSpace(text string) bool {
	r, _ := utf8.DecodeRuneInString(text)
	return r != utf8.RuneError && unicode.IsSpace(r)
}

func endsWithSpace(text string) bool {
	r, _ := utf8.DecodeLastRuneInString(text)
	return r != utf8.RuneError && unicode.IsSpace(r)
}
