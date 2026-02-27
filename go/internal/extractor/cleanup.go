package extractor

import (
	"strings"
	"unicode"

	"github.com/pymupdf4llm-c/go/internal/models"
	"github.com/pymupdf4llm-c/go/internal/text"
)

type CleanupOpts struct {
	Normalize      bool
	CollapseSpaces bool
	Trim           bool
	BrokenUnicode  bool
	BrokenBullets  bool
}

var DefaultCleanup = CleanupOpts{
	Normalize:      true,
	CollapseSpaces: true,
	Trim:           true,
	BrokenUnicode:  true,
	BrokenBullets:  true,
}

func CleanupPage(blocks []models.Block) {
	convertBulletBlocksToLists(&blocks)

	for i := range blocks {
		block := &blocks[i]
		switch block.Type {
		case models.BlockText, models.BlockHeading, models.BlockFootnote, models.BlockOther, models.BlockCode:
			block.Spans = cleanupSpans(block.Spans, DefaultCleanup)
			for j := range block.Items {
				block.Items[j].Spans = cleanupSpans(block.Items[j].Spans, DefaultCleanup)
			}
		case models.BlockTable:
			for j := range block.Rows {
				for k := range block.Rows[j].Cells {
					block.Rows[j].Cells[k].Spans = cleanupSpans(block.Rows[j].Cells[k].Spans, DefaultCleanup)
				}
			}
		case models.BlockList:
			for j := range block.Items {
				block.Items[j].Spans = cleanupSpans(block.Items[j].Spans, DefaultCleanup)
			}
		}
	}
}

func cleanupSpans(spans []models.Span, opts CleanupOpts) []models.Span {
	if len(spans) == 0 {
		return nil
	}
	spanOpts := opts
	spanOpts.Trim = false
	var cleaned []models.Span
	for i := range spans {
		spans[i].Text = cleanupSpanText(spans[i].Text, spanOpts)
		if spans[i].Text != "" {
			cleaned = append(cleaned, spans[i])
		}
	}
	if len(cleaned) == 0 {
		return nil
	}
	cleaned[0].Text = strings.TrimLeft(cleaned[0].Text, " \t\n\r\u00A0")
	cleaned[len(cleaned)-1].Text = strings.TrimRight(cleaned[len(cleaned)-1].Text, " \t\n\r\u00A0")
	out := cleaned[:0]
	for _, s := range cleaned {
		if s.Text == "" {
			continue
		}
		if len(out) > 0 && out[len(out)-1].Style == s.Style && out[len(out)-1].URI == s.URI {
			out[len(out)-1].Text += s.Text
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cleanupSpanText(input string, opts CleanupOpts) string {
	if input == "" {
		return ""
	}

	if opts.BrokenUnicode {
		input = strings.ToValidUTF8(input, "")
		input = strings.ReplaceAll(input, "\uFFFD", "")
	}

	if opts.Normalize {
		input = strings.ReplaceAll(input, "-\n", "")
		input = text.NormalizeText(input)
	}

	if opts.CollapseSpaces {
		for strings.Contains(input, "  ") {
			input = strings.ReplaceAll(input, "  ", " ")
		}
	}

	if opts.Trim {
		input = strings.TrimSpace(input)
	}

	return input
}

func convertBulletBlocksToLists(blocks *[]models.Block) {
	if blocks == nil || len(*blocks) == 0 {
		return
	}

	i := 0
	for i < len(*blocks) {
		block := &(*blocks)[i]

		if shouldConvertToList(block) {

			listItem := convertBlockToListItem(block)

			mergedPrev := false
			mergedNext := false

			if i > 0 && (*blocks)[i-1].Type == models.BlockList {

				(*blocks)[i-1].Items = append((*blocks)[i-1].Items, listItem)

				*blocks = append((*blocks)[:i], (*blocks)[i+1:]...)
				mergedPrev = true
			}

			if !mergedPrev && i+1 < len(*blocks) && (*blocks)[i+1].Type == models.BlockList {

				(*blocks)[i+1].Items = append([]models.ListItem{listItem}, (*blocks)[i+1].Items...)

				*blocks = append((*blocks)[:i], (*blocks)[i+1:]...)
				mergedNext = true
			}

			if !mergedPrev && !mergedNext {
				block.Type = models.BlockList
				block.Items = []models.ListItem{listItem}
				block.Spans = nil
				i++
			}

		} else {
			i++
		}
	}
}

func shouldConvertToList(block *models.Block) bool {
	if block == nil || len(block.Spans) < 2 {
		return false
	}

	firstSpan := block.Spans[0]
	if !firstSpan.Style.Monospace {
		return false
	}

	if !isOnlyBulletChar(firstSpan.Text) {
		return false
	}

	secondSpan := block.Spans[1]
	return hasASCIIText(secondSpan.Text)
}

func isOnlyBulletChar(text string) bool {
	hasO := false
	for _, r := range text {
		if unicode.IsSpace(r) {
			continue
		}
		if r != 'o' && r != 'O' {
			return false
		}
		hasO = true
	}
	return hasO
}

func hasASCIIText(text string) bool {
	for _, r := range text {
		if r >= 32 && r <= 126 && !unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func convertBlockToListItem(block *models.Block) models.ListItem {
	spans := block.Spans[1:]

	return models.ListItem{
		Spans:    spans,
		ListType: "bulleted",
		Indent:   0,
		Prefix:   "",
	}
}
