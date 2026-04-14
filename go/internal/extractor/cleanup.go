package extractor

import (
	"strings"
	"unicode"

	"github.com/fibrumpdf/go/internal/models"
	"github.com/fibrumpdf/go/internal/textutil"
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
			cleanupSpans(block.Spans, DefaultCleanup)
			for j := range block.Items {
				cleanupSpans(block.Items[j].Spans, DefaultCleanup)
			}
		case models.BlockTable:
			for j := range block.Rows {
				for k := range block.Rows[j].Cells {
					cleanupSpans(block.Rows[j].Cells[k].Spans, DefaultCleanup)
				}
			}
		case models.BlockList:
			for j := range block.Items {
				cleanupSpans(block.Items[j].Spans, DefaultCleanup)
			}
		}
	}
}

func cleanupSpans(spans []models.Span, opts CleanupOpts) {
	for i := range spans {
		spans[i].Text = cleanupSpanText(spans[i].Text, opts)
	}
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
		input = textutil.NormalizeText(input)
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
