package extractor

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/fibrumpdf/go/internal/column"
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
	// Assign column indices to tables using the same column detection as layout blocks
	tableColIndices := s.assignTableColumns(tables, ctx.bodyFontSize)

	ordered := make([]orderedBlock, 0, len(blocks)+len(tables))
	for _, b := range blocks {
		pb := postBlock{layoutBlock: b}
		if pb.typ == models.BlockList {
			items, listText := s.parseListItems(pb.text)
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
	for i, tbl := range tables {
		colIdx := 0
		if i < len(tableColIndices) {
			colIdx = tableColIndices[i]
		}
		ordered = append(ordered, orderedBlock{bbox: tbl.BBox, colIdx: colIdx, block: tbl})
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

func (s postProcessStage) assignTableColumns(tables []models.Block, bodyFontSize float32) []int {
	colIndices := make([]int, len(tables))
	if len(tables) == 0 {
		return colIndices
	}

	// Create a temporary layoutBlock-like structure for column detection
	type tempBlock struct {
		bbox   models.BBox
		colIdx int
	}

	tmpBlocks := make([]tempBlock, len(tables))
	for i := range tables {
		tmpBlocks[i] = tempBlock{bbox: tables[i].BBox, colIdx: 0}
	}

	// Convert to BlockWithColumn interface by wrapping
	blockList := make([]column.BlockWithColumn, len(tmpBlocks))
	for i := range tmpBlocks {
		blockList[i] = (*columnBlock)(&tmpBlocks[i])
	}

	// Run column detection
	column.DetectAndAssignColumns(blockList, bodyFontSize, nil)

	// Extract assigned indices
	for i := range tmpBlocks {
		colIndices[i] = tmpBlocks[i].colIdx
	}
	return colIndices
}

// columnBlock implements column.BlockWithColumn interface
type columnBlock struct {
	bbox   models.BBox
	colIdx int
}

func (cb *columnBlock) GetBBox() models.BBox {
	return cb.bbox
}

func (cb *columnBlock) SetColumnIndex(idx int) {
	cb.colIdx = idx
}

func (s postProcessStage) parseListItems(text string) ([]models.ListItem, string) {
	lines := strings.Split(text, "\n")
	items := make([]models.ListItem, 0, len(lines))
	outLines := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		kind, prefix, body := s.parseListLine(line)
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
		items = append(items, models.ListItem{Spans: []models.Span{{Text: itemText}}, ListType: itemType, Indent: 0, Prefix: prefix})
		outLines = append(outLines, itemText)
	}
	return items, strings.Join(outLines, "\n")
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
		spans[i].Text = textutil.NormalizeText(spans[i].Text)
		if spans[i].Text == "" {
			continue
		}
		if len(out) > 0 && out[len(out)-1].Style == spans[i].Style && out[len(out)-1].URI == spans[i].URI {
			out[len(out)-1].Text += spans[i].Text
			continue
		}
		out = append(out, spans[i])
	}
	return out
}
