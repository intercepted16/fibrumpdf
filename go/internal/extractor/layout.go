package extractor

import (
	"github.com/fibrumpdf/go/internal/column"
	"github.com/fibrumpdf/go/internal/models"
)

type layoutBlock struct {
	classifiedBlock
	colIdx int
}

func (b *layoutBlock) GetBBox() models.BBox   { return b.bbox }
func (b *layoutBlock) SetColumnIndex(idx int) { b.colIdx = idx }

type layoutStage struct{}

func (s layoutStage) Run(ctx parseOutput, blocks []classifiedBlock) []layoutBlock {
	layoutBlocks := make([]layoutBlock, len(blocks))
	for i := range blocks {
		layoutBlocks[i] = layoutBlock{classifiedBlock: blocks[i]}
	}
	colBlocks := make([]column.BlockWithColumn, len(layoutBlocks))
	for i := range layoutBlocks {
		colBlocks[i] = &layoutBlocks[i]
	}
	column.DetectAndAssignColumns(colBlocks, ctx.bodyFontSize)
	return layoutBlocks
}
