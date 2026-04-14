package extractor

import (
	"sort"

	"github.com/fibrumpdf/go/internal/column"
	"github.com/fibrumpdf/go/internal/geometry"
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
	column.DetectAndAssignColumns(colBlocks, ctx.bodyFontSize, nil)
	s.sortLayoutBlocks(layoutBlocks)
	return layoutBlocks
}

func (s layoutStage) sortLayoutBlocks(blocks []layoutBlock) {
	sort.SliceStable(blocks, func(i, j int) bool {
		return ReadingOrderLess(blocks[i].bbox, blocks[j].bbox, blocks[i].colIdx, blocks[j].colIdx)
	})
}

func ReadingOrderLess(bi, bj models.BBox, colI, colJ int) bool {
	if colI == colJ {
		if geometry.Abs32(bi.Y0()-bj.Y0()) > 2.0 {
			return bi.Y0() < bj.Y0()
		}
		return bi.X0() < bj.X0()
	}
	if colI == 0 || colJ == 0 {
		if geometry.Abs32(bi.Y0()-bj.Y0()) > 2.0 {
			return bi.Y0() < bj.Y0()
		}
		return colI == 0
	}
	return colI < colJ
}
