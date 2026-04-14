package extractor

import (
	"github.com/fibrumpdf/go/internal/geometry"
	"github.com/fibrumpdf/go/internal/models"
	"github.com/fibrumpdf/go/internal/table"
)

type tableStage struct{}

func (s tableStage) Run(ctx parseOutput, blocks []layoutBlock) ([]layoutBlock, []models.Block) {
	tableBlocks := table.ExtractAndConvertTables(ctx.raw)
	if len(tableBlocks) == 0 {
		return blocks, nil
	}
	Logger.Debug("extracted tables", "count", len(tableBlocks))
	tables := make([]models.Block, len(tableBlocks))
	copy(tables, tableBlocks)
	filtered := blocks[:0]
	for _, b := range blocks {
		if !s.overlapsTable(b.bbox, tables) {
			filtered = append(filtered, b)
		}
	}
	return filtered, tables
}

func (s tableStage) overlapsTable(bbox models.BBox, tables []models.Block) bool {
	bRect := geometry.Rect{X0: bbox[0], Y0: bbox[1], X1: bbox[2], Y1: bbox[3]}
	if bRect.Area() <= 0 {
		return false
	}
	for _, other := range tables {
		ob := other.BBox
		tableRect := geometry.Rect{X0: ob[0], Y0: ob[1], X1: ob[2], Y1: ob[3]}
		if bRect.IntersectArea(tableRect)/bRect.Area() > 0.85 {
			return true
		}
	}
	return false
}
