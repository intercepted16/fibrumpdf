package extractor

import (
	"github.com/fibrumpdf/go/internal/geometry"
	"github.com/fibrumpdf/go/internal/logger"
	"github.com/fibrumpdf/go/internal/models"
	rawdata "github.com/fibrumpdf/go/internal/raw"
	"github.com/fibrumpdf/go/internal/table"
)

var Logger = logger.GetLogger("extractor")

type pagePipeline struct {
	parser     parserStage
	splitter   splitStage
	classifier classifyStage
	layouter   layoutStage
	post       postProcessStage
}

func newPagePipeline() pagePipeline {
	return pagePipeline{}
}

func ExtractPageFromRaw(raw *rawdata.PageData) models.Page {
	return ExtractPageFromRawWithConfig(raw, NewDefaultExtractionConfig())
}

func ExtractPageFromRawWithConfig(raw *rawdata.PageData, cfg ExtractionConfig) models.Page {
	if raw == nil {
		return models.Page{}
	}
	Logger.Debug("extracting page", "pageNum", raw.PageNumber, "blocks", len(raw.Blocks), "chars", len(raw.Chars))
	p := newPagePipeline()
	parsed := p.parser.Run(raw, cfg)
	split := p.splitter.Run(parsed)
	classified := p.classifier.Run(parsed, split)
	layouted := p.layouter.Run(parsed, classified)

	// Extract and filter tables
	tableBlocks := table.ExtractAndConvertTables(parsed.raw)
	var tables []models.Block
	nonTables := layouted[:0]
	if len(tableBlocks) > 0 {
		Logger.Debug("extracted tables", "count", len(tableBlocks))
		tables = make([]models.Block, len(tableBlocks))
		copy(tables, tableBlocks)
		for _, b := range layouted {
			if !overlapsTable(b.bbox, tables) {
				nonTables = append(nonTables, b)
			}
		}
	} else {
		nonTables = layouted
	}

	final := p.post.Run(parsed, nonTables, tables)
	Logger.Debug("page extraction complete", "pageNum", raw.PageNumber, "finalBlocks", len(final))
	return models.Page{Number: raw.PageNumber, Data: final}
}

func overlapsTable(bbox models.BBox, tables []models.Block) bool {
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
