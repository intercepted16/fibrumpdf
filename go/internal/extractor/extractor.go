package extractor

import (
	"github.com/fibrumpdf/go/internal/logger"
	"github.com/fibrumpdf/go/internal/models"
	rawdata "github.com/fibrumpdf/go/internal/raw"
)

var Logger = logger.GetLogger("extractor")

type pagePipeline struct {
	parser     parserStage
	splitter   splitStage
	classifier classifyStage
	layouter   layoutStage
	tabler     tableStage
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
	nonTables, tables := p.tabler.Run(parsed, layouted)
	final := p.post.Run(parsed, nonTables, tables)
	Logger.Debug("page extraction complete", "pageNum", raw.PageNumber, "finalBlocks", len(final))
	return models.Page{Number: raw.PageNumber, Data: final}
}
