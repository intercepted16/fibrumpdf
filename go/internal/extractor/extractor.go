package extractor

import (
	"github.com/fibrumpdf/go/internal/logger"
	"github.com/fibrumpdf/go/internal/models"
	rawdata "github.com/fibrumpdf/go/internal/raw"
)

var Logger = logger.GetLogger("extractor")

func ExtractPageFromRaw(raw *rawdata.PageData) models.Page {
	return ExtractPageFromRawWithConfig(raw, NewDefaultExtractionConfig())
}

func ExtractPageFromRawWithConfig(raw *rawdata.PageData, cfg ExtractionConfig) models.Page {
	if raw == nil {
		return models.Page{}
	}
	Logger.Debug("extracting page", "pageNum", raw.PageNumber, "blocks", len(raw.Blocks), "chars", len(raw.Chars))
	parsed := parsePage(raw, cfg)
	split := splitBlocks(parsed)
	classified := classifyBlocks(parsed, split)
	layouted := layoutBlocks(parsed, classified)
	nonTables, tables := extractTables(parsed, layouted)
	final := postProcess(parsed, nonTables, tables)
	Logger.Debug("page extraction complete", "pageNum", raw.PageNumber, "finalBlocks", len(final))
	return models.Page{Number: raw.PageNumber, Data: final}
}
