package table

import (
	"github.com/pymupdf4llm-c/go/internal/geometry"
	"github.com/pymupdf4llm-c/go/internal/raw"
)

const (
	snapTolRatio    = 0.015
	joinTolRatio    = 0.005
	minCellRatio    = 0.003
	maxCellWRatio   = 0.95
	maxCellHRatio   = 0.25
	splitGapRatio   = 0.10
	rowYTolRatio    = 0.015
	colXTolRatio    = 0.003
	intersectRatio  = 0.0015
	cordScale       = 1000.0
	minHEdges       = 2
	minVEdges       = 2
	maxEdgesForGrid = 320
	heavyCharCount  = 3000
)

type Edge = raw.Edge

type Cell struct {
	BBox geometry.Rect
	Text string
}

type Row struct {
	BBox  geometry.Rect
	Cells []Cell
}

type Table struct {
	BBox       geometry.Rect
	Rows       []Row
	RuledTable bool // true when built from physical grid lines (hEdges+vEdges)
}

type TableArray struct{ Tables []Table }

func (tables *TableArray) isEmpty() bool {
	return tables == nil || len(tables.Tables) == 0
}
