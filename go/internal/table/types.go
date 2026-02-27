package table

import (
	"github.com/pymupdf4llm-c/go/internal/geometry"
)

const (
	snapTolRatio    = 0.005
	joinTolRatio    = 0.005
	minCellRatio    = 0.003
	maxCellWRatio   = 0.95
	maxCellHRatio   = 0.25
	splitGapRatio   = 0.10
	rowYTolRatio    = 0.015
	colXTolRatio    = 0.003
	intersectRatio  = 0.0015
	coordScale      = 1000.0
	minHEdges       = 2
	minVEdges       = 2
	maxEdgesForGrid = 320
	heavyCharCount  = 3000
)

type Edge struct {
	X0, Y0, X1, Y1 float64
	Orientation    byte
}

type Cell struct {
	BBox geometry.Rect
	Text string
}

type Row struct {
	BBox  geometry.Rect
	Cells []Cell
}

type Table struct {
	BBox geometry.Rect
	Rows []Row
}

type TableArray struct{ Tables []Table }
