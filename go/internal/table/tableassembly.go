package table

import (
	"math"
	"slices"
	"sort"

	"github.com/pymupdf4llm-c/go/internal/geometry"
)

// AssemblyConfig contains configuration for table assembly.
type AssemblyConfig struct {
	MinSplitGapRatio float32
	RowGapMultiplier float32
	MaxSplitGapRatio float32
}

// NewDefaultTableAssemblyConfig returns the default assembly configuration.
func NewDefaultTableAssemblyConfig() AssemblyConfig {
	return AssemblyConfig{
		MinSplitGapRatio: 0.03,
		RowGapMultiplier: 2.4,
		MaxSplitGapRatio: splitGapRatio,
	}
}

// RowGrouper builds rows from detected cells.
type RowGrouper interface {
	GroupRows(cells []geometry.Rect, pageRect geometry.Rect) []Row
}

// Segmenter splits rows into tables.
type Segmenter interface {
	Segment(rows []Row, pageRect geometry.Rect) []Table
}

// Assembler provides unified table assembly logic.
type Assembler struct {
	cfg        AssemblyConfig
	rowGrouper RowGrouper
	segmenter  Segmenter
}

// NewAssembler creates a new table assembler.
func NewAssembler(cfg AssemblyConfig, rowGrouper RowGrouper, segmenter Segmenter) *Assembler {
	return &Assembler{cfg: cfg, rowGrouper: rowGrouper, segmenter: segmenter}
}

// NewDefaultTableAssembler creates a default table assembler.
func NewDefaultTableAssembler(cfg AssemblyConfig) *Assembler {
	return NewAssembler(cfg, RowGrouperDefault{}, RowGapSegmenter{cfg: cfg})
}

// AssembleFromCells assembles tables from detected cells.
func (ta *Assembler) AssembleFromCells(cells []geometry.Rect, pageRect geometry.Rect) *TableArray {
	if len(cells) < 2 {
		return nil
	}
	rows := ta.rowGrouper.GroupRows(cells, pageRect)
	return ta.AssembleFromRows(rows, pageRect)
}

// AssembleFromRows assembles tables from pre-grouped rows.
func (ta *Assembler) AssembleFromRows(rows []Row, pageRect geometry.Rect) *TableArray {
	rows = filterEmptyRows(rows)
	if len(rows) < 2 {
		return nil
	}
	tables := ta.segmenter.Segment(rows, pageRect)
	if len(tables) == 0 {
		return nil
	}
	return &TableArray{Tables: tables}
}

// RowGrouperDefault groups cell rectangles into rows.
type RowGrouperDefault struct{}

// GroupRows groups cells into rows using a tolerance derived from average height.
func (RowGrouperDefault) GroupRows(cells []geometry.Rect, pageRect geometry.Rect) []Row {
	var avgH float32
	for _, c := range cells {
		avgH += c.Height()
	}
	avgH /= float32(len(cells))
	rowGroupTol := adaptiveRowGroupingTolerance(avgH, pageRect)

	rowHeights := make(map[float32][]geometry.Rect)
	rowTol := avgH * 0.3
	for _, c := range cells {
		foundKey := float32(-1)
		for key := range rowHeights {
			if geometry.Abs32(c.Y0-key) < rowTol {
				foundKey = key
				break
			}
		}
		if foundKey >= 0 {
			rowHeights[foundKey] = append(rowHeights[foundKey], c)
		} else {
			rowHeights[c.Y0] = []geometry.Rect{c}
		}
	}

	var rowYPositions []float32
	for y := range rowHeights {
		rowYPositions = append(rowYPositions, y)
	}
	slices.Sort(rowYPositions)

	var heights []float32
	for _, y := range rowYPositions {
		if len(rowHeights[y]) > 0 {
			h := rowHeights[y][0].Height()
			for _, c := range rowHeights[y][1:] {
				h = geometry.Max32(h, c.Height())
			}
			heights = append(heights, h)
		}
	}
	if len(heights) >= 2 {
		var sumH float32
		for _, h := range heights {
			sumH += h
		}
		avgRowH := sumH / float32(len(heights))
		var filteredCells []geometry.Rect
		for _, y := range rowYPositions {
			rowCells := rowHeights[y]
			var rowH float32
			for _, c := range rowCells {
				rowH = geometry.Max32(rowH, c.Height())
			}
			if avgRowH > 0 && rowH > 0 {
				ratio := rowH / avgRowH
				if ratio < 2.5 && ratio > 0.4 {
					filteredCells = append(filteredCells, rowCells...)
				} else {
					Logger.Debug("filtered row by height consistency", "rowH", rowH, "avgRowH", avgRowH, "ratio", ratio)
				}
			} else {
				filteredCells = append(filteredCells, rowCells...)
			}
		}
		if len(filteredCells) < len(cells)*3/4 {
			cells = filteredCells
		}
	}

	sortTol := avgH * 0.2
	sort.Slice(cells, func(i, j int) bool {
		if dy := cells[i].Y0 - cells[j].Y0; geometry.Abs32(dy) > sortTol {
			return dy < 0
		}
		return cells[i].X0 < cells[j].X0
	})
	var rows []Row
	for i := 0; i < len(cells); {
		rowY0, yTol := cells[i].Y0, rowGroupTol
		j := i + 1
		for j < len(cells) && math.Abs(float64(cells[j].Y0-rowY0)) <= float64(yTol) {
			j++
		}
		rowCells := make([]Cell, j-i)
		for k := 0; k < j-i; k++ {
			rowCells[k].BBox = cells[i+k]
		}
		sort.Slice(rowCells, func(k1, k2 int) bool { return rowCells[k1].BBox.X0 < rowCells[k2].BBox.X0 })
		row := Row{Cells: rowCells, BBox: rowCells[0].BBox}
		for k := 1; k < len(rowCells); k++ {
			row.BBox = row.BBox.Union(rowCells[k].BBox)
		}
		rows = append(rows, row)
		i = j
	}
	return rows
}

// RowGapSegmenter segments rows into tables based on vertical gaps.
type RowGapSegmenter struct {
	cfg AssemblyConfig
}

// Segment splits rows into tables using gap thresholds and structural separators.
func (s RowGapSegmenter) Segment(rows []Row, pageRect geometry.Rect) []Table {
	splitGap := computeSplitGap(rows, pageRect, s.cfg)
	var tables []Table
	var cur Table
	for i := 0; i < len(rows); i++ {
		row := rows[i]
		if len(cur.Rows) > 0 {
			gap := row.BBox.Y0 - cur.Rows[len(cur.Rows)-1].BBox.Y1
			if gap > splitGap {
				if len(cur.Rows) >= 2 && !shouldRejectFullPageTable(cur, pageRect) {
					tables = append(tables, cur)
				}
				cur = Table{}
			}
		}
		cur.Rows = append(cur.Rows, row)
		cur.BBox = cur.BBox.Union(row.BBox)
	}
	if len(cur.Rows) >= 2 && !shouldRejectFullPageTable(cur, pageRect) {
		tables = append(tables, cur)
	}
	if len(tables) == 0 {
		return nil
	}
	var segmented []Table
	for _, tbl := range tables {
		parts := splitTableOnSparseRowRuns(tbl, pageRect)
		segmented = append(segmented, parts...)
	}
	return segmented
}

func filterEmptyRows(rows []Row) []Row {
	filtered := rows[:0]
	for _, row := range rows {
		if len(row.Cells) == 0 || row.BBox.IsEmpty() {
			continue
		}
		filtered = append(filtered, row)
	}
	return filtered
}

func computeSplitGap(rows []Row, pageRect geometry.Rect, cfg AssemblyConfig) float32 {
	var sumH float32
	count := 0
	for _, row := range rows {
		h := row.BBox.Height()
		if h > 0 {
			sumH += h
			count++
		}
	}
	avgH := float32(0)
	if count > 0 {
		avgH = sumH / float32(count)
	}
	splitGap := geometry.Max32(pageRect.Height()*cfg.MinSplitGapRatio, avgH*cfg.RowGapMultiplier)
	maxGap := pageRect.Height() * cfg.MaxSplitGapRatio
	if splitGap > maxGap {
		splitGap = maxGap
	}
	return splitGap
}

func shouldRejectFullPageTable(tbl Table, pageRect geometry.Rect) bool {
	if pageRect.Height() <= 0 {
		return false
	}
	tableHeight := tbl.BBox.Height()
	return tableHeight/pageRect.Height() > 0.9 && len(tbl.Rows) > 10
}
