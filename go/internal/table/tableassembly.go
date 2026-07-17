package table

import (
	"sort"

	"github.com/fibrumpdf/go/internal/geometry"
)

func assembleCells(cells []geometry.Rect, pageRect geometry.Rect) *TableArray {
	if len(cells) < 2 {
		return nil
	}
	return assembleRows(groupRows(cells, pageRect), pageRect)
}

func assembleRows(rows []Row, pageRect geometry.Rect) *TableArray {
	rows = nonEmptyRows(rows)
	if len(rows) < 2 {
		return nil
	}
	tables := segmentRows(rows, pageRect)
	if len(tables) == 0 {
		return nil
	}
	return &TableArray{Tables: tables}
}

func groupRows(cells []geometry.Rect, pageRect geometry.Rect) []Row {
	avgHeight := float32(0)
	for _, cell := range cells {
		avgHeight += cell.Height()
	}
	avgHeight /= float32(len(cells))
	groupTolerance := adaptiveRowGroupingTolerance(avgHeight, pageRect)

	sortTolerance := avgHeight * 0.2
	sort.Slice(cells, func(i, j int) bool {
		if dy := cells[i].Y0 - cells[j].Y0; geometry.Abs32(dy) > sortTolerance {
			return dy < 0
		}
		return cells[i].X0 < cells[j].X0
	})
	type heightRow struct {
		start, end int
		height     float32
	}
	heightRows := make([]heightRow, 0, len(cells)/2)
	for start := 0; start < len(cells); {
		end, height := start+1, cells[start].Height()
		for end < len(cells) && geometry.Abs32(cells[end].Y0-cells[start].Y0) < avgHeight*0.3 {
			height = geometry.Max32(height, cells[end].Height())
			end++
		}
		heightRows = append(heightRows, heightRow{start: start, end: end, height: height})
		start = end
	}
	if len(heightRows) >= 2 {
		average := float32(0)
		for _, row := range heightRows {
			average += row.height
		}
		average /= float32(len(heightRows))
		filtered := make([]geometry.Rect, 0, len(cells))
		for _, row := range heightRows {
			if ratio := row.height / average; average == 0 || row.height == 0 || (ratio > 0.4 && ratio < 2.5) {
				filtered = append(filtered, cells[row.start:row.end]...)
			}
		}
		if len(filtered) >= len(cells)*3/4 {
			cells = filtered
		}
	}

	rows := make([]Row, 0, len(cells)/2)
	for start := 0; start < len(cells); {
		end := start + 1
		for end < len(cells) && geometry.Abs32(cells[end].Y0-cells[start].Y0) <= groupTolerance {
			end++
		}
		rowCells := make([]Cell, end-start)
		for i, rect := range cells[start:end] {
			rowCells[i].BBox = rect
		}
		sort.Slice(rowCells, func(i, j int) bool { return rowCells[i].BBox.X0 < rowCells[j].BBox.X0 })
		row := Row{Cells: rowCells, BBox: rowCells[0].BBox}
		for _, cell := range rowCells[1:] {
			row.BBox = row.BBox.Union(cell.BBox)
		}
		rows = append(rows, row)
		start = end
	}
	return rows
}

func segmentRows(rows []Row, pageRect geometry.Rect) []Table {
	splitGap := rowSplitGap(rows, pageRect)
	tables := make([]Table, 0, 2)
	start := 0
	for i := 1; i <= len(rows); i++ {
		atEnd := i == len(rows)
		if !atEnd && rows[i].BBox.Y0-rows[i-1].BBox.Y1 <= splitGap {
			continue
		}
		if i-start >= 2 {
			table := Table{Rows: rows[start:i]}
			for _, row := range table.Rows {
				table.BBox = table.BBox.Union(row.BBox)
			}
			tables = append(tables, splitTableOnSparseRowRuns(table, pageRect)...)
		}
		start = i
	}
	return tables
}

func nonEmptyRows(rows []Row) []Row {
	out := rows[:0]
	for _, row := range rows {
		if len(row.Cells) > 0 && !row.BBox.IsEmpty() {
			out = append(out, row)
		}
	}
	return out
}

func rowSplitGap(rows []Row, pageRect geometry.Rect) float32 {
	totalHeight := float32(0)
	count := 0
	for _, row := range rows {
		if height := row.BBox.Height(); height > 0 {
			totalHeight += height
			count++
		}
	}
	averageHeight := float32(0)
	if count > 0 {
		averageHeight = totalHeight / float32(count)
	}
	return geometry.Min32(
		geometry.Max32(pageRect.Height()*0.03, averageHeight*2.4),
		pageRect.Height()*splitGapRatio,
	)
}
