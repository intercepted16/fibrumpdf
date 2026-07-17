package table

import (
	"slices"
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

	byY := make(map[float32][]geometry.Rect)
	for _, cell := range cells {
		matchedY := float32(-1)
		for y := range byY {
			if geometry.Abs32(cell.Y0-y) < avgHeight*0.3 {
				matchedY = y
				break
			}
		}
		if matchedY >= 0 {
			byY[matchedY] = append(byY[matchedY], cell)
		} else {
			byY[cell.Y0] = []geometry.Rect{cell}
		}
	}

	yPositions := make([]float32, 0, len(byY))
	for y := range byY {
		yPositions = append(yPositions, y)
	}
	slices.Sort(yPositions)

	rowHeights := make([]float32, 0, len(yPositions))
	for _, y := range yPositions {
		height := float32(0)
		for _, cell := range byY[y] {
			height = geometry.Max32(height, cell.Height())
		}
		rowHeights = append(rowHeights, height)
	}
	if len(rowHeights) >= 2 {
		average := float32(0)
		for _, height := range rowHeights {
			average += height
		}
		average /= float32(len(rowHeights))
		filtered := make([]geometry.Rect, 0, len(cells))
		for i, y := range yPositions {
			ratio := rowHeights[i] / average
			if average == 0 || rowHeights[i] == 0 || (ratio > 0.4 && ratio < 2.5) {
				filtered = append(filtered, byY[y]...)
			}
		}
		if len(filtered) >= len(cells)*3/4 {
			cells = filtered
		}
	}

	sortTolerance := avgHeight * 0.2
	sort.Slice(cells, func(i, j int) bool {
		if dy := cells[i].Y0 - cells[j].Y0; geometry.Abs32(dy) > sortTolerance {
			return dy < 0
		}
		return cells[i].X0 < cells[j].X0
	})

	rows := make([]Row, 0, len(yPositions))
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
			if !isFullPageTable(table, pageRect) {
				tables = append(tables, splitTableOnSparseRowRuns(table, pageRect)...)
			}
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

func isFullPageTable(table Table, pageRect geometry.Rect) bool {
	return pageRect.Height() > 0 && table.BBox.Height()/pageRect.Height() > 0.9 && len(table.Rows) > 10
}
