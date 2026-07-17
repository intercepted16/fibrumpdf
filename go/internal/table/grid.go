package table

import (
	"sort"
	"strings"

	"github.com/fibrumpdf/go/internal/geometry"
)

func normalizeGrid(table *Table, pageRect geometry.Rect, preserveEmptyColumns bool) {
	if table == nil || len(table.Rows) == 0 {
		return
	}
	pruneEmptyRows(table)
	alignColumns(table, pageRect)
	pruneEmptyRows(table)
	if !preserveEmptyColumns {
		dropEmptyColumns(table)
	}
	padRows(table)
}

func pruneEmptyRows(table *Table) {
	rows := table.Rows[:0]
	for _, row := range table.Rows {
		for _, cell := range row.Cells {
			if !cell.BBox.IsEmpty() {
				rows = append(rows, row)
				break
			}
		}
	}
	table.Rows = rows
}

func dropEmptyColumns(table *Table) {
	if len(table.Rows) == 0 || len(table.Rows[0].Cells) == 0 {
		return
	}
	columns := len(table.Rows[0].Cells)
	keep := make([]bool, columns)
	for _, row := range table.Rows {
		for column, cell := range row.Cells {
			if column < columns && (!cell.BBox.IsEmpty() || strings.TrimSpace(cell.Text) != "") {
				keep[column] = true
			}
		}
	}
	kept := 0
	for _, ok := range keep {
		if ok {
			kept++
		}
	}
	if kept == 0 || kept == columns {
		return
	}
	for i := range table.Rows {
		cells := make([]Cell, 0, kept)
		for column, ok := range keep {
			if ok && column < len(table.Rows[i].Cells) {
				cells = append(cells, table.Rows[i].Cells[column])
			}
		}
		table.Rows[i].Cells = cells
	}
}

func padRows(table *Table) {
	columns := 0
	for _, row := range table.Rows {
		columns = max(columns, len(row.Cells))
	}
	for i := range table.Rows {
		if missing := columns - len(table.Rows[i].Cells); missing > 0 {
			table.Rows[i].Cells = append(table.Rows[i].Cells, make([]Cell, missing)...)
		}
	}
}

func alignColumns(table *Table, pageRect geometry.Rect) {
	coordinates := make(map[int]struct{})
	for _, row := range table.Rows {
		for _, cell := range row.Cells {
			if !cell.BBox.IsEmpty() {
				coordinates[coordToInt(float64(cell.BBox.X0))] = struct{}{}
				coordinates[coordToInt(float64(cell.BBox.X1))] = struct{}{}
			}
		}
	}
	x := make([]int, 0, len(coordinates))
	for coordinate := range coordinates {
		x = append(x, coordinate)
	}
	sort.Ints(x)

	tolerance := max(int(pageRect.Width()*colXTolRatio*coordScale), 2000)
	columns := make([][2]float32, 0, len(x)/2)
	for i := 0; i < len(x)-1; {
		start := x[i]
		end := i + 1
		for end < len(x) && x[end]-start < tolerance {
			end++
		}
		if end >= len(x) {
			break
		}
		columns = append(columns, [2]float32{float32(start) / coordScale, float32(x[end]) / coordScale})
		i = end
	}
	if len(columns) == 0 {
		return
	}

	for rowIndex := range table.Rows {
		aligned := make([]Cell, len(columns))
		for _, cell := range table.Rows[rowIndex].Cells {
			if cell.BBox.IsEmpty() {
				continue
			}
			best, overlap := -1, float32(0)
			for column, bounds := range columns {
				candidate := geometry.Min32(cell.BBox.X1, bounds[1]) - geometry.Max32(cell.BBox.X0, bounds[0])
				if candidate > overlap {
					best, overlap = column, candidate
				}
			}
			if best >= 0 && (aligned[best].BBox.IsEmpty() || overlap > aligned[best].BBox.Width()*0.5) {
				aligned[best] = cell
			}
		}
		table.Rows[rowIndex].Cells = aligned
	}
}
