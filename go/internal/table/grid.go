package table

import (
	"sort"
	"strings"

	"github.com/fibrumpdf/go/internal/geometry"
)

type GridNormalizeOptions struct {
	PreserveEmptyColumns bool
	NormalizeColumns     bool
	PageRect             geometry.Rect
}

type Grid struct {
	Table *Table
}

func NewTableGrid(tbl *Table) *Grid {
	return &Grid{Table: tbl}
}

func (g *Grid) Normalize(opts GridNormalizeOptions) {
	if g == nil || g.Table == nil || len(g.Table.Rows) == 0 {
		return
	}
	g.pruneEmptyRows()
	if len(g.Table.Rows) == 0 {
		return
	}
	g.padRowsToMaxCols()
	if !opts.PreserveEmptyColumns {
		g.dropEmptyColumns()
	}
	g.normalizeRowWidths()
	if opts.NormalizeColumns {
		g.normalizeColumns(opts.PageRect)
		g.pruneEmptyRows()
		if !opts.PreserveEmptyColumns {
			g.dropEmptyColumns()
		}
		g.normalizeRowWidths()
	}
}

func (g *Grid) pruneEmptyRows() {
	validRows := g.Table.Rows[:0]
	for _, row := range g.Table.Rows {
		for _, c := range row.Cells {
			if c.BBox.IsEmpty() {
				continue
			}
			validRows = append(validRows, row)
			break
		}
	}
	g.Table.Rows = validRows
}

func (g *Grid) padRowsToMaxCols() {
	maxCols := 0
	for _, row := range g.Table.Rows {
		if len(row.Cells) > maxCols {
			maxCols = len(row.Cells)
		}
	}
	if maxCols == 0 {
		return
	}
	for r := range g.Table.Rows {
		row := &g.Table.Rows[r]
		if len(row.Cells) >= maxCols {
			continue
		}
		padded := make([]Cell, maxCols)
		copy(padded, row.Cells)
		row.Cells = padded
	}
}

func (g *Grid) dropEmptyColumns() {
	if len(g.Table.Rows) == 0 {
		return
	}
	colCount := len(g.Table.Rows[0].Cells)
	if colCount == 0 {
		return
	}
	keepCols := make([]bool, colCount)
	for _, row := range g.Table.Rows {
		for c, cell := range row.Cells {
			if !cell.BBox.IsEmpty() || strings.TrimSpace(cell.Text) != "" {
				keepCols[c] = true
			}
		}
	}
	newColCount := 0
	for _, k := range keepCols {
		if k {
			newColCount++
		}
	}
	if newColCount == 0 || newColCount >= colCount {
		return
	}
	for r := range g.Table.Rows {
		oldCells := g.Table.Rows[r].Cells
		newCells := make([]Cell, 0, newColCount)
		for c, cell := range oldCells {
			if c < len(keepCols) && keepCols[c] {
				newCells = append(newCells, cell)
			}
		}
		g.Table.Rows[r].Cells = newCells
	}
}

func (g *Grid) normalizeRowWidths() {
	if len(g.Table.Rows) == 0 {
		return
	}
	colCount := len(g.Table.Rows[0].Cells)
	for r := 1; r < len(g.Table.Rows); r++ {
		row := &g.Table.Rows[r]
		if len(row.Cells) > colCount {
			row.Cells = row.Cells[:colCount]
			continue
		}
		if len(row.Cells) < colCount {
			padded := make([]Cell, colCount)
			copy(padded, row.Cells)
			row.Cells = padded
		}
	}
}

func (g *Grid) normalizeColumns(pageRect geometry.Rect) {
	if g.Table == nil || len(g.Table.Rows) == 0 {
		return
	}
	xCoords := make(map[int]bool)
	for _, row := range g.Table.Rows {
		for _, cell := range row.Cells {
			if cell.BBox.IsEmpty() {
				continue
			}
			xCoords[cordToInt(float64(cell.BBox.X0))] = true
			xCoords[cordToInt(float64(cell.BBox.X1))] = true
		}
	}
	sortedX := make([]int, 0, len(xCoords))
	for x := range xCoords {
		sortedX = append(sortedX, x)
	}
	sort.Ints(sortedX)
	var cols [][2]float32
	if len(sortedX) > 0 {
		colTol := int(pageRect.Width() * colXTolRatio * cordScale)
		colTol = max(colTol, 2000)
		for i := 0; i < len(sortedX)-1; {
			c0 := sortedX[i]
			j := i + 1
			for j < len(sortedX) && sortedX[j]-c0 < colTol {
				j++
			}
			if j >= len(sortedX) {
				break
			}
			cols = append(cols, [2]float32{float32(c0) / cordScale, float32(sortedX[j]) / cordScale})
			i = j
		}
	}
	if len(cols) == 0 {
		return
	}
	for r := range g.Table.Rows {
		row := &g.Table.Rows[r]
		newCells := make([]Cell, len(cols))
		for _, cell := range row.Cells {
			if cell.BBox.IsEmpty() {
				continue
			}
			bestCol, maxOvr := -1, float32(0)
			for ci, col := range cols {
				ovr := geometry.Min32(cell.BBox.X1, col[1]) - geometry.Max32(cell.BBox.X0, col[0])
				if ovr > maxOvr {
					maxOvr, bestCol = ovr, ci
				}
			}
			if bestCol >= 0 && (newCells[bestCol].BBox.IsEmpty() || maxOvr > newCells[bestCol].BBox.Width()*0.5) {
				newCells[bestCol] = cell
			}
		}
		row.Cells = newCells
	}
}
