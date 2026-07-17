package table

import (
	"testing"

	"github.com/fibrumpdf/go/internal/geometry"
)

func TestCleanupRuledTableMergesFragmentsAndDropsEmptyColumns(t *testing.T) {
	table := Table{
		RuledTable: true,
		Rows: []Row{
			{Cells: []Cell{
				cell("Pr", 0, 10), cell("ice", 10, 20), cell("", 20, 30),
				cell("Total", 50, 70),
			}},
			{Cells: []Cell{
				cell("$5", 0, 10), cell(".00", 10, 20), cell("", 20, 30),
				cell("$50.00", 50, 70),
			}},
		},
	}

	cleanupMaterializedTable(&table)

	for rowIndex, row := range table.Rows {
		if got, want := len(row.Cells), 2; got != want {
			t.Fatalf("row %d has %d cells, want %d", rowIndex, got, want)
		}
	}
	if got, want := table.Rows[0].Cells[0].Text, "Price"; got != want {
		t.Fatalf("heading = %q, want %q", got, want)
	}
	if got, want := table.Rows[1].Cells[0].Text, "$5.00"; got != want {
		t.Fatalf("value = %q, want %q", got, want)
	}
}

func cell(text string, x0, x1 float32) Cell {
	return Cell{Text: text, BBox: geometry.Rect{X0: x0, Y0: 0, X1: x1, Y1: 10}}
}
