package table

import (
	"testing"

	"github.com/fibrumpdf/go/internal/geometry"
	rawdata "github.com/fibrumpdf/go/internal/raw"
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

func TestConvertTableRowsPreservesGridAlignment(t *testing.T) {
	table := Table{Rows: []Row{
		{Cells: []Cell{cell("Name", 0, 10), cell("", 10, 20), cell("Total", 20, 30)}},
		{Cells: []Cell{cell("Ada", 0, 10), cell("$5", 10, 20), cell("", 20, 30)}},
	}}

	rows, visible := convertTableRows(table)

	if visible != 2 {
		t.Fatalf("visible rows = %d, want 2", visible)
	}
	for rowIndex, row := range rows {
		if got := len(row.Cells); got != 3 {
			t.Fatalf("row %d has %d cells, want 3", rowIndex, got)
		}
	}
	if got := rows[0].Cells[2].Spans[0].Text; got != "Total" {
		t.Fatalf("third heading = %q, want Total", got)
	}
}

func TestSegmentRowsKeepsFullPageTable(t *testing.T) {
	rows := make([]Row, 12)
	for index := range rows {
		y0 := float32(index * 80)
		rows[index] = Row{
			BBox: geometry.Rect{X0: 10, Y0: y0, X1: 90, Y1: y0 + 76},
			Cells: []Cell{
				{BBox: geometry.Rect{X0: 10, Y0: y0, X1: 45, Y1: y0 + 76}},
				{BBox: geometry.Rect{X0: 55, Y0: y0, X1: 90, Y1: y0 + 76}},
			},
		}
	}

	tables := segmentRows(rows, geometry.Rect{X1: 100, Y1: 1000})
	if got := len(tables); got != 1 {
		t.Fatalf("tables = %d, want 1", got)
	}
	if got := len(tables[0].Rows); got != 12 {
		t.Fatalf("rows = %d, want 12", got)
	}
}

func TestMaterializeCellOwnsCharactersByCenter(t *testing.T) {
	chars := []rawdata.Char{
		{Codepoint: 'A', Size: 10, BBox: rawdata.Rect{X0: 1, Y0: 1, X1: 3, Y1: 9}},
		{Codepoint: 'X', Size: 10, BBox: rawdata.Rect{X0: 9, Y0: 1, X1: 13, Y1: 9}},
	}

	bbox, text := materializeCell(chars, geometry.Rect{X1: 10, Y1: 10})
	if text != "A" {
		t.Fatalf("text = %q, want A", text)
	}
	if want := (geometry.Rect{X0: 1, Y0: 1, X1: 3, Y1: 9}); bbox != want {
		t.Fatalf("bbox = %+v, want %+v", bbox, want)
	}
}

func TestHasTableShapeKeepsSparseTextTable(t *testing.T) {
	table := Table{Rows: []Row{
		{Cells: []Cell{cell("University", 0, 10), cell("Form P1", 10, 20), cell("", 20, 30), cell("", 30, 40), cell("Page 2", 40, 50)}},
		{Cells: []Cell{cell("", 0, 10), cell("", 10, 20), cell("Repeat examination", 20, 30), cell("Version 1", 30, 40), cell("Valid from March", 40, 50)}},
	}}

	if !hasTableShape(table) {
		t.Fatal("sparse text table was rejected")
	}
}

func TestHasTableShapeRejectsLayoutArtifacts(t *testing.T) {
	tests := map[string]Table{
		"uniform prose fragments": {Rows: []Row{
			{Cells: []Cell{cell("First paragraph fragment", 0, 10), cell("Second prose fragment", 10, 20)}},
			{Cells: []Cell{cell("Third paragraph fragment", 0, 10), cell("Fourth prose fragment", 10, 20)}},
			{Cells: []Cell{cell("Fifth paragraph fragment", 0, 10), cell("Sixth prose fragment", 10, 20)}},
		}},
		"fragmented labels": {Rows: []Row{
			{Cells: []Cell{cell("A", 0, 10), cell("B", 10, 20), cell("C", 20, 30)}},
			{Cells: []Cell{cell("D", 0, 10), cell("E", 10, 20), cell("F", 20, 30)}},
			{Cells: []Cell{cell("G", 0, 10), cell("H", 10, 20), cell("I", 20, 30)}},
		}},
	}

	for name, table := range tests {
		t.Run(name, func(t *testing.T) {
			if hasTableShape(table) {
				t.Fatal("layout artifact was accepted as a table")
			}
		})
	}
}

func cell(text string, x0, x1 float32) Cell {
	return Cell{Text: text, BBox: geometry.Rect{X0: x0, Y0: 0, X1: x1, Y1: 10}}
}
