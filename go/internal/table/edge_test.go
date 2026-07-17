package table

import (
	"testing"

	rawdata "github.com/fibrumpdf/go/internal/raw"
)

func TestHasEdgeJoinsUnorderedReversedSegmentsWithoutAllocating(t *testing.T) {
	edges := []Edge{
		{X0: 10, Y0: 2, X1: 6, Y1: 2, Orientation: rawdata.EdgeHorizontal},
		{X0: 0, Y0: 2, X1: 4, Y1: 2, Orientation: rawdata.EdgeHorizontal},
		{X0: 4.5, Y0: 2, X1: 6.5, Y1: 2, Orientation: rawdata.EdgeHorizontal},
	}
	if !hasEdge(edges, 0, 2, 10, 2, 0.6) {
		t.Fatal("expected chained segments to cover the span")
	}
	if hasEdge(edges[:2], 0, 2, 10, 2, 0.6) {
		t.Fatal("expected the uncovered gap to reject the span")
	}
	if allocations := testing.AllocsPerRun(100, func() { hasEdge(edges, 0, 2, 10, 2, 0.6) }); allocations != 0 {
		t.Fatalf("hasEdge allocated %.0f times per call", allocations)
	}
}

func TestCoordToIntRoundsNegativeCoordinates(t *testing.T) {
	if got := coordToInt(-0.0006); got != -1 {
		t.Fatalf("coordToInt(-0.0006) = %d, want -1", got)
	}
	if got := coordToInt(-0.0004); got != 0 {
		t.Fatalf("coordToInt(-0.0004) = %d, want 0", got)
	}
}
