package table

import "github.com/fibrumpdf/go/internal/geometry"

type cluster1D struct {
	tolerance float32
	centers   []float32
	counts    []int
}

func newCluster1D(tolerance float32) *cluster1D {
	return &cluster1D{tolerance: tolerance}
}

func (c *cluster1D) add(value float32) int {
	for i := len(c.centers) - 1; i >= 0; i-- {
		if geometry.Abs32(value-c.centers[i]) > c.tolerance {
			continue
		}
		count := c.counts[i]
		c.counts[i]++
		c.centers[i] = (c.centers[i]*float32(count) + value) / float32(count+1)
		return i
	}
	c.centers = append(c.centers, value)
	c.counts = append(c.counts, 1)
	return len(c.centers) - 1
}
