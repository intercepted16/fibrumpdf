package table

import "github.com/fibrumpdf/go/internal/geometry"

// ToleranceConfig centralizes all proximity and tolerance checks
type ToleranceConfig struct {
	AlignmentTolerance       float32
	RowYTolerance            float32
	SegmentGapMultiplier     float32
	SegmentGapMin            float32
	ColumnAnchorMultiplier   float32
	ColumnAnchorDensityBoost float32
	ColumnAnchorMin          float32
	RowClusterMultiplier     float32
	RowClusterDensityBoost   float32
	RowClusterMin            float32
	WordGapMultiplier        float32
	WordGapMin               float32
	ColumnMergeMultiplier    float32
	ColumnMergeGrowthFactor  float32
	MaxColumnCount           int
}

// NewDefaultToleranceConfig returns the default tolerance configuration
func NewDefaultToleranceConfig() ToleranceConfig {
	return ToleranceConfig{
		AlignmentTolerance:       3.0,
		RowYTolerance:            3.0,
		SegmentGapMultiplier:     1.8,
		SegmentGapMin:            4.0,
		ColumnAnchorMultiplier:   2.0,
		ColumnAnchorDensityBoost: 50.0,
		ColumnAnchorMin:          12.0,
		RowClusterMultiplier:     0.005,
		RowClusterDensityBoost:   20.0,
		RowClusterMin:            3.0,
		WordGapMultiplier:        1.6,
		WordGapMin:               6.0,
		ColumnMergeMultiplier:    3.8,
		ColumnMergeGrowthFactor:  1.35,
		MaxColumnCount:           16,
	}
}

// Cluster1D maintains clustered 1D positions with counts.
type Cluster1D struct {
	Tol     float32
	Centers []float32
	Counts  []int
}

// NewCluster1D creates a new 1D cluster helper.
func NewCluster1D(tol float32) *Cluster1D {
	return &Cluster1D{Tol: tol}
}
func (c *Cluster1D) Add(value float32) int {
	lastIdx := len(c.Centers) - 1

	if lastIdx >= 0 {
		diff := value - c.Centers[lastIdx]

		if (diff >= 0 && diff <= c.Tol) || (diff < 0 && -diff <= c.Tol) {
			oldCount := c.Counts[lastIdx]
			newCount := oldCount + 1
			c.Counts[lastIdx] = newCount

			invCount := 1.0 / float32(newCount)
			c.Centers[lastIdx] = (c.Centers[lastIdx]*float32(oldCount) + value) * invCount
			return lastIdx
		}
	}

	for i := lastIdx - 1; i >= 0; i-- {
		diff := value - c.Centers[i]
		if (diff >= 0 && diff <= c.Tol) || (diff < 0 && -diff <= c.Tol) {
			oldCount := c.Counts[i]
			newCount := oldCount + 1
			c.Counts[i] = newCount
			c.Centers[i] = (c.Centers[i]*float32(oldCount) + value) / float32(newCount)
			return i
		}
	}

	c.Centers = append(c.Centers, value)
	c.Counts = append(c.Counts, 1)
	return len(c.Centers) - 1
}

// MergeSorted collapses sorted values into clustered centers.
func (c *Cluster1D) MergeSorted(values []float32) []float32 {
	if len(values) < 2 {
		return values
	}
	result := []float32{values[0]}
	for i := 1; i < len(values); i++ {
		if geometry.Abs32(values[i]-result[len(result)-1]) > c.Tol {
			result = append(result, values[i])
			continue
		}
		result[len(result)-1] = (result[len(result)-1] + values[i]) * 0.5
	}
	return result
}

// IsNearby checks if two values are within the provided tolerance.
func IsNearby(a, b, tol float32) bool {
	return geometry.Abs32(a-b) < tol
}

// ComputeRowYTolerance computes row Y tolerance with optional multiplier
func ComputeRowYTolerance(baseTol, multiplier float32) float32 {
	return baseTol * multiplier
}

// ComputeSegmentGap computes segment gap tolerance from average character width
func ComputeSegmentGap(avgCharWidth float32, cfg ToleranceConfig) float32 {
	return geometry.Max32(avgCharWidth*cfg.SegmentGapMultiplier, cfg.SegmentGapMin)
}

// ComputeColumnAnchorTolerance computes the x tolerance for column anchors.
func ComputeColumnAnchorTolerance(avgCharWidth, charDensity float32, cfg ToleranceConfig) float32 {
	return geometry.Max32(avgCharWidth*(cfg.ColumnAnchorMultiplier+charDensity*cfg.ColumnAnchorDensityBoost), cfg.ColumnAnchorMin)
}

// ComputeRowClusterTolerance computes the y tolerance for row clustering.
func ComputeRowClusterTolerance(pageHeight, charDensity float32, cfg ToleranceConfig) float32 {
	return geometry.Max32(pageHeight*cfg.RowClusterMultiplier*(1.0+charDensity*cfg.RowClusterDensityBoost), cfg.RowClusterMin)
}

// ComputeWordGap computes the gap used to separate words on a line.
func ComputeWordGap(avgCharWidth float32, cfg ToleranceConfig) float32 {
	return geometry.Max32(avgCharWidth*cfg.WordGapMultiplier, cfg.WordGapMin)
}

// ComputeRowSpacingTolerance computes row spacing tolerance from median gap
func ComputeRowSpacingTolerance(medianGap float32) float32 {
	return geometry.Max32(1.5, medianGap*0.45)
}
