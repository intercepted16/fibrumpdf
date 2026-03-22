package extractor

// ExtractionConfig contains all extraction-related configuration constants
type ExtractionConfig struct {
	DefaultFontSize       float32
	MinListBaseFont       float32
	MaxMarkerDigits       int
	MinLineWidthForColumn float32

	// Font multipliers (from blockInfo.classify)
	HeadingMultiplier         float32
	NumericHeadingMultiplier  float32
	AllCapsHeadingMultiplier  float32
	BoldRatioThreshold        float32
	StyledShortTitleRatioBold float32
	StyledShortTitleMaxChars  int
	StrongBoldThreshold       float32

	// Noise detection thresholds
	NarrowBlockMaxWidth   float32
	TallBlockMinHeight    float32
	MarginThreshold       float32
	TopMarginMultiplier   float32
	ShortLoudLineMaxChars int
	ShortLoudLineMaxSize  float32
}

// NewDefaultExtractionConfig returns the default extraction configuration
func NewDefaultExtractionConfig() ExtractionConfig {
	return ExtractionConfig{
		DefaultFontSize:       12.0,
		MinListBaseFont:       8.0,
		MaxMarkerDigits:       3,
		MinLineWidthForColumn: 5.0,

		HeadingMultiplier:         1.25,
		NumericHeadingMultiplier:  1.07,
		AllCapsHeadingMultiplier:  1.08,
		BoldRatioThreshold:        0.35,
		StyledShortTitleRatioBold: 0.6,
		StyledShortTitleMaxChars:  80,
		StrongBoldThreshold:       0.8,

		NarrowBlockMaxWidth:   30.0,
		TallBlockMinHeight:    200.0,
		MarginThreshold:       0.08,
		TopMarginMultiplier:   0.08,
		ShortLoudLineMaxChars: 42,
		ShortLoudLineMaxSize:  18.0,
	}
}
