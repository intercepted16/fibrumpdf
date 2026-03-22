package column

import (
	"github.com/pymupdf4llm-c/go/internal/geometry"
	"github.com/pymupdf4llm-c/go/internal/models"
)

const (
	maxColumns          = 8
	pageWidthResolution = 1000
)

type columnRange struct{ x0, x1 float32 }

type BlockWithColumn interface {
	GetBBox() models.BBox
	SetColumnIndex(idx int)
}

type LineBBox struct{ X0, X1 float32 }

func DetectAndAssignColumns(blocks []BlockWithColumn, bodyFontSize float32, lineBoxes []LineBBox) {
	if len(blocks) == 0 {
		return
	}
	minX, maxX := findBlockBounds(blocks)
	pageWidth := maxX - minX
	if pageWidth < 50 {
		assignAllToColumn(blocks, 0)
		return
	}
	columns := detectColumns(blocks, lineBoxes, minX, maxX, pageWidth, bodyFontSize)
	if len(columns) <= 1 {
		assignAllToColumn(blocks, 0)
		return
	}
	assignBlocksToColumns(blocks, columns)
}

func detectColumns(blocks []BlockWithColumn, lineBoxes []LineBBox, minX, maxX, pageWidth, bodyFontSize float32) []columnRange {
	occupancy := make([]bool, pageWidthResolution)
	threshold := pageWidth * 0.5
	midX := (minX + maxX) * 0.5

	if len(lineBoxes) > 0 {
		for _, lb := range lineBoxes {
			bw := lb.X1 - lb.X0
			if bw > threshold || bw < 5 {
				continue
			}

			if lb.X0 < midX && lb.X1 > midX {
				continue
			}
			idx0 := geometry.Clamp(int((lb.X0-minX)/pageWidth*float32(pageWidthResolution-1)), 0, pageWidthResolution-1)
			idx1 := geometry.Clamp(int((lb.X1-minX)/pageWidth*float32(pageWidthResolution-1)), 0, pageWidthResolution-1)
			for k := idx0; k <= idx1; k++ {
				occupancy[k] = true
			}
		}
	} else {
		for _, b := range blocks {
			bbox := b.GetBBox()
			if bw := bbox.Width(); bw > threshold || bw < 5 {
				continue
			}

			if bbox.X0() < midX && bbox.X1() > midX {
				continue
			}
			idx0 := geometry.Clamp(int((bbox.X0()-minX)/pageWidth*float32(pageWidthResolution-1)), 0, pageWidthResolution-1)
			idx1 := geometry.Clamp(int((bbox.X1()-minX)/pageWidth*float32(pageWidthResolution-1)), 0, pageWidthResolution-1)
			for k := idx0; k <= idx1; k++ {
				occupancy[k] = true
			}
		}
	}

	gapThresholdUnits := bodyFontSize * 1.2
	if gapThresholdUnits < 10 {
		gapThresholdUnits = 10
	}
	gapBins := int(gapThresholdUnits / pageWidth * float32(pageWidthResolution))
	gapBins = max(gapBins, 1)

	columns := make([]columnRange, 0, maxColumns)
	insideContent, contentStart := false, 0
	for i := 0; i < pageWidthResolution; i++ {
		if occupancy[i] {
			if !insideContent {
				insideContent, contentStart = true, i
			}
		} else if insideContent {
			gapLen := 0
			for i+gapLen < pageWidthResolution && !occupancy[i+gapLen] {
				gapLen++
			}
			if gapLen >= gapBins || i+gapLen == pageWidthResolution {
				if len(columns) < maxColumns {
					columns = append(columns, columnRange{
						x0: minX + float32(contentStart)/float32(pageWidthResolution)*pageWidth,
						x1: minX + float32(i-1)/float32(pageWidthResolution)*pageWidth,
					})
				}
				insideContent = false
				i += gapLen - 1
			}
		}
	}
	if insideContent && len(columns) < maxColumns {
		columns = append(columns, columnRange{x0: minX + float32(contentStart)/float32(pageWidthResolution)*pageWidth, x1: maxX})
	}
	return columns
}

func assignBlocksToColumns(blocks []BlockWithColumn, columns []columnRange) {
	for _, b := range blocks {
		bbox := b.GetBBox()
		bx0, bx1 := bbox.X0(), bbox.X1()
		bw := bx1 - bx0
		overlapCount, lastColIdx := 0, 0
		for c, col := range columns {
			ix0, ix1 := geometry.Max32(bx0, col.x0), geometry.Min32(bx1, col.x1)
			if ix1 > ix0 {
				if overlapWidth := ix1 - ix0; overlapWidth > bw*0.3 || overlapWidth > 5 {
					overlapCount++
					lastColIdx = c + 1
				}
			}
		}
		if overlapCount > 1 || overlapCount == 0 {
			b.SetColumnIndex(0)
		} else {
			b.SetColumnIndex(lastColIdx)
		}
	}
}

func findBlockBounds(blocks []BlockWithColumn) (minX, maxX float32) {
	minX, maxX = 100000, -100000
	for _, b := range blocks {
		bbox := b.GetBBox()
		minX, maxX = geometry.Min32(minX, bbox.X0()), geometry.Max32(maxX, bbox.X1())
	}
	return
}

func assignAllToColumn(blocks []BlockWithColumn, col int) {
	for _, b := range blocks {
		b.SetColumnIndex(col)
	}
}
