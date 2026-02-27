package table

import (
	"github.com/pymupdf4llm-c/go/internal/geometry"
)

func rectIoU(r1, r2 geometry.Rect) float32 {
	interArea := r1.IntersectArea(r2)
	unionArea := r1.Area() + r2.Area() - interArea
	if unionArea == 0 {
		return 0
	}
	return interArea / unionArea
}

func filterValid(tables *TableArray, pageRect geometry.Rect) {
	valid := tables.Tables[:0]
	for _, t := range tables.Tables {
		pruneEmpty(&t)
		highConfidence := hasHighTabularConfidence(&t)
		allowLowAlignment := hasRegularRowSpacing(&t) && hasTabularDataContent(&t) && len(t.Rows) <= 30 && len(t.Rows[0].Cells) >= 4
		if !allowLowAlignment {
			allowLowAlignment = hasRegularRowSpacing(&t) && len(t.Rows) <= 30 && len(t.Rows[0].Cells) <= 3
		}
		if len(t.Rows) < 2 || len(t.Rows[0].Cells) < 2 {
			continue
		}
		hRatio, wRatio := t.BBox.Height()/pageRect.Height(), t.BBox.Width()/pageRect.Width()
		if hRatio > 0.95 || wRatio > 0.98 {
			continue
		}
		if !checkAlignmentCoverage(&t) && !highConfidence && !allowLowAlignment {
			Logger.Debug("table rejected: alignment gate", "rows", len(t.Rows), "cols", len(t.Rows[0].Cells), "highConfidence", highConfidence, "allowLowAlignment", allowLowAlignment)
			continue
		}
		garbage := false
		for ri, row := range t.Rows {
			if len(row.Cells) < 2 {
				continue
			}
			var minH, maxH float32 = 1e6, 0
			cellCount := 0
			for _, cell := range row.Cells {
				if !cell.BBox.IsEmpty() {
					h := cell.BBox.Height()
					if h < minH {
						minH = h
					}
					if h > maxH {
						maxH = h
					}
					cellCount++
				}
			}
			if cellCount < 2 || minH <= 0 {
				continue
			}
			if minH < 2.0 {
				continue
			}
			ratio := maxH / minH
			threshold := float32(8.0)
			if ri <= 1 {
				threshold = 12.0
			}
			if ratio > threshold {
				Logger.Debug("table rejected: garbage row", "rowIndex", ri, "minH", minH, "maxH", maxH)
				garbage = true
				break
			}
		}
		if garbage {
			continue
		}
		totalCells := 0
		for _, row := range t.Rows {
			for _, cell := range row.Cells {
				if !cell.BBox.IsEmpty() {
					totalCells++
				}
			}
		}
		if len(t.Rows) > 15 && totalCells < len(t.Rows)*2 && !highConfidence && !allowLowAlignment {
			Logger.Debug("table rejected: too sparse", "rows", len(t.Rows), "totalCells", totalCells)
			continue
		}
		validRows, expectedCols, missingRows := 0, -1, 0
		for _, row := range t.Rows {
			if len(row.Cells) == 0 {
				continue
			}
			validRows++
			if expectedCols < 0 {
				expectedCols = len(row.Cells)
			} else if len(row.Cells) < expectedCols {
				missingRows++
			}
		}
		if validRows > 0 && float32(missingRows) > float32(validRows)*0.4 && !highConfidence {
			Logger.Debug("table rejected: too many missing rows", "missingRows", missingRows, "validRows", validRows)
			continue
		}
		if validRows >= 2 && expectedCols >= 2 {
			valid = append(valid, t)
		} else {
			Logger.Debug("table rejected: final check failed", "validRows", validRows, "expectedCols", expectedCols)
		}
	}
	arr := &TableArray{Tables: valid}
	deduplicateTables(arr)
	tables.Tables = arr.Tables
}

func deduplicateTables(tables *TableArray) {
	if tables == nil {
		return
	}
	keep := make([]bool, len(tables.Tables))
	for i := range keep {
		keep[i] = true
	}

	for i := 0; i < len(tables.Tables); i++ {
		if !keep[i] {
			continue
		}
		t1 := tables.Tables[i]
		for j := i + 1; j < len(tables.Tables); j++ {
			if !keep[j] {
				continue
			}
			t2 := tables.Tables[j]

			iou := rectIoU(t1.BBox, t2.BBox)
			if iou > 0.95 {
				if len(t1.Rows) == len(t2.Rows) && len(t1.Rows[0].Cells) == len(t2.Rows[0].Cells) {
					keep[j] = false
					Logger.Info("deduplicated similar tables", "iou", iou, "rows", len(t1.Rows), "cols", len(t1.Rows[0].Cells))
				}
			}
		}
	}

	var filtered []Table
	for i, k := range keep {
		if k {
			filtered = append(filtered, tables.Tables[i])
		}
	}
	tables.Tables = filtered
}
