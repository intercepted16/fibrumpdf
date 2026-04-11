package bridge

/*
#cgo CFLAGS: -I${SRCDIR} -I${SRCDIR}/../../../mupdf/include
#cgo LDFLAGS: -L${SRCDIR}/../../../lib/mupdf -lmupdf -lm -lpthread

#include "bridge.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"unsafe"

	"github.com/fibrumpdf/go/internal/logger"
)

var Logger = logger.GetLogger("bridge")

type Rect struct{ X0, Y0, X1, Y1 float32 }

func (r Rect) Width() float32  { return r.X1 - r.X0 }
func (r Rect) Height() float32 { return r.Y1 - r.Y0 }
func (r Rect) IsEmpty() bool   { return r.X0 >= r.X1 || r.Y0 >= r.Y1 }

type Edge struct {
	X0, Y0, X1, Y1 float64
	Orientation    byte
}

type RawPageData struct {
	PageNumber int
	PageBounds Rect
	Blocks     []RawBlock
	Lines      []RawLine
	Chars      []RawChar
	Edges      []Edge
	Links      []RawLink
}

type RawBlock struct {
	Type                 uint8
	BBox                 Rect
	LineStart, LineCount int
}

type RawLine struct {
	BBox                 Rect
	CharStart, CharCount int
}

type RawChar struct {
	Codepoint                      rune
	Size                           float32
	BBox                           Rect
	IsBold, IsItalic, IsMonospaced bool
}

type RawLink struct {
	Rect Rect
	URI  string
}

func ExtractAllPagesRaw(pdfPath string) (string, error) {
	Logger.Debug("extracting all pages", "pdfPath", pdfPath)
	cpath := C.CString(pdfPath)
	defer C.free(unsafe.Pointer(cpath))
	if ctempdir := C.extract_all_pages(cpath); ctempdir != nil {
		tempDir := C.GoString(ctempdir)
		C.free(unsafe.Pointer(ctempdir))
		Logger.Debug("extraction completed", "tempDir", tempDir)
		return tempDir, nil
	}
	Logger.Error("extraction failed", "pdfPath", pdfPath)
	return "", errors.New("extraction failed")
}

func ReadRawPage(filepath string) (*RawPageData, error) {
	Logger.Debug("reading raw page", "filepath", filepath)
	cpath := C.CString(filepath)
	defer C.free(unsafe.Pointer(cpath))
	var rawData C.page_data
	if C.read_page(cpath, &rawData) != 0 {
		Logger.Error("failed to read raw page", "filepath", filepath)
		return nil, errors.New("failed to read raw page")
	}
	defer C.free_page(&rawData)
	result := &RawPageData{PageNumber: int(rawData.page_number), PageBounds: Rect{float32(rawData.page_x0), float32(rawData.page_y0), float32(rawData.page_x1), float32(rawData.page_y1)}, Blocks: make([]RawBlock, int(rawData.block_count)), Lines: make([]RawLine, int(rawData.line_count)), Chars: make([]RawChar, int(rawData.char_count)), Edges: make([]Edge, int(rawData.edge_count)), Links: make([]RawLink, int(rawData.link_count))}
	Logger.Debug("page data loaded", "pageNum", result.PageNumber, "blocks", len(result.Blocks), "chars", len(result.Chars), "edges", len(result.Edges))
	if rawData.block_count > 0 {
		cBlocks := (*[1 << 20]C.fblock)(unsafe.Pointer(rawData.blocks))[:rawData.block_count:rawData.block_count]
		for i := range result.Blocks {
			result.Blocks[i] = RawBlock{Type: uint8(cBlocks[i]._type), BBox: Rect{float32(cBlocks[i].bbox_x0), float32(cBlocks[i].bbox_y0), float32(cBlocks[i].bbox_x1), float32(cBlocks[i].bbox_y1)}, LineStart: int(cBlocks[i].line_start), LineCount: int(cBlocks[i].line_count)}
		}
	}
	if rawData.line_count > 0 {
		cLines := (*[1 << 20]C.fline)(unsafe.Pointer(rawData.lines))[:rawData.line_count:rawData.line_count]
		for i := range result.Lines {
			result.Lines[i] = RawLine{BBox: Rect{float32(cLines[i].bbox_x0), float32(cLines[i].bbox_y0), float32(cLines[i].bbox_x1), float32(cLines[i].bbox_y1)}, CharStart: int(cLines[i].char_start), CharCount: int(cLines[i].char_count)}
		}
	}
	if rawData.char_count > 0 {
		cChars := (*[1 << 28]C.fchar)(unsafe.Pointer(rawData.chars))[:rawData.char_count:rawData.char_count]
		for i := range result.Chars {
			result.Chars[i] = RawChar{Codepoint: rune(cChars[i].codepoint), Size: float32(cChars[i].size), BBox: Rect{float32(cChars[i].bbox_x0), float32(cChars[i].bbox_y0), float32(cChars[i].bbox_x1), float32(cChars[i].bbox_y1)}, IsBold: cChars[i].is_bold != 0, IsItalic: cChars[i].is_italic != 0, IsMonospaced: cChars[i].is_monospaced != 0}
		}
	}
	if rawData.edge_count > 0 {
		cEdges := (*[1 << 20]C.edge)(unsafe.Pointer(rawData.edges))[:rawData.edge_count:rawData.edge_count]
		for i := range result.Edges {
			result.Edges[i] = Edge{float64(cEdges[i].x0), float64(cEdges[i].y0), float64(cEdges[i].x1), float64(cEdges[i].y1), byte(cEdges[i].orientation)}
		}
	}
	if rawData.link_count > 0 {
		cLinks := (*[1 << 20]C.flink)(unsafe.Pointer(rawData.links))[:rawData.link_count:rawData.link_count]
		for i := range result.Links {
			result.Links[i] = RawLink{Rect: Rect{float32(cLinks[i].rect_x0), float32(cLinks[i].rect_y0), float32(cLinks[i].rect_x1), float32(cLinks[i].rect_y1)}, URI: C.GoString(cLinks[i].uri)}
		}
	}
	return result, nil
}
