package raw

/*
#cgo CFLAGS: -I${SRCDIR} -I${SRCDIR}/../../../mupdf/include
#cgo !windows LDFLAGS: -L${SRCDIR}/../../../lib/mupdf -lmupdf -lm -lpthread
#cgo windows LDFLAGS: -L${SRCDIR}/../../../lib/mupdf -l:libmupdf.dll.a

#include "raw.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"path/filepath"
	"unsafe"

	"github.com/fibrumpdf/go/internal/logger"
)

var Logger = logger.GetLogger("raw")

func ExtractAllPagesRaw(pdfPath string) (string, error) {
	pdfPath = filepath.ToSlash(pdfPath)
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

func newRawPageData(rawData C.page_data) *PageData {
	return &PageData{
		PageNumber: int(rawData.page_number),
		PageBounds: Rect{
			float32(rawData.page_x0),
			float32(rawData.page_y0),
			float32(rawData.page_x1),
			float32(rawData.page_y1),
		},
		Blocks: make([]Block, int(rawData.block_count)),
		Lines:  make([]Line, int(rawData.line_count)),
		Chars:  make([]Char, int(rawData.char_count)),
		Edges:  make([]Edge, int(rawData.edge_count)),
		Links:  make([]Link, int(rawData.link_count)),
	}
}

func ReadRawPage(filepath string) (*PageData, error) {
	Logger.Debug("reading raw page", "filepath", filepath)
	cpath := C.CString(filepath)
	defer C.free(unsafe.Pointer(cpath))
	var rawData C.page_data
	if C.read_page(cpath, &rawData) != 0 {
		Logger.Error("failed to read raw page", "filepath", filepath)
		return nil, errors.New("failed to read raw page")
	}
	defer C.free_page(&rawData)
	result := newRawPageData(rawData)
	Logger.Debug("page data loaded", "pageNum", result.PageNumber, "blocks", len(result.Blocks), "chars", len(result.Chars), "edges", len(result.Edges))
	if rawData.block_count > 0 {
		cBlocks := (*[1 << 20]C.fblock)(unsafe.Pointer(rawData.blocks))[:rawData.block_count:rawData.block_count]
		for i := range result.Blocks {
			result.Blocks[i] = Block{Type: BlockType(cBlocks[i]._type), BBox: Rect{float32(cBlocks[i].bbox_x0), float32(cBlocks[i].bbox_y0), float32(cBlocks[i].bbox_x1), float32(cBlocks[i].bbox_y1)}, LineStart: int(cBlocks[i].line_start), LineCount: int(cBlocks[i].line_count)}
		}
	}
	if rawData.line_count > 0 {
		cLines := (*[1 << 20]C.fline)(unsafe.Pointer(rawData.lines))[:rawData.line_count:rawData.line_count]
		for i := range result.Lines {
			result.Lines[i] = Line{BBox: Rect{float32(cLines[i].bbox_x0), float32(cLines[i].bbox_y0), float32(cLines[i].bbox_x1), float32(cLines[i].bbox_y1)}, CharStart: int(cLines[i].char_start), CharCount: int(cLines[i].char_count), Index: i}
		}
	}
	if rawData.char_count > 0 {
		cChars := (*[1 << 28]C.fchar)(unsafe.Pointer(rawData.chars))[:rawData.char_count:rawData.char_count]
		for i := range result.Chars {
			result.Chars[i] = Char{Codepoint: rune(cChars[i].codepoint), Size: float32(cChars[i].size), BBox: Rect{float32(cChars[i].bbox_x0), float32(cChars[i].bbox_y0), float32(cChars[i].bbox_x1), float32(cChars[i].bbox_y1)}, IsBold: cChars[i].is_bold != 0, IsItalic: cChars[i].is_italic != 0, IsMonospaced: cChars[i].is_monospaced != 0}
		}
	}
	if rawData.edge_count > 0 {
		cEdges := (*[1 << 20]C.edge)(unsafe.Pointer(rawData.edges))[:rawData.edge_count:rawData.edge_count]
		for i := range result.Edges {
			result.Edges[i] = Edge{float64(cEdges[i].x0), float64(cEdges[i].y0), float64(cEdges[i].x1), float64(cEdges[i].y1), EdgeOrientation(cEdges[i].orientation)}
		}
	}
	if rawData.link_count > 0 {
		cLinks := (*[1 << 20]C.flink)(unsafe.Pointer(rawData.links))[:rawData.link_count:rawData.link_count]
		for i := range result.Links {
			result.Links[i] = Link{Rect: Rect{float32(cLinks[i].rect_x0), float32(cLinks[i].rect_y0), float32(cLinks[i].rect_x1), float32(cLinks[i].rect_y1)}, URI: C.GoString(cLinks[i].uri)}
		}
	}
	result.Sanitize()
	return result, nil
}
