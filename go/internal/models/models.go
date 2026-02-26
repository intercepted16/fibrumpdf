package models

import (
	"bytes"
	"encoding/json"
	"strconv"

	"github.com/pymupdf4llm-c/go/internal/geometry"
)

type BBox [4]float32

func (b BBox) X0() float32     { return b[0] }
func (b BBox) Y0() float32     { return b[1] }
func (b BBox) X1() float32     { return b[2] }
func (b BBox) Y1() float32     { return b[3] }
func (b BBox) Width() float32  { return b[2] - b[0] }
func (b BBox) Height() float32 { return b[3] - b[1] }
func (b BBox) IsEmpty() bool   { return b[0] >= b[2] || b[1] >= b[3] }

func (b BBox) Union(other BBox) BBox {
	if b.IsEmpty() {
		return other
	}
	if other.IsEmpty() {
		return b
	}
	return BBox{geometry.Min32(b[0], other[0]), geometry.Min32(b[1], other[1]), geometry.Max32(b[2], other[2]), geometry.Max32(b[3], other[3])}
}

func (b BBox) MarshalJSON() ([]byte, error) {
	return []byte("[" +
		strconv.FormatFloat(float64(b[0]), 'f', 2, 32) + "," +
		strconv.FormatFloat(float64(b[1]), 'f', 2, 32) + "," +
		strconv.FormatFloat(float64(b[2]), 'f', 2, 32) + "," +
		strconv.FormatFloat(float64(b[3]), 'f', 2, 32) + "]"), nil
}

type BlockType string

const (
	BlockText     BlockType = "text"
	BlockHeading  BlockType = "heading"
	BlockTable    BlockType = "table"
	BlockList     BlockType = "list"
	BlockCode     BlockType = "code"
	BlockFootnote BlockType = "footnote"
	BlockOther    BlockType = "other"
)

type TextStyle struct{ Bold, Italic, Monospace bool }

type Span struct {
	Text  string
	Style TextStyle
	URI   string
}

func (s Span) MarshalJSON() ([]byte, error) {
	link := any(false)
	if s.URI != "" {
		link = s.URI
	}
	return json.Marshal(struct {
		Text        string  `json:"text"`
		FontSize    float32 `json:"font_size"`
		Bold        bool    `json:"bold"`
		Italic      bool    `json:"italic"`
		Monospace   bool    `json:"monospace"`
		Strikeout   bool    `json:"strikeout"`
		Superscript bool    `json:"superscript"`
		Subscript   bool    `json:"subscript"`
		Link        any     `json:"link"`
	}{
		Text:        s.Text,
		FontSize:    0,
		Bold:        s.Style.Bold,
		Italic:      s.Style.Italic,
		Monospace:   s.Style.Monospace,
		Strikeout:   false,
		Superscript: false,
		Subscript:   false,
		Link:        link,
	})
}

type ListItem struct {
	Spans    []Span
	ListType string
	Indent   int
	Prefix   string
}

func (li ListItem) MarshalJSON() ([]byte, error) {
	lt, ind, pre := any(false), any(false), any(false)
	if li.ListType != "" {
		lt = li.ListType
	}
	if li.Indent >= 0 {
		ind = li.Indent
	}
	if li.Prefix != "" {
		pre = li.Prefix
	}
	return json.Marshal(struct {
		Spans    []Span `json:"spans,omitempty"`
		ListType any    `json:"list_type"`
		Indent   any    `json:"indent"`
		Prefix   any    `json:"prefix"`
	}{li.Spans, lt, ind, pre})
}

type TableCell struct {
	BBox  BBox   `json:"bbox"`
	Spans []Span `json:"spans,omitempty"`
}

type TableRow struct {
	BBox  BBox        `json:"bbox"`
	Cells []TableCell `json:"cells,omitempty"`
}

type Block struct {
	Type                          BlockType
	BBox                          BBox
	Length                        int
	FontSize                      float32 // all blocks except tables
	Lines                         int // for all blocks except tables
	Level                         int // for headings
	Spans                         []Span // this is for BlockText and BlockHeading
	Items                         []ListItem // this is for BlockList
	RowCount, ColCount, CellCount int // table
	Rows                          []TableRow //  this is for BlockTable
}

func (b Block) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // for <br>
	switch b.Type {
	case BlockText, BlockCode:
		enc.Encode(struct {
			Type     BlockType `json:"type"`
			BBox     BBox      `json:"bbox"`
			Length   int       `json:"length"`
			Spans    []Span    `json:"spans,omitempty"`
			FontSize float32   `json:"font_size"`
			Lines    int       `json:"lines"`
		}{b.Type, b.BBox, b.Length, b.Spans, b.FontSize, b.Lines})
	case BlockHeading:
		enc.Encode(struct {
			Type     BlockType `json:"type"`
			BBox     BBox      `json:"bbox"`
			Length   int       `json:"length"`
			Spans    []Span    `json:"spans,omitempty"`
			FontSize float32   `json:"font_size"`
			Level    int       `json:"level,omitempty"`
		}{b.Type, b.BBox, b.Length, b.Spans, b.FontSize, b.Level})
	case BlockList:
		enc.Encode(struct {
			Type     BlockType  `json:"type"`
			BBox     BBox       `json:"bbox"`
			Length   int        `json:"length"`
			Spans    []Span     `json:"spans,omitempty"`
			FontSize float32    `json:"font_size"`
			Items    []ListItem `json:"items,omitempty"`
		}{b.Type, b.BBox, b.Length, b.Spans, b.FontSize, b.Items})
	case BlockTable:
		enc.Encode(struct {
			Type      BlockType  `json:"type"`
			BBox      BBox       `json:"bbox"`
			Length    int        `json:"length"`
			Spans     []Span     `json:"spans,omitempty"`
			FontSize  float32    `json:"font_size"`
			RowCount  int        `json:"row_count,omitempty"`
			ColCount  int        `json:"col_count,omitempty"`
			CellCount int        `json:"cell_count,omitempty"`
			Rows      []TableRow `json:"rows,omitempty"`
		}{b.Type, b.BBox, b.Length, b.Spans, b.FontSize, b.RowCount, b.ColCount, b.CellCount, b.Rows})
	default:
		enc.Encode(struct {
			Type     BlockType `json:"type"`
			BBox     BBox      `json:"bbox"`
			Length   int       `json:"length"`
			Spans    []Span    `json:"spans,omitempty"`
			FontSize float32   `json:"font_size"`
		}{b.Type, b.BBox, b.Length, b.Spans, b.FontSize})
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}

type Page struct {
	Number int     `json:"page"`
	Data   []Block `json:"data"`
}

type Document struct{ Pages []Page }

func (d *Document) MarshalJSON() ([]byte, error) { return json.Marshal(d.Pages) }
