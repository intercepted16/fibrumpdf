package models

import (
	"encoding/json"
	"github.com/fibrumpdf/go/internal/geometry"
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

func (t BlockType) String() string { return string(t) }

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
	ListType ListType
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

type ListType string

const (
	ListTypeBulleted ListType = "bulleted"
	ListTypeNumbered ListType = "numbered"
)

func (t ListType) String() string { return string(t) }

type TableCell struct {
	BBox  BBox   `json:"bbox"`
	Spans []Span `json:"spans,omitempty"`
}

type TableRow struct {
	BBox  BBox        `json:"bbox"`
	Cells []TableCell `json:"cells,omitempty"`
}

type Block struct {
	Type      BlockType  `json:"type"`
	BBox      BBox       `json:"bbox"`
	Length    int        `json:"length"`
	FontSize  float32    `json:"font_size"`
	Lines     int        `json:"lines,omitempty"`
	Level     int        `json:"level,omitempty"`
	Spans     []Span     `json:"spans,omitempty"`
	Items     []ListItem `json:"items,omitempty"`
	RowCount  int        `json:"row_count,omitempty"`
	ColCount  int        `json:"col_count,omitempty"`
	CellCount int        `json:"cell_count,omitempty"`
	Rows      []TableRow `json:"rows,omitempty"`
}

type Page struct {
	Number int     `json:"page"`
	Data   []Block `json:"data"`
}

type Document struct{ Pages []Page }

func (d *Document) MarshalJSON() ([]byte, error) { return json.Marshal(d.Pages) }
