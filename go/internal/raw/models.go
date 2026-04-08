package raw

import (
	"sort"
	"strconv"

	"github.com/fibrumpdf/go/internal/geometry"
)

type Rect struct{ X0, Y0, X1, Y1 float32 }

func (r Rect) Width() float32  { return r.X1 - r.X0 }
func (r Rect) Height() float32 { return r.Y1 - r.Y0 }
func (r Rect) IsEmpty() bool   { return r.X0 >= r.X1 || r.Y0 >= r.Y1 }
func (r Rect) ToGeometryRect() geometry.Rect {
	return geometry.Rect{X0: r.X0, Y0: r.Y0, X1: r.X1, Y1: r.Y1}
}

type BlockType uint8

const (
	BlockText BlockType = 0
)

type EdgeOrientation byte

const (
	EdgeHorizontal EdgeOrientation = 'h'
	EdgeVertical   EdgeOrientation = 'v'
)

func (o EdgeOrientation) String() string {
	switch o {
	case EdgeHorizontal:
		return "horizontal"
	case EdgeVertical:
		return "vertical"
	default:
		return "edge_orientation(" + strconv.Itoa(int(o)) + ")"
	}
}

type Edge struct {
	X0, Y0, X1, Y1 float64
	Orientation    EdgeOrientation
}

type PageData struct {
	PageNumber         int
	PageBounds         Rect
	Blocks             []Block
	Lines              []Line
	Chars              []Char
	Edges              []Edge
	Links              []Link
	LineCharIndexCache [][]int
}

func (p *PageData) PageRect() geometry.Rect {
	if p == nil {
		return geometry.Rect{}
	}
	return p.PageBounds.ToGeometryRect()
}

func (p *PageData) LineCharIndices(line *Line, dst []int) []int {
	if p == nil || line == nil || line.CharCount <= 0 {
		return dst[:0]
	}
	if line.Index >= 0 && line.Index < len(p.LineCharIndexCache) {
		indices := p.LineCharIndexCache[line.Index]
		if len(indices) == 0 {
			return dst[:0]
		}
		if cap(dst) < len(indices) {
			dst = make([]int, len(indices))
		} else {
			dst = dst[:len(indices)]
		}
		copy(dst, indices)
		return dst
	}
	if cap(dst) < line.CharCount {
		dst = make([]int, 0, line.CharCount)
	} else {
		dst = dst[:0]
	}
	for i := 0; i < line.CharCount; i++ {
		dst = append(dst, line.CharStart+i)
	}
	return dst
}

func (p *PageData) SortedLineCharIndices(line *Line, dst []int) []int {
	indices := p.LineCharIndices(line, dst)
	if len(indices) < 2 {
		return indices
	}
	sort.SliceStable(indices, func(i, j int) bool {
		a := p.Chars[indices[i]]
		b := p.Chars[indices[j]]
		if geometry.Abs32(a.BBox.X0-b.BBox.X0) > 0.5 {
			return a.BBox.X0 < b.BBox.X0
		}
		if geometry.Abs32(a.BBox.Y0-b.BBox.Y0) > 0.5 {
			return a.BBox.Y0 < b.BBox.Y0
		}
		return indices[i] < indices[j]
	})
	return indices
}
func (p *PageData) CharIndicesInRect(rect geometry.Rect, dst []int) []int {
	if p == nil || len(p.Chars) == 0 {
		return dst[:0]
	}
	if cap(dst) < 64 {
		dst = make([]int, 0, 64)
	} else {
		dst = dst[:0]
	}
	for i := range p.Chars {
		ch := &p.Chars[i]
		cx, cy := (ch.BBox.X0+ch.BBox.X1)/2, (ch.BBox.Y0+ch.BBox.Y1)/2
		if cx < rect.X0-2 || cx > rect.X1+2 || cy < rect.Y0-2 || cy > rect.Y1+2 {
			continue
		}
		dst = append(dst, i)
	}
	return dst
}

func (p *PageData) Sanitize() {
	if p == nil {
		return
	}
	if len(p.Lines) == 0 {
		p.LineCharIndexCache = nil
		return
	}
	lineCharIndices := make([][]int, len(p.Lines))
	if len(p.Chars) == 0 {
		p.LineCharIndexCache = lineCharIndices
		return
	}
	newChars := make([]Char, 0, len(p.Chars))
	for li := range p.Lines {
		line := &p.Lines[li]
		line.Index = li
		if line.CharCount <= 0 {
			line.CharStart = len(newChars)
			line.CharCount = 0
			continue
		}
		start := line.CharStart
		end := line.CharStart + line.CharCount
		if start < 0 {
			start = 0
		}
		if end > len(p.Chars) {
			end = len(p.Chars)
		}
		line.CharStart = len(newChars)
		line.CharCount = 0
		for i := start; i < end; i++ {
			ch := p.Chars[i]
			if ch.Codepoint == 0 || ch.Codepoint == 0xFEFF {
				continue
			}
			lineCharIndices[li] = append(lineCharIndices[li], len(newChars))
			newChars = append(newChars, ch)
			line.CharCount++
		}
	}
	p.Chars = newChars
	p.LineCharIndexCache = lineCharIndices
}

func (p *PageData) ResolveCharURI(ch *Char) string {
	if p == nil || ch == nil || len(p.Links) == 0 {
		return ""
	}
	charRect := geometry.Rect{X0: ch.BBox.X0, Y0: ch.BBox.Y0, X1: ch.BBox.X1, Y1: ch.BBox.Y1}
	charArea := charRect.Area()
	cx, cy := (ch.BBox.X0+ch.BBox.X1)/2, (ch.BBox.Y0+ch.BBox.Y1)/2
	bestURI, bestScore := "", float32(0)
	for _, l := range p.Links {
		if l.URI == "" {
			continue
		}
		linkRect := geometry.Rect{X0: l.Rect.X0, Y0: l.Rect.Y0, X1: l.Rect.X1, Y1: l.Rect.Y1}
		if linkRect.IsEmpty() {
			continue
		}
		centerInside := cx >= linkRect.X0 && cx <= linkRect.X1 && cy >= linkRect.Y0 && cy <= linkRect.Y1
		if !centerInside && (cx < linkRect.X0-1.0 || cx > linkRect.X1+1.0 || cy < linkRect.Y0-1.0 || cy > linkRect.Y1+1.0) {
			continue
		}
		overlap := charRect.IntersectArea(linkRect)
		score := float32(0)
		if charArea > 0 {
			score = overlap / charArea
		}
		if centerInside {
			score += 0.35
		}
		if score > bestScore {
			bestScore = score
			bestURI = l.URI
		}
	}
	if bestScore >= 0.08 {
		return bestURI
	}
	for _, l := range p.Links {
		if l.URI == "" {
			continue
		}
		linkRect := geometry.Rect{X0: l.Rect.X0, Y0: l.Rect.Y0, X1: l.Rect.X1, Y1: l.Rect.Y1}
		if linkRect.IsEmpty() {
			continue
		}
		if charArea <= 0 {
			if cx >= linkRect.X0-1.0 && cx <= linkRect.X1+1.0 && cy >= linkRect.Y0-1.0 && cy <= linkRect.Y1+1.0 {
				return l.URI
			}
		}
	}
	return ""
}

type Block struct {
	Type                 BlockType
	BBox                 Rect
	LineStart, LineCount int
}

type Line struct {
	BBox                 Rect
	CharStart, CharCount int
	Index                int
}

type Char struct {
	Codepoint                      rune
	Size                           float32
	BBox                           Rect
	IsBold, IsItalic, IsMonospaced bool
}

type Link struct {
	Rect Rect
	URI  string
}
