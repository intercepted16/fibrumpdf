package textutil

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/pymupdf4llm-c/go/internal/geometry"
	rawdata "github.com/pymupdf4llm-c/go/internal/raw"
)

// AssembleOptions controls how text is assembled from ordered chars.
type AssembleOptions struct {
	InsertSpaces       bool
	Normalize          bool
	MergeNumericSpaces bool
	CollapseSpaces     bool
}

// TextAssembler assembles text from ordered chars with shared spacing rules.
type TextAssembler struct {
	opts AssembleOptions
}

func NewTextAssembler(opts AssembleOptions) TextAssembler {
	return TextAssembler{opts: opts}
}

func (ta TextAssembler) AssembleOrderedChars(chars []rawdata.Char) string {
	if len(chars) == 0 {
		return ""
	}
	var buf strings.Builder
	var prev rawdata.Char
	hasPrev := false
	for _, ch := range chars {
		if ta.opts.InsertSpaces && hasPrev {
			if shouldInsertSpace(prev, ch) {
				if buf.Len() > 0 {
					prevR := prev.Codepoint
					currR := ch.Codepoint
					if prevR != ' ' && !unicode.IsSpace(prevR) && !isPunctuationLike(currR) {
						buf.WriteByte(' ')
					}
				}
			}
		}
		buf.WriteRune(ch.Codepoint)
		prev = ch
		hasPrev = true
	}
	out := buf.String()
	out = strings.ReplaceAll(out, "\u00A0", " ")
	if ta.opts.Normalize {
		out = NormalizeText(out)
	}
	if ta.opts.CollapseSpaces {
		for strings.Contains(out, "  ") {
			out = strings.ReplaceAll(out, "  ", " ")
		}
	}
	if ta.opts.MergeNumericSpaces {
		out = mergeNumericSpaces(out)
	}
	return out
}

func shouldInsertSpace(prev, curr rawdata.Char) bool {
	prevCY := (prev.BBox.Y0 + prev.BBox.Y1) * 0.5
	currCY := (curr.BBox.Y0 + curr.BBox.Y1) * 0.5
	lineTol := geometry.Max32(geometry.Max32(prev.Size, curr.Size)*0.5, 1.5)
	if geometry.Abs32(currCY-prevCY) > lineTol {
		return true
	}
	gap := curr.BBox.X0 - prev.BBox.X1
	spaceGap := geometry.Max32(geometry.Max32(prev.Size, curr.Size)*0.33, 1.2)
	return gap > spaceGap
}

func isPunctuationLike(r rune) bool {
	switch r {
	case '.', ',', '$', '%', ':', ';', '\'', '"', '-', '(', ')':
		return true
	default:
		return r >= '0' && r <= '9'
	}
}

var numericCellRe = regexpMustCompile(`^[\d,.\-$%()\s]+$`)

var leadingDigitSpaceRe = regexpMustCompile(`(?:^|([^0-9]))(\d{1,2}) (\d+[,.])`)

var trailingCommaSpaceRe = regexpMustCompile(`(\d) (,\d)`)

func mergeNumericSpaces(s string) string {
	if !strings.ContainsRune(s, ' ') {
		return s
	}
	if !numericCellRe.MatchString(s) {
		return s
	}
	s = leadingDigitSpaceRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := leadingDigitSpaceRe.FindStringSubmatch(m)
		if sub == nil {
			return m
		}
		return sub[1] + sub[2] + sub[3]
	})
	s = trailingCommaSpaceRe.ReplaceAllString(s, "$1$2")
	return s
}

// regexpMustCompile avoids importing regexp in callers.
func regexpMustCompile(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}
