package textutil

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// NormalizeText trims and collapses whitespace while preserving single newlines.
func NormalizeText(input string) string {
	if input == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(input))
	lastSpace, lastWasNewline := true, false
	for _, c := range input {
		if c == '\r' {
			continue
		}
		if c == '\n' {
			if b.Len() > 0 {
				if s := b.String(); s[len(s)-1] == ' ' {
					b.Reset()
					b.WriteString(s[:len(s)-1])
				}
			}
			if !lastWasNewline {
				b.WriteByte('\n')
			}
			lastSpace, lastWasNewline = true, true
			continue
		}
		lastWasNewline = false
		if c == '\t' || c == '\f' || c == '\v' {
			c = ' '
		}
		if unicode.IsSpace(c) {
			if !lastSpace && b.Len() > 0 {
				b.WriteByte(' ')
				lastSpace = true
			}
			continue
		}
		b.WriteRune(c)
		lastSpace = false
	}
	return strings.TrimRight(b.String(), " \n")
}

// NormalizeTextFragment collapses internal whitespace while preserving whether
// the original fragment had leading/trailing whitespace boundaries.
func NormalizeTextFragment(input string) string {
	if input == "" {
		return ""
	}
	leading := hasLeadingWhitespace(input)
	trailing := hasTrailingWhitespace(input)
	out := NormalizeText(input)
	if out == "" {
		if leading || trailing {
			return " "
		}
		return ""
	}
	if leading {
		out = " " + out
	}
	if trailing {
		out += " "
	}
	return out
}

func hasLeadingWhitespace(s string) bool {
	r, _ := utf8.DecodeRuneInString(s)
	return r != utf8.RuneError && unicode.IsSpace(r)
}

func hasTrailingWhitespace(s string) bool {
	r, _ := utf8.DecodeLastRuneInString(s)
	return r != utf8.RuneError && unicode.IsSpace(r)
}
