package textutil

import (
	"strings"
	"unicode"
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
