package text

import (
	"strings"
	"unicode"
)

func IsBullet[T rune | string](v T) bool {
	bulletRunes := map[rune]bool{
		'•': true, '●': true, '○': true, '◦': true, '◯': true, '▪': true, '▫': true, '■': true, '□': true,
		'►': true, '▶': true, '▷': true, '➢': true, '➤': true, '★': true, '☆': true, '✦': true, '✧': true,
		'⁃': true, '‣': true, '⦿': true, '⁌': true, '⁍': true, '-': true, '–': true, '—': true, '*': true, '+': true,
		0xF0B7: true, 0xF076: true, 0xF0B6: true,
	}
	bulletStrings := map[string]bool{
		"`o`": true,
	}

	switch any(v).(type) {
	case rune:
		return bulletRunes[any(v).(rune)]
	case string:
		return bulletStrings[any(v).(string)]
	}
	return false
}

func HasVisibleContent(text string) bool {
	for _, r := range text {
		if unicode.IsSpace(r) {
			continue
		}
		if unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsPunct(r) || unicode.IsSymbol(r) {
			return true
		}
	}
	return false
}

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

func EndsWithPunctuation(text string) bool {
	text = strings.TrimRightFunc(text, unicode.IsSpace)
	if len(text) == 0 {
		return false
	}
	last := rune(text[len(text)-1])
	return last == '.' || last == ':' || last == ';' || last == '?' || last == '!'
}

func IsAllCaps(text string) bool {
	hasAlpha := false
	for _, r := range text {
		if unicode.IsLetter(r) {
			hasAlpha = true
			if !unicode.IsUpper(r) {
				return false
			}
		}
	}
	return hasAlpha
}

func StartsWithNumericHeading(text string) bool {
	text = strings.TrimLeft(text, " ")
	if text == "" {
		return false
	}
	seenDigit, seenSeparator, i := false, false, 0
	for i < len(text) {
		r := rune(text[i])
		if r >= '0' && r <= '9' {
			seenDigit = true
			i++
		} else if r == '.' || r == ')' || r == ':' || r == '-' {
			seenSeparator = true
			i++
		} else {
			break
		}
	}
	if !seenDigit || !seenSeparator || i >= len(text) {
		return false
	}
	next := rune(text[i])
	return unicode.IsSpace(next) || next == '-' || next == ')'
}

func StartsWithBullet(text string) bool {
	text = strings.TrimLeft(text, " \t")
	if text == "" {
		return false
	}
	r := []rune(text)
	if IsBullet(r[0]) {
		if len(r) == 1 {
			return true
		}
		if !unicode.IsSpace(r[1]) {
			return false
		}
		rest := strings.TrimSpace(string(r[1:]))
		if rest == "" {
			return false
		}
		if rr := []rune(rest); len(rr) > 0 {
			if IsBullet(rr[0]) {
				return false
			}
			if len(rr) == 1 && (rr[0] == '-' || rr[0] == '–' || rr[0] == '—') {
				return false
			}
		}
		return true
	}
	if isDigit(text[0]) || (len(text) >= 2 && isAlpha(text[0])) {
		i := 0
		for i < len(text) && isDigit(text[i]) {
			i++
		}
		if i < len(text) && (text[i] == '.' || text[i] == ')') {
			return i+1 >= len(text) || unicode.IsSpace(rune(text[i+1]))
		}
	}
	return false
}

func StartsWithNumber(text string) (bool, string) {
	text = strings.TrimLeft(text, " \t")
	if text == "" {
		return false, ""
	}
	i := 0
	for i < len(text) && isDigit(text[i]) {
		i++
	}
	if i > 0 && i < len(text) && (text[i] == '.' || text[i] == ')') && i+1 < len(text) && unicode.IsSpace(rune(text[i+1])) {
		return true, text[:i+1]
	}
	if len(text) >= 2 && isAlpha(text[0]) && (text[1] == '.' || text[1] == ')') && (len(text) == 2 || unicode.IsSpace(rune(text[2]))) {
		return true, text[:2]
	}
	return false, ""
}

func IsLonePageNumber(text string) bool {
	text = strings.TrimLeft(text, " \t")
	digitCount := 0
	for digitCount < len(text) && isDigit(text[digitCount]) {
		digitCount++
	}
	text = strings.TrimRight(text[digitCount:], " \t")
	return digitCount > 0 && digitCount <= 4 && text == ""
}

func IsInMarginArea(bbox [4]float32, pageBBox [4]float32, thresholdPercent float32) bool {
	threshold := (pageBBox[3] - pageBBox[1]) * thresholdPercent
	return bbox[1] < pageBBox[1]+threshold || bbox[3] > pageBBox[3]-threshold
}

func CountUnicodeChars(text string) int { return len([]rune(text)) }
func isDigit(b byte) bool               { return b >= '0' && b <= '9' }
func isAlpha(b byte) bool               { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
