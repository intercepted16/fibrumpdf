package extractor

import (
	"strings"
	"unicode"
)

var bulletRunes = map[rune]struct{}{
	'•': {}, '●': {}, '○': {}, '◦': {}, '◯': {}, '▪': {}, '▫': {}, '■': {}, '□': {},
	'►': {}, '▶': {}, '▷': {}, '➢': {}, '➤': {}, '★': {}, '☆': {}, '✦': {}, '✧': {},
	'⁃': {}, '‣': {}, '⦿': {}, '⁌': {}, '⁍': {}, '-': {}, '–': {}, '—': {}, '*': {}, '+': {},
	0xF0B7: {}, 0xF076: {}, 0xF0B6: {},
}

func isBulletRune(r rune) bool {
	_, ok := bulletRunes[r]
	return ok
}

func startsWithListMarker(text string) bool {
	text = strings.TrimLeft(text, " \t")
	if text == "" {
		return false
	}
	runes := []rune(text)
	if len(runes) > 0 && isBulletRune(runes[0]) {
		return len(runes) > 1 && unicode.IsSpace(runes[1])
	}
	if len(runes) >= 3 && unicode.IsDigit(runes[0]) {
		i := 0
		for i < len(runes) && unicode.IsDigit(runes[i]) {
			i++
		}
		if i+1 < len(runes) && (runes[i] == '.' || runes[i] == ')') {
			return unicode.IsSpace(runes[i+1])
		}
	}
	return false
}

func startsWithNumericHeading(text string) bool {
	text = strings.TrimLeft(text, " ")
	if text == "" {
		return false
	}
	r := []rune(text)
	i := 0
	seenSep := false
	for i < len(r) {
		if unicode.IsDigit(r[i]) {
			i++
			continue
		}
		if r[i] == '.' || r[i] == ')' || r[i] == ':' || r[i] == '-' {
			seenSep = true
			i++
			continue
		}
		break
	}
	return i < len(r) && i > 0 && seenSep
}

func startsWithNumberMarker(text string) (bool, string) {
	text = strings.TrimLeft(text, " \t")
	if text == "" {
		return false, ""
	}
	r := []rune(text)
	i := 0
	for i < len(r) && unicode.IsDigit(r[i]) {
		i++
	}
	if i == 0 || i+1 >= len(r) {
		return false, ""
	}
	if (r[i] == '.' || r[i] == ')') && unicode.IsSpace(r[i+1]) {
		return true, string(r[:i+1])
	}
	return false, ""
}

func isAllCaps(text string) bool {
	hasAlpha := false
	for _, r := range text {
		if !unicode.IsLetter(r) {
			continue
		}
		hasAlpha = true
		if !unicode.IsUpper(r) {
			return false
		}
	}
	return hasAlpha
}

func endsWithPunctuation(text string) bool {
	trimmed := strings.TrimRightFunc(text, unicode.IsSpace)
	if trimmed == "" {
		return false
	}
	r := []rune(trimmed)
	last := r[len(r)-1]
	return last == '.' || last == ':' || last == ';' || last == '?' || last == '!'
}
