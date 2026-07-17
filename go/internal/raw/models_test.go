package raw

import (
	"slices"
	"testing"
)

func TestSanitizeCompactsLineCharacters(t *testing.T) {
	page := PageData{
		Lines: []Line{{CharStart: 0, CharCount: 3}, {CharStart: 3, CharCount: 2}},
		Chars: []Char{{Codepoint: 'a'}, {Codepoint: 0}, {Codepoint: 'b'}, {Codepoint: 0xFEFF}, {Codepoint: 'c'}},
	}

	page.Sanitize()

	if got := []rune{page.Chars[0].Codepoint, page.Chars[1].Codepoint, page.Chars[2].Codepoint}; !slices.Equal(got, []rune("abc")) {
		t.Fatalf("characters = %q, want abc", string(got))
	}
	if got := page.LineCharIndices(&page.Lines[0], nil); !slices.Equal(got, []int{0, 1}) {
		t.Fatalf("first line indices = %v, want [0 1]", got)
	}
	if got := page.LineCharIndices(&page.Lines[1], nil); !slices.Equal(got, []int{2}) {
		t.Fatalf("second line indices = %v, want [2]", got)
	}
}

func TestSanitizeClearsLinesWithoutCharacters(t *testing.T) {
	page := PageData{Lines: []Line{{CharStart: 4, CharCount: 2}}}
	page.Sanitize()
	if page.Lines[0].CharStart != 0 || page.Lines[0].CharCount != 0 {
		t.Fatalf("line range = %d:%d, want 0:0", page.Lines[0].CharStart, page.Lines[0].CharCount)
	}
}
