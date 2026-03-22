package table

// CountCharMatching counts the number of runes in s that match the provided predicate.
func CountCharMatching(s string, match func(rune) bool) int {
	count := 0
	for _, r := range s {
		if match(r) {
			count++
		}
	}
	return count
}

// HasNDigits returns true if the string contains at least n digits.
func HasNDigits(s string, n int) bool {
	return CountCharMatching(s, func(r rune) bool {
		return r >= '0' && r <= '9'
	}) >= n
}
