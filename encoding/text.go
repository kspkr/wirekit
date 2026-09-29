package encoding

import "unicode/utf8"

// textSampleSize bounds how much of a body LooksLikeText examines.
const textSampleSize = 4096

// LooksLikeText reports whether data is probably human-readable UTF-8
// text: it decodes as UTF-8 (allowing a rune cut off at the sample edge),
// contains no NUL bytes, and fewer than two percent of its characters are
// control characters other than tab, newline and carriage return. Only the
// first 4 KiB are examined. Empty data is text.
func LooksLikeText(data []byte) bool {
	sample := data
	if len(sample) > textSampleSize {
		sample = sample[:textSampleSize]
	}
	if len(sample) == 0 {
		return true
	}
	// Ignore an incomplete rune at the end of a truncated sample.
	if len(sample) < len(data) {
		for i := 1; i <= utf8.UTFMax && i <= len(sample); i++ {
			if utf8.RuneStart(sample[len(sample)-i]) {
				if !utf8.FullRune(sample[len(sample)-i:]) {
					sample = sample[:len(sample)-i]
				}
				break
			}
		}
	}
	if !utf8.Valid(sample) {
		return false
	}
	control, total := 0, 0
	for i := 0; i < len(sample); {
		c := sample[i]
		if c < utf8.RuneSelf {
			i++
			total++
			switch {
			case c == 0:
				return false
			case c < 0x20 && c != '\t' && c != '\n' && c != '\r', c == 0x7f:
				control++
			}
			continue
		}
		_, size := utf8.DecodeRune(sample[i:])
		i += size
		total++
	}
	return control*50 < total
}
