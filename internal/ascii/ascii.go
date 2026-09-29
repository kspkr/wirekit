// Package ascii holds byte-level helpers for the ASCII subset that HTTP and
// related protocols are written in. Everything here is allocation-free.
package ascii

// EqualFold reports whether a and b are equal under ASCII case folding.
// Non-ASCII bytes must match exactly.
func EqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if Lower(a[i]) != Lower(b[i]) {
			return false
		}
	}
	return true
}

// Lower returns c folded to lower case if it is an ASCII upper-case letter.
func Lower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// ToLower returns s folded to ASCII lower case. It returns s itself when
// nothing needs to change.
func ToLower(s string) string {
	for i := 0; i < len(s); i++ {
		if 'A' <= s[i] && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				b[j] = Lower(b[j])
			}
			return string(b)
		}
	}
	return s
}

// IsSpace reports whether c is SP or HTAB, the only whitespace HTTP
// field values may contain around tokens.
func IsSpace(c byte) bool { return c == ' ' || c == '\t' }

// TrimSpace removes leading and trailing SP and HTAB.
func TrimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && IsSpace(s[i]) {
		i++
	}
	for j > i && IsSpace(s[j-1]) {
		j--
	}
	return s[i:j]
}

// IsTokenChar reports whether c is a tchar (RFC 9110 §5.6.2).
func IsTokenChar(c byte) bool {
	return tokenTable[c]
}

// IsToken reports whether s is a non-empty token (RFC 9110 §5.6.2).
func IsToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !tokenTable[s[i]] {
			return false
		}
	}
	return true
}

// IsFieldVchar reports whether c may appear inside an HTTP field value
// (VCHAR, obs-text, SP or HTAB per RFC 9110 §5.5).
func IsFieldVchar(c byte) bool {
	return c == ' ' || c == '\t' || (c >= 0x21 && c != 0x7f)
}

// IsDigit reports whether c is an ASCII digit.
func IsDigit(c byte) bool { return '0' <= c && c <= '9' }

// tokenTable marks the tchar set:
// "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" /
// "`" / "|" / "~" / DIGIT / ALPHA.
var tokenTable = [256]bool{
	'!': true, '#': true, '$': true, '%': true, '&': true, '\'': true,
	'*': true, '+': true, '-': true, '.': true, '^': true, '_': true,
	'`': true, '|': true, '~': true,
	'0': true, '1': true, '2': true, '3': true, '4': true,
	'5': true, '6': true, '7': true, '8': true, '9': true,
	'A': true, 'B': true, 'C': true, 'D': true, 'E': true, 'F': true,
	'G': true, 'H': true, 'I': true, 'J': true, 'K': true, 'L': true,
	'M': true, 'N': true, 'O': true, 'P': true, 'Q': true, 'R': true,
	'S': true, 'T': true, 'U': true, 'V': true, 'W': true, 'X': true,
	'Y': true, 'Z': true,
	'a': true, 'b': true, 'c': true, 'd': true, 'e': true, 'f': true,
	'g': true, 'h': true, 'i': true, 'j': true, 'k': true, 'l': true,
	'm': true, 'n': true, 'o': true, 'p': true, 'q': true, 'r': true,
	's': true, 't': true, 'u': true, 'v': true, 'w': true, 'x': true,
	'y': true, 'z': true,
}
