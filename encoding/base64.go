package encoding

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ErrInvalid is wrapped by every decoding error in this package.
var ErrInvalid = errors.New("encoding: invalid input")

// DecodeBase64 decodes base64 text leniently. It accepts the standard and
// URL-safe alphabets (but not a mix of the two), with or without padding,
// and ignores ASCII whitespace anywhere in the input. An empty input
// decodes to an empty, non-nil slice.
//
// The error wraps ErrInvalid when the text is not base64.
func DecodeBase64(s string) ([]byte, error) {
	s = stripSpace(s)
	urlSafe, std := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '-', '_':
			urlSafe = true
		case '+', '/':
			std = true
		}
	}
	if urlSafe && std {
		return nil, fmt.Errorf("%w: base64 mixes standard and URL-safe alphabets", ErrInvalid)
	}
	// Strip padding and decode without it, so both padded and unpadded
	// input work; RawStdEncoding rejects '=' inside the data.
	s = strings.TrimRight(s, "=")
	enc := base64.RawStdEncoding
	if urlSafe {
		enc = base64.RawURLEncoding
	}
	out, err := enc.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: base64: %w", ErrInvalid, err)
	}
	return out, nil
}

// stripSpace removes ASCII whitespace. It returns s itself when there is
// none.
func stripSpace(s string) string {
	if strings.IndexFunc(s, isASCIISpace) < 0 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if !isASCIISpace(rune(s[i])) {
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

func isASCIISpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f' || r == '\v'
}
