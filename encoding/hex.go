package encoding

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// DecodeHex decodes hexadecimal text leniently. It accepts upper or lower
// case, an optional "0x" prefix, and ignores ASCII whitespace and the ':'
// separators used in fingerprints and MAC addresses. An empty input
// decodes to an empty, non-nil slice.
//
// The error wraps ErrInvalid when the text is not hex or has an odd number
// of digits.
func DecodeHex(s string) ([]byte, error) {
	s = stripSpace(s)
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	s = strings.ReplaceAll(s, ":", "")
	out, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: hex: %w", ErrInvalid, err)
	}
	return out, nil
}

// HexDump formats data as a classic hex dump: an offset column, sixteen
// bytes per line as hex, and the printable ASCII of those bytes.
//
// At most limit bytes are dumped; when data is longer the dump ends with a
// line noting how many bytes were omitted. A limit of zero or less dumps
// everything.
//
//	00000000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  |HTTP/1.1 200 OK.|
func HexDump(data []byte, limit int) string {
	shown := data
	if limit > 0 && len(data) > limit {
		shown = data[:limit]
	}
	var sb strings.Builder
	sb.Grow(len(shown)/16*79 + 79)
	d := hex.Dumper(&sb)
	_, _ = d.Write(shown)
	_ = d.Close()
	if len(shown) < len(data) {
		sb.WriteString("... ")
		sb.WriteString(strconv.Itoa(len(data) - len(shown)))
		sb.WriteString(" more bytes\n")
	}
	return sb.String()
}
