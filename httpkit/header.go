package httpkit

import (
	"io"
	"net/http"
	"net/textproto"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/kspkr/wirekit/internal/ascii"
)

// Header is one header field: a name and a value, spelled as they appeared
// on the wire.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Headers is an ordered list of header fields.
//
// Unlike net/http's map, Headers keeps the order and capitalization seen on
// the wire, which matters when inspecting traffic. Lookups are
// case-insensitive. The zero value is an empty, ready-to-use list.
//
// Methods that modify the list have pointer receivers; the rest work on the
// value. A Headers value is a slice, so ranging over it is the way to
// iterate:
//
//	for _, h := range headers {
//		fmt.Println(h.Name, h.Value)
//	}
type Headers []Header

// Get returns the value of the first field named name, or "" if there is
// none. Comparison is case-insensitive.
func (hs Headers) Get(name string) string {
	for i := range hs {
		if ascii.EqualFold(hs[i].Name, name) {
			return hs[i].Value
		}
	}
	return ""
}

// Lookup is like Get but also reports whether the field was present, which
// distinguishes a missing field from an empty value.
func (hs Headers) Lookup(name string) (string, bool) {
	for i := range hs {
		if ascii.EqualFold(hs[i].Name, name) {
			return hs[i].Value, true
		}
	}
	return "", false
}

// Has reports whether at least one field named name is present.
func (hs Headers) Has(name string) bool {
	_, ok := hs.Lookup(name)
	return ok
}

// Values returns every value of the fields named name, in order. It
// returns nil when there are none.
func (hs Headers) Values(name string) []string {
	var out []string
	for i := range hs {
		if ascii.EqualFold(hs[i].Name, name) {
			out = append(out, hs[i].Value)
		}
	}
	return out
}

// Count returns how many fields named name are present.
func (hs Headers) Count(name string) int {
	n := 0
	for i := range hs {
		if ascii.EqualFold(hs[i].Name, name) {
			n++
		}
	}
	return n
}

// Add appends a field to the end of the list.
func (hs *Headers) Add(name, value string) {
	*hs = append(*hs, Header{Name: name, Value: value})
}

// Set replaces the fields named name with a single field holding value. The
// new field takes the position and name spelling of the first existing
// one, so the message changes as little as possible; if there was none, a
// field spelled as name is appended.
func (hs *Headers) Set(name, value string) {
	list := *hs
	first := -1
	for i := range list {
		if ascii.EqualFold(list[i].Name, name) {
			first = i
			break
		}
	}
	if first < 0 {
		hs.Add(name, value)
		return
	}
	list[first].Value = value
	// Compact the tail in place, dropping later fields with the same name.
	tail := slices.DeleteFunc(list[first+1:], func(h Header) bool { return ascii.EqualFold(h.Name, name) })
	*hs = list[: first+1+len(tail) : cap(list)]
}

// Del removes every field named name. It reports whether any was removed.
func (hs *Headers) Del(name string) bool {
	before := len(*hs)
	*hs = slices.DeleteFunc(*hs, func(h Header) bool { return ascii.EqualFold(h.Name, name) })
	return len(*hs) != before
}

// Clone returns a copy that shares no storage with hs.
func (hs Headers) Clone() Headers {
	if hs == nil {
		return nil
	}
	out := make(Headers, len(hs))
	copy(out, hs)
	return out
}

// Write serializes the fields as "Name: Value" lines terminated by CRLF. It
// does not write the blank line that ends a header block.
func (hs Headers) Write(w io.Writer) error {
	var buf []byte
	for i := range hs {
		buf = buf[:0]
		buf = append(buf, hs[i].Name...)
		buf = append(buf, ": "...)
		buf = append(buf, hs[i].Value...)
		buf = append(buf, "\r\n"...)
		if _, err := w.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

// String returns the fields as "Name: Value" lines separated by CRLF.
func (hs Headers) String() string {
	var sb strings.Builder
	_ = hs.Write(&sb)
	return sb.String()
}

// ToStd converts the list to a net/http header map. Names are
// canonicalized the way net/http does, and wire order is lost.
func (hs Headers) ToStd() http.Header {
	out := make(http.Header, len(hs))
	for i := range hs {
		out.Add(hs[i].Name, hs[i].Value)
	}
	return out
}

// FromStd converts a net/http header map. Because the map has no order,
// fields are sorted by name so the result is deterministic.
func FromStd(h http.Header) Headers {
	if len(h) == 0 {
		return nil
	}
	names := make([]string, 0, len(h))
	n := 0
	for k, vv := range h {
		names = append(names, k)
		n += len(vv)
	}
	sort.Strings(names)
	out := make(Headers, 0, n)
	for _, k := range names {
		for _, v := range h[k] {
			out = append(out, Header{Name: k, Value: v})
		}
	}
	return out
}

// Canonical returns name in the capitalization net/http uses
// ("content-type" becomes "Content-Type"). Names that are not valid tokens
// are returned unchanged.
func Canonical(name string) string {
	return textproto.CanonicalMIMEHeaderKey(name)
}

// ContentType parses the Content-Type field. It never fails: when the field
// is missing the result is the zero ContentType, and when it is malformed
// MediaType is the field value up to the first ';', lower-cased and
// trimmed, with Params nil.
func (hs Headers) ContentType() ContentType {
	v, ok := hs.Lookup("Content-Type")
	if !ok {
		return ContentType{}
	}
	ct, err := ParseContentType(v)
	if err != nil {
		mt, _, _ := strings.Cut(v, ";")
		return ContentType{MediaType: ascii.ToLower(ascii.TrimSpace(mt))}
	}
	return ct
}

// ContentLength returns the Content-Length value. ok is false when the
// field is absent, not a non-negative integer, or present more than once
// with differing values (which RFC 9112 requires recipients to reject).
func (hs Headers) ContentLength() (n int64, ok bool) {
	found := false
	for i := range hs {
		if !ascii.EqualFold(hs[i].Name, "Content-Length") {
			continue
		}
		v, err := parseContentLength(hs[i].Value)
		if err != nil {
			return 0, false
		}
		if found && v != n {
			return 0, false
		}
		n, found = v, true
	}
	return n, found
}

// parseContentLength accepts a list of identical values ("5, 5"), as
// RFC 9110 §8.6 allows, and rejects everything that is not a plain
// non-negative decimal integer.
func parseContentLength(v string) (int64, error) {
	v = ascii.TrimSpace(v)
	if v == "" {
		return 0, malformed("Content-Length")
	}
	var first int64 = -1
	for part := range strings.SplitSeq(v, ",") {
		part = ascii.TrimSpace(part)
		if part == "" || len(part) > 19 {
			return 0, malformed("Content-Length")
		}
		for i := 0; i < len(part); i++ {
			if !ascii.IsDigit(part[i]) {
				return 0, malformed("Content-Length")
			}
		}
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return 0, malformed("Content-Length")
		}
		if first >= 0 && n != first {
			return 0, malformed("Content-Length")
		}
		first = n
	}
	return first, nil
}

// ContentEncoding returns the content codings applied to the body, lower
// cased and in the order they were applied. It returns nil when the field
// is absent.
func (hs Headers) ContentEncoding() []string {
	return hs.tokens("Content-Encoding")
}

// TransferEncoding returns the transfer codings applied to the message,
// lower cased and in the order they were applied. It returns nil when the
// field is absent.
func (hs Headers) TransferEncoding() []string {
	return hs.tokens("Transfer-Encoding")
}

// IsChunked reports whether the final transfer coding is chunked.
func (hs Headers) IsChunked() bool {
	te := hs.TransferEncoding()
	return len(te) > 0 && te[len(te)-1] == "chunked"
}

// HasConnectionToken reports whether the Connection field lists token,
// compared case-insensitively.
func (hs Headers) HasConnectionToken(token string) bool {
	for i := range hs {
		if !ascii.EqualFold(hs[i].Name, "Connection") {
			continue
		}
		for t := range strings.SplitSeq(hs[i].Value, ",") {
			if ascii.EqualFold(ascii.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// UpgradeProtocol returns the protocol named by the Upgrade field when the
// message actually asks for an upgrade (Connection includes "upgrade"). It
// returns "" otherwise. For a WebSocket handshake this is "websocket".
func (hs Headers) UpgradeProtocol() string {
	if !hs.HasConnectionToken("upgrade") {
		return ""
	}
	return ascii.TrimSpace(hs.Get("Upgrade"))
}

// hopByHop lists the fields that describe one connection rather than the
// message and must not be forwarded by a proxy (RFC 9110 §7.6.1).
var hopByHop = [...]string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection", // not standard, but still sent by some clients
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// RemoveHopByHop deletes the hop-by-hop fields and any field named in the
// Connection field. It is what a proxy does before forwarding a message.
func (hs *Headers) RemoveHopByHop() {
	var named []string
	for i := range *hs {
		if !ascii.EqualFold((*hs)[i].Name, "Connection") {
			continue
		}
		for t := range strings.SplitSeq((*hs)[i].Value, ",") {
			if t = ascii.TrimSpace(t); t != "" {
				named = append(named, t)
			}
		}
	}
	for _, n := range named {
		hs.Del(n)
	}
	for _, n := range hopByHop {
		hs.Del(n)
	}
}

// Cookies parses every Cookie field (a request carries the cookies sent to
// the server). Malformed pieces are skipped rather than reported; see
// ParseCookies.
func (hs Headers) Cookies() []Cookie {
	var out []Cookie
	for i := range hs {
		if ascii.EqualFold(hs[i].Name, "Cookie") {
			out = append(out, ParseCookies(hs[i].Value)...)
		}
	}
	return out
}

// SetCookies parses every Set-Cookie field (a response carries the cookies
// a server wants stored). Fields that cannot be parsed at all are skipped;
// use Values("Set-Cookie") and ParseSetCookie to see errors.
func (hs Headers) SetCookies() []SetCookie {
	var out []SetCookie
	for i := range hs {
		if !ascii.EqualFold(hs[i].Name, "Set-Cookie") {
			continue
		}
		if c, err := ParseSetCookie(hs[i].Value); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// tokens returns the comma-separated tokens of every field named name,
// lower cased, with empty entries dropped.
func (hs Headers) tokens(name string) []string {
	var out []string
	for i := range hs {
		if !ascii.EqualFold(hs[i].Name, name) {
			continue
		}
		for t := range strings.SplitSeq(hs[i].Value, ",") {
			if t = ascii.TrimSpace(t); t != "" {
				out = append(out, ascii.ToLower(t))
			}
		}
	}
	return out
}
