package httpkit

import (
	"net/url"
	"slices"
	"strings"
)

// Param is one name/value pair from a query string or form body.
type Param struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Params is an ordered list of query or form parameters. Unlike url.Values
// it keeps the order the parameters appeared in and allows the same name to
// repeat. Names are compared case-sensitively.
type Params []Param

// ParseQuery parses a query string ("a=1&b=2") or an
// application/x-www-form-urlencoded body.
//
// Parsing is lenient so that inspection never loses data: pairs are split
// on '&', '+' becomes a space and percent-escapes are decoded. A pair whose
// name or value cannot be decoded is kept with the undecoded text, and the
// first such problem is returned as the error (wrapping ErrMalformed).
// Empty pairs are skipped. A leading '?' is ignored.
func ParseQuery(raw string) (Params, error) {
	raw = strings.TrimPrefix(raw, "?")
	var (
		out  Params
		errs error
	)
	for pair := range strings.SplitSeq(raw, "&") {
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		if n, err := url.QueryUnescape(name); err == nil {
			name = n
		} else if errs == nil {
			errs = malformed("query: " + err.Error())
		}
		if v, err := url.QueryUnescape(value); err == nil {
			value = v
		} else if errs == nil {
			errs = malformed("query: " + err.Error())
		}
		out = append(out, Param{Name: name, Value: value})
	}
	return out, errs
}

// Get returns the value of the first parameter named name, or "".
func (ps Params) Get(name string) string {
	for i := range ps {
		if ps[i].Name == name {
			return ps[i].Value
		}
	}
	return ""
}

// Lookup is like Get but also reports whether the parameter was present.
func (ps Params) Lookup(name string) (string, bool) {
	for i := range ps {
		if ps[i].Name == name {
			return ps[i].Value, true
		}
	}
	return "", false
}

// Has reports whether at least one parameter named name is present.
func (ps Params) Has(name string) bool {
	_, ok := ps.Lookup(name)
	return ok
}

// Values returns every value of the parameters named name, in order, or nil.
func (ps Params) Values(name string) []string {
	var out []string
	for i := range ps {
		if ps[i].Name == name {
			out = append(out, ps[i].Value)
		}
	}
	return out
}

// Add appends a parameter.
func (ps *Params) Add(name, value string) {
	*ps = append(*ps, Param{Name: name, Value: value})
}

// Set replaces the parameters named name with a single one holding value,
// in the position of the first, or appends it if there was none.
func (ps *Params) Set(name, value string) {
	list := *ps
	first := -1
	for i := range list {
		if list[i].Name == name {
			first = i
			break
		}
	}
	if first < 0 {
		ps.Add(name, value)
		return
	}
	list[first].Value = value
	tail := slices.DeleteFunc(list[first+1:], func(p Param) bool { return p.Name == name })
	*ps = list[: first+1+len(tail) : cap(list)]
}

// Del removes every parameter named name and reports whether any was
// removed.
func (ps *Params) Del(name string) bool {
	before := len(*ps)
	*ps = slices.DeleteFunc(*ps, func(p Param) bool { return p.Name == name })
	return len(*ps) != before
}

// Clone returns a copy that shares no storage with ps.
func (ps Params) Clone() Params {
	if ps == nil {
		return nil
	}
	out := make(Params, len(ps))
	copy(out, ps)
	return out
}

// Encode serializes the parameters as a query string, percent-escaping as
// url.QueryEscape does and preserving order. The result has no leading '?'.
func (ps Params) Encode() string {
	var sb strings.Builder
	for i := range ps {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(url.QueryEscape(ps[i].Name))
		sb.WriteByte('=')
		sb.WriteString(url.QueryEscape(ps[i].Value))
	}
	return sb.String()
}

// ToStd converts the list to url.Values. Order within a name is kept; order
// across names is lost.
func (ps Params) ToStd() url.Values {
	out := make(url.Values, len(ps))
	for i := range ps {
		out[ps[i].Name] = append(out[ps[i].Name], ps[i].Value)
	}
	return out
}
