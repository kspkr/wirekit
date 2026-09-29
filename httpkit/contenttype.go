package httpkit

import (
	"mime"
	"strconv"
	"strings"

	"github.com/kspkr/wirekit/internal/ascii"
)

// ContentType is a parsed media type such as "text/html; charset=utf-8".
type ContentType struct {
	// MediaType is "type/subtype" in lower case, e.g. "application/json".
	MediaType string `json:"mediaType"`
	// Params holds the parameters with lower-cased names, or nil if there
	// are none.
	Params map[string]string `json:"params,omitempty"`
}

// ParseContentType parses a Content-Type (or any media type) value. The
// returned error wraps ErrMalformed.
func ParseContentType(v string) (ContentType, error) {
	mt, params, err := mime.ParseMediaType(v)
	if err != nil {
		return ContentType{}, malformed("media type: " + err.Error())
	}
	if typ, sub, ok := strings.Cut(mt, "/"); !ok || typ == "" || sub == "" {
		return ContentType{}, malformed("media type: missing type/subtype in " + strconv.Quote(v))
	}
	if len(params) == 0 {
		params = nil
	}
	return ContentType{MediaType: mt, Params: params}, nil
}

// String formats the media type with its parameters, quoting values as
// needed.
func (ct ContentType) String() string {
	if ct.MediaType == "" && len(ct.Params) == 0 {
		return ""
	}
	return mime.FormatMediaType(ct.MediaType, ct.Params)
}

// IsZero reports whether no media type is set.
func (ct ContentType) IsZero() bool {
	return ct.MediaType == "" && len(ct.Params) == 0
}

// Type returns the part before the '/', e.g. "text" for "text/html".
func (ct ContentType) Type() string {
	t, _, _ := strings.Cut(ct.MediaType, "/")
	return t
}

// Subtype returns the part after the '/', e.g. "html" for "text/html".
func (ct ContentType) Subtype() string {
	_, s, _ := strings.Cut(ct.MediaType, "/")
	return s
}

// Suffix returns the structured syntax suffix, e.g. "json" for
// "application/ld+json", or "" if there is none.
func (ct ContentType) Suffix() string {
	sub := ct.Subtype()
	if i := strings.LastIndexByte(sub, '+'); i >= 0 {
		return sub[i+1:]
	}
	return ""
}

// Param returns the named parameter, matched case-insensitively.
func (ct ContentType) Param(name string) string {
	if v, ok := ct.Params[ascii.ToLower(name)]; ok {
		return v
	}
	return ""
}

// Charset returns the charset parameter in lower case, or "".
func (ct ContentType) Charset() string {
	return ascii.ToLower(ct.Param("charset"))
}

// Boundary returns the boundary parameter of a multipart type, or "".
func (ct ContentType) Boundary() string {
	return ct.Param("boundary")
}

// IsJSON reports whether the body is JSON: the subtype is "json" or ends in
// "+json" (application/json, text/json, application/problem+json, ...).
func (ct ContentType) IsJSON() bool {
	sub := ct.Subtype()
	return sub == "json" || strings.HasSuffix(sub, "+json")
}

// IsXML reports whether the body is XML: the subtype is "xml" or ends in
// "+xml" (application/xml, text/xml, image/svg+xml, ...).
func (ct ContentType) IsXML() bool {
	sub := ct.Subtype()
	return sub == "xml" || strings.HasSuffix(sub, "+xml")
}

// IsForm reports whether the body is application/x-www-form-urlencoded.
func (ct ContentType) IsForm() bool {
	return ct.MediaType == "application/x-www-form-urlencoded"
}

// IsMultipart reports whether the top-level type is "multipart".
func (ct ContentType) IsMultipart() bool {
	return ct.Type() == "multipart"
}

// textualTypes are non-text/* media types whose bodies are readable text.
var textualTypes = map[string]bool{
	"application/javascript":            true,
	"application/x-javascript":          true,
	"application/ecmascript":            true,
	"application/x-www-form-urlencoded": true,
	"application/graphql":               true,
	"application/x-ndjson":              true,
	"application/yaml":                  true,
	"application/x-yaml":                true,
	"application/toml":                  true,
	"application/sql":                   true,
	"application/x-sh":                  true,
	"application/x-httpd-php":           true,
	"application/xhtml+xml":             true,
	"image/svg+xml":                     true,
}

// IsText reports whether the body is text a person can read: any text/*
// type, JSON, XML, and a handful of textual application/* types such as
// JavaScript, YAML and form data. It says nothing about the charset.
func (ct ContentType) IsText() bool {
	if ct.Type() == "text" || ct.IsJSON() || ct.IsXML() {
		return true
	}
	return textualTypes[ct.MediaType]
}
