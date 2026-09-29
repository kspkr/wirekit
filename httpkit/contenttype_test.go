package httpkit

import (
	"errors"
	"testing"
)

func TestParseContentType(t *testing.T) {
	ct, err := ParseContentType(`Text/HTML; Charset="UTF-8"; boundary=abc`)
	if err != nil {
		t.Fatal(err)
	}
	if ct.MediaType != "text/html" {
		t.Errorf("MediaType = %q", ct.MediaType)
	}
	if ct.Type() != "text" || ct.Subtype() != "html" {
		t.Errorf("Type/Subtype = %q/%q", ct.Type(), ct.Subtype())
	}
	if ct.Charset() != "utf-8" || ct.Param("CHARSET") != "UTF-8" || ct.Boundary() != "abc" {
		t.Errorf("params = %v", ct.Params)
	}
	if ct.Param("nope") != "" {
		t.Error("missing param not empty")
	}
	if got := ct.String(); got != `text/html; boundary=abc; charset=UTF-8` {
		t.Errorf("String = %q", got)
	}

	plain, err := ParseContentType("application/json")
	if err != nil || plain.Params != nil || plain.String() != "application/json" {
		t.Errorf("plain = %+v, %v", plain, err)
	}

	for _, bad := range []string{"", "text", "text/html; charset", "text/html; =x", "/html"} {
		if _, err := ParseContentType(bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseContentType(%q) err = %v", bad, err)
		}
	}
	if !(ContentType{}).IsZero() || (ContentType{MediaType: "a/b"}).IsZero() || (ContentType{}).String() != "" {
		t.Error("IsZero/String on zero value wrong")
	}
}

func TestContentTypePredicates(t *testing.T) {
	cases := []struct {
		mt                               string
		json, xml, form, multipart, text bool
		suffix                           string
	}{
		{"application/json", true, false, false, false, true, ""},
		{"text/json", true, false, false, false, true, ""},
		{"application/problem+json", true, false, false, false, true, "json"},
		{"application/ld+json", true, false, false, false, true, "json"},
		{"application/jsonx", false, false, false, false, false, ""},
		{"application/xml", false, true, false, false, true, ""},
		{"text/xml", false, true, false, false, true, ""},
		{"image/svg+xml", false, true, false, false, true, "xml"},
		{"application/x-www-form-urlencoded", false, false, true, false, true, ""},
		{"multipart/form-data", false, false, false, true, false, ""},
		{"text/plain", false, false, false, false, true, ""},
		{"text/html", false, false, false, false, true, ""},
		{"application/javascript", false, false, false, false, true, ""},
		{"application/yaml", false, false, false, false, true, ""},
		{"application/octet-stream", false, false, false, false, false, ""},
		{"image/png", false, false, false, false, false, ""},
		{"", false, false, false, false, false, ""},
	}
	for _, c := range cases {
		ct := ContentType{MediaType: c.mt}
		if ct.IsJSON() != c.json || ct.IsXML() != c.xml || ct.IsForm() != c.form || ct.IsMultipart() != c.multipart || ct.IsText() != c.text {
			t.Errorf("%q: json=%v xml=%v form=%v multipart=%v text=%v", c.mt, ct.IsJSON(), ct.IsXML(), ct.IsForm(), ct.IsMultipart(), ct.IsText())
		}
		if got := ct.Suffix(); got != c.suffix {
			t.Errorf("%q: Suffix = %q, want %q", c.mt, got, c.suffix)
		}
	}
}

func BenchmarkParseContentType(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseContentType("application/json; charset=utf-8"); err != nil {
			b.Fatal(err)
		}
	}
}
