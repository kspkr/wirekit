package httpkit

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseCookies(t *testing.T) {
	cases := []struct {
		in   string
		want []Cookie
	}{
		{"", nil},
		{"a=1", []Cookie{{"a", "1"}}},
		{"a=1; b=2", []Cookie{{"a", "1"}, {"b", "2"}}},
		{"a=1;b=2;", []Cookie{{"a", "1"}, {"b", "2"}}},
		{" a = 1 ; ; b=", []Cookie{{"a", "1"}, {"b", ""}}},
		{"a=b=c", []Cookie{{"a", "b=c"}}},
		{"nameless", []Cookie{{"", "nameless"}}},
		{"=value", []Cookie{{"", "value"}}},
		{`q="quoted"`, []Cookie{{"q", `"quoted"`}}},
		{"a=1; a=2", []Cookie{{"a", "1"}, {"a", "2"}}},
	}
	for _, c := range cases {
		got := ParseCookies(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseCookies(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	if got := (Cookie{"a", "1"}).String(); got != "a=1" {
		t.Errorf("String = %q", got)
	}
	if std := (Cookie{"a", "1"}).ToStd(); std.Name != "a" || std.Value != "1" {
		t.Errorf("ToStd = %+v", std)
	}
}

func TestParseSetCookie(t *testing.T) {
	line := "sessionid=abc123; Path=/; Domain=.example.com; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=3600; Secure; HttpOnly; SameSite=Lax; Partitioned; Priority=High"
	c, err := ParseSetCookie(line)
	if err != nil {
		t.Fatal(err)
	}
	want := SetCookie{
		Name:        "sessionid",
		Value:       "abc123",
		Path:        "/",
		Domain:      ".example.com",
		Expires:     time.Date(2015, 10, 21, 7, 28, 0, 0, time.UTC),
		RawExpires:  "Wed, 21 Oct 2015 07:28:00 GMT",
		MaxAge:      3600,
		Secure:      true,
		HttpOnly:    true,
		SameSite:    SameSiteLax,
		Partitioned: true,
		Unparsed:    []string{"Priority=High"},
		Raw:         line,
	}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("got  %+v\nwant %+v", c, want)
	}
	if c.IsSession() {
		t.Error("IsSession = true")
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate = %v", err)
	}
}

func TestParseSetCookieVariants(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want SetCookie
	}{
		{"minimal", "a=1", SetCookie{Name: "a", Value: "1"}},
		{"empty value", "a=", SetCookie{Name: "a"}},
		{"empty name", "=v", SetCookie{Value: "v"}},
		{"value with equals", "a=b=c; Path=/x", SetCookie{Name: "a", Value: "b=c", Path: "/x"}},
		{"case-insensitive attrs", "a=1; PATH=/; secure; HTTPONLY; samesite=STRICT", SetCookie{Name: "a", Value: "1", Path: "/", Secure: true, HttpOnly: true, SameSite: SameSiteStrict}},
		{"samesite none", "a=1; SameSite=None", SetCookie{Name: "a", Value: "1", SameSite: SameSiteNone}},
		{"samesite bogus", "a=1; SameSite=Whatever", SetCookie{Name: "a", Value: "1", Unparsed: []string{"SameSite=Whatever"}}},
		{"max-age zero", "a=1; Max-Age=0", SetCookie{Name: "a", Value: "1", MaxAge: -1}},
		{"max-age negative", "a=1; Max-Age=-5", SetCookie{Name: "a", Value: "1", MaxAge: -1}},
		{"max-age invalid", "a=1; Max-Age=soon", SetCookie{Name: "a", Value: "1", Unparsed: []string{"Max-Age=soon"}}},
		{"max-age leading zero", "a=1; Max-Age=010", SetCookie{Name: "a", Value: "1", Unparsed: []string{"Max-Age=010"}}},
		{"max-age missing value", "a=1; Max-Age", SetCookie{Name: "a", Value: "1", Unparsed: []string{"Max-Age"}}},
		{"bad expires", "a=1; Expires=tomorrow", SetCookie{Name: "a", Value: "1", RawExpires: "tomorrow"}},
		{"netscape expires", "a=1; expires=Wed, 21-Oct-2015 07:28:00 GMT", SetCookie{Name: "a", Value: "1", Expires: time.Date(2015, 10, 21, 7, 28, 0, 0, time.UTC), RawExpires: "Wed, 21-Oct-2015 07:28:00 GMT"}},
		{"whitespace", "  a=1 ;  Path = /p ;;  ", SetCookie{Name: "a", Value: "1", Path: "/p"}},
		{"quoted value", `a="quoted"`, SetCookie{Name: "a", Value: `"quoted"`}},
	}
	for _, c := range cases {
		got, err := ParseSetCookie(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		c.want.Raw = strings.TrimSpace(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got  %+v\n want %+v", c.name, got, c.want)
		}
	}
}

func TestParseSetCookieErrors(t *testing.T) {
	for _, in := range []string{"", "   ", "noequals", "noequals; Path=/"} {
		_, err := ParseSetCookie(in)
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseSetCookie(%q) err = %v, want ErrMalformed", in, err)
		}
	}
}

func TestSetCookieString(t *testing.T) {
	c := SetCookie{
		Name: "a", Value: "1", Path: "/", Domain: "example.com",
		Expires: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		MaxAge:  60, Secure: true, HttpOnly: true, SameSite: SameSiteNone, Partitioned: true,
		Unparsed: []string{"Priority=Low"},
	}
	want := "a=1; Path=/; Domain=example.com; Expires=Wed, 02 Jan 2030 03:04:05 GMT; Max-Age=60; Secure; HttpOnly; SameSite=None; Partitioned; Priority=Low"
	if got := c.String(); got != want {
		t.Errorf("String =\n%s\nwant\n%s", got, want)
	}
	// Round trip.
	back, err := ParseSetCookie(want)
	if err != nil {
		t.Fatal(err)
	}
	back.Raw, back.RawExpires = "", ""
	if !reflect.DeepEqual(back, c) {
		t.Errorf("round trip:\n got  %+v\n want %+v", back, c)
	}

	del := SetCookie{Name: "a", MaxAge: -1}
	if got := del.String(); got != "a=; Max-Age=0" {
		t.Errorf("delete String = %q", got)
	}
	raw := SetCookie{Name: "a", Value: "1", RawExpires: "garbage"}
	if got := raw.String(); got != "a=1; Expires=garbage" {
		t.Errorf("raw expires String = %q", got)
	}
}

func TestSetCookieExpiresAt(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	exp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if _, ok := (SetCookie{Name: "a"}).ExpiresAt(now); ok {
		t.Error("session cookie has expiry")
	}
	if got, ok := (SetCookie{Name: "a", MaxAge: 60}).ExpiresAt(now); !ok || !got.Equal(now.Add(time.Minute)) {
		t.Errorf("MaxAge: %v %v", got, ok)
	}
	if got, ok := (SetCookie{Name: "a", MaxAge: -1, Expires: exp}).ExpiresAt(now); !ok || !got.Equal(now) {
		t.Errorf("MaxAge=0 should win: %v %v", got, ok)
	}
	if got, ok := (SetCookie{Name: "a", Expires: exp}).ExpiresAt(now); !ok || !got.Equal(exp) {
		t.Errorf("Expires: %v %v", got, ok)
	}
	if _, ok := (SetCookie{Name: "a", RawExpires: "bad"}).ExpiresAt(now); ok {
		t.Error("bad Expires has expiry")
	}
	if !(SetCookie{Name: "a"}).IsSession() || (SetCookie{Name: "a", RawExpires: "bad"}).IsSession() {
		t.Error("IsSession wrong")
	}
}

func TestSetCookieToStd(t *testing.T) {
	c, _ := ParseSetCookie("a=1; Path=/; SameSite=Strict; Partitioned; Secure; Foo=bar")
	std := c.ToStd()
	if std.Name != "a" || std.Path != "/" || std.SameSite != http.SameSiteStrictMode || !std.Partitioned || !std.Secure {
		t.Errorf("ToStd = %+v", std)
	}
	if !reflect.DeepEqual(std.Unparsed, []string{"Foo=bar"}) {
		t.Errorf("Unparsed = %v", std.Unparsed)
	}
	for ss, want := range map[SameSite]http.SameSite{SameSiteDefault: 0, SameSiteLax: http.SameSiteLaxMode, SameSiteNone: http.SameSiteNoneMode} {
		if got := (SetCookie{SameSite: ss}).ToStd().SameSite; got != want {
			t.Errorf("SameSite %v -> %v, want %v", ss, got, want)
		}
	}
}

func TestSetCookieValidate(t *testing.T) {
	cases := []struct {
		name string
		c    SetCookie
		want error // nil means valid
	}{
		{"ok", SetCookie{Name: "a", Value: "1"}, nil},
		{"ok quoted", SetCookie{Name: "a", Value: `"1"`}, nil},
		{"ok host prefix", SetCookie{Name: "__Host-a", Value: "1", Secure: true, Path: "/"}, nil},
		{"ok secure prefix", SetCookie{Name: "__Secure-a", Value: "1", Secure: true}, nil},
		{"ok dotted domain", SetCookie{Name: "a", Value: "1", Domain: ".example.com"}, nil},
		{"empty name", SetCookie{Value: "1"}, ErrCookieName},
		{"name not token", SetCookie{Name: "a b", Value: "1"}, ErrCookieName},
		{"value semicolon", SetCookie{Name: "a", Value: "1;2"}, ErrCookieValue},
		{"value space", SetCookie{Name: "a", Value: "1 2"}, ErrCookieValue},
		{"value comma", SetCookie{Name: "a", Value: "1,2"}, ErrCookieValue},
		{"value backslash", SetCookie{Name: "a", Value: `1\2`}, ErrCookieValue},
		{"value non-ascii", SetCookie{Name: "a", Value: "é"}, ErrCookieValue},
		{"value inner quote", SetCookie{Name: "a", Value: `1"2`}, ErrCookieValue},
		{"too long", SetCookie{Name: "a", Value: strings.Repeat("x", 4096)}, ErrCookieTooLong},
		{"bad path", SetCookie{Name: "a", Value: "1", Path: "relative"}, ErrCookiePath},
		{"bad domain", SetCookie{Name: "a", Value: "1", Domain: "exa mple.com"}, ErrCookieDomain},
		{"bad domain label", SetCookie{Name: "a", Value: "1", Domain: "-bad.com"}, ErrCookieDomain},
		{"bad domain empty label", SetCookie{Name: "a", Value: "1", Domain: "a..com"}, ErrCookieDomain},
		{"bad expires", SetCookie{Name: "a", Value: "1", RawExpires: "soon"}, ErrCookieExpires},
		{"samesite none insecure", SetCookie{Name: "a", Value: "1", SameSite: SameSiteNone}, ErrCookieSameSiteNone},
		{"partitioned insecure", SetCookie{Name: "a", Value: "1", Partitioned: true}, ErrCookiePartitioned},
		{"host prefix no secure", SetCookie{Name: "__Host-a", Value: "1", Path: "/"}, ErrCookieHostPrefix},
		{"host prefix domain", SetCookie{Name: "__Host-a", Value: "1", Secure: true, Path: "/", Domain: "x.com"}, ErrCookieHostPrefix},
		{"host prefix path", SetCookie{Name: "__Host-a", Value: "1", Secure: true, Path: "/x"}, ErrCookieHostPrefix},
		{"secure prefix", SetCookie{Name: "__Secure-a", Value: "1"}, ErrCookieSecurePrefix},
	}
	for _, c := range cases {
		err := c.c.Validate()
		if c.want == nil {
			if err != nil {
				t.Errorf("%s: Validate = %v, want nil", c.name, err)
			}
			continue
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: Validate = %v, want %v", c.name, err, c.want)
		}
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: error does not wrap ErrMalformed", c.name)
		}
	}
	// Several problems are reported together.
	err := SetCookie{Value: "a b", SameSite: SameSiteNone}.Validate()
	if !errors.Is(err, ErrCookieName) || !errors.Is(err, ErrCookieValue) || !errors.Is(err, ErrCookieSameSiteNone) {
		t.Errorf("joined error missing parts: %v", err)
	}
}

func TestParseCookieDate(t *testing.T) {
	want := time.Date(2015, 10, 21, 7, 28, 0, 0, time.UTC)
	good := []string{
		"Wed, 21 Oct 2015 07:28:00 GMT",
		"Wed, 21-Oct-2015 07:28:00 GMT",
		"Wednesday, 21-Oct-15 07:28:00 GMT",
		"Wed Oct 21 07:28:00 2015",
		"21 Oct 2015 07:28:00",
		"07:28:00 21 OCT 2015",
		"Wed, 21 Oct 2015 7:28:0 GMT",
		"Wed, 21 Oct 2015 07:28:00 +0000",
		"2015 Oct 21 07:28:00",
		"Wed,21-Oct-2015 07:28:00GMT",
		"Wed, 21 October 2015 07:28:00 GMT",
	}
	for _, s := range good {
		got, ok := ParseCookieDate(s)
		if !ok || !got.Equal(want) {
			t.Errorf("ParseCookieDate(%q) = %v, %v", s, got, ok)
		}
	}
	// Two-digit years.
	if got, _ := ParseCookieDate("Wed, 21 Oct 69 07:28:00 GMT"); got.Year() != 2069 {
		t.Errorf("69 -> %d", got.Year())
	}
	if got, _ := ParseCookieDate("Wed, 21 Oct 70 07:28:00 GMT"); got.Year() != 1970 {
		t.Errorf("70 -> %d", got.Year())
	}
	bad := []string{
		"",
		"tomorrow",
		"Wed, 21 Oct 2015",              // no time
		"Wed, 32 Oct 2015 07:28:00 GMT", // day out of range
		"Wed, 31 Feb 2015 07:28:00 GMT", // not a real date
		"Wed, 21 Oct 1600 07:28:00 GMT", // year before 1601
		"Wed, 21 Oct 2015 24:00:00 GMT",
		"Wed, 21 Oct 2015 07:60:00 GMT",
		"Wed, 21 Oct 2015 07:28:60 GMT",
		"Wed, 21 Oct 2015 07:28 GMT",
		"Wed, 21 Xyz 2015 07:28:00 GMT",
		"21 Oct 20155 07:28:00",
		"1234567 Oct 2015 07:28:00", // day token too long, no other day
	}
	for _, s := range bad {
		if got, ok := ParseCookieDate(s); ok {
			t.Errorf("ParseCookieDate(%q) = %v, want failure", s, got)
		}
	}
}

func TestSameSiteText(t *testing.T) {
	for _, ss := range []SameSite{SameSiteDefault, SameSiteLax, SameSiteStrict, SameSiteNone} {
		b, err := ss.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var back SameSite
		if err := back.UnmarshalText(b); err != nil || back != ss {
			t.Errorf("%v: round trip -> %v, %v", ss, back, err)
		}
	}
	var s SameSite
	if err := s.UnmarshalText([]byte("bogus")); err == nil {
		t.Error("UnmarshalText(bogus) succeeded")
	}
}

func FuzzParseSetCookie(f *testing.F) {
	for _, s := range []string{
		"a=1", "sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
		"a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=0", "=; ;;", "x",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		c, err := ParseSetCookie(line)
		if err != nil {
			return
		}
		_ = c.Validate()
		_ = c.ToStd()
		_, _ = c.ExpiresAt(time.Now())
		// Serializing and re-parsing must be stable.
		again, err := ParseSetCookie(c.String())
		if err != nil {
			t.Fatalf("re-parse of %q failed: %v", c.String(), err)
		}
		if again.Name != c.Name || again.Value != c.Value || again.Path != c.Path || again.Domain != c.Domain ||
			again.MaxAge != c.MaxAge || again.Secure != c.Secure || again.HttpOnly != c.HttpOnly ||
			again.SameSite != c.SameSite || again.Partitioned != c.Partitioned {
			t.Fatalf("round trip changed cookie:\n%+v\n%+v", c, again)
		}
	})
}

func FuzzParseCookies(f *testing.F) {
	f.Add("a=1; b=2")
	f.Add("=;;=")
	f.Fuzz(func(t *testing.T, s string) {
		for _, c := range ParseCookies(s) {
			_ = c.String()
		}
	})
}

func FuzzParseCookieDate(f *testing.F) {
	f.Add("Wed, 21 Oct 2015 07:28:00 GMT")
	f.Add("99:99:99 99 Xxx 99999")
	f.Fuzz(func(t *testing.T, s string) {
		if got, ok := ParseCookieDate(s); ok && (got.Year() < 1601 || got.Location() != time.UTC) {
			t.Fatalf("bad result %v for %q", got, s)
		}
	})
}

func BenchmarkParseSetCookie(b *testing.B) {
	line := "sessionid=abcdefghijklmnopqrstuvwxyz; Path=/; Domain=.example.com; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Secure; HttpOnly; SameSite=Lax"
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseSetCookie(line); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseCookies(b *testing.B) {
	line := "SID=abcdefghijklmnopqrstuvwxyz0123456789; HSID=abcdefghijklmnopqrst; SSID=abcdefghijklmnop; NID=511=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; _ga=GA1.2.123456789.1234567890"
	b.ReportAllocs()
	for b.Loop() {
		ParseCookies(line)
	}
}

func BenchmarkParseCookieDate(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ParseCookieDate("Wed, 21 Oct 2015 07:28:00 GMT")
	}
}
