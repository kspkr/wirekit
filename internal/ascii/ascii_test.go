package ascii

import "testing"

func TestEqualFold(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"", "", true},
		{"Content-Type", "content-type", true},
		{"CONTENT-TYPE", "content-type", true},
		{"content-type", "content-typ", false},
		{"a", "b", false},
		{"é", "É", false}, // non-ASCII must match exactly
		{"K", "k", true},
		{"[", "{", false}, // 0x5B vs 0x7B differ by 0x20 but are not letters
	}
	for _, c := range cases {
		if got := EqualFold(c.a, c.b); got != c.want {
			t.Errorf("EqualFold(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestToLower(t *testing.T) {
	if got := ToLower("Content-Type"); got != "content-type" {
		t.Errorf("got %q", got)
	}
	s := "already-lower"
	if got := ToLower(s); got != s {
		t.Errorf("got %q", got)
	}
}

func TestTrimSpace(t *testing.T) {
	cases := map[string]string{
		"":          "",
		"  a  ":     "a",
		"\t a b \t": "a b",
		"   ":       "",
		"\r\n":      "\r\n", // only SP and HTAB are trimmed
	}
	for in, want := range cases {
		if got := TrimSpace(in); got != want {
			t.Errorf("TrimSpace(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsToken(t *testing.T) {
	good := []string{"GET", "Content-Type", "a", "x-custom_header.1", "!#$%&'*+-.^_`|~"}
	bad := []string{"", " ", "Content Type", "a:b", "a/b", "(a)", "é", "a\x00", "\"quoted\"", "a{b}"}
	for _, s := range good {
		if !IsToken(s) {
			t.Errorf("IsToken(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if IsToken(s) {
			t.Errorf("IsToken(%q) = true, want false", s)
		}
	}
}

func TestIsFieldVchar(t *testing.T) {
	for c := 0; c < 256; c++ {
		got := IsFieldVchar(byte(c))
		want := c == ' ' || c == '\t' || (c >= 0x21 && c != 0x7f)
		if got != want {
			t.Errorf("IsFieldVchar(%#x) = %v, want %v", c, got, want)
		}
	}
}

func BenchmarkEqualFold(b *testing.B) {
	for b.Loop() {
		EqualFold("Content-Type", "content-type")
	}
}
