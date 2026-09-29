package encoding

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func TestDecodeBase64(t *testing.T) {
	want := []byte{0xfb, 0xff, 0xbf, 0x00, 'h', 'i'} // encodes with both + and / in std
	std := base64.StdEncoding.EncodeToString(want)   // "+/+/AGhp"
	cases := []struct {
		name string
		in   string
	}{
		{"standard padded", std},
		{"standard unpadded", base64.RawStdEncoding.EncodeToString(want)},
		{"url padded", base64.URLEncoding.EncodeToString(want)},
		{"url unpadded", base64.RawURLEncoding.EncodeToString(want)},
		{"whitespace", " +/+/\nAGhp \r\n"},
		{"wrapped", "+/+/\nAGhp\n"},
	}
	for _, c := range cases {
		got, err := DecodeBase64(c.in)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: DecodeBase64(%q) = %x, %v", c.name, c.in, got, err)
		}
	}
	// Padding variants of a short input.
	for _, in := range []string{"aGk=", "aGk", "aGk==", "aGk===="} {
		if got, err := DecodeBase64(in); err != nil || string(got) != "hi" {
			t.Errorf("DecodeBase64(%q) = %q, %v", in, got, err)
		}
	}
	if got, err := DecodeBase64(""); err != nil || got == nil || len(got) != 0 {
		t.Errorf("empty = %v, %v", got, err)
	}
	if got, err := DecodeBase64("  \n"); err != nil || len(got) != 0 {
		t.Errorf("whitespace only = %v, %v", got, err)
	}

	for _, bad := range []string{"+/-_", "a", "abc$", "=abc", "a=bc", "ab=c", "é"} {
		if _, err := DecodeBase64(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("DecodeBase64(%q) err = %v, want ErrInvalid", bad, err)
		}
	}
}

func FuzzDecodeBase64(f *testing.F) {
	f.Add("aGVsbG8gd29ybGQ=")
	f.Add("aGVsbG8gd29ybGQ")
	f.Add("-_-_")
	f.Fuzz(func(t *testing.T, s string) {
		out, err := DecodeBase64(s)
		if err != nil {
			return
		}
		// Anything we accept must re-encode to something we decode to the
		// same bytes.
		again, err := DecodeBase64(base64.StdEncoding.EncodeToString(out))
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("round trip failed for %q: %v", s, err)
		}
	})
}

func BenchmarkDecodeBase64(b *testing.B) {
	s := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("wirekit "), 128))
	b.SetBytes(int64(len(s)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodeBase64(s); err != nil {
			b.Fatal(err)
		}
	}
}
