package compress

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

var plain = []byte(strings.Repeat("WireKit inspects network data. ", 200))

func encode(t testing.TB, coding string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w io.WriteCloser
	switch coding {
	case "gzip":
		w = gzip.NewWriter(&buf)
	case "zlib":
		w = zlib.NewWriter(&buf)
	case "flate":
		var err error
		if w, err = flate.NewWriter(&buf, flate.DefaultCompression); err != nil {
			t.Fatal(err)
		}
	case "br":
		w = brotli.NewWriter(&buf)
	case "zstd":
		var err error
		if w, err = zstd.NewWriter(&buf); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown coding %q", coding)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecodeEachCoding(t *testing.T) {
	cases := []struct {
		header string
		data   []byte
	}{
		{"gzip", encode(t, "gzip", plain)},
		{"x-gzip", encode(t, "gzip", plain)},
		{"GZIP", encode(t, "gzip", plain)},
		{"deflate", encode(t, "zlib", plain)},  // zlib-wrapped, per the RFC
		{"deflate", encode(t, "flate", plain)}, // raw, as many servers send
		{"br", encode(t, "br", plain)},
		{"zstd", encode(t, "zstd", plain)},
		{"identity", plain},
		{"", plain},
		{" gzip , identity", encode(t, "gzip", plain)},
	}
	for _, c := range cases {
		got, err := Decode(c.header, c.data, 0)
		if err != nil {
			t.Errorf("%q: %v", c.header, err)
			continue
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("%q: output differs (%d bytes)", c.header, len(got))
		}
	}
}

func TestDecodeStacked(t *testing.T) {
	// "gzip, br" means gzip was applied first, then br.
	data := encode(t, "br", encode(t, "gzip", plain))
	got, err := Decode("gzip, br", data, 0)
	if err != nil || !bytes.Equal(got, plain) {
		t.Errorf("stacked: %v", err)
	}
	// The wrong order fails.
	if _, err := Decode("br, gzip", data, 0); !errors.Is(err, ErrCorrupt) {
		t.Errorf("wrong order: %v", err)
	}
	three := encode(t, "zstd", encode(t, "br", encode(t, "gzip", plain)))
	if got, err := Decode("gzip, br, zstd", three, 0); err != nil || !bytes.Equal(got, plain) {
		t.Errorf("three deep: %v", err)
	}
}

func TestDecodeIdentityReturnsInput(t *testing.T) {
	got, err := Decode("identity", plain, 1)
	if err != nil || &got[0] != &plain[0] {
		t.Error("identity should return the input slice")
	}
	if got, err := Decode("", nil, 0); err != nil || got != nil {
		t.Errorf("empty = %v %v", got, err)
	}
}

func TestDecodeLimit(t *testing.T) {
	data := encode(t, "gzip", plain)
	if got, err := Decode("gzip", data, int64(len(plain))); err != nil || len(got) != len(plain) {
		t.Errorf("exact limit: %d %v", len(got), err)
	}
	if _, err := Decode("gzip", data, int64(len(plain))-1); !errors.Is(err, ErrTooLarge) {
		t.Errorf("one under: %v", err)
	}
	// A bomb: 1 MiB of zeros compresses to about a kilobyte.
	bomb := encode(t, "gzip", make([]byte, 1<<20))
	if len(bomb) > 4096 {
		t.Fatalf("bomb is %d bytes", len(bomb))
	}
	if _, err := Decode("gzip", bomb, 64<<10); !errors.Is(err, ErrTooLarge) {
		t.Errorf("bomb: %v", err)
	}
	for _, coding := range []string{"br", "zstd", "flate"} {
		header := coding
		if coding == "flate" {
			header = "deflate"
		}
		bomb := encode(t, coding, make([]byte, 1<<20))
		if _, err := Decode(header, bomb, 64<<10); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s bomb: %v", coding, err)
		}
	}
	// The streaming reader delivers exactly limit bytes before failing.
	r, err := NewReader("gzip", bytes.NewReader(bomb), 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if !errors.Is(err, ErrTooLarge) || len(out) != 1000 {
		t.Errorf("stream: %d bytes, %v", len(out), err)
	}
	if _, err := r.Read(make([]byte, 1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("after limit: %v", err)
	}
}

func TestDecodeErrors(t *testing.T) {
	for _, header := range []string{"compress", "lzma", "gzip, bogus", "sdch"} {
		_, err := Decode(header, plain, 0)
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%q: err = %v, want ErrUnsupported", header, err)
		}
	}
	garbage := []byte("this is not compressed")
	for _, header := range []string{"gzip", "deflate", "br", "zstd"} {
		_, err := Decode(header, garbage, 0)
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%q garbage: err = %v, want ErrCorrupt", header, err)
		}
	}
	// Truncated streams are corrupt.
	for _, coding := range []string{"gzip", "zlib", "br", "zstd"} {
		header := coding
		if coding == "zlib" {
			header = "deflate"
		}
		data := encode(t, coding, plain)
		_, err := Decode(header, data[:len(data)/2], 0)
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%q truncated: err = %v, want ErrCorrupt", coding, err)
		}
	}
	// gzip header errors are reported through ErrCorrupt and the original.
	_, err := Decode("gzip", garbage, 0)
	if !errors.Is(err, gzip.ErrHeader) || !strings.Contains(err.Error(), "gzip") {
		t.Errorf("gzip header error = %v", err)
	}
	// Errors from the source reader surface as corrupt data.
	boom := errors.New("boom")
	r, err := NewReader("br", iotest.ErrReader(boom), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); !errors.Is(err, boom) || !errors.Is(err, ErrCorrupt) {
		t.Errorf("source error = %v", err)
	}
	// Empty input for a coding is corrupt, not empty output, except that
	// the zstd decoder accepts an empty stream as zero frames.
	for _, header := range []string{"gzip", "deflate", "br"} {
		if _, err := Decode(header, nil, 0); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%q empty: %v", header, err)
		}
	}
	if got, err := Decode("zstd", nil, 0); err != nil || len(got) != 0 {
		t.Errorf("zstd empty: %v %v", got, err)
	}
}

func TestNewReaderStreaming(t *testing.T) {
	data := encode(t, "zstd", plain)
	r, err := NewReader("zstd", iotest.OneByteReader(bytes.NewReader(data)), 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(iotest.OneByteReader(r))
	if err != nil || !bytes.Equal(got, plain) {
		t.Errorf("streaming: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Identity streaming passes r through untouched.
	r, _ = NewReader("identity", strings.NewReader("x"), 0)
	if got, _ := io.ReadAll(r); string(got) != "x" {
		t.Error("identity stream")
	}
	if _, err := NewReader("nope", strings.NewReader("x"), 0); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unsupported: %v", err)
	}
}

func TestCodingsAndSupported(t *testing.T) {
	if got := Codings(" GZIP , identity,, br "); !reflect.DeepEqual(got, []string{"gzip", "br"}) {
		t.Errorf("Codings = %v", got)
	}
	if Codings("") != nil || Codings("identity") != nil {
		t.Error("Codings of nothing should be nil")
	}
	for _, c := range []string{"gzip", "x-gzip", "deflate", "br", "zstd", "identity", "", "GZIP", " br "} {
		if !Supported(c) {
			t.Errorf("Supported(%q) = false", c)
		}
	}
	for _, c := range []string{"compress", "lzma", "bzip2", "gzip,br"} {
		if Supported(c) {
			t.Errorf("Supported(%q) = true", c)
		}
	}
}

func TestLooksLikeZlib(t *testing.T) {
	if !looksLikeZlib([]byte{0x78, 0x9c}) || !looksLikeZlib([]byte{0x78, 0x01}) || !looksLikeZlib([]byte{0x78, 0xda}) {
		t.Error("real zlib headers rejected")
	}
	if looksLikeZlib([]byte{0x78}) || looksLikeZlib(nil) || looksLikeZlib([]byte{0x78, 0x9d}) || looksLikeZlib([]byte{0x88, 0x9c}) {
		t.Error("non-zlib accepted")
	}
}

func FuzzDecode(f *testing.F) {
	for _, c := range []string{"gzip", "zlib", "flate", "br", "zstd"} {
		f.Add(c, encode(f, c, []byte("seed")))
	}
	f.Add("gzip", []byte("garbage"))
	f.Fuzz(func(t *testing.T, header string, data []byte) {
		out, err := Decode(header, data, 1<<16)
		if err == nil && len(out) > 1<<16 {
			t.Fatalf("output of %d bytes exceeds limit", len(out))
		}
	})
}

func BenchmarkDecodeGzip(b *testing.B) {
	data := encode(b, "gzip", plain)
	b.SetBytes(int64(len(plain)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Decode("gzip", data, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeBrotli(b *testing.B) {
	data := encode(b, "br", plain)
	b.SetBytes(int64(len(plain)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Decode("br", data, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeZstd(b *testing.B) {
	data := encode(b, "zstd", plain)
	b.SetBytes(int64(len(plain)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Decode("zstd", data, 0); err != nil {
			b.Fatal(err)
		}
	}
}
