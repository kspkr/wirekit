package encoding

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestDecodeHex(t *testing.T) {
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	for _, in := range []string{"deadbeef", "DEADBEEF", "0xdeadbeef", "0XDEADBEEF", "de:ad:be:ef", "DE:AD:BE:EF", "de ad be ef", "dead\nbeef", " 0xde:ad be:ef\n"} {
		got, err := DecodeHex(in)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("DecodeHex(%q) = %x, %v", in, got, err)
		}
	}
	if got, err := DecodeHex(""); err != nil || got == nil || len(got) != 0 {
		t.Errorf("empty = %v, %v", got, err)
	}
	if got, err := DecodeHex("0x"); err != nil || len(got) != 0 {
		t.Errorf("0x = %v, %v", got, err)
	}
	for _, bad := range []string{"abc", "zz", "0xg1", "12:3", "0x0x12"} {
		if _, err := DecodeHex(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("DecodeHex(%q) err = %v, want ErrInvalid", bad, err)
		}
	}
}

func TestHexDump(t *testing.T) {
	data := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n")
	got := HexDump(data, 0)
	want := "00000000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  |HTTP/1.1 200 OK.|\n" +
		"00000010  0a 43 6f 6e 74 65 6e 74  2d 54 79 70 65 3a 20 74  |.Content-Type: t|\n" +
		"00000020  65 78 74 2f 70 6c 61 69  6e 0d 0a                 |ext/plain..|\n"
	if got != want {
		t.Errorf("HexDump =\n%s\nwant\n%s", got, want)
	}
	got = HexDump(data, 16)
	if !strings.HasSuffix(got, "|HTTP/1.1 200 OK.|\n... 27 more bytes\n") || strings.Count(got, "\n") != 2 {
		t.Errorf("limited HexDump =\n%s", got)
	}
	if got := HexDump(data, len(data)); strings.Contains(got, "more bytes") {
		t.Error("exact limit reported truncation")
	}
	if got := HexDump(nil, 0); got != "" {
		t.Errorf("HexDump(nil) = %q", got)
	}
	if got := HexDump([]byte{0}, 0); got != "00000000  00                                                |.|\n" {
		t.Errorf("HexDump(one byte) = %q", got)
	}
}

func FuzzDecodeHex(f *testing.F) {
	f.Add("0xDE:AD:BE:EF")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = DecodeHex(s)
	})
}

func BenchmarkHexDump(b *testing.B) {
	data := bytes.Repeat([]byte("wirekit "), 512)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		HexDump(data, 0)
	}
}
