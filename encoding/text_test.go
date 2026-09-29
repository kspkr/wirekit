package encoding

import (
	"bytes"
	"strings"
	"testing"
)

func TestLooksLikeText(t *testing.T) {
	yes := [][]byte{
		nil,
		[]byte(""),
		[]byte("plain ascii\n"),
		[]byte("tabs\tand\r\nnewlines"),
		[]byte("unicode: héllo wörld ✓ 日本語"),
		[]byte(`{"json":true}`),
		append(bytes.Repeat([]byte("a"), 1000), 0x01, 0x02), // 0.2% control
		// Sample ends in the middle of a multi-byte rune.
		append(bytes.Repeat([]byte("a"), textSampleSize-1), []byte("日本")...),
	}
	no := [][]byte{
		{0xff, 0xfe},
		{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'},
		[]byte("has a nul\x00byte"),
		bytes.Repeat([]byte{0x01}, 100),
		append([]byte("mostly text"), bytes.Repeat([]byte{0x1b}, 10)...),
		// Invalid UTF-8 within the sample, not at its edge.
		append([]byte{0xe6, 0x97}, bytes.Repeat([]byte("a"), 100)...),
	}
	for _, b := range yes {
		if !LooksLikeText(b) {
			t.Errorf("LooksLikeText(%q...) = false", truncate(b))
		}
	}
	for _, b := range no {
		if LooksLikeText(b) {
			t.Errorf("LooksLikeText(%q...) = true", truncate(b))
		}
	}
	// Only the sample is examined: binary after 4 KiB does not matter.
	late := append(bytes.Repeat([]byte("a"), textSampleSize), bytes.Repeat([]byte{0}, 100)...)
	if !LooksLikeText(late) {
		t.Error("binary after the sample should be ignored")
	}
}

func truncate(b []byte) string {
	s := string(b)
	if len(s) > 20 {
		s = s[:20]
	}
	return s
}

func FuzzLooksLikeText(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		LooksLikeText(data)
	})
}

func BenchmarkLooksLikeText(b *testing.B) {
	data := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. ", 200))
	b.SetBytes(int64(min(len(data), textSampleSize)))
	for b.Loop() {
		LooksLikeText(data)
	}
}
