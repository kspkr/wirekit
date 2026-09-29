package tests

import (
	"bufio"
	"bytes"
	"math/rand/v2"
	"testing"

	"github.com/kspkr/wirekit/compress"
	"github.com/kspkr/wirekit/encoding"
	"github.com/kspkr/wirekit/httpkit"
	"github.com/kspkr/wirekit/tlskit"
	"github.com/kspkr/wirekit/wskit"
)

// parsers lists every entry point that takes untrusted bytes. The hostile
// sweep feeds each of them the same corpus; none may panic.
var parsers = map[string]func([]byte){
	"httpkit.ParseRequest":  func(b []byte) { _, _ = httpkit.ParseRequest(b) },
	"httpkit.ParseResponse": func(b []byte) { _, _ = httpkit.ParseResponse(b, "GET") },
	"httpkit.ParseHeaders":  func(b []byte) { _, _ = httpkit.ParseHeaders(b) },
	"httpkit.ReadRequest": func(b []byte) {
		_, _ = httpkit.ReadRequest(bufio.NewReader(bytes.NewReader(b)), &httpkit.ReadOptions{MaxHeaderBytes: 256, MaxBodyBytes: 64})
	},
	"httpkit.ParseCookies":    func(b []byte) { httpkit.ParseCookies(string(b)) },
	"httpkit.ParseSetCookie":  func(b []byte) { _, _ = httpkit.ParseSetCookie(string(b)) },
	"httpkit.ParseCookieDate": func(b []byte) { httpkit.ParseCookieDate(string(b)) },
	"httpkit.ParseQuery":      func(b []byte) { _, _ = httpkit.ParseQuery(string(b)) },
	"httpkit.ParseContentType": func(b []byte) {
		_, _ = httpkit.ParseContentType(string(b))
	},
	"wskit.ParseFrame": func(b []byte) {
		f, _, err := wskit.ParseFrame(b)
		if err == nil {
			_ = f.Validate()
		}
	},
	"wskit.Reader": func(b []byte) {
		r := wskit.NewReader(bytes.NewReader(b), 1024)
		var a wskit.Assembler
		for {
			f, err := r.ReadFrame()
			if err != nil {
				return
			}
			_, _ = a.Push(f)
		}
	},
	"wskit.ParseClosePayload": func(b []byte) { _, _, _ = wskit.ParseClosePayload(b) },
	"wskit.ParseExtensions":   func(b []byte) { wskit.ParseExtensions(string(b)) },
	"tlskit.ParseClientHello": func(b []byte) { _, _ = tlskit.ParseClientHello(b) },
	"tlskit.ParseCertificates": func(b []byte) {
		if certs, err := tlskit.ParseCertificates(b); err == nil {
			tlskit.InspectCertificates(certs)
		}
	},
	"encoding.DecodeBase64":   func(b []byte) { _, _ = encoding.DecodeBase64(string(b)) },
	"encoding.DecodeHex":      func(b []byte) { _, _ = encoding.DecodeHex(string(b)) },
	"encoding.InspectJSON":    func(b []byte) { _, _ = encoding.InspectJSON(b) },
	"encoding.LooksLikeText":  func(b []byte) { encoding.LooksLikeText(b) },
	"encoding.HexDump":        func(b []byte) { encoding.HexDump(b, 64) },
	"compress.Decode gzip":    func(b []byte) { _, _ = compress.Decode("gzip", b, 4096) },
	"compress.Decode deflate": func(b []byte) { _, _ = compress.Decode("deflate", b, 4096) },
	"compress.Decode br":      func(b []byte) { _, _ = compress.Decode("br", b, 4096) },
	"compress.Decode zstd":    func(b []byte) { _, _ = compress.Decode("zstd", b, 4096) },
}

// corpus produces deterministic hostile inputs: random bytes, random
// printable text, and mutated copies of valid messages.
func corpus() [][]byte {
	rng := rand.New(rand.NewPCG(0xC0FFEE, 0xBEEF))
	seeds := [][]byte{
		[]byte("GET /path?q=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello"),
		[]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
		[]byte("a=1; Path=/; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Secure"),
		{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58},
		{0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b, 0x03, 0x03},
		[]byte(`{"a":[1,2,{"b":null}],"c":"d"}`),
		{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
		{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x58},
		{0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
	out := [][]byte{nil, {}}
	out = append(out, seeds...)
	for range 200 {
		n := rng.IntN(300)
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(rng.IntN(256))
		}
		out = append(out, b)
	}
	for range 200 {
		n := rng.IntN(300)
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(32 + rng.IntN(95))
		}
		out = append(out, b)
	}
	for _, s := range seeds {
		for range 50 {
			m := append([]byte(nil), s...)
			for range 1 + rng.IntN(4) {
				switch rng.IntN(4) {
				case 0:
					if len(m) > 0 {
						m[rng.IntN(len(m))] = byte(rng.IntN(256))
					}
				case 1:
					if len(m) > 1 {
						m = m[:rng.IntN(len(m))]
					}
				case 2:
					i := rng.IntN(len(m) + 1)
					m = append(m[:i], append([]byte{byte(rng.IntN(256))}, m[i:]...)...)
				case 3:
					if len(m) > 0 {
						m[rng.IntN(len(m))] = 0xff
					}
				}
			}
			out = append(out, m)
		}
	}
	// Length fields that promise far more than is present.
	out = append(out,
		[]byte("POST / HTTP/1.1\r\nContent-Length: 9223372036854775807\r\n\r\nx"),
		[]byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\n"),
		[]byte{0x82, 127, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		[]byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01},
		[]byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0xff, 0xff, 0xff},
		bytes.Repeat([]byte("["), 100000),
		bytes.Repeat([]byte("{\"a\":"), 20000),
	)
	return out
}

func TestParsersNeverPanic(t *testing.T) {
	inputs := corpus()
	for name, parse := range parsers {
		t.Run(name, func(t *testing.T) {
			for i, in := range inputs {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("input %d (%d bytes) panicked: %v\n%q", i, len(in), r, truncate(in))
						}
					}()
					parse(in)
				}()
			}
		})
	}
}

func truncate(b []byte) []byte {
	if len(b) > 80 {
		return b[:80]
	}
	return b
}
