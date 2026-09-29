package tlskit

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"reflect"
	"testing"
)

// recordingConn records everything read from the wrapped connection.
type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.buf.Write(p[:n])
	return n, err
}

// captureClientHello makes a real crypto/tls client start a handshake and
// returns the raw ClientHello record(s) it sent together with what the
// server side decoded from them.
func captureClientHello(t *testing.T, cfg *tls.Config) ([]byte, *tls.ClientHelloInfo) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	rec := &recordingConn{Conn: c1}
	var info *tls.ClientHelloInfo
	stop := errors.New("stop after ClientHello")
	srv := tls.Server(rec, &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			info = chi
			return nil, stop
		},
	})
	go func() {
		cli := tls.Client(c2, cfg)
		_ = cli.Handshake() // fails once the server aborts
	}()
	if err := srv.Handshake(); err == nil || info == nil {
		t.Fatalf("server handshake did not stop at ClientHello: %v", err)
	}
	return rec.buf.Bytes(), info
}

func TestParseClientHelloFromRealClient(t *testing.T) {
	cfg := &tls.Config{
		ServerName:         "www.example.com",
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true,
	}
	raw, info := captureClientHello(t, cfg)
	if !IsClientHello(raw) {
		t.Fatal("IsClientHello = false")
	}
	h, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if h.Version != tls.VersionTLS12 || len(h.Random) != 32 || len(h.SessionID) != 32 {
		t.Errorf("version %#x random %d session %d", h.Version, len(h.Random), len(h.SessionID))
	}
	if h.ServerName != info.ServerName || h.ServerName != "www.example.com" {
		t.Errorf("ServerName = %q", h.ServerName)
	}
	if !reflect.DeepEqual(h.ALPNProtocols, info.SupportedProtos) {
		t.Errorf("ALPN = %v, want %v", h.ALPNProtocols, info.SupportedProtos)
	}
	if !reflect.DeepEqual(h.CipherSuites, info.CipherSuites) {
		t.Errorf("CipherSuites = %v, want %v", h.CipherSuites, info.CipherSuites)
	}
	if !reflect.DeepEqual(h.SupportedVersions, info.SupportedVersions) {
		t.Errorf("SupportedVersions = %v, want %v", h.SupportedVersions, info.SupportedVersions)
	}
	var curves []uint16
	for _, c := range info.SupportedCurves {
		curves = append(curves, uint16(c))
	}
	if !reflect.DeepEqual(h.SupportedGroups, curves) {
		t.Errorf("SupportedGroups = %v, want %v", h.SupportedGroups, curves)
	}
	var sigs []uint16
	for _, s := range info.SignatureSchemes {
		sigs = append(sigs, uint16(s))
	}
	if !reflect.DeepEqual(h.SignatureAlgorithms, sigs) {
		t.Errorf("SignatureAlgorithms = %v, want %v", h.SignatureAlgorithms, sigs)
	}
	if !reflect.DeepEqual(h.ECPointFormats, info.SupportedPoints) {
		t.Errorf("ECPointFormats = %v, want %v", h.ECPointFormats, info.SupportedPoints)
	}
	if !reflect.DeepEqual(h.Extensions, info.Extensions) {
		t.Errorf("Extensions = %v, want %v", h.Extensions, info.Extensions)
	}
	if !reflect.DeepEqual(h.CompressionMethods, []uint8{0}) {
		t.Errorf("CompressionMethods = %v", h.CompressionMethods)
	}
	if len(h.KeyShareGroups) == 0 || h.KeyShareGroups[0] != h.SupportedGroups[0] {
		t.Errorf("KeyShareGroups = %v (groups %v)", h.KeyShareGroups, h.SupportedGroups)
	}
	if h.HighestVersion() != tls.VersionTLS13 {
		t.Errorf("HighestVersion = %#x", h.HighestVersion())
	}
	if names := h.CipherSuiteNames(); len(names) != len(h.CipherSuites) || names[0] != tls.CipherSuiteName(h.CipherSuites[0]) {
		t.Errorf("CipherSuiteNames = %v", names)
	}
	if len(h.JA3()) != 32 {
		t.Errorf("JA3 = %q", h.JA3())
	}

	// The conversion from ClientHelloInfo agrees on everything it carries.
	from := FromClientHelloInfo(info)
	if from.ServerName != h.ServerName || !reflect.DeepEqual(from.ALPNProtocols, h.ALPNProtocols) ||
		!reflect.DeepEqual(from.CipherSuites, h.CipherSuites) || !reflect.DeepEqual(from.SupportedGroups, h.SupportedGroups) ||
		!reflect.DeepEqual(from.SignatureAlgorithms, h.SignatureAlgorithms) || !reflect.DeepEqual(from.Extensions, h.Extensions) ||
		!reflect.DeepEqual(from.ECPointFormats, h.ECPointFormats) || !reflect.DeepEqual(from.SupportedVersions, h.SupportedVersions) {
		t.Errorf("FromClientHelloInfo differs:\n%+v\n%+v", from, h)
	}
	if from.JA3() != h.JA3() {
		t.Errorf("JA3 differs: %s vs %s", from.JA3(), h.JA3())
	}
}

func TestParseClientHelloTLS12Only(t *testing.T) {
	raw, _ := captureClientHello(t, &tls.Config{MaxVersion: tls.VersionTLS12, InsecureSkipVerify: true})
	h, err := ParseClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.HighestVersion() != tls.VersionTLS12 || h.ServerName != "" || h.ALPNProtocols != nil {
		t.Errorf("tls12 hello = %+v", h)
	}
}

func TestParseClientHelloFragmented(t *testing.T) {
	raw, _ := captureClientHello(t, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
	want, err := ParseClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	body := raw[5:]
	for _, split := range []int{1, 4, 5, 40, len(body) / 2, len(body) - 1} {
		var frag []byte
		for _, part := range [][]byte{body[:split], body[split:]} {
			frag = append(frag, 0x16, 0x03, 0x01, byte(len(part)>>8), byte(len(part)))
			frag = append(frag, part...)
		}
		got, err := ParseClientHello(frag)
		if err != nil {
			t.Errorf("split %d: %v", split, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("split %d: result differs", split)
		}
	}
	// Extra records after the hello are ignored.
	extra := append(append([]byte(nil), raw...), 0x16, 0x03, 0x03, 0x00, 0x01, 0xff)
	if got, err := ParseClientHello(extra); err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("trailing record: %v", err)
	}
}

func TestParseClientHelloIncomplete(t *testing.T) {
	raw, _ := captureClientHello(t, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
	for i := range len(raw) {
		if _, err := ParseClientHello(raw[:i]); !errors.Is(err, ErrIncomplete) {
			t.Fatalf("prefix %d of %d: err = %v, want ErrIncomplete", i, len(raw), err)
		}
	}
}

// minimalHello builds a TLS 1.0-style ClientHello with no extensions.
func minimalHello(suites []uint16, comp []uint8, sessionID []byte, extra []byte) []byte {
	var body []byte
	body = append(body, 0x03, 0x01)
	body = append(body, make([]byte, 32)...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	body = append(body, byte(len(suites)*2>>8), byte(len(suites)*2))
	for _, s := range suites {
		body = append(body, byte(s>>8), byte(s))
	}
	body = append(body, byte(len(comp)))
	body = append(body, comp...)
	body = append(body, extra...)
	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func TestParseClientHelloMinimal(t *testing.T) {
	raw := minimalHello([]uint16{0x002f, 0x0035}, []uint8{0}, nil, nil)
	h, err := ParseClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.Version != tls.VersionTLS10 || !reflect.DeepEqual(h.CipherSuites, []uint16{0x2f, 0x35}) || h.SessionID != nil || h.Extensions != nil || h.HighestVersion() != tls.VersionTLS10 {
		t.Errorf("minimal = %+v", h)
	}
	if got := h.JA3String(); got != "769,47-53,,," {
		t.Errorf("JA3String = %q", got)
	}
	// An empty extensions block is fine too.
	if _, err := ParseClientHello(minimalHello([]uint16{0x2f}, []uint8{0}, nil, []byte{0, 0})); err != nil {
		t.Errorf("empty extensions: %v", err)
	}
}

func TestParseClientHelloMalformed(t *testing.T) {
	good := minimalHello([]uint16{0x2f}, []uint8{0}, []byte{1, 2, 3}, nil)
	mutate := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	cases := map[string][]byte{
		"application data record": mutate(func(b []byte) []byte { b[0] = 0x17; return b }),
		"record version 2":        mutate(func(b []byte) []byte { b[1] = 0x02; return b }),
		"zero length record":      {0x16, 0x03, 0x01, 0x00, 0x00, 0x01},
		"oversize record":         {0x16, 0x03, 0x01, 0xff, 0xff},
		"server hello":            mutate(func(b []byte) []byte { b[5] = 0x02; return b }),
		"oversize handshake":      {0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x10, 0x00, 0x00},
		"session id too long":     minimalHello([]uint16{0x2f}, []uint8{0}, make([]byte, 33), nil),
		"odd cipher suites":       mutate(func(b []byte) []byte { b[5+4+2+32+1+3+1]--; return b }), // cut to 1 byte, comp becomes 0x2f length... still malformed
		"no cipher suites":        minimalHello(nil, []uint8{0}, nil, nil),
		"no compression":          minimalHello([]uint16{0x2f}, nil, nil, nil),
		"trailing byte":           minimalHello([]uint16{0x2f}, []uint8{0}, nil, []byte{0, 0, 0xff}),
		"truncated extensions":    minimalHello([]uint16{0x2f}, []uint8{0}, nil, []byte{0, 10, 0, 0}),
		"truncated extension":     minimalHello([]uint16{0x2f}, []uint8{0}, nil, []byte{0, 4, 0, 0, 0, 9}),
		"truncated sni":           minimalHello([]uint16{0x2f}, []uint8{0}, nil, []byte{0, 7, 0, 0, 0, 3, 0, 1, 0}),
		"truncated sni list":      minimalHello([]uint16{0x2f}, []uint8{0}, nil, []byte{0, 9, 0, 0, 0, 5, 0, 3, 0, 0, 5}),
		"truncated alpn":          minimalHello([]uint16{0x2f}, []uint8{0}, nil, []byte{0, 7, 0, 16, 0, 3, 0, 1, 5}),
		"truncated key share":     minimalHello([]uint16{0x2f}, []uint8{0}, nil, []byte{0, 8, 0, 51, 0, 4, 0, 2, 0, 29}),
		"truncated groups":        minimalHello([]uint16{0x2f}, []uint8{0}, nil, []byte{0, 5, 0, 10, 0, 1, 0}),
		"truncated body":          {0x16, 0x03, 0x01, 0x00, 0x06, 0x01, 0x00, 0x00, 0x02, 0x03, 0x01},
	}
	for name, raw := range cases {
		h, err := ParseClientHello(raw)
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v (hello %+v), want ErrMalformed", name, err, h)
		}
	}
	if IsClientHello(nil) || IsClientHello([]byte{0x17, 3, 1, 0, 1, 1}) || !IsClientHello(good) {
		t.Error("IsClientHello wrong")
	}
}

func TestJA3(t *testing.T) {
	h := &ClientHello{
		Version:         0x0303,
		CipherSuites:    []uint16{0x0a0a, 4865, 4866, 0xfafa},
		Extensions:      []uint16{0x1a1a, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 0x2a2a, 21},
		SupportedGroups: []uint16{0x3a3a, 29, 23, 24},
		ECPointFormats:  []uint8{0},
	}
	want := "771,4865-4866,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
	if got := h.JA3String(); got != want {
		t.Errorf("JA3String =\n%s\nwant\n%s", got, want)
	}
	sum := md5.Sum([]byte(want))
	if got := h.JA3(); got != hex.EncodeToString(sum[:]) {
		t.Errorf("JA3 = %s", got)
	}
	if names := h.CipherSuiteNames(); names[0] != "GREASE (0x0a0a)" || names[1] != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("CipherSuiteNames = %v", names)
	}
	if (&ClientHello{}).CipherSuiteNames() != nil {
		t.Error("empty CipherSuiteNames")
	}
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0xfafa} {
		if !IsGREASE(v) {
			t.Errorf("%#x not GREASE", v)
		}
	}
	for _, v := range []uint16{0x0a0b, 0x0b0a, 0x1301, 0, 0xffff, 0x0a1a} {
		if IsGREASE(v) {
			t.Errorf("%#x GREASE", v)
		}
	}
	// GREASE-only supported versions fall back to the legacy version.
	if got := (&ClientHello{Version: 0x0303, SupportedVersions: []uint16{0x0a0a}}).HighestVersion(); got != 0x0303 {
		t.Errorf("HighestVersion = %#x", got)
	}
}

func FuzzParseClientHello(f *testing.F) {
	raw, _ := captureClientHello(&testing.T{}, &tls.Config{ServerName: "example.com", NextProtos: []string{"h2"}, InsecureSkipVerify: true})
	f.Add(raw)
	f.Add(minimalHello([]uint16{0x2f, 0x35}, []uint8{0}, []byte{1, 2, 3}, nil))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := ParseClientHello(data)
		if err != nil {
			if h != nil {
				t.Fatal("hello returned with error")
			}
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrIncomplete) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		if len(h.Random) != 32 || len(h.CipherSuites) == 0 || len(h.CompressionMethods) == 0 {
			t.Fatalf("invariants broken: %+v", h)
		}
		_ = h.JA3()
		_ = h.HighestVersion()
		_ = h.CipherSuiteNames()
	})
}

func BenchmarkParseClientHello(b *testing.B) {
	raw, _ := captureClientHello(&testing.T{}, &tls.Config{ServerName: "www.example.com", NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true})
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseClientHello(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJA3(b *testing.B) {
	raw, _ := captureClientHello(&testing.T{}, &tls.Config{ServerName: "www.example.com", InsecureSkipVerify: true})
	h, err := ParseClientHello(raw)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		h.JA3()
	}
}
