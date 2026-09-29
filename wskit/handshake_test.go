package wskit

import (
	"net/http"
	"reflect"
	"testing"
)

func TestAcceptKey(t *testing.T) {
	// Example from RFC 6455 §1.3.
	if got := AcceptKey("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Errorf("AcceptKey = %q", got)
	}
	if got := AcceptKey(" dGhlIHNhbXBsZSBub25jZQ== "); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Errorf("AcceptKey with spaces = %q", got)
	}
	if !VerifyAccept("dGhlIHNhbXBsZSBub25jZQ==", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") || VerifyAccept("dGhlIHNhbXBsZSBub25jZQ==", "nope") {
		t.Error("VerifyAccept wrong")
	}
}

func TestIsUpgradeRequestResponse(t *testing.T) {
	h := http.Header{}
	h.Set("Upgrade", "WebSocket")
	h.Set("Connection", "keep-alive, Upgrade")
	h.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	h.Set("Sec-WebSocket-Version", "13")
	if !IsUpgradeRequest(h) {
		t.Error("valid request not recognized")
	}
	for name, mutate := range map[string]func(http.Header){
		"no upgrade":    func(h http.Header) { h.Del("Upgrade") },
		"wrong upgrade": func(h http.Header) { h.Set("Upgrade", "h2c") },
		"no connection": func(h http.Header) { h.Set("Connection", "keep-alive") },
		"no key":        func(h http.Header) { h.Set("Sec-WebSocket-Key", " ") },
		"old version":   func(h http.Header) { h.Set("Sec-WebSocket-Version", "8") },
	} {
		c := h.Clone()
		mutate(c)
		if IsUpgradeRequest(c) {
			t.Errorf("%s: recognized as upgrade", name)
		}
	}

	r := http.Header{}
	r.Set("Upgrade", "websocket")
	r.Set("Connection", "Upgrade")
	r.Set("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
	if !IsUpgradeResponse(101, r) {
		t.Error("valid response not recognized")
	}
	if IsUpgradeResponse(200, r) {
		t.Error("status 200 recognized")
	}
	r.Del("Sec-WebSocket-Accept")
	if IsUpgradeResponse(101, r) {
		t.Error("missing accept recognized")
	}

	// Any type with Get works, such as a plain function-backed getter.
	if IsUpgradeRequest(getter(func(string) string { return "" })) {
		t.Error("empty getter recognized")
	}
}

type getter func(string) string

func (g getter) Get(name string) string { return g(name) }

func TestParseExtensions(t *testing.T) {
	got := ParseExtensions(`permessage-deflate; client_max_window_bits, permessage-deflate; server_no_context_takeover; server_max_window_bits="12", x-custom,, ; ,bare`)
	want := []Extension{
		{Name: "permessage-deflate", Params: map[string]string{"client_max_window_bits": ""}},
		{Name: "permessage-deflate", Params: map[string]string{"server_no_context_takeover": "", "server_max_window_bits": "12"}},
		{Name: "x-custom"},
		{Name: "bare"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseExtensions =\n%+v\nwant\n%+v", got, want)
	}
	if ParseExtensions("") != nil || ParseExtensions(" , ; ") != nil {
		t.Error("empty header should give nil")
	}
	if s := want[1].String(); s != "permessage-deflate; server_max_window_bits=12; server_no_context_takeover" {
		t.Errorf("String = %q", s)
	}
	if s := want[2].String(); s != "x-custom" {
		t.Errorf("String = %q", s)
	}
}

func TestPermessageDeflate(t *testing.T) {
	p, ok := PermessageDeflate(ParseExtensions("permessage-deflate; server_no_context_takeover; client_max_window_bits; server_max_window_bits=10"))
	if !ok {
		t.Fatal("not ok")
	}
	if !p.ServerNoContextTakeover || p.ClientNoContextTakeover || p.ClientMaxWindowBits != 15 || p.ServerMaxWindowBits != 10 {
		t.Errorf("params = %+v", p)
	}
	if _, ok := PermessageDeflate(ParseExtensions("x-other")); ok {
		t.Error("absent extension reported ok")
	}
	if _, ok := PermessageDeflate(nil); ok {
		t.Error("nil reported ok")
	}
	for _, bad := range []string{
		"permessage-deflate; server_max_window_bits=7",
		"permessage-deflate; server_max_window_bits=16",
		"permessage-deflate; client_max_window_bits=abc",
		"permessage-deflate; client_max_window_bits=100",
		"permessage-deflate; unknown_param",
	} {
		if _, ok := PermessageDeflate(ParseExtensions(bad)); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	// First matching extension wins.
	p, ok = PermessageDeflate(ParseExtensions("permessage-deflate, permessage-deflate; server_no_context_takeover"))
	if !ok || p.ServerNoContextTakeover {
		t.Errorf("first offer not used: %+v %v", p, ok)
	}
}

func FuzzParseExtensions(f *testing.F) {
	f.Add("permessage-deflate; client_max_window_bits=15")
	f.Add(",;=\"")
	f.Fuzz(func(t *testing.T, s string) {
		exts := ParseExtensions(s)
		for _, e := range exts {
			if e.Name == "" {
				t.Fatal("empty extension name")
			}
			_ = e.String()
		}
		_, _ = PermessageDeflate(exts)
	})
}
