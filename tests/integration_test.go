// Package tests holds tests that cross package boundaries: realistic flows
// that combine several WireKit packages the way an application would, and
// a hostile-input sweep over every parser.
package tests

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kspkr/wirekit/compress"
	"github.com/kspkr/wirekit/encoding"
	"github.com/kspkr/wirekit/httpkit"
	"github.com/kspkr/wirekit/wskit"
)

// TestCompressedJSONResponse follows a captured response from wire bytes to
// a JSON summary: parse, decode the content coding, inspect the JSON.
func TestCompressedJSONResponse(t *testing.T) {
	payload := `{"users":[{"id":1,"name":"Ada"},{"id":2,"name":"Linus"}],"total":2}`
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte(payload))
	w.Close()

	var wire bytes.Buffer
	resp := &httpkit.Response{
		Proto:      "HTTP/1.1",
		StatusCode: 200,
		Headers: httpkit.Headers{
			{Name: "Content-Type", Value: "application/json; charset=utf-8"},
			{Name: "Content-Encoding", Value: "gzip"},
			{Name: "Transfer-Encoding", Value: "chunked"},
			{Name: "Set-Cookie", Value: "sid=1; Path=/; Secure; HttpOnly; SameSite=None"},
		},
		Body: httpkit.BodyOf(gz.Bytes()),
	}
	if _, err := resp.WriteTo(&wire); err != nil {
		t.Fatal(err)
	}

	parsed, err := httpkit.ReadResponse(bufio.NewReader(&wire), &httpkit.ReadOptions{RequestMethod: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.ContentType().IsJSON() || parsed.ContentType().Charset() != "utf-8" {
		t.Errorf("content type = %+v", parsed.ContentType())
	}
	if !bytes.Equal(parsed.Body.Data, gz.Bytes()) {
		t.Error("chunked body did not round-trip")
	}
	decoded, err := compress.Decode(parsed.Headers.Get("Content-Encoding"), parsed.Body.Data, 1<<20)
	if err != nil || string(decoded) != payload {
		t.Fatalf("decode: %q %v", decoded, err)
	}
	info, err := encoding.InspectJSON(decoded)
	if err != nil || info.Kind != encoding.JSONObject || info.Objects != 3 || info.Keys != 6 {
		t.Errorf("json info = %+v %v", info, err)
	}
	cookies := parsed.SetCookies()
	if len(cookies) != 1 || cookies[0].Validate() != nil {
		t.Errorf("cookies = %+v", cookies)
	}
}

// TestWebSocketHandshakeAndFrames drives a WebSocket connection with
// net/http and a tiny hand-rolled server, using wskit for the protocol.
func TestWebSocketHandshakeAndFrames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hs := httpkit.FromRequest(r).Headers
		// A server-side request has no Host header in the map; that is fine
		// for the handshake check.
		if !wskit.IsUpgradeRequest(hs) || hs.UpgradeProtocol() != "websocket" {
			http.Error(w, "not a websocket handshake", http.StatusBadRequest)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		resp := &httpkit.Response{
			StatusCode: http.StatusSwitchingProtocols,
			Headers: httpkit.Headers{
				{Name: "Upgrade", Value: "websocket"},
				{Name: "Connection", Value: "Upgrade"},
				{Name: "Sec-WebSocket-Accept", Value: wskit.AcceptKey(hs.Get("Sec-WebSocket-Key"))},
			},
		}
		if err := resp.WriteHead(brw); err != nil {
			t.Error(err)
			return
		}
		brw.Flush()

		// Echo one message, then close.
		r2 := wskit.NewReader(brw.Reader, 1<<20)
		var asm wskit.Assembler
		for {
			f, err := r2.ReadFrame()
			if err != nil {
				return
			}
			if err := f.ValidateDirection(true); err != nil {
				t.Errorf("client frame invalid: %v", err)
			}
			m, err := asm.Push(f)
			if err != nil {
				t.Error(err)
				return
			}
			if m == nil || m.Type != wskit.OpText {
				continue
			}
			echo := wskit.Frame{FIN: true, Opcode: wskit.OpText, Payload: m.Data}
			closeF := wskit.Frame{FIN: true, Opcode: wskit.OpClose, Payload: wskit.ClosePayload(wskit.CloseNormal, "done")}
			conn.Write(echo.Bytes())
			conn.Write(closeF.Bytes())
			return
		}
	}))
	defer srv.Close()

	// Client handshake with net/http primitives.
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !wskit.IsUpgradeResponse(resp.StatusCode, resp.Header) || !wskit.VerifyAccept("dGhlIHNhbXBsZSBub25jZQ==", resp.Header.Get("Sec-WebSocket-Accept")) {
		t.Fatalf("handshake failed: %d %v", resp.StatusCode, resp.Header)
	}
	rwc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatal("response body is not writable")
	}

	// Send a fragmented, masked text message.
	key := [4]byte{1, 2, 3, 4}
	rwc.Write((&wskit.Frame{Opcode: wskit.OpText, Masked: true, MaskKey: key, Payload: []byte("hello, ")}).Bytes())
	rwc.Write((&wskit.Frame{FIN: true, Opcode: wskit.OpContinuation, Masked: true, MaskKey: key, Payload: []byte("wirekit")}).Bytes())

	r := wskit.NewReader(rwc, 1<<20)
	var asm wskit.Assembler
	var got []string
	for {
		f, err := r.ReadFrame()
		if err != nil {
			break
		}
		if err := f.ValidateDirection(false); err != nil {
			t.Errorf("server frame invalid: %v", err)
		}
		m, _ := asm.Push(f)
		if m == nil {
			continue
		}
		if m.Type == wskit.OpClose {
			code, reason, err := m.CloseInfo()
			if err != nil || code != wskit.CloseNormal || reason != "done" {
				t.Errorf("close = %v %q %v", code, reason, err)
			}
			break
		}
		got = append(got, string(m.Data))
	}
	if len(got) != 1 || got[0] != "hello, wirekit" {
		t.Errorf("echo = %q", got)
	}
}

// TestModelRoundTripsThroughJSON checks that the message model survives
// serialization, which is how a traffic tool would store it.
func TestModelRoundTripsThroughJSON(t *testing.T) {
	raw := "PUT /things/1?v=2 HTTP/1.1\r\nHost: h\r\nx-a: 1\r\nX-A: 2\r\nContent-Length: 3\r\n\r\nabc"
	req, err := httpkit.ParseRequest([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var back httpkit.Request
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	back.WriteTo(&out)
	if out.String() != raw {
		t.Errorf("round trip:\n%q\n%q", out.String(), raw)
	}
}

// TestStdInterop checks that WireKit values move to and from net/http.
func TestStdInterop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := httpkit.FromRequest(r)
		if req.Query().Get("q") != "wire kit" || req.Cookies()[0].Value != "1" {
			http.Error(w, "bad request", 400)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	wreq := &httpkit.Request{Method: "GET", Headers: httpkit.Headers{{Name: "Cookie", Value: "a=1"}}}
	wreq.URL, _ = wreq.URL.Parse(srv.URL + "/?q=wire+kit")
	std, err := wreq.ToStd()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(std)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	wresp := httpkit.FromResponse(resp)
	if wresp.StatusCode != 200 || !wresp.ContentType().IsText() {
		t.Errorf("response = %+v", wresp)
	}
	c := httpkit.NewCapture(1)
	io.Copy(io.Discard, c.TeeReader(resp.Body))
	wresp.Body = c.Body()
	if wresp.Body.Size != 2 || string(wresp.Body.Data) != "o" || !wresp.Body.Truncated {
		t.Errorf("body = %+v", wresp.Body)
	}
}

func TestErrorsAreClassified(t *testing.T) {
	_, err := httpkit.ParseRequest([]byte("GARBAGE\r\n\r\n"))
	if !errors.Is(err, httpkit.ErrMalformed) {
		t.Errorf("httpkit: %v", err)
	}
	_, _, err = wskit.ParseFrame([]byte{0x81})
	if !errors.Is(err, wskit.ErrIncomplete) {
		t.Errorf("wskit: %v", err)
	}
	_, err = compress.Decode("gzip", []byte("nope"), 0)
	if !errors.Is(err, compress.ErrCorrupt) {
		t.Errorf("compress: %v", err)
	}
	_, err = encoding.DecodeHex("xyz")
	if !errors.Is(err, encoding.ErrInvalid) {
		t.Errorf("encoding: %v", err)
	}
	_, err = httpkit.ReadRequest(bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\nX: "+strings.Repeat("a", 100)+"\r\n\r\n")), &httpkit.ReadOptions{MaxHeaderBytes: 50})
	if !errors.Is(err, httpkit.ErrTooLarge) {
		t.Errorf("limit: %v", err)
	}
}
