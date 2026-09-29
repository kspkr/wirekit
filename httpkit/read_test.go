package httpkit

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestReadRequestOriginForm(t *testing.T) {
	raw := "POST /api/items?id=7&x=y HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"content-type: application/json\r\n" +
		"Content-Length: 13\r\n" +
		"X-Trace: abc\r\n" +
		"\r\n" +
		`{"name":"go"}` +
		"GET / HTTP/1.1\r\n" // next message must be left in the reader

	br := bufio.NewReader(strings.NewReader(raw))
	req, err := ReadRequest(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.Proto != "HTTP/1.1" {
		t.Errorf("start line = %q %q", req.Method, req.Proto)
	}
	if req.URL.Path != "/api/items" || req.URL.RawQuery != "id=7&x=y" || req.URL.Host != "" {
		t.Errorf("URL = %+v", req.URL)
	}
	if req.Host != "api.example.com" {
		t.Errorf("Host = %q", req.Host)
	}
	wantHeaders := Headers{
		{"Host", "api.example.com"},
		{"content-type", "application/json"},
		{"Content-Length", "13"},
		{"X-Trace", "abc"},
	}
	if !reflect.DeepEqual(req.Headers, wantHeaders) {
		t.Errorf("Headers = %v", req.Headers)
	}
	if string(req.Body.Data) != `{"name":"go"}` || req.Body.Size != 13 || req.Body.Truncated {
		t.Errorf("Body = %+v", req.Body)
	}
	if req.Query().Get("id") != "7" || !req.ContentType().IsJSON() {
		t.Error("accessors wrong")
	}
	rest, _ := io.ReadAll(br)
	if string(rest) != "GET / HTTP/1.1\r\n" {
		t.Errorf("reader left with %q", rest)
	}
}

func TestReadRequestTargetForms(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		host     string // Host header, "" for none
		wantHost string
		wantPath string
		wantURL  string
	}{
		{"absolute", "GET http://proxy.example.com:8080/p?q=1 HTTP/1.1", "ignored.example", "proxy.example.com:8080", "/p", "http://proxy.example.com:8080/p?q=1"},
		{"connect", "CONNECT example.com:443 HTTP/1.1", "example.com:443", "example.com:443", "", "//example.com:443"},
		{"connect no host header", "CONNECT example.com:443 HTTP/1.1", "", "example.com:443", "", "//example.com:443"},
		{"asterisk", "OPTIONS * HTTP/1.1", "example.com", "example.com", "*", "*"},
		{"http/1.0 no host", "GET /x HTTP/1.0", "", "", "/x", "/x"},
	}
	for _, c := range cases {
		raw := c.line + "\r\n"
		if c.host != "" {
			raw += "Host: " + c.host + "\r\n"
		}
		raw += "\r\n"
		req, err := ParseRequest([]byte(raw))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if req.Host != c.wantHost || req.URL.Path != c.wantPath || req.URL.String() != c.wantURL {
			t.Errorf("%s: Host=%q Path=%q URL=%q", c.name, req.Host, req.URL.Path, req.URL.String())
		}
	}
}

func TestReadRequestChunkedWithTrailers(t *testing.T) {
	raw := "POST /upload HTTP/1.1\r\n" +
		"Host: h\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Trailer: X-Checksum\r\n" +
		"\r\n" +
		"5;ext=1\r\nhello\r\n" +
		"6\r\n world\r\n" +
		"0\r\n" +
		"X-Checksum: abc\r\n" +
		"x-other: 1\r\n" +
		"\r\n" +
		"NEXT"
	br := bufio.NewReader(strings.NewReader(raw))
	req, err := ReadRequest(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(req.Body.Data) != "hello world" || req.Body.Size != 11 {
		t.Errorf("Body = %+v", req.Body)
	}
	if !reflect.DeepEqual(req.Trailer, Headers{{"X-Checksum", "abc"}, {"x-other", "1"}}) {
		t.Errorf("Trailer = %v", req.Trailer)
	}
	rest, _ := io.ReadAll(br)
	if string(rest) != "NEXT" {
		t.Errorf("left %q", rest)
	}

	// Chunked with no trailers: the blank line is consumed.
	raw = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nNEXT"
	br = bufio.NewReader(strings.NewReader(raw))
	req, err = ReadRequest(br, nil)
	if err != nil || string(req.Body.Data) != "abc" || req.Trailer != nil {
		t.Fatalf("no-trailer: %+v %v", req, err)
	}
	rest, _ = io.ReadAll(br)
	if string(rest) != "NEXT" {
		t.Errorf("left %q", rest)
	}
}

func TestReadRequestNoBody(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\nHost: h\r\n\r\nleftover"))
	req, err := ReadRequest(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !req.Body.IsEmpty() {
		t.Errorf("Body = %+v", req.Body)
	}
	rest, _ := io.ReadAll(br)
	if string(rest) != "leftover" {
		t.Errorf("request without framing consumed body: %q", rest)
	}
}

func TestReadRequestLenientLineEndings(t *testing.T) {
	raw := "\r\n\r\nGET /lf HTTP/1.1\nHost: h\nX-A: 1\n\nrest"
	br := bufio.NewReader(strings.NewReader(raw))
	req, err := ReadRequest(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Path != "/lf" || len(req.Headers) != 2 || req.Headers.Get("X-A") != "1" {
		t.Errorf("req = %+v", req)
	}
	rest, _ := io.ReadAll(br)
	if string(rest) != "rest" {
		t.Errorf("left %q", rest)
	}
}

func TestReadRequestMalformed(t *testing.T) {
	cases := map[string]string{
		"obs-fold":               "GET / HTTP/1.1\r\nX-A: 1\r\n continued\r\n\r\n",
		"space before colon":     "GET / HTTP/1.1\r\nHost : h\r\n\r\n",
		"no colon":               "GET / HTTP/1.1\r\nHost h\r\n\r\n",
		"empty name":             "GET / HTTP/1.1\r\n: h\r\n\r\n",
		"name not token":         "GET / HTTP/1.1\r\nHo(st): h\r\n\r\n",
		"control in value":       "GET / HTTP/1.1\r\nX: a\x01b\r\n\r\n",
		"nul in value":           "GET / HTTP/1.1\r\nX: a\x00b\r\n\r\n",
		"method not token":       "G ET / HTTP/1.1\r\n\r\n",
		"missing target":         "GET HTTP/1.1\r\n\r\n",
		"missing version":        "GET /\r\n\r\n",
		"bad version":            "GET / HTTP/1.x\r\n\r\n",
		"lowercase http":         "GET / http/1.1\r\n\r\n",
		"target with space":      "GET /a b HTTP/1.1\r\n\r\n",
		"target with control":    "GET /a\x7fb HTTP/1.1\r\n\r\n",
		"bad target":             "GET :// HTTP/1.1\r\n\r\n",
		"connect with path":      "CONNECT example.com:443/x HTTP/1.1\r\n\r\n",
		"connect with userinfo":  "CONNECT user@example.com:443 HTTP/1.1\r\n\r\n",
		"connect control char":   "CONNECT \x00 HTTP/1.1\r\n\r\n",
		"connect empty host":     "CONNECT :443 HTTP/1.1\r\n\r\n",
		"connect bad port":       "CONNECT example.com:4x3 HTTP/1.1\r\n\r\n",
		"negative length":        "GET / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
		"non-numeric length":     "GET / HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
		"conflicting lengths":    "GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
		"te without chunked":     "GET / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
		"chunked twice":          "GET / HTTP/1.1\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n",
		"chunked not final":      "GET / HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n",
		"bad chunk size":         "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n",
		"chunk size overflow":    "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffffffff\r\n",
		"bad trailer":            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nbad trailer line\r\n\r\n",
		"absolute form bad host": "GET http://exa mple/ HTTP/1.1\r\n\r\n",
	}
	for name, raw := range cases {
		req, err := ParseRequest([]byte(raw))
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed (req=%+v)", name, err, req)
		}
	}
	// A malformed body still yields the parsed head.
	req, err := ParseRequest([]byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"))
	if !errors.Is(err, ErrMalformed) || req == nil || req.Method != "POST" {
		t.Errorf("malformed body: req=%+v err=%v", req, err)
	}
}

func TestReadRequestEmptyAndIncomplete(t *testing.T) {
	if _, err := ReadRequest(bufio.NewReader(strings.NewReader("")), nil); !errors.Is(err, io.EOF) {
		t.Errorf("empty: err = %v, want io.EOF", err)
	}
	if _, err := ReadRequest(bufio.NewReader(strings.NewReader("\r\n\r\n")), nil); !errors.Is(err, io.EOF) {
		t.Errorf("only blank lines: err = %v, want io.EOF", err)
	}
	for _, raw := range []string{"GET / HTTP/1.1", "GET / HTTP/1.1\r\n", "GET / HTTP/1.1\r\nHost: h\r\n", "GET / HTTP/1.1\r\nHost: h"} {
		req, err := ReadRequest(bufio.NewReader(strings.NewReader(raw)), nil)
		if !errors.Is(err, io.ErrUnexpectedEOF) || req != nil {
			t.Errorf("%q: req=%v err=%v, want nil, ErrUnexpectedEOF", raw, req, err)
		}
	}

	// A body that ends early is returned along with the error.
	raw := "POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc"
	req, err := ReadRequest(bufio.NewReader(strings.NewReader(raw)), nil)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v", err)
	}
	if req == nil || string(req.Body.Data) != "abc" || req.Body.Size != 3 {
		t.Errorf("partial req = %+v", req)
	}
	raw = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab"
	req, err = ReadRequest(bufio.NewReader(strings.NewReader(raw)), nil)
	if !errors.Is(err, io.ErrUnexpectedEOF) || req == nil || string(req.Body.Data) != "ab" {
		t.Errorf("partial chunked: req=%+v err=%v", req, err)
	}
	raw = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n"
	req, err = ReadRequest(bufio.NewReader(strings.NewReader(raw)), nil)
	if !errors.Is(err, io.ErrUnexpectedEOF) || req == nil {
		t.Errorf("missing trailer terminator: req=%+v err=%v", req, err)
	}
}

func TestReadRequestLimits(t *testing.T) {
	big := "GET / HTTP/1.1\r\nX-Big: " + strings.Repeat("a", 2000) + "\r\n\r\n"
	_, err := ReadRequest(bufio.NewReader(strings.NewReader(big)), &ReadOptions{MaxHeaderBytes: 1024})
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("header limit: err = %v", err)
	}
	if _, err := ReadRequest(bufio.NewReader(strings.NewReader(big)), &ReadOptions{MaxHeaderBytes: 4096}); err != nil {
		t.Errorf("within limit: %v", err)
	}
	// A single line longer than bufio's buffer is still bounded.
	huge := "GET / HTTP/1.1\r\nX-Big: " + strings.Repeat("a", 100000) + "\r\n\r\n"
	if _, err := ReadRequest(bufio.NewReader(strings.NewReader(huge)), &ReadOptions{MaxHeaderBytes: 8192}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("long line: err = %v", err)
	}
	// Many headers within the byte budget are fine; beyond it are not.
	many := "GET / HTTP/1.1\r\n" + strings.Repeat("X: y\r\n", 500) + "\r\n"
	if _, err := ReadRequest(bufio.NewReader(strings.NewReader(many)), &ReadOptions{MaxHeaderBytes: 1000}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("many headers: err = %v", err)
	}

	// Body retention limit: the rest is counted, not kept, and the stream
	// is positioned after the message.
	body := strings.Repeat("b", 5000)
	raw := "POST / HTTP/1.1\r\nContent-Length: 5000\r\n\r\n" + body + "NEXT"
	br := bufio.NewReader(strings.NewReader(raw))
	req, err := ReadRequest(br, &ReadOptions{MaxBodyBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(req.Body.Data) != 100 || req.Body.Size != 5000 || !req.Body.Truncated {
		t.Errorf("Body = len %d size %d truncated %v", len(req.Body.Data), req.Body.Size, req.Body.Truncated)
	}
	rest, _ := io.ReadAll(br)
	if string(rest) != "NEXT" {
		t.Errorf("left %q", rest)
	}
	// Default retains DefaultMaxBodyBytes; explicit max retains everything.
	req, _ = ReadRequest(bufio.NewReader(strings.NewReader(raw)), &ReadOptions{MaxBodyBytes: math.MaxInt64})
	if len(req.Body.Data) != 5000 || req.Body.Truncated {
		t.Errorf("unlimited retained %d", len(req.Body.Data))
	}
	// ParseRequest retains everything regardless of size.
	req, _ = ParseRequest([]byte(raw[:len(raw)-4]))
	if len(req.Body.Data) != 5000 {
		t.Errorf("ParseRequest retained %d", len(req.Body.Data))
	}
}

func TestReadResponse(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"Set-Cookie: a=1; Path=/\r\n" +
		"Set-Cookie: b=2\r\n" +
		"Content-Length: 5\r\n" +
		"\r\n" +
		"hello" +
		"HTTP/1.1 404 Not Found\r\n"
	br := bufio.NewReader(strings.NewReader(raw))
	resp, err := ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Proto != "HTTP/1.1" || resp.StatusCode != 200 || resp.StatusText != "OK" || resp.Status() != "200 OK" {
		t.Errorf("status = %+v", resp)
	}
	if string(resp.Body.Data) != "hello" || resp.Body.Size != 5 {
		t.Errorf("Body = %+v", resp.Body)
	}
	if sc := resp.SetCookies(); len(sc) != 2 || sc[0].Path != "/" {
		t.Errorf("SetCookies = %+v", sc)
	}
	if !resp.ContentType().IsText() {
		t.Error("ContentType wrong")
	}
	rest, _ := io.ReadAll(br)
	if string(rest) != "HTTP/1.1 404 Not Found\r\n" {
		t.Errorf("left %q", rest)
	}
}

func TestReadResponseStatusLines(t *testing.T) {
	cases := []struct {
		line       string
		code       int
		text       string
		wantErr    bool
		wantStatus string
	}{
		{"HTTP/1.1 200 OK", 200, "OK", false, "200 OK"},
		{"HTTP/1.1 404 Not Found", 404, "Not Found", false, "404 Not Found"},
		{"HTTP/1.1 204", 204, "", false, "204 No Content"},
		{"HTTP/1.1 204 ", 204, "", false, "204 No Content"},
		{"HTTP/1.0 599 Custom  Reason", 599, "Custom  Reason", false, "599 Custom  Reason"},
		{"HTTP/1.1 999", 999, "", false, "999"},
		{"HTTP/1.1 2000 OK", 0, "", true, ""},
		{"HTTP/1.1 20 OK", 0, "", true, ""},
		{"HTTP/1.1 099 OK", 0, "", true, ""},
		{"HTTP/1.1 abc OK", 0, "", true, ""},
		{"HTTP/1.1", 0, "", true, ""},
		{"200 OK", 0, "", true, ""},
		{"HTTP/1.1 200 bad\x01reason", 0, "", true, ""},
	}
	for _, c := range cases {
		resp, err := ParseResponse([]byte(c.line+"\r\n\r\n"), "")
		if c.wantErr {
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("%q: err = %v, want ErrMalformed", c.line, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.line, err)
			continue
		}
		if resp.StatusCode != c.code || resp.StatusText != c.text || resp.Status() != c.wantStatus {
			t.Errorf("%q: %d %q %q", c.line, resp.StatusCode, resp.StatusText, resp.Status())
		}
	}
}

func TestReadResponseBodyRules(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		method   string
		wantBody string
		wantRest string
	}{
		{"no framing reads to EOF", "HTTP/1.1 200 OK\r\n\r\nall of this", "", "all of this", ""},
		{"204 has no body", "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\nhello", "", "", "hello"},
		{"304 has no body", "HTTP/1.1 304 Not Modified\r\n\r\nhello", "", "", "hello"},
		{"1xx has no body", "HTTP/1.1 100 Continue\r\n\r\nhello", "", "", "hello"},
		{"HEAD has no body", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", "HEAD", "", "hello"},
		{"CONNECT 2xx has no body", "HTTP/1.1 200 Connection Established\r\n\r\ntunnel bytes", "CONNECT", "", "tunnel bytes"},
		{"CONNECT 4xx has body", "HTTP/1.1 403 Forbidden\r\nContent-Length: 3\r\n\r\nno!", "CONNECT", "no!", ""},
		{"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n0\r\n\r\nrest", "GET", "wiki", "rest"},
		{"zero length", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nrest", "GET", "", "rest"},
	}
	for _, c := range cases {
		br := bufio.NewReader(strings.NewReader(c.raw))
		resp, err := ReadResponse(br, &ReadOptions{RequestMethod: c.method})
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		rest, _ := io.ReadAll(br)
		if string(resp.Body.Data) != c.wantBody || string(rest) != c.wantRest {
			t.Errorf("%s: body=%q rest=%q", c.name, resp.Body.Data, rest)
		}
	}

	// Content-Length body cut short.
	resp, err := ParseResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"), "")
	if !errors.Is(err, io.ErrUnexpectedEOF) || resp == nil || string(resp.Body.Data) != "abc" {
		t.Errorf("short body: resp=%+v err=%v", resp, err)
	}
}

func TestReadHeadersAndParseHeaders(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("A: 1\r\nb:2\r\n\r\nrest"))
	hs, err := ReadHeaders(br, 0)
	if err != nil || !reflect.DeepEqual(hs, Headers{{"A", "1"}, {"b", "2"}}) {
		t.Errorf("ReadHeaders = %v, %v", hs, err)
	}
	rest, _ := io.ReadAll(br)
	if string(rest) != "rest" {
		t.Errorf("left %q", rest)
	}
	if _, err := ReadHeaders(bufio.NewReader(strings.NewReader("A: 1\r\n")), 0); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("unterminated: %v", err)
	}
	if _, err := ReadHeaders(bufio.NewReader(strings.NewReader("A: 1\r\n\r\n")), 3); !errors.Is(err, ErrTooLarge) {
		t.Errorf("limit: %v", err)
	}

	for _, in := range []string{"A: 1\r\nB: 2", "A: 1\r\nB: 2\r\n", "A: 1\r\nB: 2\r\n\r\n", "A: 1\nB: 2\n\n"} {
		hs, err := ParseHeaders([]byte(in))
		if err != nil || !reflect.DeepEqual(hs, Headers{{"A", "1"}, {"B", "2"}}) {
			t.Errorf("ParseHeaders(%q) = %v, %v", in, hs, err)
		}
	}
	if hs, err := ParseHeaders(nil); err != nil || hs != nil {
		t.Errorf("ParseHeaders(nil) = %v, %v", hs, err)
	}
	if _, err := ParseHeaders([]byte("bad line")); !errors.Is(err, ErrMalformed) {
		t.Errorf("ParseHeaders(bad) = %v", err)
	}
}

func FuzzParseRequest(f *testing.F) {
	seeds := []string{
		browserRequest,
		"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nT: 1\r\n\r\n",
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
		"GET / HTTP/1.1\r\nContent-Length: 3\r\n\r\nab",
		"GET / HTTP/1.1\r\n folded\r\n\r\n",
		"\r\n\r\nGET / HTTP/1.0\n\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := ParseRequest(data)
		if err != nil {
			if req != nil {
				// A partial message must still be usable.
				var buf bytes.Buffer
				_, _ = req.WriteTo(&buf)
				_, _ = req.MarshalJSON()
			}
			return
		}
		// Anything we accept must serialize and parse back to the same message.
		var buf bytes.Buffer
		if _, err := req.WriteTo(&buf); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
		again, err := ParseRequest(buf.Bytes())
		if err != nil {
			t.Fatalf("re-parse of %q failed: %v", buf.Bytes(), err)
		}
		if again.Method != req.Method || again.URL.RequestURI() != req.URL.RequestURI() || again.Proto != req.Proto ||
			!bytes.Equal(again.Body.Data, req.Body.Data) || !reflect.DeepEqual(again.Trailer, req.Trailer) {
			t.Fatalf("round trip changed message:\n%+v\n%+v\nwire: %q", req, again, buf.Bytes())
		}
		_, _ = req.ToStd()
		_, _ = req.MarshalJSON()
	})
}

func FuzzParseResponse(f *testing.F) {
	seeds := []string{
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n0\r\n\r\n",
		"HTTP/1.1 204 No Content\r\n\r\n",
		"HTTP/1.0 200\r\n\r\nto eof",
		"HTTP/1.1 301 Moved Permanently\r\nLocation: /x\r\nSet-Cookie: a=1; Path=/\r\n\r\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		resp, err := ParseResponse(data, "GET")
		if err != nil {
			if resp != nil {
				var buf bytes.Buffer
				_, _ = resp.WriteTo(&buf)
				_, _ = resp.MarshalJSON()
			}
			return
		}
		var buf bytes.Buffer
		if _, err := resp.WriteTo(&buf); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
		again, err := ParseResponse(buf.Bytes(), "GET")
		if err != nil {
			t.Fatalf("re-parse of %q failed: %v", buf.Bytes(), err)
		}
		if again.StatusCode != resp.StatusCode || again.Proto != resp.Proto || !bytes.Equal(again.Body.Data, resp.Body.Data) {
			t.Fatalf("round trip changed message:\n%+v\n%+v", resp, again)
		}
		_ = resp.ToStd()
		_, _ = resp.MarshalJSON()
	})
}

func FuzzParseHeaders(f *testing.F) {
	f.Add([]byte("A: 1\r\nB: 2\r\n\r\n"))
	f.Add([]byte(" folded\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		hs, err := ParseHeaders(data)
		if err != nil {
			return
		}
		again, err := ParseHeaders([]byte(hs.String()))
		if err != nil || !reflect.DeepEqual(again, hs) && (len(again) != 0 || len(hs) != 0) {
			t.Fatalf("round trip: %v -> %v (%v)", hs, again, err)
		}
	})
}

func BenchmarkReadRequest(b *testing.B) {
	data := []byte(browserRequest)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	br := bufio.NewReader(nil)
	for b.Loop() {
		br.Reset(bytes.NewReader(data))
		if _, err := ReadRequest(br, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadResponse(b *testing.B) {
	data := []byte("HTTP/1.1 200 OK\r\n" +
		"Date: Wed, 21 Oct 2015 07:28:00 GMT\r\n" +
		"Content-Type: application/json; charset=utf-8\r\n" +
		"Content-Length: 27\r\n" +
		"Cache-Control: private, max-age=0\r\n" +
		"Server: gws\r\n" +
		"X-Frame-Options: SAMEORIGIN\r\n" +
		"Set-Cookie: 1P_JAR=2015-10-21-07; expires=Fri, 20-Nov-2015 07:28:00 GMT; path=/; domain=.example.com; Secure\r\n" +
		"Alt-Svc: h3=\":443\"; ma=2592000\r\n" +
		"\r\n" +
		`{"ok":true,"items":[1,2,3]}`)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	br := bufio.NewReader(nil)
	for b.Loop() {
		br.Reset(bytes.NewReader(data))
		if _, err := ReadResponse(br, nil); err != nil {
			b.Fatal(err)
		}
	}
}
