package httpkit

import (
	"bytes"
	"net/url"
	"testing"
)

func TestRequestWriteHead(t *testing.T) {
	req := &Request{
		Method:  "GET",
		URL:     &url.URL{Scheme: "https", Host: "example.com", Path: "/a b", RawQuery: "x=1"},
		Host:    "example.com",
		Headers: Headers{{"accept", "*/*"}},
	}
	var buf bytes.Buffer
	if err := req.WriteHead(&buf); err != nil {
		t.Fatal(err)
	}
	want := "GET /a%20b?x=1 HTTP/1.1\r\nHost: example.com\r\naccept: */*\r\n\r\n"
	if buf.String() != want {
		t.Errorf("got  %q\nwant %q", buf.String(), want)
	}

	// Existing Host header is left alone; Proto is written as held.
	req.Headers = Headers{{"host", "other"}}
	req.Proto = "HTTP/1.0"
	buf.Reset()
	req.WriteHead(&buf)
	if want := "GET /a%20b?x=1 HTTP/1.0\r\nhost: other\r\n\r\n"; buf.String() != want {
		t.Errorf("got %q", buf.String())
	}

	// CONNECT writes authority-form.
	c := &Request{Method: "CONNECT", URL: &url.URL{Host: "example.com:443"}, Host: "example.com:443"}
	buf.Reset()
	c.WriteHead(&buf)
	if want := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"; buf.String() != want {
		t.Errorf("CONNECT got %q", buf.String())
	}

	// Empty path becomes "/", asterisk stays.
	e := &Request{Method: "GET", URL: &url.URL{Host: "h"}}
	buf.Reset()
	e.WriteHead(&buf)
	if !bytes.HasPrefix(buf.Bytes(), []byte("GET / HTTP/1.1\r\n")) {
		t.Errorf("empty path got %q", buf.String())
	}
	o := &Request{Method: "OPTIONS", URL: &url.URL{Path: "*"}}
	buf.Reset()
	o.WriteHead(&buf)
	if !bytes.HasPrefix(buf.Bytes(), []byte("OPTIONS * HTTP/1.1\r\n")) {
		t.Errorf("asterisk got %q", buf.String())
	}

	if err := (&Request{Method: "GET"}).WriteHead(&buf); err == nil {
		t.Error("nil URL did not fail")
	}
}

func TestRequestWriteTo(t *testing.T) {
	req := &Request{
		Method:  "POST",
		URL:     &url.URL{Path: "/"},
		Headers: Headers{{"Content-Length", "3"}},
		Body:    BodyOf([]byte("abc")),
	}
	var buf bytes.Buffer
	n, err := req.WriteTo(&buf)
	if err != nil {
		t.Fatal(err)
	}
	want := "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"
	if buf.String() != want || n != int64(len(want)) {
		t.Errorf("got %q (%d)", buf.String(), n)
	}

	// Chunked headers re-chunk the body and append trailers.
	req.Headers = Headers{{"Transfer-Encoding", "chunked"}}
	req.Trailer = Headers{{"X-Sum", "1"}}
	buf.Reset()
	req.WriteTo(&buf)
	want = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Sum: 1\r\n\r\n"
	if buf.String() != want {
		t.Errorf("chunked got %q", buf.String())
	}
	back, err := ParseRequest(buf.Bytes())
	if err != nil || string(back.Body.Data) != "abc" || back.Trailer.Get("X-Sum") != "1" {
		t.Errorf("re-parse = %+v, %v", back, err)
	}

	// Empty chunked body still terminates properly.
	req.Body = Body{}
	req.Trailer = nil
	buf.Reset()
	req.WriteTo(&buf)
	if want := "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"; buf.String() != want {
		t.Errorf("empty chunked got %q", buf.String())
	}
}

func TestResponseWrite(t *testing.T) {
	resp := &Response{StatusCode: 404, Headers: Headers{{"Content-Length", "0"}}}
	var buf bytes.Buffer
	if err := resp.WriteHead(&buf); err != nil {
		t.Fatal(err)
	}
	if want := "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"; buf.String() != want {
		t.Errorf("got %q", buf.String())
	}

	resp = &Response{Proto: "HTTP/1.0", StatusCode: 200, StatusText: "Fine", Body: BodyOf([]byte("hi"))}
	buf.Reset()
	n, err := resp.WriteTo(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if want := "HTTP/1.0 200 Fine\r\n\r\nhi"; buf.String() != want || n != int64(len(want)) {
		t.Errorf("got %q (%d)", buf.String(), n)
	}

	// Unknown status without text writes an empty reason.
	resp = &Response{StatusCode: 799}
	buf.Reset()
	resp.WriteHead(&buf)
	if want := "HTTP/1.1 799 \r\n\r\n"; buf.String() != want {
		t.Errorf("got %q", buf.String())
	}
	if _, err := ParseResponse(buf.Bytes(), ""); err != nil {
		t.Errorf("re-parse: %v", err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errTest }

var errTest = &malformedError{"test"}

func TestWriteErrors(t *testing.T) {
	req := &Request{Method: "GET", URL: &url.URL{Path: "/"}, Body: BodyOf([]byte("x"))}
	if _, err := req.WriteTo(failWriter{}); err == nil {
		t.Error("WriteTo to failing writer succeeded")
	}
	resp := &Response{StatusCode: 200, Headers: Headers{{"Transfer-Encoding", "chunked"}}, Body: BodyOf([]byte("x"))}
	if _, err := resp.WriteTo(failWriter{}); err == nil {
		t.Error("chunked WriteTo to failing writer succeeded")
	}
}

func BenchmarkRequestWriteTo(b *testing.B) {
	req, err := ParseRequest([]byte(browserRequest))
	if err != nil {
		b.Fatal(err)
	}
	var buf bytes.Buffer
	b.ReportAllocs()
	for b.Loop() {
		buf.Reset()
		if _, err := req.WriteTo(&buf); err != nil {
			b.Fatal(err)
		}
	}
	b.SetBytes(int64(buf.Len()))
}
