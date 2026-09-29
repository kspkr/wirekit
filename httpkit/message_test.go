package httpkit

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestRequestJSON(t *testing.T) {
	req, err := ParseRequest([]byte("POST /p?a=1 HTTP/1.1\r\nHost: h\r\nX: y\r\nContent-Length: 2\r\n\r\nhi"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"method":"POST","url":"/p?a=1","proto":"HTTP/1.1","host":"h","headers":[{"name":"Host","value":"h"},{"name":"X","value":"y"},{"name":"Content-Length","value":"2"}],"body":{"data":"aGk=","size":2}}`
	if string(data) != want {
		t.Errorf("JSON =\n%s\nwant\n%s", data, want)
	}
	var back Request
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&back, req) {
		t.Errorf("round trip:\n%+v\n%+v", back, *req)
	}

	// Value receiver: marshalling a non-pointer works too, nil URL and
	// headers produce "" and [].
	data, _ = json.Marshal(Request{Method: "GET"})
	if string(data) != `{"method":"GET","url":"","headers":[],"body":{"size":0}}` {
		t.Errorf("minimal JSON = %s", data)
	}
	var empty Request
	if err := json.Unmarshal(data, &empty); err != nil || empty.URL != nil {
		t.Errorf("unmarshal minimal: %+v %v", empty, err)
	}
	if err := json.Unmarshal([]byte(`{"url":"://bad"}`), &empty); err == nil {
		t.Error("bad URL accepted")
	}
	if err := json.Unmarshal([]byte(`[]`), &empty); err == nil {
		t.Error("wrong JSON shape accepted")
	}
}

func TestResponseJSON(t *testing.T) {
	resp := &Response{Proto: "HTTP/1.1", StatusCode: 200, StatusText: "OK", Headers: Headers{{"A", "1"}}, Body: BodyOf([]byte("x")), Trailer: Headers{{"T", "2"}}}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"proto":"HTTP/1.1","statusCode":200,"statusText":"OK","headers":[{"name":"A","value":"1"}],"body":{"data":"eA==","size":1},"trailer":[{"name":"T","value":"2"}]}`
	if string(data) != want {
		t.Errorf("JSON =\n%s\nwant\n%s", data, want)
	}
	var back Response
	if err := json.Unmarshal(data, &back); err != nil || !reflect.DeepEqual(&back, resp) {
		t.Errorf("round trip: %+v %v", back, err)
	}
	data, _ = json.Marshal(Response{StatusCode: 204})
	if string(data) != `{"statusCode":204,"headers":[],"body":{"size":0}}` {
		t.Errorf("minimal JSON = %s", data)
	}
	if err := json.Unmarshal([]byte(`"str"`), &back); err == nil {
		t.Error("wrong JSON shape accepted")
	}
}

func TestClone(t *testing.T) {
	u, _ := url.Parse("https://user:pw@example.com/p?q=1")
	req := &Request{Method: "GET", URL: u, Headers: Headers{{"A", "1"}}, Trailer: Headers{{"T", "1"}}, Body: BodyOf([]byte("b"))}
	c := req.Clone()
	c.URL.Path = "/other"
	c.URL.User = url.User("x")
	c.Headers[0].Value = "2"
	c.Trailer[0].Value = "2"
	if req.URL.Path != "/p" || req.URL.User.Username() != "user" || req.Headers[0].Value != "1" || req.Trailer[0].Value != "1" {
		t.Error("Clone shares URL or headers")
	}
	if &c.Body.Data[0] != &req.Body.Data[0] {
		t.Error("Clone should share Body.Data")
	}
	if (&Request{}).Clone().URL != nil {
		t.Error("Clone of nil URL")
	}

	resp := &Response{StatusCode: 200, Headers: Headers{{"A", "1"}}}
	rc := resp.Clone()
	rc.Headers[0].Value = "2"
	if resp.Headers[0].Value != "1" {
		t.Error("Response.Clone shares headers")
	}
}

func TestStatusHelpers(t *testing.T) {
	for code, want := range map[int]int{100: 1, 200: 2, 299: 2, 404: 4, 599: 5, 600: 0, 99: 0, 0: 0, -1: 0} {
		if got := StatusClass(code); got != want {
			t.Errorf("StatusClass(%d) = %d", code, got)
		}
	}
	if got := (&Response{StatusCode: 200}).Status(); got != "200 OK" {
		t.Errorf("Status = %q", got)
	}
	if got := (&Response{StatusCode: 418, StatusText: "short and stout"}).Status(); got != "418 short and stout" {
		t.Errorf("Status = %q", got)
	}
	if got := (&Response{StatusCode: 799}).Status(); got != "799" {
		t.Errorf("Status = %q", got)
	}
}

func TestFromRequest(t *testing.T) {
	// Server-side: Host lives in req.Host, header map has no Host.
	srvReq := httptest.NewRequest("POST", "http://example.com/p?x=1", strings.NewReader("body"))
	srvReq.Header.Set("Content-Type", "text/plain")
	srvReq.Header.Add("X-Multi", "a")
	srvReq.Header.Add("X-Multi", "b")
	srvReq.Trailer = http.Header{"X-T": {"t"}}

	r := FromRequest(srvReq)
	if r.Method != "POST" || r.Proto != "HTTP/1.1" || r.Host != "example.com" {
		t.Errorf("basics = %+v", r)
	}
	if r.URL == srvReq.URL || r.URL.String() != "http://example.com/p?x=1" {
		t.Errorf("URL = %v (shared: %v)", r.URL, r.URL == srvReq.URL)
	}
	if !reflect.DeepEqual(r.Headers, Headers{{"Content-Type", "text/plain"}, {"X-Multi", "a"}, {"X-Multi", "b"}}) {
		t.Errorf("Headers = %v", r.Headers)
	}
	if !reflect.DeepEqual(r.Trailer, Headers{{"X-T", "t"}}) {
		t.Errorf("Trailer = %v", r.Trailer)
	}
	if !r.Body.IsEmpty() {
		t.Error("FromRequest read the body")
	}
	if data, _ := io.ReadAll(srvReq.Body); string(data) != "body" {
		t.Error("original body consumed")
	}

	// Client-side: Host empty, taken from URL.
	cliReq, _ := http.NewRequest("GET", "https://api.example.com/v1", nil)
	if got := FromRequest(cliReq).Host; got != "api.example.com" {
		t.Errorf("client Host = %q", got)
	}
	if FromRequest(&http.Request{Method: "GET"}).URL != nil {
		t.Error("nil URL not preserved")
	}
}

func TestFromResponse(t *testing.T) {
	resp := &http.Response{
		Status:     "404 Not Found",
		StatusCode: 404,
		Proto:      "HTTP/2.0",
		Header:     http.Header{"Content-Type": {"text/html"}},
		Body:       io.NopCloser(strings.NewReader("x")),
	}
	r := FromResponse(resp)
	if r.StatusCode != 404 || r.StatusText != "Not Found" || r.Proto != "HTTP/2.0" || r.Headers.Get("content-type") != "text/html" || !r.Body.IsEmpty() {
		t.Errorf("FromResponse = %+v", r)
	}
	if got := FromResponse(&http.Response{Status: "200"}).StatusText; got != "" {
		t.Errorf("StatusText without phrase = %q", got)
	}
}

func TestToStd(t *testing.T) {
	req, _ := ParseRequest([]byte("POST /p?a=1 HTTP/1.0\r\nHost: h\r\nX: y\r\nContent-Length: 2\r\n\r\nhi"))
	req.Trailer = Headers{{"T", "1"}}
	std, err := req.ToStd()
	if err != nil {
		t.Fatal(err)
	}
	if std.Method != "POST" || std.Host != "h" || std.URL.RawQuery != "a=1" || std.Proto != "HTTP/1.0" || std.ProtoMajor != 1 || std.ProtoMinor != 0 {
		t.Errorf("std = %+v", std)
	}
	if std.Header.Get("Host") != "" || std.Header.Get("X") != "y" || std.ContentLength != 2 || std.Trailer.Get("T") != "1" {
		t.Errorf("std headers = %+v", std)
	}
	if data, _ := io.ReadAll(std.Body); string(data) != "hi" {
		t.Errorf("std body = %q", data)
	}
	if std.URL == req.URL {
		t.Error("ToStd shares URL")
	}
	if _, err := (&Request{Method: "GET"}).ToStd(); err == nil {
		t.Error("nil URL accepted")
	}
	// Defaults and Host from header.
	std, _ = (&Request{Method: "GET", URL: &url.URL{Path: "/"}, Headers: Headers{{"host", "hh"}}}).ToStd()
	if std.Proto != "HTTP/1.1" || std.ProtoMajor != 1 || std.ProtoMinor != 1 || std.Host != "hh" || std.Trailer != nil {
		t.Errorf("defaults = %+v", std)
	}

	// The converted request can actually be served.
	rec := httptest.NewRecorder()
	http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Echo", r.Host+":"+string(b))
	}).ServeHTTP(rec, std)
	if got := rec.Header().Get("X-Echo"); got != "hh:" {
		t.Errorf("served = %q", got)
	}

	resp := &Response{StatusCode: 201, Headers: Headers{{"A", "1"}}, Body: BodyOf([]byte("ok"))}
	sr := resp.ToStd()
	if sr.Status != "201 Created" || sr.Proto != "HTTP/1.1" || sr.ContentLength != 2 || sr.Header.Get("A") != "1" || sr.Trailer != nil {
		t.Errorf("resp std = %+v", sr)
	}
	if data, _ := io.ReadAll(sr.Body); string(data) != "ok" {
		t.Errorf("resp body = %q", data)
	}
}

func TestProtoVersion(t *testing.T) {
	for proto, want := range map[string][2]int{"HTTP/1.1": {1, 1}, "HTTP/1.0": {1, 0}, "HTTP/2.0": {2, 0}, "HTTP/2": {2, 0}, "HTTP/3": {3, 0}, "": {1, 1}, "junk": {1, 1}} {
		if a, b := protoVersion(proto); a != want[0] || b != want[1] {
			t.Errorf("protoVersion(%q) = %d.%d", proto, a, b)
		}
	}
}

func TestRequestQueryNilURL(t *testing.T) {
	if (&Request{}).Query() != nil {
		t.Error("Query on nil URL")
	}
	req := &Request{URL: &url.URL{RawQuery: "a=1&b=%zz"}}
	if got := req.Query(); len(got) != 2 || got[1].Value != "%zz" {
		t.Errorf("Query = %v", got)
	}
}
