package httpkit

import (
	"bufio"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func sampleHeaders() Headers {
	return Headers{
		{"Host", "example.com"},
		{"content-type", "text/html; charset=utf-8"},
		{"Set-Cookie", "a=1"},
		{"X-Custom", "one"},
		{"set-cookie", "b=2"},
		{"X-Custom", "two"},
	}
}

func TestHeadersLookup(t *testing.T) {
	hs := sampleHeaders()
	if got := hs.Get("CONTENT-TYPE"); got != "text/html; charset=utf-8" {
		t.Errorf("Get = %q", got)
	}
	if got := hs.Get("missing"); got != "" {
		t.Errorf("Get(missing) = %q", got)
	}
	if v, ok := hs.Lookup("x-custom"); !ok || v != "one" {
		t.Errorf("Lookup = %q, %v", v, ok)
	}
	if _, ok := hs.Lookup("nope"); ok {
		t.Error("Lookup(nope) reported present")
	}
	if !hs.Has("SET-COOKIE") || hs.Has("cookie") {
		t.Error("Has wrong")
	}
	if got := hs.Values("set-cookie"); !reflect.DeepEqual(got, []string{"a=1", "b=2"}) {
		t.Errorf("Values = %v", got)
	}
	if got := hs.Values("nope"); got != nil {
		t.Errorf("Values(nope) = %v, want nil", got)
	}
	if got := hs.Count("x-custom"); got != 2 {
		t.Errorf("Count = %d", got)
	}
	var empty Headers
	if empty.Get("a") != "" || empty.Has("a") || empty.Values("a") != nil {
		t.Error("zero Headers not empty")
	}
}

func TestHeadersMutation(t *testing.T) {
	hs := sampleHeaders()
	hs.Add("X-New", "v")
	if hs[len(hs)-1] != (Header{"X-New", "v"}) {
		t.Errorf("Add did not append: %v", hs)
	}

	// Set replaces in place, keeps the wire spelling, and removes later
	// duplicates.
	hs.Set("x-custom", "three")
	want := Headers{
		{"Host", "example.com"},
		{"content-type", "text/html; charset=utf-8"},
		{"Set-Cookie", "a=1"},
		{"X-Custom", "three"},
		{"set-cookie", "b=2"},
		{"X-New", "v"},
	}
	if !reflect.DeepEqual(hs, want) {
		t.Errorf("after Set:\n got %v\nwant %v", hs, want)
	}
	if got := hs.Count("X-Custom"); got != 1 {
		t.Errorf("Count after Set = %d", got)
	}

	// Set on a missing name appends.
	hs.Set("Accept", "*/*")
	if hs[len(hs)-1] != (Header{"Accept", "*/*"}) {
		t.Errorf("Set(missing) did not append: %v", hs)
	}

	// Del removes all matches and reports it.
	if !hs.Del("SET-COOKIE") {
		t.Error("Del returned false")
	}
	if hs.Has("Set-Cookie") {
		t.Error("Del left a Set-Cookie behind")
	}
	if hs.Del("Set-Cookie") {
		t.Error("second Del returned true")
	}
	if len(hs) != 5 {
		t.Errorf("len after Del = %d: %v", len(hs), hs)
	}
}

func TestHeadersSetKeepsOtherFieldsWhenFirstIsFirst(t *testing.T) {
	hs := Headers{{"A", "1"}, {"B", "2"}, {"a", "3"}, {"C", "4"}}
	hs.Set("a", "x")
	want := Headers{{"A", "x"}, {"B", "2"}, {"C", "4"}}
	if !reflect.DeepEqual(hs, want) {
		t.Errorf("got %v want %v", hs, want)
	}
}

func TestHeadersDelClearsTail(t *testing.T) {
	// Del must not leave stale entries reachable through the old capacity.
	hs := Headers{{"A", "1"}, {"B", "2"}}
	backing := hs
	hs.Del("A")
	if backing[1] != (Header{}) {
		t.Errorf("tail not cleared: %v", backing)
	}
}

func TestHeadersClone(t *testing.T) {
	hs := sampleHeaders()
	c := hs.Clone()
	c[0].Value = "changed"
	if hs[0].Value == "changed" {
		t.Error("Clone shares storage")
	}
	var nilHs Headers
	if nilHs.Clone() != nil {
		t.Error("Clone(nil) != nil")
	}
}

func TestHeadersWriteString(t *testing.T) {
	hs := Headers{{"Host", "example.com"}, {"Accept", "*/*"}}
	want := "Host: example.com\r\nAccept: */*\r\n"
	if got := hs.String(); got != want {
		t.Errorf("String = %q, want %q", got, want)
	}
	var sb strings.Builder
	if err := hs.Write(&sb); err != nil || sb.String() != want {
		t.Errorf("Write = %q, %v", sb.String(), err)
	}
}

func TestHeadersStdConversion(t *testing.T) {
	std := http.Header{}
	std.Add("Content-Type", "text/plain")
	std.Add("Set-Cookie", "a=1")
	std.Add("Set-Cookie", "b=2")
	std.Add("Accept", "*/*")

	hs := FromStd(std)
	want := Headers{
		{"Accept", "*/*"},
		{"Content-Type", "text/plain"},
		{"Set-Cookie", "a=1"},
		{"Set-Cookie", "b=2"},
	}
	if !reflect.DeepEqual(hs, want) {
		t.Errorf("FromStd = %v", hs)
	}
	if FromStd(nil) != nil || FromStd(http.Header{}) != nil {
		t.Error("FromStd(empty) should be nil")
	}

	back := hs.ToStd()
	if !reflect.DeepEqual(back, std) {
		t.Errorf("ToStd = %v, want %v", back, std)
	}
	// Non-canonical names are canonicalized by ToStd.
	if got := (Headers{{"x-thing", "v"}}).ToStd().Get("X-Thing"); got != "v" {
		t.Errorf("ToStd canonicalization failed: %q", got)
	}
	if got := Canonical("content-type"); got != "Content-Type" {
		t.Errorf("Canonical = %q", got)
	}
}

func TestHeadersContentLength(t *testing.T) {
	cases := []struct {
		name   string
		hs     Headers
		want   int64
		wantOK bool
	}{
		{"absent", Headers{}, 0, false},
		{"simple", Headers{{"Content-Length", "42"}}, 42, true},
		{"zero", Headers{{"Content-Length", "0"}}, 0, true},
		{"spaces", Headers{{"Content-Length", " 7 "}}, 7, true},
		{"duplicate same", Headers{{"Content-Length", "5"}, {"content-length", "5"}}, 5, true},
		{"duplicate differs", Headers{{"Content-Length", "5"}, {"Content-Length", "6"}}, 0, false},
		{"list same", Headers{{"Content-Length", "5, 5"}}, 5, true},
		{"list differs", Headers{{"Content-Length", "5, 6"}}, 0, false},
		{"negative", Headers{{"Content-Length", "-1"}}, 0, false},
		{"plus", Headers{{"Content-Length", "+1"}}, 0, false},
		{"hex", Headers{{"Content-Length", "0x10"}}, 0, false},
		{"empty", Headers{{"Content-Length", ""}}, 0, false},
		{"overflow", Headers{{"Content-Length", "99999999999999999999"}}, 0, false},
		{"max", Headers{{"Content-Length", "9223372036854775807"}}, 9223372036854775807, true},
		{"trailing junk", Headers{{"Content-Length", "12abc"}}, 0, false},
	}
	for _, c := range cases {
		got, ok := c.hs.ContentLength()
		if got != c.want || ok != c.wantOK {
			t.Errorf("%s: ContentLength = %d, %v; want %d, %v", c.name, got, ok, c.want, c.wantOK)
		}
	}
}

func TestHeadersCodings(t *testing.T) {
	hs := Headers{
		{"Content-Encoding", "GZIP"},
		{"Transfer-Encoding", "gzip, Chunked"},
	}
	if got := hs.ContentEncoding(); !reflect.DeepEqual(got, []string{"gzip"}) {
		t.Errorf("ContentEncoding = %v", got)
	}
	if got := hs.TransferEncoding(); !reflect.DeepEqual(got, []string{"gzip", "chunked"}) {
		t.Errorf("TransferEncoding = %v", got)
	}
	if !hs.IsChunked() {
		t.Error("IsChunked = false")
	}
	if (Headers{{"Transfer-Encoding", "chunked, gzip"}}).IsChunked() {
		t.Error("IsChunked should be false when chunked is not final")
	}
	if (Headers{}).ContentEncoding() != nil {
		t.Error("ContentEncoding(absent) != nil")
	}
	multi := Headers{{"Content-Encoding", "br"}, {"Content-Encoding", " , gzip,,"}}
	if got := multi.ContentEncoding(); !reflect.DeepEqual(got, []string{"br", "gzip"}) {
		t.Errorf("multi ContentEncoding = %v", got)
	}
}

func TestHeadersConnectionUpgrade(t *testing.T) {
	hs := Headers{
		{"Connection", "keep-alive, Upgrade"},
		{"Upgrade", "websocket"},
	}
	if !hs.HasConnectionToken("upgrade") || !hs.HasConnectionToken("KEEP-ALIVE") || hs.HasConnectionToken("close") {
		t.Error("HasConnectionToken wrong")
	}
	if got := hs.UpgradeProtocol(); got != "websocket" {
		t.Errorf("UpgradeProtocol = %q", got)
	}
	noConn := Headers{{"Upgrade", "websocket"}}
	if got := noConn.UpgradeProtocol(); got != "" {
		t.Errorf("UpgradeProtocol without Connection = %q", got)
	}
}

func TestHeadersRemoveHopByHop(t *testing.T) {
	hs := Headers{
		{"Host", "example.com"},
		{"Connection", "keep-alive, X-Per-Hop"},
		{"X-Per-Hop", "1"},
		{"Keep-Alive", "timeout=5"},
		{"Transfer-Encoding", "chunked"},
		{"Proxy-Connection", "keep-alive"},
		{"TE", "trailers"},
		{"Content-Type", "text/plain"},
		{"Upgrade", "h2c"},
	}
	hs.RemoveHopByHop()
	want := Headers{{"Host", "example.com"}, {"Content-Type", "text/plain"}}
	if !reflect.DeepEqual(hs, want) {
		t.Errorf("RemoveHopByHop = %v", hs)
	}
}

func TestHeadersContentTypeFallback(t *testing.T) {
	if ct := (Headers{}).ContentType(); !ct.IsZero() {
		t.Errorf("absent = %+v", ct)
	}
	ct := Headers{{"Content-Type", "Application/JSON; charset=UTF-8"}}.ContentType()
	if ct.MediaType != "application/json" || ct.Charset() != "utf-8" {
		t.Errorf("parsed = %+v", ct)
	}
	// Malformed parameter: media type still recovered.
	ct = Headers{{"Content-Type", "text/html; charset"}}.ContentType()
	if ct.MediaType != "text/html" || ct.Params != nil {
		t.Errorf("fallback = %+v", ct)
	}
}

func TestHeadersCookies(t *testing.T) {
	hs := Headers{
		{"Cookie", "a=1; b=2"},
		{"cookie", "c=3"},
		{"Set-Cookie", "x=1; Path=/; HttpOnly"},
		{"Set-Cookie", "garbage-without-equals"},
		{"Set-Cookie", "y=2; Secure"},
	}
	cs := hs.Cookies()
	if len(cs) != 3 || cs[0].Name != "a" || cs[2].Value != "3" {
		t.Errorf("Cookies = %v", cs)
	}
	sc := hs.SetCookies()
	if len(sc) != 2 || sc[0].Name != "x" || !sc[0].HttpOnly || sc[1].Name != "y" || !sc[1].Secure {
		t.Errorf("SetCookies = %+v", sc)
	}
}

var browserRequest = "GET /search?q=wirekit&hl=en HTTP/1.1\r\n" +
	"Host: www.example.com\r\n" +
	"Connection: keep-alive\r\n" +
	"sec-ch-ua: \"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\"\r\n" +
	"sec-ch-ua-mobile: ?0\r\n" +
	"sec-ch-ua-platform: \"Windows\"\r\n" +
	"Upgrade-Insecure-Requests: 1\r\n" +
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n" +
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n" +
	"Sec-Fetch-Site: none\r\n" +
	"Sec-Fetch-Mode: navigate\r\n" +
	"Sec-Fetch-User: ?1\r\n" +
	"Sec-Fetch-Dest: document\r\n" +
	"Accept-Encoding: gzip, deflate, br, zstd\r\n" +
	"Accept-Language: en-US,en;q=0.9\r\n" +
	"Cookie: SID=abcdefghijklmnopqrstuvwxyz0123456789; HSID=abcdefghijklmnopqrst; SSID=abcdefghijklmnop; NID=511=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n" +
	"\r\n"

func BenchmarkHeadersGet(b *testing.B) {
	req, err := ParseRequest([]byte(browserRequest))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		req.Headers.Get("Accept-Language")
	}
}

func BenchmarkHeadersSet(b *testing.B) {
	req, err := ParseRequest([]byte(browserRequest))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		req.Headers.Set("Accept-Language", "de")
	}
}

func BenchmarkReadHeaders(b *testing.B) {
	block := browserRequest[strings.Index(browserRequest, "\r\n")+2:]
	data := []byte(block)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	br := bufio.NewReader(nil)
	for b.Loop() {
		br.Reset(strings.NewReader(string(data)))
		if _, err := ReadHeaders(br, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFromStd(b *testing.B) {
	req, err := ParseRequest([]byte(browserRequest))
	if err != nil {
		b.Fatal(err)
	}
	std := req.Headers.ToStd()
	b.ReportAllocs()
	for b.Loop() {
		FromStd(std)
	}
}
