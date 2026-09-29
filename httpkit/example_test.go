package httpkit_test

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/kspkr/wirekit/httpkit"
)

func ExampleParseRequest() {
	raw := "POST /api/login?next=%2Fhome HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"content-type: application/json; charset=utf-8\r\n" +
		"Cookie: session=abc123; theme=dark\r\n" +
		"Content-Length: 27\r\n" +
		"\r\n" +
		`{"user":"go","pass":"****"}`

	req, err := httpkit.ParseRequest([]byte(raw))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(req.Method, req.URL.Path, req.Host)
	fmt.Println("next:", req.Query().Get("next"))
	fmt.Println("json:", req.ContentType().IsJSON())
	for _, c := range req.Cookies() {
		fmt.Printf("cookie %s=%s\n", c.Name, c.Value)
	}
	fmt.Printf("body: %d bytes\n", req.Body.Size)
	// Output:
	// POST /api/login example.com
	// next: /home
	// json: true
	// cookie session=abc123
	// cookie theme=dark
	// body: 27 bytes
}

func ExampleReadResponse() {
	raw := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Set-Cookie: id=42; Path=/; HttpOnly; SameSite=Lax\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"5\r\nhello\r\n0\r\n\r\n"

	resp, err := httpkit.ReadResponse(bufio.NewReader(strings.NewReader(raw)), &httpkit.ReadOptions{
		MaxBodyBytes: 1 << 20, // keep up to 1 MiB, count the rest
	})
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(resp.Status())
	for _, c := range resp.SetCookies() {
		fmt.Println("sets", c.Name, "HttpOnly:", c.HttpOnly, "SameSite:", c.SameSite)
	}
	fmt.Printf("%s (%d bytes)\n", resp.Body.Data, resp.Body.Size)
	// Output:
	// 200 OK
	// sets id HttpOnly: true SameSite: Lax
	// hello (5 bytes)
}

func ExampleHeaders() {
	var h httpkit.Headers
	h.Add("Content-Type", "text/plain")
	h.Add("set-cookie", "a=1")
	h.Add("Set-Cookie", "b=2")

	fmt.Println(h.Get("CONTENT-TYPE"))
	fmt.Println(h.Values("Set-Cookie"))
	h.Set("content-type", "application/json")
	h.Del("set-cookie")
	fmt.Print(h)
	// Output:
	// text/plain
	// [a=1 b=2]
	// Content-Type: application/json
}

func ExampleParseSetCookie() {
	c, err := httpkit.ParseSetCookie("sid=xyz; Path=/; Domain=example.com; Max-Age=0; SameSite=None")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(c.Name, c.Domain, "delete:", c.MaxAge < 0)
	fmt.Println("valid:", c.Validate())
	// Output:
	// sid example.com delete: true
	// valid: httpkit: malformed cookie: SameSite=None requires Secure
}

func ExampleCapture() {
	// Keep the first 8 bytes of a stream while counting all of it.
	capture := httpkit.NewCapture(8)
	body := capture.TeeReader(strings.NewReader("a body that is longer than eight bytes"))
	_, _ = bufio.NewReader(body).WriteTo(os.NewFile(0, os.DevNull)) // consume the stream

	b := capture.Body()
	fmt.Printf("%q size=%d truncated=%v\n", b.Data, b.Size, b.Truncated)
	// Output:
	// "a body t" size=38 truncated=true
}

func ExampleRequest_WriteTo() {
	req, _ := httpkit.ParseRequest([]byte("GET /x HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"))
	req.Headers.Set("Accept", "application/json")
	req.Headers.Add("X-Trace", "1")

	var wire bytes.Buffer
	_, _ = req.WriteTo(&wire)
	// The wire format uses CRLF line endings; print them visibly.
	fmt.Printf("%q\n", wire.String())
	// Output:
	// "GET /x HTTP/1.1\r\nHost: example.com\r\nAccept: application/json\r\nX-Trace: 1\r\n\r\n"
}
