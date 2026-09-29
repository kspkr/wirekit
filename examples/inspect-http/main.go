// Command inspect-http parses a raw HTTP/1.x request or response and prints
// what WireKit sees in it.
//
// Pipe a captured message on stdin, or run it with no input to see a
// built-in sample:
//
//	go run ./examples/inspect-http < request.txt
//	go run ./examples/inspect-http -response < response.txt
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/kspkr/wirekit/compress"
	"github.com/kspkr/wirekit/encoding"
	"github.com/kspkr/wirekit/httpkit"
)

const sampleRequest = "POST /api/v1/login?redirect=%2Fhome HTTP/1.1\r\n" +
	"Host: api.example.com\r\n" +
	"User-Agent: curl/8.6.0\r\n" +
	"Accept: application/json\r\n" +
	"content-type: application/json; charset=utf-8\r\n" +
	"Cookie: session=abc123; theme=dark\r\n" +
	"Content-Length: 39\r\n" +
	"\r\n" +
	`{"username":"ada","password":"hunter2"}`

func main() {
	isResponse := flag.Bool("response", false, "parse a response instead of a request")
	flag.Parse()

	data, err := readInput()
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		data = []byte(sampleRequest)
		fmt.Println("(no input on stdin; using the built-in sample)")
	}

	if *isResponse {
		inspectResponse(data)
	} else {
		inspectRequest(data)
	}
}

func readInput() ([]byte, error) {
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		return nil, nil // interactive terminal, nothing piped
	}
	return io.ReadAll(os.Stdin)
}

func inspectRequest(data []byte) {
	req, err := httpkit.ParseRequest(data)
	if err != nil && req == nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(1)
	}
	if err != nil {
		fmt.Println("warning:", err)
	}
	fmt.Printf("%s %s %s\n", req.Method, req.URL.RequestURI(), req.Proto)
	fmt.Println("host:", req.Host)
	if q := req.Query(); len(q) > 0 {
		fmt.Println("query:")
		for _, p := range q {
			fmt.Printf("  %s = %q\n", p.Name, p.Value)
		}
	}
	printHeaders(req.Headers)
	if cookies := req.Cookies(); len(cookies) > 0 {
		fmt.Println("cookies:")
		for _, c := range cookies {
			fmt.Printf("  %s = %s\n", c.Name, c.Value)
		}
	}
	printBody(req.Headers, req.Body)
}

func inspectResponse(data []byte) {
	resp, err := httpkit.ParseResponse(data, "")
	if err != nil && resp == nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(1)
	}
	if err != nil {
		fmt.Println("warning:", err)
	}
	fmt.Printf("%s %s\n", resp.Proto, resp.Status())
	printHeaders(resp.Headers)
	for _, c := range resp.SetCookies() {
		fmt.Printf("set-cookie: %s=%s (Secure=%v HttpOnly=%v SameSite=%s)\n", c.Name, c.Value, c.Secure, c.HttpOnly, c.SameSite)
		if err := c.Validate(); err != nil {
			fmt.Println("  warning:", err)
		}
	}
	printBody(resp.Headers, resp.Body)
}

func printHeaders(hs httpkit.Headers) {
	fmt.Printf("headers (%d):\n", len(hs))
	for _, h := range hs {
		fmt.Printf("  %s: %s\n", h.Name, h.Value)
	}
}

func printBody(hs httpkit.Headers, body httpkit.Body) {
	if body.IsEmpty() {
		fmt.Println("body: none")
		return
	}
	ct := hs.ContentType()
	fmt.Printf("body: %d bytes (%d captured), type %q\n", body.Size, body.Captured(), ct.MediaType)

	data := body.Data
	if enc := hs.Get("Content-Encoding"); enc != "" {
		decoded, err := compress.Decode(enc, data, 8<<20)
		if err != nil {
			if errors.Is(err, compress.ErrUnsupported) {
				fmt.Println("  content-encoding:", enc, "(not decodable)")
			} else {
				fmt.Println("  decode error:", err)
			}
		} else {
			fmt.Printf("  content-encoding: %s (%d bytes decoded)\n", enc, len(decoded))
			data = decoded
		}
	}

	switch {
	case ct.IsJSON() || encoding.LooksLikeJSON(data):
		if info, err := encoding.InspectJSON(data); err == nil {
			fmt.Printf("  json: %s, depth %d, %d keys\n", info.Kind, info.Depth, info.Keys)
		} else {
			fmt.Println("  json:", err)
		}
		fmt.Printf("  %s\n", data)
	case ct.IsText() || encoding.LooksLikeText(data):
		fmt.Printf("  %s\n", data)
	default:
		fmt.Print(encoding.HexDump(data, 256))
	}
}
