package httpkit

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
)

// WriteHead writes the request line, headers and the empty line that ends
// the header block, in HTTP/1.x wire format.
//
// The request target is written in origin-form ("/path?query"), or
// authority-form for CONNECT. When Proto is empty, HTTP/1.1 is written.
// When Host is set and the headers have no Host field, a Host field is
// written first, as net/http does; otherwise headers are written exactly as
// held.
func (r *Request) WriteHead(w io.Writer) error {
	if r.URL == nil {
		return errors.New("httpkit: request has no URL")
	}
	bw := bufio.NewWriter(w)
	bw.WriteString(r.Method)
	bw.WriteByte(' ')
	if r.Method == "CONNECT" {
		host := r.URL.Host
		if host == "" {
			host = r.Host
		}
		bw.WriteString(host)
	} else {
		bw.WriteString(r.URL.RequestURI())
	}
	bw.WriteByte(' ')
	bw.WriteString(protoOrDefault(r.Proto))
	bw.WriteString("\r\n")
	if r.Host != "" && !r.Headers.Has("Host") {
		bw.WriteString("Host: ")
		bw.WriteString(r.Host)
		bw.WriteString("\r\n")
	}
	if err := r.Headers.Write(bw); err != nil {
		return err
	}
	bw.WriteString("\r\n")
	return bw.Flush()
}

// WriteTo writes the whole request in HTTP/1.x wire format: the head, then
// the retained body bytes.
//
// The body is written as held except that when the headers declare
// Transfer-Encoding: chunked, Body.Data is chunk-encoded and any Trailer
// fields follow it, so the output re-parses to the same message. Headers
// are never adjusted: a truncated body is written short of its declared
// Content-Length. WriteTo implements io.WriterTo.
func (r *Request) WriteTo(w io.Writer) (int64, error) {
	cw := &countWriter{w: w}
	if err := r.WriteHead(cw); err != nil {
		return cw.n, err
	}
	err := writeBody(cw, r.Body, r.Headers.IsChunked(), r.Trailer)
	return cw.n, err
}

// WriteHead writes the status line, headers and the empty line that ends
// the header block, in HTTP/1.x wire format. When StatusText is empty the
// standard reason phrase is used; when Proto is empty, HTTP/1.1 is written.
func (r *Response) WriteHead(w io.Writer) error {
	bw := bufio.NewWriter(w)
	bw.WriteString(protoOrDefault(r.Proto))
	bw.WriteByte(' ')
	bw.WriteString(strconv.Itoa(r.StatusCode))
	bw.WriteByte(' ')
	text := r.StatusText
	if text == "" {
		text = http.StatusText(r.StatusCode)
	}
	bw.WriteString(text)
	bw.WriteString("\r\n")
	if err := r.Headers.Write(bw); err != nil {
		return err
	}
	bw.WriteString("\r\n")
	return bw.Flush()
}

// WriteTo writes the whole response in HTTP/1.x wire format. Body handling
// matches Request.WriteTo. WriteTo implements io.WriterTo.
func (r *Response) WriteTo(w io.Writer) (int64, error) {
	cw := &countWriter{w: w}
	if err := r.WriteHead(cw); err != nil {
		return cw.n, err
	}
	err := writeBody(cw, r.Body, r.Headers.IsChunked(), r.Trailer)
	return cw.n, err
}

func writeBody(w io.Writer, body Body, chunked bool, trailer Headers) error {
	if !chunked {
		if len(body.Data) == 0 {
			return nil
		}
		_, err := w.Write(body.Data)
		return err
	}
	cw := httputil.NewChunkedWriter(w)
	if len(body.Data) > 0 {
		if _, err := cw.Write(body.Data); err != nil {
			return err
		}
	}
	if err := cw.Close(); err != nil { // writes the final "0\r\n"
		return err
	}
	if err := trailer.Write(w); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

func protoOrDefault(proto string) string {
	if proto == "" {
		return "HTTP/1.1"
	}
	return proto
}

// countWriter counts bytes passed through to w.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
