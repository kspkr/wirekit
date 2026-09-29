package httpkit

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/kspkr/wirekit/internal/ascii"
)

// Limits used by ReadRequest and ReadResponse when ReadOptions leaves a
// field zero.
const (
	// DefaultMaxHeaderBytes bounds the start line and header block (and
	// the trailer block, separately). It matches net/http's default.
	DefaultMaxHeaderBytes = 1 << 20
	// DefaultMaxBodyBytes bounds how much of a body is retained in Body.Data.
	// Bytes beyond it are still read and counted in Body.Size.
	DefaultMaxBodyBytes = 1 << 20
)

// ReadOptions bounds and informs the HTTP/1.x readers. A nil *ReadOptions
// means defaults.
type ReadOptions struct {
	// MaxHeaderBytes is the most the start line and header block may
	// occupy, in bytes. Zero means DefaultMaxHeaderBytes.
	MaxHeaderBytes int
	// MaxBodyBytes is the most body bytes to retain in Body.Data. The rest
	// of the body is read and counted but discarded. Zero means
	// DefaultMaxBodyBytes; use math.MaxInt64 to retain everything.
	MaxBodyBytes int64
	// RequestMethod is the method of the request a response answers. It is
	// only used by ReadResponse, to know that a response to HEAD has no
	// body. Leave it empty when unknown.
	RequestMethod string
}

func (o *ReadOptions) headerLimit() int {
	if o == nil || o.MaxHeaderBytes <= 0 {
		return DefaultMaxHeaderBytes
	}
	return o.MaxHeaderBytes
}

func (o *ReadOptions) bodyLimit() int64 {
	if o == nil || o.MaxBodyBytes <= 0 {
		return DefaultMaxBodyBytes
	}
	return o.MaxBodyBytes
}

func (o *ReadOptions) requestMethod() string {
	if o == nil {
		return ""
	}
	return o.RequestMethod
}

// ReadRequest reads one HTTP/1.x request from br: start line, headers,
// body and any trailers. Header order and spelling are preserved.
//
// The body is framed by Transfer-Encoding or Content-Length as RFC 9112
// specifies; a request with neither has no body. Up to opts.MaxBodyBytes of
// the body are retained in Body.Data and the rest is read and counted.
//
// Errors wrap ErrMalformed for invalid syntax and ErrTooLarge when a limit
// is exceeded. An error in the start line or headers returns a nil request.
// Once the head has parsed, a problem with the body (the stream ends early,
// which yields an error wrapping io.ErrUnexpectedEOF, or the chunked framing
// is malformed) returns the request together with the error, so an
// inspector can still show what arrived. If br is empty, the error is
// io.EOF.
func ReadRequest(br *bufio.Reader, opts *ReadOptions) (*Request, error) {
	lr := &lineReader{br: br, remaining: opts.headerLimit()}
	line, err := lr.startLine()
	if err != nil {
		return nil, err
	}
	req, err := parseRequestLine(line)
	if err != nil {
		return nil, err
	}
	if req.Headers, err = lr.headers(); err != nil {
		return nil, err
	}
	if req.URL.Host != "" && req.Method != "CONNECT" {
		req.Host = req.URL.Host
	} else if h, ok := req.Headers.Lookup("Host"); ok {
		req.Host = h
	} else if req.Method == "CONNECT" {
		req.Host = req.URL.Host
	}

	body, chunked, err := bodyReader(br, req.Headers, true)
	if err != nil {
		return nil, err
	}
	req.Body, req.Trailer, err = readBody(br, body, chunked, opts)
	if err != nil {
		return req, err
	}
	return req, nil
}

// ReadResponse reads one HTTP/1.x response from br: status line, headers,
// body and any trailers. Header order and spelling are preserved.
//
// The body is framed as RFC 9112 specifies: responses with status 1xx, 204
// or 304, and responses to HEAD (see ReadOptions.RequestMethod), have no
// body; otherwise Transfer-Encoding or Content-Length frame it, and a
// response with neither extends to the end of the stream.
//
// Error behaviour matches ReadRequest.
func ReadResponse(br *bufio.Reader, opts *ReadOptions) (*Response, error) {
	lr := &lineReader{br: br, remaining: opts.headerLimit()}
	line, err := lr.startLine()
	if err != nil {
		return nil, err
	}
	resp, err := parseStatusLine(line)
	if err != nil {
		return nil, err
	}
	if resp.Headers, err = lr.headers(); err != nil {
		return nil, err
	}

	var body io.Reader
	var chunked bool
	if responseHasBody(resp.StatusCode, opts.requestMethod()) {
		body, chunked, err = bodyReader(br, resp.Headers, false)
		if err != nil {
			return nil, err
		}
	}
	resp.Body, resp.Trailer, err = readBody(br, body, chunked, opts)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

// ParseRequest parses a complete HTTP/1.x request held in memory. Unlike
// ReadRequest it retains the whole body and places no limit on header size
// beyond the length of data.
func ParseRequest(data []byte) (*Request, error) {
	return ReadRequest(bufio.NewReader(bytes.NewReader(data)), inMemoryOptions(data, ""))
}

// ParseResponse parses a complete HTTP/1.x response held in memory. Unlike
// ReadResponse it retains the whole body and places no limit on header size
// beyond the length of data. requestMethod may be "" when unknown.
func ParseResponse(data []byte, requestMethod string) (*Response, error) {
	return ReadResponse(bufio.NewReader(bytes.NewReader(data)), inMemoryOptions(data, requestMethod))
}

func inMemoryOptions(data []byte, method string) *ReadOptions {
	n := max(len(data), 1)
	return &ReadOptions{MaxHeaderBytes: n, MaxBodyBytes: int64(n), RequestMethod: method}
}

// ReadHeaders reads a header block from br up to and including the empty
// line that ends it. maxBytes bounds the block; zero means
// DefaultMaxHeaderBytes. It is the parser behind ReadRequest and
// ReadResponse, exposed for trailers, multipart parts and other places a
// bare header block appears.
func ReadHeaders(br *bufio.Reader, maxBytes int) (Headers, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxHeaderBytes
	}
	lr := &lineReader{br: br, remaining: maxBytes}
	return lr.headers()
}

// ParseHeaders parses a header block held in memory. The block may or may
// not end with an empty line.
func ParseHeaders(data []byte) (Headers, error) {
	lr := &lineReader{br: bufio.NewReader(bytes.NewReader(data)), remaining: max(len(data), 1) + 2}
	hs, err := lr.headers()
	if errors.Is(err, io.ErrUnexpectedEOF) {
		// No terminating blank line: acceptable for an in-memory block.
		return hs, nil
	}
	return hs, err
}

// lineReader reads CRLF- or LF-terminated lines within a byte budget.
type lineReader struct {
	br        *bufio.Reader
	remaining int
	buf       []byte
	// unterminated is set once a final line without a terminator has been
	// returned; the next call reports io.ErrUnexpectedEOF.
	unterminated bool
}

// line returns the next line without its terminator. The returned slice is
// only valid until the next call. io.EOF is returned only when no bytes
// were read. A final line without a terminator is returned normally and
// the call after it fails with io.ErrUnexpectedEOF.
func (lr *lineReader) line() ([]byte, error) {
	if lr.unterminated {
		return nil, fmt.Errorf("httpkit: header block ended early: %w", io.ErrUnexpectedEOF)
	}
	lr.buf = lr.buf[:0]
	for {
		chunk, err := lr.br.ReadSlice('\n')
		lr.remaining -= len(chunk)
		if lr.remaining < 0 {
			return nil, tooLarge("header block")
		}
		lr.buf = append(lr.buf, chunk...)
		switch {
		case err == nil:
			return trimLineEnd(lr.buf), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if len(lr.buf) == 0 {
				return nil, io.EOF
			}
			lr.unterminated = true
			return lr.buf, nil
		default:
			return nil, err
		}
	}
}

func trimLineEnd(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
		if n := len(b); n > 0 && b[n-1] == '\r' {
			b = b[:n-1]
		}
	}
	return b
}

// startLine returns the first non-empty line. RFC 9112 §2.2 asks
// recipients to ignore empty lines before a request line.
func (lr *lineReader) startLine() ([]byte, error) {
	for {
		line, err := lr.line()
		if err != nil {
			return nil, err
		}
		if len(line) > 0 {
			return line, nil
		}
	}
}

// headers parses field lines up to the empty line that ends the block.
func (lr *lineReader) headers() (Headers, error) {
	var hs Headers
	for {
		line, err := lr.line()
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = fmt.Errorf("httpkit: header block ended early: %w", io.ErrUnexpectedEOF)
			}
			return hs, err
		}
		if len(line) == 0 {
			return hs, nil
		}
		if ascii.IsSpace(line[0]) {
			// Obsolete line folding. RFC 9112 §5.2 lets a recipient reject it,
			// and accepting it is a request-smuggling vector.
			return nil, malformed("header: obsolete line folding")
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return nil, malformed("header: missing ':' in field line")
		}
		name := string(line[:colon])
		if !ascii.IsToken(name) {
			// A space before the colon is the common case here; RFC 9112
			// §5.1 requires rejecting it.
			return nil, malformed("header: invalid field name " + strconv.Quote(name))
		}
		value := ascii.TrimSpace(string(line[colon+1:]))
		for i := 0; i < len(value); i++ {
			if !ascii.IsFieldVchar(value[i]) {
				return nil, malformed("header: control character in value of " + name)
			}
		}
		hs = append(hs, Header{Name: name, Value: value})
	}
}

// parseRequestLine parses "METHOD target HTTP/x.y".
func parseRequestLine(line []byte) (*Request, error) {
	s := string(line)
	method, rest, ok := strings.Cut(s, " ")
	if !ok {
		return nil, malformed("request line " + strconv.Quote(s))
	}
	target, proto, ok := strings.Cut(rest, " ")
	if !ok || target == "" || !ascii.IsToken(method) || !validProto(proto) {
		return nil, malformed("request line " + strconv.Quote(s))
	}
	u, err := parseRequestTarget(method, target)
	if err != nil {
		return nil, err
	}
	return &Request{Method: method, URL: u, Proto: proto}, nil
}

// parseRequestTarget handles the four target forms of RFC 9112 §3.2.
func parseRequestTarget(method, target string) (*url.URL, error) {
	if method == "CONNECT" {
		// authority-form: host:port with no scheme, userinfo or path. Parse
		// it the way net/http does, as the authority of a URL, which also
		// rejects control characters and invalid host syntax.
		if strings.ContainsAny(target, "/?#@") {
			return nil, malformed("CONNECT target " + strconv.Quote(target))
		}
		u, err := url.ParseRequestURI("http://" + target)
		if err != nil || u.Host != target || u.Hostname() == "" {
			return nil, malformed("CONNECT target " + strconv.Quote(target))
		}
		return &url.URL{Host: target}, nil
	}
	if target == "*" {
		return &url.URL{Path: "*"}, nil
	}
	for i := 0; i < len(target); i++ {
		if c := target[i]; c <= ' ' || c == 0x7f {
			return nil, malformed("request target " + strconv.Quote(target))
		}
	}
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return nil, malformed("request target " + strconv.Quote(target))
	}
	// absolute-form must carry an authority ("http://host/..."); a scheme
	// with an opaque part ("mailto:x") is not a request target.
	if u.Scheme != "" && (u.Host == "" || u.Opaque != "") {
		return nil, malformed("request target " + strconv.Quote(target))
	}
	return u, nil
}

// parseStatusLine parses "HTTP/x.y 200 Reason". The reason phrase may be
// empty, with or without the space before it.
func parseStatusLine(line []byte) (*Response, error) {
	s := string(line)
	proto, rest, ok := strings.Cut(s, " ")
	if !ok || !validProto(proto) {
		return nil, malformed("status line " + strconv.Quote(s))
	}
	code, reason, _ := strings.Cut(rest, " ")
	if len(code) != 3 || !ascii.IsDigit(code[0]) || !ascii.IsDigit(code[1]) || !ascii.IsDigit(code[2]) {
		return nil, malformed("status line " + strconv.Quote(s))
	}
	n, _ := strconv.Atoi(code)
	if n < 100 {
		return nil, malformed("status line " + strconv.Quote(s))
	}
	for i := 0; i < len(reason); i++ {
		if !ascii.IsFieldVchar(reason[i]) {
			return nil, malformed("status line " + strconv.Quote(s))
		}
	}
	return &Response{Proto: proto, StatusCode: n, StatusText: reason}, nil
}

// validProto reports whether s is "HTTP/" followed by DIGIT "." DIGIT.
func validProto(s string) bool {
	return len(s) == 8 && s[:5] == "HTTP/" && ascii.IsDigit(s[5]) && s[6] == '.' && ascii.IsDigit(s[7])
}

// responseHasBody applies RFC 9112 §6.3 rules 1 and 2.
func responseHasBody(code int, requestMethod string) bool {
	if requestMethod == "HEAD" {
		return false
	}
	if code/100 == 1 || code == 204 || code == 304 {
		return false
	}
	if requestMethod == "CONNECT" && code/100 == 2 {
		return false
	}
	return true
}

// bodyReader returns a reader framing the message body per RFC 9112 §6.3
// rules 3 to 8. For a request with neither framing header it returns nil;
// for a response it returns br itself (body until close).
func bodyReader(br *bufio.Reader, hs Headers, isRequest bool) (r io.Reader, chunked bool, err error) {
	if te := hs.TransferEncoding(); len(te) > 0 {
		if te[len(te)-1] != "chunked" {
			// Without chunked as the final coding the length is unknowable.
			return nil, false, malformed("Transfer-Encoding without final chunked coding")
		}
		if slices.Contains(te[:len(te)-1], "chunked") {
			return nil, false, malformed("Transfer-Encoding lists chunked more than once")
		}
		// Content-Length alongside Transfer-Encoding is a smuggling signal;
		// RFC 9112 §6.1 says Transfer-Encoding wins for a recipient that
		// does not reject the message. We follow it and leave the caller to
		// notice both headers.
		return &chunkedReader{br: br}, true, nil
	}
	if hs.Has("Content-Length") {
		n, ok := hs.ContentLength()
		if !ok {
			return nil, false, malformed("Content-Length " + strconv.Quote(hs.Get("Content-Length")))
		}
		return io.LimitReader(br, n), false, nil
	}
	if isRequest {
		return nil, false, nil
	}
	return br, false, nil
}

// readBody drains body into a bounded capture, then reads trailers if the
// body was chunked. A nil body means the message has none.
func readBody(br *bufio.Reader, body io.Reader, chunked bool, opts *ReadOptions) (Body, Headers, error) {
	if body == nil {
		return Body{}, nil, nil
	}
	c := NewCapture(opts.bodyLimit())
	_, err := io.Copy(c, body)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return c.Body(), nil, fmt.Errorf("httpkit: body ended early: %w", io.ErrUnexpectedEOF)
		}
		return c.Body(), nil, err
	}
	if lim, ok := body.(*io.LimitedReader); ok && lim.N > 0 {
		return c.Body(), nil, fmt.Errorf("httpkit: body ended early: %w", io.ErrUnexpectedEOF)
	}
	if !chunked {
		return c.Body(), nil, nil
	}
	lr := &lineReader{br: br, remaining: opts.headerLimit()}
	trailer, err := lr.headers()
	if err != nil {
		return c.Body(), nil, err
	}
	return c.Body(), trailer, nil
}

// maxChunkLineBytes bounds a chunk-size line, including any chunk
// extensions, which this reader ignores.
const maxChunkLineBytes = 4096

// chunkedReader decodes the chunked transfer coding (RFC 9112 §7.1). It
// stops before the trailer section, leaving it in br for the caller.
// Errors for bad syntax wrap ErrMalformed; a stream that ends inside the
// body yields io.ErrUnexpectedEOF.
type chunkedReader struct {
	br   *bufio.Reader
	n    uint64 // bytes left in the current chunk
	done bool
	err  error
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	for c.err == nil {
		if c.done {
			return 0, io.EOF
		}
		if c.n == 0 {
			c.err = c.beginChunk()
			continue
		}
		if len(p) == 0 {
			return 0, nil
		}
		n, err := c.br.Read(p[:min(uint64(len(p)), c.n)])
		c.n -= uint64(n) //nolint:gosec // n is a read count, never negative
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			c.err = err
			return n, err
		}
		if c.n == 0 {
			c.err = c.endChunk()
		}
		return n, c.err
	}
	return 0, c.err
}

// beginChunk reads a chunk-size line. A size of zero marks the last chunk.
func (c *chunkedReader) beginChunk() error {
	lr := lineReader{br: c.br, remaining: maxChunkLineBytes}
	line, err := lr.line()
	if err != nil {
		return chunkLineErr(err)
	}
	if lr.unterminated {
		return io.ErrUnexpectedEOF
	}
	// chunk-size [ chunk-ext ]: extensions are ignored, as RFC 9112 §7.1.1
	// allows.
	if i := bytes.IndexByte(line, ';'); i >= 0 {
		line = line[:i]
	}
	line = bytes.TrimRight(line, " \t")
	if len(line) == 0 || len(line) > 16 {
		return malformed("chunk size " + strconv.Quote(string(line)))
	}
	var size uint64
	for _, ch := range line {
		var d byte
		switch {
		case '0' <= ch && ch <= '9':
			d = ch - '0'
		case 'a' <= ch && ch <= 'f':
			d = ch - 'a' + 10
		case 'A' <= ch && ch <= 'F':
			d = ch - 'A' + 10
		default:
			return malformed("chunk size " + strconv.Quote(string(line)))
		}
		size = size<<4 | uint64(d)
	}
	if size > 1<<62 {
		return malformed("chunk size " + strconv.Quote(string(line)) + " too large")
	}
	if size == 0 {
		c.done = true
		return nil
	}
	c.n = size
	return nil
}

// endChunk consumes the CRLF that follows chunk data.
func (c *chunkedReader) endChunk() error {
	lr := lineReader{br: c.br, remaining: 2}
	line, err := lr.line()
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			return malformed("chunk data not followed by CRLF")
		}
		return chunkLineErr(err)
	}
	if lr.unterminated {
		return io.ErrUnexpectedEOF
	}
	if len(line) != 0 {
		return malformed("chunk data not followed by CRLF")
	}
	return nil
}

func chunkLineErr(err error) error {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return io.ErrUnexpectedEOF
	case errors.Is(err, ErrTooLarge):
		return malformed("chunk size line too long")
	}
	return err
}
