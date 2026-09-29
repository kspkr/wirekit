package httpkit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/kspkr/wirekit/internal/ascii"
)

// Request is an HTTP request as observed on the wire or converted from
// net/http.
//
// The zero value is not a usable request; at minimum Method and URL should
// be set. Request serializes to JSON with URL as a string.
type Request struct {
	// Method is the request method, e.g. "GET". It is not normalized.
	Method string
	// URL is the request target. For a request read from the wire in
	// origin-form ("GET /path HTTP/1.1") only Path and RawQuery are set;
	// Host carries the authority. For CONNECT, URL.Host is the tunnel target.
	URL *url.URL
	// Proto is the protocol version as written, e.g. "HTTP/1.1".
	Proto string
	// Host is the authority the request is addressed to: the Host header
	// for HTTP/1.x, or the :authority for HTTP/2.
	Host string
	// Headers are the header fields in wire order.
	Headers Headers
	// Body is the request body as captured.
	Body Body
	// Trailer holds any trailer fields received after a chunked body.
	Trailer Headers
}

// Response is an HTTP response as observed on the wire or converted from
// net/http.
type Response struct {
	// Proto is the protocol version as written, e.g. "HTTP/1.1".
	Proto string
	// StatusCode is the three-digit status code.
	StatusCode int
	// StatusText is the reason phrase as sent by the server ("OK"), which
	// may be empty.
	StatusText string
	// Headers are the header fields in wire order.
	Headers Headers
	// Body is the response body as captured.
	Body Body
	// Trailer holds any trailer fields received after a chunked body.
	Trailer Headers
}

// Query returns the parsed query parameters of the request URL. Malformed
// escapes are kept undecoded; use ParseQuery on URL.RawQuery to see errors.
func (r *Request) Query() Params {
	if r.URL == nil {
		return nil
	}
	ps, _ := ParseQuery(r.URL.RawQuery)
	return ps
}

// Cookies returns the cookies carried by the Cookie headers.
func (r *Request) Cookies() []Cookie { return r.Headers.Cookies() }

// ContentType returns the parsed Content-Type header.
func (r *Request) ContentType() ContentType { return r.Headers.ContentType() }

// Clone returns a copy with its own Headers, URL and Trailer. Body.Data is
// shared, not copied.
func (r *Request) Clone() *Request {
	c := *r
	if r.URL != nil {
		u := *r.URL
		if r.URL.User != nil {
			user := *r.URL.User
			u.User = &user
		}
		c.URL = &u
	}
	c.Headers = r.Headers.Clone()
	c.Trailer = r.Trailer.Clone()
	return &c
}

// SetCookies returns the cookies set by the Set-Cookie headers.
func (r *Response) SetCookies() []SetCookie { return r.Headers.SetCookies() }

// ContentType returns the parsed Content-Type header.
func (r *Response) ContentType() ContentType { return r.Headers.ContentType() }

// Status returns the status line text in net/http's form: "200 OK". When
// StatusText is empty the standard reason phrase is used.
func (r *Response) Status() string {
	text := r.StatusText
	if text == "" {
		text = http.StatusText(r.StatusCode)
	}
	if text == "" {
		return strconv.Itoa(r.StatusCode)
	}
	return strconv.Itoa(r.StatusCode) + " " + text
}

// Clone returns a copy with its own Headers and Trailer. Body.Data is
// shared, not copied.
func (r *Response) Clone() *Response {
	c := *r
	c.Headers = r.Headers.Clone()
	c.Trailer = r.Trailer.Clone()
	return &c
}

// StatusClass returns the class of a status code: 1 for 1xx through 5 for
// 5xx, or 0 for a code outside 100-599.
func StatusClass(code int) int {
	if code < 100 || code > 599 {
		return 0
	}
	return code / 100
}

// requestJSON is the wire shape of Request.
type requestJSON struct {
	Method  string  `json:"method"`
	URL     string  `json:"url"`
	Proto   string  `json:"proto,omitempty"`
	Host    string  `json:"host,omitempty"`
	Headers Headers `json:"headers"`
	Body    Body    `json:"body"`
	Trailer Headers `json:"trailer,omitempty"`
}

// MarshalJSON encodes the request with URL as a string.
func (r Request) MarshalJSON() ([]byte, error) {
	j := requestJSON{
		Method:  r.Method,
		Proto:   r.Proto,
		Host:    r.Host,
		Headers: r.Headers,
		Body:    r.Body,
		Trailer: r.Trailer,
	}
	if r.URL != nil {
		j.URL = r.URL.String()
	}
	if j.Headers == nil {
		j.Headers = Headers{}
	}
	return json.Marshal(j)
}

// UnmarshalJSON decodes the form produced by MarshalJSON.
func (r *Request) UnmarshalJSON(b []byte) error {
	var j requestJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	var u *url.URL
	if j.URL != "" {
		var err error
		if u, err = url.Parse(j.URL); err != nil {
			return err
		}
	}
	*r = Request{
		Method:  j.Method,
		URL:     u,
		Proto:   j.Proto,
		Host:    j.Host,
		Headers: j.Headers,
		Body:    j.Body,
		Trailer: j.Trailer,
	}
	return nil
}

// responseJSON is the wire shape of Response.
type responseJSON struct {
	Proto      string  `json:"proto,omitempty"`
	StatusCode int     `json:"statusCode"`
	StatusText string  `json:"statusText,omitempty"`
	Headers    Headers `json:"headers"`
	Body       Body    `json:"body"`
	Trailer    Headers `json:"trailer,omitempty"`
}

// MarshalJSON encodes the response.
func (r Response) MarshalJSON() ([]byte, error) {
	j := responseJSON(r)
	if j.Headers == nil {
		j.Headers = Headers{}
	}
	return json.Marshal(j)
}

// UnmarshalJSON decodes the form produced by MarshalJSON.
func (r *Response) UnmarshalJSON(b []byte) error {
	var j responseJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	*r = Response(j)
	return nil
}

// FromRequest converts a net/http request. The body is not read: Body is
// left empty so the caller can keep streaming it, typically through a
// [Capture]. Header order is lost by net/http, so Headers are sorted by
// name. URL is copied.
func FromRequest(req *http.Request) *Request {
	r := &Request{
		Method:  req.Method,
		Proto:   req.Proto,
		Host:    req.Host,
		Headers: FromStd(req.Header),
		Trailer: FromStd(req.Trailer),
	}
	if req.URL != nil {
		u := *req.URL
		r.URL = &u
	}
	if r.Host == "" && r.URL != nil {
		r.Host = r.URL.Host
	}
	return r
}

// FromResponse converts a net/http response. The body is not read: Body is
// left empty so the caller can keep streaming it. Headers are sorted by
// name because net/http does not keep their order.
func FromResponse(resp *http.Response) *Response {
	r := &Response{
		Proto:      resp.Proto,
		StatusCode: resp.StatusCode,
		Headers:    FromStd(resp.Header),
		Trailer:    FromStd(resp.Trailer),
	}
	// resp.Status is "200 OK"; keep only the reason phrase.
	if _, text, ok := strings.Cut(resp.Status, " "); ok {
		r.StatusText = text
	}
	return r
}

// ToStd converts the request to a net/http request suitable for sending
// with an http.Client or serving to a handler. The body is the retained
// Data; if the body was truncated only the retained prefix is sent. It
// fails when URL is nil.
func (r *Request) ToStd() (*http.Request, error) {
	if r.URL == nil {
		return nil, errors.New("httpkit: request has no URL")
	}
	major, minor := protoVersion(r.Proto)
	u := *r.URL
	req := &http.Request{
		Method:        r.Method,
		URL:           &u,
		Proto:         r.Proto,
		ProtoMajor:    major,
		ProtoMinor:    minor,
		Host:          r.Host,
		Header:        r.Headers.ToStd(),
		Body:          io.NopCloser(bytes.NewReader(r.Body.Data)),
		ContentLength: int64(len(r.Body.Data)),
		Trailer:       r.Trailer.ToStd(),
	}
	if req.Proto == "" {
		req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/1.1", 1, 1
	}
	if req.Host == "" {
		req.Host = req.Header.Get("Host")
	}
	// net/http carries the authority in Request.Host, not the header map.
	req.Header.Del("Host")
	if len(req.Trailer) == 0 {
		req.Trailer = nil
	}
	return req, nil
}

// ToStd converts the response to a net/http response. The body is the
// retained Data.
func (r *Response) ToStd() *http.Response {
	major, minor := protoVersion(r.Proto)
	resp := &http.Response{
		Status:        r.Status(),
		StatusCode:    r.StatusCode,
		Proto:         r.Proto,
		ProtoMajor:    major,
		ProtoMinor:    minor,
		Header:        r.Headers.ToStd(),
		Body:          io.NopCloser(bytes.NewReader(r.Body.Data)),
		ContentLength: int64(len(r.Body.Data)),
		Trailer:       r.Trailer.ToStd(),
	}
	if resp.Proto == "" {
		resp.Proto, resp.ProtoMajor, resp.ProtoMinor = "HTTP/1.1", 1, 1
	}
	if len(resp.Trailer) == 0 {
		resp.Trailer = nil
	}
	return resp
}

// protoVersion extracts the major and minor version from "HTTP/x.y". It
// returns 1, 1 for anything it cannot parse.
func protoVersion(proto string) (major, minor int) {
	if len(proto) == 8 && strings.HasPrefix(proto, "HTTP/") && ascii.IsDigit(proto[5]) && proto[6] == '.' && ascii.IsDigit(proto[7]) {
		return int(proto[5] - '0'), int(proto[7] - '0')
	}
	if proto == "HTTP/2" || proto == "HTTP/3" {
		return int(proto[5] - '0'), 0
	}
	return 1, 1
}
