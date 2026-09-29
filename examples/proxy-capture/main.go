// Command proxy-capture shows how a proxy or middleware records traffic
// with WireKit: it converts net/http values to the httpkit model, captures
// a bounded prefix of each body while streaming it through, and serializes
// the result as JSON.
//
//	go run ./examples/proxy-capture
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/kspkr/wirekit/httpkit"
)

// exchange is what a traffic tool might store per request.
type exchange struct {
	Request  *httpkit.Request  `json:"request"`
	Response *httpkit.Response `json:"response"`
}

// capture wraps a handler and records what passes through it. Only the
// first maxBody bytes of each body are kept; the rest is counted.
func capture(next http.Handler, maxBody int64, sink func(exchange)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := httpkit.FromRequest(r)
		reqCap := httpkit.NewCapture(maxBody)
		r.Body = struct {
			io.Reader
			io.Closer
		}{reqCap.TeeReader(r.Body), r.Body}

		rec := &recorder{ResponseWriter: w, cap: httpkit.NewCapture(maxBody), status: http.StatusOK}
		next.ServeHTTP(rec, r)

		req.Body = reqCap.Body()
		resp := &httpkit.Response{
			Proto:      r.Proto,
			StatusCode: rec.status,
			Headers:    httpkit.FromStd(w.Header()),
			Body:       rec.cap.Body(),
		}
		sink(exchange{Request: req, Response: resp})
	})
}

// recorder tees the response body into a Capture.
type recorder struct {
	http.ResponseWriter
	cap    *httpkit.Capture
	status int
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(p []byte) (int, error) {
	r.cap.Write(p)
	return r.ResponseWriter.Write(p)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "s3cr3t", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		fmt.Fprintf(w, `{"echoed":%d,"path":%q}`, len(body), r.URL.Path)
	})

	var captured []exchange
	srv := httptest.NewServer(capture(app, 64, func(x exchange) { captured = append(captured, x) }))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/items?limit=10", "text/plain", strings.NewReader(strings.Repeat("payload ", 50)))
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	for _, x := range captured {
		fmt.Printf("%s %s -> %d\n", x.Request.Method, x.Request.URL.RequestURI(), x.Response.StatusCode)
		fmt.Printf("request body: %d bytes, %d captured, truncated=%v\n", x.Request.Body.Size, x.Request.Body.Captured(), x.Request.Body.Truncated)
		for _, c := range x.Response.SetCookies() {
			fmt.Printf("response sets cookie %q (HttpOnly=%v)\n", c.Name, c.HttpOnly)
		}
		out, _ := json.MarshalIndent(x, "", "  ")
		fmt.Println(string(out))
	}
	return nil
}
