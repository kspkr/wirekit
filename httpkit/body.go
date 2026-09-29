package httpkit

import (
	"bytes"
	"io"
	"sync"
)

// Body is the payload of a message as observed by an inspector.
//
// A Body separates what was seen from what was kept: Size counts every byte
// that crossed the wire, while Data holds the prefix that was retained.
// This lets callers bound memory for large bodies (see [Capture]) without
// losing the size. Data is the body after transfer codings (chunking) have
// been removed but before any content coding (gzip and so on) is undone.
//
// Data is shared, not copied, by [Request.Clone] and [Response.Clone]. Treat
// it as read-only once a message is stored.
type Body struct {
	// Data is the retained prefix of the body, encoded as it was on the wire
	// with respect to Content-Encoding. It serializes to JSON as base64.
	Data []byte `json:"data,omitempty"`
	// Size is the total number of body bytes observed, including any that
	// were not retained.
	Size int64 `json:"size"`
	// Truncated is true when Data holds fewer bytes than Size.
	Truncated bool `json:"truncated,omitempty"`
}

// BodyOf returns a Body holding all of data. It does not copy data.
func BodyOf(data []byte) Body {
	return Body{Data: data, Size: int64(len(data))}
}

// Captured returns the number of bytes retained in Data.
func (b Body) Captured() int { return len(b.Data) }

// IsEmpty reports whether no body bytes were observed at all.
func (b Body) IsEmpty() bool { return b.Size == 0 && len(b.Data) == 0 }

// Reader returns a reader over the retained bytes.
func (b Body) Reader() io.Reader { return bytes.NewReader(b.Data) }

// Clone returns a Body with its own copy of Data.
func (b Body) Clone() Body {
	if b.Data != nil {
		b.Data = append([]byte(nil), b.Data...)
	}
	return b
}

// Capture is an io.Writer that keeps the first limit bytes written to it
// and counts the rest. Writes never fail, so a Capture can sit behind an
// io.TeeReader or io.MultiWriter without affecting the stream it observes.
//
// A Capture is safe for concurrent use: one goroutine may write while
// another takes snapshots with [Capture.Body].
type Capture struct {
	mu    sync.Mutex
	limit int64
	buf   []byte
	n     int64
}

// NewCapture returns a Capture that retains at most limit bytes. A limit of
// zero retains nothing and only counts; a negative limit retains
// everything.
func NewCapture(limit int64) *Capture {
	return &Capture{limit: limit}
}

// Write records p. It always returns len(p), nil.
func (c *Capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n += int64(len(p))
	switch {
	case c.limit < 0:
		c.buf = append(c.buf, p...)
	case c.limit > 0:
		if room := c.limit - int64(len(c.buf)); room > 0 {
			c.buf = append(c.buf, p[:min(int64(len(p)), room)]...)
		}
	}
	return len(p), nil
}

// Size returns the number of bytes written so far.
func (c *Capture) Size() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// Body returns a snapshot of what has been captured. The returned Data is
// a private copy, so later writes do not affect it.
func (c *Capture) Body() Body {
	c.mu.Lock()
	defer c.mu.Unlock()
	var data []byte
	if len(c.buf) > 0 {
		data = append(make([]byte, 0, len(c.buf)), c.buf...)
	}
	return Body{Data: data, Size: c.n, Truncated: c.n > int64(len(c.buf))}
}

// TeeReader returns a reader that records everything read from r into c on
// the way through.
func (c *Capture) TeeReader(r io.Reader) io.Reader {
	return io.TeeReader(r, c)
}

// Reset forgets everything captured so far.
func (c *Capture) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = c.buf[:0]
	c.n = 0
}
