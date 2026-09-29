package compress

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// DefaultMaxDecoded is the output limit used when a caller passes a limit
// of zero or less.
const DefaultMaxDecoded = 64 << 20

// Sentinel errors.
var (
	// ErrUnsupported means a content coding is not one this package can
	// decode. The error message names the coding.
	ErrUnsupported = errors.New("compress: unsupported content coding")
	// ErrTooLarge means decoding stopped because the output exceeded the
	// limit.
	ErrTooLarge = errors.New("compress: decoded data exceeds limit")
	// ErrCorrupt means the compressed data is malformed. The error also
	// wraps the decoder's own error.
	ErrCorrupt = errors.New("compress: corrupt data")
)

// Supported reports whether coding (case-insensitive) can be decoded.
// "identity" and "" are supported and mean no coding.
func Supported(coding string) bool {
	switch strings.ToLower(strings.TrimSpace(coding)) {
	case "", "identity", "gzip", "x-gzip", "deflate", "br", "zstd":
		return true
	}
	return false
}

// Codings parses a Content-Encoding value into its codings, lower-cased
// and in the order they were applied, dropping empty entries and
// "identity".
func Codings(contentEncoding string) []string {
	var out []string
	for c := range strings.SplitSeq(contentEncoding, ",") {
		c = strings.ToLower(strings.TrimSpace(c))
		if c != "" && c != "identity" {
			out = append(out, c)
		}
	}
	return out
}

// Decode removes the codings named by a Content-Encoding value from data,
// last applied first, and returns the result. limit bounds the output; zero
// or less means DefaultMaxDecoded.
//
// When the value is empty or "identity" data is returned as is. Errors
// wrap ErrUnsupported, ErrTooLarge or ErrCorrupt.
func Decode(contentEncoding string, data []byte, limit int64) ([]byte, error) {
	codings := Codings(contentEncoding)
	if len(codings) == 0 {
		return data, nil
	}
	if limit <= 0 {
		limit = DefaultMaxDecoded
	}
	r, err := NewReader(contentEncoding, bytes.NewReader(data), limit)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	if cerr := r.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// NewReader returns a reader that yields r decoded according to a
// Content-Encoding value, removing stacked codings in the right order.
// limit bounds the total output; zero or less means DefaultMaxDecoded.
// Reads fail with ErrTooLarge once the limit is passed and with an error
// wrapping ErrCorrupt when the data is malformed. Errors from r itself are
// wrapped the same way, since a decoder cannot tell a truncated stream
// from a broken one.
//
// An unsupported coding is reported immediately. Closing the returned
// reader releases decoder resources; it does not close r.
func NewReader(contentEncoding string, r io.Reader, limit int64) (io.ReadCloser, error) {
	codings := Codings(contentEncoding)
	for _, c := range codings {
		if !Supported(c) {
			return nil, fmt.Errorf("%w: %q", ErrUnsupported, c)
		}
	}
	if len(codings) == 0 {
		return io.NopCloser(r), nil
	}
	if limit <= 0 {
		limit = DefaultMaxDecoded
	}
	s := &stack{}
	cur := r
	for _, coding := range slices.Backward(codings) {
		next, err := newDecoder(coding, cur)
		if err != nil {
			_ = s.Close()
			return nil, err
		}
		s.closers = append(s.closers, next)
		cur = next
	}
	s.r = &limitedReader{r: cur, remaining: limit}
	return s, nil
}

// newDecoder wraps r in a decoder for one coding. Header errors are
// returned lazily on Read by the decoders that read a header in Read, and
// eagerly by gzip and zlib, which read it in their constructors; both
// paths report ErrCorrupt.
func newDecoder(coding string, r io.Reader) (io.ReadCloser, error) {
	switch coding {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, corrupt(coding, err)
		}
		return &decoder{coding: coding, r: zr, c: zr}, nil
	case "deflate":
		br := bufio.NewReader(r)
		head, _ := br.Peek(2)
		if looksLikeZlib(head) {
			zr, err := zlib.NewReader(br)
			if err != nil {
				return nil, corrupt(coding, err)
			}
			return &decoder{coding: coding, r: zr, c: zr}, nil
		}
		fr := flate.NewReader(br)
		return &decoder{coding: coding, r: fr, c: fr}, nil
	case "br":
		return &decoder{coding: coding, r: brotli.NewReader(r), c: closerFunc(func() error { return nil })}, nil
	case "zstd":
		zr, err := zstd.NewReader(r,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxMemory(DefaultMaxDecoded),
		)
		if err != nil {
			return nil, corrupt(coding, err)
		}
		return &decoder{coding: coding, r: zr, c: closerFunc(func() error { zr.Close(); return nil })}, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupported, coding)
}

// looksLikeZlib checks the two-byte zlib header: compression method 8
// with a valid FCHECK.
func looksLikeZlib(b []byte) bool {
	return len(b) >= 2 && b[0]&0x0f == 8 && b[0]>>4 <= 7 && (uint16(b[0])<<8|uint16(b[1]))%31 == 0
}

// decoder wraps one decoding stage and translates its errors.
type decoder struct {
	coding string
	r      io.Reader
	c      io.Closer
}

func (d *decoder) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, ErrTooLarge) {
		err = corrupt(d.coding, err)
	}
	return n, err
}

func (d *decoder) Close() error { return d.c.Close() }

// limitedReader fails with ErrTooLarge once more than remaining bytes have
// been produced.
type limitedReader struct {
	r         io.Reader
	remaining int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.remaining < 0 {
		return 0, ErrTooLarge
	}
	// Read one byte past the limit so an output of exactly limit bytes is
	// accepted and anything longer is detected on the same call.
	if int64(len(p)) > l.remaining+1 {
		p = p[:l.remaining+1]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	if l.remaining < 0 {
		return n - 1, ErrTooLarge
	}
	return n, err
}

// stack is the assembled chain of decoders.
type stack struct {
	r       io.Reader
	closers []io.Closer
}

func (s *stack) Read(p []byte) (int, error) { return s.r.Read(p) }

func (s *stack) Close() error {
	var err error
	for _, c := range slices.Backward(s.closers) {
		err = errors.Join(err, c.Close())
	}
	return err
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// corruptError wraps ErrCorrupt and the decoder's own error.
type corruptError struct {
	coding string
	err    error
}

func (e *corruptError) Error() string   { return "compress: " + e.coding + ": " + e.err.Error() }
func (e *corruptError) Unwrap() []error { return []error{ErrCorrupt, e.err} }

func corrupt(coding string, err error) error {
	// io.ErrUnexpectedEOF is what every decoder returns for truncated
	// input; it is corrupt data from the caller's point of view.
	return &corruptError{coding: coding, err: err}
}
