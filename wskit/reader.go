package wskit

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// DefaultMaxPayload is the payload limit a Reader uses when none is given.
const DefaultMaxPayload = 16 << 20

// Reader decodes frames from a byte stream one at a time.
//
// A Reader refuses frames whose declared payload exceeds its limit before
// allocating anything, so a peer cannot make it allocate arbitrary memory.
// It is not safe for concurrent use.
type Reader struct {
	br         *bufio.Reader
	maxPayload int64
	err        error
}

// NewReader returns a Reader over r that rejects frames with payloads
// larger than maxPayload bytes. A maxPayload of zero or less means
// DefaultMaxPayload. If r is not already buffered it is wrapped in a
// bufio.Reader, so r should not be read from directly afterwards.
func NewReader(r io.Reader, maxPayload int64) *Reader {
	if maxPayload <= 0 {
		maxPayload = DefaultMaxPayload
	}
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	return &Reader{br: br, maxPayload: maxPayload}
}

// ReadFrame reads and decodes the next frame. The returned Payload is owned
// by the caller.
//
// At a clean end of stream the error is io.EOF. If the stream ends inside a
// frame the error wraps io.ErrUnexpectedEOF. A frame whose payload exceeds
// the limit yields an error wrapping ErrTooLarge; the Reader is then
// unusable, since the stream position is inside the oversize frame. Any
// error is sticky.
func (r *Reader) ReadFrame() (Frame, error) {
	if r.err != nil {
		return Frame{}, r.err
	}
	f, err := r.readFrame()
	if err != nil {
		r.err = err
	}
	return f, err
}

func (r *Reader) readFrame() (Frame, error) {
	var hdr [14]byte
	if _, err := io.ReadFull(r.br, hdr[:2]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return Frame{}, fmt.Errorf("wskit: stream ended inside a frame header: %w", io.ErrUnexpectedEOF)
		}
		return Frame{}, err // io.EOF at a frame boundary, or a read error
	}
	// Work out the rest of the header from the first two bytes.
	need := 2
	switch hdr[1] & 0x7f {
	case 126:
		need += 2
	case 127:
		need += 8
	}
	if hdr[1]&0x80 != 0 {
		need += 4
	}
	if need > 2 {
		if _, err := io.ReadFull(r.br, hdr[2:need]); err != nil {
			return Frame{}, fmt.Errorf("wskit: stream ended inside a frame header: %w", unexpectedEOF(err))
		}
	}
	h, length, err := parseHeader(hdr[:need])
	if err != nil {
		return Frame{}, err
	}
	if length > uint64(r.maxPayload) { //nolint:gosec // NewReader ensures maxPayload > 0
		return Frame{}, fmt.Errorf("%w: payload of %d bytes exceeds limit of %d", ErrTooLarge, length, r.maxPayload)
	}
	f := h.frame
	if length > 0 {
		f.Payload = make([]byte, length)
		if _, err := io.ReadFull(r.br, f.Payload); err != nil {
			return Frame{}, fmt.Errorf("wskit: stream ended inside a frame payload: %w", unexpectedEOF(err))
		}
		if f.Masked {
			Mask(f.Payload, f.MaskKey, 0)
		}
	}
	return f, nil
}

// unexpectedEOF turns io.EOF into io.ErrUnexpectedEOF and leaves other
// errors alone.
func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
