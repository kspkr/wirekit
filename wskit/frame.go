package wskit

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// Sentinel errors. Every error returned by this package wraps one of them.
var (
	// ErrIncomplete means more bytes are needed to finish parsing.
	ErrIncomplete = errors.New("wskit: incomplete frame")
	// ErrMalformed means the bytes cannot be a WebSocket frame.
	ErrMalformed = errors.New("wskit: malformed frame")
	// ErrTooLarge means a frame or message exceeds a configured limit.
	ErrTooLarge = errors.New("wskit: frame too large")
	// ErrProtocol means a frame or message parses but breaks an RFC 6455
	// rule that a compliant endpoint must fail the connection for.
	ErrProtocol = errors.New("wskit: protocol violation")
)

// Opcode identifies the kind of a frame.
type Opcode uint8

// The opcodes defined by RFC 6455 §5.2. Values 0x3-0x7 and 0xB-0xF are
// reserved.
const (
	OpContinuation Opcode = 0x0
	OpText         Opcode = 0x1
	OpBinary       Opcode = 0x2
	OpClose        Opcode = 0x8
	OpPing         Opcode = 0x9
	OpPong         Opcode = 0xA
)

// String returns the lower-case name of the opcode ("text", "binary",
// "continuation", "close", "ping", "pong") or "reserved(0xN)".
func (o Opcode) String() string {
	switch o {
	case OpContinuation:
		return "continuation"
	case OpText:
		return "text"
	case OpBinary:
		return "binary"
	case OpClose:
		return "close"
	case OpPing:
		return "ping"
	case OpPong:
		return "pong"
	}
	return fmt.Sprintf("reserved(0x%x)", uint8(o))
}

// IsControl reports whether the opcode is a control opcode (0x8-0xF).
func (o Opcode) IsControl() bool { return o >= 0x8 }

// IsData reports whether the opcode is a data opcode (continuation, text or
// binary).
func (o Opcode) IsData() bool { return o <= OpBinary }

// IsReserved reports whether the opcode has no meaning in RFC 6455.
func (o Opcode) IsReserved() bool {
	return (o >= 0x3 && o <= 0x7) || o >= 0xB
}

// MarshalText implements encoding.TextMarshaler using String.
func (o Opcode) MarshalText() ([]byte, error) { return []byte(o.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler for the names produced
// by String.
func (o *Opcode) UnmarshalText(b []byte) error {
	for _, c := range [...]Opcode{OpContinuation, OpText, OpBinary, OpClose, OpPing, OpPong} {
		if string(b) == c.String() {
			*o = c
			return nil
		}
	}
	var v uint8
	if n, err := fmt.Sscanf(string(b), "reserved(0x%x)", &v); err == nil && n == 1 && v <= 0xF {
		*o = Opcode(v)
		return nil
	}
	return fmt.Errorf("wskit: unknown opcode %q", b)
}

// Frame is one WebSocket frame with its payload unmasked.
type Frame struct {
	// FIN is set on the final fragment of a message.
	FIN bool
	// RSV1, RSV2 and RSV3 are the reserved bits. RSV1 marks a compressed
	// message when permessage-deflate is in use.
	RSV1, RSV2, RSV3 bool
	// Opcode is the frame type.
	Opcode Opcode
	// Masked reports whether the payload was masked on the wire, as frames
	// from a client must be. Payload is always stored unmasked.
	Masked bool
	// MaskKey is the masking key when Masked is set.
	MaskKey [4]byte
	// Payload is the unmasked payload data.
	Payload []byte
}

// MaxControlPayload is the largest payload a control frame may carry
// (RFC 6455 §5.5).
const MaxControlPayload = 125

// ParseFrame decodes the frame at the start of b. It returns the frame and
// the number of bytes it occupied.
//
// If b holds less than a whole frame the error wraps ErrIncomplete and n is
// zero. If the header is invalid (a 64-bit length with its top bit set) the
// error wraps ErrMalformed.
//
// For an unmasked frame, Payload aliases b to avoid a copy; call
// [Frame.Clone] to own it. For a masked frame, Payload is freshly allocated
// and holds the unmasked bytes. ParseFrame does not check RFC 6455 rules
// beyond framing; see [Frame.Validate].
func ParseFrame(b []byte) (f Frame, n int, err error) {
	hdr, length, err := parseHeader(b)
	if err != nil {
		return Frame{}, 0, err
	}
	// parseHeader guarantees hdr.size <= len(b), so the difference is
	// non-negative, and the comparison bounds length by len(b) before it is
	// narrowed to int.
	if uint64(len(b)-hdr.size) < length { //nolint:gosec // see above
		return Frame{}, 0, ErrIncomplete
	}
	f = hdr.frame
	total := hdr.size + int(length) //nolint:gosec // length <= len(b)
	payload := b[hdr.size:total]
	if f.Masked {
		out := make([]byte, len(payload))
		copy(out, payload)
		Mask(out, f.MaskKey, 0)
		payload = out
	}
	if len(payload) > 0 {
		f.Payload = payload
	}
	return f, total, nil
}

// header is a decoded frame header.
type header struct {
	frame Frame // Payload unset
	size  int   // header length in bytes
}

// parseHeader decodes the fixed header, extended length and mask key. It
// returns the payload length separately because it may exceed len(b).
func parseHeader(b []byte) (header, uint64, error) {
	if len(b) < 2 {
		return header{}, 0, ErrIncomplete
	}
	var h header
	h.frame.FIN = b[0]&0x80 != 0
	h.frame.RSV1 = b[0]&0x40 != 0
	h.frame.RSV2 = b[0]&0x20 != 0
	h.frame.RSV3 = b[0]&0x10 != 0
	h.frame.Opcode = Opcode(b[0] & 0x0f)
	h.frame.Masked = b[1]&0x80 != 0
	length := uint64(b[1] & 0x7f)
	h.size = 2
	switch length {
	case 126:
		h.size += 2
	case 127:
		h.size += 8
	}
	if h.frame.Masked {
		h.size += 4
	}
	if len(b) < h.size {
		return header{}, 0, ErrIncomplete
	}
	switch length {
	case 126:
		length = uint64(binary.BigEndian.Uint16(b[2:4]))
	case 127:
		length = binary.BigEndian.Uint64(b[2:10])
		if length>>63 != 0 {
			return header{}, 0, fmt.Errorf("%w: 64-bit payload length has its top bit set", ErrMalformed)
		}
	}
	if h.frame.Masked {
		copy(h.frame.MaskKey[:], b[h.size-4:h.size])
	}
	return h, length, nil
}

// HeaderLen returns the size in bytes of the frame header when encoded:
// 2 to 14 depending on payload length and masking.
func (f *Frame) HeaderLen() int {
	n := 2
	switch l := len(f.Payload); {
	case l > 0xffff:
		n += 8
	case l > 125:
		n += 2
	}
	if f.Masked {
		n += 4
	}
	return n
}

// WireLen returns the encoded size of the frame: header plus payload.
func (f *Frame) WireLen() int { return f.HeaderLen() + len(f.Payload) }

// AppendTo appends the encoded frame to dst and returns the extended slice.
// When Masked is set the payload is masked with MaskKey on the way out;
// Payload itself is not modified.
func (f *Frame) AppendTo(dst []byte) []byte {
	var b0 byte
	if f.FIN {
		b0 |= 0x80
	}
	if f.RSV1 {
		b0 |= 0x40
	}
	if f.RSV2 {
		b0 |= 0x20
	}
	if f.RSV3 {
		b0 |= 0x10
	}
	b0 |= byte(f.Opcode) & 0x0f
	dst = append(dst, b0)

	var b1 byte
	if f.Masked {
		b1 = 0x80
	}
	l := len(f.Payload)
	switch {
	case l > 0xffff:
		dst = append(dst, b1|127)
		dst = binary.BigEndian.AppendUint64(dst, uint64(l))
	case l > 125:
		dst = append(dst, b1|126)
		dst = binary.BigEndian.AppendUint16(dst, uint16(l))
	default:
		dst = append(dst, b1|byte(l))
	}
	if f.Masked {
		dst = append(dst, f.MaskKey[:]...)
		start := len(dst)
		dst = append(dst, f.Payload...)
		Mask(dst[start:], f.MaskKey, 0)
		return dst
	}
	return append(dst, f.Payload...)
}

// Bytes returns the encoded frame.
func (f *Frame) Bytes() []byte {
	return f.AppendTo(make([]byte, 0, f.WireLen()))
}

// WriteTo writes the encoded frame to w. It implements io.WriterTo.
func (f *Frame) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(f.Bytes())
	return int64(n), err
}

// Clone returns a copy of the frame with its own Payload.
func (f Frame) Clone() Frame {
	if f.Payload != nil {
		f.Payload = append(make([]byte, 0, len(f.Payload)), f.Payload...)
	}
	return f
}

// CloseInfo interprets the payload of a Close frame. It returns the status
// code and reason, or an error wrapping ErrProtocol if the payload is
// invalid. For a frame that is not a Close frame the error wraps
// ErrProtocol as well. See ParseClosePayload for the rules.
func (f *Frame) CloseInfo() (CloseCode, string, error) {
	if f.Opcode != OpClose {
		return 0, "", fmt.Errorf("%w: %s frame has no close status", ErrProtocol, f.Opcode)
	}
	return ParseClosePayload(f.Payload)
}

// Validate reports the RFC 6455 rules the frame breaks, as an error
// wrapping ErrProtocol, or nil. It checks:
//
//   - the opcode is not reserved;
//   - RSV2 and RSV3 are clear (RSV1 is not checked, because
//     permessage-deflate legitimately sets it);
//   - a control frame is not fragmented and carries at most 125 bytes;
//   - a Close frame has a valid status code and UTF-8 reason.
//
// It does not check masking, because whether a frame must be masked
// depends on its direction; see [Frame.ValidateDirection]. Several problems
// are joined into one error.
func (f *Frame) Validate() error {
	var errs []error
	if f.Opcode.IsReserved() {
		errs = append(errs, fmt.Errorf("%w: reserved opcode %s", ErrProtocol, f.Opcode))
	}
	if f.RSV2 || f.RSV3 {
		errs = append(errs, fmt.Errorf("%w: RSV2 or RSV3 set without an extension", ErrProtocol))
	}
	if f.Opcode.IsControl() {
		if !f.FIN {
			errs = append(errs, fmt.Errorf("%w: fragmented control frame", ErrProtocol))
		}
		if len(f.Payload) > MaxControlPayload {
			errs = append(errs, fmt.Errorf("%w: control frame payload of %d bytes exceeds %d", ErrProtocol, len(f.Payload), MaxControlPayload))
		}
		if f.Opcode == OpClose {
			if _, _, err := ParseClosePayload(f.Payload); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// ValidateDirection checks the masking rule of RFC 6455 §5.1 in addition
// to everything Validate checks: frames from a client must be masked and
// frames from a server must not be.
func (f *Frame) ValidateDirection(fromClient bool) error {
	err := f.Validate()
	if fromClient && !f.Masked {
		err = errors.Join(err, fmt.Errorf("%w: client frame is not masked", ErrProtocol))
	}
	if !fromClient && f.Masked {
		err = errors.Join(err, fmt.Errorf("%w: server frame is masked", ErrProtocol))
	}
	return err
}

// Mask applies the WebSocket masking algorithm (RFC 6455 §5.3) to b in
// place. offset is the position of b[0] within the frame payload, so a
// payload can be masked or unmasked in pieces. Masking and unmasking are
// the same operation.
func Mask(b []byte, key [4]byte, offset int) {
	// Rotate the key so key32 applies to b[0] regardless of offset, then
	// work eight bytes at a time.
	k := [4]byte{key[offset&3], key[(offset+1)&3], key[(offset+2)&3], key[(offset+3)&3]}
	i := 0
	if len(b) >= 8 {
		k32 := binary.LittleEndian.Uint32(k[:])
		k64 := uint64(k32)<<32 | uint64(k32)
		for ; i+8 <= len(b); i += 8 {
			binary.LittleEndian.PutUint64(b[i:], binary.LittleEndian.Uint64(b[i:])^k64)
		}
	}
	for ; i < len(b); i++ {
		b[i] ^= k[i&3]
	}
}

// validUTF8 is utf8.Valid, kept here so callers of this file read clearly.
func validUTF8(b []byte) bool { return utf8.Valid(b) }
