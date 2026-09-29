package wskit

import "fmt"

// DefaultMaxMessage is the message size limit an Assembler uses when none
// is given.
const DefaultMaxMessage = 64 << 20

// Message is a complete WebSocket message: a text or binary message
// reassembled from one or more frames, or a single control frame.
type Message struct {
	// Type is OpText or OpBinary for data messages, or the control opcode
	// for control messages.
	Type Opcode
	// Data is the payload. For a text message it should be UTF-8; see
	// Validate.
	Data []byte
	// Compressed is set when the first frame had RSV1 set, which under
	// permessage-deflate means Data is deflate-compressed.
	Compressed bool
	// Frames is the number of frames the message was carried in.
	Frames int
}

// IsControl reports whether the message is a control message (close, ping
// or pong).
func (m *Message) IsControl() bool { return m.Type.IsControl() }

// CloseInfo interprets a Close message's payload; see ParseClosePayload.
func (m *Message) CloseInfo() (CloseCode, string, error) {
	if m.Type != OpClose {
		return 0, "", fmt.Errorf("%w: %s message has no close status", ErrProtocol, m.Type)
	}
	return ParseClosePayload(m.Data)
}

// Validate reports the RFC 6455 rules the message breaks: a text message
// that is not valid UTF-8 (unless it is compressed, in which case the check
// applies after decompression) or a Close message with an invalid payload.
// It returns nil when the message is valid.
func (m *Message) Validate() error {
	switch m.Type {
	case OpText:
		if !m.Compressed && !validUTF8(m.Data) {
			return fmt.Errorf("%w: text message is not valid UTF-8", ErrProtocol)
		}
	case OpClose:
		_, _, err := ParseClosePayload(m.Data)
		return err
	}
	return nil
}

// Assembler reassembles messages from a sequence of frames in one
// direction of a connection.
//
// Push each frame in order. Data frames are accumulated until a frame with
// FIN completes the message; control frames, which may be interleaved with
// a fragmented message, are returned immediately. The zero value is ready
// to use with DefaultMaxMessage. An Assembler is not safe for concurrent
// use.
type Assembler struct {
	// MaxMessage bounds the size of a reassembled message in bytes. Zero
	// means DefaultMaxMessage.
	MaxMessage int64

	cur *Message
}

// Push adds a frame. It returns a complete message when f finishes one, or
// nil when more fragments are expected.
//
// Errors wrap ErrProtocol when fragmentation rules are broken (a data frame
// arrives while a fragmented message is in progress, a continuation frame
// arrives without one, or the opcode is reserved) and ErrTooLarge when the
// message would exceed MaxMessage. After an error the in-progress message
// is discarded.
//
// Data of a single-frame message aliases f.Payload; data of a fragmented
// message is a fresh buffer. Control messages copy their payload.
func (a *Assembler) Push(f Frame) (*Message, error) {
	if f.Opcode.IsReserved() {
		a.cur = nil
		return nil, fmt.Errorf("%w: reserved opcode %s", ErrProtocol, f.Opcode)
	}
	if f.Opcode.IsControl() {
		var data []byte
		if len(f.Payload) > 0 {
			data = append(make([]byte, 0, len(f.Payload)), f.Payload...)
		}
		return &Message{Type: f.Opcode, Data: data, Frames: 1}, nil
	}

	limit := a.MaxMessage
	if limit <= 0 {
		limit = DefaultMaxMessage
	}
	if f.Opcode == OpContinuation {
		if a.cur == nil {
			return nil, fmt.Errorf("%w: continuation frame without a message in progress", ErrProtocol)
		}
		if int64(len(a.cur.Data))+int64(len(f.Payload)) > limit {
			a.cur = nil
			return nil, fmt.Errorf("%w: fragmented message exceeds limit of %d bytes", ErrTooLarge, limit)
		}
		a.cur.Data = append(a.cur.Data, f.Payload...)
		a.cur.Frames++
		if !f.FIN {
			return nil, nil
		}
		m := a.cur
		a.cur = nil
		return m, nil
	}

	// Text or binary: the first frame of a message.
	if a.cur != nil {
		a.cur = nil
		return nil, fmt.Errorf("%w: new %s frame while a fragmented message is in progress", ErrProtocol, f.Opcode)
	}
	if int64(len(f.Payload)) > limit {
		return nil, fmt.Errorf("%w: message of %d bytes exceeds limit of %d", ErrTooLarge, len(f.Payload), limit)
	}
	if f.FIN {
		return &Message{Type: f.Opcode, Data: f.Payload, Compressed: f.RSV1, Frames: 1}, nil
	}
	a.cur = &Message{
		Type:       f.Opcode,
		Data:       append([]byte(nil), f.Payload...),
		Compressed: f.RSV1,
		Frames:     1,
	}
	return nil, nil
}

// Pending reports whether a fragmented message is in progress.
func (a *Assembler) Pending() bool { return a.cur != nil }

// Reset discards any fragmented message in progress.
func (a *Assembler) Reset() { a.cur = nil }
