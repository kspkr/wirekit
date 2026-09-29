package wskit

import (
	"bytes"
	"errors"
	"testing"
)

func mustParse(t *testing.T, b []byte) Frame {
	t.Helper()
	f, _, err := ParseFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestAssemblerFragmentsAndControl(t *testing.T) {
	var a Assembler
	m, err := a.Push(mustParse(t, rfcFragment1))
	if err != nil || m != nil || !a.Pending() {
		t.Fatalf("fragment1: %v %v pending %v", m, err, a.Pending())
	}
	// A control frame in the middle is delivered immediately.
	m, err = a.Push(mustParse(t, rfcPing))
	if err != nil || m == nil || m.Type != OpPing || string(m.Data) != "Hello" || m.Frames != 1 || !m.IsControl() {
		t.Fatalf("ping: %+v %v", m, err)
	}
	if !a.Pending() {
		t.Error("control frame ended the fragmented message")
	}
	m, err = a.Push(mustParse(t, rfcFragment2))
	if err != nil || m == nil {
		t.Fatalf("fragment2: %v %v", m, err)
	}
	if m.Type != OpText || string(m.Data) != "Hello" || m.Frames != 2 || m.Compressed || m.IsControl() {
		t.Errorf("message = %+v", m)
	}
	if a.Pending() {
		t.Error("still pending after FIN")
	}
	if err := m.Validate(); err != nil {
		t.Errorf("Validate = %v", err)
	}

	// Single-frame message aliases the payload; fragmented one does not.
	f := mustParse(t, rfcHello)
	m, _ = a.Push(f)
	if &m.Data[0] != &f.Payload[0] {
		t.Error("single-frame message should alias payload")
	}
	first := Frame{Opcode: OpBinary, Payload: []byte("ab")}
	a.Push(first)
	m, _ = a.Push(Frame{FIN: true, Opcode: OpContinuation, Payload: []byte("cd")})
	first.Payload[0] = 'X'
	if string(m.Data) != "abcd" {
		t.Errorf("fragmented message shares payload: %q", m.Data)
	}
	// Control payload is copied.
	ping := Frame{FIN: true, Opcode: OpPing, Payload: []byte("p")}
	m, _ = a.Push(ping)
	ping.Payload[0] = 'q'
	if string(m.Data) != "p" {
		t.Error("control message shares payload")
	}
	// Empty control frame has nil data.
	if m, _ := a.Push(Frame{FIN: true, Opcode: OpPong}); m.Data != nil {
		t.Error("empty pong has non-nil data")
	}
}

func TestAssemblerCompressedFlag(t *testing.T) {
	var a Assembler
	m, _ := a.Push(Frame{FIN: true, RSV1: true, Opcode: OpText, Payload: []byte{0xff, 0xfe}})
	if !m.Compressed {
		t.Error("RSV1 not reported")
	}
	if err := m.Validate(); err != nil {
		t.Errorf("compressed text should skip UTF-8 check: %v", err)
	}
	a.Push(Frame{RSV1: true, Opcode: OpText})
	m, _ = a.Push(Frame{FIN: true, Opcode: OpContinuation}) // RSV1 only on the first frame
	if !m.Compressed {
		t.Error("RSV1 on first fragment not carried to the message")
	}
}

func TestAssemblerProtocolErrors(t *testing.T) {
	var a Assembler
	if _, err := a.Push(Frame{FIN: true, Opcode: OpContinuation}); !errors.Is(err, ErrProtocol) {
		t.Errorf("stray continuation: %v", err)
	}
	a.Push(Frame{Opcode: OpText, Payload: []byte("a")})
	if _, err := a.Push(Frame{FIN: true, Opcode: OpBinary}); !errors.Is(err, ErrProtocol) {
		t.Errorf("interleaved data frame: %v", err)
	}
	if a.Pending() {
		t.Error("in-progress message kept after error")
	}
	if _, err := a.Push(Frame{FIN: true, Opcode: 0x5}); !errors.Is(err, ErrProtocol) {
		t.Errorf("reserved opcode: %v", err)
	}
	a.Push(Frame{Opcode: OpText})
	a.Reset()
	if a.Pending() {
		t.Error("Reset did not clear")
	}
}

func TestAssemblerLimits(t *testing.T) {
	a := Assembler{MaxMessage: 10}
	if _, err := a.Push(Frame{FIN: true, Opcode: OpBinary, Payload: make([]byte, 11)}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("single frame over limit: %v", err)
	}
	if m, err := a.Push(Frame{FIN: true, Opcode: OpBinary, Payload: make([]byte, 10)}); err != nil || m == nil {
		t.Errorf("single frame at limit: %v", err)
	}
	a.Push(Frame{Opcode: OpBinary, Payload: make([]byte, 6)})
	if _, err := a.Push(Frame{Opcode: OpContinuation, Payload: make([]byte, 5)}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("fragments over limit: %v", err)
	}
	if a.Pending() {
		t.Error("oversize message kept")
	}
	// Default limit applies to the zero value.
	var d Assembler
	if _, err := d.Push(Frame{FIN: true, Opcode: OpBinary, Payload: make([]byte, 1000)}); err != nil {
		t.Errorf("default limit: %v", err)
	}
}

func TestMessageValidateAndCloseInfo(t *testing.T) {
	if err := (&Message{Type: OpText, Data: []byte{0xff}}).Validate(); !errors.Is(err, ErrProtocol) {
		t.Errorf("bad utf8 text: %v", err)
	}
	if err := (&Message{Type: OpBinary, Data: []byte{0xff}}).Validate(); err != nil {
		t.Errorf("binary: %v", err)
	}
	if err := (&Message{Type: OpClose, Data: []byte{1}}).Validate(); !errors.Is(err, ErrProtocol) {
		t.Errorf("bad close: %v", err)
	}
	m := &Message{Type: OpClose, Data: ClosePayload(CloseNormal, "ok")}
	code, reason, err := m.CloseInfo()
	if err != nil || code != CloseNormal || reason != "ok" {
		t.Errorf("CloseInfo = %v %q %v", code, reason, err)
	}
	if _, _, err := (&Message{Type: OpText}).CloseInfo(); !errors.Is(err, ErrProtocol) {
		t.Errorf("CloseInfo on text: %v", err)
	}
}

func FuzzAssembler(f *testing.F) {
	var seed []byte
	seed = append(seed, rfcFragment1...)
	seed = append(seed, rfcPing...)
	seed = append(seed, rfcFragment2...)
	f.Add(seed)
	f.Add(rfcHelloMasked)
	f.Fuzz(func(t *testing.T, data []byte) {
		a := Assembler{MaxMessage: 1 << 16}
		for len(data) > 0 {
			fr, n, err := ParseFrame(data)
			if err != nil {
				return
			}
			data = data[n:]
			m, err := a.Push(fr)
			if err != nil {
				if a.Pending() {
					t.Fatal("pending after error")
				}
				continue
			}
			if m != nil {
				_ = m.Validate()
				if int64(len(m.Data)) > a.MaxMessage {
					t.Fatalf("message of %d exceeds limit", len(m.Data))
				}
			}
		}
	})
}

func BenchmarkAssemblerFragmented(b *testing.B) {
	frames := []Frame{
		{Opcode: OpText, Payload: bytes.Repeat([]byte("a"), 1024)},
		{Opcode: OpContinuation, Payload: bytes.Repeat([]byte("b"), 1024)},
		{FIN: true, Opcode: OpContinuation, Payload: bytes.Repeat([]byte("c"), 1024)},
	}
	var a Assembler
	b.SetBytes(3 * 1024)
	b.ReportAllocs()
	for b.Loop() {
		for _, f := range frames {
			if _, err := a.Push(f); err != nil {
				b.Fatal(err)
			}
		}
	}
}
