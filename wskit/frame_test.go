package wskit

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Examples from RFC 6455 §5.7.
var (
	rfcHello       = []byte{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}
	rfcHelloMasked = []byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}
	rfcFragment1   = []byte{0x01, 0x03, 0x48, 0x65, 0x6c}
	rfcFragment2   = []byte{0x80, 0x02, 0x6c, 0x6f}
	rfcPing        = []byte{0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}
	rfcPongMasked  = []byte{0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}
)

func TestParseFrameRFCExamples(t *testing.T) {
	f, n, err := ParseFrame(rfcHello)
	if err != nil || n != len(rfcHello) {
		t.Fatalf("hello: %v %d", err, n)
	}
	if !f.FIN || f.Opcode != OpText || f.Masked || string(f.Payload) != "Hello" {
		t.Errorf("hello = %+v", f)
	}
	// Unmasked payload aliases the input.
	if &f.Payload[0] != &rfcHello[2] {
		t.Error("unmasked payload should alias input")
	}

	f, n, err = ParseFrame(rfcHelloMasked)
	if err != nil || n != len(rfcHelloMasked) {
		t.Fatalf("masked: %v %d", err, n)
	}
	if !f.Masked || f.MaskKey != [4]byte{0x37, 0xfa, 0x21, 0x3d} || string(f.Payload) != "Hello" {
		t.Errorf("masked = %+v", f)
	}
	if bytes.Equal(rfcHelloMasked[6:], f.Payload) {
		t.Error("masked input was modified in place")
	}

	f, _, _ = ParseFrame(rfcFragment1)
	if f.FIN || f.Opcode != OpText || string(f.Payload) != "Hel" {
		t.Errorf("fragment1 = %+v", f)
	}
	f, _, _ = ParseFrame(rfcFragment2)
	if !f.FIN || f.Opcode != OpContinuation || string(f.Payload) != "lo" {
		t.Errorf("fragment2 = %+v", f)
	}
	f, _, _ = ParseFrame(rfcPing)
	if f.Opcode != OpPing || string(f.Payload) != "Hello" {
		t.Errorf("ping = %+v", f)
	}
	f, _, _ = ParseFrame(rfcPongMasked)
	if f.Opcode != OpPong || string(f.Payload) != "Hello" {
		t.Errorf("pong = %+v", f)
	}
}

func TestParseFrameLengths(t *testing.T) {
	for _, size := range []int{0, 1, 125, 126, 127, 0xffff, 0x10000, 100000} {
		payload := bytes.Repeat([]byte("x"), size)
		for _, masked := range []bool{false, true} {
			f := Frame{FIN: true, Opcode: OpBinary, Masked: masked, MaskKey: [4]byte{1, 2, 3, 4}, Payload: payload}
			wire := f.Bytes()
			wantHdr := 2
			switch {
			case size > 0xffff:
				wantHdr += 8
			case size > 125:
				wantHdr += 2
			}
			if masked {
				wantHdr += 4
			}
			if f.HeaderLen() != wantHdr || len(wire) != wantHdr+size || f.WireLen() != len(wire) {
				t.Errorf("size %d masked %v: header %d wire %d", size, masked, f.HeaderLen(), len(wire))
			}
			got, n, err := ParseFrame(wire)
			if err != nil || n != len(wire) {
				t.Fatalf("size %d masked %v: %v %d", size, masked, err, n)
			}
			if got.Masked != masked || !bytes.Equal(got.Payload, payload) || (size == 0 && got.Payload != nil) {
				t.Errorf("size %d masked %v: payload mismatch", size, masked)
			}
			// Trailing data is not consumed.
			got2, n2, err := ParseFrame(append(wire, 0xff, 0xff))
			if err != nil || n2 != n || !bytes.Equal(got2.Payload, payload) {
				t.Errorf("size %d masked %v with trailer: %v %d", size, masked, err, n2)
			}
		}
	}
}

func TestParseFrameIncompleteAndMalformed(t *testing.T) {
	full := (&Frame{FIN: true, Opcode: OpText, Masked: true, Payload: []byte("hello world")}).Bytes()
	for i := range len(full) {
		_, n, err := ParseFrame(full[:i])
		if !errors.Is(err, ErrIncomplete) || n != 0 {
			t.Errorf("prefix %d: err=%v n=%d", i, err, n)
		}
	}
	// 16-bit and 64-bit lengths that promise more than is present.
	for _, b := range [][]byte{
		{0x82, 126, 0x01},
		{0x82, 126, 0x01, 0x00, 0x00},
		{0x82, 127, 0, 0, 0, 0, 0, 0},
		{0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0},
		{0x82, 127, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // 2^63-1
		{0x82, 0x80 | 5, 1, 2, 3},
		{},
		{0x81},
	} {
		if _, _, err := ParseFrame(b); !errors.Is(err, ErrIncomplete) {
			t.Errorf("%x: err = %v, want ErrIncomplete", b, err)
		}
	}
	// 64-bit length with the top bit set is malformed, not incomplete.
	if _, _, err := ParseFrame([]byte{0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0}); !errors.Is(err, ErrMalformed) {
		t.Errorf("top bit: err = %v", err)
	}
}

func TestFrameRSVAndReservedOpcodes(t *testing.T) {
	f, _, err := ParseFrame([]byte{0xf3, 0x00}) // FIN + RSV1-3, opcode 3
	if err != nil {
		t.Fatal(err)
	}
	if !f.RSV1 || !f.RSV2 || !f.RSV3 || f.Opcode != 3 || !f.Opcode.IsReserved() {
		t.Errorf("frame = %+v", f)
	}
	err = f.Validate()
	if !errors.Is(err, ErrProtocol) || !strings.Contains(err.Error(), "reserved opcode") || !strings.Contains(err.Error(), "RSV2") {
		t.Errorf("Validate = %v", err)
	}
	if got := f.Bytes(); !bytes.Equal(got, []byte{0xf3, 0x00}) {
		t.Errorf("round trip = %x", got)
	}
	// RSV1 alone is fine.
	if err := (&Frame{FIN: true, RSV1: true, Opcode: OpText}).Validate(); err != nil {
		t.Errorf("RSV1 rejected: %v", err)
	}
}

func TestFrameValidate(t *testing.T) {
	cases := []struct {
		name string
		f    Frame
		want string // substring of the error, "" for valid
	}{
		{"text", Frame{FIN: true, Opcode: OpText, Payload: []byte("hi")}, ""},
		{"fragment", Frame{Opcode: OpBinary}, ""},
		{"ping", Frame{FIN: true, Opcode: OpPing, Payload: make([]byte, 125)}, ""},
		{"close ok", Frame{FIN: true, Opcode: OpClose, Payload: ClosePayload(CloseNormal, "bye")}, ""},
		{"close empty", Frame{FIN: true, Opcode: OpClose}, ""},
		{"fragmented ping", Frame{Opcode: OpPing}, "fragmented control"},
		{"big pong", Frame{FIN: true, Opcode: OpPong, Payload: make([]byte, 126)}, "exceeds 125"},
		{"close one byte", Frame{FIN: true, Opcode: OpClose, Payload: []byte{3}}, "one byte"},
		{"close bad code", Frame{FIN: true, Opcode: OpClose, Payload: ClosePayload(1005, "")}, "not valid"},
		{"close bad utf8", Frame{FIN: true, Opcode: OpClose, Payload: append(ClosePayload(CloseNormal, ""), 0xff)}, "UTF-8"},
		{"reserved 0xb", Frame{FIN: true, Opcode: 0xB}, "reserved"},
	}
	for _, c := range cases {
		err := c.f.Validate()
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if !errors.Is(err, ErrProtocol) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}

	client := Frame{FIN: true, Opcode: OpText, Masked: true}
	server := Frame{FIN: true, Opcode: OpText}
	if err := client.ValidateDirection(true); err != nil {
		t.Errorf("masked client frame: %v", err)
	}
	if err := server.ValidateDirection(false); err != nil {
		t.Errorf("unmasked server frame: %v", err)
	}
	if err := client.ValidateDirection(false); !errors.Is(err, ErrProtocol) {
		t.Errorf("masked server frame accepted: %v", err)
	}
	if err := server.ValidateDirection(true); !errors.Is(err, ErrProtocol) {
		t.Errorf("unmasked client frame accepted: %v", err)
	}
	if err := (&Frame{Opcode: OpPing}).ValidateDirection(true); err == nil || !strings.Contains(err.Error(), "fragmented") || !strings.Contains(err.Error(), "masked") {
		t.Errorf("direction error should include Validate errors: %v", err)
	}
}

func TestFrameCloseInfoAndClone(t *testing.T) {
	f := Frame{FIN: true, Opcode: OpClose, Payload: ClosePayload(CloseGoingAway, "bye")}
	code, reason, err := f.CloseInfo()
	if err != nil || code != CloseGoingAway || reason != "bye" {
		t.Errorf("CloseInfo = %v %q %v", code, reason, err)
	}
	if _, _, err := (&Frame{Opcode: OpText}).CloseInfo(); !errors.Is(err, ErrProtocol) {
		t.Errorf("CloseInfo on text = %v", err)
	}
	c := f.Clone()
	c.Payload[0] = 0xff
	if f.Payload[0] == 0xff {
		t.Error("Clone shares payload")
	}
	if (Frame{}).Clone().Payload != nil {
		t.Error("Clone allocated for nil payload")
	}
}

func TestFrameWriteTo(t *testing.T) {
	f := Frame{FIN: true, Opcode: OpText, Payload: []byte("Hello")}
	var buf bytes.Buffer
	n, err := f.WriteTo(&buf)
	if err != nil || n != int64(len(rfcHello)) || !bytes.Equal(buf.Bytes(), rfcHello) {
		t.Errorf("WriteTo = %d %v %x", n, err, buf.Bytes())
	}
	// Masked serialization matches the RFC example when the key matches.
	m := Frame{FIN: true, Opcode: OpText, Masked: true, MaskKey: [4]byte{0x37, 0xfa, 0x21, 0x3d}, Payload: []byte("Hello")}
	if got := m.Bytes(); !bytes.Equal(got, rfcHelloMasked) {
		t.Errorf("masked Bytes = %x", got)
	}
	if string(m.Payload) != "Hello" {
		t.Error("serialization masked Payload in place")
	}
}

func TestMask(t *testing.T) {
	key := [4]byte{0x37, 0xfa, 0x21, 0x3d}
	for _, size := range []int{0, 1, 3, 7, 8, 9, 15, 16, 17, 100, 1000} {
		want := make([]byte, size)
		for i := range want {
			want[i] = byte(i * 7)
		}
		// Reference implementation.
		ref := append([]byte(nil), want...)
		for i := range ref {
			ref[i] ^= key[i&3]
		}
		got := append([]byte(nil), want...)
		Mask(got, key, 0)
		if !bytes.Equal(got, ref) {
			t.Errorf("size %d: fast path differs", size)
		}
		// Masking in two pieces with an offset gives the same result.
		for split := 0; split <= size; split++ {
			piece := append([]byte(nil), want...)
			Mask(piece[:split], key, 0)
			Mask(piece[split:], key, split)
			if !bytes.Equal(piece, ref) {
				t.Errorf("size %d split %d: offset path differs", size, split)
			}
		}
		Mask(got, key, 0)
		if !bytes.Equal(got, want) {
			t.Errorf("size %d: mask is not its own inverse", size)
		}
	}
}

func TestOpcode(t *testing.T) {
	for op, want := range map[Opcode]string{OpContinuation: "continuation", OpText: "text", OpBinary: "binary", OpClose: "close", OpPing: "ping", OpPong: "pong", 0x3: "reserved(0x3)", 0xF: "reserved(0xf)"} {
		if got := op.String(); got != want {
			t.Errorf("%d.String() = %q", op, got)
		}
		b, _ := op.MarshalText()
		var back Opcode
		if err := back.UnmarshalText(b); err != nil || back != op {
			t.Errorf("%q round trip -> %v, %v", b, back, err)
		}
	}
	var o Opcode
	if err := o.UnmarshalText([]byte("nope")); err == nil {
		t.Error("UnmarshalText(nope) succeeded")
	}
	if !OpClose.IsControl() || OpText.IsControl() || !OpContinuation.IsData() || OpPing.IsData() {
		t.Error("IsControl/IsData wrong")
	}
	for _, op := range []Opcode{3, 4, 5, 6, 7, 0xB, 0xC, 0xD, 0xE, 0xF} {
		if !op.IsReserved() {
			t.Errorf("%d not reserved", op)
		}
	}
	for _, op := range []Opcode{0, 1, 2, 8, 9, 0xA} {
		if op.IsReserved() {
			t.Errorf("%d reserved", op)
		}
	}
}

func FuzzParseFrame(f *testing.F) {
	f.Add(rfcHello)
	f.Add(rfcHelloMasked)
	f.Add(rfcFragment1)
	f.Add([]byte{0x82, 126, 0x01, 0x00})
	f.Add([]byte{0x82, 127, 0, 0, 0, 0, 0, 0, 0, 5, 1, 2, 3, 4, 5})
	f.Add([]byte{0x88, 0x02, 0x03, 0xe8})
	f.Fuzz(func(t *testing.T, data []byte) {
		fr, n, err := ParseFrame(data)
		if err != nil {
			if n != 0 {
				t.Fatalf("n=%d with error %v", n, err)
			}
			return
		}
		if n <= 0 || n > len(data) {
			t.Fatalf("bad n=%d for len %d", n, len(data))
		}
		_ = fr.Validate()
		_, _, _ = fr.CloseInfo()

		// Re-encoding must reproduce a frame that parses to the same thing.
		// (The wire bytes may differ when the input used a non-minimal
		// length encoding.)
		wire := fr.Bytes()
		again, n2, err := ParseFrame(wire)
		if err != nil || n2 != len(wire) {
			t.Fatalf("re-parse failed: %v (%d of %d)", err, n2, len(wire))
		}
		if again.FIN != fr.FIN || again.RSV1 != fr.RSV1 || again.RSV2 != fr.RSV2 || again.RSV3 != fr.RSV3 ||
			again.Opcode != fr.Opcode || again.Masked != fr.Masked || again.MaskKey != fr.MaskKey || !bytes.Equal(again.Payload, fr.Payload) {
			t.Fatalf("round trip changed frame:\n%+v\n%+v", fr, again)
		}
		// Minimal encodings are stable.
		if wire2 := again.Bytes(); !bytes.Equal(wire, wire2) {
			t.Fatalf("second encoding differs")
		}
	})
}

func BenchmarkParseFrameSmall(b *testing.B) {
	b.SetBytes(int64(len(rfcHelloMasked)))
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := ParseFrame(rfcHelloMasked); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseFrameMasked64K(b *testing.B) {
	f := Frame{FIN: true, Opcode: OpBinary, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: make([]byte, 64<<10)}
	wire := f.Bytes()
	b.SetBytes(int64(len(wire)))
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := ParseFrame(wire); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseFrameUnmasked64K(b *testing.B) {
	f := Frame{FIN: true, Opcode: OpBinary, Payload: make([]byte, 64<<10)}
	wire := f.Bytes()
	b.SetBytes(int64(len(wire)))
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := ParseFrame(wire); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFrameAppendTo(b *testing.B) {
	f := Frame{FIN: true, Opcode: OpText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: make([]byte, 1024)}
	buf := make([]byte, 0, f.WireLen())
	b.SetBytes(int64(f.WireLen()))
	b.ReportAllocs()
	for b.Loop() {
		buf = f.AppendTo(buf[:0])
	}
}

func BenchmarkMask(b *testing.B) {
	data := make([]byte, 64<<10)
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		Mask(data, [4]byte{1, 2, 3, 4}, 0)
	}
}
