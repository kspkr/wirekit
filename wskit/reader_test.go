package wskit

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func TestReader(t *testing.T) {
	var stream []byte
	stream = append(stream, rfcFragment1...)
	stream = append(stream, rfcPing...)
	stream = append(stream, rfcFragment2...)
	stream = append(stream, rfcHelloMasked...)
	big := Frame{FIN: true, Opcode: OpBinary, Masked: true, MaskKey: [4]byte{9, 8, 7, 6}, Payload: bytes.Repeat([]byte("z"), 70000)}
	stream = big.AppendTo(stream)

	// Read through a one-byte-at-a-time reader to exercise partial reads.
	r := NewReader(iotest.OneByteReader(bytes.NewReader(stream)), 0)
	var got []Frame
	for {
		f, err := r.ReadFrame()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, f)
	}
	if len(got) != 5 {
		t.Fatalf("got %d frames", len(got))
	}
	if string(got[0].Payload) != "Hel" || got[1].Opcode != OpPing || string(got[2].Payload) != "lo" || string(got[3].Payload) != "Hello" {
		t.Errorf("frames = %+v", got[:4])
	}
	if !got[4].Masked || !bytes.Equal(got[4].Payload, big.Payload) {
		t.Errorf("big frame wrong: masked %v len %d", got[4].Masked, len(got[4].Payload))
	}
	// EOF is sticky.
	if _, err := r.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Errorf("second EOF = %v", err)
	}
	// A bufio.Reader is used as is.
	br := bufio.NewReader(bytes.NewReader(rfcHello))
	if NewReader(br, 0).br != br {
		t.Error("bufio.Reader was re-wrapped")
	}
}

func TestReaderErrors(t *testing.T) {
	// Stream ends inside the header.
	for _, b := range [][]byte{{0x81}, {0x82, 126, 0x01}, {0x82, 0x85, 1, 2}} {
		r := NewReader(bytes.NewReader(b), 0)
		if _, err := r.ReadFrame(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("%x: err = %v", b, err)
		}
	}
	// Stream ends inside the payload.
	r := NewReader(bytes.NewReader(rfcHello[:5]), 0)
	if _, err := r.ReadFrame(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("short payload: err = %v", err)
	}
	// Malformed length.
	r = NewReader(bytes.NewReader([]byte{0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0}), 0)
	if _, err := r.ReadFrame(); !errors.Is(err, ErrMalformed) {
		t.Errorf("top bit: err = %v", err)
	}
	// Oversize frame is rejected before its payload is read or allocated.
	huge := []byte{0x82, 127, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	r = NewReader(bytes.NewReader(huge), 1<<20)
	_, err := r.ReadFrame()
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("huge: err = %v", err)
	}
	// Errors are sticky.
	if _, err2 := r.ReadFrame(); err2 != err {
		t.Errorf("error not sticky: %v", err2)
	}
	// Exactly at the limit is fine; one over is not.
	f := Frame{FIN: true, Opcode: OpBinary, Payload: make([]byte, 1000)}
	if _, err := NewReader(bytes.NewReader(f.Bytes()), 1000).ReadFrame(); err != nil {
		t.Errorf("at limit: %v", err)
	}
	if _, err := NewReader(bytes.NewReader(f.Bytes()), 999).ReadFrame(); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over limit: %v", err)
	}
	// Underlying read errors pass through.
	r = NewReader(iotest.ErrReader(errors.New("boom")), 0)
	if _, err := r.ReadFrame(); err == nil || err.Error() != "boom" {
		t.Errorf("read error = %v", err)
	}
}

func TestReaderOwnsPayload(t *testing.T) {
	stream := append(append([]byte(nil), rfcHello...), rfcHello...)
	r := NewReader(bytes.NewReader(stream), 0)
	a, _ := r.ReadFrame()
	b, _ := r.ReadFrame()
	a.Payload[0] = 'J'
	if string(b.Payload) != "Hello" {
		t.Error("frames share payload storage")
	}
}

func BenchmarkReaderReadFrame(b *testing.B) {
	f := Frame{FIN: true, Opcode: OpText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: make([]byte, 1024)}
	one := f.Bytes()
	stream := bytes.Repeat(one, 100)
	b.SetBytes(int64(len(one)))
	b.ReportAllocs()
	src := bytes.NewReader(stream)
	br := bufio.NewReaderSize(src, 64<<10)
	r := NewReader(br, 0)
	for b.Loop() {
		if _, err := r.ReadFrame(); err != nil {
			if !errors.Is(err, io.EOF) {
				b.Fatal(err)
			}
			src.Reset(stream)
			br.Reset(src)
			r = NewReader(br, 0)
		}
	}
}
