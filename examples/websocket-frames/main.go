// Command websocket-frames decodes a stream of WebSocket frames and prints
// the messages they carry.
//
// Pipe raw frame bytes on stdin (for example a capture of one direction of
// a connection), or run it with no input to decode a built-in sample:
//
//	go run ./examples/websocket-frames < frames.bin
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/kspkr/wirekit/encoding"
	"github.com/kspkr/wirekit/wskit"
)

func main() {
	data, err := readInput()
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	if len(data) == 0 {
		data = sample()
		fmt.Println("(no input on stdin; using a built-in sample)")
	}

	r := wskit.NewReader(bytes.NewReader(data), 16<<20)
	var asm wskit.Assembler
	for n := 1; ; n++ {
		f, err := r.ReadFrame()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			fmt.Println("stream error:", err)
			break
		}
		fmt.Printf("frame %d: %-12s fin=%-5v masked=%-5v rsv1=%-5v %d bytes", n, f.Opcode, f.FIN, f.Masked, f.RSV1, len(f.Payload))
		if err := f.Validate(); err != nil {
			fmt.Printf("  INVALID: %v", err)
		}
		fmt.Println()

		m, err := asm.Push(f)
		if err != nil {
			fmt.Println("  protocol error:", err)
			continue
		}
		if m == nil {
			continue
		}
		switch m.Type {
		case wskit.OpClose:
			code, reason, _ := m.CloseInfo()
			fmt.Printf("  => close: %v %q\n", code, reason)
		case wskit.OpText:
			fmt.Printf("  => text message (%d frames): %s\n", m.Frames, m.Data)
		case wskit.OpBinary:
			fmt.Printf("  => binary message (%d frames):\n%s", m.Frames, encoding.HexDump(m.Data, 64))
		default:
			fmt.Printf("  => %s\n", m.Type)
		}
	}
}

func readInput() ([]byte, error) {
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		return nil, nil
	}
	return io.ReadAll(os.Stdin)
}

// sample builds a client-to-server stream: a fragmented text message with
// a ping in the middle, a binary message, and a close.
func sample() []byte {
	key := [4]byte{0x37, 0xfa, 0x21, 0x3d}
	var b []byte
	b = (&wskit.Frame{Opcode: wskit.OpText, Masked: true, MaskKey: key, Payload: []byte(`{"type":"sub`)}).AppendTo(b)
	b = (&wskit.Frame{FIN: true, Opcode: wskit.OpPing, Masked: true, MaskKey: key, Payload: []byte("keepalive")}).AppendTo(b)
	b = (&wskit.Frame{FIN: true, Opcode: wskit.OpContinuation, Masked: true, MaskKey: key, Payload: []byte(`scribe","channel":"ticks"}`)}).AppendTo(b)
	b = (&wskit.Frame{FIN: true, Opcode: wskit.OpBinary, Masked: true, MaskKey: key, Payload: []byte{0x00, 0x01, 0x02, 0x03, 0xde, 0xad, 0xbe, 0xef}}).AppendTo(b)
	b = (&wskit.Frame{FIN: true, Opcode: wskit.OpClose, Masked: true, MaskKey: key, Payload: wskit.ClosePayload(wskit.CloseGoingAway, "bye")}).AppendTo(b)
	return b
}
