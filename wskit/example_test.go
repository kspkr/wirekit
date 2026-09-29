package wskit_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/kspkr/wirekit/wskit"
)

func ExampleParseFrame() {
	// A masked text frame carrying "Hello", from RFC 6455 §5.7.
	wire := []byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}

	f, n, err := wskit.ParseFrame(wire)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("%s fin=%v masked=%v payload=%q (%d bytes on the wire)\n", f.Opcode, f.FIN, f.Masked, f.Payload, n)
	// Output:
	// text fin=true masked=true payload="Hello" (11 bytes on the wire)
}

func ExampleReader() {
	// Build a stream: a fragmented text message with a ping in the middle,
	// then a close frame.
	var stream []byte
	stream = (&wskit.Frame{Opcode: wskit.OpText, Payload: []byte("Hel")}).AppendTo(stream)
	stream = (&wskit.Frame{FIN: true, Opcode: wskit.OpPing}).AppendTo(stream)
	stream = (&wskit.Frame{FIN: true, Opcode: wskit.OpContinuation, Payload: []byte("lo")}).AppendTo(stream)
	stream = (&wskit.Frame{FIN: true, Opcode: wskit.OpClose, Payload: wskit.ClosePayload(wskit.CloseNormal, "bye")}).AppendTo(stream)

	r := wskit.NewReader(bytes.NewReader(stream), 1<<20)
	var a wskit.Assembler
	for {
		f, err := r.ReadFrame()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			fmt.Println("error:", err)
			return
		}
		m, err := a.Push(f)
		if err != nil {
			fmt.Println("protocol error:", err)
			return
		}
		if m == nil {
			continue // waiting for more fragments
		}
		switch m.Type {
		case wskit.OpClose:
			code, reason, _ := m.CloseInfo()
			fmt.Printf("close: %v %q\n", code, reason)
		default:
			fmt.Printf("%s: %q in %d frame(s)\n", m.Type, m.Data, m.Frames)
		}
	}
	// Output:
	// ping: "" in 1 frame(s)
	// text: "Hello" in 2 frame(s)
	// close: normal closure (1000) "bye"
}

func ExampleFrame_Validate() {
	f := wskit.Frame{Opcode: wskit.OpPing, Payload: make([]byte, 200)} // fragmented and too long
	fmt.Println(f.Validate())
	// Output:
	// wskit: protocol violation: fragmented control frame
	// wskit: protocol violation: control frame payload of 200 bytes exceeds 125
}

func ExampleAcceptKey() {
	fmt.Println(wskit.AcceptKey("dGhlIHNhbXBsZSBub25jZQ=="))
	// Output:
	// s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
}
