package encoding_test

import (
	"fmt"

	"github.com/kspkr/wirekit/encoding"
)

func ExampleDecodeBase64() {
	// A JWT payload: URL-safe alphabet, no padding.
	payload, err := encoding.DecodeBase64("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(string(payload))
	// Output:
	// {"sub":"1234567890","name":"John Doe"}
}

func ExampleHexDump() {
	fmt.Print(encoding.HexDump([]byte("GET / HTTP/1.1\r\n"), 0))
	// Output:
	// 00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|
}

func ExampleInspectJSON() {
	body := []byte(`)]}',
{"users":[{"id":1,"tags":["a","b"]},{"id":2,"tags":[]}],"total":2}`)

	data, prefix := encoding.StripXSSI(body)
	fmt.Printf("removed %q\n", prefix)

	info, err := encoding.InspectJSON(data)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("%s, depth %d, %d objects, %d arrays, %d keys\n", info.Kind, info.Depth, info.Objects, info.Arrays, info.Keys)
	// Output:
	// removed ")]}',"
	// object, depth 4, 3 objects, 3 arrays, 6 keys
}
