package compress_test

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"

	"github.com/kspkr/wirekit/compress"
)

func ExampleDecode() {
	// A gzip-compressed response body, as a proxy would capture it.
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte(`{"status":"ok"}`))
	w.Close()

	body, err := compress.Decode("gzip", buf.Bytes(), 1<<20)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(string(body))
	// Output:
	// {"status":"ok"}
}

func ExampleDecode_limit() {
	// A decompression bomb: a megabyte of zeros in about a kilobyte.
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(make([]byte, 1<<20))
	w.Close()

	_, err := compress.Decode("gzip", buf.Bytes(), 64<<10)
	fmt.Println(errors.Is(err, compress.ErrTooLarge), err)
	// Output:
	// true compress: decoded data exceeds limit
}
