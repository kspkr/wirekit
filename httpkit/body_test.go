package httpkit

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestCaptureLimits(t *testing.T) {
	c := NewCapture(5)
	n, err := c.Write([]byte("hello"))
	if n != 5 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	n, err = c.Write([]byte(" world"))
	if n != 6 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	b := c.Body()
	if string(b.Data) != "hello" || b.Size != 11 || !b.Truncated || b.Captured() != 5 {
		t.Errorf("Body = %+v", b)
	}
	if c.Size() != 11 {
		t.Errorf("Size = %d", c.Size())
	}

	// Zero limit counts only.
	c = NewCapture(0)
	c.Write([]byte("abc"))
	if b := c.Body(); b.Data != nil || b.Size != 3 || !b.Truncated {
		t.Errorf("zero-limit Body = %+v", b)
	}

	// Negative limit keeps everything.
	c = NewCapture(-1)
	c.Write(bytes.Repeat([]byte("x"), 10000))
	if b := c.Body(); len(b.Data) != 10000 || b.Truncated {
		t.Errorf("unlimited Body = size %d truncated %v", len(b.Data), b.Truncated)
	}

	// Exact fit is not truncated.
	c = NewCapture(3)
	c.Write([]byte("abc"))
	if b := c.Body(); b.Truncated || string(b.Data) != "abc" {
		t.Errorf("exact Body = %+v", b)
	}

	// Empty capture has nil Data and is empty.
	if b := NewCapture(10).Body(); b.Data != nil || !b.IsEmpty() {
		t.Errorf("empty Body = %+v", b)
	}
}

func TestCaptureSnapshotIsIndependent(t *testing.T) {
	c := NewCapture(100)
	c.Write([]byte("abc"))
	b := c.Body()
	c.Write([]byte("def"))
	if string(b.Data) != "abc" {
		t.Errorf("snapshot changed: %q", b.Data)
	}
	b.Data[0] = 'X'
	if string(c.Body().Data) != "abcdef" {
		t.Error("modifying snapshot affected capture")
	}
	c.Reset()
	if b := c.Body(); b.Size != 0 || b.Data != nil {
		t.Errorf("after Reset = %+v", b)
	}
}

func TestCaptureTeeReader(t *testing.T) {
	c := NewCapture(4)
	r := c.TeeReader(strings.NewReader("streaming body"))
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "streaming body" {
		t.Fatalf("ReadAll = %q, %v", got, err)
	}
	if b := c.Body(); string(b.Data) != "stre" || b.Size != 14 || !b.Truncated {
		t.Errorf("Body = %+v", b)
	}
}

func TestCaptureConcurrent(t *testing.T) {
	c := NewCapture(1 << 10)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 100 {
				c.Write([]byte("0123456789"))
			}
		}()
		go func() {
			defer wg.Done()
			for range 100 {
				b := c.Body()
				if int64(len(b.Data)) > b.Size {
					t.Error("captured more than size")
				}
			}
		}()
	}
	wg.Wait()
	if c.Size() != 4000 {
		t.Errorf("Size = %d", c.Size())
	}
}

func TestBodyHelpers(t *testing.T) {
	b := BodyOf([]byte("abc"))
	if b.Size != 3 || b.Truncated || b.Captured() != 3 || b.IsEmpty() {
		t.Errorf("BodyOf = %+v", b)
	}
	data, _ := io.ReadAll(b.Reader())
	if string(data) != "abc" {
		t.Errorf("Reader = %q", data)
	}
	c := b.Clone()
	c.Data[0] = 'X'
	if b.Data[0] != 'a' {
		t.Error("Clone shares Data")
	}
	if (Body{}).Clone().Data != nil {
		t.Error("Clone of nil Data allocated")
	}
	if !(Body{}).IsEmpty() || (Body{Size: 1}).IsEmpty() {
		t.Error("IsEmpty wrong")
	}
}

func BenchmarkCaptureWrite(b *testing.B) {
	chunk := make([]byte, 4096)
	c := NewCapture(1 << 20)
	b.SetBytes(int64(len(chunk)))
	b.ReportAllocs()
	for b.Loop() {
		c.Write(chunk)
	}
}
