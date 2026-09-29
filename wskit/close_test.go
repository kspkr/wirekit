package wskit

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCloseCodeString(t *testing.T) {
	cases := map[CloseCode]string{
		CloseNormal:       "normal closure (1000)",
		CloseAbnormal:     "abnormal closure (1006)",
		CloseTLSHandshake: "TLS handshake failure (1015)",
		3000:              "application code (3000)",
		4999:              "private use code (4999)",
		0:                 "unknown code 0",
		1004:              "unknown code 1004",
		1016:              "unknown code 1016",
		2999:              "unknown code 2999",
		5000:              "unknown code 5000",
	}
	for code, want := range cases {
		if got := code.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", code, got, want)
		}
	}
}

func TestCloseCodeIsValid(t *testing.T) {
	valid := []CloseCode{1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 3999, 4000, 4999}
	invalid := []CloseCode{0, 1, 999, 1004, 1005, 1006, 1015, 1016, 1999, 2000, 2999, 5000, 65535}
	for _, c := range valid {
		if !c.IsValid() {
			t.Errorf("%d should be valid", c)
		}
	}
	for _, c := range invalid {
		if c.IsValid() {
			t.Errorf("%d should be invalid", c)
		}
	}
}

func TestParseClosePayload(t *testing.T) {
	code, reason, err := ParseClosePayload(nil)
	if err != nil || code != CloseNoStatus || reason != "" {
		t.Errorf("empty = %v %q %v", code, reason, err)
	}
	_, _, err = ParseClosePayload([]byte{0x03})
	if !errors.Is(err, ErrProtocol) {
		t.Errorf("one byte = %v", err)
	}
	code, reason, err = ParseClosePayload([]byte{0x03, 0xe8})
	if err != nil || code != CloseNormal || reason != "" {
		t.Errorf("1000 = %v %q %v", code, reason, err)
	}
	code, reason, err = ParseClosePayload([]byte{0x03, 0xe9, 'b', 'y', 'e'})
	if err != nil || code != CloseGoingAway || reason != "bye" {
		t.Errorf("1001 bye = %v %q %v", code, reason, err)
	}
	// Invalid code: still reported.
	code, reason, err = ParseClosePayload([]byte{0x03, 0xed, 'x'})
	if !errors.Is(err, ErrProtocol) || code != 1005 || reason != "x" {
		t.Errorf("1005 = %v %q %v", code, reason, err)
	}
	// Bad UTF-8: still reported.
	code, _, err = ParseClosePayload([]byte{0x03, 0xe8, 0xff})
	if !errors.Is(err, ErrProtocol) || code != CloseNormal || !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("bad utf8 = %v %v", code, err)
	}
}

func TestClosePayload(t *testing.T) {
	p := ClosePayload(CloseNormal, "done")
	code, reason, err := ParseClosePayload(p)
	if err != nil || code != CloseNormal || reason != "done" {
		t.Errorf("round trip = %v %q %v", code, reason, err)
	}
	if len(ClosePayload(CloseNormal, "")) != 2 {
		t.Error("empty reason length")
	}
	// Long reasons are cut on a rune boundary to fit a control frame.
	long := strings.Repeat("é", 100) // 200 bytes
	p = ClosePayload(CloseNormal, long)
	if len(p) > MaxControlPayload || !utf8.Valid(p[2:]) || len(p) != 2+122 {
		t.Errorf("truncated payload len %d valid %v", len(p), utf8.Valid(p[2:]))
	}
	p = ClosePayload(CloseNormal, strings.Repeat("a", 123))
	if len(p) != 125 {
		t.Errorf("exact fit len %d", len(p))
	}
}

func FuzzParseClosePayload(f *testing.F) {
	f.Add([]byte{0x03, 0xe8, 'o', 'k'})
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		code, reason, err := ParseClosePayload(data)
		if err == nil && len(data) >= 2 && !code.IsValid() {
			t.Fatalf("invalid code %d accepted", code)
		}
		if err == nil && len(data) >= 2 && len(data) <= MaxControlPayload {
			back := ClosePayload(code, reason)
			if string(back) != string(data) {
				t.Fatalf("round trip changed payload: %x -> %x", data, back)
			}
		}
	})
}
