package encoding

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestInspectJSON(t *testing.T) {
	cases := []struct {
		in   string
		want JSONInfo
	}{
		{`{}`, JSONInfo{Kind: JSONObject, Depth: 1, Objects: 1}},
		{`[]`, JSONInfo{Kind: JSONArray, Depth: 1, Arrays: 1}},
		{`"s"`, JSONInfo{Kind: JSONString, Values: 1}},
		{`42`, JSONInfo{Kind: JSONNumber, Values: 1}},
		{`true`, JSONInfo{Kind: JSONBool, Values: 1}},
		{`null`, JSONInfo{Kind: JSONNull, Values: 1}},
		{` {"a":1,"b":[1,2,{"c":null}],"d":{"e":"f"}} `, JSONInfo{Kind: JSONObject, Depth: 3, Objects: 3, Arrays: 1, Values: 5, Keys: 5}},
		{`[[[[]]]]`, JSONInfo{Kind: JSONArray, Depth: 4, Arrays: 4}},
		{`[1,[2,[3]]]`, JSONInfo{Kind: JSONArray, Depth: 3, Arrays: 3, Values: 3}},
		{`{"k":{"k":{"k":1}}}`, JSONInfo{Kind: JSONObject, Depth: 3, Objects: 3, Values: 1, Keys: 3}},
	}
	for _, c := range cases {
		got, err := InspectJSON([]byte(c.in))
		if err != nil {
			t.Errorf("InspectJSON(%q): %v", c.in, err)
			continue
		}
		c.want.Size = len(c.in)
		if got != c.want {
			t.Errorf("InspectJSON(%q) =\n%+v\nwant\n%+v", c.in, got, c.want)
		}
	}
	bad := []string{"", "  ", "{", "}", "[1,]", `{"a":}`, `{"a" 1}`, "nul", `"unterminated`, "{}{}", "{} x", "[] 1", "1 2", "{\"a\":1}\n{", "\x00"}
	for _, in := range bad {
		got, err := InspectJSON([]byte(in))
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("InspectJSON(%q) = %+v, err %v, want ErrInvalid", in, got, err)
		}
		if got.Size != len(in) || got.Kind != JSONInvalid {
			t.Errorf("InspectJSON(%q) on error = %+v", in, got)
		}
	}
	// Depth limit.
	deep := strings.Repeat("[", MaxJSONDepth) + strings.Repeat("]", MaxJSONDepth)
	if info, err := InspectJSON([]byte(deep)); err != nil || info.Depth != MaxJSONDepth {
		t.Errorf("at depth limit: %+v %v", info, err)
	}
	if _, err := InspectJSON([]byte("[" + deep + "]")); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "nesting") {
		t.Errorf("over depth limit: %v", err)
	}
	// Numbers keep their precision through the token decoder.
	if info, err := InspectJSON([]byte(`[12345678901234567890.123456789]`)); err != nil || info.Values != 1 {
		t.Errorf("big number: %+v %v", info, err)
	}
}

func TestJSONKind(t *testing.T) {
	for k, want := range map[JSONKind]string{JSONInvalid: "invalid", JSONObject: "object", JSONArray: "array", JSONString: "string", JSONNumber: "number", JSONBool: "bool", JSONNull: "null", JSONKind(99): "invalid"} {
		if got := k.String(); got != want {
			t.Errorf("%d.String() = %q", k, got)
		}
	}
	b, err := json.Marshal(JSONInfo{Kind: JSONArray})
	if err != nil || !strings.Contains(string(b), `"kind":"array"`) {
		t.Errorf("JSON = %s, %v", b, err)
	}
}

func TestLooksLikeJSONAndXSSI(t *testing.T) {
	yes := []string{"{}", "[]", "  {\"a\":1}", "\n[1]", ")]}',\n{\"a\":1}", ")]}'{}", "while(1);[1]", "while (1); {}", "for(;;);[]", "for (;;);{}"}
	no := []string{"", " ", "1", "\"s\"", "null", "<html>", "x{}", ")]}'", "while(1);"}
	for _, s := range yes {
		if !LooksLikeJSON([]byte(s)) {
			t.Errorf("LooksLikeJSON(%q) = false", s)
		}
	}
	for _, s := range no {
		if LooksLikeJSON([]byte(s)) {
			t.Errorf("LooksLikeJSON(%q) = true", s)
		}
	}

	rest, prefix := StripXSSI([]byte(" )]}',\n {\"a\":1}"))
	if string(rest) != `{"a":1}` || prefix != ")]}'," {
		t.Errorf("StripXSSI = %q %q", rest, prefix)
	}
	rest, prefix = StripXSSI([]byte(")]}'\n[1]"))
	if string(rest) != "[1]" || prefix != ")]}'" {
		t.Errorf("StripXSSI short = %q %q", rest, prefix)
	}
	data := []byte(`{"a":1}`)
	rest, prefix = StripXSSI(data)
	if &rest[0] != &data[0] || prefix != "" {
		t.Error("StripXSSI without prefix should return data unchanged")
	}
	if rest, prefix := StripXSSI(nil); rest != nil || prefix != "" {
		t.Error("StripXSSI(nil)")
	}
}

func FuzzInspectJSON(f *testing.F) {
	f.Add([]byte(`{"a":[1,2,{"b":null}],"c":"d"}`))
	f.Add([]byte(`[[[[]]]]`))
	f.Add([]byte(`{} {}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		info, err := InspectJSON(data)
		valid := json.Valid(data)
		if (err == nil) != valid {
			t.Fatalf("InspectJSON error=%v but json.Valid=%v for %q", err, valid, data)
		}
		if err == nil && (info.Kind == JSONInvalid || info.Depth < 0 || info.Depth > MaxJSONDepth) {
			t.Fatalf("bad info %+v for %q", info, data)
		}
		_ = LooksLikeJSON(data)
	})
}

func BenchmarkInspectJSON(b *testing.B) {
	data := []byte(`{"users":[{"id":1,"name":"Ada","tags":["a","b"],"active":true,"score":9.5},{"id":2,"name":"Linus","tags":[],"active":false,"score":null}],"total":2,"page":{"next":"/users?page=2","prev":null}}`)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := InspectJSON(data); err != nil {
			b.Fatal(err)
		}
	}
}
