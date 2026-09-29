package encoding

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// JSONKind is the type of a JSON value.
type JSONKind int

// The JSON value kinds. JSONInvalid is the zero value and means the input
// was not valid JSON.
const (
	JSONInvalid JSONKind = iota
	JSONObject
	JSONArray
	JSONString
	JSONNumber
	JSONBool
	JSONNull
)

var jsonKindNames = [...]string{"invalid", "object", "array", "string", "number", "bool", "null"}

// String returns the kind's name: "object", "array", "string", "number",
// "bool", "null" or "invalid".
func (k JSONKind) String() string {
	if int(k) < len(jsonKindNames) {
		return jsonKindNames[k]
	}
	return "invalid"
}

// MarshalText implements encoding.TextMarshaler using String.
func (k JSONKind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// JSONInfo summarizes the shape of a JSON document without building it in
// memory.
type JSONInfo struct {
	// Kind is the type of the top-level value.
	Kind JSONKind `json:"kind"`
	// Depth is the deepest nesting of objects and arrays; a scalar has
	// depth 0 and "{}" has depth 1.
	Depth int `json:"depth"`
	// Objects, Arrays and Values count containers and scalar values in the
	// whole document. Keys counts object members.
	Objects int `json:"objects"`
	Arrays  int `json:"arrays"`
	Values  int `json:"values"`
	Keys    int `json:"keys"`
	// Size is the length of the input in bytes.
	Size int `json:"size"`
}

// MaxJSONDepth bounds nesting in InspectJSON. Deeper documents are
// reported as invalid rather than walked further.
const MaxJSONDepth = 10000

// InspectJSON validates data as JSON and reports its shape. It streams
// through the document with a token decoder, so memory does not grow with
// the size of the input. Leading and trailing whitespace is allowed; any
// other trailing content is an error. The error wraps ErrInvalid.
func InspectJSON(data []byte) (JSONInfo, error) {
	info := JSONInfo{Size: len(data)}
	invalid := func(format string, args ...any) (JSONInfo, error) {
		return JSONInfo{Size: len(data)}, fmt.Errorf("%w: json: "+format, append([]any{ErrInvalid}, args...)...)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	// stack remembers, for each open container, whether it is an object so
	// keys can be counted.
	var stack []bool
	expectKey := false
	first := true
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if first {
				return invalid("empty input")
			}
			return invalid("unexpected end of input")
		}
		if err != nil {
			return invalid("%v", err)
		}
		if first {
			first = false
			info.Kind = kindOf(tok)
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				if len(stack) == MaxJSONDepth {
					return invalid("nesting deeper than %d", MaxJSONDepth)
				}
				stack = append(stack, v == '{')
				info.Depth = max(info.Depth, len(stack))
				if v == '{' {
					info.Objects++
				} else {
					info.Arrays++
				}
				expectKey = v == '{'
			case '}', ']':
				stack = stack[:len(stack)-1]
				expectKey = len(stack) > 0 && stack[len(stack)-1]
			}
		default:
			if expectKey {
				// In an object, tokens alternate key, value.
				info.Keys++
				expectKey = false
				continue
			}
			info.Values++
			if len(stack) > 0 && stack[len(stack)-1] {
				expectKey = true
			}
		}
		if len(stack) == 0 {
			break // the top-level value is complete
		}
	}
	// json.Decoder would happily continue with a second value; only
	// whitespace may follow the first.
	if _, err := dec.Token(); err != io.EOF {
		return invalid("data after top-level value")
	}
	return info, nil
}

func kindOf(tok json.Token) JSONKind {
	switch v := tok.(type) {
	case json.Delim:
		if v == '{' {
			return JSONObject
		}
		return JSONArray
	case string:
		return JSONString
	case json.Number:
		return JSONNumber
	case bool:
		return JSONBool
	case nil:
		return JSONNull
	}
	return JSONInvalid
}

// LooksLikeJSON reports whether data starts, after optional whitespace and
// an XSSI prefix, with '{' or '['. It is a cheap guess for choosing a
// viewer; use InspectJSON or json.Valid to know for sure.
func LooksLikeJSON(data []byte) bool {
	data, _ = StripXSSI(data)
	data = bytes.TrimLeft(data, " \t\r\n")
	return len(data) > 0 && (data[0] == '{' || data[0] == '[')
}

// xssiPrefixes are the guards some APIs prepend to JSON so it cannot be
// loaded as a script by another origin.
var xssiPrefixes = [...]string{")]}',", ")]}'", "while(1);", "while (1);", "for(;;);", "for (;;);"}

// StripXSSI removes a cross-site script inclusion guard such as ")]}'" or
// "while(1);" from the start of data, along with surrounding whitespace.
// It returns the remaining bytes (a sub-slice of data) and the prefix that
// was removed, or data unchanged and "" when there was none.
func StripXSSI(data []byte) (rest []byte, prefix string) {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	for _, p := range xssiPrefixes {
		if bytes.HasPrefix(trimmed, []byte(p)) {
			return bytes.TrimLeft(trimmed[len(p):], " \t\r\n"), p
		}
	}
	return data, ""
}
