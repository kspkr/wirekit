package wskit

import (
	"crypto/sha1"
	"encoding/base64"
	"maps"
	"slices"
	"strings"

	"github.com/kspkr/wirekit/internal/ascii"
)

// GUID is the constant appended to Sec-WebSocket-Key when computing
// Sec-WebSocket-Accept (RFC 6455 §1.3).
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// AcceptKey computes the Sec-WebSocket-Accept value for a
// Sec-WebSocket-Key.
func AcceptKey(secWebSocketKey string) string {
	h := sha1.New()
	h.Write([]byte(strings.TrimSpace(secWebSocketKey)))
	h.Write([]byte(GUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// HeaderGetter is the part of a header collection the handshake helpers
// need. Both net/http's Header and httpkit's Headers satisfy it.
type HeaderGetter interface {
	Get(name string) string
}

// IsUpgradeRequest reports whether the headers of an HTTP request form a
// WebSocket opening handshake: Upgrade lists websocket, Connection lists
// upgrade, and Sec-WebSocket-Key and Sec-WebSocket-Version 13 are present.
func IsUpgradeRequest(h HeaderGetter) bool {
	return hasToken(h.Get("Upgrade"), "websocket") &&
		hasToken(h.Get("Connection"), "upgrade") &&
		strings.TrimSpace(h.Get("Sec-WebSocket-Key")) != "" &&
		hasToken(h.Get("Sec-WebSocket-Version"), "13")
}

// IsUpgradeResponse reports whether a response completes a WebSocket
// handshake: status 101 with Upgrade websocket, Connection upgrade and a
// Sec-WebSocket-Accept value. Use [VerifyAccept] to check the value.
func IsUpgradeResponse(statusCode int, h HeaderGetter) bool {
	return statusCode == 101 &&
		hasToken(h.Get("Upgrade"), "websocket") &&
		hasToken(h.Get("Connection"), "upgrade") &&
		strings.TrimSpace(h.Get("Sec-WebSocket-Accept")) != ""
}

// VerifyAccept reports whether accept is the correct Sec-WebSocket-Accept
// for key.
func VerifyAccept(key, accept string) bool {
	return AcceptKey(key) == strings.TrimSpace(accept)
}

// hasToken reports whether the comma-separated list value contains token,
// compared case-insensitively.
func hasToken(value, token string) bool {
	for t := range strings.SplitSeq(value, ",") {
		if ascii.EqualFold(ascii.TrimSpace(t), token) {
			return true
		}
	}
	return false
}

// Extension is one entry of a Sec-WebSocket-Extensions header.
type Extension struct {
	// Name is the extension token, e.g. "permessage-deflate".
	Name string
	// Params holds the parameters. A parameter without a value maps to "".
	// Nil when there are none.
	Params map[string]string
}

// String formats the extension as it appears in the header.
func (e Extension) String() string {
	var sb strings.Builder
	sb.WriteString(e.Name)
	for _, k := range sortedKeys(e.Params) {
		sb.WriteString("; ")
		sb.WriteString(k)
		if v := e.Params[k]; v != "" {
			sb.WriteByte('=')
			sb.WriteString(v)
		}
	}
	return sb.String()
}

// ParseExtensions parses a Sec-WebSocket-Extensions value such as
// "permessage-deflate; client_max_window_bits, x-custom". The same
// extension may appear more than once with different parameters, as
// RFC 6455 §9.1 allows for offers. Quoted parameter values are unquoted.
// Empty entries are skipped and nothing is rejected.
func ParseExtensions(header string) []Extension {
	var out []Extension
	for entry := range strings.SplitSeq(header, ",") {
		parts := strings.Split(entry, ";")
		name := strings.TrimSpace(parts[0])
		if name == "" {
			continue
		}
		e := Extension{Name: name}
		for _, p := range parts[1:] {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			k, v, _ := strings.Cut(p, "=")
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
				v = v[1 : len(v)-1]
			}
			if e.Params == nil {
				e.Params = make(map[string]string)
			}
			e.Params[k] = v
		}
		out = append(out, e)
	}
	return out
}

// DeflateParams are the negotiated parameters of permessage-deflate
// (RFC 7692 §7.1).
type DeflateParams struct {
	// ServerNoContextTakeover and ClientNoContextTakeover mean the sender
	// resets its compression context after every message.
	ServerNoContextTakeover bool
	ClientNoContextTakeover bool
	// ServerMaxWindowBits and ClientMaxWindowBits are the LZ77 window sizes
	// (8-15). Zero means the parameter was absent, i.e. the default of 15.
	// A parameter present without a value is reported as 15.
	ServerMaxWindowBits int
	ClientMaxWindowBits int
}

// PermessageDeflate finds the permessage-deflate extension in exts and
// returns its parameters. ok is false when the extension is absent or a
// parameter is invalid. Pass the extensions from the server's response to
// learn what was actually negotiated.
func PermessageDeflate(exts []Extension) (p DeflateParams, ok bool) {
	for _, e := range exts {
		if e.Name != "permessage-deflate" {
			continue
		}
		for k, v := range e.Params {
			switch k {
			case "server_no_context_takeover":
				p.ServerNoContextTakeover = true
			case "client_no_context_takeover":
				p.ClientNoContextTakeover = true
			case "server_max_window_bits":
				if p.ServerMaxWindowBits, ok = windowBits(v); !ok {
					return DeflateParams{}, false
				}
			case "client_max_window_bits":
				if p.ClientMaxWindowBits, ok = windowBits(v); !ok {
					return DeflateParams{}, false
				}
			default:
				return DeflateParams{}, false
			}
		}
		return p, true
	}
	return DeflateParams{}, false
}

func windowBits(v string) (int, bool) {
	if v == "" {
		return 15, true
	}
	if len(v) > 2 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(v); i++ {
		if !ascii.IsDigit(v[i]) {
			return 0, false
		}
		n = n*10 + int(v[i]-'0')
	}
	if n < 8 || n > 15 {
		return 0, false
	}
	return n, true
}

func sortedKeys(m map[string]string) []string {
	return slices.Sorted(maps.Keys(m))
}
