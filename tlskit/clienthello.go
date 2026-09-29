package tlskit

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Sentinel errors for ParseClientHello.
var (
	// ErrIncomplete means more bytes are needed to finish parsing.
	ErrIncomplete = errors.New("tlskit: incomplete ClientHello")
	// ErrMalformed means the bytes are not a valid ClientHello.
	ErrMalformed = errors.New("tlskit: malformed ClientHello")
)

// Extension type numbers from the IANA TLS ExtensionType registry that
// this package interprets.
const (
	ExtServerName          uint16 = 0
	ExtSupportedGroups     uint16 = 10
	ExtECPointFormats      uint16 = 11
	ExtSignatureAlgorithms uint16 = 13
	ExtALPN                uint16 = 16
	ExtSupportedVersions   uint16 = 43
	ExtKeyShare            uint16 = 51
)

// ClientHello is the decoded first message of a TLS handshake.
type ClientHello struct {
	// Version is legacy_version, 0x0303 (TLS 1.2) for every modern client.
	// TLS 1.3 clients advertise 1.3 in SupportedVersions instead.
	Version uint16 `json:"version"`
	// Random is the 32-byte client random.
	Random []byte `json:"random"`
	// SessionID is the legacy session ID, which TLS 1.3 clients fill with
	// random bytes for middlebox compatibility.
	SessionID []byte `json:"sessionId,omitempty"`
	// CipherSuites are the offered suites in preference order, including
	// any GREASE values.
	CipherSuites []uint16 `json:"cipherSuites"`
	// CompressionMethods is almost always [0].
	CompressionMethods []uint8 `json:"compressionMethods"`
	// Extensions lists the extension types in the order sent, including
	// GREASE values and duplicates.
	Extensions []uint16 `json:"extensions"`

	// ServerName is the host from the server_name extension (SNI), or "".
	ServerName string `json:"serverName,omitempty"`
	// ALPNProtocols are the offered application protocols, e.g. ["h2",
	// "http/1.1"].
	ALPNProtocols []string `json:"alpnProtocols,omitempty"`
	// SupportedVersions is the supported_versions extension, present for
	// TLS 1.3-capable clients.
	SupportedVersions []uint16 `json:"supportedVersions,omitempty"`
	// SupportedGroups are the offered key exchange groups (curves).
	SupportedGroups []uint16 `json:"supportedGroups,omitempty"`
	// ECPointFormats is the ec_point_formats extension.
	ECPointFormats []uint8 `json:"ecPointFormats,omitempty"`
	// SignatureAlgorithms are the offered signature schemes.
	SignatureAlgorithms []uint16 `json:"signatureAlgorithms,omitempty"`
	// KeyShareGroups are the groups the client sent key shares for.
	KeyShareGroups []uint16 `json:"keyShareGroups,omitempty"`
}

// IsClientHello reports whether b starts like a TLS handshake record
// carrying a ClientHello. It looks at the first six bytes only, so it is
// cheap enough to run on every new connection; use ParseClientHello to
// find out whether the rest is valid.
func IsClientHello(b []byte) bool {
	return len(b) >= 6 && b[0] == recordHandshake && b[1] == 0x03 && b[5] == handshakeClientHello
}

const (
	recordHandshake      = 0x16
	handshakeClientHello = 0x01
	// maxRecord allows the 2^14 plaintext limit plus the 2048-byte slack
	// RFC 5246 grants compressed records, which some stacks still use.
	maxRecord = 16384 + 2048
	// maxHello bounds the assembled handshake message. Real ClientHellos
	// are a few kilobytes; post-quantum key shares push them toward 2 KB.
	maxHello = 1 << 16
)

// ParseClientHello decodes the ClientHello at the start of b, which must
// begin with a TLS record. The message may span several records.
//
// The error wraps ErrIncomplete when b ends before the message does, so a
// caller reading from a connection can fetch more bytes and retry, and
// ErrMalformed when the bytes cannot be a ClientHello. Unknown extensions
// are recorded in Extensions and otherwise skipped.
func ParseClientHello(b []byte) (*ClientHello, error) {
	body, err := assembleHandshake(b)
	if err != nil {
		return nil, err
	}
	c := &cursor{b: body}
	h := &ClientHello{}
	h.Version = c.u16()
	h.Random = c.bytes(32)
	h.SessionID = c.bytes(int(c.u8()))
	suites := c.bytes(int(c.u16()))
	comp := c.bytes(int(c.u8()))
	if c.failed {
		return nil, fmt.Errorf("%w: truncated body", ErrMalformed)
	}
	if len(suites) == 0 || len(suites)%2 != 0 {
		return nil, fmt.Errorf("%w: cipher suite list of %d bytes", ErrMalformed, len(suites))
	}
	if len(comp) == 0 {
		return nil, fmt.Errorf("%w: empty compression method list", ErrMalformed)
	}
	if len(h.SessionID) > 32 {
		return nil, fmt.Errorf("%w: session ID of %d bytes", ErrMalformed, len(h.SessionID))
	}
	h.CipherSuites = u16s(suites)
	h.CompressionMethods = append([]uint8(nil), comp...)
	if len(h.SessionID) == 0 {
		h.SessionID = nil
	}
	if c.remaining() == 0 {
		return h, nil // TLS 1.0/1.1 style hello without extensions
	}
	exts := c.bytes(int(c.u16()))
	if c.failed {
		return nil, fmt.Errorf("%w: truncated extensions", ErrMalformed)
	}
	if c.remaining() != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes after extensions", ErrMalformed, c.remaining())
	}
	if err := h.parseExtensions(exts); err != nil {
		return nil, err
	}
	return h, nil
}

// assembleHandshake collects the handshake bytes of the ClientHello from
// one or more records and returns the message body (after the 4-byte
// handshake header).
func assembleHandshake(b []byte) ([]byte, error) {
	var hs []byte
	need := -1
	rest := b
	for need < 0 || len(hs) < need {
		if len(rest) < 5 {
			return nil, ErrIncomplete
		}
		if rest[0] != recordHandshake {
			return nil, fmt.Errorf("%w: record type 0x%02x is not handshake", ErrMalformed, rest[0])
		}
		if rest[1] != 0x03 {
			return nil, fmt.Errorf("%w: record version 0x%02x%02x", ErrMalformed, rest[1], rest[2])
		}
		n := int(binary.BigEndian.Uint16(rest[3:5]))
		if n == 0 || n > maxRecord {
			return nil, fmt.Errorf("%w: record length %d", ErrMalformed, n)
		}
		if len(rest) < 5+n {
			return nil, ErrIncomplete
		}
		if hs == nil {
			hs = rest[5 : 5+n : 5+n] // alias the first record; copy only if more follow
		} else {
			hs = append(hs, rest[5:5+n]...)
		}
		rest = rest[5+n:]
		if need < 0 && len(hs) >= 4 {
			if hs[0] != handshakeClientHello {
				return nil, fmt.Errorf("%w: handshake type 0x%02x is not ClientHello", ErrMalformed, hs[0])
			}
			l := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if l > maxHello {
				return nil, fmt.Errorf("%w: handshake length %d", ErrMalformed, l)
			}
			need = 4 + l
		}
	}
	return hs[4:need], nil
}

func (h *ClientHello) parseExtensions(exts []byte) error {
	c := &cursor{b: exts}
	for c.remaining() > 0 {
		typ := c.u16()
		data := c.bytes(int(c.u16()))
		if c.failed {
			return fmt.Errorf("%w: truncated extension", ErrMalformed)
		}
		h.Extensions = append(h.Extensions, typ)
		ec := &cursor{b: data}
		switch typ {
		case ExtServerName:
			// ServerNameList: u16 length, then {u8 type, u16 length, name}.
			list := &cursor{b: ec.bytes(int(ec.u16()))}
			for list.remaining() > 0 {
				nameType := list.u8()
				name := list.bytes(int(list.u16()))
				if list.failed {
					return fmt.Errorf("%w: truncated server_name", ErrMalformed)
				}
				if nameType == 0 && h.ServerName == "" {
					h.ServerName = string(name)
				}
			}
		case ExtSupportedGroups:
			h.SupportedGroups = u16s(ec.bytes(int(ec.u16())))
		case ExtECPointFormats:
			h.ECPointFormats = append([]uint8(nil), ec.bytes(int(ec.u8()))...)
		case ExtSignatureAlgorithms:
			h.SignatureAlgorithms = u16s(ec.bytes(int(ec.u16())))
		case ExtALPN:
			list := &cursor{b: ec.bytes(int(ec.u16()))}
			for list.remaining() > 0 {
				proto := list.bytes(int(list.u8()))
				if list.failed {
					return fmt.Errorf("%w: truncated ALPN list", ErrMalformed)
				}
				h.ALPNProtocols = append(h.ALPNProtocols, string(proto))
			}
		case ExtSupportedVersions:
			h.SupportedVersions = u16s(ec.bytes(int(ec.u8())))
		case ExtKeyShare:
			list := &cursor{b: ec.bytes(int(ec.u16()))}
			for list.remaining() > 0 {
				group := list.u16()
				list.bytes(int(list.u16()))
				if list.failed {
					return fmt.Errorf("%w: truncated key_share", ErrMalformed)
				}
				h.KeyShareGroups = append(h.KeyShareGroups, group)
			}
		}
		if ec.failed {
			return fmt.Errorf("%w: truncated extension %d", ErrMalformed, typ)
		}
	}
	return nil
}

// FromClientHelloInfo converts the ClientHelloInfo crypto/tls hands to
// GetConfigForClient and GetCertificate callbacks. Fields crypto/tls does
// not expose (Random, SessionID, CompressionMethods, ECPointFormats and
// KeyShareGroups) are left empty, and Version is set to 0x0303.
func FromClientHelloInfo(info *tls.ClientHelloInfo) *ClientHello {
	h := &ClientHello{
		Version:       tls.VersionTLS12,
		ServerName:    info.ServerName,
		ALPNProtocols: cloneStrings(info.SupportedProtos),
		CipherSuites:  append([]uint16(nil), info.CipherSuites...),
		Extensions:    append([]uint16(nil), info.Extensions...),
	}
	if len(h.CipherSuites) == 0 {
		h.CipherSuites = nil
	}
	if len(h.Extensions) == 0 {
		h.Extensions = nil
	}
	if len(info.SupportedVersions) > 0 {
		h.SupportedVersions = append([]uint16(nil), info.SupportedVersions...)
	}
	for _, g := range info.SupportedCurves {
		h.SupportedGroups = append(h.SupportedGroups, uint16(g))
	}
	for _, s := range info.SignatureSchemes {
		h.SignatureAlgorithms = append(h.SignatureAlgorithms, uint16(s))
	}
	if len(info.SupportedPoints) > 0 {
		h.ECPointFormats = append([]uint8(nil), info.SupportedPoints...)
	}
	return h
}

// HighestVersion returns the highest protocol version the client offers:
// the largest non-GREASE entry of SupportedVersions, or Version when the
// extension is absent.
func (h *ClientHello) HighestVersion() uint16 {
	best := uint16(0)
	for _, v := range h.SupportedVersions {
		if !IsGREASE(v) && v > best {
			best = v
		}
	}
	if best == 0 {
		return h.Version
	}
	return best
}

// CipherSuiteNames returns the IANA names of the offered cipher suites,
// with GREASE values shown as "GREASE (0x0a0a)" and unknown ones as hex.
func (h *ClientHello) CipherSuiteNames() []string {
	if len(h.CipherSuites) == 0 {
		return nil
	}
	out := make([]string, len(h.CipherSuites))
	for i, s := range h.CipherSuites {
		if IsGREASE(s) {
			out[i] = fmt.Sprintf("GREASE (0x%04x)", s)
		} else {
			out[i] = tls.CipherSuiteName(s)
		}
	}
	return out
}

// JA3String returns the JA3 fingerprint input: the legacy version, cipher
// suites, extension types, supported groups and point formats as decimal
// lists, with GREASE values removed as the JA3 specification requires.
func (h *ClientHello) JA3String() string {
	var sb strings.Builder
	sb.WriteString(strconv.Itoa(int(h.Version)))
	sb.WriteByte(',')
	writeJA3List(&sb, h.CipherSuites)
	sb.WriteByte(',')
	writeJA3List(&sb, h.Extensions)
	sb.WriteByte(',')
	writeJA3List(&sb, h.SupportedGroups)
	sb.WriteByte(',')
	for i, p := range h.ECPointFormats {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(p)))
	}
	return sb.String()
}

// JA3 returns the JA3 fingerprint: the MD5 of JA3String as lower-case hex.
// JA3 is a widely used way to identify TLS client software.
func (h *ClientHello) JA3() string {
	sum := md5.Sum([]byte(h.JA3String()))
	return hex.EncodeToString(sum[:])
}

func writeJA3List(sb *strings.Builder, vals []uint16) {
	first := true
	for _, v := range vals {
		if IsGREASE(v) {
			continue
		}
		if !first {
			sb.WriteByte('-')
		}
		first = false
		sb.WriteString(strconv.Itoa(int(v)))
	}
}

// IsGREASE reports whether v is a GREASE value (RFC 8701): 0x0a0a, 0x1a1a,
// ... 0xfafa. Clients send these to keep servers honest about ignoring
// unknown values; they carry no meaning.
func IsGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// cursor reads big-endian fields from a byte slice, recording an underflow
// instead of panicking.
type cursor struct {
	b      []byte
	failed bool
}

func (c *cursor) remaining() int { return len(c.b) }

func (c *cursor) bytes(n int) []byte {
	if n < 0 || n > len(c.b) {
		c.failed = true
		c.b = nil
		return nil
	}
	out := c.b[:n:n]
	c.b = c.b[n:]
	return out
}

func (c *cursor) u8() uint8 {
	b := c.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (c *cursor) u16() uint16 {
	b := c.bytes(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

// u16s decodes a list of big-endian uint16. An odd trailing byte is
// ignored.
func u16s(b []byte) []uint16 {
	if len(b) < 2 {
		return nil
	}
	out := make([]uint16, len(b)/2)
	for i := range out {
		out[i] = binary.BigEndian.Uint16(b[2*i:])
	}
	return out
}
