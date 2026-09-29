package wskit

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

// CloseCode is the status code carried by a Close frame (RFC 6455 §7.4).
type CloseCode uint16

// Status codes defined by RFC 6455 §7.4.1 and the IANA registry.
const (
	CloseNormal             CloseCode = 1000
	CloseGoingAway          CloseCode = 1001
	CloseProtocolError      CloseCode = 1002
	CloseUnsupportedData    CloseCode = 1003
	CloseNoStatus           CloseCode = 1005 // never sent; means no code was present
	CloseAbnormal           CloseCode = 1006 // never sent; means the connection dropped
	CloseInvalidPayload     CloseCode = 1007
	ClosePolicyViolation    CloseCode = 1008
	CloseMessageTooBig      CloseCode = 1009
	CloseMandatoryExtension CloseCode = 1010
	CloseInternalError      CloseCode = 1011
	CloseServiceRestart     CloseCode = 1012
	CloseTryAgainLater      CloseCode = 1013
	CloseBadGateway         CloseCode = 1014
	CloseTLSHandshake       CloseCode = 1015 // never sent; means TLS failed
)

var closeNames = map[CloseCode]string{
	CloseNormal:             "normal closure",
	CloseGoingAway:          "going away",
	CloseProtocolError:      "protocol error",
	CloseUnsupportedData:    "unsupported data",
	CloseNoStatus:           "no status received",
	CloseAbnormal:           "abnormal closure",
	CloseInvalidPayload:     "invalid frame payload data",
	ClosePolicyViolation:    "policy violation",
	CloseMessageTooBig:      "message too big",
	CloseMandatoryExtension: "mandatory extension",
	CloseInternalError:      "internal error",
	CloseServiceRestart:     "service restart",
	CloseTryAgainLater:      "try again later",
	CloseBadGateway:         "bad gateway",
	CloseTLSHandshake:       "TLS handshake failure",
}

// String returns the registered description of the code, "application
// code" for 3000-3999 or "private use code" for 4000-4999, or "unknown code
// N" otherwise, in every case followed by the numeric code in parentheses.
func (c CloseCode) String() string {
	name, ok := closeNames[c]
	switch {
	case ok:
	case c >= 3000 && c <= 3999:
		name = "application code"
	case c >= 4000 && c <= 4999:
		name = "private use code"
	default:
		return "unknown code " + strconv.Itoa(int(c))
	}
	return name + " (" + strconv.Itoa(int(c)) + ")"
}

// IsValid reports whether the code may appear in a Close frame on the wire:
// 1000-1003, 1007-1014 or 3000-4999. Codes 1004-1006 and 1015 are
// reserved for local use and must never be sent, and everything else is
// unassigned.
func (c CloseCode) IsValid() bool {
	switch {
	case c >= 1000 && c <= 1003:
		return true
	case c >= 1007 && c <= 1014:
		return true
	case c >= 3000 && c <= 4999:
		return true
	}
	return false
}

// ParseClosePayload interprets the payload of a Close frame. An empty
// payload means no status was sent and yields CloseNoStatus. Otherwise the
// first two bytes are the code and the rest is a UTF-8 reason.
//
// The error wraps ErrProtocol when the payload is one byte long, the code
// is not valid on the wire, or the reason is not UTF-8. The code and reason
// are still returned so an inspector can show them.
func ParseClosePayload(p []byte) (code CloseCode, reason string, err error) {
	switch {
	case len(p) == 0:
		return CloseNoStatus, "", nil
	case len(p) == 1:
		return 0, "", fmt.Errorf("%w: close payload of one byte", ErrProtocol)
	}
	code = CloseCode(binary.BigEndian.Uint16(p))
	reason = string(p[2:])
	if !code.IsValid() {
		err = fmt.Errorf("%w: close code %d is not valid on the wire", ErrProtocol, code)
	}
	if !validUTF8(p[2:]) {
		err = fmt.Errorf("%w: close reason is not valid UTF-8", ErrProtocol)
	}
	return code, reason, err
}

// ClosePayload builds the payload of a Close frame from a code and reason.
// The reason is truncated to fit the 125-byte control frame limit, on a
// UTF-8 boundary.
func ClosePayload(code CloseCode, reason string) []byte {
	const maxReason = MaxControlPayload - 2
	if len(reason) > maxReason {
		reason = reason[:maxReason]
		for len(reason) > 0 && !validUTF8([]byte(reason)) {
			reason = reason[:len(reason)-1]
		}
	}
	p := make([]byte, 2, 2+len(reason))
	binary.BigEndian.PutUint16(p, uint16(code))
	return append(p, reason...)
}
