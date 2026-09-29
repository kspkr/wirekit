// Package encoding holds small helpers for the encodings that show up when
// inspecting network traffic: base64 and hex as they appear in headers,
// tokens and payloads, hex dumps of binary data, and light JSON and text
// inspection.
//
// The decoders are lenient on purpose. Data seen on the wire rarely
// matches one alphabet or padding convention exactly, so [DecodeBase64]
// and [DecodeHex] accept the variants that occur in practice and reject
// only what cannot be decoded at all.
//
// Everything here is bounded and never panics on hostile input. The
// package is not a general encoding library: for producing output use the
// standard library's encoding/base64 and encoding/hex directly.
package encoding
