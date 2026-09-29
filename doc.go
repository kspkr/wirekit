// Package wirekit is the root of WireKit, a set of Go packages for
// inspecting, parsing and working with network data.
//
// The root package holds only documentation. The functionality lives in
// focused subpackages that can be imported independently:
//
//   - [github.com/kspkr/wirekit/httpkit]: HTTP messages, ordered headers,
//     cookies, query strings, media types, bounded body capture and an
//     HTTP/1.x reader and writer that preserve wire order.
//   - [github.com/kspkr/wirekit/wskit]: WebSocket frames, message
//     reassembly, close codes and handshake helpers.
//   - [github.com/kspkr/wirekit/tlskit]: TLS connection and certificate
//     summaries, chain verification and a ClientHello parser with JA3.
//   - [github.com/kspkr/wirekit/encoding]: lenient base64 and hex, hex
//     dumps, JSON shape inspection and text detection.
//   - [github.com/kspkr/wirekit/compress]: content-coding decompression
//     (gzip, deflate, br, zstd) with output limits.
//
// WireKit is not an HTTP client, a server framework or a general utility
// library. Its job is to make bytes on the wire easy to parse, inspect,
// normalize, manipulate and serialize, and to do so safely when the bytes
// come from someone else.
//
// # Design
//
// Every parser treats its input as hostile: it never panics, bounds the
// memory it allocates, and reports problems as errors that wrap a small
// set of sentinel values (ErrMalformed, ErrIncomplete, ErrTooLarge,
// ErrProtocol) so callers can distinguish bad input from exceeded limits.
//
// Parsing is separated from validation. A parser accepts anything
// structurally decodable, so an inspector can show exactly what was sent;
// a Validate method then reports the rules the data breaks.
//
// Types are plain values with exported fields and JSON tags, so they can be
// stored, compared and serialized without ceremony. Large payloads are
// represented by a bounded prefix plus the true size rather than loaded in
// full.
//
// Only the compress package has dependencies outside the standard library.
package wirekit
