// Package httpkit provides types for inspecting, normalizing and
// serializing HTTP messages.
//
// The package is built around a small message model:
//
//   - [Request] and [Response] describe one HTTP message each: start line,
//     [Headers] and a [Body].
//   - [Headers] is an ordered list of name/value pairs. It keeps the order
//     and spelling seen on the wire while offering case-insensitive lookup,
//     which a map-based representation such as net/http's cannot do.
//   - [Body] holds the bytes captured for a message together with how many
//     bytes actually crossed the wire, so callers can keep a bounded prefix
//     of large bodies without losing size information. [Capture] fills one
//     from a stream.
//
// On top of the model there are parsers for the pieces of an HTTP message
// that are usually inspected individually: cookies ([ParseCookies],
// [ParseSetCookie]), query strings ([ParseQuery]) and media types
// ([ParseContentType]).
//
// [ReadRequest] and [ReadResponse] parse HTTP/1.x messages from a stream
// while preserving header order. [FromRequest] and [FromResponse] convert
// net/http values instead. Every message can be written back out with
// [Request.WriteTo] and [Response.WriteTo].
//
// # Untrusted input
//
// Everything parsed by this package is treated as hostile. Parsers never
// panic on malformed input; they return an error that wraps [ErrMalformed]
// (or [ErrTooLarge] when a configured limit is exceeded). Header block and
// body sizes are bounded by [ReadOptions].
//
// # Dependencies
//
// httpkit depends only on the standard library. Content-coding
// decompression, which needs third-party decoders for brotli and zstd,
// lives in the sibling package compress.
package httpkit
