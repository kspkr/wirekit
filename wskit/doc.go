// Package wskit parses, inspects and serializes WebSocket frames
// (RFC 6455).
//
// The package does not implement a WebSocket client or server. It works on
// the bytes that flow through one, which makes it suitable for proxies,
// traffic inspectors, protocol tests and fuzzers:
//
//   - [ParseFrame] decodes one frame from a byte slice and [Frame.AppendTo]
//     encodes it again.
//   - [Reader] decodes a stream of frames from an io.Reader with a bound on
//     payload size.
//   - [Assembler] turns frames into complete [Message] values, joining
//     fragmented messages and passing control frames straight through.
//   - [CloseCode] and [ParseClosePayload] interpret Close frames.
//   - [AcceptKey], [IsUpgradeRequest] and [ParseExtensions] cover the HTTP
//     handshake that precedes the frames.
//
// # Parsing versus validating
//
// Parsing is deliberately structural: [ParseFrame] accepts any frame whose
// header and length are well formed, including frames a compliant endpoint
// would reject, so that an inspector can show exactly what was sent.
// [Frame.Validate] and [Message.Validate] then report the RFC 6455 rules a
// frame or message breaks, as errors wrapping [ErrProtocol].
//
// # Untrusted input
//
// All input is treated as hostile. Parsers never panic; they return errors
// wrapping [ErrMalformed], [ErrIncomplete], [ErrTooLarge] or [ErrProtocol].
// [Reader] and [Assembler] bound the memory a peer can make them allocate.
//
// # Extensions
//
// The permessage-deflate extension (RFC 7692) is recognized in the
// handshake by [PermessageDeflate] and its use is visible on frames as RSV1,
// but this package does not decompress payloads.
package wskit
