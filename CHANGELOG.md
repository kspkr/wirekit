# Changelog

All notable changes to WireKit are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until
1.0, minor versions may change the API; such changes are called out.

## [Unreleased]

Initial release, intended to become v0.1.0.

### Added

**httpkit**

- `Request` and `Response` message model with JSON serialization and
  conversion to and from `net/http` (`FromRequest`, `FromResponse`,
  `ToStd`).
- `Headers`: ordered, case-insensitive header list that preserves wire
  order and spelling, with `Get`, `Lookup`, `Values`, `Set`, `Add`, `Del`,
  `FromStd`, `ToStd`, and semantic accessors for content type, content
  length, content and transfer codings, connection tokens, upgrade,
  hop-by-hop removal, cookies and set-cookies.
- `Body` (bounded prefix plus true size) and `Capture` (bounded tee
  writer, safe for concurrent snapshots).
- `ReadRequest`, `ReadResponse`, `ParseRequest`, `ParseResponse`,
  `ReadHeaders`, `ParseHeaders`: HTTP/1.x parsing with header and body
  limits, chunked decoding with trailers, RFC 9112 body framing rules, and
  partial results when a body ends early.
- `WriteHead` and `WriteTo` on both message types, re-chunking bodies when
  the headers say chunked.
- Cookies: lenient `ParseCookies` and `ParseSetCookie`, `SetCookie.Validate`
  covering RFC 6265 and 6265bis rules (prefixes, SameSite=None, size,
  Partitioned), `ExpiresAt`, `ParseCookieDate` implementing the RFC 6265
  date algorithm.
- `Params` and `ParseQuery`: ordered, lenient query and form parsing with
  `Encode`.
- `ContentType` and `ParseContentType` with `IsJSON`, `IsXML`, `IsText`,
  `IsForm`, `IsMultipart`, `Charset`, `Boundary`, `Suffix`.

**wskit**

- `Frame`, `ParseFrame`, `AppendTo`, `Bytes`, `WriteTo`, `Mask`.
- `Frame.Validate` and `ValidateDirection` for RFC 6455 rules.
- `Reader` for streaming frames with a payload limit.
- `Assembler` and `Message` for fragment reassembly with a message limit.
- `CloseCode`, `ParseClosePayload`, `ClosePayload`.
- Handshake helpers: `AcceptKey`, `VerifyAccept`, `IsUpgradeRequest`,
  `IsUpgradeResponse`, `ParseExtensions`, `PermessageDeflate`.

**tlskit**

- `InspectConnection` and `Connection` summary of `tls.ConnectionState`.
- `InspectCertificate`, `Certificate` summary, `Fingerprint`,
  `ParseCertificates` (PEM or DER), `EncodePEM`.
- `Verify` and `VerifyAt` returning a `VerifyResult`.
- `ParseClientHello`, `ClientHello`, `IsClientHello`,
  `FromClientHelloInfo`, `JA3`, `JA3String`, `IsGREASE`.

**encoding**

- `DecodeBase64` and `DecodeHex` (lenient), `HexDump`.
- `InspectJSON`, `JSONInfo`, `JSONKind`, `LooksLikeJSON`, `StripXSSI`.
- `LooksLikeText`.

**compress**

- `Decode` and `NewReader` for gzip, deflate (zlib or raw), br and zstd,
  stacked codings, with output limits; `Codings`, `Supported`.

**Project**

- Fuzz tests for every parser, a hostile-input sweep across all entry
  points, benchmarks for the parsing paths, and CI on Linux, Windows and
  macOS with the race detector, vet, gofmt and golangci-lint.
- Runnable examples: `inspect-http`, `websocket-frames`, `tls-inspect`,
  `proxy-capture`.

[Unreleased]: https://github.com/kspkr/wirekit/commits/main
