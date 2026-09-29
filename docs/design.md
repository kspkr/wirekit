# WireKit design notes

Architecture decisions behind WireKit, the alternatives that were
considered, and what was deliberately left out of the first release. For
contributors, and for the TrafficKit refactor that will consume WireKit.

## Goal

> Make network data easy to parse, inspect, normalize, manipulate and
> serialize.

WireKit is infrastructure for tools that already move traffic. It does not
move traffic itself. The test for every addition is: would a proxy, traffic
inspector, protocol test or fuzzer that is not TrafficKit want this?

## Package layout

```
httpkit/    HTTP messages, headers, cookies, query, media types, body capture, HTTP/1.x I/O
wskit/      WebSocket frames, reassembly, close codes, handshake
tlskit/     TLS connection/certificate summaries, ClientHello parser
encoding/   base64, hex, hex dump, JSON inspection, text detection
compress/   content-coding decompression with limits
internal/   shared helpers (ASCII case folding, token tables)
examples/   runnable programs
tests/      cross-package integration tests and the hostile-input sweep
```

The five public packages do not import each other. The only edge is every
package importing `internal/ascii`. This keeps each package independently
useful and makes the dependency story simple: import `httpkit` and you get
the standard library, nothing else.

### Why `httpkit` and not `http`

The obvious names are `http`, `tls` and `websocket`. Two of those collide
with standard library packages, and the collision is not hypothetical:
`tlskit` takes a `tls.ConnectionState` as input, so every file that uses
it also imports `crypto/tls` and would need an alias. The same is true of
`httpkit` and `net/http` for anyone writing a proxy. Renaming a package
after release breaks every importer, so this was decided first, and
`wskit` follows the same pattern for consistency. `encoding` keeps its
plain name because the standard `encoding` package is almost never
imported directly.

### Why `compress` is separate

Brotli and Zstandard decoding need third-party code. Keeping them in their
own package means `httpkit` stays dependency-free and a consumer that only
needs header parsing does not pull in two compression libraries.

## The message model

```
Request                     Response
├── Method                  ├── Proto
├── URL     *url.URL        ├── StatusCode
├── Proto                   ├── StatusText
├── Host                    ├── Headers   Headers
├── Headers Headers         ├── Body      Body
├── Body    Body            └── Trailer   Headers
└── Trailer Headers
```

Decisions:

- **`Headers` is an ordered slice, not a map.** TrafficKit's roadmap lists
  "header order and casing" as a known gap caused by `net/http`'s map.
  A slice of `{Name, Value}` keeps wire order and spelling, serializes to
  JSON as a list, and iterates with `range`. Lookups are linear, which is
  fine: header blocks are small, and lookups are not the hot path.
  `Set` keeps the existing field's spelling so a modified message changes
  as little as possible.
- **`URL` is a `*url.URL`**, the idiomatic Go type, with custom JSON
  marshalling that writes it as a string. The alternative, a `URL string`
  field, would force every consumer to re-parse.
- **`Body` is a prefix plus a size.** `Data` holds what was retained,
  `Size` counts what crossed the wire, `Truncated` says whether they
  differ. This is the shape TrafficKit already uses and it is the only
  shape that works for a proxy that cannot buffer everything. `Capture` is
  the writer that fills one from a stream; it is safe to snapshot while
  writes continue.
- **`Body.Data` is shared by `Clone`, not copied.** Bodies can be large and
  are treated as immutable once stored. Headers, which are small and often
  edited, are copied.
- **Values, not interfaces.** Every type has exported fields and JSON tags.
  There are no options structs beyond `ReadOptions` and no interfaces
  beyond `wskit.HeaderGetter`, which exists only so both `http.Header` and
  `httpkit.Headers` work with the handshake helpers.

## Parse, then validate

Every parser accepts anything that is structurally decodable. Rule
violations are reported by a separate `Validate` method:

| Parser | Accepts | `Validate` reports |
|---|---|---|
| `httpkit.ParseSetCookie` | any `name=value; attrs` | non-token name, bad octets, `SameSite=None` without `Secure`, `__Host-` rules, size, bad `Expires` |
| `wskit.ParseFrame` | any well-formed header and length | reserved opcodes, RSV bits, fragmented or oversize control frames, bad close payloads, masking direction |
| `wskit.Assembler` | frames in any order | fragmentation rule violations (these must be errors, since reassembly depends on them) |

The reason is the audience. A debugger's job is to show what the server
actually sent and then explain what is wrong with it. A parser that refuses
malformed input hides the evidence; one that silently accepts it hides the
problem.

The exception is HTTP/1.x framing. `ReadRequest` and `ReadResponse` reject
obsolete line folding, whitespace before a header colon, conflicting
`Content-Length` values, and `Transfer-Encoding` without a final `chunked`,
because accepting those is how request smuggling happens and the RFC tells
recipients to reject them. When the head parses but the body cannot be
read, the message is returned together with the error so the inspector can
still show the head.

## Errors

Each package exposes a few sentinels and every error wraps one:

| Sentinel | Meaning |
|---|---|
| `ErrMalformed` | the bytes cannot be this protocol |
| `ErrIncomplete` | more bytes are needed (`wskit`, `tlskit`) |
| `ErrTooLarge` | a configured limit was exceeded |
| `ErrProtocol` | parses, but breaks a rule an endpoint must fail on (`wskit`) |
| `ErrCorrupt`, `ErrUnsupported` | `compress` |
| `ErrInvalid` | `encoding` |

Callers use `errors.Is`. Nothing requires matching error text.

## Limits and defaults

Everything that allocates in proportion to input has a limit, and zero
means a safe default rather than "unlimited":

| Limit | Default |
|---|---|
| `httpkit.ReadOptions.MaxHeaderBytes` | 1 MiB (matches `net/http`) |
| `httpkit.ReadOptions.MaxBodyBytes` (retained) | 1 MiB; the rest is counted |
| `httpkit` chunk-size line | 4 KiB |
| `wskit.Reader` payload | 16 MiB, checked before allocating |
| `wskit.Assembler.MaxMessage` | 64 MiB |
| `tlskit.ParseClientHello` record / message | 18 KiB / 64 KiB |
| `encoding.MaxJSONDepth` | 10 000 |
| `compress` decoded output | 64 MiB |

`ParseRequest([]byte)` and friends retain everything, because the data is
already in memory.

## Performance choices

- Header lookups fold ASCII case with a byte loop and allocate nothing.
- `wskit.ParseFrame` aliases the input for unmasked frames and unmasks into
  a fresh buffer for masked ones; `Mask` works eight bytes at a time.
  `wskit.Reader` always returns owned payloads, so the aliasing rule only
  applies to the low-level function and is documented there.
- `httpkit.Capture` is a mutex around an append; a snapshot copies once.
- `encoding.InspectJSON` walks tokens with `json.Decoder` instead of
  building a tree, so its memory is independent of document size. It is
  the slowest thing in the module (about 20 MB/s) because the standard
  token decoder allocates per token; a hand-written scanner is a possible
  later improvement if it matters.

## What was left out of v0.1, and why

- **permessage-deflate inflation** in `wskit`. TrafficKit has a working
  implementation with context-takeover handling. It is contained, but its
  desync semantics deserve their own design pass; RSV1 is exposed so
  callers know a message is compressed.
- **Head-only streaming readers** (`ReadRequestHead` returning a body
  `io.Reader`). Needed only once a consumer relays bodies through WireKit
  instead of `net/http`. Can be added without breaking anything.
- **HTTP/2 frame inspection.** Different wire format, different package.
- **Multipart and form body parsing** beyond `ParseQuery`. The standard
  `mime/multipart` covers it for now.
- **HAR import/export**, redaction, filter languages. Application features.
- **Certificate transparency, OCSP, revocation.** Network operations, not
  parsing.

## TrafficKit integration map

For the refactor that makes TrafficKit consume WireKit:

| TrafficKit today | WireKit |
|---|---|
| `traffic.Header`, `[]traffic.Header`, `HeaderList(http.Header)` | `httpkit.Header`, `httpkit.Headers`, `httpkit.FromStd` |
| `traffic.Body{Size, Captured, Truncated}` + `SetData` | `httpkit.Body{Data, Size, Truncated}`, `Captured()` |
| `proxy.capture`, `teeBody` | `httpkit.Capture`, `Capture.TeeReader` |
| `traffic.mediaType` | `Headers.ContentType().MediaType` |
| `proxy.removeHopHeaders` | `Headers.RemoveHopByHop` |
| `proxy.upgradeType` | `Headers.UpgradeProtocol` |
| `bodyutil.Decode`, `MaxDecoded`, `ErrTooLarge` | `compress.Decode`, `DefaultMaxDecoded`, `ErrTooLarge` |
| `proxy.wsDecoder` (framing, masking, reassembly) | `wskit.Reader` or `wskit.ParseFrame` + `wskit.Assembler` |
| `proxy.parseDeflate` | `wskit.ParseExtensions` + `wskit.PermessageDeflate` |
| `WSMessage.Type` strings | `wskit.Opcode` (`String()` gives the same names) |
| first-byte `0x16` TLS peek | `tlskit.IsClientHello`, then `ParseClientHello` for SNI |
| UI `parseCookieHeader`, `parseSetCookie` | `httpkit.ParseCookies`, `ParseSetCookie` (server side) |
| UI `isTextType`, `isJsonType`, `looksLikeText`, `stripXssi`, `hexDump` | `ContentType.IsText`/`IsJSON`, `encoding.LooksLikeText`, `StripXSSI`, `HexDump` |

TrafficKit's `Exchange`, `Summary`, `Timings`, `Failure`, store and event
hub stay in TrafficKit: they describe a *capture*, not a protocol.

## Versioning

Semantic versioning. v0.1.0 is tagged once this document, the README and
the API agree and the test suite is green on all CI targets. Until 1.0,
API changes are allowed in minor versions and are listed in the changelog.
