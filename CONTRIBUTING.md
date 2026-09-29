# Contributing to WireKit

Thanks for your interest. WireKit is small on purpose, so most of this
document is about keeping it that way.

## What belongs here

WireKit makes network data easy to parse, inspect, normalize, manipulate
and serialize. A change fits when it:

- handles bytes as they appear on the wire (HTTP, WebSocket, TLS, and the
  encodings wrapped around them), and
- would be useful to more than one downstream tool, and
- can be done with the standard library, or with a dependency that earns
  its place (today only the `compress` package has any).

Things that do not belong, even if they are handy: HTTP clients and servers,
frameworks, logging, configuration, storage, CLI plumbing, general string or
crypto utilities, and anything specific to one application. Those live in
the applications that use WireKit.

If you are unsure, open an issue before writing code. It is much easier to
agree on an API in an issue than in a pull request.

## Development

```sh
go build ./...
go test ./...
go vet ./...
gofmt -l .
golangci-lint run          # uses .golangci.yml
```

Fuzz a target for a while (one target per invocation):

```sh
go test ./httpkit -run '^$' -fuzz='^FuzzParseRequest$' -fuzztime=60s
```

Benchmarks:

```sh
go test ./... -run '^$' -bench . -benchmem
```

CI runs the tests on Linux (Go 1.25 and 1.26, with the race detector),
Windows and macOS, plus vet, gofmt, `go mod tidy`, golangci-lint and a
short run of every fuzz target.

## What a change needs

- **Tests.** Unit tests for the behaviour, and for parsers, tests with
  malformed input: truncated, oversized, wrong types, wrong lengths. If you
  add a parser or extend one, add or extend its `Fuzz` function too.
- **No panics on input.** Anything that reads bytes from outside must
  return an error instead. The hostile-input sweep in `tests/` should cover
  any new entry point; add it to the `parsers` map there.
- **Bounded memory.** If input can make you allocate, there must be a
  limit, with a sensible default when the caller passes zero.
- **Classified errors.** Wrap the package's sentinel errors
  (`ErrMalformed`, `ErrTooLarge`, ...) so callers can use `errors.Is`.
- **Documentation.** Every exported identifier has a doc comment that says
  what it does and, where it matters, what it does with bad input.
- **Benchmarks** for anything on a parsing hot path.
- **A changelog entry** under "Unreleased" in `CHANGELOG.md`.

## Style

`gofmt` is the style guide. Beyond that:

- Prefer plain types with exported fields over interfaces and options
  structs until there is a second implementation or a fourth option.
- Follow the parse-then-validate split: parsers accept anything decodable,
  `Validate` methods report rule violations.
- Keep packages independent. `httpkit`, `wskit`, `tlskit`, `encoding` and
  `compress` do not import each other. Shared helpers go in `internal/`.
- Name things the way the RFCs do, then explain in the comment.
- Do not add dependencies without discussing it in an issue first.

## Commits and pull requests

- One logical change per pull request.
- Commit messages: a short imperative summary line, then the context a
  reviewer needs. Explain *why*, the diff already shows *what*.
- Public API changes call out the change in the PR description and in the
  changelog.

By contributing you agree that your work is released under the MIT license
in [LICENSE](LICENSE).
