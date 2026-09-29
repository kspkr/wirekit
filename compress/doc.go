// Package compress undoes HTTP content codings so a body can be inspected.
//
// It supports gzip, deflate (zlib-wrapped or raw, as servers send both),
// br (Brotli) and zstd, and applies stacked codings such as
// "gzip, br" in the right order. Every operation is bounded: a few
// kilobytes of compressed input can expand to gigabytes, so [Decode] and
// [NewReader] stop with [ErrTooLarge] once the output exceeds a limit.
//
// This is the only WireKit package with third-party dependencies, for the
// Brotli and Zstandard decoders the standard library lacks. It is kept
// separate so the rest of WireKit stays dependency-free.
package compress
