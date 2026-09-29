// Package tlskit inspects TLS connections, certificates and handshakes.
//
// It does not implement TLS; the standard library does that. tlskit turns
// what crypto/tls and crypto/x509 already know into plain, serializable
// values that are convenient to display, log or compare:
//
//   - [InspectConnection] summarizes a tls.ConnectionState: version, cipher
//     suite, server name, ALPN protocol, resumption, key exchange group and
//     the peer's certificates.
//   - [InspectCertificate] summarizes an x509.Certificate: names, validity,
//     key and signature algorithms, usages, fingerprints and extensions.
//   - [ParseCertificates] reads certificates from PEM or DER.
//   - [Verify] checks a certificate chain against a set of roots and
//     reports the result in the same summary form.
//   - [ParseClientHello] decodes a ClientHello from raw bytes without
//     performing a handshake, exposing the server name (SNI), offered
//     versions, cipher suites, ALPN protocols and extensions, and computing
//     a JA3 fingerprint. This is what a proxy needs to decide how to treat
//     a connection before terminating it.
//
// # Untrusted input
//
// [ParseClientHello] treats its input as hostile and never panics; errors
// wrap [ErrMalformed] or [ErrIncomplete]. Certificate parsing is delegated
// to crypto/x509, which has the same guarantee.
package tlskit
