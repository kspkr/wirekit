package tlskit

import "crypto/tls"

// Connection summarizes the negotiated state of a TLS connection.
type Connection struct {
	// Version is the protocol version name, e.g. "TLS 1.3".
	Version string `json:"version"`
	// VersionID is the numeric version, e.g. 0x0304.
	VersionID uint16 `json:"versionId"`
	// CipherSuite is the IANA name, e.g. "TLS_AES_128_GCM_SHA256".
	CipherSuite string `json:"cipherSuite"`
	// CipherSuiteID is the numeric cipher suite.
	CipherSuiteID uint16 `json:"cipherSuiteId"`
	// ServerName is the SNI the client sent, if any.
	ServerName string `json:"serverName,omitempty"`
	// NegotiatedProtocol is the ALPN protocol, e.g. "h2", if any.
	NegotiatedProtocol string `json:"negotiatedProtocol,omitempty"`
	// Resumed reports whether the session was resumed rather than fully
	// negotiated.
	Resumed bool `json:"resumed"`
	// HandshakeComplete reports whether the handshake finished.
	HandshakeComplete bool `json:"handshakeComplete"`
	// KeyExchangeGroup names the group used for key exchange, e.g.
	// "X25519MLKEM768" or "CurveP256", or "" when unknown (for example on a
	// resumed session without a fresh key exchange).
	KeyExchangeGroup string `json:"keyExchangeGroup,omitempty"`
	// ECHAccepted reports whether Encrypted Client Hello was accepted.
	ECHAccepted bool `json:"echAccepted,omitempty"`

	// PeerCertificates are the certificates the peer presented, leaf first.
	PeerCertificates []Certificate `json:"peerCertificates,omitempty"`
	// Verified reports whether crypto/tls built at least one chain from the
	// leaf to a trusted root. It is always false when verification was
	// skipped (InsecureSkipVerify) or not requested.
	Verified bool `json:"verified"`
	// VerifiedChains holds each chain crypto/tls built, leaf first.
	VerifiedChains [][]Certificate `json:"verifiedChains,omitempty"`
}

// InspectConnection summarizes a tls.ConnectionState, as obtained from
// tls.Conn.ConnectionState, http.Request.TLS or http.Response.TLS.
func InspectConnection(cs tls.ConnectionState) Connection {
	c := Connection{
		Version:            tls.VersionName(cs.Version),
		VersionID:          cs.Version,
		CipherSuite:        tls.CipherSuiteName(cs.CipherSuite),
		CipherSuiteID:      cs.CipherSuite,
		ServerName:         cs.ServerName,
		NegotiatedProtocol: cs.NegotiatedProtocol,
		Resumed:            cs.DidResume,
		HandshakeComplete:  cs.HandshakeComplete,
		ECHAccepted:        cs.ECHAccepted,
		PeerCertificates:   InspectCertificates(cs.PeerCertificates),
		Verified:           len(cs.VerifiedChains) > 0,
	}
	if cs.CurveID != 0 {
		c.KeyExchangeGroup = cs.CurveID.String()
	}
	if len(cs.VerifiedChains) > 0 {
		c.VerifiedChains = make([][]Certificate, len(cs.VerifiedChains))
		for i, chain := range cs.VerifiedChains {
			c.VerifiedChains[i] = InspectCertificates(chain)
		}
	}
	return c
}

// Leaf returns the peer's leaf certificate, or nil if none was presented.
func (c *Connection) Leaf() *Certificate {
	if len(c.PeerCertificates) == 0 {
		return nil
	}
	return &c.PeerCertificates[0]
}
