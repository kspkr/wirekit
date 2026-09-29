package tlskit

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"testing"
)

// handshake runs a real TLS handshake over an in-memory pipe and returns
// both sides' connection states.
func handshake(t *testing.T, serverCfg, clientCfg *tls.Config) (server, client tls.ConnectionState) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	srv := tls.Server(c1, serverCfg)
	cli := tls.Client(c2, clientCfg)
	errc := make(chan error, 1)
	go func() { errc <- srv.Handshake() }()
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	return srv.ConnectionState(), cli.ConnectionState()
}

func TestInspectConnection(t *testing.T) {
	pki := newPKI(t, keyECDSA)
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{pki.leaf.Raw, pki.ca.Raw}, PrivateKey: pki.leafKey}},
		NextProtos:   []string{"h2"},
	}
	clientCfg := &tls.Config{
		RootCAs:    pki.pool(),
		ServerName: "example.com",
		NextProtos: []string{"h2", "http/1.1"},
	}
	srvState, cliState := handshake(t, serverCfg, clientCfg)

	c := InspectConnection(cliState)
	if c.Version != "TLS 1.3" || c.VersionID != tls.VersionTLS13 {
		t.Errorf("version = %q %#x", c.Version, c.VersionID)
	}
	if c.CipherSuite == "" || c.CipherSuiteID == 0 || tls.CipherSuiteName(c.CipherSuiteID) != c.CipherSuite {
		t.Errorf("cipher = %q %#x", c.CipherSuite, c.CipherSuiteID)
	}
	if c.NegotiatedProtocol != "h2" || !c.HandshakeComplete || c.Resumed {
		t.Errorf("alpn %q complete %v resumed %v", c.NegotiatedProtocol, c.HandshakeComplete, c.Resumed)
	}
	if c.KeyExchangeGroup == "" {
		t.Error("no key exchange group")
	}
	if len(c.PeerCertificates) != 2 || c.Leaf().CommonName != "example.com" || !c.PeerCertificates[1].IsCA {
		t.Errorf("peer certs = %d", len(c.PeerCertificates))
	}
	if !c.Verified || len(c.VerifiedChains) != 1 || len(c.VerifiedChains[0]) != 2 {
		t.Errorf("verified %v chains %d", c.Verified, len(c.VerifiedChains))
	}
	// Both sides report the SNI; only the client verified a chain.
	if c.ServerName != "example.com" {
		t.Errorf("client ServerName = %q", c.ServerName)
	}
	s := InspectConnection(srvState)
	if s.ServerName != "example.com" || s.Verified || s.PeerCertificates != nil || s.Leaf() != nil {
		t.Errorf("server side = %+v", s)
	}
	if _, err := json.Marshal(c); err != nil {
		t.Error(err)
	}

	// Zero state is harmless.
	z := InspectConnection(tls.ConnectionState{})
	if z.Version != "0x0000" || z.PeerCertificates != nil || z.Verified || z.KeyExchangeGroup != "" {
		t.Errorf("zero = %+v", z)
	}
}

func TestInspectConnectionTLS12(t *testing.T) {
	pki := newPKI(t, keyECDSA)
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{pki.leaf.Raw}, PrivateKey: pki.leafKey}},
		MaxVersion:   tls.VersionTLS12,
	}
	clientCfg := &tls.Config{RootCAs: pki.pool(), ServerName: "example.com"}
	_, cliState := handshake(t, serverCfg, clientCfg)
	c := InspectConnection(cliState)
	if c.Version != "TLS 1.2" || c.NegotiatedProtocol != "" || !c.Verified {
		t.Errorf("tls12 = %+v", c)
	}
}
