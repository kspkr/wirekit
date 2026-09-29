package tlskit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

// testPKI is a CA and a leaf certificate generated for a test.
type testPKI struct {
	ca, leaf       *x509.Certificate
	caKey, leafKey crypto.Signer
}

type keyKind int

const (
	keyECDSA keyKind = iota
	keyRSA
	keyEd25519
)

func newKey(t *testing.T, kind keyKind) crypto.Signer {
	t.Helper()
	var (
		key crypto.Signer
		err error
	)
	switch kind {
	case keyECDSA:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case keyRSA:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case keyEd25519:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// newPKI builds a CA and a leaf for example.com valid for a year.
func newPKI(t *testing.T, kind keyKind) testPKI {
	t.Helper()
	now := time.Now()
	caKey := newKey(t, kind)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0x0102ab),
		Subject:               pkix.Name{CommonName: "WireKit Test CA", Organization: []string{"WireKit"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey := newKey(t, kind)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "example.com", Organization: []string{"Example Inc"}, Country: []string{"US"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              []string{"example.com", "*.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		EmailAddresses:        []string{"admin@example.com"},
		URIs:                  []*url.URL{{Scheme: "https", Host: "example.com"}},
		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://ca.example.com/ca.crt"},
		CRLDistributionPoints: []string{"http://crl.example.com/ca.crl"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, leafKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return testPKI{ca: ca, leaf: leaf, caKey: caKey, leafKey: leafKey}
}

func (p testPKI) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.ca)
	return pool
}
