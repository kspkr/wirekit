package tlskit

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

var fingerprintRe = regexp.MustCompile(`^([0-9A-F]{2}:)+[0-9A-F]{2}$`)

func TestInspectCertificate(t *testing.T) {
	pki := newPKI(t, keyECDSA)
	leaf := InspectCertificate(pki.leaf)

	if leaf.Subject != "CN=example.com,O=Example Inc,C=US" || leaf.CommonName != "example.com" {
		t.Errorf("Subject = %q CN = %q", leaf.Subject, leaf.CommonName)
	}
	if leaf.Issuer != "CN=WireKit Test CA,O=WireKit" {
		t.Errorf("Issuer = %q", leaf.Issuer)
	}
	if !reflect.DeepEqual(leaf.DNSNames, []string{"example.com", "*.example.com"}) {
		t.Errorf("DNSNames = %v", leaf.DNSNames)
	}
	if !reflect.DeepEqual(leaf.IPAddresses, []string{"127.0.0.1", "::1"}) {
		t.Errorf("IPAddresses = %v", leaf.IPAddresses)
	}
	if !reflect.DeepEqual(leaf.EmailAddresses, []string{"admin@example.com"}) || !reflect.DeepEqual(leaf.URIs, []string{"https://example.com"}) {
		t.Errorf("SANs = %v %v", leaf.EmailAddresses, leaf.URIs)
	}
	if leaf.SerialNumber != "2A" || leaf.Version != 3 || leaf.IsCA || leaf.SelfSigned {
		t.Errorf("serial %q version %d ca %v self %v", leaf.SerialNumber, leaf.Version, leaf.IsCA, leaf.SelfSigned)
	}
	if leaf.SignatureAlgorithm != "ECDSA-SHA256" || leaf.PublicKeyAlgorithm != "ECDSA" || leaf.PublicKeyBits != 256 || leaf.PublicKeyCurve != "P-256" {
		t.Errorf("algorithms = %q %q %d %q", leaf.SignatureAlgorithm, leaf.PublicKeyAlgorithm, leaf.PublicKeyBits, leaf.PublicKeyCurve)
	}
	if !reflect.DeepEqual(leaf.KeyUsage, []string{"DigitalSignature", "KeyEncipherment"}) {
		t.Errorf("KeyUsage = %v", leaf.KeyUsage)
	}
	if !reflect.DeepEqual(leaf.ExtKeyUsage, []string{"ServerAuth", "ClientAuth"}) {
		t.Errorf("ExtKeyUsage = %v", leaf.ExtKeyUsage)
	}
	if !fingerprintRe.MatchString(leaf.SHA256) || len(leaf.SHA256) != 32*3-1 || !fingerprintRe.MatchString(leaf.SHA1) || len(leaf.SHA1) != 20*3-1 {
		t.Errorf("fingerprints = %q %q", leaf.SHA256, leaf.SHA1)
	}
	if leaf.SHA256 != Fingerprint(pki.leaf) {
		t.Error("SHA256 differs from Fingerprint")
	}
	// crypto/x509 only generates a SubjectKeyId for CA certificates.
	if leaf.AuthorityKeyID != "01:02:03:04" || leaf.SubjectKeyID != "" {
		t.Errorf("key IDs = %q %q", leaf.AuthorityKeyID, leaf.SubjectKeyID)
	}
	if !reflect.DeepEqual(leaf.OCSPServers, []string{"http://ocsp.example.com"}) ||
		!reflect.DeepEqual(leaf.IssuingCertificateURLs, []string{"http://ca.example.com/ca.crt"}) ||
		!reflect.DeepEqual(leaf.CRLDistributionPoints, []string{"http://crl.example.com/ca.crl"}) {
		t.Errorf("AIA/CRL = %v %v %v", leaf.OCSPServers, leaf.IssuingCertificateURLs, leaf.CRLDistributionPoints)
	}
	if !leaf.NotBefore.Equal(pki.leaf.NotBefore) || !leaf.NotAfter.Equal(pki.leaf.NotAfter) {
		t.Error("validity dates differ")
	}

	ca := InspectCertificate(pki.ca)
	if !ca.IsCA || !ca.SelfSigned || ca.SerialNumber != "01:02:AB" || ca.CommonName != "WireKit Test CA" || ca.SubjectKeyID != "01:02:03:04" {
		t.Errorf("ca = %+v", ca)
	}
	if !reflect.DeepEqual(ca.KeyUsage, []string{"DigitalSignature", "CertSign", "CRLSign"}) || ca.ExtKeyUsage != nil {
		t.Errorf("ca usages = %v %v", ca.KeyUsage, ca.ExtKeyUsage)
	}

	// The summary is plain JSON.
	if _, err := json.Marshal(leaf); err != nil {
		t.Error(err)
	}
	if InspectCertificates(nil) != nil {
		t.Error("InspectCertificates(nil) != nil")
	}
	if got := InspectCertificates([]*x509.Certificate{pki.leaf, pki.ca}); len(got) != 2 || got[1].IsCA != true {
		t.Errorf("InspectCertificates = %d", len(got))
	}
}

func TestInspectCertificateKeyTypes(t *testing.T) {
	rsaPKI := newPKI(t, keyRSA)
	c := InspectCertificate(rsaPKI.leaf)
	if c.PublicKeyAlgorithm != "RSA" || c.PublicKeyBits != 2048 || c.PublicKeyCurve != "" || c.SignatureAlgorithm != "SHA256-RSA" {
		t.Errorf("rsa = %q %d %q %q", c.PublicKeyAlgorithm, c.PublicKeyBits, c.PublicKeyCurve, c.SignatureAlgorithm)
	}
	edPKI := newPKI(t, keyEd25519)
	c = InspectCertificate(edPKI.leaf)
	if c.PublicKeyAlgorithm != "Ed25519" || c.PublicKeyBits != 256 || c.SignatureAlgorithm != "Ed25519" {
		t.Errorf("ed25519 = %q %d %q", c.PublicKeyAlgorithm, c.PublicKeyBits, c.SignatureAlgorithm)
	}
	// Unknown key types are tolerated.
	if bits, curve := publicKeyInfo(nil); bits != 0 || curve != "" {
		t.Error("nil key")
	}
	if got := extKeyUsageName(x509.ExtKeyUsage(99)); got != "Unknown(99)" {
		t.Errorf("unknown EKU = %q", got)
	}
}

func TestCertificateValidity(t *testing.T) {
	c := Certificate{
		NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC),
	}
	if !c.IsValidAt(time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)) || !c.IsValidAt(c.NotBefore) || !c.IsValidAt(c.NotAfter) {
		t.Error("IsValidAt inside/edges")
	}
	if c.IsValidAt(c.NotBefore.Add(-time.Second)) || c.IsValidAt(c.NotAfter.Add(time.Second)) {
		t.Error("IsValidAt outside")
	}
	if c.Expired(c.NotAfter) || !c.Expired(c.NotAfter.Add(time.Second)) {
		t.Error("Expired")
	}
	if got := c.RemainingValidity(c.NotAfter.Add(-time.Hour)); got != time.Hour {
		t.Errorf("RemainingValidity = %v", got)
	}
	if got := c.RemainingValidity(c.NotAfter.Add(time.Hour)); got != -time.Hour {
		t.Errorf("RemainingValidity after expiry = %v", got)
	}
}

func TestParseCertificates(t *testing.T) {
	pki := newPKI(t, keyECDSA)

	// PEM with a non-certificate block mixed in.
	var pemData []byte
	pemData = append(pemData, EncodePEM(pki.leaf)...)
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}})...)
	pemData = append(pemData, EncodePEM(pki.ca)...)
	certs, err := ParseCertificates(pemData)
	if err != nil || len(certs) != 2 || !certs[0].Equal(pki.leaf) || !certs[1].Equal(pki.ca) {
		t.Fatalf("PEM: %d %v", len(certs), err)
	}

	// DER, single and concatenated.
	certs, err = ParseCertificates(pki.leaf.Raw)
	if err != nil || len(certs) != 1 || !certs[0].Equal(pki.leaf) {
		t.Fatalf("DER: %d %v", len(certs), err)
	}
	certs, err = ParseCertificates(append(append([]byte(nil), pki.leaf.Raw...), pki.ca.Raw...))
	if err != nil || len(certs) != 2 {
		t.Fatalf("DER x2: %d %v", len(certs), err)
	}

	// Failures.
	if _, err := ParseCertificates(nil); !errors.Is(err, ErrNoCertificates) {
		t.Errorf("empty: %v", err)
	}
	if _, err := ParseCertificates([]byte("not a certificate")); err == nil {
		t.Error("garbage accepted")
	}
	if _, err := ParseCertificates(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})); !errors.Is(err, ErrNoCertificates) {
		t.Errorf("PEM without certs: %v", err)
	}
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x01}})
	if _, err := ParseCertificates(bad); err == nil || !strings.Contains(err.Error(), "certificate 1") {
		t.Errorf("bad PEM cert: %v", err)
	}
	if _, err := ParseCertificates([]byte{0x30, 0x03, 0x02, 0x01, 0x01}); err == nil {
		t.Error("bad DER accepted")
	}
}

func TestVerify(t *testing.T) {
	pki := newPKI(t, keyECDSA)
	chain := []*x509.Certificate{pki.leaf, pki.ca}

	r := Verify(chain, "example.com", pki.pool())
	if !r.Valid || r.Error != "" || len(r.Chains) != 1 || len(r.Chains[0]) != 2 || r.Chains[0][0].CommonName != "example.com" || !r.Chains[0][1].IsCA {
		t.Errorf("valid chain: %+v", r)
	}
	if r := Verify(chain, "sub.example.com", pki.pool()); !r.Valid {
		t.Errorf("wildcard: %+v", r)
	}
	if r := Verify(chain, "", pki.pool()); !r.Valid {
		t.Errorf("no name check: %+v", r)
	}
	if r := Verify([]*x509.Certificate{pki.leaf}, "example.com", pki.pool()); !r.Valid {
		t.Errorf("leaf only with CA in roots: %+v", r)
	}

	r = Verify(chain, "other.org", pki.pool())
	if r.Valid || r.Error == "" || r.Chains != nil {
		t.Errorf("wrong name: %+v", r)
	}
	r = Verify(chain, "example.com", x509.NewCertPool())
	if r.Valid || !strings.Contains(r.Error, "unknown authority") {
		t.Errorf("no roots: %+v", r)
	}
	r = VerifyAt(chain, "example.com", pki.pool(), time.Now().Add(10*365*24*time.Hour))
	if r.Valid || !strings.Contains(r.Error, "expired") {
		t.Errorf("expired: %+v", r)
	}
	if r := Verify(nil, "", nil); r.Valid || r.Error != ErrNoCertificates.Error() {
		t.Errorf("no certs: %+v", r)
	}
	if _, err := json.Marshal(r); err != nil {
		t.Error(err)
	}
}

func TestColonHex(t *testing.T) {
	if got := colonHex(nil); got != "" {
		t.Errorf("empty = %q", got)
	}
	if got := colonHex([]byte{0x00, 0xab, 0xff}); got != "00:AB:FF" {
		t.Errorf("got %q", got)
	}
}

func BenchmarkInspectCertificate(b *testing.B) {
	pki := newPKI(&testing.T{}, keyECDSA)
	b.ReportAllocs()
	for b.Loop() {
		InspectCertificate(pki.leaf)
	}
}
