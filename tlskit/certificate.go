package tlskit

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Certificate summarizes an X.509 certificate in plain values. Every field
// is derived from the parsed certificate; nothing is verified. Use Verify
// for that.
type Certificate struct {
	// Subject and Issuer are the distinguished names in RFC 2253 form,
	// e.g. "CN=example.com,O=Example Inc,C=US".
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
	// CommonName is the subject's CN, or "" if it has none.
	CommonName string `json:"commonName,omitempty"`

	// DNSNames, IPAddresses, EmailAddresses and URIs are the subject
	// alternative names.
	DNSNames       []string `json:"dnsNames,omitempty"`
	IPAddresses    []string `json:"ipAddresses,omitempty"`
	EmailAddresses []string `json:"emailAddresses,omitempty"`
	URIs           []string `json:"uris,omitempty"`

	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`

	// SerialNumber is the serial as upper-case hex bytes separated by
	// colons, the way browsers show it.
	SerialNumber string `json:"serialNumber"`
	// Version is the X.509 version (1, 2 or 3).
	Version int `json:"version"`

	// IsCA reports the basic constraints CA flag.
	IsCA bool `json:"isCA"`
	// SelfSigned reports whether the certificate is signed by its own key.
	SelfSigned bool `json:"selfSigned"`

	// SignatureAlgorithm names the algorithm the issuer signed with, e.g.
	// "SHA256-RSA" or "ECDSA-SHA384".
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	// PublicKeyAlgorithm is "RSA", "ECDSA", "Ed25519" or "DSA".
	PublicKeyAlgorithm string `json:"publicKeyAlgorithm"`
	// PublicKeyBits is the RSA modulus size, the ECDSA curve size or 256
	// for Ed25519. Zero when unknown.
	PublicKeyBits int `json:"publicKeyBits,omitempty"`
	// PublicKeyCurve names the ECDSA curve ("P-256"), or is "" otherwise.
	PublicKeyCurve string `json:"publicKeyCurve,omitempty"`

	// KeyUsage and ExtKeyUsage list the usages by name, e.g.
	// "DigitalSignature" and "ServerAuth".
	KeyUsage    []string `json:"keyUsage,omitempty"`
	ExtKeyUsage []string `json:"extKeyUsage,omitempty"`

	// SHA256 and SHA1 are fingerprints of the DER encoding, as upper-case
	// hex bytes separated by colons.
	SHA256 string `json:"sha256"`
	SHA1   string `json:"sha1"`

	// SubjectKeyID and AuthorityKeyID are hex, or "" when absent.
	SubjectKeyID   string `json:"subjectKeyId,omitempty"`
	AuthorityKeyID string `json:"authorityKeyId,omitempty"`

	// OCSPServers, IssuingCertificateURLs and CRLDistributionPoints come
	// from the AIA and CRL extensions.
	OCSPServers            []string `json:"ocspServers,omitempty"`
	IssuingCertificateURLs []string `json:"issuingCertificateUrls,omitempty"`
	CRLDistributionPoints  []string `json:"crlDistributionPoints,omitempty"`
}

// InspectCertificate summarizes cert. It never fails; fields that cannot
// be derived are left zero.
func InspectCertificate(cert *x509.Certificate) Certificate {
	c := Certificate{
		Subject:                cert.Subject.String(),
		Issuer:                 cert.Issuer.String(),
		CommonName:             cert.Subject.CommonName,
		DNSNames:               cloneStrings(cert.DNSNames),
		EmailAddresses:         cloneStrings(cert.EmailAddresses),
		NotBefore:              cert.NotBefore,
		NotAfter:               cert.NotAfter,
		Version:                cert.Version,
		IsCA:                   cert.IsCA,
		SignatureAlgorithm:     cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm:     cert.PublicKeyAlgorithm.String(),
		SHA256:                 Fingerprint(cert),
		SHA1:                   fingerprintSHA1(cert),
		OCSPServers:            cloneStrings(cert.OCSPServer),
		IssuingCertificateURLs: cloneStrings(cert.IssuingCertificateURL),
		CRLDistributionPoints:  cloneStrings(cert.CRLDistributionPoints),
	}
	if cert.SerialNumber != nil {
		c.SerialNumber = colonHex(cert.SerialNumber.Bytes())
	}
	for _, ip := range cert.IPAddresses {
		c.IPAddresses = append(c.IPAddresses, ip.String())
	}
	for _, u := range cert.URIs {
		c.URIs = append(c.URIs, u.String())
	}
	if len(cert.SubjectKeyId) > 0 {
		c.SubjectKeyID = colonHex(cert.SubjectKeyId)
	}
	if len(cert.AuthorityKeyId) > 0 {
		c.AuthorityKeyID = colonHex(cert.AuthorityKeyId)
	}
	c.PublicKeyBits, c.PublicKeyCurve = publicKeyInfo(cert.PublicKey)
	c.KeyUsage = keyUsageNames(cert.KeyUsage)
	for _, eku := range cert.ExtKeyUsage {
		c.ExtKeyUsage = append(c.ExtKeyUsage, extKeyUsageName(eku))
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		c.ExtKeyUsage = append(c.ExtKeyUsage, oid.String())
	}
	// A self-signed certificate is one whose signature verifies with its
	// own key; comparing names alone is not enough.
	c.SelfSigned = cert.CheckSignatureFrom(cert) == nil
	return c
}

// InspectCertificates summarizes each certificate in order.
func InspectCertificates(certs []*x509.Certificate) []Certificate {
	if len(certs) == 0 {
		return nil
	}
	out := make([]Certificate, len(certs))
	for i, c := range certs {
		out[i] = InspectCertificate(c)
	}
	return out
}

// IsValidAt reports whether t falls within the certificate's validity
// period.
func (c Certificate) IsValidAt(t time.Time) bool {
	return !t.Before(c.NotBefore) && !t.After(c.NotAfter)
}

// Expired reports whether the certificate's NotAfter has passed at now.
func (c Certificate) Expired(now time.Time) bool { return now.After(c.NotAfter) }

// RemainingValidity returns how long the certificate stays valid after
// now, or a negative duration if it has expired.
func (c Certificate) RemainingValidity(now time.Time) time.Duration {
	return c.NotAfter.Sub(now)
}

// Fingerprint returns the SHA-256 fingerprint of the certificate's DER
// encoding as upper-case hex bytes separated by colons.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return colonHex(sum[:])
}

func fingerprintSHA1(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.Raw)
	return colonHex(sum[:])
}

// ErrNoCertificates is returned by ParseCertificates when the input holds
// no certificate.
var ErrNoCertificates = errors.New("tlskit: no certificates found")

// ParseCertificates reads every certificate from data, which may be PEM
// (any number of CERTIFICATE blocks, other block types are skipped) or DER
// (one or more certificates back to back). The order is preserved.
func ParseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	sawPEM := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		sawPEM = true
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("tlskit: certificate %d: %w", len(certs)+1, err)
		}
		certs = append(certs, cert)
	}
	if !sawPEM {
		var err error
		if certs, err = x509.ParseCertificates(data); err != nil {
			return nil, fmt.Errorf("tlskit: %w", err)
		}
	}
	if len(certs) == 0 {
		return nil, ErrNoCertificates
	}
	return certs, nil
}

// EncodePEM returns the PEM encoding of the certificates, concatenated.
func EncodePEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// VerifyResult reports the outcome of verifying a certificate chain.
type VerifyResult struct {
	// Valid is true when at least one chain to a trusted root was built.
	Valid bool `json:"valid"`
	// Error describes why verification failed, or is "" when Valid.
	Error string `json:"error,omitempty"`
	// Chains holds every verified chain, leaf first, when Valid.
	Chains [][]Certificate `json:"chains,omitempty"`
}

// Verify checks that certs[0] is valid for dnsName at the current time and
// chains to a root in roots, using the remaining certs as intermediates.
// A nil roots means the system roots. An empty dnsName skips the name
// check. The result reports the outcome instead of returning an error, so
// it can be recorded alongside the certificates.
func Verify(certs []*x509.Certificate, dnsName string, roots *x509.CertPool) VerifyResult {
	return VerifyAt(certs, dnsName, roots, time.Time{})
}

// VerifyAt is Verify at a specific time; the zero time means now.
func VerifyAt(certs []*x509.Certificate, dnsName string, roots *x509.CertPool, at time.Time) VerifyResult {
	if len(certs) == 0 {
		return VerifyResult{Error: ErrNoCertificates.Error()}
	}
	opts := x509.VerifyOptions{
		DNSName:     dnsName,
		Roots:       roots,
		CurrentTime: at,
	}
	if len(certs) > 1 {
		opts.Intermediates = x509.NewCertPool()
		for _, c := range certs[1:] {
			opts.Intermediates.AddCert(c)
		}
	}
	chains, err := certs[0].Verify(opts)
	if err != nil {
		return VerifyResult{Error: err.Error()}
	}
	r := VerifyResult{Valid: true, Chains: make([][]Certificate, len(chains))}
	for i, chain := range chains {
		r.Chains[i] = InspectCertificates(chain)
	}
	return r
}

func publicKeyInfo(key any) (bits int, curve string) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen(), ""
	case *ecdsa.PublicKey:
		if k.Curve == nil {
			return 0, ""
		}
		p := k.Params()
		if p == nil {
			return 0, ""
		}
		name := p.Name
		if name == "" {
			switch k.Curve {
			case elliptic.P256():
				name = "P-256"
			case elliptic.P384():
				name = "P-384"
			case elliptic.P521():
				name = "P-521"
			}
		}
		return p.BitSize, name
	case ed25519.PublicKey:
		return 256, ""
	}
	return 0, ""
}

var keyUsageBits = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "DigitalSignature"},
	{x509.KeyUsageContentCommitment, "ContentCommitment"},
	{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
	{x509.KeyUsageDataEncipherment, "DataEncipherment"},
	{x509.KeyUsageKeyAgreement, "KeyAgreement"},
	{x509.KeyUsageCertSign, "CertSign"},
	{x509.KeyUsageCRLSign, "CRLSign"},
	{x509.KeyUsageEncipherOnly, "EncipherOnly"},
	{x509.KeyUsageDecipherOnly, "DecipherOnly"},
}

func keyUsageNames(ku x509.KeyUsage) []string {
	var out []string
	for _, b := range keyUsageBits {
		if ku&b.bit != 0 {
			out = append(out, b.name)
		}
	}
	return out
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "Any",
	x509.ExtKeyUsageServerAuth:                     "ServerAuth",
	x509.ExtKeyUsageClientAuth:                     "ClientAuth",
	x509.ExtKeyUsageCodeSigning:                    "CodeSigning",
	x509.ExtKeyUsageEmailProtection:                "EmailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "IPSECEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "IPSECTunnel",
	x509.ExtKeyUsageIPSECUser:                      "IPSECUser",
	x509.ExtKeyUsageTimeStamping:                   "TimeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "MicrosoftServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "NetscapeServerGatedCrypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "MicrosoftCommercialCodeSigning",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "MicrosoftKernelCodeSigning",
}

func extKeyUsageName(eku x509.ExtKeyUsage) string {
	if name, ok := extKeyUsageNames[eku]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", eku)
}

// colonHex formats b as upper-case hex bytes separated by colons.
func colonHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.Grow(len(b) * 3)
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(strings.ToUpper(hex.EncodeToString([]byte{c})))
	}
	return sb.String()
}

func cloneStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return append([]string(nil), s...)
}
