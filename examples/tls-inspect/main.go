// Command tls-inspect connects to a TLS server and prints what WireKit
// learns from the connection and its certificates, or inspects certificates
// from a PEM or DER file.
//
//	go run ./examples/tls-inspect example.com:443
//	go run ./examples/tls-inspect -file chain.pem
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/kspkr/wirekit/tlskit"
)

func main() {
	file := flag.String("file", "", "inspect certificates from this PEM or DER file instead of connecting")
	asJSON := flag.Bool("json", false, "print the summary as JSON")
	flag.Parse()

	switch {
	case *file != "":
		inspectFile(*file, *asJSON)
	case flag.NArg() == 1:
		inspectHost(flag.Arg(0), *asJSON)
	default:
		fmt.Fprintln(os.Stderr, "usage: tls-inspect host:port | tls-inspect -file chain.pem")
		os.Exit(2)
	}
}

func inspectFile(path string, asJSON bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	certs, err := tlskit.ParseCertificates(data)
	if err != nil {
		fatal(err)
	}
	infos := tlskit.InspectCertificates(certs)
	if asJSON {
		printJSON(infos)
		return
	}
	for i, c := range infos {
		fmt.Printf("certificate %d\n", i+1)
		printCertificate(c)
	}
	host := ""
	if len(infos[0].DNSNames) > 0 {
		host = infos[0].DNSNames[0]
	}
	result := tlskit.Verify(certs, host, nil)
	fmt.Println("verifies against system roots:", result.Valid, result.Error)
}

func inspectHost(addr string, asJSON bool) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		addr = net.JoinHostPort(addr, "443")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName: host,
		NextProtos: []string{"h2", "http/1.1"},
		// Verification failures are something we want to report, not stop
		// on, so verify separately below.
		InsecureSkipVerify: true,
	})
	if err != nil {
		fatal(err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	info := tlskit.InspectConnection(state)
	verify := tlskit.Verify(state.PeerCertificates, host, nil)
	if asJSON {
		printJSON(struct {
			Connection tlskit.Connection   `json:"connection"`
			Verify     tlskit.VerifyResult `json:"verify"`
		}{info, verify})
		return
	}
	fmt.Println("version:     ", info.Version)
	fmt.Println("cipher suite:", info.CipherSuite)
	fmt.Println("key exchange:", info.KeyExchangeGroup)
	fmt.Println("alpn:        ", info.NegotiatedProtocol)
	fmt.Println("resumed:     ", info.Resumed)
	fmt.Println("verified:    ", verify.Valid, verify.Error)
	for i, c := range info.PeerCertificates {
		fmt.Printf("\ncertificate %d\n", i+1)
		printCertificate(c)
	}
}

func printCertificate(c tlskit.Certificate) {
	fmt.Println("  subject:    ", c.Subject)
	fmt.Println("  issuer:     ", c.Issuer)
	if len(c.DNSNames) > 0 {
		fmt.Println("  dns names:  ", c.DNSNames)
	}
	fmt.Printf("  valid:       %s to %s (%s left)\n", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"), c.RemainingValidity(time.Now()).Round(24*time.Hour))
	fmt.Printf("  key:         %s %d bits %s\n", c.PublicKeyAlgorithm, c.PublicKeyBits, c.PublicKeyCurve)
	fmt.Println("  signature:  ", c.SignatureAlgorithm)
	fmt.Println("  ca:         ", c.IsCA, " self-signed:", c.SelfSigned)
	fmt.Println("  sha256:     ", c.SHA256)
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
