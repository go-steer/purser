// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package authtest provides the test harness every purser
// authenticator is held to: an in-memory certificate authority and a
// conformance suite.
//
// It exists because the properties that matter in authentication code
// are negative ones. A test that only asserts the happy path passes
// just as well against a check that never runs, so the interesting
// cases are the untrusted issuer, the expired certificate, the
// malformed token, the peer the authorizer should have rejected.
// Writing those once, here, is the reason purser is a shared module
// rather than four copies of the same package.
//
// Certificates are minted in-process. Nothing touches disk, no fixture
// keys live in the repository, and no test rots when a checked-in
// certificate expires.
//
// This package imports testing and is meant for use from tests.
package authtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

// CA is an in-memory certificate authority. Use it to mint client and
// server certificates for handshake tests, and to build the trust pool
// a verifier is configured with.
//
// A test that needs an untrusted-issuer negative creates a second CA
// and offers its leaf to a verifier configured with the first CA's
// pool.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

// NewCA returns a fresh self-signed authority named name. The name
// appears in the issuer DN, so give the trusted and untrusted
// authorities in a test distinguishable names: it is the difference
// between a legible failure and "x509: certificate signed by unknown
// authority".
func NewCA(tb testing.TB, name string) *CA {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("authtest: generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(tb),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("authtest: self-sign CA %q: %v", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("authtest: parse CA %q: %v", name, err)
	}
	return &CA{cert: cert, key: key, der: der}
}

// Cert returns the authority's own certificate.
func (ca *CA) Cert() *x509.Certificate { return ca.cert }

// Pool returns a certificate pool trusting only this authority. Each
// call returns a fresh pool, so a test may add to one without
// affecting another.
func (ca *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// LeafOptions describes a certificate to mint. The zero value yields a
// client certificate valid from an hour ago until an hour from now,
// with no subject and no SANs — useful in itself, as the certificate
// that carries none of the fields an authenticator might read.
type LeafOptions struct {
	// CommonName sets the subject CN.
	CommonName string
	// Organization and OrganizationalUnit set the corresponding
	// subject RDNs, for authenticators that match on OU membership or
	// render the full DN as the identity.
	Organization       []string
	OrganizationalUnit []string

	// EmailSANs, DNSSANs, and IPSANs populate the matching subject
	// alternative names.
	EmailSANs []string
	DNSSANs   []string
	IPSANs    []net.IP
	// URISANs populates URI subject alternative names. SPIFFE IDs go
	// here: a SPIFFE X.509-SVID is an ordinary certificate whose sole
	// URI SAN is a spiffe:// identity, so this mints one without
	// depending on go-spiffe.
	URISANs []string

	// NotBefore and NotAfter override the validity window. Zero means
	// an hour ago and an hour from now respectively; set NotAfter to a
	// past instant for the expired-certificate case.
	NotBefore time.Time
	NotAfter  time.Time

	// ExtKeyUsage overrides the extended key usage. Nil means client
	// authentication.
	ExtKeyUsage []x509.ExtKeyUsage
}

// Issue mints and signs a leaf certificate. The returned
// tls.Certificate carries the leaf's parsed form in its Leaf field and
// the issuing CA in its chain, so it can be presented directly by
// either side of a handshake.
func (ca *CA) Issue(tb testing.TB, opts LeafOptions) tls.Certificate {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("authtest: generate leaf key: %v", err)
	}

	notBefore := opts.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-time.Hour)
	}
	notAfter := opts.NotAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(time.Hour)
	}
	eku := opts.ExtKeyUsage
	if eku == nil {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	uris := make([]*url.URL, 0, len(opts.URISANs))
	for _, raw := range opts.URISANs {
		u, err := url.Parse(raw)
		if err != nil {
			tb.Fatalf("authtest: parse URI SAN %q: %v", raw, err)
		}
		uris = append(uris, u)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial(tb),
		Subject: pkix.Name{
			CommonName:         opts.CommonName,
			Organization:       opts.Organization,
			OrganizationalUnit: opts.OrganizationalUnit,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		// Digital signature alone: these are ECDSA keys, and key
		// encipherment is an RSA-era usage that no TLS 1.3 handshake
		// consults.
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		EmailAddresses:        opts.EmailSANs,
		DNSNames:              opts.DNSSANs,
		IPAddresses:           opts.IPSANs,
		URIs:                  uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		tb.Fatalf("authtest: sign leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("authtest: parse leaf: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, ca.der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

// IssueClient mints a client certificate whose subject CN is cn. A
// shorthand for the common case; reach for Issue when the test cares
// about SANs or validity.
func (ca *CA) IssueClient(tb testing.TB, cn string) tls.Certificate {
	tb.Helper()
	return ca.Issue(tb, LeafOptions{CommonName: cn})
}

// IssueServer mints a server certificate valid for host, which may be
// a DNS name or an IP literal.
func (ca *CA) IssueServer(tb testing.TB, host string) tls.Certificate {
	tb.Helper()
	opts := LeafOptions{
		CommonName:  host,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		opts.IPSANs = []net.IP{ip}
	} else {
		opts.DNSSANs = []string{host}
	}
	return ca.Issue(tb, opts)
}

// serial returns a random 128-bit certificate serial number. Random
// rather than sequential so two CAs in the same test cannot mint
// colliding serials, which some verifiers treat as a re-issued
// certificate.
func serial(tb testing.TB) *big.Int {
	tb.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		tb.Fatalf("authtest: generate serial: %v", err)
	}
	return n
}
