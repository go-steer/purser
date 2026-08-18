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

package ca_test

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-steer/purser/internal/ca"
)

func newCA(tb testing.TB, name string) *ca.CA {
	tb.Helper()
	authority, err := ca.New(name)
	if err != nil {
		tb.Fatalf("ca.New(%q): %v", name, err)
	}
	return authority
}

func TestNewSelfSignsAUsableAuthority(t *testing.T) {
	t.Parallel()

	authority := newCA(t, "purser-test-ca")
	cert := authority.Cert()
	if !cert.IsCA {
		t.Error("the authority's certificate is not marked as a CA")
	}
	if cert.Subject.CommonName != "purser-test-ca" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "purser-test-ca")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("the authority cannot sign certificates")
	}
}

// TestPoolIsFreshPerCall pins that a caller may add to one pool without
// the addition showing up in another. x509.CertPool is a value that
// looks immutable and is not.
func TestPoolIsFreshPerCall(t *testing.T) {
	t.Parallel()

	authority := newCA(t, "purser-test-ca")
	other := newCA(t, "other-ca")

	first := authority.Pool()
	first.AddCert(other.Cert())

	second := authority.Pool()
	if len(second.Subjects()) != 1 { //nolint:staticcheck // Subjects is fine for a pool we built
		t.Errorf("the second pool holds %d subjects, want only the authority's own",
			len(second.Subjects())) //nolint:staticcheck // as above
	}
}

func TestIssueSetsTheRequestedFields(t *testing.T) {
	t.Parallel()

	authority := newCA(t, "purser-test-ca")
	notAfter := time.Now().Add(3 * time.Hour).Truncate(time.Second)
	cert, err := authority.Issue(ca.LeafOptions{
		CommonName:         "api.prod",
		Organization:       []string{"go-steer"},
		OrganizationalUnit: []string{"platform"},
		EmailSANs:          []string{"api@example.org"},
		DNSSANs:            []string{"api.prod.example.org"},
		URISANs:            []string{"spiffe://example.org/ns/prod/sa/api"},
		NotAfter:           notAfter,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	leaf := cert.Leaf
	if leaf == nil {
		t.Fatal("Issue returned a certificate with no parsed Leaf")
	}
	if got := leaf.Subject.CommonName; got != "api.prod" {
		t.Errorf("CommonName = %q, want %q", got, "api.prod")
	}
	if got := leaf.Subject.Organization; len(got) != 1 || got[0] != "go-steer" {
		t.Errorf("Organization = %v, want [go-steer]", got)
	}
	// OU is not decoration: MatchCertOrganizationalUnit is an admission
	// matcher, and a CA that dropped this field would make every test of
	// that matcher pass vacuously.
	if got := leaf.Subject.OrganizationalUnit; len(got) != 1 || got[0] != "platform" {
		t.Errorf("OrganizationalUnit = %v, want [platform]", got)
	}
	if got := leaf.EmailAddresses; len(got) != 1 || got[0] != "api@example.org" {
		t.Errorf("EmailAddresses = %v, want [api@example.org]", got)
	}
	if got := leaf.DNSNames; len(got) != 1 || got[0] != "api.prod.example.org" {
		t.Errorf("DNSNames = %v, want [api.prod.example.org]", got)
	}
	if got := leaf.URIs; len(got) != 1 || got[0].String() != "spiffe://example.org/ns/prod/sa/api" {
		t.Errorf("URIs = %v, want the one SPIFFE ID", got)
	}
	if !leaf.NotAfter.Equal(notAfter.UTC()) {
		t.Errorf("NotAfter = %s, want %s", leaf.NotAfter, notAfter.UTC())
	}
	// Leaf plus issuer, so the certificate can be presented directly.
	if len(cert.Certificate) != 2 {
		t.Errorf("the chain holds %d certificates, want the leaf and its issuer", len(cert.Certificate))
	}
}

func TestIssueRejectsAnUnparseableURISAN(t *testing.T) {
	t.Parallel()

	authority := newCA(t, "purser-test-ca")
	_, err := authority.Issue(ca.LeafOptions{URISANs: []string{"://no-scheme"}})
	if err == nil {
		t.Fatal("Issue accepted a URI SAN that does not parse")
	}
	if !strings.Contains(err.Error(), "URI SAN") {
		t.Errorf("error = %q, want it to name the offending field", err)
	}
}

func TestIssueServerChoosesTheRightSANForTheHost(t *testing.T) {
	t.Parallel()

	authority := newCA(t, "purser-test-ca")

	byIP, err := authority.IssueServer("127.0.0.1")
	if err != nil {
		t.Fatalf("IssueServer by IP: %v", err)
	}
	// The value, not the count. A hostname check matches on the value,
	// so "exactly one IP SAN" passes just as happily for the wrong
	// address — and that is the failure mode these certificates exist to
	// rule out.
	if got := byIP.Leaf.IPAddresses; len(got) != 1 || !got[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IPAddresses = %v, want [127.0.0.1]", got)
	}
	if got := byIP.Leaf.DNSNames; len(got) != 0 {
		t.Errorf("DNSNames = %v, want none for an IP host", got)
	}

	byName, err := authority.IssueServer("api.example.org")
	if err != nil {
		t.Fatalf("IssueServer by name: %v", err)
	}
	if got := byName.Leaf.DNSNames; len(got) != 1 || got[0] != "api.example.org" {
		t.Errorf("DNSNames = %v, want [api.example.org]", got)
	}
	if got := byName.Leaf.IPAddresses; len(got) != 0 {
		t.Errorf("IPAddresses = %v, want none for a DNS host", got)
	}

	// Both must be usable as server certificates. crypto/tls does not
	// enforce EKU on the server's own certificate, but x509.Verify on
	// the client side does, so a missing ServerAuth would surface as a
	// client-side handshake failure with no obvious cause.
	for name, cert := range map[string]tls.Certificate{"by IP": byIP, "by name": byName} {
		if got := cert.Leaf.ExtKeyUsage; len(got) != 1 || got[0] != x509.ExtKeyUsageServerAuth {
			t.Errorf("%s: ExtKeyUsage = %v, want [ServerAuth]", name, got)
		}
	}
}

func TestIssueClientDefaultsToClientAuth(t *testing.T) {
	t.Parallel()

	authority := newCA(t, "purser-test-ca")
	cert, err := authority.IssueClient("alice")
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	if got := cert.Leaf.ExtKeyUsage; len(got) != 1 || got[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", got)
	}
}

// TestEncodePEMRoundTrips is the property the file-backed credential
// source depends on: what this writes, crypto/tls reads back as the same
// keypair.
func TestEncodePEMRoundTrips(t *testing.T) {
	t.Parallel()

	authority := newCA(t, "purser-test-ca")
	original, err := authority.Issue(ca.LeafOptions{CommonName: "api.prod"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	certPEM, keyPEM, err := ca.EncodePEM(original)
	if err != nil {
		t.Fatalf("EncodePEM: %v", err)
	}

	reloaded, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair on the encoded form: %v", err)
	}
	if len(reloaded.Certificate) != len(original.Certificate) {
		t.Fatalf("the reloaded chain holds %d certificates, want %d",
			len(reloaded.Certificate), len(original.Certificate))
	}
	for i := range original.Certificate {
		if string(reloaded.Certificate[i]) != string(original.Certificate[i]) {
			t.Errorf("chain element %d changed across the round trip", i)
		}
	}

	// tls.X509KeyPair already proves the key matches the leaf, but only
	// the encoded key: assert it is the same key, not merely a valid one.
	got, ok := reloaded.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("reloaded private key is %T, want *ecdsa.PrivateKey", reloaded.PrivateKey)
	}
	want, ok := original.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("original private key is %T, want *ecdsa.PrivateKey", original.PrivateKey)
	}
	if !got.Equal(want) {
		t.Error("the round-tripped private key differs from the original")
	}
}

// TestEncodePEMWritesTheLeafFirst pins the ordering both crypto/tls and
// x509svid.Parse assume. A chain written root-first parses as a
// certificate for the root.
func TestEncodePEMWritesTheLeafFirst(t *testing.T) {
	t.Parallel()

	authority := newCA(t, "purser-test-ca")
	cert, err := authority.Issue(ca.LeafOptions{CommonName: "api.prod"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	certPEM, _, err := ca.EncodePEM(cert)
	if err != nil {
		t.Fatalf("EncodePEM: %v", err)
	}

	block, rest := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("the encoded chain holds no PEM block")
	}
	first, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse the first block: %v", err)
	}
	if first.Subject.CommonName != "api.prod" {
		t.Errorf("the first PEM block is %q, want the leaf %q",
			first.Subject.CommonName, "api.prod")
	}
	if len(rest) == 0 {
		t.Error("the encoded chain holds only one block, want the issuer after the leaf")
	}
}

func TestCertPEMIsTheAuthorityAnchor(t *testing.T) {
	t.Parallel()

	authority := newCA(t, "purser-test-ca")
	block, rest := pem.Decode(authority.CertPEM())
	if block == nil {
		t.Fatal("CertPEM produced no PEM block")
	}
	if len(rest) != 0 {
		t.Errorf("CertPEM produced %d trailing bytes, want exactly one block", len(rest))
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CertPEM: %v", err)
	}
	if !parsed.Equal(authority.Cert()) {
		t.Error("CertPEM does not encode the authority's own certificate")
	}
}
