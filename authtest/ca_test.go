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

package authtest_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-steer/purser/authtest"
)

const serverName = "purser.test.example"

// handshakeResult is what the server observed about its peer.
type handshakeResult struct {
	state tls.ConnectionState
	err   error
}

// mutualHandshake runs a real TLS handshake over an in-memory pipe: a
// server requiring and verifying a client certificate against
// serverTrust, and a client presenting clientCert and trusting
// clientTrust.
//
// The point of driving a real handshake, rather than assembling a
// tls.ConnectionState by hand, is that the properties under test
// belong to crypto/tls rather than to this package. A hand-built
// state would assert only that the test author's beliefs are
// self-consistent.
func mutualHandshake(t *testing.T, serverTrust *x509.CertPool, serverCert tls.Certificate, clientTrust *x509.CertPool, clientCert tls.Certificate) handshakeResult {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	deadline := time.Now().Add(30 * time.Second)
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set server deadline: %v", err)
	}
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	server := tls.Server(serverConn, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    serverTrust,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	})
	client := tls.Client(clientConn, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      clientTrust,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	})

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Handshake() }()
	clientHandshakeErr := client.Handshake()

	// Under TLS 1.3 the client finishes before the server has looked at
	// its certificate, so a rejection arrives as an alert afterwards.
	// net.Pipe is unbuffered: without a reader, the server's alert write
	// blocks until the deadline and every negative test costs a timeout.
	go func() { _, _ = io.Copy(io.Discard, client) }()

	err := <-serverErr
	if err == nil {
		err = clientHandshakeErr
	}
	return handshakeResult{state: server.ConnectionState(), err: err}
}

// TestIssuedClientCertVerifies is the baseline: a leaf this CA signed
// is accepted by a verifier configured with this CA's pool.
func TestIssuedClientCertVerifies(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	res := mutualHandshake(t, ca.Pool(), ca.IssueServer(t, serverName), ca.Pool(),
		ca.IssueClient(t, "alice@example.com"))
	if res.err != nil {
		t.Fatalf("handshake with a certificate from the trusted CA: %v", res.err)
	}
	if len(res.state.PeerCertificates) == 0 {
		t.Fatal("server saw no peer certificate")
	}
	if got := res.state.PeerCertificates[0].Subject.CommonName; got != "alice@example.com" {
		t.Errorf("peer CN = %q, want %q", got, "alice@example.com")
	}
}

// TestPKIProfilePopulatesVerifiedChains pins the stdlib behavior the
// PKI half of the mTLS profile reads its identity from. The SPIFFE
// profile leaves VerifiedChains empty, and the contrast between the
// two is the single easiest thing to get wrong in this module — this
// is the baseline half of that pair.
func TestPKIProfilePopulatesVerifiedChains(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	res := mutualHandshake(t, ca.Pool(), ca.IssueServer(t, serverName), ca.Pool(),
		ca.IssueClient(t, "alice@example.com"))
	if res.err != nil {
		t.Fatalf("handshake: %v", res.err)
	}
	if len(res.state.VerifiedChains) == 0 {
		t.Fatal("VerifiedChains is empty under RequireAndVerifyClientCert; " +
			"the PKI profile reads its peer certificate from VerifiedChains[0][0]")
	}
	if got := res.state.VerifiedChains[0][0]; !got.Equal(res.state.PeerCertificates[0]) {
		t.Error("VerifiedChains[0][0] is not the peer certificate")
	}
}

// TestUntrustedIssuerRejected is the negative the whole harness exists
// for: without it, a verifier that accepts everything passes the
// positive test above.
func TestUntrustedIssuerRejected(t *testing.T) {
	t.Parallel()

	trusted := authtest.NewCA(t, "purser-test-ca")
	attacker := authtest.NewCA(t, "purser-test-attacker-ca")

	res := mutualHandshake(t, trusted.Pool(), trusted.IssueServer(t, serverName), trusted.Pool(),
		attacker.IssueClient(t, "alice@example.com"))
	if res.err == nil {
		t.Fatal("handshake succeeded with a certificate from an untrusted CA")
	}
}

func TestExpiredClientCertRejected(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	expired := ca.Issue(t, authtest.LeafOptions{
		CommonName: "alice@example.com",
		NotBefore:  time.Now().Add(-2 * time.Hour),
		NotAfter:   time.Now().Add(-time.Hour),
	})

	res := mutualHandshake(t, ca.Pool(), ca.IssueServer(t, serverName), ca.Pool(), expired)
	if res.err == nil {
		t.Fatal("handshake succeeded with an expired certificate")
	}
}

func TestIssueCarriesRequestedSANs(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	const spiffeID = "spiffe://example.org/ns/prod/sa/api"
	cert := ca.Issue(t, authtest.LeafOptions{
		CommonName:         "api",
		Organization:       []string{"Example"},
		OrganizationalUnit: []string{"platform"},
		EmailSANs:          []string{"alice@example.com"},
		DNSSANs:            []string{"api.example.com"},
		URISANs:            []string{spiffeID},
	})

	leaf := cert.Leaf
	if leaf == nil {
		t.Fatal("Issue returned a tls.Certificate with a nil Leaf")
	}
	if got := leaf.EmailAddresses; len(got) != 1 || got[0] != "alice@example.com" {
		t.Errorf("email SANs = %v, want [alice@example.com]", got)
	}
	if got := leaf.DNSNames; len(got) != 1 || got[0] != "api.example.com" {
		t.Errorf("DNS SANs = %v, want [api.example.com]", got)
	}
	if got := leaf.URIs; len(got) != 1 || got[0].String() != spiffeID {
		t.Errorf("URI SANs = %v, want [%s]", got, spiffeID)
	}
	if got := leaf.Subject.OrganizationalUnit; len(got) != 1 || got[0] != "platform" {
		t.Errorf("subject OU = %v, want [platform]", got)
	}
}

// TestSPIFFEShapedCertVerifiesOverPKI records that a SPIFFE-shaped
// certificate is an ordinary X.509 certificate: it can be minted and
// chain-verified with the standard library alone. What go-spiffe adds
// is bundle-based verification and SVID validation rules, not a
// different certificate format.
func TestSPIFFEShapedCertVerifiesOverPKI(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	const spiffeID = "spiffe://example.org/ns/prod/sa/api"
	svid := ca.Issue(t, authtest.LeafOptions{URISANs: []string{spiffeID}})

	res := mutualHandshake(t, ca.Pool(), ca.IssueServer(t, serverName), ca.Pool(), svid)
	if res.err != nil {
		t.Fatalf("handshake with a SPIFFE-shaped certificate: %v", res.err)
	}
	uris := res.state.PeerCertificates[0].URIs
	if len(uris) != 1 || uris[0].String() != spiffeID {
		t.Errorf("peer URI SANs = %v, want [%s]", uris, spiffeID)
	}
}

// TestIssueServerUsesIPSANForAnIPHost covers the branch a loopback
// test server takes: a certificate for 127.0.0.1 needs an IP SAN, and
// a DNS name of "127.0.0.1" would not satisfy verification.
func TestIssueServerUsesIPSANForAnIPHost(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	leaf := ca.IssueServer(t, "127.0.0.1").Leaf
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IP SANs = %v, want [127.0.0.1]", leaf.IPAddresses)
	}
	if len(leaf.DNSNames) != 0 {
		t.Errorf("DNS SANs = %v, want none for an IP host", leaf.DNSNames)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     ca.Pool(),
		DNSName:   "127.0.0.1",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("verify as a server certificate for 127.0.0.1: %v", err)
	}
}

func TestZeroLeafOptionsYieldsUsableCert(t *testing.T) {
	t.Parallel()

	// The certificate that carries none of the fields an authenticator
	// might read: it must still be mintable and still chain, so that a
	// "certificate missing the configured subject field" test exercises
	// the authenticator rather than the handshake.
	ca := authtest.NewCA(t, "purser-test-ca")
	bare := ca.Issue(t, authtest.LeafOptions{})

	res := mutualHandshake(t, ca.Pool(), ca.IssueServer(t, serverName), ca.Pool(), bare)
	if res.err != nil {
		t.Fatalf("handshake with a subject-less certificate: %v", res.err)
	}
	leaf := res.state.PeerCertificates[0]
	if leaf.Subject.CommonName != "" || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 {
		t.Errorf("zero LeafOptions produced subject %q / emails %v / URIs %v, want all empty",
			leaf.Subject.CommonName, leaf.EmailAddresses, leaf.URIs)
	}
}

func TestPoolsAreIndependent(t *testing.T) {
	t.Parallel()

	// Each Pool call returns a fresh pool, so a test that adds a
	// second authority to one cannot widen another test's trust.
	ca := authtest.NewCA(t, "purser-test-ca")
	other := authtest.NewCA(t, "purser-test-other-ca")

	widened := ca.Pool()
	widened.AddCert(other.Cert())

	res := mutualHandshake(t, ca.Pool(), ca.IssueServer(t, serverName), ca.Pool(),
		other.IssueClient(t, "alice@example.com"))
	if res.err == nil {
		t.Fatal("a certificate from the other CA verified against a pool that should not trust it")
	}
}

func TestSerialsAreUnique(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	seen := map[string]bool{}
	for range 16 {
		s := ca.IssueClient(t, "alice@example.com").Leaf.SerialNumber.String()
		if seen[s] {
			t.Fatalf("duplicate serial %s", s)
		}
		seen[s] = true
	}
}
