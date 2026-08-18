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

package client_test

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/go-steer/purser/authn/mtls"
	"github.com/go-steer/purser/authtest"
	"github.com/go-steer/purser/client"
)

const (
	testTrustDomain = "example.org"
	testServerID    = "spiffe://example.org/ns/purser/sa/server"
	testClientID    = "spiffe://example.org/ns/prod/sa/api"
	greeting        = "purser\n"
)

// staticSVIDSource serves one X509-SVID, standing in for the
// workloadapi.X509Source a real deployment uses.
type staticSVIDSource struct{ svid *x509svid.SVID }

func (s *staticSVIDSource) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }

// mutableBundleSource is a trust bundle a test can rewrite mid-run, to
// model an authority being withdrawn while a session ticket is still
// outstanding.
type mutableBundleSource struct {
	mu     sync.Mutex
	bundle *x509bundle.Bundle
}

func (m *mutableBundleSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bundle.GetX509BundleForTrustDomain(td)
}

func (m *mutableBundleSource) set(b *x509bundle.Bundle) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bundle = b
}

func trustDomain(tb testing.TB, s string) spiffeid.TrustDomain {
	tb.Helper()
	td, err := spiffeid.TrustDomainFromString(s)
	if err != nil {
		tb.Fatalf("parse trust domain %q: %v", s, err)
	}
	return td
}

// bundleOf returns a trust bundle for td holding the given authorities.
func bundleOf(tb testing.TB, td string, cas ...*authtest.CA) *x509bundle.Bundle {
	tb.Helper()
	authorities := make([]*x509.Certificate, 0, len(cas))
	for _, ca := range cas {
		authorities = append(authorities, ca.Cert())
	}
	return x509bundle.FromX509Authorities(trustDomain(tb, td), authorities)
}

// mintSVID issues an X509-SVID carrying id.
func mintSVID(tb testing.TB, ca *authtest.CA, id string) *x509svid.SVID {
	tb.Helper()
	cert := ca.Issue(tb, authtest.LeafOptions{
		URISANs: []string{id},
		// An SVID is presented by both ends of an mTLS connection, so
		// it carries both usages.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	})
	key, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		tb.Fatalf("leaf private key is %T, want a crypto.Signer", cert.PrivateKey)
	}
	parsed, err := spiffeid.FromString(id)
	if err != nil {
		tb.Fatalf("parse SPIFFE ID %q: %v", id, err)
	}
	return &x509svid.SVID{ID: parsed, Certificates: []*x509.Certificate{cert.Leaf}, PrivateKey: key}
}

// serveTLS runs a listener that completes the handshake, writes a fixed
// greeting, and stays open until the peer closes.
//
// Raw TLS rather than HTTP because these tests assert on
// tls.ConnectionState — DidResume in particular — which net/http does
// not surface per connection. Staying open until the peer closes
// matters too: the client processes the server's NewSessionTicket
// messages on its first read, so a server that hung up immediately
// would leave the session cache empty and the resumption tests would
// pass vacuously.
func serveTLS(tb testing.TB, cfg *tls.Config) string {
	tb.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	tb.Cleanup(func() { _ = ln.Close() })

	tlsLn := tls.NewListener(ln, cfg)
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if _, err := conn.Write([]byte(greeting)); err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// dialTLS completes one handshake, reads the greeting, and returns the
// connection state.
func dialTLS(tb testing.TB, addr string, cfg *tls.Config) (tls.ConnectionState, error) {
	tb.Helper()

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		tb.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, len(greeting))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return tls.ConnectionState{}, err
	}
	if string(buf) != greeting {
		tb.Fatalf("greeting = %q, want %q", buf, greeting)
	}
	return conn.ConnectionState(), nil
}

// --- PKI profile ---------------------------------------------------

func TestNewPKIRejectsIncompleteOptions(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	cert := ca.IssueClient(t, "alice")

	tests := []struct {
		name    string
		opts    client.PKIOptions
		wantErr string
	}{
		{
			name:    "no certificate at all",
			opts:    client.PKIOptions{RootCAs: ca.Pool()},
			wantErr: "one of Certificate or GetClientCertificate",
		},
		{
			name: "both certificate forms",
			opts: client.PKIOptions{
				Certificate: &cert,
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &cert, nil
				},
				RootCAs: ca.Pool(),
			},
			wantErr: "mutually exclusive",
		},
		{
			name:    "no roots",
			opts:    client.PKIOptions{Certificate: &cert},
			wantErr: "RootCAs is required",
		},
		{
			name: "a floor below TLS 1.2",
			opts: client.PKIOptions{
				Certificate: &cert,
				RootCAs:     ca.Pool(),
				MinVersion:  tls.VersionTLS11,
			},
			wantErr: "below TLS 1.2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := client.NewPKI(tc.opts)
			if err == nil {
				t.Fatalf("NewPKI accepted %s and returned %+v", tc.name, cfg)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewPKIConfigShape(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	cert := ca.IssueClient(t, "alice")

	cfg, err := client.NewPKI(client.PKIOptions{Certificate: &cert, RootCAs: ca.Pool()})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %#04x, want TLS 1.3 by default", cfg.MinVersion)
	}
	if cfg.InsecureSkipVerify {
		t.Error("the PKI profile set InsecureSkipVerify; crypto/tls must verify the server")
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs is nil")
	}
	if cfg.GetClientCertificate == nil {
		t.Fatal("GetClientCertificate is nil, so no client certificate would be presented")
	}
	got, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if got.Leaf == nil || got.Leaf.Subject.CommonName != "alice" {
		t.Errorf("GetClientCertificate returned %v, want alice's certificate", got.Leaf)
	}
	if cfg.ServerName != "" {
		t.Errorf("ServerName = %q, want empty so crypto/tls uses the dialed host", cfg.ServerName)
	}
	if len(cfg.NextProtos) != 0 {
		t.Errorf("NextProtos = %v, want none by default", cfg.NextProtos)
	}
}

// TestNewPKICarriesServerNameAndNextProtos covers the two fields that are
// pure pass-through and so would go unnoticed if a constructor dropped
// them: ServerName is the hostname the server's certificate is checked
// against, and NextProtos decides whether HTTP/2 is even offered.
func TestNewPKICarriesServerNameAndNextProtos(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	cert := ca.IssueClient(t, "alice")
	protos := []string{"h2", "http/1.1"}

	cfg, err := client.NewPKI(client.PKIOptions{
		Certificate: &cert,
		RootCAs:     ca.Pool(),
		ServerName:  "api.example.org",
		NextProtos:  protos,
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	if cfg.ServerName != "api.example.org" {
		t.Errorf("ServerName = %q, want %q", cfg.ServerName, "api.example.org")
	}
	if !slices.Equal(cfg.NextProtos, protos) {
		t.Errorf("NextProtos = %v, want %v", cfg.NextProtos, protos)
	}

	// Copied, not aliased. net/http appends to this slice in place when
	// it enables HTTP/2, so a shared backing array would let one
	// transport rewrite the caller's own list.
	protos[0] = "mutated"
	if cfg.NextProtos[0] != "h2" {
		t.Errorf("NextProtos[0] = %q after mutating the caller's slice, want %q — the "+
			"constructor aliased it instead of copying", cfg.NextProtos[0], "h2")
	}
}

// TestNewPKIServerNameIsVerified proves ServerName is not merely stored:
// an otherwise trusted server presenting a certificate for a different
// name must be rejected.
func TestNewPKIServerNameIsVerified(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	cert := ca.IssueClient(t, "alice")
	addr := newPKIServer(t, ca, nil) // its certificate names 127.0.0.1

	cfg, err := client.NewPKI(client.PKIOptions{
		Certificate: &cert,
		RootCAs:     ca.Pool(),
		ServerName:  "elsewhere.example.org",
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	if _, err := dialTLS(t, addr, cfg); err == nil {
		t.Fatal("the client accepted a server whose certificate names a different host")
	}
}

// newPKIServer starts a listener from mtls.NewPKI and returns its
// address, so the client is exercised against the real server profile
// rather than a hand-built config.
func newPKIServer(tb testing.TB, ca *authtest.CA, admit mtls.CertMatcher) string {
	tb.Helper()

	serverCert := ca.IssueServer(tb, "127.0.0.1")
	cfg, _, err := mtls.NewPKI(mtls.PKIOptions{
		Certificate: &serverCert,
		ClientCAs:   ca.Pool(),
		Subject:     mtls.SubjectCommonName,
		Admit:       admit,
	})
	if err != nil {
		tb.Fatalf("mtls.NewPKI: %v", err)
	}
	return serveTLS(tb, cfg)
}

func TestPKIEndToEndHandshake(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	other := authtest.NewCA(t, "untrusted-ca")
	addr := newPKIServer(t, ca, nil)

	t.Run("trusted client and server", func(t *testing.T) {
		t.Parallel()

		cert := ca.IssueClient(t, "alice")
		cfg, err := client.NewPKI(client.PKIOptions{Certificate: &cert, RootCAs: ca.Pool()})
		if err != nil {
			t.Fatalf("NewPKI: %v", err)
		}
		state, err := dialTLS(t, addr, cfg)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		if len(state.VerifiedChains) == 0 {
			t.Error("VerifiedChains is empty on an accepted PKI connection")
		}
	})

	t.Run("server from an authority the client does not trust", func(t *testing.T) {
		t.Parallel()

		cert := ca.IssueClient(t, "alice")
		cfg, err := client.NewPKI(client.PKIOptions{Certificate: &cert, RootCAs: other.Pool()})
		if err != nil {
			t.Fatalf("NewPKI: %v", err)
		}
		if _, err := dialTLS(t, addr, cfg); err == nil {
			t.Error("the handshake succeeded against a server the client's pool does not trust")
		}
	})

	t.Run("client certificate the server does not trust", func(t *testing.T) {
		t.Parallel()

		cert := other.IssueClient(t, "mallory")
		cfg, err := client.NewPKI(client.PKIOptions{Certificate: &cert, RootCAs: ca.Pool()})
		if err != nil {
			t.Fatalf("NewPKI: %v", err)
		}
		if _, err := dialTLS(t, addr, cfg); err == nil {
			t.Error("the server accepted a client certificate from an untrusted authority")
		}
	})
}

// TestPKIGetClientCertificateIsCalledPerHandshake covers the rotating
// alternative to a fixed Certificate: the callback must reach the
// handshake, not be snapshotted at construction.
func TestPKIGetClientCertificateIsCalledPerHandshake(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	// A server that admits only the rotated identity, so the two dials
	// have to disagree. Counting calls alone would pass on a callback
	// memoised in a sync.Once — the exact bug that makes an in-place
	// rotation silently stop working — because the count would still be
	// non-zero and the stale certificate would still be presented.
	addr := newPKIServer(t, ca, mtls.MatchCertFunc(func(cert *x509.Certificate) error {
		if cert.Subject.CommonName != "alice-rotated" {
			return fmt.Errorf("not the rotated identity: %q", cert.Subject.CommonName)
		}
		return nil
	}))

	var mu sync.Mutex
	var calls int
	current := ca.IssueClient(t, "alice")

	cfg, err := client.NewPKI(client.PKIOptions{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			mu.Lock()
			defer mu.Unlock()
			calls++
			return &current, nil
		},
		RootCAs: ca.Pool(),
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	if _, err := dialTLS(t, addr, cfg); err == nil {
		t.Fatal("the server admitted the pre-rotation identity, so the second dial " +
			"would prove nothing")
	}

	mu.Lock()
	current = ca.IssueClient(t, "alice-rotated")
	first := calls
	mu.Unlock()

	if _, err := dialTLS(t, addr, cfg); err != nil {
		t.Fatalf("the rotated credential was not presented on the second handshake: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if first == 0 {
		t.Error("GetClientCertificate was never called; the callback did not reach the handshake")
	}
	if calls <= first {
		t.Errorf("GetClientCertificate was called %d times across two handshakes, want one "+
			"call per handshake", calls)
	}
}

func TestPKIClientAdmitRejectsTheServer(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	addr := newPKIServer(t, ca, nil)
	cert := ca.IssueClient(t, "alice")

	cfg, err := client.NewPKI(client.PKIOptions{
		Certificate: &cert,
		RootCAs:     ca.Pool(),
		Admit:       mtls.MatchCertDNSSAN("not-the-server.example"),
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	_, err = dialTLS(t, addr, cfg)
	if err == nil {
		t.Fatal("the client accepted a server its own matcher must reject")
	}
	// The full prefix, so this cannot pass on some other layer's phrasing
	// — x509's own "certificate is not valid for any names", say, which
	// also contains "not admitted" nowhere but is the kind of message a
	// looser match invites.
	if !strings.Contains(err.Error(), "purser/client: server not admitted") {
		t.Errorf("error = %q, want it to name purser's admission check", err)
	}
	// And the matcher's own reason has to survive, or an operator sees
	// only that something was rejected.
	if !strings.Contains(err.Error(), "not-the-server.example") {
		t.Errorf("error = %q, want it to carry the matcher's reason", err)
	}
}

// TestPKIClientAdmitAppliesOnResumedSessions is the client-side mirror
// of the server's VerifyConnection property. crypto/tls does not call
// VerifyPeerCertificate on a resumed handshake, so a matcher installed
// there would stop applying the moment a client reconnected with a
// ticket — admitting a peer under a policy that no longer holds.
func TestPKIClientAdmitAppliesOnResumedSessions(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	addr := newPKIServer(t, ca, nil)
	cert := ca.IssueClient(t, "alice")

	var admitted int
	var mu sync.Mutex
	cfg, err := client.NewPKI(client.PKIOptions{
		Certificate: &cert,
		RootCAs:     ca.Pool(),
		Admit: func(*x509.Certificate) error {
			mu.Lock()
			defer mu.Unlock()
			admitted++
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)

	if _, err := dialTLS(t, addr, cfg); err != nil {
		t.Fatalf("first dial: %v", err)
	}
	state, err := dialTLS(t, addr, cfg)
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	// Fatal rather than Skip, matching establishResumption. A skip here
	// would turn "this client and server stopped resuming" into a silent
	// pass, and the whole point of the test is what happens when they do.
	if !state.DidResume {
		t.Fatal("the second connection did not resume, so this test proves nothing about " +
			"resumed handshakes; the session cache or the server's ticket issuance changed")
	}

	mu.Lock()
	defer mu.Unlock()
	if admitted != 2 {
		t.Errorf("the matcher ran %d times across two connections, want 2; "+
			"it must apply to resumed handshakes as well as full ones", admitted)
	}
}

// --- SPIFFE profile ------------------------------------------------

func TestNewSPIFFERejectsIncompleteOptions(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	svid := &staticSVIDSource{svid: mintSVID(t, ca, testClientID)}
	bundle := bundleOf(t, testTrustDomain, ca)

	tests := []struct {
		name    string
		opts    client.SPIFFEOptions
		wantErr string
	}{
		{
			name:    "no SVID source",
			opts:    client.SPIFFEOptions{BundleSource: bundle, Authorize: spiffeid.MatchAny()},
			wantErr: "SVIDSource is required",
		},
		{
			name:    "no bundle source",
			opts:    client.SPIFFEOptions{SVIDSource: svid, Authorize: spiffeid.MatchAny()},
			wantErr: "BundleSource is required",
		},
		{
			name:    "no authorizer",
			opts:    client.SPIFFEOptions{SVIDSource: svid, BundleSource: bundle},
			wantErr: "Authorize is required",
		},
		{
			name: "a floor below TLS 1.2",
			opts: client.SPIFFEOptions{
				SVIDSource:   svid,
				BundleSource: bundle,
				Authorize:    spiffeid.MatchAny(),
				MinVersion:   tls.VersionTLS11,
			},
			wantErr: "below TLS 1.2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := client.NewSPIFFE(tc.opts)
			if err == nil {
				t.Fatalf("NewSPIFFE accepted %s and returned %+v", tc.name, cfg)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewSPIFFEConfigShape(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	newConfig := func(tb testing.TB, minVersion uint16, protos []string) *tls.Config {
		tb.Helper()
		cfg, err := client.NewSPIFFE(client.SPIFFEOptions{
			SVIDSource:   &staticSVIDSource{svid: mintSVID(tb, ca, testClientID)},
			BundleSource: bundleOf(tb, testTrustDomain, ca),
			Authorize:    spiffeid.MatchAny(),
			MinVersion:   minVersion,
			NextProtos:   protos,
		})
		if err != nil {
			tb.Fatalf("NewSPIFFE: %v", err)
		}
		return cfg
	}

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()

		cfg := newConfig(t, 0, nil)
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Errorf("MinVersion = %#04x, want TLS 1.3 by default", cfg.MinVersion)
		}
		if len(cfg.NextProtos) != 0 {
			t.Errorf("NextProtos = %v, want none by default", cfg.NextProtos)
		}
		// The one field on this profile that must not be touched: with
		// it false, crypto/tls would try to build a chain for an SVID it
		// has no hostname or pool for and every handshake would fail.
		if !cfg.InsecureSkipVerify {
			t.Error("InsecureSkipVerify is false; the SPIFFE profile verifies in VerifyConnection")
		}
		if cfg.VerifyConnection == nil {
			t.Fatal("VerifyConnection is nil, so nothing would verify the server at all")
		}
	})

	// MinVersion is not decoration here: it is also what keeps the
	// ECH-rejected path unreachable, since crypto/tls will not offer ECH
	// below TLS 1.3. See TestECHRejectionNeedsNoHook.
	t.Run("a configured floor is honoured", func(t *testing.T) {
		t.Parallel()

		if got := newConfig(t, tls.VersionTLS12, nil).MinVersion; got != tls.VersionTLS12 {
			t.Errorf("MinVersion = %#04x, want the configured TLS 1.2", got)
		}
	})

	t.Run("a floor below TLS 1.2 is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := client.NewSPIFFE(client.SPIFFEOptions{
			SVIDSource:   &staticSVIDSource{svid: mintSVID(t, ca, testClientID)},
			BundleSource: bundleOf(t, testTrustDomain, ca),
			Authorize:    spiffeid.MatchAny(),
			MinVersion:   tls.VersionTLS11,
		})
		if err == nil {
			t.Fatal("NewSPIFFE accepted a TLS 1.1 floor")
		}
		if !strings.Contains(err.Error(), "below TLS 1.2") {
			t.Errorf("error = %q, want it to name the floor", err)
		}
	})

	t.Run("NextProtos is carried and copied", func(t *testing.T) {
		t.Parallel()

		protos := []string{"h2", "http/1.1"}
		cfg := newConfig(t, 0, protos)
		if !slices.Equal(cfg.NextProtos, protos) {
			t.Errorf("NextProtos = %v, want %v", cfg.NextProtos, protos)
		}
		protos[0] = "mutated"
		if cfg.NextProtos[0] != "h2" {
			t.Errorf("NextProtos[0] = %q after mutating the caller's slice, want %q",
				cfg.NextProtos[0], "h2")
		}
	})
}

// newSPIFFEServer starts a listener from mtls.NewSPIFFE.
func newSPIFFEServer(tb testing.TB, ca *authtest.CA) string {
	tb.Helper()

	cfg, _, err := mtls.NewSPIFFE(mtls.SPIFFEOptions{
		SVIDSource:   &staticSVIDSource{svid: mintSVID(tb, ca, testServerID)},
		BundleSource: bundleOf(tb, testTrustDomain, ca),
	})
	if err != nil {
		tb.Fatalf("mtls.NewSPIFFE: %v", err)
	}
	return serveTLS(tb, cfg)
}

func TestSPIFFEEndToEndHandshake(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	other := authtest.NewCA(t, "untrusted-ca")
	addr := newSPIFFEServer(t, ca)
	bundle := bundleOf(t, testTrustDomain, ca)

	serverID, err := spiffeid.FromString(testServerID)
	if err != nil {
		t.Fatalf("parse the server ID: %v", err)
	}

	t.Run("the expected server", func(t *testing.T) {
		t.Parallel()

		cfg, err := client.NewSPIFFE(client.SPIFFEOptions{
			SVIDSource:   &staticSVIDSource{svid: mintSVID(t, ca, testClientID)},
			BundleSource: bundle,
			Authorize:    spiffeid.MatchID(serverID),
		})
		if err != nil {
			t.Fatalf("NewSPIFFE: %v", err)
		}
		state, err := dialTLS(t, addr, cfg)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		// The mirror of the server-side property: go-spiffe verifies
		// outside crypto/tls's chain builder, so VerifiedChains stays
		// empty on an accepted SPIFFE connection.
		if len(state.VerifiedChains) != 0 {
			t.Errorf("VerifiedChains holds %d chains on a SPIFFE connection, want none",
				len(state.VerifiedChains))
		}
	})

	t.Run("a server the authorizer rejects", func(t *testing.T) {
		t.Parallel()

		wrong, err := spiffeid.FromString("spiffe://example.org/ns/purser/sa/other")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		cfg, err := client.NewSPIFFE(client.SPIFFEOptions{
			SVIDSource:   &staticSVIDSource{svid: mintSVID(t, ca, testClientID)},
			BundleSource: bundle,
			Authorize:    spiffeid.MatchID(wrong),
		})
		if err != nil {
			t.Fatalf("NewSPIFFE: %v", err)
		}
		_, err = dialTLS(t, addr, cfg)
		if err == nil {
			t.Fatal("the client accepted a server SPIFFE ID its authorizer must reject")
		}
		if !strings.Contains(err.Error(), "not authorized") {
			t.Errorf("error = %q, want it to say the server was not authorized", err)
		}
	})

	t.Run("a server whose authority is not in the bundle", func(t *testing.T) {
		t.Parallel()

		cfg, err := client.NewSPIFFE(client.SPIFFEOptions{
			SVIDSource:   &staticSVIDSource{svid: mintSVID(t, ca, testClientID)},
			BundleSource: bundleOf(t, testTrustDomain, other),
			Authorize:    spiffeid.MatchAny(),
		})
		if err != nil {
			t.Fatalf("NewSPIFFE: %v", err)
		}
		if _, err := dialTLS(t, addr, cfg); err == nil {
			t.Error("the client accepted a server SVID from an authority outside its bundle")
		}
	})
}

// TestSPIFFEClientVerifiesOnResumedSessions is the reason this package
// does not return tlsconfig.MTLSClientConfig.
//
// The setup: connect once successfully, so the client caches a session
// ticket. Then withdraw the authority from the client's bundle — a
// compromised CA revoked, the everyday reason a bundle changes — and
// connect again. The second connection resumes, and must be rejected:
// the server's SVID no longer chains to anything the client trusts.
//
// purser verifies from VerifyConnection, which crypto/tls calls on
// resumed handshakes, so it is. The subtest below pins that go-spiffe's
// own helper is not, which is what makes this a purser property rather
// than something inherited for free.
func TestSPIFFEClientVerifiesOnResumedSessions(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	addr := newSPIFFEServer(t, ca)
	empty := x509bundle.New(trustDomain(t, testTrustDomain))

	t.Run("purser rejects the resumed connection", func(t *testing.T) {
		t.Parallel()

		bundle := &mutableBundleSource{bundle: bundleOf(t, testTrustDomain, ca)}
		cfg, err := client.NewSPIFFE(client.SPIFFEOptions{
			SVIDSource:   &staticSVIDSource{svid: mintSVID(t, ca, testClientID)},
			BundleSource: bundle,
			Authorize:    spiffeid.MatchAny(),
		})
		if err != nil {
			t.Fatalf("NewSPIFFE: %v", err)
		}
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)

		// Two dials before the bundle changes, to establish that this
		// client and this server do in fact resume. Without it, a third
		// dial that fails proves nothing: it might have been a full
		// handshake, where verification was never in doubt.
		establishResumption(t, addr, cfg)

		bundle.set(empty)

		// The rejection cannot be attributed to the resumed path with
		// certainty: dialTLS returns a zero ConnectionState on error, so
		// DidResume is unreadable here. Establishing resumption above is
		// what makes the inference sound — a third dial to the same
		// server with the same cache resumes as the second did, and if it
		// somehow fell back to a full handshake the verification under
		// test would have run anyway. The sibling subtest, which succeeds
		// and so can read the state, checks DidResume directly.
		if _, err := dialTLS(t, addr, cfg); err == nil {
			t.Error("the client accepted a server whose authority had been withdrawn from the " +
				"bundle; verification is not running on the resumed handshake")
		}
	})

	// Pin the upstream gap. If go-spiffe closes it, this fails and the
	// deviation documented in the package comment can be revisited.
	t.Run("go-spiffe's MTLSClientConfig does not", func(t *testing.T) {
		t.Parallel()

		bundle := &mutableBundleSource{bundle: bundleOf(t, testTrustDomain, ca)}
		cfg := tlsconfig.MTLSClientConfig(
			&staticSVIDSource{svid: mintSVID(t, ca, testClientID)},
			bundle,
			tlsconfig.AuthorizeAny(),
		)
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)

		establishResumption(t, addr, cfg)

		bundle.set(empty)

		state, err := dialTLS(t, addr, cfg)
		switch {
		case err != nil:
			// Falsifiable on purpose. Resumption is established above, so
			// a rejection here means go-spiffe now verifies on the resumed
			// path — good news, and the reason to revisit the deviation
			// documented in the package comment rather than skip past it.
			t.Errorf("go-spiffe's MTLSClientConfig rejected the resumed connection (%v); "+
				"the upstream gap this pins appears to be closed, so purser's reason for "+
				"not returning tlsconfig.MTLSClientConfig should be re-examined", err)
		case !state.DidResume:
			t.Error("the third connection did not resume even though the second did; " +
				"the upstream gap is no longer being exercised and this pin has gone quiet")
		default:
			t.Log("as expected: go-spiffe's MTLSClientConfig accepted a resumed connection " +
				"after its trust bundle was emptied, because crypto/tls skips " +
				"VerifyPeerCertificate on resumption")
		}
	})
}

// establishResumption dials addr twice with cfg and fails the test
// unless the second connection resumed the first.
//
// Every "verification still runs on a resumed handshake" assertion needs
// this first. A test that dials once, changes something, dials again and
// sees a rejection has not shown anything about resumption unless the
// second handshake actually resumed — and if the server never issues a
// usable ticket, it never will.
func establishResumption(tb testing.TB, addr string, cfg *tls.Config) {
	tb.Helper()

	first, err := dialTLS(tb, addr, cfg)
	if err != nil {
		tb.Fatalf("first dial: %v", err)
	}
	if first.DidResume {
		tb.Fatal("the first connection resumed; the session cache should have been empty")
	}
	second, err := dialTLS(tb, addr, cfg)
	if err != nil {
		tb.Fatalf("second dial: %v", err)
	}
	if !second.DidResume {
		tb.Fatal("the second connection did not resume, so this test cannot say anything " +
			"about verification on resumed handshakes")
	}
}

// TestSPIFFEClientPresentsItsSVID pins that the client actually
// authenticates, rather than merely verifying the server. The server
// requires a client certificate, so a config that presented none would
// fail the handshake.
func TestSPIFFEClientPresentsItsSVID(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	cfg, err := client.NewSPIFFE(client.SPIFFEOptions{
		SVIDSource:   &staticSVIDSource{svid: mintSVID(t, ca, testClientID)},
		BundleSource: bundleOf(t, testTrustDomain, ca),
		Authorize:    spiffeid.MatchAny(),
	})
	if err != nil {
		t.Fatalf("NewSPIFFE: %v", err)
	}
	if cfg.GetClientCertificate == nil {
		t.Fatal("GetClientCertificate is nil, so no SVID would be presented")
	}
	got, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if got.Leaf == nil {
		t.Fatal("the presented certificate has no parsed leaf")
	}
	if len(got.Leaf.URIs) != 1 || got.Leaf.URIs[0].String() != testClientID {
		t.Errorf("presented URIs = %v, want the single SPIFFE ID %q", got.Leaf.URIs, testClientID)
	}
}

// TestSPIFFEClientSurvivesAnEmptyBundleAtDial covers the source
// returning an error rather than stale anchors: the handshake must fail
// rather than proceed unverified.
func TestSPIFFEClientSurvivesAnEmptyBundleAtDial(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	addr := newSPIFFEServer(t, ca)

	cfg, err := client.NewSPIFFE(client.SPIFFEOptions{
		SVIDSource:   &staticSVIDSource{svid: mintSVID(t, ca, testClientID)},
		BundleSource: &erroringBundleSource{},
		Authorize:    spiffeid.MatchAny(),
	})
	if err != nil {
		t.Fatalf("NewSPIFFE: %v", err)
	}
	if _, err := dialTLS(t, addr, cfg); err == nil {
		t.Error("the handshake succeeded although the bundle source could supply no anchors")
	}
}

type erroringBundleSource struct{}

func (e *erroringBundleSource) GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return nil, errors.New("bundle unavailable")
}

// --- Encrypted Client Hello ------------------------------------------

// echConfigList builds a syntactically valid ECHConfigList, enough for
// crypto/tls to accept it and offer ECH. Nothing decrypts it: the point
// is to reach the rejected path, which is what an ordinary server that
// has never heard of ECH produces.
//
// Wire format is draft-ietf-tls-esni-18 §4. Any 32 bytes are a valid
// X25519 public key, so the key need not correspond to anything.
func echConfigList() []byte {
	publicName := []byte("public.example")
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i + 1)
	}

	var contents []byte
	contents = append(contents, 0x01)       // config_id
	contents = append(contents, 0x00, 0x20) // kem_id: DHKEM(X25519, HKDF-SHA256)
	contents = append(contents, 0x00, 0x20) // public_key length
	contents = append(contents, pub...)
	contents = append(contents, 0x00, 0x04) // cipher_suites length
	contents = append(contents, 0x00, 0x01) // kdf_id: HKDF-SHA256
	contents = append(contents, 0x00, 0x01) // aead_id: AES-128-GCM
	contents = append(contents, 0x00)       // maximum_name_length
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = append(contents, 0x00, 0x00) // extensions

	cfg := []byte{0xfe, 0x0d} // version: draft-13
	cfg = append(cfg, byte(len(contents)>>8), byte(len(contents)))
	cfg = append(cfg, contents...)

	return append([]byte{byte(len(cfg) >> 8), byte(len(cfg))}, cfg...)
}

// TestECHRejectionNeedsNoHook pins the two independent reasons neither
// constructor installs EncryptedClientHelloRejectionVerify.
//
// The setup invites one. crypto/tls guards both VerifyPeerCertificate
// and VerifyConnection with `&& !echRejected` and calls the ECH hook
// instead, and the fallback it falls back to verifies against RootCAs
// without consulting InsecureSkipVerify — which reads exactly like the
// resumption hole this package does close. An earlier version of this
// package installed the hook on both profiles. It was wrong twice over,
// and each subtest here is one of the two reasons, expressed so that it
// fails if a future Go changes the behaviour it depends on.
func TestECHRejectionNeedsNoHook(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	clientCert := ca.IssueClient(t, "alice")

	t.Run("neither profile installs a hook", func(t *testing.T) {
		t.Parallel()

		pki, err := client.NewPKI(client.PKIOptions{
			Certificate: &clientCert,
			RootCAs:     ca.Pool(),
			Admit:       mtls.MatchCertFunc(func(*x509.Certificate) error { return nil }),
		})
		if err != nil {
			t.Fatalf("NewPKI: %v", err)
		}
		if pki.EncryptedClientHelloRejectionVerify != nil {
			t.Error("the PKI profile installs an ECH-rejection hook; see the subtests below " +
				"for why one cannot help and does harm")
		}
		spiffe, err := client.NewSPIFFE(client.SPIFFEOptions{
			SVIDSource:   &staticSVIDSource{svid: mintSVID(t, ca, testClientID)},
			BundleSource: bundleOf(t, testTrustDomain, ca),
			Authorize:    spiffeid.MatchAny(),
		})
		if err != nil {
			t.Fatalf("NewSPIFFE: %v", err)
		}
		if spiffe.EncryptedClientHelloRejectionVerify != nil {
			t.Error("the SPIFFE profile installs an ECH-rejection hook; see the subtests below")
		}
	})

	// Reason one, and the decisive one: whatever the hook decides, the
	// connection is never usable. The TLS 1.3 client sends
	// alertECHRequired and returns *tls.ECHRejectionError before marking
	// the handshake complete. A hook can only make that error worse — it
	// would replace the RetryConfigs a caller needs to recover from a
	// stale ECH config with a bad_certificate alert.
	t.Run("an ECH-rejected handshake fails whatever the hook decides", func(t *testing.T) {
		t.Parallel()

		addr := newPKIServer(t, ca, nil)
		cfg, err := client.NewPKI(client.PKIOptions{
			Certificate: &clientCert,
			RootCAs:     ca.Pool(),
		})
		if err != nil {
			t.Fatalf("NewPKI: %v", err)
		}
		cfg.EncryptedClientHelloConfigList = echConfigList()
		// The most permissive hook there is. If a rejected handshake can
		// ever succeed, it succeeds here.
		cfg.EncryptedClientHelloRejectionVerify = func(tls.ConnectionState) error { return nil }

		state, err := dialTLS(t, addr, cfg)
		if err == nil {
			t.Fatal("an ECH-rejected handshake completed; the hook purser omits would " +
				"then be load-bearing and must be restored")
		}
		var echErr *tls.ECHRejectionError
		if !errors.As(err, &echErr) {
			t.Errorf("error = %v (%T), want *tls.ECHRejectionError — crypto/tls aborts the "+
				"handshake on rejection regardless of the hook", err, err)
		}
		if state.HandshakeComplete {
			t.Error("the handshake was marked complete on an ECH-rejected connection")
		}
	})

	// Reason two: the hook could not verify anything even if reason one
	// were fixed. crypto/tls calls it with the ConnectionState built
	// before c.peerCertificates is assigned, so PeerCertificates is
	// empty and any honest hook fails unconditionally. If this subtest
	// starts failing, crypto/tls has moved the assignment — revisit
	// reason one first, since that is what makes the path unreachable.
	t.Run("crypto/tls calls the hook before it records the peer certificates", func(t *testing.T) {
		t.Parallel()

		addr := newPKIServer(t, ca, nil)
		cfg, err := client.NewPKI(client.PKIOptions{
			Certificate: &clientCert,
			RootCAs:     ca.Pool(),
		})
		if err != nil {
			t.Fatalf("NewPKI: %v", err)
		}
		cfg.EncryptedClientHelloConfigList = echConfigList()

		var called bool
		var sawCerts, sawChains int
		cfg.EncryptedClientHelloRejectionVerify = func(cs tls.ConnectionState) error {
			called, sawCerts, sawChains = true, len(cs.PeerCertificates), len(cs.VerifiedChains)
			return nil
		}
		if _, err := dialTLS(t, addr, cfg); err == nil {
			t.Fatal("an ECH-rejected handshake completed")
		}
		if !called {
			t.Fatal("crypto/tls did not call the ECH-rejection hook, so this test proves nothing")
		}
		if sawCerts != 0 {
			t.Errorf("the hook saw %d peer certificates, want 0 — crypto/tls has started "+
				"populating them, so the reasoning in the package comment needs revisiting",
				sawCerts)
		}
		if sawChains != 0 {
			t.Errorf("the hook saw %d verified chains, want 0", sawChains)
		}
	})

	// The only way past reason one would be to negotiate TLS 1.2, where
	// there is no post-handshake abort. crypto/tls closes that off: it
	// refuses to offer ECH at all below 1.3, and these constructors
	// always set MinVersion, so neither spelling gets there.
	t.Run("ECH below TLS 1.3 is refused outright", func(t *testing.T) {
		t.Parallel()

		addr := newPKIServer(t, ca, nil)
		cfg, err := client.NewPKI(client.PKIOptions{
			Certificate: &clientCert,
			RootCAs:     ca.Pool(),
			MinVersion:  tls.VersionTLS12,
		})
		if err != nil {
			t.Fatalf("NewPKI: %v", err)
		}
		cfg.EncryptedClientHelloConfigList = echConfigList()

		_, err = dialTLS(t, addr, cfg)
		if err == nil {
			t.Fatal("a TLS 1.2 floor negotiated a connection with ECH configured; the " +
				"ECH-rejected path may now be reachable without the 1.3 abort")
		}
		if !strings.Contains(err.Error(), "MinVersion must be >= VersionTLS13") {
			t.Errorf("error = %q, want crypto/tls's refusal to offer ECH below TLS 1.3", err)
		}
	})
}

// --- Mispaired profiles ----------------------------------------------

// TestMispairedProfiles records what actually happens when a client
// built for one profile dials a listener built for the other.
//
// The package comment used to claim the mismatch is caught. It is not,
// in general: mispairing is a configuration error, not a security
// boundary, and these subtests are the evidence for that wording. The
// PKI direction happens to fail — but on hostname verification, which is
// incidental — and the SPIFFE direction succeeds outright once the
// listener's certificate is SVID-shaped.
func TestMispairedProfiles(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")

	t.Run("a PKI client rejects a SPIFFE listener", func(t *testing.T) {
		t.Parallel()

		addr := newSPIFFEServer(t, ca)
		cert := ca.IssueClient(t, "alice")
		cfg, err := client.NewPKI(client.PKIOptions{Certificate: &cert, RootCAs: ca.Pool()})
		if err != nil {
			t.Fatalf("client.NewPKI: %v", err)
		}

		_, err = dialTLS(t, addr, cfg)
		if err == nil {
			t.Fatal("a PKI client accepted a SPIFFE listener")
		}
		// Note *why*. An X509-SVID carries a URI SAN and nothing else, so
		// the standard hostname check has no name to match — the profile
		// mismatch is not what rejected it, and a SPIFFE listener that
		// also carried a DNS SAN would be accepted.
		if !strings.Contains(err.Error(), "not valid for any names") &&
			!strings.Contains(err.Error(), "doesn't contain any IP SANs") {
			t.Logf("rejected with %v", err)
		}
	})

	t.Run("a SPIFFE client accepts an SVID-shaped PKI listener", func(t *testing.T) {
		t.Parallel()

		// A PKI listener whose own certificate happens to be SVID-shaped.
		// Contrived, but not absurd: a deployment migrating to SPIFFE
		// issues SVID-shaped certificates from the same CA well before it
		// switches the server constructor over.
		serverSVID := mintSVID(t, ca, testServerID)
		serverCert := tls.Certificate{
			Certificate: [][]byte{serverSVID.Certificates[0].Raw},
			PrivateKey:  serverSVID.PrivateKey,
			Leaf:        serverSVID.Certificates[0],
		}
		serverCfg, _, err := mtls.NewPKI(mtls.PKIOptions{
			Certificate: &serverCert,
			ClientCAs:   ca.Pool(),
			Subject:     mtls.SubjectURISAN,
		})
		if err != nil {
			t.Fatalf("mtls.NewPKI: %v", err)
		}
		addr := serveTLS(t, serverCfg)

		cfg, err := client.NewSPIFFE(client.SPIFFEOptions{
			SVIDSource:   &staticSVIDSource{svid: mintSVID(t, ca, testClientID)},
			BundleSource: bundleOf(t, testTrustDomain, ca),
			Authorize:    spiffeid.MatchAny(),
		})
		if err != nil {
			t.Fatalf("client.NewSPIFFE: %v", err)
		}

		if _, err := dialTLS(t, addr, cfg); err != nil {
			t.Fatalf("the SPIFFE client failed against an SVID-shaped PKI listener (%v); "+
				"if this now fails reliably, the package comment's claim that mispairing is "+
				"merely a configuration error is too weak and should be tightened", err)
		}
	})
}

// --- Transport -----------------------------------------------------

func TestTransportKeepsHTTP2AndTheConfig(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	cert := ca.IssueClient(t, "alice")
	cfg, err := client.NewPKI(client.PKIOptions{
		Certificate: &cert,
		RootCAs:     ca.Pool(),
		// Supplied so the assertions below can check that the admission
		// hook survives the clone; without it VerifyConnection is
		// legitimately nil and crypto/tls does the verifying.
		Admit: mtls.MatchCertFunc(func(*x509.Certificate) error { return nil }),
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}

	tr := client.Transport(cfg)
	installed := tr.TLSClientConfig
	if installed == nil {
		t.Fatal("Transport installed no TLS config")
	}
	// A clone, not the caller's value: net/http's HTTP/2 wiring appends
	// to TLSClientConfig.NextProtos in place on first use. See
	// TestTransportDoesNotMutateTheCallersConfig.
	if installed == cfg {
		t.Error("Transport installed the caller's config by reference rather than cloning it")
	}
	// Cloned, and still the config purser built: the pieces that make it
	// an mTLS config have to survive the copy.
	if installed.GetClientCertificate == nil {
		t.Error("the installed config presents no client certificate")
	}
	if installed.VerifyConnection == nil {
		t.Error("the installed config lost the admission hook")
	}
	if installed.RootCAs != cfg.RootCAs {
		t.Error("the installed config does not carry the caller's root pool")
	}
	if installed.MinVersion != cfg.MinVersion {
		t.Errorf("MinVersion = %#04x, want %#04x", installed.MinVersion, cfg.MinVersion)
	}
	// The whole reason the helper exists: net/http silently drops to
	// HTTP/1.1 when a transport carries a TLSClientConfig and this is
	// not set.
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 is false, so the transport would not negotiate HTTP/2")
	}
	if tr.TLSHandshakeTimeout == 0 {
		t.Error("TLSHandshakeTimeout is unset, so a black-holed peer would hang the dial")
	}
	if tr.Proxy == nil {
		t.Error("Proxy is nil, so the transport would ignore HTTPS_PROXY " +
			"where http.DefaultTransport honours it")
	}
}

// TestTransportDoesNotMutateTheCallersConfig is why Transport clones.
//
// net/http's HTTP/2 setup writes t.TLSClientConfig.NextProtos in place,
// so a transport handed the caller's *tls.Config edits it. A caller who
// builds one config and hands it to two transports — or who keeps it to
// dial with directly — would find ALPN protocols appearing in it that it
// never asked for, and a config reused for a non-HTTP dial would offer
// "h2" on a connection that speaks something else.
func TestTransportDoesNotMutateTheCallersConfig(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	serverCert := ca.IssueServer(t, "127.0.0.1")
	serverCfg, _, err := mtls.NewPKI(mtls.PKIOptions{
		Certificate: &serverCert,
		ClientCAs:   ca.Pool(),
		Subject:     mtls.SubjectCommonName,
	})
	if err != nil {
		t.Fatalf("mtls.NewPKI: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
	}
	go func() { _ = srv.Serve(tls.NewListener(ln, serverCfg)) }()
	t.Cleanup(func() { _ = srv.Close() })

	clientCert := ca.IssueClient(t, "alice")
	cfg, err := client.NewPKI(client.PKIOptions{Certificate: &clientCert, RootCAs: ca.Pool()})
	if err != nil {
		t.Fatalf("client.NewPKI: %v", err)
	}
	if len(cfg.NextProtos) != 0 {
		t.Fatalf("NewPKI set NextProtos = %q; this test assumes it starts empty", cfg.NextProtos)
	}

	// The mutation happens lazily, when the transport first configures
	// HTTP/2 — so it takes a real request to provoke it.
	httpClient := &http.Client{Transport: client.Transport(cfg), Timeout: 10 * time.Second}
	defer httpClient.CloseIdleConnections()
	resp, err := httpClient.Get("https://" + ln.Addr().String()) //nolint:noctx // a test against a local server
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	if len(cfg.NextProtos) != 0 {
		t.Errorf("the caller's config gained NextProtos = %q after a request", cfg.NextProtos)
	}
}

// TestTransportSurvivesAReplacedDefaultTransport covers the fallback
// arm. http.DefaultTransport is a package variable, and instrumentation
// libraries routinely wrap it in a RoundTripper of their own; the helper
// must still return a usable transport rather than a zero one with no
// proxy support and no connection limits.
//
// Not parallel: it replaces a process-wide variable.
func TestTransportSurvivesAReplacedDefaultTransport(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("not a *http.Transport")
	})

	ca := authtest.NewCA(t, "purser-test-ca")
	cert := ca.IssueClient(t, "alice")
	cfg, err := client.NewPKI(client.PKIOptions{Certificate: &cert, RootCAs: ca.Pool()})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}

	tr := client.Transport(cfg)
	if tr == nil {
		t.Fatal("Transport returned nil")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.GetClientCertificate == nil {
		t.Fatal("Transport did not install the TLS config")
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 is false")
	}
	if tr.Proxy == nil {
		t.Error("Proxy is nil, so the fallback transport ignores HTTPS_PROXY")
	}
	if tr.IdleConnTimeout == 0 {
		t.Error("IdleConnTimeout is unset, so idle connections would never be reaped")
	}
	if tr.MaxIdleConns == 0 {
		t.Error("MaxIdleConns is unset, so the idle pool is unbounded")
	}
	// Without this, net/http dials with a zero net.Dialer, which has no
	// connect timeout at all — so this branch would be strictly more
	// dangerous than the Clone branch it stands in for, and only on the
	// machines where the type assertion happens to fail.
	if tr.DialContext == nil {
		t.Error("DialContext is nil, so net/http would dial with a zero net.Dialer and " +
			"a connection to a black-holed address would never time out")
	}
}

// TestTransportRejectsANilConfig pins the one input Transport refuses.
//
// A nil config is not "no TLS settings": net/http reads it as the system
// roots and no client certificate, so a transport built for mTLS would
// quietly become one that cannot authenticate and trusts every CA a
// browser does. Neither constructor returns a nil config with a nil
// error, so reaching this means an unchecked error further up.
func TestTransportRejectsANilConfig(t *testing.T) {
	t.Parallel()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("Transport(nil) returned a transport; it would dial with the system " +
				"roots and no client certificate")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value is %T, want a string explaining the misuse", r)
		}
		if !strings.Contains(msg, "purser/client") {
			t.Errorf("panic = %q, want it to name the package", msg)
		}
	}()

	_ = client.Transport(nil)
}

// TestTransportClipsNextProtos covers the aliasing tls.Config.Clone does
// not undo.
//
// Clone copies the NextProtos slice header but shares its backing array,
// and net/http's HTTP/2 setup appends to that slice in place. When the
// caller's slice has spare capacity, the append writes into the caller's
// array rather than allocating — so cloning the config is not on its own
// enough to keep "h2" out of a slice the caller still holds.
func TestTransportClipsNextProtos(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	cert := ca.IssueClient(t, "alice")
	cfg, err := client.NewPKI(client.PKIOptions{Certificate: &cert, RootCAs: ca.Pool()})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	// Room to grow, which is what makes an in-place append possible.
	cfg.NextProtos = append(make([]string, 0, 4), "http/1.1")

	installed := client.Transport(cfg).TLSClientConfig
	if cap(installed.NextProtos) != len(installed.NextProtos) {
		t.Errorf("the installed NextProtos has cap %d for len %d; an append would write "+
			"into the caller's backing array", cap(installed.NextProtos), len(installed.NextProtos))
	}

	// The property that capacity is a proxy for: appending to the
	// installed slice, as net/http does, must not be visible through the
	// caller's.
	installed.NextProtos = append(installed.NextProtos, "h2")
	if !slices.Equal(cfg.NextProtos, []string{"http/1.1"}) {
		t.Errorf("the caller's NextProtos became %v after the transport appended to its "+
			"own copy", cfg.NextProtos)
	}
}

// roundTripperFunc is an http.RoundTripper that is deliberately not an
// *http.Transport.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestTransportDoesNotShareStateWithTheDefault pins that the helper
// clones rather than reconfiguring http.DefaultTransport, which every
// other client in the process is using.
//
// It does not assert that DefaultTransport's TLSClientConfig stays nil.
// http.Transport.Clone runs onceSetNextProtoDefaults on its *receiver*,
// so cloning the default gives the default a TLSClientConfig of its own
// — net/http initialising itself, not our config escaping. What must
// hold is that the two transports are distinct and the default is not
// left holding our credentials.
func TestTransportDoesNotShareStateWithTheDefault(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	cert := ca.IssueClient(t, "alice")
	cfg, err := client.NewPKI(client.PKIOptions{Certificate: &cert, RootCAs: ca.Pool()})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}

	tr := client.Transport(cfg)

	def, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("http.DefaultTransport is %T, want *http.Transport", http.DefaultTransport)
	}
	if tr == def {
		t.Fatal("Transport returned http.DefaultTransport itself")
	}
	if def.TLSClientConfig == cfg {
		t.Error("Transport installed the caller's TLS config on http.DefaultTransport; " +
			"every other client in the process would present these credentials")
	}
	if def.TLSClientConfig != nil && def.TLSClientConfig.GetClientCertificate != nil {
		t.Error("http.DefaultTransport was left holding a client certificate")
	}
}

// TestTransportRoundTripsOverMTLS is the end-to-end that the DESIGN
// note asks for: a real HTTP request, over a real mTLS connection, from
// the client helpers to a purser-authenticated handler.
func TestTransportRoundTripsOverMTLS(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	serverCert := ca.IssueServer(t, "127.0.0.1")
	serverCfg, auth, err := mtls.NewPKI(mtls.PKIOptions{
		Certificate: &serverCert,
		ClientCAs:   ca.Pool(),
		Subject:     mtls.SubjectCommonName,
	})
	if err != nil {
		t.Fatalf("mtls.NewPKI: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller, err := auth.Authenticate(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(caller.Identity))
		}),
	}
	go func() { _ = srv.Serve(tls.NewListener(ln, serverCfg)) }()
	t.Cleanup(func() { _ = srv.Close() })

	clientCert := ca.IssueClient(t, "alice")
	clientCfg, err := client.NewPKI(client.PKIOptions{
		Certificate: &clientCert,
		RootCAs:     ca.Pool(),
	})
	if err != nil {
		t.Fatalf("client.NewPKI: %v", err)
	}
	httpClient := &http.Client{Transport: client.Transport(clientCfg), Timeout: 10 * time.Second}
	defer httpClient.CloseIdleConnections()

	resp, err := httpClient.Get("https://" + ln.Addr().String()) //nolint:noctx // a test against a local server
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "alice" {
		t.Errorf("status = %d, body = %q; want 200 and %q", resp.StatusCode, body, "alice")
	}
}
