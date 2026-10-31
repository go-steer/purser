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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-steer/purser/authn/mtls"
	"github.com/go-steer/purser/authtest"
	"github.com/go-steer/purser/client"
)

// swappableRoots is a RootCAsSource whose pool, or failure, the test
// changes between handshakes.
type swappableRoots struct {
	mu    sync.Mutex
	pool  *x509.CertPool
	err   error
	calls int
}

func (s *swappableRoots) CertPool() (*x509.CertPool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.pool, s.err
}

func (s *swappableRoots) set(pool *x509.CertPool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pool, s.err = pool, err
}

// newDNSNamedServer serves a certificate for name only, issued by
// serverCA, and admits clients from clientCA: the shape of Agent
// Substrate's router, whose certificate carries one DNS SAN from a
// different authority than its clients'.
func newDNSNamedServer(tb testing.TB, serverCA, clientCA *authtest.CA, name string) string {
	tb.Helper()
	serverCert := serverCA.Issue(tb, authtest.LeafOptions{
		CommonName:  name,
		DNSSANs:     []string{name},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	cfg, _, err := mtls.NewPKI(mtls.PKIOptions{
		Certificate: &serverCert,
		ClientCAs:   clientCA.Pool(),
		Subject:     mtls.SubjectCommonName,
	})
	if err != nil {
		tb.Fatalf("mtls.NewPKI: %v", err)
	}
	return serveTLS(tb, cfg)
}

func TestPKIRootCAsSourceVerifiesAgainstTheCurrentPool(t *testing.T) {
	t.Parallel()
	serviceDNS := authtest.NewCA(t, "servicedns")
	rotated := authtest.NewCA(t, "servicedns-rotated")
	podIdentity := authtest.NewCA(t, "podidentity")
	const name = "atenet-router.ate-system.svc"
	addr := newDNSNamedServer(t, serviceDNS, podIdentity, name)

	roots := &swappableRoots{pool: serviceDNS.Pool()}
	cert := podIdentity.IssueClient(t, "lookout")
	cfg, err := client.NewPKI(client.PKIOptions{
		Certificate:   &cert,
		RootCAsSource: roots,
		ServerName:    name,
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	if cfg.RootCAs != nil || !cfg.InsecureSkipVerify || cfg.VerifyConnection == nil {
		t.Fatal("a RootCAsSource config must verify in VerifyConnection, not through RootCAs")
	}

	if _, err := dialTLS(t, addr, cfg); err != nil {
		t.Fatalf("dial with the server's authority in the pool: %v", err)
	}

	// The pool rotates to an authority that did not issue the server's
	// certificate: the next handshake must see it.
	roots.set(rotated.Pool(), nil)
	if _, err := dialTLS(t, addr, cfg); err == nil {
		t.Fatal("the handshake succeeded after the pool stopped trusting the server's authority")
	}

	// And back, with both: rotation in progress.
	both := serviceDNS.Pool()
	both.AddCert(rotated.Cert())
	roots.set(both, nil)
	if _, err := dialTLS(t, addr, cfg); err != nil {
		t.Fatalf("dial with both authorities in the pool: %v", err)
	}
	if roots.calls < 3 {
		t.Errorf("CertPool called %d times for 3 handshakes; it must be consulted per handshake", roots.calls)
	}
}

func TestPKIRootCAsSourceChecksTheServerName(t *testing.T) {
	t.Parallel()
	serviceDNS := authtest.NewCA(t, "servicedns")
	podIdentity := authtest.NewCA(t, "podidentity")
	// The authority issues to every Service: chain verification alone
	// would accept any of them as the router.
	addr := newDNSNamedServer(t, serviceDNS, podIdentity, "some-other-service.default.svc")

	cert := podIdentity.IssueClient(t, "lookout")
	cfg, err := client.NewPKI(client.PKIOptions{
		Certificate:   &cert,
		RootCAsSource: &swappableRoots{pool: serviceDNS.Pool()},
		ServerName:    "atenet-router.ate-system.svc",
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	_, err = dialTLS(t, addr, cfg)
	if err == nil {
		t.Fatal("a certificate for another service was accepted as the router's")
	}
}

func TestPKIRootCAsSourceRefusesAnUnnamedIPDial(t *testing.T) {
	t.Parallel()
	serviceDNS := authtest.NewCA(t, "servicedns")
	podIdentity := authtest.NewCA(t, "podidentity")
	addr := newDNSNamedServer(t, serviceDNS, podIdentity, "atenet-router.ate-system.svc")

	cert := podIdentity.IssueClient(t, "lookout")
	cfg, err := client.NewPKI(client.PKIOptions{
		Certificate:   &cert,
		RootCAsSource: &swappableRoots{pool: serviceDNS.Pool()},
		// No ServerName, and addr is 127.0.0.1:port: SNI carries nothing.
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	_, err = dialTLS(t, addr, cfg)
	if err == nil {
		t.Fatal("dialing an IP with no ServerName verified nothing and succeeded")
	}
	if !strings.Contains(err.Error(), "no server name") {
		t.Errorf("error = %q, want it to explain that there is no name to verify", err)
	}
}

func TestPKIRootCAsSourceFailures(t *testing.T) {
	t.Parallel()
	serviceDNS := authtest.NewCA(t, "servicedns")
	podIdentity := authtest.NewCA(t, "podidentity")
	const name = "atenet-router.ate-system.svc"
	addr := newDNSNamedServer(t, serviceDNS, podIdentity, name)
	cert := podIdentity.IssueClient(t, "lookout")

	for _, tc := range []struct {
		name    string
		pool    *x509.CertPool
		err     error
		wantErr string
	}{
		{"source error", nil, errors.New("mount gone"), "load trust anchors"},
		{"nil pool", nil, nil, "returned no pool"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			roots := &swappableRoots{}
			roots.set(tc.pool, tc.err)
			cfg, err := client.NewPKI(client.PKIOptions{
				Certificate: &cert, RootCAsSource: roots, ServerName: name,
			})
			if err != nil {
				t.Fatalf("NewPKI: %v", err)
			}
			_, err = dialTLS(t, addr, cfg)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("dial error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestPKIRootCAsSourceAppliesAdmit(t *testing.T) {
	t.Parallel()
	serviceDNS := authtest.NewCA(t, "servicedns")
	podIdentity := authtest.NewCA(t, "podidentity")
	const name = "atenet-router.ate-system.svc"
	addr := newDNSNamedServer(t, serviceDNS, podIdentity, name)
	cert := podIdentity.IssueClient(t, "lookout")

	var admitted *x509.Certificate
	cfg, err := client.NewPKI(client.PKIOptions{
		Certificate:   &cert,
		RootCAsSource: &swappableRoots{pool: serviceDNS.Pool()},
		ServerName:    name,
		Admit: func(leaf *x509.Certificate) error {
			admitted = leaf
			return errors.New("not this one")
		},
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	if _, err := dialTLS(t, addr, cfg); err == nil || !strings.Contains(err.Error(), "not admitted") {
		t.Fatalf("dial error = %v, want the Admit refusal", err)
	}
	if admitted == nil || admitted.Subject.CommonName != name {
		t.Errorf("Admit saw %v, want the server's verified leaf", admitted)
	}
}

// TestPKIRootCAsSourceVerifiesResumedSessions is the reason the hook is
// VerifyConnection: a resumed session must be checked against the pool
// as it is now, not as it was when the ticket was issued.
func TestPKIRootCAsSourceVerifiesResumedSessions(t *testing.T) {
	t.Parallel()
	serviceDNS := authtest.NewCA(t, "servicedns")
	other := authtest.NewCA(t, "other")
	podIdentity := authtest.NewCA(t, "podidentity")
	const name = "atenet-router.ate-system.svc"
	addr := newDNSNamedServer(t, serviceDNS, podIdentity, name)
	cert := podIdentity.IssueClient(t, "lookout")

	roots := &swappableRoots{pool: serviceDNS.Pool()}
	cfg, err := client.NewPKI(client.PKIOptions{Certificate: &cert, RootCAsSource: roots, ServerName: name})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	establishResumption(t, addr, cfg)

	roots.set(other.Pool(), nil)
	if _, err := dialTLS(t, addr, cfg); err == nil {
		t.Fatal("a resumed session was accepted after its server's authority left the pool")
	}
}

// TestPKIRootCAsSourceVerifiesTheNameSent covers the SNI path: with no
// ServerName the dialed host is verified, and a caller who clones the
// config and changes ServerName has the new name verified, as crypto/tls
// itself would.
func TestPKIRootCAsSourceVerifiesTheNameSent(t *testing.T) {
	t.Parallel()
	serviceDNS := authtest.NewCA(t, "servicedns")
	podIdentity := authtest.NewCA(t, "podidentity")
	addr := newDNSNamedServer(t, serviceDNS, podIdentity, "localhost")
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	cert := podIdentity.IssueClient(t, "lookout")
	roots := &swappableRoots{pool: serviceDNS.Pool()}

	t.Run("dialed host, no ServerName", func(t *testing.T) {
		cfg, err := client.NewPKI(client.PKIOptions{Certificate: &cert, RootCAsSource: roots})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dialTLS(t, net.JoinHostPort("localhost", port), cfg); err != nil {
			t.Fatalf("dial localhost with a localhost certificate: %v", err)
		}
	})
	t.Run("ServerName changed on a clone", func(t *testing.T) {
		cfg, err := client.NewPKI(client.PKIOptions{
			Certificate: &cert, RootCAsSource: roots, ServerName: "atenet-router.ate-system.svc",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dialTLS(t, addr, cfg); err == nil {
			t.Fatal("a localhost certificate was accepted as atenet-router's")
		}
		clone := cfg.Clone()
		clone.ServerName = "localhost"
		if _, err := dialTLS(t, addr, clone); err != nil {
			t.Fatalf("the clone's ServerName was not the one verified: %v", err)
		}
	})
}

func TestPKIRootCAsSourceAcceptsAnIPServerName(t *testing.T) {
	t.Parallel()
	serviceDNS := authtest.NewCA(t, "servicedns")
	podIdentity := authtest.NewCA(t, "podidentity")
	serverCert := serviceDNS.IssueServer(t, "127.0.0.1") // an IP SAN
	srv, _, err := mtls.NewPKI(mtls.PKIOptions{
		Certificate: &serverCert, ClientCAs: podIdentity.Pool(), Subject: mtls.SubjectCommonName,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveTLS(t, srv)
	cert := podIdentity.IssueClient(t, "lookout")
	cfg, err := client.NewPKI(client.PKIOptions{
		Certificate: &cert, RootCAsSource: &swappableRoots{pool: serviceDNS.Pool()}, ServerName: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dialTLS(t, addr, cfg); err != nil {
		t.Fatalf("an IP ServerName did not match the IP SAN: %v", err)
	}
}

func TestPKIRootCAsSourceRequiresServerAuth(t *testing.T) {
	t.Parallel()
	serviceDNS := authtest.NewCA(t, "servicedns")
	podIdentity := authtest.NewCA(t, "podidentity")
	const name = "atenet-router.ate-system.svc"
	serverCert := serviceDNS.Issue(t, authtest.LeafOptions{
		CommonName: name, DNSSANs: []string{name},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, // client-only
	})
	srv, _, err := mtls.NewPKI(mtls.PKIOptions{
		Certificate: &serverCert, ClientCAs: podIdentity.Pool(), Subject: mtls.SubjectCommonName,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveTLS(t, srv)
	cert := podIdentity.IssueClient(t, "lookout")
	cfg, err := client.NewPKI(client.PKIOptions{
		Certificate: &cert, RootCAsSource: &swappableRoots{pool: serviceDNS.Pool()}, ServerName: name,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dialTLS(t, addr, cfg); err == nil {
		t.Fatal("a server certificate without the serverAuth usage was accepted")
	}
}

// TestPKIRootCAsSourceSessionCacheAcrossRotation pins the documented
// difference from RootCAs: a session cached before a rotation fails its
// first resumption and is evicted, so the next dial is a full handshake.
func TestPKIRootCAsSourceSessionCacheAcrossRotation(t *testing.T) {
	t.Parallel()
	oldCA := authtest.NewCA(t, "servicedns-old")
	newCA := authtest.NewCA(t, "servicedns-new")
	podIdentity := authtest.NewCA(t, "podidentity")
	const name = "atenet-router.ate-system.svc"
	addr := newDNSNamedServer(t, oldCA, podIdentity, name)
	cert := podIdentity.IssueClient(t, "lookout")

	roots := &swappableRoots{pool: oldCA.Pool()}
	cfg, err := client.NewPKI(client.PKIOptions{Certificate: &cert, RootCAsSource: roots, ServerName: name})
	if err != nil {
		t.Fatal(err)
	}
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	establishResumption(t, addr, cfg)

	roots.set(newCA.Pool(), nil)
	if _, err := dialTLS(t, addr, cfg); err == nil {
		t.Fatal("the stale session resumed although its authority left the pool")
	}
	// The pool goes back to trusting the server: the next dial must be
	// a full handshake, because the failed session was evicted.
	roots.set(oldCA.Pool(), nil)
	state, err := dialTLS(t, addr, cfg)
	if err != nil {
		t.Fatalf("dial after eviction: %v", err)
	}
	if state.DidResume {
		t.Error("the session that failed verification was resumed again; it should have been evicted")
	}
}

func TestNewPKIRootCAsAndSourceAreExclusive(t *testing.T) {
	t.Parallel()
	ca := authtest.NewCA(t, "x")
	cert := ca.IssueClient(t, "x")
	_, err := client.NewPKI(client.PKIOptions{
		Certificate:   &cert,
		RootCAs:       ca.Pool(),
		RootCAsSource: &swappableRoots{pool: ca.Pool()},
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("NewPKI with both = %v, want a mutual-exclusion error", err)
	}
}

// TestPKIRootCAsSourceWithFileSources is the deployment shape end to
// end: a pod-certificate credential bundle for the client's identity
// and a projected trust bundle for the server's authority, both from
// files.
func TestPKIRootCAsSourceWithFileSources(t *testing.T) {
	t.Parallel()
	serviceDNS := authtest.NewCA(t, "servicedns")
	podIdentity := authtest.NewCA(t, "podidentity")
	const name = "atenet-router.ate-system.svc"
	addr := newDNSNamedServer(t, serviceDNS, podIdentity, name)

	dir := t.TempDir()
	clientCert := podIdentity.IssueClient(t, "lookout")
	bundlePath := writeCredentialBundle(t, dir, clientCert)
	trustPath := writePEM(t, dir, "trust-bundle.pem", serviceDNS.Cert())

	creds, err := mtls.NewCertificateFileSource(mtls.CertificateFileOptions{CredentialBundlePath: bundlePath})
	if err != nil {
		t.Fatalf("NewCertificateFileSource: %v", err)
	}
	defer func() { _ = creds.Close() }()
	roots, err := mtls.NewCertPoolFileSource(mtls.CertPoolFileOptions{Path: trustPath})
	if err != nil {
		t.Fatalf("NewCertPoolFileSource: %v", err)
	}
	defer func() { _ = roots.Close() }()

	cfg, err := client.NewPKI(client.PKIOptions{
		GetClientCertificate: creds.GetClientCertificate,
		RootCAsSource:        roots,
		ServerName:           name,
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	state, err := dialTLS(t, addr, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if state.PeerCertificates[0].Subject.CommonName != name {
		t.Errorf("connected to %q, want %q", state.PeerCertificates[0].Subject.CommonName, name)
	}
}

// Compile-time check: the file source satisfies the client's interface.
var _ client.RootCAsSource = (*mtls.CertPoolFileSource)(nil)

// writeCredentialBundle writes cert in a podCertificate projection's
// credentialBundlePath layout: PKCS#8 key, then the chain.
func writeCredentialBundle(tb testing.TB, dir string, cert tls.Certificate) string {
	tb.Helper()
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		tb.Fatalf("marshal key: %v", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	for _, der := range cert.Certificate {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	path := filepath.Join(dir, "credential-bundle.pem")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		tb.Fatalf("write bundle: %v", err)
	}
	return path
}

func writePEM(tb testing.TB, dir, name string, certs ...*x509.Certificate) string {
	tb.Helper()
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		tb.Fatalf("write %s: %v", name, err)
	}
	return path
}
