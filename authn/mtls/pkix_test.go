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

package mtls_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
	"github.com/go-steer/purser/authn/mtls"
	"github.com/go-steer/purser/authtest"
)

// tlsRequest returns a request whose connection presented chain and had
// it verified — the state crypto/tls produces under
// RequireAndVerifyClientCert.
func tlsRequest(chain ...*x509.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{
		VerifiedChains:   [][]*x509.Certificate{chain},
		PeerCertificates: chain,
	}
	return r
}

// unverifiedRequest returns a request whose connection presented chain
// but had it *not* verified: PeerCertificates populated,
// VerifiedChains empty. This is the state under RequireAnyClientCert,
// and the shape a PKI authenticator must never read an identity from.
func unverifiedRequest(chain ...*x509.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: chain}
	return r
}

// newPKI builds an authenticator for the given subject source, failing
// the test if the options are rejected.
func newPKI(tb testing.TB, ca *authtest.CA, subject mtls.SubjectSource) *mtls.PKIAuth {
	tb.Helper()
	serverCert := ca.IssueServer(tb, "127.0.0.1")
	_, auth, err := mtls.NewPKI(mtls.PKIOptions{
		Certificate: &serverCert,
		ClientCAs:   ca.Pool(),
		Subject:     subject,
	})
	if err != nil {
		tb.Fatalf("NewPKI: %v", err)
	}
	return auth
}

func TestConformance(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	auth := newPKI(t, ca, mtls.SubjectEmailSAN)
	valid := ca.Issue(t, authtest.LeafOptions{
		CommonName: "Alice Example",
		EmailSANs:  []string{"alice@example.com"},
	})
	// Minted up front rather than inside the closures: the suite calls
	// them from subtests, and issuing against the parent's testing.TB
	// from there reports a failure on the wrong test.
	noEmail := ca.Issue(t, authtest.LeafOptions{CommonName: "alice@example.com"})
	twoEmails := ca.Issue(t, authtest.LeafOptions{
		EmailSANs: []string{"alice@example.com", "root@example.com"},
	})

	authtest.RunAuthenticatorSuite(t, authtest.Subject{
		Authenticator: auth,
		WantSource:    purser.AuthSourceMTLS,
		Valid: func() (*http.Request, purser.Caller) {
			// Labels are asserted separately: they carry the
			// certificate serial, which differs per issued leaf.
			return tlsRequest(valid.Leaf, ca.Cert()), purser.Caller{Identity: "alice@example.com"}
		},
		Malformed: []authtest.MalformedCase{
			{
				// The critical one. A peer whose certificate was never
				// verified must not be read at all.
				Name:    "certificate presented but not verified",
				Request: func() *http.Request { return unverifiedRequest(valid.Leaf, ca.Cert()) },
			},
			{
				Name: "verified chain is empty",
				Request: func() *http.Request {
					r := httptest.NewRequest(http.MethodGet, "/", nil)
					r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}
					return r
				},
			},
			{
				Name:    "no email SAN",
				Request: func() *http.Request { return tlsRequest(noEmail.Leaf, ca.Cert()) },
			},
			{
				Name:    "two email SANs",
				Request: func() *http.Request { return tlsRequest(twoEmails.Leaf, ca.Cert()) },
			},
		},
	})
}

func TestAuthenticateResolvesLabelsForAudit(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	auth := newPKI(t, ca, mtls.SubjectEmailSAN)
	notAfter := time.Now().Add(30 * time.Minute).Truncate(time.Second)
	cert := ca.Issue(t, authtest.LeafOptions{
		EmailSANs: []string{"alice@example.com"},
		NotAfter:  notAfter,
	})

	c, err := auth.Authenticate(tlsRequest(cert.Leaf, ca.Cert()))
	if err != nil {
		t.Fatalf("Authenticate() = %v, want success", err)
	}
	// Issuer DN plus serial is what a revocation list is keyed by, and
	// what traces a request back to an issued credential; without them
	// an audit record cannot distinguish two certificates minted for
	// the same identity.
	if got, want := c.Label(mtls.LabelIssuerDN), ca.Cert().Subject.String(); got != want {
		t.Errorf("label %s = %q, want %q", mtls.LabelIssuerDN, got, want)
	}
	if got, want := c.Label(mtls.LabelSerial), cert.Leaf.SerialNumber.Text(16); got != want {
		t.Errorf("label %s = %q, want %q", mtls.LabelSerial, got, want)
	}
	if got, want := c.Label(mtls.LabelNotAfter), notAfter.UTC().Format(time.RFC3339); got != want {
		t.Errorf("label %s = %q, want %q", mtls.LabelNotAfter, got, want)
	}
	// Admin comes from policy, never from a credential.
	if c.Admin {
		t.Error("Admin = true; a certificate must not be able to assert its own role")
	}
}

func TestAuthenticateNeverFallsBackToPeerCertificates(t *testing.T) {
	t.Parallel()

	// The attack this profile is shaped to avoid: a self-signed
	// certificate claiming an identity, offered on a connection where
	// no chain was verified. Reading PeerCertificates would accept it.
	ca := authtest.NewCA(t, "purser-test-ca")
	attacker := authtest.NewCA(t, "attacker-ca")
	forged := attacker.Issue(t, authtest.LeafOptions{EmailSANs: []string{"alice@example.com"}})
	auth := newPKI(t, ca, mtls.SubjectEmailSAN)

	c, err := auth.Authenticate(unverifiedRequest(forged.Leaf, attacker.Cert()))
	if !errors.Is(err, purser.ErrUnauthenticated) {
		t.Errorf("Authenticate() error = %v, want purser.ErrUnauthenticated", err)
	}
	if !c.IsZero() {
		t.Errorf("Authenticate() resolved %q from an unverified certificate", c.Identity)
	}
}

func TestAuthenticateWithoutTLS(t *testing.T) {
	t.Parallel()

	// A plaintext listener, or a handler wired up without TLS: 401, not
	// a panic on a nil r.TLS and not a 500.
	ca := authtest.NewCA(t, "purser-test-ca")
	auth := newPKI(t, ca, mtls.SubjectEmailSAN)

	for name, req := range map[string]*http.Request{
		"plaintext request": httptest.NewRequest(http.MethodGet, "/", nil),
		"nil request":       nil,
	} {
		c, panicked, err := authenticateNoPanic(auth, req)
		if panicked != nil {
			t.Errorf("Authenticate(%s) panicked: %v", name, panicked)
			continue
		}
		if !errors.Is(err, purser.ErrUnauthenticated) {
			t.Errorf("Authenticate(%s) error = %v, want purser.ErrUnauthenticated", name, err)
		}
		if !c.IsZero() {
			t.Errorf("Authenticate(%s) returned Caller %q alongside an error", name, c.Identity)
		}
	}
}

// authenticateNoPanic mirrors the conformance suite's guard, for the
// cases this file probes directly.
func authenticateNoPanic(a authn.Authenticator, r *http.Request) (c purser.Caller, panicked any, err error) {
	defer func() { panicked = recover() }()
	c, err = a.Authenticate(r)
	return c, nil, err
}

// TestZeroPKIAuthFailsClosed covers a PKIAuth built by other means than
// NewPKI — a zero value, which no constructor produces but a composite
// literal in a consuming package can. Its subject source is unset, and
// the only safe reading of "no configured field" is to resolve nobody.
func TestZeroPKIAuthFailsClosed(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	cert := ca.Issue(t, authtest.LeafOptions{EmailSANs: []string{"alice@example.com"}})
	var auth mtls.PKIAuth

	c, err := auth.Authenticate(tlsRequest(cert.Leaf, ca.Cert()))
	if !errors.Is(err, purser.ErrUnauthenticated) {
		t.Errorf("Authenticate() error = %v, want purser.ErrUnauthenticated", err)
	}
	if !c.IsZero() {
		t.Errorf("Authenticate() resolved %q with no subject source configured", c.Identity)
	}
}

// TestBlankSubjectValueIsRejected covers a field that is present but
// carries only whitespace. Accepting it would put an empty — or
// whitespace-named — identity into audit records and authorization
// rules, where "" tends to compare equal to an unset expectation.
func TestBlankSubjectValueIsRejected(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	auth := newPKI(t, ca, mtls.SubjectCommonName)
	cert := ca.Issue(t, authtest.LeafOptions{CommonName: "   "})

	c, err := auth.Authenticate(tlsRequest(cert.Leaf, ca.Cert()))
	if !errors.Is(err, purser.ErrUnauthenticated) {
		t.Errorf("Authenticate() error = %v, want purser.ErrUnauthenticated", err)
	}
	if !c.IsZero() {
		t.Errorf("Authenticate() resolved %q from a blank subject field", c.Identity)
	}
}

// TestVerifyConnectionWithoutAChain covers the admission hook's own
// guard. crypto/tls only calls it with verified chains populated under
// RequireAndVerifyClientCert, so this is defence against the config
// being altered after the pair is built: the hook must refuse rather
// than hand a nil certificate to the matcher.
func TestVerifyConnectionWithoutAChain(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	serverCert := ca.IssueServer(t, "127.0.0.1")
	called := false
	cfg, _, err := mtls.NewPKI(mtls.PKIOptions{
		Certificate: &serverCert,
		ClientCAs:   ca.Pool(),
		Subject:     mtls.SubjectEmailSAN,
		Admit: mtls.MatchCertFunc(func(*x509.Certificate) error {
			called = true
			return nil
		}),
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	if cfg.VerifyConnection == nil {
		t.Fatal("VerifyConnection is not set despite an Admit matcher")
	}

	if err := cfg.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Error("VerifyConnection(no chains) = nil, want the handshake refused")
	}
	if called {
		t.Error("the Admit matcher was called with no verified chain")
	}
}

func TestSubjectSources(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	tests := []struct {
		name    string
		subject mtls.SubjectSource
		leaf    authtest.LeafOptions
		want    string
		wantErr string
	}{
		{
			name:    "email SAN",
			subject: mtls.SubjectEmailSAN,
			leaf:    authtest.LeafOptions{EmailSANs: []string{"alice@example.com"}},
			want:    "alice@example.com",
		},
		{
			name:    "URI SAN",
			subject: mtls.SubjectURISAN,
			leaf:    authtest.LeafOptions{URISANs: []string{"spiffe://example.org/ns/prod/sa/api"}},
			want:    "spiffe://example.org/ns/prod/sa/api",
		},
		{
			name:    "DNS SAN",
			subject: mtls.SubjectDNSSAN,
			leaf:    authtest.LeafOptions{DNSSANs: []string{"api.prod.svc.cluster.local"}},
			want:    "api.prod.svc.cluster.local",
		},
		{
			name:    "common name",
			subject: mtls.SubjectCommonName,
			leaf:    authtest.LeafOptions{CommonName: "alice@example.com"},
			want:    "alice@example.com",
		},
		{
			name:    "distinguished name",
			subject: mtls.SubjectDN,
			leaf: authtest.LeafOptions{
				CommonName:         "alice",
				Organization:       []string{"Example"},
				OrganizationalUnit: []string{"Platform"},
			},
			want: "CN=alice,OU=Platform,O=Example",
		},
		{
			// The configured source is the only one read: a certificate
			// carrying a CN but not the configured email SAN is
			// rejected, rather than quietly falling back to the CN.
			// That fallback is what lets an attacker choose which field
			// their identity comes from.
			name:    "no fallback from email SAN to CN",
			subject: mtls.SubjectEmailSAN,
			leaf:    authtest.LeafOptions{CommonName: "alice@example.com"},
			wantErr: "carries no san_email",
		},
		{
			name:    "no fallback from CN to email SAN",
			subject: mtls.SubjectCommonName,
			leaf:    authtest.LeafOptions{EmailSANs: []string{"alice@example.com"}},
			wantErr: "carries no subject_cn",
		},
		{
			name:    "two email SANs are ambiguous",
			subject: mtls.SubjectEmailSAN,
			leaf:    authtest.LeafOptions{EmailSANs: []string{"alice@example.com", "root@example.com"}},
			wantErr: "carries 2 values for san_email",
		},
		{
			// The Kubernetes shape. Rejected rather than resolved by
			// picking one, since which name the request is attributed
			// to would then depend on the CA's encoding order.
			name:    "several DNS SANs are ambiguous",
			subject: mtls.SubjectDNSSAN,
			leaf:    authtest.LeafOptions{DNSSANs: []string{"api", "api.prod", "api.prod.svc"}},
			wantErr: "carries 3 values for san_dns",
		},
		{
			name:    "no URI SAN",
			subject: mtls.SubjectURISAN,
			leaf:    authtest.LeafOptions{CommonName: "alice"},
			wantErr: "carries no san_uri",
		},
		{
			name:    "empty subject for subject_dn",
			subject: mtls.SubjectDN,
			leaf:    authtest.LeafOptions{EmailSANs: []string{"alice@example.com"}},
			wantErr: "empty subject",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			auth := newPKI(t, ca, tt.subject)
			cert := ca.Issue(t, tt.leaf)

			got, err := auth.Authenticate(tlsRequest(cert.Leaf, ca.Cert()))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Authenticate() resolved %q, want an error mentioning %q", got.Identity, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Authenticate() error = %v, want it to mention %q", err, tt.wantErr)
				}
				if !errors.Is(err, purser.ErrUnauthenticated) {
					t.Errorf("Authenticate() error = %v, want purser.ErrUnauthenticated", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Authenticate() = %v, want success", err)
			}
			if got.Identity != tt.want {
				t.Errorf("Authenticate() identity = %q, want %q", got.Identity, tt.want)
			}
		})
	}
}

func TestNewPKIRejectsIncompleteOptions(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	serverCert := ca.IssueServer(t, "127.0.0.1")
	getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &serverCert, nil }

	tests := []struct {
		name    string
		opts    mtls.PKIOptions
		wantErr string
	}{
		{
			name:    "no server certificate",
			opts:    mtls.PKIOptions{ClientCAs: ca.Pool(), Subject: mtls.SubjectEmailSAN},
			wantErr: "one of Certificate or GetCertificate is required",
		},
		{
			name: "both certificate sources",
			opts: mtls.PKIOptions{
				Certificate:    &serverCert,
				GetCertificate: getCert,
				ClientCAs:      ca.Pool(),
				Subject:        mtls.SubjectEmailSAN,
			},
			wantErr: "mutually exclusive",
		},
		{
			// A nil pool with RequireAndVerifyClientCert makes every
			// handshake fail, which reads as an outage rather than as
			// the misconfiguration it is.
			name:    "no client CA pool",
			opts:    mtls.PKIOptions{Certificate: &serverCert, Subject: mtls.SubjectEmailSAN},
			wantErr: "ClientCAs is required",
		},
		{
			name:    "no subject source",
			opts:    mtls.PKIOptions{Certificate: &serverCert, ClientCAs: ca.Pool()},
			wantErr: "Subject is required",
		},
		{
			name: "unknown subject source",
			opts: mtls.PKIOptions{
				Certificate: &serverCert, ClientCAs: ca.Pool(), Subject: mtls.SubjectSource("san_ip"),
			},
			wantErr: `unknown Subject "san_ip"`,
		},
		{
			name: "TLS floor below 1.2",
			opts: mtls.PKIOptions{
				Certificate: &serverCert, ClientCAs: ca.Pool(), Subject: mtls.SubjectEmailSAN,
				MinVersion: tls.VersionTLS11,
			},
			wantErr: "below TLS 1.2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, auth, err := mtls.NewPKI(tt.opts)
			if err == nil {
				t.Fatalf("NewPKI() succeeded, want an error mentioning %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("NewPKI() error = %v, want it to mention %q", err, tt.wantErr)
			}
			// A half-built pair is worse than none: a caller ignoring
			// the error would serve with a config that verifies nothing.
			if cfg != nil || auth != nil {
				t.Errorf("NewPKI() = (%v, %v, err), want both nil alongside an error", cfg, auth)
			}
		})
	}
}

func TestNewPKIConfigShape(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	serverCert := ca.IssueServer(t, "127.0.0.1")
	pool := ca.Pool()
	cfg, _, err := mtls.NewPKI(mtls.PKIOptions{
		Certificate: &serverCert,
		ClientCAs:   pool,
		Subject:     mtls.SubjectEmailSAN,
		NextProtos:  []string{"h2"},
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}

	// This is the half of the matched pair that the authenticator's
	// correctness rests on: RequireAndVerifyClientCert is what makes
	// crypto/tls populate VerifiedChains.
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs != pool {
		t.Error("ClientCAs is not the configured pool")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %#04x, want TLS 1.3 by default", cfg.MinVersion)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("len(Certificates) = %d, want 1", len(cfg.Certificates))
	}
	if got := cfg.NextProtos; len(got) != 1 || got[0] != "h2" {
		t.Errorf("NextProtos = %v, want [h2]", got)
	}
	// No admission matcher was configured, so nothing should be hooked
	// in: an empty hook that always returns nil is indistinguishable
	// from a real one that stopped being called.
	if cfg.VerifyConnection != nil {
		t.Error("VerifyConnection is set without an Admit matcher")
	}
	// The matcher must never be hung off VerifyPeerCertificate, which
	// resumed sessions skip.
	if cfg.VerifyPeerCertificate != nil {
		t.Error("VerifyPeerCertificate is set; admission belongs in VerifyConnection")
	}
}

func TestNewPKIAcceptsATLS12Floor(t *testing.T) {
	t.Parallel()

	// Opting down is allowed — a deployment with an older client needs
	// it — but it has to be asked for.
	ca := authtest.NewCA(t, "purser-test-ca")
	serverCert := ca.IssueServer(t, "127.0.0.1")
	cfg, _, err := mtls.NewPKI(mtls.PKIOptions{
		Certificate: &serverCert,
		ClientCAs:   ca.Pool(),
		Subject:     mtls.SubjectEmailSAN,
		MinVersion:  tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#04x, want TLS 1.2", cfg.MinVersion)
	}
}

func TestNewPKIWithGetCertificate(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	serverCert := ca.IssueServer(t, "127.0.0.1")
	cfg, _, err := mtls.NewPKI(mtls.PKIOptions{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &serverCert, nil },
		ClientCAs:      ca.Pool(),
		Subject:        mtls.SubjectEmailSAN,
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	if cfg.GetCertificate == nil {
		t.Fatal("GetCertificate is not wired into the config")
	}
	if len(cfg.Certificates) != 0 {
		t.Errorf("len(Certificates) = %d, want 0 when GetCertificate is used", len(cfg.Certificates))
	}
	got, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "127.0.0.1"})
	if err != nil || got == nil {
		t.Fatalf("GetCertificate() = (%v, %v), want the configured certificate", got, err)
	}
}

func TestPKIAuthInterfaces(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	var a authn.Authenticator = newPKI(t, ca, mtls.SubjectEmailSAN)

	if got := a.Source(); got != purser.AuthSourceMTLS {
		t.Errorf("Source() = %q, want %q", got, purser.AuthSourceMTLS)
	}
	g, ok := a.(authn.CredentialGate)
	if !ok {
		t.Fatal("*mtls.PKIAuth does not implement authn.CredentialGate")
	}
	if !g.GatesCredentials() {
		t.Error("GatesCredentials() = false, want true")
	}
	// A certificate is not a table, so there is nothing to look an
	// asserted identity up in and nobody to grant proxying to. Not
	// implementing these is what denies the proxy path by default.
	if _, ok := a.(authn.IdentityLookup); ok {
		t.Error("*mtls.PKIAuth implements authn.IdentityLookup, which it has no table to back")
	}
	if _, ok := a.(authn.AuthenticatorWithProxy); ok {
		t.Error("*mtls.PKIAuth implements authn.AuthenticatorWithProxy, which it cannot honour")
	}
}

func TestSubjectSourceKnown(t *testing.T) {
	t.Parallel()

	for _, s := range []mtls.SubjectSource{
		mtls.SubjectEmailSAN, mtls.SubjectURISAN, mtls.SubjectDNSSAN,
		mtls.SubjectCommonName, mtls.SubjectDN,
	} {
		if !s.Known() {
			t.Errorf("%q.Known() = false", s)
		}
		if s.String() != string(s) {
			t.Errorf("%q.String() = %q", s, s.String())
		}
	}
	for _, s := range []mtls.SubjectSource{"", "san_ip", "SAN_EMAIL"} {
		if s.Known() {
			t.Errorf("%q.Known() = true, want false", s)
		}
	}
}

// startPKIServer serves the resolved identity over a TLS listener built
// from the returned config, and hands back the URL.
func startPKIServer(tb testing.TB, cfg *tls.Config, auth *mtls.PKIAuth) string {
	tb.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := auth.Authenticate(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(c.Identity))
	}))
	srv.TLS = cfg
	srv.StartTLS()
	tb.Cleanup(srv.Close)
	return srv.URL
}

// get issues one request with the given client certificate, or with
// none when cert is nil.
func get(tb testing.TB, url string, roots *x509.CertPool, cert *tls.Certificate) (int, string, error) {
	tb.Helper()
	clientTLS := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	if cert != nil {
		clientTLS.Certificates = []tls.Certificate{*cert}
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	defer client.CloseIdleConnections()

	resp, err := client.Get(url) //nolint:noctx // a test against a local server
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body), nil
}

// TestAdmitAppliesToResumedSessions is the regression test for the
// resumption bypass.
//
// The obvious place to hang an admission matcher is
// VerifyPeerCertificate, and crypto/tls does not call it when a session
// is resumed from a ticket: it re-checks the carried chain against
// ClientCAs, rejects an expired leaf, restores VerifiedChains, and
// proceeds. A matcher installed there stops applying the moment a
// client reconnects with a ticket, so a peer admitted under an older
// policy keeps its access for the ticket's lifetime.
//
// The matcher counts its calls and can be switched to refusing, which
// stands in for a policy that has since narrowed. The test asserts the
// second handshake genuinely resumed before drawing any conclusion from
// it — without that, a run where resumption did not happen would pass
// for the wrong reason.
func TestAdmitAppliesToResumedSessions(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	serverCert := ca.IssueServer(t, "127.0.0.1")
	var mu sync.Mutex
	calls, deny := 0, false
	cfg, auth, err := mtls.NewPKI(mtls.PKIOptions{
		Certificate: &serverCert,
		ClientCAs:   ca.Pool(),
		Subject:     mtls.SubjectEmailSAN,
		Admit: mtls.MatchCertFunc(func(*x509.Certificate) error {
			mu.Lock()
			defer mu.Unlock()
			calls++
			if deny {
				return errors.New("no longer admitted")
			}
			return nil
		}),
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	url := startPKIServer(t, cfg, auth)

	clientCert := ca.Issue(t, authtest.LeafOptions{EmailSANs: []string{"alice@example.com"}})
	// One transport across every request, with a session cache, so each
	// later handshake has a ticket to resume from.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:            ca.Pool(),
		Certificates:       []tls.Certificate{clientCert},
		MinVersion:         tls.VersionTLS13,
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
	}}}
	t.Cleanup(client.CloseIdleConnections)

	// Closing idle connections between requests forces a new connection,
	// and so a new handshake, rather than reusing the open one.
	do := func(what string) *http.Response {
		t.Helper()
		resp, err := client.Get(url) //nolint:noctx // a test against a local server
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", what, resp.StatusCode)
		}
		client.CloseIdleConnections()
		return resp
	}
	callCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}

	if resp := do("first request"); resp.TLS.DidResume {
		t.Fatal("the first connection resumed a session, so it is not the full-handshake case")
	}
	if got := callCount(); got != 1 {
		t.Fatalf("the Admit matcher was called %d time(s) during the full handshake, want 1", got)
	}

	if resp := do("second request"); !resp.TLS.DidResume {
		t.Skip("the second connection did not resume; crypto/tls declined to issue or accept a ticket")
	}
	// The property. On the resumed handshake the matcher ran again;
	// hung off VerifyPeerCertificate it would still be at one call.
	if got := callCount(); got != 2 {
		t.Errorf("the Admit matcher was called %d time(s) after a resumed handshake, want 2: "+
			"admission is not being applied to resumed sessions", got)
	}

	// And a refusal on a resumed connection actually refuses.
	mu.Lock()
	deny = true
	mu.Unlock()
	resp, err := client.Get(url) //nolint:noctx // a test against a local server
	if err == nil {
		resumed := resp.TLS.DidResume
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("a request was served (status %d, resumed=%v) after admission was withdrawn",
			resp.StatusCode, resumed)
	}
}

// TestEndToEndHandshakeWithoutAdmit is the same exercise with no Admit
// matcher configured, so nothing but crypto/tls's own chain
// verification stands between an untrusted peer and the handler.
//
// It exists because the Admit hook in TestEndToEndHandshake also
// rejects a peer whose chain was not verified, which would mask a
// ClientAuth downgrade for every deployment that leaves Admit nil — the
// documented default.
func TestEndToEndHandshakeWithoutAdmit(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	other := authtest.NewCA(t, "untrusted-ca")
	serverCert := ca.IssueServer(t, "127.0.0.1")
	cfg, auth, err := mtls.NewPKI(mtls.PKIOptions{
		Certificate: &serverCert,
		ClientCAs:   ca.Pool(),
		Subject:     mtls.SubjectEmailSAN,
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	url := startPKIServer(t, cfg, auth)

	trusted := ca.Issue(t, authtest.LeafOptions{EmailSANs: []string{"alice@example.com"}})
	status, body, err := get(t, url, ca.Pool(), &trusted)
	if err != nil {
		t.Fatalf("request with a trusted certificate: %v", err)
	}
	if status != http.StatusOK || body != "alice@example.com" {
		t.Errorf("got (%d, %q), want (200, %q)", status, body, "alice@example.com")
	}

	// Same asserted identity, wrong issuer. Chain verification alone
	// must refuse it at the handshake.
	forged := other.Issue(t, authtest.LeafOptions{EmailSANs: []string{"alice@example.com"}})
	if status, body, err := get(t, url, ca.Pool(), &forged); err == nil {
		t.Errorf("a certificate from an untrusted CA was served (%d, %q), want the handshake refused",
			status, body)
	}
	if status, body, err := get(t, url, ca.Pool(), nil); err == nil {
		t.Errorf("a request with no client certificate was served (%d, %q), want the handshake refused",
			status, body)
	}
}

// TestEndToEndHandshake exercises the pair over a real TLS connection,
// which is the only way to prove the config half actually produces the
// state the authenticator half reads. Every other test in this file
// synthesizes tls.ConnectionState and would pass just as well against a
// config that verified nothing.
func TestEndToEndHandshake(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	other := authtest.NewCA(t, "untrusted-ca")
	serverCert := ca.IssueServer(t, "127.0.0.1")

	cfg, auth, err := mtls.NewPKI(mtls.PKIOptions{
		Certificate: &serverCert,
		ClientCAs:   ca.Pool(),
		Subject:     mtls.SubjectEmailSAN,
		Admit:       mtls.MatchCertEmailDomain("example.com"),
	})
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}

	url := startPKIServer(t, cfg, auth)

	tests := []struct {
		name       string
		clientCert tls.Certificate
		noCert     bool
		wantBody   string
		wantErr    bool
	}{
		{
			name:       "trusted client in the admitted domain",
			clientCert: ca.Issue(t, authtest.LeafOptions{EmailSANs: []string{"alice@example.com"}}),
			wantBody:   "alice@example.com",
		},
		{
			// Layer A rejects at the handshake, so the request never
			// reaches the handler: the client sees a TLS error, not a
			// 401.
			name:       "trusted client outside the admitted domain",
			clientCert: ca.Issue(t, authtest.LeafOptions{EmailSANs: []string{"mallory@evil.test"}}),
			wantErr:    true,
		},
		{
			name:       "untrusted issuer",
			clientCert: other.Issue(t, authtest.LeafOptions{EmailSANs: []string{"alice@example.com"}}),
			wantErr:    true,
		},
		{
			name:       "expired certificate",
			clientCert: ca.Issue(t, authtest.LeafOptions{EmailSANs: []string{"alice@example.com"}, NotAfter: time.Now().Add(-time.Minute)}),
			wantErr:    true,
		},
		{
			name:    "no client certificate",
			noCert:  true,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cert := &tt.clientCert
			if tt.noCert {
				cert = nil
			}
			status, body, err := get(t, url, ca.Pool(), cert)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("request was served (%d, %q), want the handshake refused", status, body)
				}
				return
			}
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			if status != http.StatusOK {
				t.Fatalf("status = %d (%q), want 200", status, body)
			}
			if body != tt.wantBody {
				t.Errorf("resolved identity = %q, want %q", body, tt.wantBody)
			}
		})
	}
}
