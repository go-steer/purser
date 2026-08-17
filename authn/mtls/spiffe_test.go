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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
	"github.com/go-steer/purser/authn/mtls"
	"github.com/go-steer/purser/authtest"
)

const (
	testTrustDomain = "example.org"
	testServerID    = "spiffe://example.org/ns/purser/sa/server"
	testClientID    = "spiffe://example.org/ns/prod/sa/api"
)

// staticSVIDSource serves one X509-SVID. A real deployment uses
// workloadapi.X509Source, which rotates; the interface is what lets a
// test stand in for it without a SPIFFE agent.
type staticSVIDSource struct{ svid *x509svid.SVID }

func (s *staticSVIDSource) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }

// mintSVID issues an X509-SVID from ca. An empty id mints a certificate
// with no SPIFFE ID at all, which is the "not an SVID" negative.
func mintSVID(tb testing.TB, ca *authtest.CA, id string, opts authtest.LeafOptions) *x509svid.SVID {
	tb.Helper()
	if id != "" {
		opts.URISANs = append(opts.URISANs, id)
	}
	if opts.ExtKeyUsage == nil {
		// A SPIFFE X509-SVID is presented by both ends of an mTLS
		// connection, so it carries both usages.
		opts.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	}
	cert := ca.Issue(tb, opts)
	key, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		tb.Fatalf("leaf private key is %T, want a crypto.Signer", cert.PrivateKey)
	}
	svid := &x509svid.SVID{Certificates: []*x509.Certificate{cert.Leaf}, PrivateKey: key}
	if id != "" {
		parsed, err := spiffeid.FromString(id)
		if err != nil {
			tb.Fatalf("parse SPIFFE ID %q: %v", id, err)
		}
		svid.ID = parsed
	}
	return svid
}

// leafOf returns the SVID's leaf certificate, the one a peer presents.
func leafOf(svid *x509svid.SVID) *x509.Certificate { return svid.Certificates[0] }

// bundleOf returns a trust bundle for td holding the given authorities.
func bundleOf(tb testing.TB, td string, cas ...*authtest.CA) *x509bundle.Bundle {
	tb.Helper()
	domain, err := spiffeid.TrustDomainFromString(td)
	if err != nil {
		tb.Fatalf("parse trust domain %q: %v", td, err)
	}
	authorities := make([]*x509.Certificate, 0, len(cas))
	for _, ca := range cas {
		authorities = append(authorities, ca.Cert())
	}
	return x509bundle.FromX509Authorities(domain, authorities)
}

// newSPIFFE builds a server config and authenticator from ca, failing
// the test if the options are rejected.
func newSPIFFE(tb testing.TB, ca *authtest.CA, admit spiffeid.Matcher) (*tls.Config, *mtls.SPIFFEAuth) {
	tb.Helper()
	cfg, auth, err := mtls.NewSPIFFE(mtls.SPIFFEOptions{
		SVIDSource:   &staticSVIDSource{svid: mintSVID(tb, ca, testServerID, authtest.LeafOptions{})},
		BundleSource: bundleOf(tb, testTrustDomain, ca),
		Admit:        admit,
	})
	if err != nil {
		tb.Fatalf("NewSPIFFE: %v", err)
	}
	return cfg, auth
}

func TestSPIFFEConformance(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	other := authtest.NewCA(t, "untrusted-ca")
	_, auth := newSPIFFE(t, ca, nil)

	// Minted here rather than inside the case closures: the suite calls
	// them from subtests, and a certificate minted with the parent t
	// would be reported against the wrong test.
	valid := mintSVID(t, ca, testClientID, authtest.LeafOptions{})
	untrusted := mintSVID(t, other, testClientID, authtest.LeafOptions{})
	expired := mintSVID(t, ca, testClientID, authtest.LeafOptions{
		NotBefore: time.Now().Add(-2 * time.Hour),
		NotAfter:  time.Now().Add(-time.Hour),
	})
	notAnSVID := mintSVID(t, ca, "", authtest.LeafOptions{CommonName: "api.prod"})
	twoIDs := mintSVID(t, ca, testClientID, authtest.LeafOptions{
		URISANs: []string{"spiffe://example.org/ns/prod/sa/other"},
	})
	foreign := mintSVID(t, ca, "spiffe://other.example/ns/prod/sa/api", authtest.LeafOptions{})

	authtest.RunAuthenticatorSuite(t, authtest.Subject{
		Authenticator: auth,
		WantSource:    purser.AuthSourceSPIFFE,
		Valid: func() (*http.Request, purser.Caller) {
			return unverifiedRequest(leafOf(valid)), purser.Caller{Identity: testClientID}
		},
		Malformed: []authtest.MalformedCase{
			{
				Name:    "issued by an authority not in the bundle",
				Request: func() *http.Request { return unverifiedRequest(leafOf(untrusted)) },
			},
			{
				Name:    "expired SVID",
				Request: func() *http.Request { return unverifiedRequest(leafOf(expired)) },
			},
			{
				Name:    "certificate carrying no SPIFFE ID",
				Request: func() *http.Request { return unverifiedRequest(leafOf(notAnSVID)) },
			},
			{
				Name:    "certificate carrying two SPIFFE IDs",
				Request: func() *http.Request { return unverifiedRequest(leafOf(twoIDs)) },
			},
			{
				Name:    "SPIFFE ID in a trust domain the bundle does not cover",
				Request: func() *http.Request { return unverifiedRequest(leafOf(foreign)) },
			},
			{
				Name:    "no certificate on the connection",
				Request: func() *http.Request { return unverifiedRequest() },
			},
		},
	})
}

func TestSPIFFEAuthenticateResolvesLabelsForAudit(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	_, auth := newSPIFFE(t, ca, nil)
	svid := mintSVID(t, ca, testClientID, authtest.LeafOptions{})
	leaf := leafOf(svid)

	caller, err := auth.Authenticate(unverifiedRequest(leaf))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if caller.Identity != testClientID {
		t.Errorf("identity = %q, want %q", caller.Identity, testClientID)
	}
	want := map[string]string{
		mtls.LabelTrustDomain: testTrustDomain,
		mtls.LabelPath:        "/ns/prod/sa/api",
		mtls.LabelIssuerDN:    leaf.Issuer.String(),
		mtls.LabelSerial:      leaf.SerialNumber.Text(16),
		mtls.LabelNotAfter:    leaf.NotAfter.UTC().Format(time.RFC3339),
	}
	for key, wantValue := range want {
		if got := caller.Label(key); got != wantValue {
			t.Errorf("label %q = %q, want %q", key, got, wantValue)
		}
	}
	if len(caller.Labels) != len(want) {
		t.Errorf("labels = %v, want exactly %d keys", caller.Labels, len(want))
	}
}

// TestZeroSPIFFEAuthFailsClosed covers a SPIFFEAuth obtained by any
// means other than NewSPIFFE. It holds no trust bundle, so it has
// nothing to verify against, and the only safe answer is to reject —
// not to read the identity out of PeerCertificates and hope the
// handshake checked it.
//
// Rejection alone is over-determined: x509svid.Verify refuses a nil
// bundle source too, so the explicit guard could be deleted and this
// test would still pass on the error alone. What the guard is *for* is
// the message, which is the whole difference between an operator
// reading "no bundle" and reading how they got one — so the message is
// what this asserts.
func TestZeroSPIFFEAuthFailsClosed(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	svid := mintSVID(t, ca, testClientID, authtest.LeafOptions{})

	var auth mtls.SPIFFEAuth
	caller, panicked, err := authenticateNoPanic(&auth, unverifiedRequest(leafOf(svid)))
	if panicked != nil {
		t.Fatalf("Authenticate panicked: %v", panicked)
	}
	if !errors.Is(err, purser.ErrUnauthenticated) {
		t.Errorf("Authenticate error = %v, want purser.ErrUnauthenticated", err)
	}
	if !strings.Contains(err.Error(), "must come from NewSPIFFE") {
		t.Errorf("error = %q, want it to name the fix: a SPIFFEAuth must come from NewSPIFFE", err)
	}
	if !caller.IsZero() {
		t.Errorf("Authenticate returned Caller %q alongside an error", caller.Identity)
	}
}

// TestSPIFFEAuthenticateReverifies is the property that makes the
// SPIFFE authenticator safe to hold: it does not take the connection's
// word for it.
//
// The PKI profile can tell a verified connection from an unverified one
// by looking at VerifiedChains. The SPIFFE profile cannot — go-spiffe
// verifies outside crypto/tls's chain builder, so VerifiedChains is
// always empty and PeerCertificates is all there is. An authenticator
// that read the SPIFFE ID straight out of it would accept a
// self-signed certificate asserting any identity the peer liked, the
// moment it was paired with a config that does not verify.
func TestSPIFFEAuthenticateReverifies(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	attacker := authtest.NewCA(t, "attacker-ca")
	_, auth := newSPIFFE(t, ca, nil)

	// The same SPIFFE ID as the legitimate workload, from an authority
	// the bundle has never heard of.
	forged := mintSVID(t, attacker, testClientID, authtest.LeafOptions{})
	caller, err := auth.Authenticate(unverifiedRequest(leafOf(forged)))
	if err == nil {
		t.Fatalf("Authenticate accepted %q from an untrusted authority", caller.Identity)
	}
	if !errors.Is(err, purser.ErrUnauthenticated) {
		t.Errorf("Authenticate error = %v, want purser.ErrUnauthenticated", err)
	}
	if !caller.IsZero() {
		t.Errorf("Authenticate returned Caller %q alongside an error", caller.Identity)
	}
}

func TestSPIFFEAuthenticateWithoutTLS(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	_, auth := newSPIFFE(t, ca, nil)

	for name, req := range map[string]*http.Request{
		"plaintext request": httptest.NewRequest(http.MethodGet, "/", nil),
		"nil request":       nil,
	} {
		t.Run(name, func(t *testing.T) {
			caller, panicked, err := authenticateNoPanic(auth, req)
			if panicked != nil {
				t.Fatalf("Authenticate panicked: %v", panicked)
			}
			if !errors.Is(err, purser.ErrUnauthenticated) {
				t.Errorf("Authenticate error = %v, want purser.ErrUnauthenticated", err)
			}
			if !caller.IsZero() {
				t.Errorf("Authenticate returned Caller %q alongside an error", caller.Identity)
			}
		})
	}
}

func TestNewSPIFFERejectsIncompleteOptions(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	svidSource := &staticSVIDSource{svid: mintSVID(t, ca, testServerID, authtest.LeafOptions{})}
	bundle := bundleOf(t, testTrustDomain, ca)

	for name, tc := range map[string]struct {
		opts mtls.SPIFFEOptions
		want string
	}{
		"no SVID source": {
			opts: mtls.SPIFFEOptions{BundleSource: bundle},
			want: "SVIDSource is required",
		},
		"no bundle source": {
			opts: mtls.SPIFFEOptions{SVIDSource: svidSource},
			want: "BundleSource is required",
		},
		"TLS floor below 1.2": {
			opts: mtls.SPIFFEOptions{
				SVIDSource:   svidSource,
				BundleSource: bundle,
				MinVersion:   tls.VersionTLS11,
			},
			want: "below TLS 1.2",
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, auth, err := mtls.NewSPIFFE(tc.opts)
			if err == nil {
				t.Fatalf("NewSPIFFE(%s) succeeded, want an error", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
			// Both halves nil, so a caller who ignores the error cannot
			// end up serving on a config that verifies nothing.
			if cfg != nil || auth != nil {
				t.Errorf("NewSPIFFE returned cfg=%v auth=%v alongside an error, want both nil", cfg, auth)
			}
		})
	}
}

func TestNewSPIFFEConfigShape(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	cfg, _, err := mtls.NewSPIFFE(mtls.SPIFFEOptions{
		SVIDSource:   &staticSVIDSource{svid: mintSVID(t, ca, testServerID, authtest.LeafOptions{})},
		BundleSource: bundleOf(t, testTrustDomain, ca),
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatalf("NewSPIFFE: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAnyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAnyClientCert: SVID verification is go-spiffe's, "+
			"not crypto/tls's", cfg.ClientAuth)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %#04x, want TLS 1.3 (%#04x)", cfg.MinVersion, uint16(tls.VersionTLS13))
	}
	if cfg.GetCertificate == nil {
		t.Error("GetCertificate is nil: the server has no SVID to present")
	}
	if cfg.VerifyConnection == nil {
		t.Error("VerifyConnection is nil: nothing verifies the peer's SVID")
	}
	// The deviation from go-spiffe's own server helpers, pinned: exactly
	// one hook makes the decision, and it is the one crypto/tls calls on
	// resumed handshakes too.
	if cfg.VerifyPeerCertificate != nil {
		t.Error("VerifyPeerCertificate is set: verification must live in VerifyConnection alone, " +
			"which is the only hook a resumed handshake reaches")
	}
	if cfg.ClientCAs != nil {
		t.Error("ClientCAs is set: the SPIFFE profile's anchors come from the bundle source")
	}
	if len(cfg.Certificates) != 0 {
		t.Error("Certificates is set: the server SVID comes from the source, per handshake")
	}
	if strings.Join(cfg.NextProtos, ",") != "h2,http/1.1" {
		t.Errorf("NextProtos = %v, want the configured list", cfg.NextProtos)
	}
}

func TestNewSPIFFEAcceptsATLS12Floor(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	cfg, _, err := mtls.NewSPIFFE(mtls.SPIFFEOptions{
		SVIDSource:   &staticSVIDSource{svid: mintSVID(t, ca, testServerID, authtest.LeafOptions{})},
		BundleSource: bundleOf(t, testTrustDomain, ca),
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("NewSPIFFE: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#04x, want the configured TLS 1.2 (%#04x)",
			cfg.MinVersion, uint16(tls.VersionTLS12))
	}
}

func TestSPIFFEAuthInterfaces(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	_, auth := newSPIFFE(t, ca, nil)

	if got := auth.Source(); got != purser.AuthSourceSPIFFE {
		t.Errorf("Source() = %q, want %q", got, purser.AuthSourceSPIFFE)
	}
	if !auth.GatesCredentials() {
		t.Error("GatesCredentials() = false: a SPIFFE connection is admitted only with a verified SVID")
	}
	var _ authn.Authenticator = auth
	var _ authn.CredentialGate = auth
}

// serveTLS runs handler over a TLS listener built from cfg and returns
// the URL.
//
// Not httptest.NewUnstartedServer + StartTLS: that fills in its own
// Certificates when the config carries none, and crypto/tls consults
// GetCertificate only when Certificates is empty or the client sent
// SNI. A client dialing 127.0.0.1 sends no SNI, so the SPIFFE profile's
// server would silently present httptest's certificate instead of its
// X509-SVID and every test here would fail for the wrong reason.
func serveTLS(tb testing.TB, cfg *tls.Config, handler http.Handler) string {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(tls.NewListener(ln, cfg)) }()
	tb.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String()
}

// startSPIFFEServer serves the resolved identity over a TLS listener
// built from the returned config, and hands back the URL.
func startSPIFFEServer(tb testing.TB, cfg *tls.Config, auth authn.Authenticator) string {
	tb.Helper()
	return serveTLS(tb, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := auth.Authenticate(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(c.Identity))
	}))
}

// spiffeClient returns an HTTP client that authenticates the server's
// SVID the way a first-party peer would, presenting svid when non-nil.
func spiffeClient(bundle x509bundle.Source, svid x509svid.Source) *http.Client {
	var clientTLS *tls.Config
	if svid != nil {
		clientTLS = tlsconfig.MTLSClientConfig(svid, bundle, tlsconfig.AuthorizeAny())
	} else {
		clientTLS = tlsconfig.TLSClientConfig(bundle, tlsconfig.AuthorizeAny())
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
}

// spiffeGet issues one request over a fresh connection.
func spiffeGet(tb testing.TB, url string, bundle x509bundle.Source, svid x509svid.Source) (int, string, error) {
	tb.Helper()
	client := spiffeClient(bundle, svid)
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

func TestSPIFFEEndToEndHandshake(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	other := authtest.NewCA(t, "untrusted-ca")
	bundle := bundleOf(t, testTrustDomain, ca)
	cfg, auth := newSPIFFE(t, ca, mtls.MatchPathPrefix("ns", "prod"))
	url := startSPIFFEServer(t, cfg, auth)

	t.Run("admitted workload", func(t *testing.T) {
		svid := &staticSVIDSource{svid: mintSVID(t, ca, testClientID, authtest.LeafOptions{})}
		status, body, err := spiffeGet(t, url, bundle, svid)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		if status != http.StatusOK || body != testClientID {
			t.Errorf("status = %d, body = %q; want 200 and %q", status, body, testClientID)
		}
	})

	t.Run("workload outside the admitted path", func(t *testing.T) {
		svid := &staticSVIDSource{svid: mintSVID(t, ca,
			"spiffe://example.org/ns/production/sa/api", authtest.LeafOptions{})}
		if _, _, err := spiffeGet(t, url, bundle, svid); err == nil {
			t.Error("the handshake succeeded for a path the matcher must not admit; " +
				"an unanchored prefix test would let /ns/production through a /ns/prod rule")
		}
	})

	t.Run("SVID from an authority not in the bundle", func(t *testing.T) {
		svid := &staticSVIDSource{svid: mintSVID(t, other, testClientID, authtest.LeafOptions{})}
		if _, _, err := spiffeGet(t, url, bundle, svid); err == nil {
			t.Error("the handshake succeeded for an SVID from an untrusted authority")
		}
	})

	t.Run("certificate carrying no SPIFFE ID", func(t *testing.T) {
		svid := &staticSVIDSource{svid: mintSVID(t, ca, "", authtest.LeafOptions{CommonName: "api.prod"})}
		if _, _, err := spiffeGet(t, url, bundle, svid); err == nil {
			t.Error("the handshake succeeded for a certificate that is not an SVID")
		}
	})

	t.Run("no client certificate", func(t *testing.T) {
		if _, _, err := spiffeGet(t, url, bundle, nil); err == nil {
			t.Error("the handshake succeeded without a client certificate")
		}
	})
}

// TestSPIFFEEndToEndHandshakeWithoutAdmit is the same exercise with no
// Admit matcher, the documented default. Without it, a matcher that
// also happens to reject unverified peers would mask a config that
// verifies nothing.
func TestSPIFFEEndToEndHandshakeWithoutAdmit(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	other := authtest.NewCA(t, "untrusted-ca")
	bundle := bundleOf(t, testTrustDomain, ca)
	cfg, auth := newSPIFFE(t, ca, nil)
	url := startSPIFFEServer(t, cfg, auth)

	trusted := &staticSVIDSource{svid: mintSVID(t, ca, testClientID, authtest.LeafOptions{})}
	status, body, err := spiffeGet(t, url, bundle, trusted)
	if err != nil {
		t.Fatalf("request with a trusted SVID: %v", err)
	}
	if status != http.StatusOK || body != testClientID {
		t.Errorf("status = %d, body = %q; want 200 and %q", status, body, testClientID)
	}

	untrusted := &staticSVIDSource{svid: mintSVID(t, other, testClientID, authtest.LeafOptions{})}
	if _, _, err := spiffeGet(t, url, bundle, untrusted); err == nil {
		t.Error("the handshake succeeded for an untrusted SVID with no Admit matcher configured; " +
			"nothing but bundle verification stands in the way, and it did not run")
	}
}

// TestSPIFFEVerifiedChainsAreEmpty pins the fact the whole two-profile
// split rests on, against a real handshake rather than a hand-built
// ConnectionState: under the SPIFFE profile crypto/tls verifies
// nothing, so VerifiedChains is empty and a PKI authenticator handed
// the same request resolves no identity at all.
func TestSPIFFEVerifiedChainsAreEmpty(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	bundle := bundleOf(t, testTrustDomain, ca)
	cfg, _, err := mtls.NewSPIFFE(mtls.SPIFFEOptions{
		SVIDSource:   &staticSVIDSource{svid: mintSVID(t, ca, testServerID, authtest.LeafOptions{})},
		BundleSource: bundle,
	})
	if err != nil {
		t.Fatalf("NewSPIFFE: %v", err)
	}

	var mu sync.Mutex
	var state tls.ConnectionState
	var pkiErr error
	pki := newPKI(t, ca, mtls.SubjectURISAN)

	url := serveTLS(t, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		state = *r.TLS
		_, pkiErr = pki.Authenticate(r)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))

	svid := &staticSVIDSource{svid: mintSVID(t, ca, testClientID, authtest.LeafOptions{})}
	if _, _, err := spiffeGet(t, url, bundle, svid); err != nil {
		t.Fatalf("request: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(state.VerifiedChains) != 0 {
		t.Errorf("VerifiedChains has %d chain(s); the SPIFFE profile is expected to leave it empty, "+
			"and if that has changed the two profiles no longer need separate authenticators",
			len(state.VerifiedChains))
	}
	if len(state.PeerCertificates) == 0 {
		t.Error("PeerCertificates is empty: the peer's SVID is nowhere to be found")
	}
	if !errors.Is(pkiErr, purser.ErrUnauthenticated) {
		t.Errorf("a PKIAuth handed a SPIFFE connection returned %v, want purser.ErrUnauthenticated: "+
			"it must not fall back to PeerCertificates", pkiErr)
	}
}

// TestSPIFFEAdmitAppliesToResumedSessions is the regression test for
// the reason NewSPIFFE does not use tlsconfig.MTLSServerConfig.
//
// crypto/tls does not call VerifyPeerCertificate on a session resumed
// from a ticket, and under RequireAnyClientCert there is no ClientCAs
// pool for it to fall back on either — so a server that verifies there
// verifies once and then stops. purser verifies in VerifyConnection,
// which every handshake reaches.
func TestSPIFFEAdmitAppliesToResumedSessions(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	bundle := bundleOf(t, testTrustDomain, ca)

	var mu sync.Mutex
	calls, deny := 0, false
	admit := func(spiffeid.ID) error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if deny {
			return errors.New("no longer admitted")
		}
		return nil
	}
	callCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}

	cfg, auth, err := mtls.NewSPIFFE(mtls.SPIFFEOptions{
		SVIDSource:   &staticSVIDSource{svid: mintSVID(t, ca, testServerID, authtest.LeafOptions{})},
		BundleSource: bundle,
		Admit:        admit,
	})
	if err != nil {
		t.Fatalf("NewSPIFFE: %v", err)
	}
	url := startSPIFFEServer(t, cfg, auth)

	svid := &staticSVIDSource{svid: mintSVID(t, ca, testClientID, authtest.LeafOptions{})}
	client := resumingSPIFFEClient(bundle, svid)
	t.Cleanup(client.CloseIdleConnections)

	if resp := mustGet(t, client, url, "first request"); resp.TLS.DidResume {
		t.Fatal("the first connection resumed a session, so it is not the full-handshake case")
	}
	if got := callCount(); got != 1 {
		t.Fatalf("the Admit matcher was called %d time(s) during the full handshake, want 1", got)
	}

	if resp := mustGet(t, client, url, "second request"); !resp.TLS.DidResume {
		t.Skip("the second connection did not resume; crypto/tls declined to issue or accept a ticket")
	}
	if got := callCount(); got != 2 {
		t.Errorf("the Admit matcher was called %d time(s) after a resumed handshake, want 2: "+
			"admission is not being applied to resumed sessions", got)
	}

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

// TestUpstreamHookVerifiesOnlyTheFullHandshake is the evidence for that
// deviation, run against go-spiffe's own server helper.
//
// It is a test of a dependency, deliberately: NewSPIFFE departs from
// the documented upstream integration, and a departure needs a reason
// that is checked rather than remembered. If go-spiffe (or crypto/tls)
// closes the gap, this test fails — and that failure is the signal to
// reconsider, not a bug.
func TestUpstreamHookVerifiesOnlyTheFullHandshake(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	bundle := bundleOf(t, testTrustDomain, ca)

	var mu sync.Mutex
	calls := 0
	authorizer := tlsconfig.Authorizer(func(spiffeid.ID, [][]*x509.Certificate) error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return nil
	})
	callCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}

	serverSVID := &staticSVIDSource{svid: mintSVID(t, ca, testServerID, authtest.LeafOptions{})}
	cfg := tlsconfig.MTLSServerConfig(serverSVID, bundle, authorizer)
	url := serveTLS(t, cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	svid := &staticSVIDSource{svid: mintSVID(t, ca, testClientID, authtest.LeafOptions{})}
	client := resumingSPIFFEClient(bundle, svid)
	t.Cleanup(client.CloseIdleConnections)

	if resp := mustGet(t, client, url, "first request"); resp.TLS.DidResume {
		t.Fatal("the first connection resumed a session, so it is not the full-handshake case")
	}
	if got := callCount(); got != 1 {
		t.Fatalf("the upstream authorizer was called %d time(s) during the full handshake, want 1", got)
	}

	if resp := mustGet(t, client, url, "second request"); !resp.TLS.DidResume {
		t.Skip("the second connection did not resume; crypto/tls declined to issue or accept a ticket")
	}
	if got := callCount(); got != 1 {
		t.Errorf("the upstream authorizer was called %d time(s) after a resumed handshake, want 1. "+
			"go-spiffe's HookMTLSServerConfig verifies in VerifyPeerCertificate, which a resumed "+
			"handshake does not reach; if it now runs on resumption the gap is closed and NewSPIFFE "+
			"can go back to using the upstream helper", got)
	}
}

// resumingSPIFFEClient is a client that keeps one session cache across
// requests, so a second connection has a ticket to resume from.
func resumingSPIFFEClient(bundle x509bundle.Source, svid x509svid.Source) *http.Client {
	clientTLS := tlsconfig.MTLSClientConfig(svid, bundle, tlsconfig.AuthorizeAny())
	clientTLS.MinVersion = tls.VersionTLS13
	clientTLS.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	return &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
}

// mustGet issues one request and closes the connection afterwards, so
// the next one handshakes again rather than reusing the open one.
func mustGet(tb testing.TB, client *http.Client, url, what string) *http.Response {
	tb.Helper()
	resp, err := client.Get(url) //nolint:noctx // a test against a local server
	if err != nil {
		tb.Fatalf("%s: %v", what, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		tb.Fatalf("%s: status = %d", what, resp.StatusCode)
	}
	client.CloseIdleConnections()
	return resp
}
