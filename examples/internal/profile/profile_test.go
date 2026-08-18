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

package profile

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-steer/purser/authn"
	"github.com/go-steer/purser/client"
	"github.com/go-steer/purser/examples/internal/credentials"
	"github.com/go-steer/purser/examples/internal/hello"
)

const trustDomain = "example.org"

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// parseFlags exercises the real flag surface rather than the struct
// behind it, so a renamed flag fails a test instead of a demo script.
func parseFlags(t *testing.T, role Role, args ...string) *Flags {
	t.Helper()
	var f Flags
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f.Register(fs, role)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return &f
}

func pkiArgs(dir string) []string {
	return []string{
		"-profile", PKI,
		"-pki-cert", filepath.Join(dir, credentials.PKICertFile),
		"-pki-key", filepath.Join(dir, credentials.PKIKeyFile),
		"-pki-peer-ca", filepath.Join(dir, credentials.PKICAFile),
	}
}

func spiffeArgs(dir string) []string {
	return []string{
		"-profile", SPIFFE,
		"-spiffe-dir", dir,
		"-spiffe-trust-domain", trustDomain,
		// Negative disables the reload goroutine: these tests hand the
		// source files that never change.
		"-spiffe-reload", "-1s",
	}
}

func mintPKI(t *testing.T) credentials.Set {
	t.Helper()
	set, err := credentials.MintPKI(credentials.PKIOptions{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("mint pki credentials: %v", err)
	}
	return set
}

func mintSPIFFE(t *testing.T) credentials.Set {
	t.Helper()
	set, err := credentials.MintSPIFFE(credentials.SPIFFEOptions{Dir: t.TempDir(), TrustDomain: trustDomain})
	if err != nil {
		t.Fatalf("mint spiffe credentials: %v", err)
	}
	return set
}

// counts is how the rejection tests tell the two layers apart.
//
// Reading only reached would not: hello.Authenticate answers 401
// without calling the handler when identity extraction fails, so
// reached == 0 is satisfied by a Layer B rejection as well as by a
// Layer A one — and an implementation that moved admission out of the
// handshake into a per-request check, the exact regression these tests
// are named for, would keep every assertion green.
type counts struct {
	// handshakes counts connections that completed the TLS handshake
	// and began a request. Layer A rejects strictly before this: a peer
	// the admission matcher turns away never reaches http.StateActive.
	handshakes atomic.Int64

	// reached counts requests that got past the authenticator into the
	// handler.
	reached atomic.Int64
}

// serve starts the example service on a loopback port and returns its
// base URL plus the two counters.
func serve(t *testing.T, cfg *tls.Config, auth authn.Authenticator) (string, *counts) {
	t.Helper()

	var c counts
	count := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.reached.Add(1)
		hello.Handler("test-server", discardLogger()).ServeHTTP(w, r)
	})

	mux := http.NewServeMux()
	mux.Handle(hello.Path, hello.Authenticate(auth, discardLogger(), count))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler:           mux,
		TLSConfig:         cfg,
		ReadHeaderTimeout: 5 * time.Second,
		// crypto/tls logs every failed handshake through here, and the
		// rejection tests cause plenty on purpose.
		ErrorLog: slog.NewLogLogger(discardLogger().Handler(), slog.LevelDebug),
		// StateNew fires on accept, before the handshake; StateActive
		// fires only once net/http has read the first byte of a request
		// off the decrypted stream. So this counts handshakes that
		// succeeded, and nothing else.
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateActive {
				c.handshakes.Add(1)
			}
		},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	return "https://" + ln.Addr().String(), &c
}

func greet(t *testing.T, cfg *tls.Config, url string) (hello.Greeting, error) {
	t.Helper()
	c := &http.Client{Transport: client.Transport(cfg)}
	defer c.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hello.Greet(ctx, c, url)
}

// serverFor builds a server config, failing the test on error and
// closing the credential source on cleanup.
func serverFor(t *testing.T, args ...string) (*tls.Config, authn.Authenticator) {
	t.Helper()
	f := parseFlags(t, RoleServer, args...)
	cfg, auth, closer, err := f.Server(discardLogger())
	if err != nil {
		t.Fatalf("Server(%v): %v", args, err)
	}
	t.Cleanup(func() { _ = closer() })
	return cfg, auth
}

func clientFor(t *testing.T, args ...string) *tls.Config {
	t.Helper()
	f := parseFlags(t, RoleClient, args...)
	cfg, closer, err := f.Client(discardLogger())
	if err != nil {
		t.Fatalf("Client(%v): %v", args, err)
	}
	t.Cleanup(func() { _ = closer() })
	return cfg
}

func TestPKIRoundTrip(t *testing.T) {
	set := mintPKI(t)

	cfg, auth := serverFor(t, append(pkiArgs(set.Server.Dir), "-pki-admit-ou", "platform")...)
	url, c := serve(t, cfg, auth)

	g, err := greet(t, clientFor(t, pkiArgs(set.Client.Dir)...), url)
	if err != nil {
		t.Fatalf("greet: %v", err)
	}
	if g.Caller != set.Client.Subject {
		t.Errorf("caller = %q, want %q", g.Caller, set.Client.Subject)
	}
	if g.AuthSource != "mtls" {
		t.Errorf("auth source = %q, want mtls", g.AuthSource)
	}
	if c.reached.Load() != 1 {
		t.Errorf("handler ran %d times, want 1", c.reached.Load())
	}
	// Non-vacuity for the rejection tests: this is what a completed
	// handshake looks like on the counter they assert is zero.
	if c.handshakes.Load() == 0 {
		t.Error("no connection reached http.StateActive; the handshake counter is not counting")
	}
	if g.Labels == nil {
		t.Error("no credential labels; the PKI authenticator should attach issuer and serial")
	}
}

// The unauthorized identity chains to the same CA. Only the Layer A
// matcher stands between it and the service, which is the point: a
// shared internal CA is not an authorization decision.
func TestPKIAdmitOURejectsAtTheHandshake(t *testing.T) {
	set := mintPKI(t)

	cfg, auth := serverFor(t, append(pkiArgs(set.Server.Dir), "-pki-admit-ou", "platform")...)
	url, c := serve(t, cfg, auth)

	if _, err := greet(t, clientFor(t, pkiArgs(set.Unauthorized.Dir)...), url); err == nil {
		t.Fatal("a certificate with the wrong OU was admitted")
	}
	// Rejected at the handshake, not by a 401: the connection never
	// carried a request.
	if c.handshakes.Load() != 0 {
		t.Errorf("%d connections completed the handshake, want 0 — "+
			"admission is not being enforced during the handshake", c.handshakes.Load())
	}
	if c.reached.Load() != 0 {
		t.Errorf("handler ran %d times for a rejected peer, want 0", c.reached.Load())
	}
}

// The control for the test above: without the matcher, the same
// certificate is admitted, so it is the OU check doing the rejecting
// and not something incidental about the credential.
func TestPKIWithoutAdmitOUAdmitsAnyoneTheCASigned(t *testing.T) {
	set := mintPKI(t)

	cfg, auth := serverFor(t, pkiArgs(set.Server.Dir)...)
	url, _ := serve(t, cfg, auth)

	g, err := greet(t, clientFor(t, pkiArgs(set.Unauthorized.Dir)...), url)
	if err != nil {
		t.Fatalf("greet: %v", err)
	}
	if g.Caller != set.Unauthorized.Subject {
		t.Errorf("caller = %q, want %q", g.Caller, set.Unauthorized.Subject)
	}
}

func TestSPIFFERoundTrip(t *testing.T) {
	set := mintSPIFFE(t)

	cfg, auth := serverFor(t, append(spiffeArgs(set.Server.Dir), "-spiffe-admit-id", set.Client.Subject)...)
	url, c := serve(t, cfg, auth)

	clientCfg := clientFor(t, append(spiffeArgs(set.Client.Dir), "-spiffe-authorize-id", set.Server.Subject)...)
	g, err := greet(t, clientCfg, url)
	if err != nil {
		t.Fatalf("greet: %v", err)
	}
	if g.Caller != set.Client.Subject {
		t.Errorf("caller = %q, want %q", g.Caller, set.Client.Subject)
	}
	if g.AuthSource != "spiffe" {
		t.Errorf("auth source = %q, want spiffe", g.AuthSource)
	}
	if c.reached.Load() != 1 {
		t.Errorf("handler ran %d times, want 1", c.reached.Load())
	}
	if c.handshakes.Load() == 0 {
		t.Error("no connection reached http.StateActive; the handshake counter is not counting")
	}
}

func TestSPIFFEAdmitIDRejectsAtTheHandshake(t *testing.T) {
	set := mintSPIFFE(t)

	cfg, auth := serverFor(t, append(spiffeArgs(set.Server.Dir), "-spiffe-admit-id", set.Client.Subject)...)
	url, c := serve(t, cfg, auth)

	clientCfg := clientFor(t,
		append(spiffeArgs(set.Unauthorized.Dir), "-spiffe-authorize-id", set.Server.Subject)...)
	if _, err := greet(t, clientCfg, url); err == nil {
		t.Fatal("an unnamed SVID was admitted")
	}
	if c.handshakes.Load() != 0 {
		t.Errorf("%d connections completed the handshake, want 0 — "+
			"admission is not being enforced during the handshake", c.handshakes.Load())
	}
	if c.reached.Load() != 0 {
		t.Errorf("handler ran %d times for a rejected peer, want 0", c.reached.Load())
	}
}

// A client that names the wrong server must refuse to talk to it. This
// is the half a PKI hostname check does for free and that the SPIFFE
// profile has to do explicitly, because it verifies with
// InsecureSkipVerify set and no hostname is checked at all.
func TestSPIFFEClientRefusesAnUnauthorizedServer(t *testing.T) {
	set := mintSPIFFE(t)

	cfg, auth := serverFor(t, spiffeArgs(set.Server.Dir)...)
	url, c := serve(t, cfg, auth)

	clientCfg := clientFor(t,
		append(spiffeArgs(set.Client.Dir), "-spiffe-authorize-id", set.Unauthorized.Subject)...)
	if _, err := greet(t, clientCfg, url); err == nil {
		t.Fatal("the client accepted a server it did not authorize")
	}
	// The client aborts on the server's certificate, so the server never
	// sees a request — the refusal is the client's, not a 401 it read.
	if c.handshakes.Load() != 0 {
		t.Errorf("%d connections completed the handshake, want 0", c.handshakes.Load())
	}
	if c.reached.Load() != 0 {
		t.Errorf("handler ran %d times, want 0", c.reached.Load())
	}
}

// Two -spiffe-admit-id flags are alternatives. MatchAll of two distinct
// IDs would admit nobody, which is the bug this guards.
func TestSPIFFEAdmitsAnyOfSeveralIDs(t *testing.T) {
	set := mintSPIFFE(t)

	cfg, auth := serverFor(t, append(spiffeArgs(set.Server.Dir),
		"-spiffe-admit-id", set.Unauthorized.Subject,
		"-spiffe-admit-id", set.Client.Subject)...)
	url, _ := serve(t, cfg, auth)

	clientCfg := clientFor(t, append(spiffeArgs(set.Client.Dir), "-spiffe-authorize-id", set.Server.Subject)...)
	if _, err := greet(t, clientCfg, url); err != nil {
		t.Fatalf("greet: %v", err)
	}
}

// copyIdentity copies one minted identity's three PEM files into dst,
// so a test can rewrite them underneath a running process the way
// cert-manager rewrites a mounted Secret.
func copyIdentity(t *testing.T, src, dst string) {
	t.Helper()
	for _, name := range []string{credentials.PKICertFile, credentials.PKIKeyFile, credentials.PKICAFile} {
		b, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dst, name), b, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

// cert-manager renews by rewriting the mounted Secret in place, and
// nothing restarts the pod. A process that loaded its leaf once serves
// the old one until it expires — so the example must not load it once.
func TestPKICertificateIsRereadAfterRotation(t *testing.T) {
	set := mintPKI(t)

	live := t.TempDir()
	copyIdentity(t, set.Client.Dir, live)

	cfg, auth := serverFor(t, append(pkiArgs(set.Server.Dir), "-pki-admit-ou", "platform")...)
	url, c := serve(t, cfg, auth)

	clientCfg := clientFor(t, append(pkiArgs(live), "-pki-reload", "1ms")...)
	if _, err := greet(t, clientCfg, url); err != nil {
		t.Fatalf("greet with the platform certificate: %v", err)
	}

	// Rotate the mount to the identity the server's OU matcher rejects.
	// If the source were pinned, the client would keep presenting the
	// old certificate and would still be admitted.
	copyIdentity(t, set.Unauthorized.Dir, live)
	time.Sleep(5 * time.Millisecond)

	before := c.handshakes.Load()
	if _, err := greet(t, clientCfg, url); err == nil {
		t.Fatal("the rotated-in certificate was admitted; the old one is still being presented")
	}
	if got := c.handshakes.Load(); got != before {
		t.Errorf("%d further connections completed the handshake, want 0", got-before)
	}
}

func TestPKICertSourceKeepsTheLastGoodPairOnAFailedReload(t *testing.T) {
	set := mintPKI(t)

	live := t.TempDir()
	copyIdentity(t, set.Client.Dir, live)

	src, err := newPKICertSource(
		filepath.Join(live, credentials.PKICertFile),
		filepath.Join(live, credentials.PKIKeyFile),
		time.Millisecond,
		discardLogger(),
	)
	if err != nil {
		t.Fatalf("newPKICertSource: %v", err)
	}
	good := src.get()

	// A half-written file — the state a rotation passes through — must
	// not take a healthy workload offline.
	if err := os.WriteFile(filepath.Join(live, credentials.PKICertFile), []byte("-----BEGIN CERT"), 0o600); err != nil {
		t.Fatalf("truncate certificate: %v", err)
	}
	time.Sleep(5 * time.Millisecond)

	if got := src.get(); got != good {
		t.Error("a failed reload replaced the last good certificate")
	}
}

func TestPKICertSourcePinsOnANegativeInterval(t *testing.T) {
	set := mintPKI(t)

	live := t.TempDir()
	copyIdentity(t, set.Client.Dir, live)

	src, err := newPKICertSource(
		filepath.Join(live, credentials.PKICertFile),
		filepath.Join(live, credentials.PKIKeyFile),
		-time.Second,
		discardLogger(),
	)
	if err != nil {
		t.Fatalf("newPKICertSource: %v", err)
	}
	pinned := src.get()

	copyIdentity(t, set.Unauthorized.Dir, live)
	time.Sleep(5 * time.Millisecond)

	if got := src.get(); got != pinned {
		t.Error("a negative -pki-reload still reloaded")
	}
}

func TestUnknownProfileIsRejected(t *testing.T) {
	_, _, closer, err := parseFlags(t, RoleServer, "-profile", "mtls").Server(discardLogger())
	if err == nil {
		t.Error("Server accepted an unknown profile")
	}
	if closer == nil {
		t.Error("Server returned a nil Closer on the error path")
	} else {
		_ = closer()
	}

	_, cCloser, err := parseFlags(t, RoleClient, "-profile", "mtls").Client(discardLogger())
	if err == nil {
		t.Error("Client accepted an unknown profile")
	}
	if cCloser == nil {
		t.Error("Client returned a nil Closer on the error path")
	} else {
		_ = cCloser()
	}
}

func TestPKIMissingFlagsAreAllNamed(t *testing.T) {
	_, _, _, err := parseFlags(t, RoleServer, "-profile", PKI).Server(discardLogger())
	if err == nil {
		t.Fatal("Server accepted -profile pki with no credential files")
	}
	for _, want := range []string{"-pki-cert", "-pki-key", "-pki-peer-ca"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
	// Sorted, because the check walks a map and a flapping error message
	// is a flapping test for whoever reads it.
	if got := err.Error(); !strings.Contains(got, "-pki-cert, -pki-key, -pki-peer-ca") {
		t.Errorf("error = %q, want the flags in sorted order", got)
	}
}

func TestPKIRejectsUnknownSubjectSource(t *testing.T) {
	set := mintPKI(t)
	args := append(pkiArgs(set.Server.Dir), "-pki-subject", "favourite_colour")
	if _, _, _, err := parseFlags(t, RoleServer, args...).Server(discardLogger()); err == nil {
		t.Fatal("Server accepted an unknown -pki-subject")
	}
}

func TestPKIRejectsAPeerCAFileWithNoCertificates(t *testing.T) {
	set := mintPKI(t)
	args := pkiArgs(set.Server.Dir)
	// Point -pki-peer-ca at the key: a real file, readable, no
	// certificate in it. AppendCertsFromPEM reports this only by
	// returning false, so an unchecked call yields an empty pool that
	// rejects every peer at handshake time instead of at startup.
	args[len(args)-1] = filepath.Join(set.Server.Dir, credentials.PKIKeyFile)
	_, _, _, err := parseFlags(t, RoleServer, args...).Server(discardLogger())
	if err == nil {
		t.Fatal("Server accepted a -pki-peer-ca holding no certificate")
	}
	if !strings.Contains(err.Error(), "no PEM certificate") {
		t.Errorf("error = %q, want it to say the file holds no certificate", err)
	}
}

func TestSPIFFERequiresATrustDomain(t *testing.T) {
	set := mintSPIFFE(t)
	_, _, _, err := parseFlags(t, RoleServer, "-profile", SPIFFE, "-spiffe-dir", set.Server.Dir).
		Server(discardLogger())
	if err == nil {
		t.Fatal("Server accepted -profile spiffe with no trust domain")
	}
	if !strings.Contains(err.Error(), "-spiffe-trust-domain") {
		t.Errorf("error = %q, want it to name -spiffe-trust-domain", err)
	}
}

// A client dials one known service. Leaving it unnamed would mean
// trusting every SVID the bundle can verify, which is most of the fleet.
func TestSPIFFEClientRequiresSomethingToAuthorize(t *testing.T) {
	set := mintSPIFFE(t)
	_, closer, err := parseFlags(t, RoleClient, spiffeArgs(set.Client.Dir)...).Client(discardLogger())
	if err == nil {
		t.Fatal("Client accepted -profile spiffe with nothing to authorize")
	}
	_ = closer()
	if !strings.Contains(err.Error(), "-spiffe-authorize-id") {
		t.Errorf("error = %q, want it to name -spiffe-authorize-id", err)
	}
}

func TestSPIFFEFlagErrorsNameTheRolesFlag(t *testing.T) {
	tests := []struct {
		name string
		role Role
		args []string
		want string
	}{
		{
			name: "server id",
			role: RoleServer,
			args: []string{"-spiffe-admit-id", "not a spiffe id"},
			want: "-spiffe-admit-id",
		},
		{
			name: "client id",
			role: RoleClient,
			args: []string{"-spiffe-authorize-id", "not a spiffe id"},
			want: "-spiffe-authorize-id",
		},
		{
			name: "server gke",
			role: RoleServer,
			args: []string{"-spiffe-admit-gke", "project/namespace"},
			want: "-spiffe-admit-gke",
		},
		{
			name: "client gke",
			role: RoleClient,
			args: []string{"-spiffe-authorize-gke", "project//sa"},
			want: "-spiffe-authorize-gke",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := parseFlags(t, tc.role, tc.args...)
			_, err := f.spiffeMatcher()
			if err == nil {
				t.Fatalf("spiffeMatcher accepted %v", tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %s", err, tc.want)
			}
		})
	}
}

func TestSPIFFEGKEWorkloadMatcher(t *testing.T) {
	f := parseFlags(t, RoleServer, "-spiffe-admit-gke", "my-project/default/hello-client")
	m, err := f.spiffeMatcher()
	if err != nil {
		t.Fatalf("spiffeMatcher: %v", err)
	}
	if m == nil {
		t.Fatal("spiffeMatcher returned nil for a valid -spiffe-admit-gke")
	}
}

func TestSPIFFEMatcherIsNilWhenNothingIsNamed(t *testing.T) {
	m, err := parseFlags(t, RoleServer).spiffeMatcher()
	if err != nil {
		t.Fatalf("spiffeMatcher: %v", err)
	}
	if m != nil {
		t.Error("spiffeMatcher invented a matcher from no flags")
	}
}

// An empty -spiffe-admit-id would otherwise append the zero ID, which
// matches nothing and looks like a working allowlist.
func TestRepeatableFlagRejectsAnEmptyValue(t *testing.T) {
	var f Flags
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f.Register(fs, RoleServer)
	if err := fs.Parse([]string{"-spiffe-admit-id", ""}); err == nil {
		t.Fatal("an empty -spiffe-admit-id was accepted")
	}
}

func TestBothProfilesOfferHTTP2(t *testing.T) {
	pkiSet := mintPKI(t)
	spiffeSet := mintSPIFFE(t)

	serverPKI, _ := serverFor(t, pkiArgs(pkiSet.Server.Dir)...)
	clientPKI := clientFor(t, pkiArgs(pkiSet.Client.Dir)...)
	serverSPIFFE, _ := serverFor(t, spiffeArgs(spiffeSet.Server.Dir)...)
	clientSPIFFE := clientFor(t,
		append(spiffeArgs(spiffeSet.Client.Dir), "-spiffe-authorize-id", spiffeSet.Server.Subject)...)

	for name, cfg := range map[string]*tls.Config{
		"pki server":    serverPKI,
		"pki client":    clientPKI,
		"spiffe server": serverSPIFFE,
		"spiffe client": clientSPIFFE,
	} {
		if len(cfg.NextProtos) == 0 || cfg.NextProtos[0] != "h2" {
			t.Errorf("%s NextProtos = %v, want h2 first", name, cfg.NextProtos)
		}
	}
}
