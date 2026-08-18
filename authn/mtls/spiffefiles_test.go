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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/go-steer/purser/authn/mtls"
	"github.com/go-steer/purser/internal/ca"
)

// credDir is a directory shaped like GKE's credential mount, whose
// contents a test can rewrite to simulate rotation.
type credDir struct {
	dir        string
	certPath   string
	keyPath    string
	bundlePath string
}

func newCredDir(tb testing.TB) *credDir {
	tb.Helper()
	dir := tb.TempDir()
	return &credDir{
		dir:        dir,
		certPath:   filepath.Join(dir, mtls.GKECertFile),
		keyPath:    filepath.Join(dir, mtls.GKEKeyFile),
		bundlePath: filepath.Join(dir, mtls.GKEBundleFile),
	}
}

func (d *credDir) options(td spiffeid.TrustDomain) mtls.SPIFFEFileOptions {
	return mtls.SPIFFEFileOptions{
		CertPath:    d.certPath,
		KeyPath:     d.keyPath,
		BundlePath:  d.bundlePath,
		TrustDomain: td,
		// Reloading off by default: the tests that care about it ask
		// for it, and the ones that do not should not race a ticker.
		ReloadInterval: -1,
	}
}

// write lays down one generation of credentials: an SVID for id signed
// by authority, and anchors trusting the given authorities.
func (d *credDir) write(tb testing.TB, authority *ca.CA, id string, anchors ...*ca.CA) {
	tb.Helper()

	cert, err := authority.Issue(ca.LeafOptions{URISANs: []string{id}})
	if err != nil {
		tb.Fatalf("issue SVID %q: %v", id, err)
	}
	certPEM, keyPEM, err := ca.EncodePEM(cert)
	if err != nil {
		tb.Fatalf("encode SVID: %v", err)
	}
	var bundlePEM []byte
	for _, anchor := range anchors {
		bundlePEM = append(bundlePEM, anchor.CertPEM()...)
	}
	d.writeRaw(tb, certPEM, keyPEM, bundlePEM)
}

func (d *credDir) writeRaw(tb testing.TB, certPEM, keyPEM, bundlePEM []byte) {
	tb.Helper()
	for path, content := range map[string][]byte{
		d.certPath:   certPEM,
		d.keyPath:    keyPEM,
		d.bundlePath: bundlePEM,
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			tb.Fatalf("write %s: %v", path, err)
		}
	}
}

// writeFile drops one extra file into the mount and returns its path.
func (d *credDir) writeFile(tb testing.TB, name string, content []byte) string {
	tb.Helper()
	path := filepath.Join(d.dir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		tb.Fatalf("write %s: %v", path, err)
	}
	return path
}

func newCoreCA(tb testing.TB, name string) *ca.CA {
	tb.Helper()
	authority, err := ca.New(name)
	if err != nil {
		tb.Fatalf("ca.New(%q): %v", name, err)
	}
	return authority
}

func trustDomain(tb testing.TB, s string) spiffeid.TrustDomain {
	tb.Helper()
	td, err := spiffeid.TrustDomainFromString(s)
	if err != nil {
		tb.Fatalf("parse trust domain %q: %v", s, err)
	}
	return td
}

func TestSPIFFEFileSourceLoadsBothHalves(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	td := trustDomain(t, testTrustDomain)
	dir.write(t, authority, testClientID, authority)

	src, err := mtls.NewSPIFFEFileSource(dir.options(td))
	if err != nil {
		t.Fatalf("NewSPIFFEFileSource: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	svid, err := src.GetX509SVID()
	if err != nil {
		t.Fatalf("GetX509SVID: %v", err)
	}
	if got := svid.ID.String(); got != testClientID {
		t.Errorf("SVID ID = %q, want %q", got, testClientID)
	}

	bundle, err := src.GetX509BundleForTrustDomain(td)
	if err != nil {
		t.Fatalf("GetX509BundleForTrustDomain: %v", err)
	}
	if n := len(bundle.X509Authorities()); n != 1 {
		t.Errorf("the bundle holds %d authorities, want 1", n)
	}
}

// TestSPIFFEFileSourceServesTheSPIFFEProfile is the integration that
// matters: a source built from files drives a real handshake, so the
// GKE path and the Workload API path are interchangeable at
// SPIFFEOptions.
func TestSPIFFEFileSourceServesTheSPIFFEProfile(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	td := trustDomain(t, testTrustDomain)
	dir.write(t, authority, testServerID, authority)

	src, err := mtls.NewSPIFFEFileSource(dir.options(td))
	if err != nil {
		t.Fatalf("NewSPIFFEFileSource: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	cfg, auth, err := mtls.NewSPIFFE(mtls.SPIFFEOptions{
		SVIDSource:   src,
		BundleSource: src,
	})
	if err != nil {
		t.Fatalf("NewSPIFFE with a file source: %v", err)
	}
	url := startSPIFFEServer(t, cfg, auth)

	// The client's credential comes from the same files, so a
	// round trip proves both halves of the source.
	status, body, err := spiffeGet(t, url, src, src)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if status != 200 || body != testServerID {
		t.Errorf("status = %d, body = %q; want 200 and %q", status, body, testServerID)
	}
}

// TestSPIFFEFileSourceReloads is the property the whole type exists
// for. A source that read once at startup would keep serving the first
// credential, and on a platform that rotates them that means presenting
// an expired certificate a few hours after deploy.
func TestSPIFFEFileSourceReloads(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	td := trustDomain(t, testTrustDomain)
	dir.write(t, authority, testClientID, authority)

	opts := dir.options(td)
	opts.ReloadInterval = time.Millisecond
	src, err := mtls.NewSPIFFEFileSource(opts)
	if err != nil {
		t.Fatalf("NewSPIFFEFileSource: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	first, err := src.GetX509SVID()
	if err != nil {
		t.Fatalf("GetX509SVID: %v", err)
	}

	// Rotate: same identity, a freshly minted certificate.
	dir.write(t, authority, testClientID, authority)

	deadline := time.Now().Add(5 * time.Second)
	for {
		current, err := src.GetX509SVID()
		if err != nil {
			t.Fatalf("GetX509SVID after rotation: %v", err)
		}
		if !current.Certificates[0].Equal(first.Certificates[0]) {
			return // picked up the new generation
		}
		if time.Now().After(deadline) {
			t.Fatal("the source never picked up the rotated credential")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestSPIFFEFileSourceKeepsTheLastGoodCredential covers the torn read:
// a rotating writer observed mid-write leaves a new certificate beside
// an old key. Going dark on that would turn a transient inconsistency
// into an outage, so the previous credential is retained and the error
// is reported.
func TestSPIFFEFileSourceKeepsTheLastGoodCredential(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	td := trustDomain(t, testTrustDomain)
	dir.write(t, authority, testClientID, authority)

	var mu sync.Mutex
	var errs []error
	opts := dir.options(td)
	opts.ReloadInterval = time.Millisecond
	opts.OnError = func(err error) {
		mu.Lock()
		defer mu.Unlock()
		errs = append(errs, err)
	}
	src, err := mtls.NewSPIFFEFileSource(opts)
	if err != nil {
		t.Fatalf("NewSPIFFEFileSource: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	good, err := src.GetX509SVID()
	if err != nil {
		t.Fatalf("GetX509SVID: %v", err)
	}

	// A new certificate beside the key that does not match it — what a
	// reader sees between the two writes of an in-place rotation.
	torn, err := authority.Issue(ca.LeafOptions{URISANs: []string{testClientID}})
	if err != nil {
		t.Fatalf("issue the torn generation: %v", err)
	}
	tornCertPEM, _, err := ca.EncodePEM(torn)
	if err != nil {
		t.Fatalf("encode the torn generation: %v", err)
	}
	if err := os.WriteFile(dir.certPath, tornCertPEM, 0o600); err != nil {
		t.Fatalf("write the torn certificate: %v", err)
	}

	// Wait for a reload to fail *for this reason*. Counting errors would
	// also be satisfied by the torn-read detector firing on the write
	// itself, which is a different mechanism and is covered by its own
	// test — the property here is that x509svid.Parse catches a
	// certificate that does not go with the key.
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for {
		mu.Lock()
		if n := len(errs); n > 0 {
			lastErr = errs[n-1]
		}
		mu.Unlock()
		if lastErr != nil && strings.Contains(lastErr.Error(), "does not match private key") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a mismatched certificate and key did not produce a key-mismatch reload "+
				"error; last error was %v", lastErr)
		}
		time.Sleep(2 * time.Millisecond)
	}

	current, err := src.GetX509SVID()
	if err != nil {
		t.Fatalf("GetX509SVID after a failed reload: %v", err)
	}
	if !current.Certificates[0].Equal(good.Certificates[0]) {
		t.Error("a failed reload replaced the last good credential; it must be retained")
	}
}

func TestNewSPIFFEFileSourceRejectsIncompleteOptions(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	td := trustDomain(t, testTrustDomain)
	dir.write(t, authority, testClientID, authority)

	tests := []struct {
		name    string
		mutate  func(*mtls.SPIFFEFileOptions)
		wantErr string
	}{
		{
			name:    "no cert path",
			mutate:  func(o *mtls.SPIFFEFileOptions) { o.CertPath = "" },
			wantErr: "CertPath is required",
		},
		{
			name:    "no key path",
			mutate:  func(o *mtls.SPIFFEFileOptions) { o.KeyPath = "" },
			wantErr: "KeyPath is required",
		},
		{
			name:    "no bundle path",
			mutate:  func(o *mtls.SPIFFEFileOptions) { o.BundlePath = "" },
			wantErr: "BundlePath is required",
		},
		{
			name:    "no trust domain",
			mutate:  func(o *mtls.SPIFFEFileOptions) { o.TrustDomain = spiffeid.TrustDomain{} },
			wantErr: "TrustDomain is required",
		},
		{
			name:    "cert file absent",
			mutate:  func(o *mtls.SPIFFEFileOptions) { o.CertPath = filepath.Join(dir.dir, "absent.pem") },
			wantErr: "read SVID chain",
		},
		{
			name:    "key file absent",
			mutate:  func(o *mtls.SPIFFEFileOptions) { o.KeyPath = filepath.Join(dir.dir, "absent.pem") },
			wantErr: "read SVID key",
		},
		{
			name:    "bundle file absent",
			mutate:  func(o *mtls.SPIFFEFileOptions) { o.BundlePath = filepath.Join(dir.dir, "absent.pem") },
			wantErr: "read trust bundle",
		},
		{
			name: "cert file is not PEM",
			mutate: func(o *mtls.SPIFFEFileOptions) {
				o.CertPath = dir.writeFile(t, "garbage.pem", []byte("not a certificate"))
			},
			wantErr: "load X509-SVID",
		},
		{
			name: "bundle file is not PEM",
			mutate: func(o *mtls.SPIFFEFileOptions) {
				o.BundlePath = dir.writeFile(t, "garbage-bundle.pem", []byte("not a certificate"))
			},
			wantErr: "load trust bundle",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := dir.options(td)
			tc.mutate(&opts)
			src, err := mtls.NewSPIFFEFileSource(opts)
			if err == nil {
				_ = src.Close()
				t.Fatalf("NewSPIFFEFileSource accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestNewSPIFFEFileSourceRejectsACrossDomainBundle catches the
// misconfiguration whose symptom is otherwise entirely remote: anchors
// filed under a trust domain no peer presents, so every peer is
// rejected as untrusted with nothing pointing at the bundle.
func TestNewSPIFFEFileSourceRejectsACrossDomainBundle(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	dir.write(t, authority, testClientID, authority)

	opts := dir.options(trustDomain(t, "other.example"))
	src, err := mtls.NewSPIFFEFileSource(opts)
	if err == nil {
		_ = src.Close()
		t.Fatal("NewSPIFFEFileSource accepted a bundle domain the SVID is not in")
	}
	if !strings.Contains(err.Error(), "other.example") || !strings.Contains(err.Error(), testTrustDomain) {
		t.Errorf("error = %q, want it to name both trust domains", err)
	}
}

func TestNewSPIFFEFileSourceRejectsAnEmptyBundle(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	td := trustDomain(t, testTrustDomain)
	// An SVID, but anchors trusting nobody.
	dir.write(t, authority, testClientID)

	src, err := mtls.NewSPIFFEFileSource(dir.options(td))
	if err == nil {
		_ = src.Close()
		t.Fatal("NewSPIFFEFileSource accepted a bundle holding no authorities")
	}
	if !strings.Contains(err.Error(), "no X.509 authorities") {
		t.Errorf("error = %q, want it to say the bundle is empty", err)
	}
}

func TestSPIFFEFileSourceRejectsAnotherTrustDomain(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	td := trustDomain(t, testTrustDomain)
	dir.write(t, authority, testClientID, authority)

	src, err := mtls.NewSPIFFEFileSource(dir.options(td))
	if err != nil {
		t.Fatalf("NewSPIFFEFileSource: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	if _, err := src.GetX509BundleForTrustDomain(trustDomain(t, "federated.example")); err == nil {
		t.Error("a single-domain source answered for a domain it holds no anchors for")
	}
}

// TestZeroSPIFFEFileSourceFailsClosed covers a value obtained by any
// means other than the constructor. It has loaded nothing, and
// returning a nil SVID would hand crypto/tls a nil certificate rather
// than an error it can report.
func TestZeroSPIFFEFileSourceFailsClosed(t *testing.T) {
	t.Parallel()

	var src mtls.SPIFFEFileSource

	if _, err := src.GetX509SVID(); err == nil {
		t.Error("a zero SPIFFEFileSource returned an SVID")
	} else if !strings.Contains(err.Error(), "NewSPIFFEFileSource") {
		t.Errorf("error = %q, want it to name the constructor", err)
	}

	if _, err := src.GetX509BundleForTrustDomain(trustDomain(t, testTrustDomain)); err == nil {
		t.Error("a zero SPIFFEFileSource returned a bundle")
	}
}

func TestSPIFFEFileSourceCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	td := trustDomain(t, testTrustDomain)
	dir.write(t, authority, testClientID, authority)

	opts := dir.options(td)
	opts.ReloadInterval = time.Millisecond
	src, err := mtls.NewSPIFFEFileSource(opts)
	if err != nil {
		t.Fatalf("NewSPIFFEFileSource: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	// A closed source stops answering, matching workloadapi.X509Source.
	// It is no longer reloading, so anything it served would be a
	// credential frozen at the moment of Close — fine for a second,
	// wrong by expiry, and silent in between. The caller who wrote
	// `defer src.Close()` in a function that returns the tls.Config
	// finds out immediately instead.
	if _, err := src.GetX509SVID(); err == nil {
		t.Error("GetX509SVID served a credential after Close")
	} else if !strings.Contains(err.Error(), "closed") {
		t.Errorf("GetX509SVID after Close: %v, want an error saying the source is closed", err)
	}
	if _, err := src.GetX509BundleForTrustDomain(td); err == nil {
		t.Error("GetX509BundleForTrustDomain served a bundle after Close")
	}
}

// TestZeroSPIFFEFileSourceCloseDoesNotPanic covers the misuse the
// getters already handle: Close on a value that never came from the
// constructor has a nil stop channel, and close(nil) panics.
func TestZeroSPIFFEFileSourceCloseDoesNotPanic(t *testing.T) {
	t.Parallel()

	var src mtls.SPIFFEFileSource
	if err := src.Close(); err != nil {
		t.Errorf("Close on a zero value: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Errorf("second Close on a zero value: %v", err)
	}
}

// TestNilSPIFFEFileSourceFailsClosed pins that a nil source reports an
// error rather than panicking. The getters go out of their way to fail
// closed on a zero value; a nil pointer is the same misuse.
func TestNilSPIFFEFileSourceFailsClosed(t *testing.T) {
	t.Parallel()

	var src *mtls.SPIFFEFileSource
	if _, err := src.GetX509SVID(); err == nil {
		t.Error("a nil source returned an SVID")
	}
	if _, err := src.GetX509BundleForTrustDomain(trustDomain(t, testTrustDomain)); err == nil {
		t.Error("a nil source returned a bundle")
	}
	if err := src.Close(); err != nil {
		t.Errorf("Close on a nil source: %v", err)
	}
}

// TestSPIFFEFileSourceCloseWithReloadingDisabled pins that Close does
// not block when no reload goroutine was ever started.
func TestSPIFFEFileSourceCloseWithReloadingDisabled(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	td := trustDomain(t, testTrustDomain)
	dir.write(t, authority, testClientID, authority)

	src, err := mtls.NewSPIFFEFileSource(dir.options(td))
	if err != nil {
		t.Fatalf("NewSPIFFEFileSource: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = src.Close()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked with reloading disabled")
	}
}

func TestGKEFileOptionsUsesTheDocumentedMount(t *testing.T) {
	t.Parallel()

	td := trustDomain(t, "example-project.svc.id.goog")
	opts := mtls.GKEFileOptions(td)

	want := map[string]string{
		"CertPath":   "/var/run/secrets/workload-spiffe-credentials/certificates.pem",
		"KeyPath":    "/var/run/secrets/workload-spiffe-credentials/private_key.pem",
		"BundlePath": "/var/run/secrets/workload-spiffe-credentials/ca_certificates.pem",
	}
	got := map[string]string{
		"CertPath":   opts.CertPath,
		"KeyPath":    opts.KeyPath,
		"BundlePath": opts.BundlePath,
	}
	for field, wantPath := range want {
		if got[field] != wantPath {
			t.Errorf("%s = %q, want %q", field, got[field], wantPath)
		}
	}
	if opts.TrustDomain != td {
		t.Errorf("TrustDomain = %q, want %q", opts.TrustDomain, td)
	}
}

// TestSPIFFEFileSourceClonesTheBundle pins that a caller cannot reach
// through the returned bundle and change what every other handshake in
// the process trusts.
//
// x509bundle.Bundle looks immutable and is not: AddX509Authority is
// exported, and x509bundle's own GetX509BundleForTrustDomain returns the
// receiver rather than a copy. Handing out the live bundle would let any
// holder promote an untrusted issuer to a trusted one process-wide.
func TestSPIFFEFileSourceClonesTheBundle(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	rogue := newCoreCA(t, "rogue-ca")
	td := trustDomain(t, testTrustDomain)
	dir.write(t, authority, testClientID, authority)

	src, err := mtls.NewSPIFFEFileSource(dir.options(td))
	if err != nil {
		t.Fatalf("NewSPIFFEFileSource: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	handed, err := src.GetX509BundleForTrustDomain(td)
	if err != nil {
		t.Fatalf("GetX509BundleForTrustDomain: %v", err)
	}
	handed.AddX509Authority(rogue.Cert())
	handed.SetX509Authorities(nil)

	fresh, err := src.GetX509BundleForTrustDomain(td)
	if err != nil {
		t.Fatalf("second GetX509BundleForTrustDomain: %v", err)
	}
	if fresh.Empty() {
		t.Fatal("emptying the returned bundle emptied the source's anchors")
	}
	if fresh.HasX509Authority(rogue.Cert()) {
		t.Error("an authority added to the returned bundle became trusted by the source")
	}
	if !fresh.HasX509Authority(authority.Cert()) {
		t.Error("the source lost its real authority")
	}
}

// TestSPIFFEFileSourceRejectsATornBundleRead is the CA-rotation case.
//
// A bundle growing from one anchor to two, caught mid-write, parses
// cleanly as a one-anchor bundle: go-spiffe's PEM reader discards a
// trailing partial block without error. Accepting that generation would
// swap in new-anchor-only anchors and reject every existing peer, with
// nothing logged. The double read catches the file moving underneath.
func TestSPIFFEFileSourceRejectsATornBundleRead(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	incoming := newCoreCA(t, "purser-file-ca-next")
	td := trustDomain(t, testTrustDomain)
	dir.write(t, authority, testClientID, authority)

	var mu sync.Mutex
	var lastErr error
	torn := make(chan struct{})
	var tornOnce sync.Once
	opts := dir.options(td)
	opts.ReloadInterval = time.Millisecond
	opts.OnError = func(err error) {
		mu.Lock()
		lastErr = err
		mu.Unlock()
		// A torn read can also surface as "no X.509 authorities" when
		// both reads land on a freshly truncated file. That is a real
		// rejection too, but it is not what this test is pinning.
		if strings.Contains(err.Error(), "changed while being read") {
			tornOnce.Do(func() { close(torn) })
		}
	}

	src, err := mtls.NewSPIFFEFileSource(opts)
	if err != nil {
		t.Fatalf("NewSPIFFEFileSource: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	// Rewrite the bundle continuously between one anchor and two, so a
	// reload is overwhelmingly likely to read it in two different
	// states. This is the writer the double read exists to catch.
	both := make([]byte, 0, len(authority.CertPEM())+len(incoming.CertPEM()))
	both = append(both, authority.CertPEM()...)
	both = append(both, incoming.CertPEM()...)
	stop := make(chan struct{})
	writing := make(chan struct{})
	go func() {
		defer close(writing)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.WriteFile(dir.bundlePath, authority.CertPEM(), 0o600)
			_ = os.WriteFile(dir.bundlePath, both, 0o600)
		}
	}()
	defer func() {
		close(stop)
		<-writing
	}()

	select {
	case <-torn:
	case <-time.After(30 * time.Second):
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("the bundle was rewritten continuously and no reload reported a torn read, "+
			"so a torn generation would have been accepted silently; last error was %v", lastErr)
	}
}

// TestSPIFFEFileSourceRefusesAnExpiredSVID pins that retention is not
// unbounded. If the mount becomes permanently unreadable there is no
// next good tick, and serving a dead certificate turns a local
// misconfiguration into a remote TLS alert.
func TestSPIFFEFileSourceRefusesAnExpiredSVID(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	td := trustDomain(t, testTrustDomain)

	// Long enough that the "still valid" assertion below is not a race
	// against a loaded machine under -race, short enough that the test
	// can wait it out.
	notAfter := time.Now().Add(2 * time.Second)
	cert, err := authority.Issue(ca.LeafOptions{
		URISANs:   []string{testClientID},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  notAfter,
	})
	if err != nil {
		t.Fatalf("issue a short-lived SVID: %v", err)
	}
	certPEM, keyPEM, err := ca.EncodePEM(cert)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	dir.writeRaw(t, certPEM, keyPEM, authority.CertPEM())

	opts := dir.options(td)
	// A live reload loop, so this pins retention rather than the absence
	// of reloading: the loop keeps trying and keeps failing.
	opts.ReloadInterval = time.Millisecond
	src, err := mtls.NewSPIFFEFileSource(opts)
	if err != nil {
		t.Fatalf("NewSPIFFEFileSource: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	if time.Now().Before(notAfter) {
		if _, err := src.GetX509SVID(); err != nil {
			t.Fatalf("GetX509SVID while still valid: %v", err)
		}
	} else {
		t.Log("the SVID expired before it could be read once; skipping the still-valid check")
	}

	// Remove the mount, so no reload can ever succeed again.
	if err := os.Remove(dir.certPath); err != nil {
		t.Fatalf("remove the cert: %v", err)
	}
	time.Sleep(time.Until(notAfter) + 100*time.Millisecond)

	_, err = src.GetX509SVID()
	if err == nil {
		t.Fatal("the source served an expired SVID")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error = %q, want it to say the SVID expired", err)
	}
	// The bundle is unaffected: anchors do not expire with the SVID, and
	// a workload that cannot present an identity can still verify peers.
	if _, err := src.GetX509BundleForTrustDomain(td); err != nil {
		t.Errorf("GetX509BundleForTrustDomain after SVID expiry: %v", err)
	}
}

// TestSPIFFEFileSourceSurvivesABlockingOnError pins that caller-supplied
// code cannot freeze rotation.
//
// Called inline from the reload loop, a callback that blocks would stop
// every future reload — the SVID ages out to expiry even after the files
// recover — and would deadlock Close, which waits for that loop.
func TestSPIFFEFileSourceSurvivesABlockingOnError(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	td := trustDomain(t, testTrustDomain)
	dir.write(t, authority, testClientID, authority)

	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	entered := make(chan struct{}, 1)

	opts := dir.options(td)
	opts.ReloadInterval = time.Millisecond
	opts.OnError = func(error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}

	src, err := mtls.NewSPIFFEFileSource(opts)
	if err != nil {
		t.Fatalf("NewSPIFFEFileSource: %v", err)
	}

	// Break the mount so reloads start failing and OnError blocks.
	if err := os.Remove(dir.certPath); err != nil {
		t.Fatalf("remove the cert: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("OnError was never called")
	}

	// Restore the files with a new SVID. A frozen loop would never see
	// them.
	next := "spiffe://example.org/ns/prod/sa/rotated"
	dir.write(t, authority, next, authority)

	deadline := time.After(30 * time.Second)
	for {
		svid, err := src.GetX509SVID()
		if err == nil && svid.ID.String() == next {
			break
		}
		select {
		case <-deadline:
			t.Fatal("the reload loop never picked up the restored credential; " +
				"a blocking OnError froze rotation")
		case <-time.After(2 * time.Millisecond):
		}
	}

	// And Close must not wait on the still-blocked callback.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = src.Close()
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Close blocked behind a blocking OnError")
	}
}

// TestSPIFFEFileSourceSerialisesOnError is what bounds the cost of a
// slow callback.
//
// Delivering each failure on a goroutine of its own is the obvious way
// to keep caller code off the reload loop, and it is unbounded: a
// callback blocked on a wedged log sink accumulates one goroutine per
// tick — thousands a day at the default interval — for as long as the
// mount stays broken. One long-lived goroutine draining a short queue
// costs a few dropped duplicates of "the reload is still failing"
// instead, which is a message the first call already delivered.
func TestSPIFFEFileSourceSerialisesOnError(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	td := trustDomain(t, testTrustDomain)
	dir.write(t, authority, testClientID, authority)

	var inFlight, maxInFlight, calls atomic.Int64
	opts := dir.options(td)
	opts.ReloadInterval = time.Millisecond
	opts.OnError = func(error) {
		calls.Add(1)
		n := inFlight.Add(1)
		for {
			was := maxInFlight.Load()
			if n <= was || maxInFlight.CompareAndSwap(was, n) {
				break
			}
		}
		// Long enough, against a 1ms tick, that overlapping calls would
		// be the norm rather than a race the test might miss.
		time.Sleep(5 * time.Millisecond)
		inFlight.Add(-1)
	}

	src, err := mtls.NewSPIFFEFileSource(opts)
	if err != nil {
		t.Fatalf("NewSPIFFEFileSource: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	if err := os.Remove(dir.certPath); err != nil {
		t.Fatalf("remove the cert: %v", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for calls.Load() < 5 {
		if time.Now().After(deadline) {
			t.Fatalf("OnError ran %d times, want at least 5 failing reloads", calls.Load())
		}
		time.Sleep(2 * time.Millisecond)
	}
	if got := maxInFlight.Load(); got != 1 {
		t.Errorf("%d OnError calls ran concurrently, want 1; delivery is not serialised, "+
			"so a blocked callback would accumulate a goroutine per failed reload", got)
	}
}

// TestSPIFFEFileSourceSurvivesACloseFromOnError covers the natural
// reaction to a credential failure — tear the source down — which,
// called inline from the reload loop, would self-deadlock: Close waits
// for the loop, the loop waits for the callback, the callback waits for
// Close.
func TestSPIFFEFileSourceSurvivesACloseFromOnError(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	td := trustDomain(t, testTrustDomain)
	dir.write(t, authority, testClientID, authority)

	closed := make(chan struct{})
	// ready publishes src to the callback's goroutine. The reload loop
	// starts inside the constructor, so without it the callback would be
	// reading a variable the test is still writing.
	ready := make(chan struct{})
	var src *mtls.SPIFFEFileSource
	var once sync.Once

	opts := dir.options(td)
	opts.ReloadInterval = time.Millisecond
	opts.OnError = func(error) {
		<-ready
		once.Do(func() {
			_ = src.Close()
			close(closed)
		})
	}

	var err error
	src, err = mtls.NewSPIFFEFileSource(opts)
	close(ready)
	if err != nil {
		t.Fatalf("NewSPIFFEFileSource: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	if err := os.Remove(dir.certPath); err != nil {
		t.Fatalf("remove the cert: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(30 * time.Second):
		t.Fatal("Close called from OnError deadlocked")
	}
}

// TestSPIFFEFileSourceSurvivesAPanickingOnError pins that a bug in
// caller-supplied code does not take down the process from a goroutine
// the caller never started and cannot recover on.
func TestSPIFFEFileSourceSurvivesAPanickingOnError(t *testing.T) {
	t.Parallel()

	dir := newCredDir(t)
	authority := newCoreCA(t, "purser-file-ca")
	td := trustDomain(t, testTrustDomain)
	dir.write(t, authority, testClientID, authority)

	panicked := make(chan struct{}, 1)
	opts := dir.options(td)
	opts.ReloadInterval = time.Millisecond
	opts.OnError = func(error) {
		select {
		case panicked <- struct{}{}:
		default:
		}
		panic("a bug in the caller's error handler")
	}

	src, err := mtls.NewSPIFFEFileSource(opts)
	if err != nil {
		t.Fatalf("NewSPIFFEFileSource: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	if err := os.Remove(dir.certPath); err != nil {
		t.Fatalf("remove the cert: %v", err)
	}
	select {
	case <-panicked:
	case <-time.After(30 * time.Second):
		t.Fatal("OnError was never called")
	}

	// Reaching here at all means the panic did not kill the process.
	// Rotation must also still work.
	next := "spiffe://example.org/ns/prod/sa/rotated"
	dir.write(t, authority, next, authority)

	deadline := time.After(30 * time.Second)
	for {
		svid, err := src.GetX509SVID()
		if err == nil && svid.ID.String() == next {
			return
		}
		select {
		case <-deadline:
			t.Fatal("rotation stopped after a panicking OnError")
		case <-time.After(2 * time.Millisecond):
		}
	}
}
