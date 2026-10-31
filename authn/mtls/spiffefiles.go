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

package mtls

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/go-steer/purser/internal/filereload"
)

// GKE's managed workload identity delivers credentials as files, not
// over the SPIFFE Workload API. The podcertificate.gke.io CSI driver
// mounts this directory read-only into the pod and rewrites the
// contents in place as the SVID and the trust anchors rotate.
const (
	// GKECredentialsDir is the conventional mount point.
	GKECredentialsDir = "/var/run/secrets/workload-spiffe-credentials" //nolint:gosec // G101: a mount path, not a credential
	// GKECertFile holds the SVID chain, leaf first.
	GKECertFile = "certificates.pem"
	// GKEKeyFile holds the SVID private key.
	GKEKeyFile = "private_key.pem"
	// GKEBundleFile holds the X.509 trust anchors for the pod's own
	// trust domain.
	//
	// The directory also carries trust_bundles.json, which describes
	// federated domains. This package does not read it; a deployment
	// that federates needs a bundle source covering several trust
	// domains, which this single-domain source is not.
	GKEBundleFile = "ca_certificates.pem"
)

// SPIFFEFileOptions configures NewSPIFFEFileSource.
type SPIFFEFileOptions struct {
	// CertPath, KeyPath, and BundlePath are the PEM files holding the
	// SVID chain (leaf first), its private key, and the X.509 trust
	// anchors. BundlePath is required, and so is either the CertPath
	// and KeyPath pair or CredentialBundlePath.
	CertPath   string
	KeyPath    string
	BundlePath string

	// CredentialBundlePath is a single PEM file holding the private key
	// and the SVID chain, leaf first: the credentialBundlePath layout of
	// a Kubernetes podCertificate projected volume, as Agent
	// Substrate's podidentity signer issues. It replaces CertPath and
	// KeyPath and is mutually exclusive with them. See
	// CertificateFileOptions.CredentialBundlePath for the format; here
	// the key must be PKCS#8 ("PRIVATE KEY"), as go-spiffe requires and
	// as Kubernetes writes it.
	CredentialBundlePath string

	// TrustDomain is the domain the anchors in BundlePath vouch for.
	// Required: a PEM file is a bare list of certificates and says
	// nothing about which trust domain it belongs to, whereas a
	// x509bundle.Source is keyed by exactly that.
	TrustDomain spiffeid.TrustDomain

	// ReloadInterval is how often the files are re-read. Zero means 30
	// seconds. A negative interval disables reloading, which is the
	// right setting only when the files provably never change — a
	// local demo minting one credential at startup, say — and the
	// wrong one on any platform that rotates them.
	ReloadInterval time.Duration

	// OnError is called when a reload fails and the previous
	// credential is retained. Optional, but a deployment that sets
	// nothing here has no way to learn that its credentials stopped
	// refreshing — and if the mount has become permanently unreadable,
	// a handshake failure at expiry is the only other signal it gets.
	//
	// It is called on a goroutine of the source's own, one call at a
	// time and in order, so it may block and it may call Close. A panic
	// in it is recovered and discarded rather than taking down a
	// process on a goroutine the caller never started. It may still be
	// running after Close returns.
	//
	// Because it is serialised, a callback that blocks causes errors
	// raised while it is blocked to be dropped once a small queue
	// fills. The alternative — a goroutine per failed reload — is
	// unbounded: a callback blocked on a wedged log sink would
	// accumulate one goroutine per tick, thousands a day, for as long
	// as the mount stays broken. Dropping duplicates of "the reload is
	// still failing" costs the operator nothing; the first one already
	// said it.
	OnError func(error)
}

// SPIFFEFileSource supplies an X509-SVID and a trust bundle from files
// on disk, re-reading them so that rotation needs no restart.
//
// It implements both x509svid.Source and x509bundle.Source, so one
// value satisfies both halves of SPIFFEOptions.
//
// # Why this exists
//
// The go-spiffe answer to "where do my credentials come from" is
// workloadapi.X509Source, which streams them from a local agent over a
// Unix socket. SPIRE works that way. GKE's managed workload identity
// does not: it hands the pod files and rewrites them in place. There is
// no socket to dial, so there is nothing for workloadapi.X509Source to
// talk to.
//
// Reading those files once at startup is the trap. SVIDs are
// short-lived by design — the whole SPIFFE security argument rests on
// it — so a server that loads its credential at boot presents an
// expired certificate within hours and cannot explain why. NewSPIFFE
// takes sources rather than certificates precisely so the credential
// can change underneath it; a file-backed source has to actually
// change.
//
// # Rotation is not atomic
//
// A rotating writer can be observed mid-write, and parsing alone does
// not catch it. A mismatched cert and key is caught, because
// x509svid.Parse checks the private key against the leaf's public key.
// A *truncated* file is not: go-spiffe's PEM reader discards a trailing
// partial block without error, so a half-written three-certificate
// chain parses cleanly as a two-certificate chain. The sharp case is a
// CA rotation, when the bundle grows from one anchor to two and a torn
// read lands on new-anchor-only — every existing peer is rejected, with
// nothing logged.
//
// So each generation is read twice and the bytes compared, and a
// generation is only accepted if the files held still across both
// reads. A writer caught mid-rotation is retried on the next tick.
//
// On any reload error the last good credential is retained and OnError
// is called; a stale SVID that may still be valid beats no SVID. If the
// mount becomes permanently unreadable there is no next good tick, so
// that retention needs a bound — and only one half of it has one.
//
// The SVID half does: GetX509SVID refuses to serve a leaf that has
// actually expired, so the process fails locally and legibly rather
// than presenting a dead certificate and collecting a TLS alert.
//
// The bundle half does not, and cannot from here. A trust anchor is a
// long-lived CA certificate; withdrawing one is an edit to the file,
// not an expiry, and a source that can no longer read the file has no
// way to tell a withdrawal from a mount glitch. So a revoked authority
// stays honoured for as long as the mount stays broken. Where the two
// halves come from one source this is bounded in practice — the SVID
// expires within hours and the workload stops serving — but that is a
// side effect, not a guarantee, and it disappears when the halves are
// split: a workloadapi.X509Source for the SVID beside this for the
// bundle keeps presenting a fresh SVID while trusting a withdrawn
// authority indefinitely. OnError is the only signal that happens, so
// a deployment that splits them should alert on it.
//
// # The returned values are read-only
//
// GetX509SVID and GetX509BundleForTrustDomain hand out values the
// source may also be serving to concurrent handshakes. The bundle is
// cloned per call, so mutating it is merely useless. The SVID is not —
// x509svid.SVID is a plain struct with no lock — so writing to the
// returned Certificates or PrivateKey fields is a data race. Treat both
// as immutable.
type SPIFFEFileSource struct {
	opts   SPIFFEFileOptions
	reload *filereload.Reloader[fileCredentials]
}

// fileCredentials is one consistent read of all three files. It is
// swapped in whole, so a caller never sees an SVID from one generation
// beside a bundle from another.
type fileCredentials struct {
	svid   *x509svid.SVID
	bundle *x509bundle.Bundle
}

var (
	_ x509svid.Source   = (*SPIFFEFileSource)(nil)
	_ x509bundle.Source = (*SPIFFEFileSource)(nil)
)

// GKEFileOptions returns the options for GKE's managed workload
// identity mount, for the given trust domain.
//
// On the fleet path that domain is PROJECT_ID.svc.id.goog; on a
// self-managed pool it is POOL_ID.global.PROJECT_NUMBER.workload.id.goog.
// It is a parameter rather than something this package derives, because
// getting it wrong is a silent misconfiguration: the anchors would be
// filed under a domain no peer presents, and every peer would be
// rejected as untrusted.
func GKEFileOptions(trustDomain spiffeid.TrustDomain) SPIFFEFileOptions {
	return SPIFFEFileOptions{
		CertPath:    filepath.Join(GKECredentialsDir, GKECertFile),
		KeyPath:     filepath.Join(GKECredentialsDir, GKEKeyFile),
		BundlePath:  filepath.Join(GKECredentialsDir, GKEBundleFile),
		TrustDomain: trustDomain,
	}
}

// NewSPIFFEFileSource reads the credentials once and, unless reloading
// is disabled, starts a goroutine that re-reads them on an interval.
//
// The initial read is synchronous and its failure is the constructor's:
// a server whose credentials are missing or malformed should not reach
// the point of listening. Call Close to stop the reloader.
func NewSPIFFEFileSource(opts SPIFFEFileOptions) (*SPIFFEFileSource, error) {
	if err := validateCredentialPaths("SPIFFEFileOptions", opts.CredentialBundlePath,
		opts.CertPath, opts.KeyPath); err != nil {
		return nil, err
	}
	switch {
	case opts.BundlePath == "":
		return nil, errors.New("purser/mtls: SPIFFEFileOptions: BundlePath is required")
	case opts.TrustDomain.IsZero():
		return nil, errors.New("purser/mtls: SPIFFEFileOptions: TrustDomain is required; " +
			"a PEM bundle does not say which trust domain its anchors vouch for")
	}

	s := &SPIFFEFileSource{opts: opts}
	r, err := filereload.Start(s.load, opts.ReloadInterval, opts.OnError)
	if err != nil {
		return nil, err
	}
	s.reload = r
	return s, nil
}

// GetX509SVID returns the most recently loaded SVID.
//
// It returns an error once that SVID has expired. Reloading is
// best-effort — the mount may be gone — and there is no honest way to
// serve a certificate that is already dead: presenting it produces a
// TLS alert from the peer, which is a slower and more confusing way to
// learn the same thing.
//
// The returned value must not be modified; see the type comment.
func (s *SPIFFEFileSource) GetX509SVID() (*x509svid.SVID, error) {
	creds, err := s.current()
	if err != nil {
		return nil, err
	}
	if len(creds.svid.Certificates) == 0 {
		return nil, errors.New("purser/mtls: SPIFFEFileSource holds an SVID with no certificates")
	}
	if notAfter := creds.svid.Certificates[0].NotAfter; time.Now().After(notAfter) {
		return nil, fmt.Errorf("purser/mtls: SPIFFEFileSource: the SVID for %q expired at %s and "+
			"has not been replaced; check %q and the OnError callback",
			creds.svid.ID, notAfter.UTC().Format(time.RFC3339), s.certSource())
	}
	return creds.svid, nil
}

// current returns the live credential, or the reason there is none.
func (s *SPIFFEFileSource) current() (*fileCredentials, error) {
	if s == nil {
		return nil, errors.New("purser/mtls: SPIFFEFileSource is nil")
	}
	creds, err := s.reload.Current()
	switch {
	case errors.Is(err, filereload.ErrClosed):
		// Matching workloadapi.X509Source, which reports every read
		// after Close rather than serving a credential it has stopped
		// refreshing. A caller who closed the source but left the
		// tls.Config alive — `defer src.Close()` in a function that
		// returns the config — should find out now, not at expiry.
		return nil, errors.New("purser/mtls: SPIFFEFileSource is closed")
	case err != nil:
		// Reached only by a zero value: NewSPIFFEFileSource stores a
		// credential before returning.
		return nil, errors.New("purser/mtls: SPIFFEFileSource has loaded no credential; " +
			"it must come from NewSPIFFEFileSource")
	}
	return creds, nil
}

// certSource names the file the SVID chain comes from, for messages.
func (s *SPIFFEFileSource) certSource() string {
	if s.opts.CredentialBundlePath != "" {
		return s.opts.CredentialBundlePath
	}
	return s.opts.CertPath
}

// GetX509BundleForTrustDomain returns the most recently loaded anchors
// for trustDomain, and an error for any other domain.
//
// One PEM file describes one trust domain, so this source cannot answer
// for a federated peer. A deployment that federates composes a
// x509bundle.Set from several sources.
//
// The bundle is cloned per call. x509bundle.Bundle looks immutable and
// is not: AddX509Authority and SetX509Authorities are exported, and
// x509bundle's own GetX509BundleForTrustDomain returns the receiver
// rather than a copy. Handing out the live bundle would let any holder
// add a trust anchor — turning an unverifiable peer into a verified one
// for every concurrent handshake in the process — or empty it and
// reject all of them.
func (s *SPIFFEFileSource) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	creds, err := s.current()
	if err != nil {
		return nil, err
	}
	bundle, err := creds.bundle.GetX509BundleForTrustDomain(trustDomain)
	if err != nil {
		return nil, err
	}
	return bundle.Clone(), nil
}

// Close stops the reload goroutine and makes every subsequent read
// report that the source is closed. It is idempotent and safe to call
// concurrently, including from OnError.
//
// It returns once the reload goroutine has exited, so a test can assert
// no goroutine outlives the source. The goroutine running OnError is not
// waited for and a callback in progress may outlive this call.
//
// The wait is not bounded, and on one failure mode it does not return:
// the reload goroutine notices Close only between ticks, so if it is
// blocked inside os.ReadFile on a wedged mount — an unresponsive CSI
// driver or a hung network filesystem — Close blocks with it. Reads
// already fail by then, since they check the closed flag rather than
// the goroutine, so what is lost is the caller's shutdown path rather
// than any safety property. A timeout here was considered and rejected:
// it would trade a visible hang for a silently leaked goroutine still
// writing to the source, and a process whose credential mount has
// wedged is not going to shut down cleanly regardless. Callers who must
// bound shutdown should give Close its own goroutine and move on.
func (s *SPIFFEFileSource) Close() error {
	if s == nil {
		return nil
	}
	return s.reload.Close()
}

// load reads and validates one generation of all three files.
//
// The files are read twice and the bytes compared, because a rotating
// writer can be caught mid-write and the parsers do not reliably say so:
// go-spiffe's PEM reader drops a trailing partial block silently, so a
// truncated chain or bundle parses as a shorter valid one. Two identical
// reads is not a proof — a writer could finish between them — but it
// turns the common case, a write in progress right now, from a silent
// wrong answer into a retry on the next tick.
func (s *SPIFFEFileSource) load() (*fileCredentials, error) {
	certPEM, keyPEM, bundlePEM, err := s.readAll()
	if err != nil {
		return nil, err
	}

	svid, err := x509svid.Parse(certPEM, keyPEM)
	if err != nil {
		if s.opts.CredentialBundlePath != "" {
			return nil, fmt.Errorf("purser/mtls: load X509-SVID from %q: %w",
				s.opts.CredentialBundlePath, err)
		}
		return nil, fmt.Errorf("purser/mtls: load X509-SVID from %q and %q: %w",
			s.opts.CertPath, s.opts.KeyPath, err)
	}
	bundle, err := x509bundle.Parse(s.opts.TrustDomain, bundlePEM)
	if err != nil {
		return nil, fmt.Errorf("purser/mtls: load trust bundle for %q from %q: %w",
			s.opts.TrustDomain, s.opts.BundlePath, err)
	}
	// A workload whose own SVID is in one domain and whose anchors are
	// filed under another is misconfigured, and the symptom is remote:
	// every peer in the real trust domain is rejected as untrusted,
	// with nothing pointing at the bundle. Say so here instead.
	if got := svid.ID.TrustDomain(); got != s.opts.TrustDomain {
		return nil, fmt.Errorf("purser/mtls: SVID %q is in trust domain %q, but the bundle at "+
			"%q is configured for %q", svid.ID, got, s.opts.BundlePath, s.opts.TrustDomain)
	}
	if bundle.Empty() {
		return nil, fmt.Errorf("purser/mtls: trust bundle at %q holds no X.509 authorities, "+
			"so no peer SVID could verify", s.opts.BundlePath)
	}
	return &fileCredentials{svid: svid, bundle: bundle}, nil
}

// readAll reads the credential and bundle files twice, and returns
// their contents only if both reads agree. See filereload.ReadStable.
func (s *SPIFFEFileSource) readAll() (certPEM, keyPEM, bundlePEM []byte, err error) {
	files := []filereload.File{
		{Path: s.opts.CertPath, What: "SVID chain"},
		{Path: s.opts.KeyPath, What: "SVID key"},
		{Path: s.opts.BundlePath, What: "trust bundle"},
	}
	if s.opts.CredentialBundlePath != "" {
		files = []filereload.File{
			{Path: s.opts.CredentialBundlePath, What: "SVID credential bundle"},
			{Path: s.opts.BundlePath, What: "trust bundle"},
		}
	}
	got, err := filereload.ReadStable(files...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("purser/mtls: %w", err)
	}
	if s.opts.CredentialBundlePath == "" {
		return got[0], got[1], got[2], nil
	}
	certPEM, keyPEM, keyType, err := splitCredentialBundle(got[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("purser/mtls: SVID credential bundle at %q: %w",
			s.opts.CredentialBundlePath, err)
	}
	if keyType != "PRIVATE KEY" {
		// go-spiffe parses only PKCS#8 and skips other key blocks
		// silently, which surfaces as a baffling "no private key found".
		return nil, nil, nil, fmt.Errorf("purser/mtls: SVID credential bundle at %q holds a %q "+
			"block; the SPIFFE profile needs a PKCS#8 \"PRIVATE KEY\"",
			s.opts.CredentialBundlePath, keyType)
	}
	return certPEM, keyPEM, got[1], nil
}
