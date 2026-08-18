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
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
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

// defaultReloadInterval is how often SPIFFEFileSource re-reads its
// files when ReloadInterval is unset.
//
// Parsing three small PEM documents is far cheaper than being wrong
// about a rotation, so this errs toward freshness. It is well under
// GKE's roughly five-minute trust-anchor propagation delay, which is
// the real floor on how quickly a withdrawal can take effect.
const defaultReloadInterval = 30 * time.Second

// SPIFFEFileOptions configures NewSPIFFEFileSource.
type SPIFFEFileOptions struct {
	// CertPath, KeyPath, and BundlePath are the PEM files holding the
	// SVID chain (leaf first), its private key, and the X.509 trust
	// anchors. All three are required.
	CertPath   string
	KeyPath    string
	BundlePath string

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
	opts  SPIFFEFileOptions
	state atomic.Pointer[fileCredentials]

	// errs queues reload failures for the single goroutine that runs
	// OnError. Nil when the caller supplied no callback.
	errs      chan error
	stop      chan struct{}
	closeOnce sync.Once
	done      chan struct{}
}

// errQueueDepth is how many reload failures may be waiting on OnError
// before further ones are dropped.
//
// Deep enough that an ordinarily slow callback loses nothing at a 30s
// tick, shallow enough to stay a constant. What it buys is a bound: the
// queue, not the goroutine count, is what grows when a callback wedges.
const errQueueDepth = 8

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
	switch {
	case opts.CertPath == "":
		return nil, errors.New("purser/mtls: SPIFFEFileOptions: CertPath is required")
	case opts.KeyPath == "":
		return nil, errors.New("purser/mtls: SPIFFEFileOptions: KeyPath is required")
	case opts.BundlePath == "":
		return nil, errors.New("purser/mtls: SPIFFEFileOptions: BundlePath is required")
	case opts.TrustDomain.IsZero():
		return nil, errors.New("purser/mtls: SPIFFEFileOptions: TrustDomain is required; " +
			"a PEM bundle does not say which trust domain its anchors vouch for")
	}

	s := &SPIFFEFileSource{
		opts: opts,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	creds, err := s.load()
	if err != nil {
		return nil, err
	}
	s.state.Store(creds)

	if opts.ReloadInterval < 0 {
		close(s.done)
		return s, nil
	}
	interval := opts.ReloadInterval
	if interval == 0 {
		interval = defaultReloadInterval
	}
	if opts.OnError != nil {
		s.errs = make(chan error, errQueueDepth)
		go s.reportLoop()
	}
	go s.reloadLoop(interval)
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
			creds.svid.ID, notAfter.UTC().Format(time.RFC3339), s.opts.CertPath)
	}
	return creds.svid, nil
}

// current returns the live credential, or the reason there is none.
func (s *SPIFFEFileSource) current() (*fileCredentials, error) {
	if s == nil {
		return nil, errors.New("purser/mtls: SPIFFEFileSource is nil")
	}
	if s.isClosed() {
		// Matching workloadapi.X509Source, which reports every read
		// after Close rather than serving a credential it has stopped
		// refreshing. A caller who closed the source but left the
		// tls.Config alive — `defer src.Close()` in a function that
		// returns the config — should find out now, not at expiry.
		return nil, errors.New("purser/mtls: SPIFFEFileSource is closed")
	}
	creds := s.state.Load()
	if creds == nil {
		// Unreachable via NewSPIFFEFileSource, which stores a
		// credential before returning. Reached only by a zero value.
		return nil, errors.New("purser/mtls: SPIFFEFileSource has loaded no credential; " +
			"it must come from NewSPIFFEFileSource")
	}
	return creds, nil
}

// isClosed reports whether Close has been called. A zero value has a nil
// stop channel and is not closed — it never started.
func (s *SPIFFEFileSource) isClosed() bool {
	if s.stop == nil {
		return false
	}
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
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
	if s == nil || s.stop == nil {
		// A zero value never started a goroutine, and close(nil) would
		// panic. The getters already fail closed for this case; Close
		// should not be the one method that punishes it.
		return nil
	}
	s.closeOnce.Do(func() { close(s.stop) })
	<-s.done
	return nil
}

// reloadLoop re-reads the files until Close.
func (s *SPIFFEFileSource) reloadLoop(interval time.Duration) {
	defer close(s.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			creds, err := s.load()
			if err != nil {
				// Keep the last good credential. See the type comment:
				// a stale SVID may still be valid, and GetX509SVID
				// refuses to serve it once it is not.
				s.reportError(err)
				continue
			}
			s.state.Store(creds)
		}
	}
}

// reportError queues err for the OnError goroutine, dropping it if that
// goroutine is behind.
//
// Delivery is off the reload loop because calling OnError inline would
// put caller-supplied code on that loop's critical path, where three
// ordinary things become severe: a callback that blocks stops all future
// reloads, so the SVID quietly ages out to expiry even after the files
// recover; a callback that calls Close deadlocks outright, since Close
// waits for the loop that is waiting for the callback; and a panic takes
// down the process from a goroutine the caller never started and cannot
// recover on.
//
// The send is non-blocking so that the reload loop is not merely off the
// callback's critical path but independent of it.
func (s *SPIFFEFileSource) reportError(err error) {
	if s.errs == nil {
		return
	}
	select {
	case s.errs <- err:
	default:
		// The callback is more than errQueueDepth behind. See the
		// OnError field comment: the errors being dropped here all say
		// the same thing as the one already queued ahead of them.
	}
}

// reportLoop runs OnError, one call at a time, until Close.
//
// One long-lived goroutine rather than one per failure: a callback that
// blocks should cost a bounded queue, not an unbounded pile of
// goroutines for as long as the mount stays unreadable.
func (s *SPIFFEFileSource) reportLoop() {
	for {
		select {
		case <-s.stop:
			return
		case err := <-s.errs:
			s.deliver(err)
		}
	}
}

// deliver calls OnError with a panic in it recovered, so that a callback
// cannot take the process down from a goroutine its author never started.
func (s *SPIFFEFileSource) deliver(err error) {
	defer func() { _ = recover() }()
	s.opts.OnError(err)
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

// readAll reads the three files twice and returns their contents only if
// both reads agree. See load for why.
func (s *SPIFFEFileSource) readAll() (certPEM, keyPEM, bundlePEM []byte, err error) {
	read := func() (c, k, b []byte, err error) {
		if c, err = os.ReadFile(s.opts.CertPath); err != nil {
			return nil, nil, nil, fmt.Errorf("purser/mtls: read SVID chain: %w", err)
		}
		if k, err = os.ReadFile(s.opts.KeyPath); err != nil {
			return nil, nil, nil, fmt.Errorf("purser/mtls: read SVID key: %w", err)
		}
		if b, err = os.ReadFile(s.opts.BundlePath); err != nil {
			return nil, nil, nil, fmt.Errorf("purser/mtls: read trust bundle: %w", err)
		}
		return c, k, b, nil
	}

	certPEM, keyPEM, bundlePEM, err = read()
	if err != nil {
		return nil, nil, nil, err
	}
	certAgain, keyAgain, bundleAgain, err := read()
	if err != nil {
		return nil, nil, nil, err
	}
	if !bytes.Equal(certPEM, certAgain) ||
		!bytes.Equal(keyPEM, keyAgain) ||
		!bytes.Equal(bundlePEM, bundleAgain) {
		return nil, nil, nil, fmt.Errorf("purser/mtls: credentials under %q changed while being "+
			"read, so this generation may be torn; retrying on the next reload",
			filepath.Dir(s.opts.CertPath))
	}
	return certPEM, keyPEM, bundlePEM, nil
}
