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

// Package client dials purser-authenticated services.
//
// It is the other half of authn/mtls: the same two profiles, from the
// side that presents the certificate rather than the side that reads
// it. NewPKI matches mtls.NewPKI and NewSPIFFE matches mtls.NewSPIFFE.
//
// Pair them accordingly, but note that mispairing is a configuration
// error rather than a security boundary: each end still applies its own
// profile's checks in full. A SPIFFE client dialling a PKI listener can
// in fact succeed, when that listener's own certificate happens to be
// SVID-shaped and issued by an authority in the client's bundle — the
// client verified an SVID and the server verified a chain, both
// correctly, having merely disagreed about which profile they were
// speaking. What the matched-pair rule prevents is the opposite and
// much worse case, on the server: an authenticator reading a verified
// chain that the config it was paired with never populated.
//
// # Verification is symmetric
//
// Authentication is mutual, so the client owes the server exactly what
// the server owes the client. Both profiles here verify the *server's*
// certificate, and both do it from tls.Config.VerifyConnection, for the
// same reason the server side does: crypto/tls skips
// VerifyPeerCertificate when a session is resumed from a ticket. Go
// says so itself, in handshake_client.go — "Resumptions currently don't
// reverify certificates so they don't call verifyServerCertificate" —
// and calls VerifyConnection on both paths to compensate.
//
// This is why NewSPIFFE does not return tlsconfig.MTLSClientConfig.
// That helper sets InsecureSkipVerify and hangs go-spiffe's
// verification off VerifyPeerCertificate, so a resumed session verifies
// the server's SVID not at all: with crypto/tls's own checking disabled
// and the only replacement skipped, a ticket is the entire proof of
// identity for the lifetime of that ticket. An authority since
// withdrawn from the bundle keeps being accepted, and so does a server
// whose SVID a narrowed Authorize would now reject.
//
// Expiry of the server's leaf is the one thing crypto/tls still catches
// on its own: loadSession drops a cached session whose certificate has
// passed NotAfter, and that check sits above the InsecureSkipVerify
// guard, so it applies even to a config like go-spiffe's. Everything
// else on that path is the helper's to do and it does not do it. purser
// keeps go-spiffe's verification logic and moves the hook.
//
// Neither constructor sets a ClientSessionCache, so a purser client
// does not resume by default and none of the above is load-bearing
// until a caller opts in. It is set up this way regardless, because the
// caller who does opt in should not have to know that doing so is what
// makes the difference.
//
// # What these configs do not check
//
// The SPIFFE profile enforces no extended key usage. go-spiffe's
// x509svid.Verify passes ExtKeyUsageAny, where crypto/tls would have
// required serverAuth of a server and clientAuth of a client, so a
// client-only SVID is accepted as a server identity. SPIRE mints both
// usages by default and this matches every other go-spiffe consumer,
// but an operator should not read EKU as a control here. Where it
// matters, narrow Authorize.
//
// # Returned configs are owned by the caller, with two caveats
//
// The config is yours to adjust — a ClientSessionCache, a KeyLogWriter,
// a tighter CipherSuites list — but two fields are load-bearing and
// overwriting them removes the verification the constructor installed:
// VerifyConnection, and (for SPIFFE) InsecureSkipVerify, which must
// stay true for the reason given above.
//
// # Encrypted Client Hello needs nothing here, and that is worth saying
//
// crypto/tls skips VerifyConnection on one further path: when a caller
// sets EncryptedClientHelloConfigList and the server rejects ECH, both
// VerifyPeerCertificate and VerifyConnection are guarded by
// !echRejected, and the chain is verified against RootCAs instead —
// nil under the SPIFFE profile, meaning the system roots. That reads
// like the resumption trap above and invites the same fix, an
// EncryptedClientHelloRejectionVerify hook. It is not, and the hook is
// a mistake, for two independent reasons.
//
// The path cannot complete a handshake. On rejection the TLS 1.3
// client sends alertECHRequired and returns *tls.ECHRejectionError
// before marking the handshake complete, whatever the hook decided. The
// only way past that is to negotiate TLS 1.2, and crypto/tls refuses to
// offer ECH at all unless MinVersion is 1.3 or unset — these
// constructors always set MinVersion, so a purser config takes the
// error either way. There is no reachable state in which an
// ECH-rejected connection is used.
//
// And the hook could not verify anything if there were. crypto/tls
// calls it with the ConnectionState built before c.peerCertificates is
// assigned, so PeerCertificates is empty: any honest hook returns an
// error unconditionally. Installing one converts a clean
// ECHRejectionError — which carries the RetryConfigs a client needs to
// recover from a stale ECH config — into a bad_certificate alert and a
// misleading complaint about the server's chain.
//
// So neither constructor sets the hook. If a future Go closes the gap
// between the call and the assignment, revisit reason one first: it is
// the one that makes the path unreachable.
package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/go-steer/purser/authn/mtls"
	"github.com/go-steer/purser/internal/tlsfloor"
)

// PKIOptions configures NewPKI, the standard-CA client profile.
type PKIOptions struct {
	// Certificate is the client's own certificate and key. Exactly one
	// of Certificate and GetClientCertificate is required.
	Certificate *tls.Certificate

	// GetClientCertificate supplies the client certificate per
	// handshake, for deployments that rotate it in place. Exactly one
	// of Certificate and GetClientCertificate is required.
	GetClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)

	// RootCAs is the pool of authorities the server's certificate must
	// chain to. Required.
	//
	// Nil is not taken to mean the system roots. A service-to-service
	// client talks to an internal CA, and the two spellings of nil —
	// "I forgot" and "I meant the public web PKI" — are worth
	// distinguishing when the consequence of the first is trusting
	// every CA a browser would. A deployment that really does want the
	// system pool passes x509.SystemCertPool.
	RootCAs *x509.CertPool

	// ServerName is the name verified against the server certificate,
	// and sent as SNI. Empty leaves crypto/tls to use the dialed host,
	// which is what a client addressing a service by DNS wants. Set it
	// when dialing by IP, or through a tunnel whose address is not the
	// service's name.
	ServerName string

	// Admit is the optional check applied to the server's verified
	// leaf, the mirror of mtls.PKIOptions.Admit. Nil admits any server
	// whose chain reaches RootCAs.
	//
	// Worth setting when the pool holds a CA that issues broadly: chain
	// verification alone then proves only that the peer holds some
	// certificate from that CA, which every other client of it also
	// does.
	Admit mtls.CertMatcher

	// MinVersion is the minimum TLS version. Zero means TLS 1.3;
	// values below TLS 1.2 are rejected.
	MinVersion uint16

	// NextProtos is the ALPN protocol list. Empty leaves crypto/tls to
	// negotiate.
	NextProtos []string
}

// SPIFFEOptions configures NewSPIFFE, the X509-SVID client profile.
type SPIFFEOptions struct {
	// SVIDSource supplies the client's own X509-SVID, freshly, per
	// handshake. Required.
	//
	// A *workloadapi.X509Source where a SPIFFE agent exposes the
	// Workload API, or mtls.NewSPIFFEFileSource where the platform
	// delivers credentials as files, as GKE's managed workload
	// identity does.
	SVIDSource x509svid.Source

	// BundleSource supplies the X.509 authorities the server's SVID
	// must chain to, keyed by trust domain. Required, and consulted on
	// every verification rather than snapshotted.
	BundleSource x509bundle.Source

	// Authorize decides which server SPIFFE IDs this client will talk
	// to. Required.
	//
	// The server profile lets Admit be nil and the client profile does
	// not, because the two sides are asking different questions. A
	// server admits a population — every workload the authority issues
	// to may legitimately connect — while a client dials one known
	// service, and "any workload in the trust domain" includes every
	// compromised peer that can win a race for the address. Naming the
	// server is the point of mutual authentication; a nil authorizer
	// would quietly discard half of it.
	//
	// Compose with the Match helpers in authn/mtls, or with go-spiffe's
	// spiffeid.MatchID, MatchOneOf, and MatchMemberOf.
	Authorize spiffeid.Matcher

	// MinVersion is the minimum TLS version. Zero means TLS 1.3;
	// values below TLS 1.2 are rejected.
	MinVersion uint16

	// NextProtos is the ALPN protocol list. Empty leaves crypto/tls to
	// negotiate.
	NextProtos []string
}

// NewPKI returns a client TLS config presenting a certificate from a
// standard CA and verifying the server against RootCAs.
//
// The returned config pairs with a listener from mtls.NewPKI.
func NewPKI(opts PKIOptions) (*tls.Config, error) {
	switch {
	case opts.Certificate == nil && opts.GetClientCertificate == nil:
		return nil, errors.New("purser/client: PKIOptions: one of Certificate or " +
			"GetClientCertificate is required; a client that presents none cannot " +
			"authenticate to an mTLS listener")
	case opts.Certificate != nil && opts.GetClientCertificate != nil:
		return nil, errors.New("purser/client: PKIOptions: Certificate and " +
			"GetClientCertificate are mutually exclusive")
	}
	if opts.RootCAs == nil {
		return nil, errors.New("purser/client: PKIOptions: RootCAs is required; " +
			"nil is not taken to mean the system pool, which for an internal service " +
			"would trust every CA a browser does")
	}
	minVersion, err := tlsfloor.Resolve(opts.MinVersion)
	if err != nil {
		return nil, fmt.Errorf("purser/client: %w", err)
	}

	cfg := &tls.Config{
		MinVersion: minVersion,
		RootCAs:    opts.RootCAs,
		ServerName: opts.ServerName,
		// Copied: net/http appends "h2" to this slice in place when the
		// transport upgrades, and a shared backing array would carry
		// that into the caller's own.
		NextProtos: slices.Clone(opts.NextProtos),
	}
	if opts.Certificate != nil {
		cert := *opts.Certificate
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		}
	} else {
		cfg.GetClientCertificate = opts.GetClientCertificate
	}
	if opts.Admit != nil {
		admit := opts.Admit
		// VerifyConnection, not VerifyPeerCertificate: see the package
		// comment. crypto/tls populates VerifiedChains on a resumed
		// handshake too, restoring it from the session, so the matcher
		// sees a verified leaf on every connection.
		verify := func(cs tls.ConnectionState) error {
			if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
				// Unreachable while InsecureSkipVerify is false, which
				// this constructor never sets. Failing closed is the
				// only safe reading if it ever becomes reachable.
				return errors.New("purser/client: server presented no verified certificate chain")
			}
			if err := admit(cs.VerifiedChains[0][0]); err != nil {
				return fmt.Errorf("purser/client: server not admitted: %w", err)
			}
			return nil
		}
		cfg.VerifyConnection = verify
	}
	return cfg, nil
}

// NewSPIFFE returns a client TLS config presenting an X509-SVID and
// verifying the server's against the trust bundle.
//
// The returned config pairs with a listener from mtls.NewSPIFFE.
func NewSPIFFE(opts SPIFFEOptions) (*tls.Config, error) {
	if opts.SVIDSource == nil {
		return nil, errors.New("purser/client: SPIFFEOptions: SVIDSource is required; " +
			"the client has no identity of its own to present")
	}
	if opts.BundleSource == nil {
		return nil, errors.New("purser/client: SPIFFEOptions: BundleSource is required; " +
			"without trust anchors the server's SVID cannot be verified")
	}
	if opts.Authorize == nil {
		return nil, errors.New("purser/client: SPIFFEOptions: Authorize is required; " +
			"see the field comment — a client that will talk to any SVID in the trust " +
			"domain has given up the half of mutual authentication it controls. Pass " +
			"spiffeid.MatchAny() to say so deliberately")
	}
	minVersion, err := tlsfloor.Resolve(opts.MinVersion)
	if err != nil {
		return nil, fmt.Errorf("purser/client: %w", err)
	}

	bundle := opts.BundleSource
	authorize := opts.Authorize
	verify := func(cs tls.ConnectionState) error {
		id, _, err := x509svid.Verify(cs.PeerCertificates, bundle)
		if err != nil {
			return fmt.Errorf("purser/client: server X509-SVID did not verify: %w", err)
		}
		if err := authorize(id); err != nil {
			return fmt.Errorf("purser/client: server %q not authorized: %w", id, err)
		}
		return nil
	}
	return &tls.Config{
		MinVersion: minVersion,
		// Copied: net/http appends "h2" to this slice in place when the
		// transport upgrades, and a shared backing array would carry
		// that into the caller's own.
		NextProtos:           slices.Clone(opts.NextProtos),
		GetClientCertificate: tlsconfig.GetClientCertificate(opts.SVIDSource),
		// crypto/tls cannot verify an SVID: there is no hostname to
		// match, and the anchors are keyed by the peer's trust domain
		// rather than pooled. Its chain builder is switched off and
		// VerifyConnection does the work instead — never left as the
		// only line of defence on a hook crypto/tls might skip.
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection below
		VerifyConnection:   verify,
	}, nil
}

// Transport returns an HTTP transport using cfg, with sane timeouts and
// HTTP/2 enabled.
//
// It exists because the obvious construction is subtly wrong.
// net/http upgrades a transport to HTTP/2 automatically only while its
// TLSClientConfig is nil; setting one — which mTLS requires — silently
// drops the connection back to HTTP/1.1 unless ForceAttemptHTTP2 is
// also set. A streaming surface that quietly lost multiplexing is a
// hard thing to notice and an easy thing to prevent.
//
// The config is cloned. net/http does not treat TLSClientConfig as
// read-only — enabling HTTP/2 appends "h2" to its NextProtos in place —
// so handing it the caller's config would mutate a value the caller may
// still be using for a raw tls.Dial or a second transport, and two
// transports over one config is a genuine data race under -race.
// Adjust the config before calling this, not after.
//
// Callers wanting different timeouts should build their own
// http.Transport; this is the default, not a policy.
//
// It panics on a nil config. Every other reading is worse: net/http
// would dial with the system roots and no client certificate, so a
// transport built for mTLS would silently become one that cannot
// authenticate and will trust any CA a browser does. Neither
// constructor returns a nil config with a nil error, so reaching this
// means an unchecked error somewhere above.
func Transport(cfg *tls.Config) *http.Transport {
	if cfg == nil {
		panic("purser/client: Transport called with a nil *tls.Config; " +
			"that would dial with the system roots and no client certificate")
	}
	// Not http.DefaultTransport.(*http.Transport) directly: a failed
	// assertion would yield a nil *http.Transport whose Clone method
	// dereferences the receiver on its first line. Test harnesses and
	// tracing libraries do replace DefaultTransport, and panicking
	// there would be a strange way to find out.
	out := &http.Transport{}
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		out = t.Clone()
	} else {
		// Whatever replaced DefaultTransport, the result still has to be
		// a usable transport. Without a DialContext net/http falls back
		// to a zero net.Dialer, which has no connect timeout at all — so
		// this branch would hand back something strictly more dangerous
		// than the one above, and only on the machines where the
		// assertion happens to fail.
		out.Proxy = http.ProxyFromEnvironment
		out.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
		out.MaxIdleConns = 100
		out.IdleConnTimeout = 90 * time.Second
		out.ExpectContinueTimeout = time.Second
	}
	clone := cfg.Clone()
	// Clone copies the NextProtos header but not its backing array, and
	// net/http's HTTP/2 setup appends to that slice in place. Clip so
	// the append has to reallocate rather than write into whatever the
	// caller still holds.
	clone.NextProtos = slices.Clip(slices.Clone(clone.NextProtos))
	out.TLSClientConfig = clone
	out.ForceAttemptHTTP2 = true
	out.TLSHandshakeTimeout = 10 * time.Second
	return out
}
