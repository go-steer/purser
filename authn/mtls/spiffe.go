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
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
)

// Label keys set on the Caller resolved from an X509-SVID, in addition
// to the cert.* audit labels every mTLS profile sets.
const (
	// LabelTrustDomain is the SPIFFE ID's trust domain — the part a
	// federation policy is written against, and the one field of an ID
	// that says which authority minted it.
	LabelTrustDomain = "spiffe.trust_domain"
	// LabelPath is the SPIFFE ID's path, leading slash included. It is
	// the workload-naming half of the ID, and what an authz rule that
	// does not care about federation matches on.
	LabelPath = "spiffe.path"
)

// SPIFFEOptions configures NewSPIFFE.
type SPIFFEOptions struct {
	// SVIDSource supplies the server's own X509-SVID, freshly, per
	// handshake. Required.
	//
	// In a SPIFFE deployment this is a *workloadapi.X509Source talking
	// to the local SPIFFE agent; SVIDs are short-lived by design, so
	// the source is an interface rather than a certificate for the same
	// reason PKIOptions.GetCertificate exists — the credential is
	// expected to change underneath the server.
	SVIDSource x509svid.Source

	// BundleSource supplies the X.509 authorities a peer's SVID must
	// chain to, keyed by trust domain. Required.
	//
	// It is consulted on every verification rather than snapshotted, so
	// a bundle rotation — a new authority added, a compromised one
	// withdrawn — takes effect without restarting the server.
	BundleSource x509bundle.Source

	// Admit is the optional connection-admission check (Layer A),
	// applied to the peer's verified SPIFFE ID during the handshake.
	//
	// Nil admits any peer holding an SVID that chains to the bundle.
	// That is a real policy inside a single trust domain, where the
	// SPIFFE authority issues only to workloads that are meant to be
	// able to connect. It is a much weaker one when BundleSource covers
	// federated trust domains: every federated peer is then admitted,
	// so a federating deployment should set at least
	// spiffeid.MatchMemberOf.
	//
	// Compose with the Match* helpers in this package, or with
	// go-spiffe's spiffeid.MatchID, MatchOneOf, and MatchMemberOf.
	Admit spiffeid.Matcher

	// MinVersion is the minimum TLS version. Zero means TLS 1.3;
	// values below TLS 1.2 are rejected.
	MinVersion uint16

	// NextProtos is the ALPN protocol list. Empty leaves crypto/tls to
	// negotiate; set it to, say, {"h2", "http/1.1"} to offer HTTP/2.
	NextProtos []string
}

// SPIFFEAuth resolves a Caller from a peer's X.509-SVID.
//
// SPIFFEAuth is safe for concurrent use; it is immutable after
// NewSPIFFE, and the bundle source it holds is required to be.
type SPIFFEAuth struct {
	// bundle is both the trust anchor Authenticate verifies against and
	// the marker that this value came from NewSPIFFE. A zero SPIFFEAuth
	// has none and rejects every request.
	bundle x509bundle.Source
}

var (
	_ authn.Authenticator  = (*SPIFFEAuth)(nil)
	_ authn.CredentialGate = (*SPIFFEAuth)(nil)
)

// NewSPIFFE returns a server TLS config requiring a client X509-SVID
// that chains to the trust bundle, and the authenticator that reads a
// SPIFFE ID from it.
//
// # Why this does not call tlsconfig.MTLSServerConfig
//
// go-spiffe's server helpers set RequireAnyClientCert and do the real
// work in VerifyPeerCertificate. crypto/tls does not call
// VerifyPeerCertificate when a session is resumed from a ticket — and
// because RequireAnyClientCert is below VerifyClientCertIfGiven, it
// does not re-check the carried chain against a pool either, there
// being no pool. A server built that way verifies the peer's SVID on
// the first handshake and, for the lifetime of the ticket, on no
// handshake after it: an SVID that has since expired, or an authority
// since withdrawn from the bundle, keeps working.
//
// So this constructor puts verification and admission in
// VerifyConnection, which crypto/tls calls on every handshake, resumed
// or full, on TLS 1.2 and 1.3, and leaves VerifyPeerCertificate unset
// so there is exactly one place the decision is made. The SVID is still
// parsed, verified, and authorized by go-spiffe's own code
// (x509svid.Verify); only the hook it hangs from is purser's.
//
// The config and the authenticator are returned together because they
// are one decision. The SPIFFE profile leaves tls.ConnectionState's
// VerifiedChains empty — go-spiffe verifies outside crypto/tls's chain
// builder — so there is no verified-state flag for the authenticator to
// read, and SPIFFEAuth re-verifies against the same bundle rather than
// trusting PeerCertificates on the say-so of a config it cannot inspect.
func NewSPIFFE(opts SPIFFEOptions) (*tls.Config, *SPIFFEAuth, error) {
	if opts.SVIDSource == nil {
		return nil, nil, errors.New("purser/mtls: SPIFFEOptions: SVIDSource is required; " +
			"the server has no identity of its own to present")
	}
	if opts.BundleSource == nil {
		return nil, nil, errors.New("purser/mtls: SPIFFEOptions: BundleSource is required; " +
			"without trust anchors no peer SVID can be verified")
	}
	minVersion, err := resolveMinVersion(opts.MinVersion)
	if err != nil {
		return nil, nil, err
	}

	bundle := opts.BundleSource
	admit := opts.Admit
	if admit == nil {
		admit = spiffeid.MatchAny()
	}

	cfg := &tls.Config{
		MinVersion: minVersion,
		// A certificate is demanded but crypto/tls is told not to judge
		// it: SVID verification has rules of its own — a single URI SAN
		// holding a well-formed SPIFFE ID, a non-CA leaf — and the
		// anchors come from a bundle keyed by the peer's own trust
		// domain, which ClientCAs cannot express.
		ClientAuth:     tls.RequireAnyClientCert,
		GetCertificate: tlsconfig.GetCertificate(opts.SVIDSource),
		NextProtos:     opts.NextProtos,
		VerifyConnection: func(cs tls.ConnectionState) error {
			id, _, err := x509svid.Verify(cs.PeerCertificates, bundle)
			if err != nil {
				return fmt.Errorf("purser/mtls: client X509-SVID did not verify: %w", err)
			}
			if err := admit(id); err != nil {
				return fmt.Errorf("purser/mtls: peer %q not admitted: %w", id, err)
			}
			return nil
		},
	}
	return cfg, &SPIFFEAuth{bundle: bundle}, nil
}

// Authenticate resolves the Caller from the peer's X509-SVID.
//
// It re-verifies the peer's certificates against the trust bundle
// rather than trusting the handshake to have done it. That costs a
// chain verification per request, and it buys two things. A SPIFFEAuth
// paired with a TLS config that does not verify — the mistake the
// matched-pair rule exists to prevent, and one the SPIFFE profile
// cannot otherwise detect, because there is no VerifiedChains to find
// empty — fails closed instead of accepting a self-signed certificate
// asserting any SPIFFE ID at all. And a bundle rotation or an expiring
// SVID takes effect on the next request rather than the next handshake,
// which on a long-lived streaming connection may be hours away.
//
// SPIFFEOptions.Admit is deliberately not re-applied here. Admission is
// a decision about a connection; per-request policy belongs to the
// authz layer, which sees the request as well as the caller.
func (a *SPIFFEAuth) Authenticate(r *http.Request) (purser.Caller, error) {
	state, err := connectionState(r)
	if err != nil {
		return purser.Caller{}, err
	}
	if a.bundle == nil {
		// A zero SPIFFEAuth, built by something other than NewSPIFFE. It
		// has no trust anchors, so it can verify nothing.
		return purser.Caller{}, fmt.Errorf("purser/mtls: SPIFFEAuth has no trust bundle; "+
			"it must come from NewSPIFFE: %w", purser.ErrUnauthenticated)
	}
	id, chains, err := x509svid.Verify(state.PeerCertificates, a.bundle)
	if err != nil {
		return purser.Caller{}, fmt.Errorf("purser/mtls: client X509-SVID did not verify: %w: %w",
			err, purser.ErrUnauthenticated)
	}
	// x509svid.Verify returns the chains it built, so this leaf is the
	// verified one rather than whatever the peer put first.
	leaf := chains[0][0]
	return purser.Caller{
		Identity: id.String(),
		Labels: map[string]string{
			LabelTrustDomain: id.TrustDomain().Name(),
			LabelPath:        id.Path(),
			LabelIssuerDN:    leaf.Issuer.String(),
			LabelSerial:      leaf.SerialNumber.Text(16),
			LabelNotAfter:    leaf.NotAfter.UTC().Format(time.RFC3339),
		},
	}, nil
}

// Source reports purser.AuthSourceSPIFFE, distinct from the PKI
// profile's AuthSourceMTLS, so an operator reading an audit record can
// tell a verified SPIFFE ID from a certificate subject that happens to
// look like one.
func (a *SPIFFEAuth) Source() purser.AuthSource { return purser.AuthSourceSPIFFE }

// GatesCredentials reports true: a request only reaches Authenticate
// over a connection whose client SVID was verified during the
// handshake — and Authenticate verifies it again.
func (a *SPIFFEAuth) GatesCredentials() bool { return true }
