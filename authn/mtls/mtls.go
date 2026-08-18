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

// Package mtls authenticates callers by the client certificate they
// presented on the TLS connection.
//
// # Two profiles
//
// A standard-CA (PKI) profile and a SPIFFE profile, because SPIFFE is
// the goal but nothing may require it: a deployment with an existing
// internal CA is a first-class path. They are separate constructors
// rather than one with a switch, because they verify with opposite
// crypto/tls idioms and a field that silently does nothing in the other
// profile is how a deployment ends up unverified.
//
//   - PKI sets ClientAuth to RequireAndVerifyClientCert with a
//     ClientCAs pool. crypto/tls builds the chain, so the verified leaf
//     is VerifiedChains[0][0].
//   - SPIFFE sets RequireAnyClientCert and verifies with go-spiffe,
//     against a trust bundle keyed by the peer's own trust domain.
//     crypto/tls's chain builder never runs, so VerifiedChains is
//     *empty* and the certificates are in PeerCertificates.
//
// Reading the wrong one is not a cosmetic mistake. PeerCertificates
// holds whatever the peer sent, verified or not; a PKI authenticator
// that read it — or that fell back to it when VerifiedChains was empty
// — would accept a self-signed certificate carrying any identity the
// attacker chose. This package never falls back. The SPIFFE
// authenticator, which has no VerifiedChains to read, re-verifies the
// certificates itself rather than assume the handshake did.
//
// # Matched pairs
//
// Each constructor returns a *tls.Config and the Authenticator that
// understands the connections it admits, together. It does not accept a
// caller-supplied *tls.Config to decorate. The verification idiom and
// the identity extraction are two halves of one decision, and a library
// that lets a caller supply half of it cannot state what the other half
// will find.
//
// # Admission and identity are separate
//
// Layer A — connection admission — decides whether a peer may open a
// connection at all: chain verification, plus the optional matcher in
// PKIOptions.Admit or SPIFFEOptions.Admit. It runs during the
// handshake, and a rejected peer never reaches an HTTP handler. Both
// profiles enforce it from tls.Config.VerifyConnection, the one hook
// crypto/tls calls on resumed handshakes as well as full ones.
//
// Layer B — identity extraction — runs per request and is
// unconditional. Whatever Layer A decided, the caller's identity is
// extracted and passed on, because authorization and audit need to name
// who acted. A peer that Layer A admitted but whose certificate carries
// no usable subject is rejected at Layer B with
// purser.ErrUnauthenticated — a 401 the client can read, rather than an
// opaque TLS alert.
package mtls

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/internal/tlsfloor"
)

// Label keys set on the Caller resolved from a client certificate.
// Namespaced under "cert." so they cannot collide with labels a
// deployment's own policy adds.
const (
	// LabelIssuerDN is the RFC 2253 distinguished name of the issuing
	// CA. With more than one CA in the pool, this is what says which
	// one vouched for the caller.
	LabelIssuerDN = "cert.issuer_dn"
	// LabelSerial is the certificate serial number in hex. Issuer DN
	// plus serial is the pair that identifies a certificate uniquely,
	// which is what a revocation list is keyed by and what an audit
	// trail needs to trace a request back to an issued credential.
	LabelSerial = "cert.serial"
	// LabelNotAfter is the certificate expiry, RFC 3339. An audit
	// consumer reading it can tell a long-lived credential from a
	// short-lived one without re-fetching the certificate.
	LabelNotAfter = "cert.not_after"
)

// connectionState returns the request's TLS state.
//
// A nil r.TLS means the request did not arrive over TLS at all — a
// plaintext listener, or a handler reached in a test. There is no
// certificate to read and no identity to infer, so it is
// unauthenticated rather than an internal error: the surface's job is
// to say 401, not 500.
func connectionState(r *http.Request) (*tls.ConnectionState, error) {
	if r == nil || r.TLS == nil {
		return nil, fmt.Errorf("purser/mtls: request did not arrive over TLS: %w", purser.ErrUnauthenticated)
	}
	return r.TLS, nil
}

// resolveMinVersion validates a configured TLS floor. The policy is
// shared with the client package so the two halves cannot drift.
func resolveMinVersion(v uint16) (uint16, error) {
	out, err := tlsfloor.Resolve(v)
	if err != nil {
		return 0, fmt.Errorf("purser/mtls: %w", err)
	}
	return out, nil
}
