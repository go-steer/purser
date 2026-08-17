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
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
)

// SubjectSource names the single certificate field an identity is read
// from.
//
// It is required, and there is deliberately no fallback chain. A rule
// like "the email SAN, or else the CN" is an impersonation surface: if
// any issuer in the pool can mint a certificate lacking the preferred
// field — and a CA that issues for more than one purpose usually can —
// then the attacker, not the operator, picks which field their identity
// comes from. One configured source; a certificate that does not carry
// it is rejected.
type SubjectSource string

const (
	// SubjectEmailSAN reads the rfc822Name SAN. The natural fit for
	// human operator certificates.
	SubjectEmailSAN SubjectSource = "san_email"

	// SubjectURISAN reads the URI SAN. For non-SPIFFE URI identities;
	// a SPIFFE deployment should use the SPIFFE profile, which
	// validates the ID's syntax rather than treating it as an opaque
	// string.
	SubjectURISAN SubjectSource = "san_uri"

	// SubjectDNSSAN reads the dNSName SAN. For service certificates.
	SubjectDNSSAN SubjectSource = "san_dns"

	// SubjectCommonName reads the subject CN.
	//
	// Supported because deployments have certificates shaped this way,
	// but discouraged: the CN is a display field with no defined
	// syntax, unconstrained by the SAN-based name constraints an
	// operator would use to stop one CA from minting identities in
	// another's namespace. Prefer a SAN.
	SubjectCommonName SubjectSource = "subject_cn"

	// SubjectDN reads the whole subject as an RFC 2253 string, for
	// deployments where the DN — organization, unit, and all — is the
	// identity.
	SubjectDN SubjectSource = "subject_dn"
)

// oidCommonName is 2.5.4.3, used to count how many CN attributes a
// subject actually carries. crypto/x509 flattens the subject into a
// pkix.Name whose CommonName field holds only the last one.
var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// Known reports whether s is a SubjectSource this package implements.
func (s SubjectSource) Known() bool {
	switch s {
	case SubjectEmailSAN, SubjectURISAN, SubjectDNSSAN, SubjectCommonName, SubjectDN:
		return true
	}
	return false
}

// String returns the wire form of s.
func (s SubjectSource) String() string { return string(s) }

// PKIOptions configures NewPKI.
type PKIOptions struct {
	// Certificate is the server's own certificate and key. Exactly one
	// of Certificate and GetCertificate is required.
	Certificate *tls.Certificate

	// GetCertificate supplies the server certificate per handshake, for
	// deployments that rotate it in place — cert-manager renewing a
	// secret, for instance. Exactly one of Certificate and
	// GetCertificate is required.
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	// ClientCAs is the pool of authorities a client certificate must
	// chain to. Required: this constructor exists to build a mutually
	// authenticated config, and a nil pool would silently produce a
	// server that authenticates nobody.
	ClientCAs *x509.CertPool

	// Subject names the certificate field the caller's identity is
	// read from. Required; see SubjectSource.
	Subject SubjectSource

	// Admit is the optional connection-admission check (Layer A),
	// applied to the verified leaf during the handshake. Nil admits
	// every peer whose chain verifies — which is a real policy, not an
	// oversight, when the pool contains only an authority that issues
	// exclusively to permitted callers.
	//
	// It runs after chain verification, so it may trust the
	// certificate's contents, and it runs on resumed connections as
	// well as fresh ones. Rejecting here fails the handshake; to
	// let a peer connect and be denied per request, leave this nil and
	// use the authz layer instead.
	Admit CertMatcher

	// MinVersion is the minimum TLS version. Zero means TLS 1.3;
	// values below TLS 1.2 are rejected.
	MinVersion uint16

	// NextProtos is the ALPN protocol list. Empty leaves crypto/tls to
	// negotiate; set it to, say, {"h2", "http/1.1"} to offer HTTP/2.
	NextProtos []string
}

// PKIAuth resolves a Caller from a client certificate verified against
// a standard CA pool.
//
// It reads VerifiedChains — the chain crypto/tls built and checked —
// and never PeerCertificates, which holds whatever the peer sent.
//
// PKIAuth is safe for concurrent use; it is immutable after NewPKI.
type PKIAuth struct {
	subject SubjectSource
}

var (
	_ authn.Authenticator  = (*PKIAuth)(nil)
	_ authn.CredentialGate = (*PKIAuth)(nil)
)

// NewPKI returns a server TLS config requiring a verified client
// certificate, and the authenticator that reads an identity from it.
//
// The two are returned together because they are one decision: the
// config's ClientAuth mode determines where the verified certificate
// can be found, and PKIAuth reads exactly that place. Mutating the
// returned config's ClientAuth or ClientCAs invalidates the pairing —
// in particular, lowering ClientAuth below RequireAndVerifyClientCert
// leaves VerifiedChains empty and every request 401s.
func NewPKI(opts PKIOptions) (*tls.Config, *PKIAuth, error) {
	switch {
	case opts.Certificate == nil && opts.GetCertificate == nil:
		return nil, nil, errors.New("purser/mtls: PKIOptions: one of Certificate or GetCertificate is required")
	case opts.Certificate != nil && opts.GetCertificate != nil:
		return nil, nil, errors.New("purser/mtls: PKIOptions: Certificate and GetCertificate are mutually exclusive")
	}
	if opts.ClientCAs == nil {
		return nil, nil, errors.New("purser/mtls: PKIOptions: ClientCAs is required; " +
			"without a pool no client certificate can be verified")
	}
	if opts.Subject == "" {
		return nil, nil, errors.New("purser/mtls: PKIOptions: Subject is required; " +
			"the field an identity is read from must be configured, not guessed")
	}
	if !opts.Subject.Known() {
		return nil, nil, fmt.Errorf("purser/mtls: PKIOptions: unknown Subject %q", opts.Subject)
	}
	minVersion, err := resolveMinVersion(opts.MinVersion)
	if err != nil {
		return nil, nil, err
	}

	cfg := &tls.Config{
		MinVersion: minVersion,
		// The whole point of the profile: crypto/tls builds and
		// verifies the client's chain, and refuses the handshake
		// outright if it does not reach the pool.
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  opts.ClientCAs,
		NextProtos: opts.NextProtos,
	}
	if opts.Certificate != nil {
		cfg.Certificates = []tls.Certificate{*opts.Certificate}
	} else {
		cfg.GetCertificate = opts.GetCertificate
	}
	if opts.Admit != nil {
		admit := opts.Admit
		// VerifyConnection, not VerifyPeerCertificate.
		//
		// The obvious hook is VerifyPeerCertificate, and it would be
		// right for every full handshake: Go calls it after its own
		// chain verification has succeeded, with verifiedChains
		// populated. But it is not called at all when a session is
		// resumed from a ticket. On resumption crypto/tls re-checks the
		// carried chain against ClientCAs and rejects an expired leaf,
		// then restores VerifiedChains and moves on — so an admission
		// matcher hung off VerifyPeerCertificate silently stops
		// applying, and a peer admitted under an older policy keeps
		// connecting for the lifetime of its ticket.
		//
		// VerifyConnection runs on both paths, on TLS 1.2 and 1.3, with
		// the same verified state, so the matcher sees every connection.
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			leaf, err := verifiedLeaf(cs.VerifiedChains)
			if err != nil {
				return err
			}
			if err := admit(leaf); err != nil {
				return fmt.Errorf("purser/mtls: peer not admitted: %w", err)
			}
			return nil
		}
	}
	return cfg, &PKIAuth{subject: opts.Subject}, nil
}

// Authenticate resolves the Caller from the verified client
// certificate on the request's connection.
func (a *PKIAuth) Authenticate(r *http.Request) (purser.Caller, error) {
	state, err := connectionState(r)
	if err != nil {
		return purser.Caller{}, err
	}
	leaf, err := verifiedLeaf(state.VerifiedChains)
	if err != nil {
		return purser.Caller{}, err
	}
	identity, err := extractSubject(a.subject, leaf)
	if err != nil {
		return purser.Caller{}, err
	}
	return purser.Caller{
		Identity: identity,
		Labels: map[string]string{
			LabelIssuerDN: leaf.Issuer.String(),
			LabelSerial:   leaf.SerialNumber.Text(16),
			LabelNotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
		},
	}, nil
}

// Source reports purser.AuthSourceMTLS. The SPIFFE profile reports
// purser.AuthSourceSPIFFE instead, so /whoami can tell an operator
// which profile admitted them.
func (a *PKIAuth) Source() purser.AuthSource { return purser.AuthSourceMTLS }

// GatesCredentials reports true: a request only reaches Authenticate
// over a connection whose client certificate crypto/tls already
// verified against the pool.
func (a *PKIAuth) GatesCredentials() bool { return true }

// verifiedLeaf returns the leaf of the first verified chain.
//
// An empty VerifiedChains is treated as no credential, never as an
// invitation to look at PeerCertificates. That fallback is the bug this
// package exists to not have: PeerCertificates holds what the peer
// sent, so reading it when verification did not happen accepts a
// self-signed certificate carrying any identity the peer chose.
func verifiedLeaf(chains [][]*x509.Certificate) (*x509.Certificate, error) {
	if len(chains) == 0 || len(chains[0]) == 0 {
		return nil, fmt.Errorf("purser/mtls: no verified client certificate chain: %w",
			purser.ErrUnauthenticated)
	}
	return chains[0][0], nil
}

// extractSubject reads the identity out of the one configured field.
//
// A field carrying more than one value is rejected rather than
// resolved by picking the first. Two email SANs are two identities, and
// which of them a request is attributed to should not depend on the
// order the CA happened to encode them in. A multi-name service
// certificate — the usual Kubernetes shape — wants SubjectURISAN or the
// SPIFFE profile, where the identity is singular by construction.
func extractSubject(src SubjectSource, cert *x509.Certificate) (string, error) {
	switch src {
	case SubjectEmailSAN:
		return exactlyOne(src, cert.EmailAddresses)
	case SubjectDNSSAN:
		return exactlyOne(src, cert.DNSNames)
	case SubjectURISAN:
		uris := make([]string, 0, len(cert.URIs))
		for _, u := range cert.URIs {
			uris = append(uris, u.String())
		}
		return exactlyOne(src, uris)
	case SubjectCommonName:
		// Subject.CommonName holds only the last CN in a subject that
		// carries several. Counting the raw attributes is what catches
		// a certificate asserting two of them.
		var cns []string
		for _, attr := range cert.Subject.Names {
			if attr.Type.Equal(oidCommonName) {
				if s, ok := attr.Value.(string); ok {
					cns = append(cns, s)
				}
			}
		}
		return exactlyOne(src, cns)
	case SubjectDN:
		dn := cert.Subject.String()
		if dn == "" {
			return "", fmt.Errorf("purser/mtls: client certificate has an empty subject, "+
				"and %s is configured: %w", src, purser.ErrUnauthenticated)
		}
		return dn, nil
	default:
		// Unreachable through NewPKI, which rejects an unknown source.
		// Reached only by a PKIAuth built by other means, and failing
		// closed is the only safe answer.
		return "", fmt.Errorf("purser/mtls: unknown subject source %q: %w", src, purser.ErrUnauthenticated)
	}
}

// exactlyOne returns the single value of a certificate field, rejecting
// both absence and ambiguity.
func exactlyOne(src SubjectSource, values []string) (string, error) {
	switch len(values) {
	case 1:
		if strings.TrimSpace(values[0]) == "" {
			return "", fmt.Errorf("purser/mtls: client certificate's %s is empty: %w",
				src, purser.ErrUnauthenticated)
		}
		return values[0], nil
	case 0:
		return "", fmt.Errorf("purser/mtls: client certificate carries no %s: %w",
			src, purser.ErrUnauthenticated)
	default:
		return "", fmt.Errorf("purser/mtls: client certificate carries %d values for %s (%s); "+
			"an identity must be unambiguous: %w",
			len(values), src, strings.Join(values, ", "), purser.ErrUnauthenticated)
	}
}
