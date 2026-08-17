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

package purser

import "context"

// AuthSource names the class of credential a server actually verified
// for a request. It answers an operator's "how did this request get
// in?" — which is a different question from "who is this?" (Caller)
// and from "may they do this?" (authorization).
//
// The critical property: an AuthSource is stamped by the code that
// performed the verification, and is never re-derived from request
// headers. A value inferred from a header is a value any client can
// forge, and a forgeable "how did they authenticate" field is worse
// than no field at all, because it is trusted.
//
// The string values are wire-visible (they surface on core-agent's
// /whoami) and are part of the compatibility contract.
type AuthSource string

const (
	// AuthSourceAnonymous — the server verified no credential and the
	// surface allowed the request through. This also covers requests
	// that carried credential-looking headers the server had no
	// validator for: presenting a credential nobody checked is
	// indistinguishable from presenting none.
	AuthSourceAnonymous AuthSource = "anonymous"

	// AuthSourceBearer — the server validated a bearer token, either
	// against the static table or at a transport-level bearer gate.
	// The mere presence of an Authorization header does not produce
	// this value.
	AuthSourceBearer AuthSource = "bearer"

	// AuthSourceMTLS — the server's own TLS stack verified the peer's
	// certificate chain against the configured CA pool (the PKI
	// profile: ClientAuth = RequireAndVerifyClientCert), and the
	// identity was read from the configured subject field. A merely
	// presented-but-unverified certificate never produces this value.
	AuthSourceMTLS AuthSource = "mtls"

	// AuthSourceSPIFFE — the peer presented an X.509-SVID that
	// verified against the SPIFFE trust bundle, and the identity is
	// the SVID's URI SAN.
	//
	// Distinct from AuthSourceMTLS on purpose. Both are mutual TLS,
	// but they verify by opposite means and can be configured
	// independently, so collapsing them would leave an operator unable
	// to tell which listener profile admitted a caller.
	AuthSourceSPIFFE AuthSource = "spiffe"

	// AuthSourceOIDC — the server validated a signed OIDC/JWT token
	// against the issuer's published keys, including audience and
	// expiry.
	AuthSourceOIDC AuthSource = "oidc"

	// AuthSourceAsserted — a proxy-permitted credential asserted
	// another identity and the server validated the assertion. The
	// asserted path is the audit-relevant source and outranks the
	// underlying credential's own class; the proxying identity is
	// recorded separately (see WithProxyBy).
	AuthSourceAsserted AuthSource = "asserted"

	// AuthSourceIAP — reserved for a verified identity-gateway
	// assertion (Google IAP, Cloudflare Access, a service-mesh
	// sidecar). Not emitted yet: it may only be stamped once the
	// server validates a gateway's signed assertion, never inferred
	// from the gateway's plaintext headers, which any client that can
	// reach the port may set.
	AuthSourceIAP AuthSource = "iap"
)

// String implements fmt.Stringer.
func (s AuthSource) String() string { return string(s) }

// Known reports whether s is one of the sources purser defines.
//
// Authenticators live outside this package, including in consuming
// repos, so an unknown source is a real possibility rather than an
// impossible state; it means some authenticator invented a value the
// rest of the stack cannot interpret. The conformance suite rejects it.
func (s AuthSource) Known() bool {
	switch s {
	case AuthSourceAnonymous, AuthSourceBearer, AuthSourceMTLS,
		AuthSourceSPIFFE, AuthSourceOIDC, AuthSourceAsserted, AuthSourceIAP:
		return true
	default:
		return false
	}
}

type authSourceKey struct{}

// WithAuthSource returns a copy of ctx carrying the verdict on how the
// request was authenticated. Only code that performed or directly
// observed the verification may call this.
func WithAuthSource(ctx context.Context, s AuthSource) context.Context {
	return context.WithValue(ctx, authSourceKey{}, s)
}

// AuthSourceFromContext returns the verdict stored on ctx by
// WithAuthSource. ok is false when no authentication middleware ran;
// treat absence as AuthSourceAnonymous, since nothing was verified.
func AuthSourceFromContext(ctx context.Context) (s AuthSource, ok bool) {
	s, ok = ctx.Value(authSourceKey{}).(AuthSource)
	return s, ok
}
