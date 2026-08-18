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

// Package authn defines the contract every purser authenticator
// implements: turn an inbound HTTP request into a purser.Caller, or
// report that no valid credential was present.
//
// The package itself is stdlib-only. Concrete authenticators live in
// subpackages so a consumer links only what it uses — a client that
// dials with a bearer token does not pull in a JWKS cache, and a PKI
// mTLS server does not pull in go-spiffe.
//
// Implementations must pass authtest.RunAuthenticatorSuite. The
// interface below states the contract; the suite is what enforces it.
package authn

import (
	"net/http"

	"github.com/go-steer/purser"
)

// Authenticator extracts a Caller from an inbound HTTP request.
//
// Authenticate returns purser.ErrUnauthenticated when the request
// carries no valid credential. Contract for implementations:
//
//   - A nil error means the credential was verified. Returning a
//     zero-identity Caller with a nil error is a bug: downstream code
//     reads a non-error result as proof of identity.
//   - Any error means no identity. Never return a partially populated
//     Caller alongside an error; a consumer that ignores the error
//     would then act on an unverified identity.
//   - A malformed credential is an error, not a panic. Inbound bytes
//     are attacker-controlled.
//   - Labels on the returned Caller must not alias state the
//     authenticator retains. Return purser.Caller.Clone when resolving
//     from a table.
//
// Source reports the credential class this authenticator verifies. It
// is a method rather than a type switch at the middleware so that
// adding an authenticator cannot silently mis-report how a request was
// authenticated — the new type would otherwise fall into whatever the
// switch's default arm happened to be. It must return the same value
// for the lifetime of the authenticator.
type Authenticator interface {
	Authenticate(r *http.Request) (purser.Caller, error)
	Source() purser.AuthSource
}

// AuthenticatorWithProxy is the optional extension implemented by
// authenticators that support the proxy pattern: a Caller permitted to
// act on behalf of other Callers via the asserted-caller header.
//
// The motivating case is a chat bot. It authenticates as itself, then
// asserts the human's identity per request, so audit records and
// per-caller credentials attribute to the human rather than to the
// bot.
//
// Authenticators that do not implement this interface deny every proxy
// assertion. That is the safe default and it is implicit: forgetting
// to implement the interface cannot accidentally permit proxying.
type AuthenticatorWithProxy interface {
	Authenticator

	// CanProxyAs reports whether c may assert other identities. It
	// must return false for the zero Caller — an unauthenticated
	// request must never reach the proxy path.
	CanProxyAs(c purser.Caller) bool
}

// IdentityLookup is the optional extension implemented by
// authenticators backed by a table of provisioned identities. The
// proxy path uses it to materialize the asserted Caller with the
// Labels and Admin flag a direct authentication would have produced,
// and to reject assertions of identities nobody provisioned
// (purser.ErrAssertedCallerUnknown).
//
// Claim-based authenticators (OIDC) have no such table and do not
// implement it; for them an asserted identity can only be taken at
// face value, which is why the proxy allowlist is the real control.
type IdentityLookup interface {
	// LookupIdentity returns the Caller provisioned under identity.
	// ok is false when the identity is not provisioned, and must be
	// false for the empty string.
	//
	// As with Authenticate, the returned Caller's Labels must not
	// alias state the authenticator retains — return
	// purser.Caller.Clone. The result is handed to a handler, and a
	// handler that adds a label to what it believes is its own copy
	// would otherwise rewrite the provisioned identity for every later
	// request.
	LookupIdentity(identity string) (purser.Caller, bool)
}

// CredentialGate is the optional extension by which an authenticator
// declares that it admits no unverified request: every request that
// reaches it has already presented a credential this authenticator
// checked.
//
// It exists so that a surface deciding whether it is safe to bind a
// non-loopback address can ask the authenticator instead of inspecting
// configuration fields. Inspecting fields is how core-agent's
// listenerAuthenticated ended up gating on a CA file path, which is
// absent under SPIFFE — a working mTLS listener that the check would
// refuse as unauthenticated. An authenticator knows what it enforces;
// a config field only knows how it was spelled.
//
// It answers for the authenticator and not for the surface. Whether a
// request this authenticator rejects still reaches the handler is the
// middleware's decision — httpmw.CallerOptions.Enforce — so a bind
// policy asks the middleware, which reports this only when it is
// actually enforcing. See httpmw.CallerMiddleware.GatesCredentials.
// The distinction does not arise for a profile enforced at the
// transport, where the handshake has already refused the connection.
//
// Authenticators that do not implement this interface are treated as
// not gating credentials, which is the conservative reading.
type CredentialGate interface {
	Authenticator

	// GatesCredentials reports whether every admitted request
	// presented a credential this authenticator verified. An
	// authenticator that falls back to an anonymous identity must
	// return false.
	GatesCredentials() bool
}

// HeaderAssertedCaller is the conventional header a proxy-permitted
// Caller uses to assert the effective identity. Surfaces may make the
// name configurable; this is the default.
const HeaderAssertedCaller = "X-Asserted-Caller"

// HeaderAttachToken is the conventional side-channel header a token
// may be presented in, checked before Authorization. It exists for
// deployments where an identity gateway — Cloud Run IAM, IAP,
// Cloudflare Access — owns the Authorization header for its own
// validation and the service still needs a channel of its own.
//
// It lives here, in the package neither the token table nor the
// middleware can avoid importing, so that authn/bearer and httpmw
// cannot drift onto two different spellings of the same header.
const HeaderAttachToken = "X-Attach-Token" //nolint:gosec // G101: a header name, not a credential
