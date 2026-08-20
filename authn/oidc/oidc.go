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

// Package oidc authenticates callers by OpenID Connect ID token.
//
// It is the human-operator path. An engineer already signs in to an
// identity provider every morning; this lets that session authenticate
// them to a service without anyone issuing, distributing, or revoking a
// client certificate for their laptop. Services keep authn/mtls.
//
// A token is accepted only when all of the following hold: it is a
// compact JWS with exactly one signature, made with an algorithm on the
// configured allowlist, by a key the issuer publishes at its JWKS
// endpoint over HTTPS; the "iss" claim matches the configured issuer
// byte for byte; the "aud" claim includes one of the configured
// audiences; and it is within its validity window given the configured
// clock leeway. Everything else — every parse failure, every missing
// claim — is purser.ErrUnauthenticated, so a surface maps the lot to
// 401.
//
// # What this package does not do
//
// It does not implement the OAuth 2.0 authorization code flow. It
// verifies a token the client already holds, which is the server half.
// Obtaining one is the client's problem: `gcloud auth print-identity-token`,
// an oauth2 library, an IdP's device flow.
//
// It never reads Caller.Admin from a claim. A token that could assert
// its own admin bit would be a privilege escalation the moment an
// operator gained write access to their own IdP profile, so the Admin
// bit is set by policy — see authz.Rules — against claims this package
// records as Labels.
//
// # Identity
//
// By default the identity is the "email" claim, falling back to "sub"
// when the token carries no email. Email is the identity an operator
// recognizes, an ACL is written in, and an audit record is legible
// with; sub is opaque but always present.
//
// That default is only safe because an unverified email is refused. An
// IdP where a user can set their own email address — most of them, for
// a self-service profile field — would otherwise let anyone mint a
// token naming somebody else's address. So an email-derived identity
// requires "email_verified" to be present and true, unless
// Options.AllowUnverifiedEmail says the deployment knows better.
//
// Identity is not qualified by issuer. One Auth trusts exactly one
// issuer, so within a surface there is no ambiguity; a deployment that
// federates two issuers and cares which one a caller came from should
// match on the oidc.issuer label rather than parsing the identity.
package oidc

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
)

// Label keys set on the Caller resolved from an ID token. Namespaced
// under "oidc." so they cannot collide with labels a deployment's own
// policy adds.
const (
	// LabelIssuer is the "iss" claim: which provider vouched for this
	// caller. Constant for a given Auth, and recorded anyway, because
	// an audit record read years later should not depend on knowing
	// how the service was configured that week.
	LabelIssuer = "oidc.issuer"
	// LabelSubject is the "sub" claim, the provider's stable opaque
	// identifier for the caller. It is recorded even when it is also
	// the identity, and it is the claim to correlate on when an
	// operator's email address changes.
	LabelSubject = "oidc.sub"
	// LabelEmail is the "email" claim, present only when the token
	// carried one. Its presence says nothing about verification: see
	// the oidc.claim/email_verified label, and note that an
	// email-derived identity is refused outright when the address is
	// unverified.
	LabelEmail = "oidc.email"
	// LabelExpiry is the "exp" claim, RFC 3339. It lets an audit
	// consumer tell a one-hour operator token from a long-lived one
	// without re-parsing the credential.
	LabelExpiry = "oidc.expires_at"

	// LabelClaimPrefix prefixes every other claim copied from the
	// token, so a policy can match on them:
	//
	//	authz.MatchLabel(oidc.LabelClaimPrefix+"hd", "example.com")
	//
	// The prefix is what keeps a provider that starts emitting a claim
	// called "issuer" from overwriting the label this package sets.
	LabelClaimPrefix = "oidc.claim/"
)

// Defaults for the corresponding Options fields.
const (
	defaultLeeway          = time.Minute
	defaultMaxTokenBytes   = 8 << 10
	defaultKeyRefresh      = 15 * time.Minute
	defaultKeyRefreshFloor = 30 * time.Second

	// maxLeeway bounds Options.Leeway. Leeway is a hole in expiry
	// enforcement, and one big enough to matter is far more often a
	// unit mix-up — seconds written where a Duration was meant — than
	// a deployment with genuinely five-minute clock drift.
	maxLeeway = 5 * time.Minute
)

// schemeBearer is the Authorization scheme, matched case-insensitively
// per RFC 7235 §2.1.
const schemeBearer = "bearer"

// permittedAlgs is every signature algorithm Options.SignatureAlgorithms
// may name. It is an allowlist rather than a denylist of the bad ones,
// so an algorithm added to go-jose in a future release cannot become
// acceptable here without somebody deciding it should be.
//
// The exclusions are the point. "none" is not a signature. The HS*
// family is symmetric: verifying with it means the verification key is
// also a signing key, which is the classic JWT confusion bug — a
// server that will accept HS256 can be handed a token signed with the
// issuer's *public* key, which is public.
var permittedAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// defaultAlgs is the allowlist applied when Options.SignatureAlgorithms
// is unset: RS256, which OpenID Connect requires every provider to
// support, and ES256, which the providers offering a choice offer.
var defaultAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

// Options configures New. Issuer and Audiences are required; the rest
// have defaults documented on each field.
type Options struct {
	// Issuer is the provider's issuer URL — "https://accounts.google.com".
	// It must be https, and it must be spelled the way the provider
	// spells it in the "iss" claim, without a trailing slash: the claim
	// is compared byte for byte, because an issuer check that
	// normalizes is an issuer check with an argument about what
	// normalization means.
	//
	// Unless JWKSURL is set, this is also where discovery happens:
	// Issuer + "/.well-known/openid-configuration".
	Issuer string

	// Audiences are the audience values this service answers to,
	// typically its OAuth client ID or its URL. A token is accepted
	// when its "aud" claim contains any of them.
	//
	// At least one is required, and this is the requirement worth
	// understanding. The audience is the only thing that distinguishes
	// a token minted for this service from one minted for any other
	// service the same provider serves: without it, a token an
	// operator handed to some unrelated site replays here.
	Audiences []string

	// JWKSURL overrides discovery with the key endpoint's URL, for a
	// provider that publishes keys without a discovery document —
	// "https://www.googleapis.com/oauth2/v3/certs" — or a deployment
	// that would rather not make the extra request. Must be https.
	JWKSURL string

	// HTTPClient fetches the discovery document and the key set.
	// Defaults to a client with sane timeouts. Supply one to pin the
	// provider's CA, to route through a proxy, or — in tests — to
	// trust an httptest server; see authtest.Issuer.
	//
	// The client's TLS is not decoration. It is what makes the fetched
	// keys the issuer's keys: nothing else in this package
	// authenticates the JWKS endpoint, so an attacker who could
	// substitute its response could sign tokens as anybody.
	//
	// The client is copied, not retained, and the copy is given a
	// redirect policy that refuses any hop to a non-https URL. A
	// CheckRedirect of the caller's own still runs after that one.
	HTTPClient *http.Client

	// IdentityClaim names the claim to use as Caller.Identity. Empty
	// means the documented default: "email" when the token carries a
	// verified one, otherwise "sub".
	//
	// Setting it pins the choice: the named claim must be present and
	// a non-empty string or the token is refused. There is no fallback
	// — a deployment that asked for one claim and silently got another
	// would have identities of two different shapes in its ACLs.
	IdentityClaim string

	// AllowUnverifiedEmail accepts an email-derived identity whose
	// "email_verified" claim is absent or false.
	//
	// Set it only for a provider that verifies addresses out of band
	// and does not bother emitting the claim — a corporate IdP whose
	// only source of addresses is the HR system. Setting it for a
	// provider with self-service profile fields means any user of that
	// provider can authenticate as any address they type.
	AllowUnverifiedEmail bool

	// SignatureAlgorithms is the "alg" allowlist. Defaults to RS256
	// and ES256. Symmetric algorithms and "none" are refused whatever
	// is listed.
	SignatureAlgorithms []string

	// Leeway absorbs clock skew between this service and the issuer,
	// applied to "exp", "nbf" and "iat". Defaults to one minute;
	// negative values and values over five minutes are refused.
	Leeway time.Duration

	// MaxTokenBytes bounds the credential this package will parse,
	// before it parses any of it. Defaults to 8 KiB, which is roughly
	// four times the largest ID token the major providers issue.
	//
	// It is a bound on work done for an unauthenticated request, and
	// on the size of the label set a token can produce.
	MaxTokenBytes int

	// KeyRefresh is how old the cached key set may be before the next
	// verification refetches it. Defaults to 15 minutes.
	//
	// This is what bounds how long a key withdrawn by the issuer keeps
	// verifying tokens here, since the demand-driven refetch below
	// only triggers on a key ID this process has never seen.
	//
	// It bounds it only while fetches succeed. When the refetch fails
	// and a matching key is already cached, the cached key is served
	// rather than the request refused, so an issuer that stays
	// unreachable keeps a withdrawn key alive for as long as the outage
	// lasts. That is the deliberate trade: the alternative is that
	// every IdP outage is also a total authentication outage.
	KeyRefresh time.Duration

	// KeyRefreshFloor is the minimum interval between fetches of the
	// key set. Defaults to 30 seconds.
	//
	// A token's key ID is read from its unverified header, so anyone
	// who can reach the surface can name a key ID that is not cached.
	// Without a floor, each such request becomes a fetch against the
	// issuer, and an unauthenticated client turns this service into an
	// amplifier pointed at its own IdP. With one, a rotation the
	// service has not yet seen costs its callers at most this long.
	KeyRefreshFloor time.Duration

	// ProxyIdentities names the identities permitted to assert other
	// identities via authn.HeaderAssertedCaller — a bot that
	// authenticates as itself and acts for a human, so audit records
	// name the human.
	//
	// This authenticator has no table of provisioned identities, so an
	// asserted identity is taken at face value: anyone on this list
	// can act as anyone at all. The list is the whole control. Prefer
	// granting it through authz rules, which can require more of the
	// caller than its name.
	ProxyIdentities []string
}

// Auth authenticates requests carrying an OIDC ID token.
//
// It is safe for concurrent use. Its only mutable state is the cached
// key set, which is refreshed under a lock and never handed out.
type Auth struct {
	issuer               string
	audiences            []string
	identityClaim        string
	allowUnverifiedEmail bool
	algs                 []jose.SignatureAlgorithm
	leeway               time.Duration
	maxTokenBytes        int
	proxy                map[string]struct{}
	keys                 *keySet

	// now is time.Now, replaced in tests. Every expiry decision reads
	// it, so a test can mint a token at a fixed instant and assert the
	// edge of the window rather than sleeping up to it.
	now func() time.Time
}

var (
	_ authn.Authenticator          = (*Auth)(nil)
	_ authn.AuthenticatorWithProxy = (*Auth)(nil)
	_ authn.CredentialGate         = (*Auth)(nil)
)

// Auth deliberately does not implement authn.IdentityLookup: there is
// no table of provisioned identities behind a claim-based
// authenticator, and implementing it with anything other than a real
// table would either invent Callers or reject every assertion.

// New validates opts and returns an authenticator.
//
// No network request is made here. Discovery and the first key fetch
// happen on the first request that presents a token, so a service does
// not fail to start because its IdP is briefly unreachable — and, more
// to the point, does not come up with an authenticator that silently
// rejects everything because the fetch at construction failed.
func New(opts Options) (*Auth, error) {
	issuer, err := validateIssuer(opts.Issuer)
	if err != nil {
		return nil, err
	}
	audiences, err := validateAudiences(opts.Audiences)
	if err != nil {
		return nil, err
	}
	algs, err := validateAlgorithms(opts.SignatureAlgorithms)
	if err != nil {
		return nil, err
	}
	jwksURL, err := validateJWKSURL(opts.JWKSURL)
	if err != nil {
		return nil, err
	}
	leeway, err := validateLeeway(opts.Leeway)
	if err != nil {
		return nil, err
	}
	maxTokenBytes, err := positiveOrDefault("MaxTokenBytes", int64(opts.MaxTokenBytes), defaultMaxTokenBytes)
	if err != nil {
		return nil, err
	}
	refresh, err := positiveOrDefault("KeyRefresh", int64(opts.KeyRefresh), int64(defaultKeyRefresh))
	if err != nil {
		return nil, err
	}
	floor, err := positiveOrDefault("KeyRefreshFloor", int64(opts.KeyRefreshFloor), int64(defaultKeyRefreshFloor))
	if err != nil {
		return nil, err
	}

	return &Auth{
		issuer:               issuer,
		audiences:            audiences,
		identityClaim:        opts.IdentityClaim,
		allowUnverifiedEmail: opts.AllowUnverifiedEmail,
		algs:                 algs,
		leeway:               leeway,
		maxTokenBytes:        int(maxTokenBytes),
		proxy:                stringSet(opts.ProxyIdentities),
		keys: newKeySet(keySetOptions{
			Issuer:       issuer,
			JWKSURL:      jwksURL,
			HTTPClient:   opts.HTTPClient,
			Refresh:      time.Duration(refresh),
			RefreshFloor: time.Duration(floor),
		}),
		now: time.Now,
	}, nil
}

// Authenticate verifies the request's ID token and resolves it to a
// Caller.
//
// Every failure is purser.ErrUnauthenticated with a message naming what
// was wrong. The message is for the server's log: an HTTP surface
// returns 401 and the sentinel, not the reason, because "wrong
// audience" and "expired" are useful to someone probing what this
// service accepts and useless to a client that must obtain a fresh
// token either way.
func (a *Auth) Authenticate(r *http.Request) (purser.Caller, error) {
	raw := extractToken(r)
	if raw == "" {
		return purser.Caller{}, fmt.Errorf("purser/oidc: no token presented: %w", purser.ErrUnauthenticated)
	}
	if len(raw) > a.maxTokenBytes {
		// Checked before parsing: this is the one bound that applies to
		// work done on behalf of a request that has proved nothing.
		return purser.Caller{}, fmt.Errorf("purser/oidc: token is %d bytes, over the %d-byte limit: %w",
			len(raw), a.maxTokenBytes, purser.ErrUnauthenticated)
	}

	payload, err := a.verifySignature(r, raw)
	if err != nil {
		return purser.Caller{}, err
	}
	return a.callerFromPayload(payload)
}

// verifySignature parses the compact JWS and verifies it against the
// issuer's published keys, returning the signed payload.
func (a *Auth) verifySignature(r *http.Request, raw string) ([]byte, error) {
	// ParseSignedCompact, not ParseSigned: the latter also accepts the
	// JWS JSON serialization, which can carry several signatures and
	// per-signature headers. An ID token is always compact, so
	// accepting the other form only widens what an attacker may hand
	// us.
	jws, err := jose.ParseSignedCompact(raw, a.algs)
	if err != nil {
		return nil, fmt.Errorf("purser/oidc: malformed token: %v: %w", err, purser.ErrUnauthenticated)
	}
	if len(jws.Signatures) != 1 {
		// Unreachable through the compact serialization, which has room
		// for exactly one. Asserted rather than assumed, because "the
		// first signature verified" is the shape of several real CVEs.
		return nil, fmt.Errorf("purser/oidc: token carries %d signatures, want exactly 1: %w",
			len(jws.Signatures), purser.ErrUnauthenticated)
	}
	sig := jws.Signatures[0]

	keys, err := a.keys.keysFor(r.Context(), sig.Header.KeyID, sig.Header.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("purser/oidc: %v: %w", err, purser.ErrUnauthenticated)
	}
	for i := range keys {
		if payload, err := jws.Verify(keys[i].Key); err == nil {
			return payload, nil
		}
	}
	// Which key was tried is not said: the caller learns only that this
	// signature is not one of the issuer's.
	return nil, fmt.Errorf("purser/oidc: signature does not verify against the issuer's keys: %w",
		purser.ErrUnauthenticated)
}

// Source reports purser.AuthSourceOIDC.
func (a *Auth) Source() purser.AuthSource { return purser.AuthSourceOIDC }

// GatesCredentials reports true: every request Authenticate admits
// presented a token this authenticator verified against the issuer's
// keys.
func (a *Auth) GatesCredentials() bool { return true }

// CanProxyAs reports whether c may assert other identities. False for
// the zero Caller and for any identity absent from
// Options.ProxyIdentities.
func (a *Auth) CanProxyAs(c purser.Caller) bool {
	if c.IsZero() {
		return false
	}
	_, ok := a.proxy[c.Identity]
	return ok
}

// Issuer returns the issuer this authenticator trusts. Useful to a
// surface logging its configuration, and to a test asserting which of
// several authenticators it holds.
func (a *Auth) Issuer() string { return a.issuer }

// extractToken returns the token presented on r, preferring the
// side-channel header over Authorization for the same reason
// authn/bearer does: a deployment behind an identity gateway may not
// own the Authorization header. Returns "" when neither carries one.
func extractToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	if side := strings.TrimSpace(r.Header.Get(authn.HeaderAttachToken)); side != "" {
		return side
	}
	scheme, rest, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, schemeBearer) {
		return ""
	}
	return strings.TrimSpace(rest)
}

func validateIssuer(issuer string) (string, error) {
	if issuer == "" {
		return "", fmt.Errorf("purser/oidc: Issuer is required")
	}
	if strings.HasSuffix(issuer, "/") {
		return "", fmt.Errorf("purser/oidc: Issuer %q has a trailing slash: spell it exactly as the "+
			"provider spells it in the \"iss\" claim, which the token is compared against byte for byte", issuer)
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("purser/oidc: Issuer %q is not a URL: %w", issuer, err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("purser/oidc: Issuer %q is not https: the transport is what authenticates "+
			"the published keys, and an attacker who can rewrite them can sign tokens as anybody", issuer)
	}
	if u.Host == "" {
		return "", fmt.Errorf("purser/oidc: Issuer %q has no host", issuer)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("purser/oidc: Issuer %q carries a query or fragment", issuer)
	}
	return issuer, nil
}

func validateAudiences(audiences []string) ([]string, error) {
	if len(audiences) == 0 {
		return nil, fmt.Errorf("purser/oidc: Audiences is empty: without an audience check, a token " +
			"minted for any other service of the same issuer is accepted here")
	}
	out := make([]string, 0, len(audiences))
	for _, aud := range audiences {
		if aud == "" {
			return nil, fmt.Errorf("purser/oidc: Audiences contains an empty string: a configuration " +
				"value that never got set must not become an audience the service answers to")
		}
		if !slices.Contains(out, aud) {
			out = append(out, aud)
		}
	}
	return out, nil
}

func validateAlgorithms(algs []string) ([]jose.SignatureAlgorithm, error) {
	if len(algs) == 0 {
		return slices.Clone(defaultAlgs), nil
	}
	out := make([]jose.SignatureAlgorithm, 0, len(algs))
	for _, alg := range algs {
		a := jose.SignatureAlgorithm(alg)
		if !slices.Contains(permittedAlgs, a) {
			return nil, fmt.Errorf("purser/oidc: SignatureAlgorithms contains %q, which is not one of %v; "+
				"symmetric algorithms and \"none\" are refused because a verifier that accepts one can be "+
				"handed a token signed with the issuer's public key", alg, permittedAlgs)
		}
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out, nil
}

func validateJWKSURL(jwksURL string) (string, error) {
	if jwksURL == "" {
		return "", nil
	}
	u, err := url.Parse(jwksURL)
	if err != nil {
		return "", fmt.Errorf("purser/oidc: JWKSURL %q is not a URL: %w", jwksURL, err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("purser/oidc: JWKSURL %q is not https", jwksURL)
	}
	if u.Host == "" {
		return "", fmt.Errorf("purser/oidc: JWKSURL %q has no host", jwksURL)
	}
	return jwksURL, nil
}

func validateLeeway(leeway time.Duration) (time.Duration, error) {
	switch {
	case leeway < 0:
		return 0, fmt.Errorf("purser/oidc: Leeway is negative (%s)", leeway)
	case leeway == 0:
		return defaultLeeway, nil
	case leeway > maxLeeway:
		return 0, fmt.Errorf("purser/oidc: Leeway is %s, over the %s limit: leeway is a hole in expiry "+
			"enforcement, and one this size is more often a unit mistake than a deployment with that "+
			"much clock drift", leeway, maxLeeway)
	}
	return leeway, nil
}

// positiveOrDefault applies the zero-means-default convention to a
// field that must not be negative.
func positiveOrDefault(name string, v, def int64) (int64, error) {
	if v < 0 {
		return 0, fmt.Errorf("purser/oidc: %s is negative", name)
	}
	if v == 0 {
		return def, nil
	}
	return v, nil
}

func stringSet(xs []string) map[string]struct{} {
	out := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		// A configuration value that never got set must not become an
		// identity permitted to proxy. Belt and braces today: CanProxyAs
		// refuses the zero Caller first, and purser.Caller.IsZero is
		// defined as an empty Identity, so nothing can currently reach
		// the lookup with "". This does not depend on that staying true.
		if x == "" {
			continue
		}
		out[x] = struct{}{}
	}
	return out
}
