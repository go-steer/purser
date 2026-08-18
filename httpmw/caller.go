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

package httpmw

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
)

// CallerOptions configures NewCaller.
type CallerOptions struct {
	// Authenticator resolves the inbound credential to a Caller.
	//
	// Nil means authn.Anonymous carrying Fallback: every request
	// resolves to the same unverified identity. That is a legitimate
	// posture for a surface that has not enabled per-caller identity,
	// and it is why the middleware can promise that a Caller is always
	// on the context.
	Authenticator authn.Authenticator

	// Fallback is the Caller a request falls back to when the
	// authenticator reports purser.ErrUnauthenticated and Enforce is
	// false. A zero Fallback means purser.Anonymous().
	//
	// It is refused alongside Enforce, which has no fallback path.
	Fallback purser.Caller

	// Enforce turns a failed authentication into 401 instead of a
	// downgrade to Fallback. This is the posture for a surface that
	// requires a credential; leaving it false is the posture for one
	// that permits anonymous access.
	//
	// It is also what CallerMiddleware.GatesCredentials reports, and so
	// what CheckBind reads when deciding whether this surface is safe
	// to expose on the network.
	Enforce bool

	// ProxyHeader names the header a proxy-permitted Caller uses to
	// assert an effective identity. Empty means
	// authn.HeaderAssertedCaller.
	//
	// The header is consulted on every request regardless of this
	// setting's origin, because a request that carries it and is not
	// entitled to must be refused rather than ignored.
	ProxyHeader string

	// Logger receives the rejected-assertion audit line. Nil means
	// slog.Default().
	Logger *slog.Logger
}

// CallerMiddleware resolves each request's Caller and attaches it, the
// proxying identity, and the auth-source verdict to the request context
// for handlers to read with purser.CallerFromContext,
// purser.ProxyByFromContext and purser.AuthSourceFromContext.
//
// It is a named type rather than a bare Middleware because it is also
// the answer to CheckBind's question: whether a request can reach the
// handler without a verified credential is this middleware's decision
// (CallerOptions.Enforce), not the authenticator's. See GatesCredentials.
//
// It is safe for concurrent use; it is immutable after NewCaller.
type CallerMiddleware struct {
	authenticator authn.Authenticator
	fallback      purser.Caller
	enforce       bool
	proxyHeader   string
	log           *slog.Logger
}

var _ Gate = (*CallerMiddleware)(nil)

// NewCaller builds the caller middleware from opts.
//
// Behavior:
//
//   - The authenticator succeeds: its Caller goes on the context and
//     its Source() is the verdict.
//   - The authenticator returns an error and Enforce is false: Fallback
//     goes on the context. The verdict is anonymous unless an outer
//     middleware already stamped a non-anonymous one, in which case
//     that stands — see below. purser.ErrUnauthenticated and every
//     other error are treated alike, because an authenticator must not
//     return an identity alongside an error, so there is nothing to
//     fall back to either way.
//   - The authenticator returns any error and Enforce is true: 401,
//     and the handler does not run.
//   - The request carries the proxy header: 401 unless the request
//     authenticated, the authenticator implements
//     authn.AuthenticatorWithProxy, it permits this caller to proxy,
//     and (where it implements authn.IdentityLookup) it has the
//     asserted identity provisioned. A bad assertion is a security
//     event, not a fall-back-to-the-underlying-identity case: silently
//     ignoring it would let a compromised proxy credential look like a
//     working one while an operator's allowlist change had no effect.
//
// The proxy path requires a *successful* authentication and not merely
// a Caller, which is the one precondition the underlying interface
// cannot enforce on its own. authn.AuthenticatorWithProxy asks
// implementations to return false from CanProxyAs for the zero Caller,
// but on the fallback path there is no zero Caller to catch: the
// fallback is a configured identity, or purser.Anonymous(), and an
// implementation reading only its argument would see a perfectly
// ordinary Caller. Deciding it here means a request that presented no
// valid credential can never assert one, whatever any authenticator
// does.
//
// # The auth-source verdict
//
// The verdict comes from the authenticator's Source(), never from
// inspecting the request or the TLS state. Middleware that infers
// "mtls" from a populated tls.ConnectionState.VerifiedChains is correct
// only for the PKI profile: a SPIFFE listener leaves VerifiedChains
// empty on a perfectly good connection, so the same check silently
// reports anonymous for a caller whose SVID was verified. Asking the
// authenticator is the fix, and it is why Source() is on the base
// interface rather than a type switch here.
//
// One thing is inherited rather than derived. Where this middleware
// would otherwise report anonymous — the authenticator verifies
// nothing, or verified nothing on this request — and an outer
// middleware already stamped a non-anonymous verdict, the outer verdict
// stands. A TokenGate that validated the shared transport token is the
// case to picture: the request did not get in anonymously, and
// reporting that it did would be the lie. The identity is still the
// fallback's, because a shared token names nobody. This is inheritance
// from code that did the work, not inference from a header.
//
// A validated proxy assertion outranks both: the asserted path is what
// an audit record should show, with the proxying credential kept
// alongside it under purser.WithProxyBy.
func NewCaller(opts CallerOptions) (*CallerMiddleware, error) {
	a := opts.Authenticator
	if a == nil {
		a = authn.Anonymous{Caller: opts.Fallback}
	}

	if opts.Enforce {
		// Each of these is a configuration that reads as "require a
		// credential" and behaves as "do not". Refusing at
		// construction is the only place the contradiction is
		// visible; at runtime it looks exactly like a working
		// enforced surface — and GatesCredentials would report it to
		// CheckBind as one.
		if opts.Authenticator == nil {
			return nil, errors.New("httpmw: NewCaller: Enforce with no Authenticator: the anonymous default authenticates every request, so nothing would ever be enforced")
		}
		if !opts.Fallback.IsZero() {
			return nil, fmt.Errorf("httpmw: NewCaller: Enforce with a Fallback (%q) is contradictory: enforcement has no fallback path", opts.Fallback.Identity)
		}
		if gate, ok := a.(authn.CredentialGate); ok && !gate.GatesCredentials() {
			return nil, fmt.Errorf("httpmw: NewCaller: Enforce with an authenticator that reports GatesCredentials() == false (%T): it admits unverified requests, so no request would ever be rejected", a)
		}
	}

	m := &CallerMiddleware{
		authenticator: a,
		fallback:      opts.Fallback,
		enforce:       opts.Enforce,
		proxyHeader:   opts.ProxyHeader,
		log:           opts.Logger,
	}
	if m.fallback.IsZero() {
		m.fallback = purser.Anonymous()
	}
	if m.proxyHeader == "" {
		m.proxyHeader = authn.HeaderAssertedCaller
	}
	if m.log == nil {
		m.log = slog.Default()
	}
	return m, nil
}

// GatesCredentials reports whether every request that reaches the
// handler presented a credential the authenticator verified — which is
// to say, whether CallerOptions.Enforce was set.
//
// It is deliberately the middleware's answer and not the
// authenticator's. authn.CredentialGate describes what an authenticator
// does with a request it is handed; whether a request that fails it
// still reaches the handler is settled here. A bearer table reports
// GatesCredentials() == true and is telling the truth about itself, yet
// the surface in front of it admits every anonymous request unless
// Enforce is set — so it is this method, not that one, that CheckBind
// has to be given.
func (m *CallerMiddleware) GatesCredentials() bool { return m != nil && m.enforce }

// Middleware returns the resolver as a Middleware. It belongs innermost
// in the chain, closest to the handler that reads the Caller off the
// context.
func (m *CallerMiddleware) Middleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, source, authenticated, ok := m.resolve(w, r)
			if !ok {
				return
			}

			var proxyBy string
			// Presence is tested on the raw header and the value used
			// trimmed: a header that is present but blank asserts
			// nothing, and must not read as "no assertion was made".
			if raw := r.Header.Get(m.proxyHeader); raw != "" {
				effective, by, err := m.resolveProxyAssertion(c, authenticated, strings.TrimSpace(raw))
				if err != nil {
					// Logged with the *requesting* identity so an
					// operator can correlate the attempt with a
					// credential; the asserted value is attacker-
					// controlled and goes in as a quoted attribute.
					m.log.WarnContext(r.Context(), "purser: proxy assertion rejected",
						"requester", c.Identity, "authenticated", authenticated,
						"asserted", raw, "err", err)
					writeUnauthorized(w, err)
					return
				}
				c, proxyBy, source = effective, by, purser.AuthSourceAsserted
			}

			ctx := purser.WithCaller(r.Context(), c)
			if proxyBy != "" {
				ctx = purser.WithProxyBy(ctx, proxyBy)
			}
			ctx = purser.WithAuthSource(ctx, source)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// resolve runs the authenticator and settles the Caller and the
// auth-source verdict. authenticated reports whether a credential was
// actually verified, as distinct from a Caller having been produced.
// ok is false when a 401 has already been written and the request must
// not proceed.
func (m *CallerMiddleware) resolve(w http.ResponseWriter, r *http.Request) (purser.Caller, purser.AuthSource, bool, bool) {
	c, err := m.authenticator.Authenticate(r)
	if err != nil {
		if m.enforce {
			writeUnauthorized(w, err)
			return purser.Caller{}, "", false, false
		}
		// Cloned per request: the fallback is one value held by this
		// middleware, so handing out its Labels map would let one
		// request's mutation rewrite what every later unauthenticated
		// request sees.
		return m.fallback.Clone(), inherited(r, purser.AuthSourceAnonymous), false, true
	}
	// A successful Authenticate from an authenticator that verifies
	// nothing is not an authentication. authn.Anonymous is the case in
	// point: it never errors, and every request it admits presented no
	// credential at all.
	authenticated := m.authenticator.Source() != purser.AuthSourceAnonymous
	return c, inherited(r, m.authenticator.Source()), authenticated, true
}

// inherited returns source, or the verdict an outer middleware already
// stamped when source is anonymous. See NewCaller.
func inherited(r *http.Request, source purser.AuthSource) purser.AuthSource {
	if source != purser.AuthSourceAnonymous {
		return source
	}
	if prior, ok := purser.AuthSourceFromContext(r.Context()); ok && prior != purser.AuthSourceAnonymous {
		return prior
	}
	return source
}

// resolveProxyAssertion validates that requester may assert asserted,
// and returns the effective Caller plus the proxying identity.
//
// Every precondition failure is an error rather than a downgrade:
// purser.ErrAssertedCallerForbidden when the request did not
// authenticate, the authenticator cannot proxy at all, or this caller
// is not permitted to; purser.ErrAssertedCallerUnknown when the
// asserted identity is blank or not provisioned.
func (m *CallerMiddleware) resolveProxyAssertion(requester purser.Caller, authenticated bool, asserted string) (purser.Caller, string, error) {
	if !authenticated {
		// The requester is the fallback, not a verified caller. No
		// allowlist can make an unauthenticated request entitled to
		// speak for someone else, and an authenticator asked to judge
		// this would be handed an ordinary-looking Caller with no way
		// to tell.
		return purser.Caller{}, "", purser.ErrAssertedCallerForbidden
	}
	proxy, ok := m.authenticator.(authn.AuthenticatorWithProxy)
	if !ok {
		// The authenticator has no proxy capability, so the header
		// cannot have been meant for it. Treated as forbidden rather
		// than dropped: an operator who set the header on a client
		// and saw it quietly ignored would conclude proxying worked.
		return purser.Caller{}, "", purser.ErrAssertedCallerForbidden
	}
	if !proxy.CanProxyAs(requester) {
		return purser.Caller{}, "", purser.ErrAssertedCallerForbidden
	}
	if asserted == "" {
		// A blank assertion, which authn.IdentityLookup already
		// requires its implementations to refuse. Checked here so a
		// claim-based authenticator with no table refuses it too,
		// rather than minting a Caller whose Identity is whitespace
		// and whose IsZero is therefore false.
		return purser.Caller{}, "", purser.ErrAssertedCallerUnknown
	}
	// Materialize the asserted Caller from the authenticator's table
	// so downstream code sees the Labels and Admin bit a direct
	// authentication would have produced. An authenticator with no
	// table — a claim-based one, where there is nothing to look an
	// identity up in — yields a Caller carrying just the asserted
	// name; for those the proxy allowlist is the whole control, which
	// authn.IdentityLookup documents.
	if lookup, ok := m.authenticator.(authn.IdentityLookup); ok {
		c, found := lookup.LookupIdentity(asserted)
		if !found {
			return purser.Caller{}, "", purser.ErrAssertedCallerUnknown
		}
		// Cloned even though the contract asks implementations to do
		// it themselves: this middleware hands the result straight to
		// a handler, and the cost of one implementation getting it
		// wrong is a request's mutation rewriting a provisioned
		// identity for every request after it.
		return c.Clone(), requester.Identity, nil
	}
	return purser.Caller{Identity: asserted}, requester.Identity, nil
}

// writeUnauthorized writes a 401 whose body names the category of
// failure without the detail.
//
// The distinction matters to an operator reading logs and to a client
// deciding whether to retry, and the three categories are already
// distinguishable from the outside by whether the request carried the
// asserted-caller header. What stays out is anything the authenticator
// said about *why* a credential failed — that is the operator's, and
// it is on the log line.
func writeUnauthorized(w http.ResponseWriter, err error) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="purser"`)
	msg := "unauthorized"
	switch {
	case errors.Is(err, purser.ErrAssertedCallerForbidden):
		msg = "unauthorized: caller is not permitted to assert identities"
	case errors.Is(err, purser.ErrAssertedCallerUnknown):
		msg = "unauthorized: asserted identity is not provisioned"
	case errors.Is(err, purser.ErrUnauthenticated):
		msg = "unauthorized: no valid credential"
	}
	http.Error(w, msg, http.StatusUnauthorized)
}
