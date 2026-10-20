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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
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
	// authenticator returns any error and Enforce is false. A zero
	// Fallback means purser.Anonymous().
	//
	// It is refused alongside Enforce, which has no fallback path.
	Fallback purser.Caller

	// Enforce turns a failed authentication into an error response
	// instead of a downgrade to Fallback: 401 when the authenticator
	// rejected the credential, 503 when it could not reach a verdict.
	// This is the posture for a surface that requires a credential;
	// leaving it false is the posture for one that permits anonymous
	// access.
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

	// Logger receives the rejected-assertion audit line, a Warn for
	// every request whose authenticator could not reach a verdict, and
	// a Debug for every 401 naming the authenticator's reason. The
	// request's own credential is removed from that reason before it is
	// logged, as a backstop for an authenticator that quotes it; see
	// scrubbed for what that does and does not catch. Nil means
	// slog.Default().
	Logger *slog.Logger

	// Challenge is the WWW-Authenticate value sent with every 401 this
	// middleware writes. Empty means `Bearer realm="purser"`.
	//
	// It exists for protected resources whose clients discover how to
	// authenticate from the challenge: an MCP server names its RFC 9728
	// metadata document there (`Bearer resource_metadata="https://…"`),
	// and an MCP client that cannot find it cannot sign in. The value is
	// sent verbatim. NewCaller refuses one that is not a valid header
	// field value (RFC 9110 §5.5: no control bytes other than tab),
	// because net/http would not refuse it either: HTTP/1 turns CR and
	// LF into spaces, and the HTTP/2 server drops the header outright,
	// so the client would get a 401 with no challenge at all.
	Challenge string
}

// defaultChallenge is the WWW-Authenticate value when
// CallerOptions.Challenge is empty.
const defaultChallenge = `Bearer realm="purser"`

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
	challenge     string
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
//   - The authenticator returns purser.ErrUnauthenticated and Enforce
//     is true: 401 with the configured challenge, and the handler does
//     not run.
//   - The authenticator returns any other error and Enforce is true:
//     503 with Retry-After and no challenge, and the handler does not
//     run. See "401 or 503" below.
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
//
// # 401 or 503
//
// purser.ErrUnauthenticated is the only error that is a verdict on the
// credential, and the only one that earns a 401. Anything else means
// the authenticator could not decide — its issuer's keys would not
// load, the endpoint it asks did not answer — and is a 503. The
// difference is what the client does next: a 401 tells it to discard
// its credential and sign in again, which during an outage on this side
// sends every user back through sign-in at once for a credential that
// was fine. purser.ErrUnavailable is how an authenticator says so on
// purpose, and it takes precedence when an error matches both; an error
// matching neither is treated the same way, since it is not a verdict
// either.
//
// The 503 carries no WWW-Authenticate, for the same reason. It is
// logged at Warn whatever Enforce says: with Enforce off the request
// still proceeds as Fallback, so a signed-in user is quietly served as
// anonymous for the length of the outage, and the log line is the only
// place that shows.
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

	if !validFieldValue(opts.Challenge) {
		return nil, fmt.Errorf("httpmw: NewCaller: Challenge %q is not a valid header value: it contains a control byte", opts.Challenge)
	}

	m := &CallerMiddleware{
		authenticator: a,
		fallback:      opts.Fallback,
		enforce:       opts.Enforce,
		proxyHeader:   opts.ProxyHeader,
		log:           opts.Logger,
		challenge:     opts.Challenge,
	}
	if m.challenge == "" {
		m.challenge = defaultChallenge
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
					m.writeUnauthorized(w, err)
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
// ok is false when a response has already been written and the request
// must not proceed.
func (m *CallerMiddleware) resolve(w http.ResponseWriter, r *http.Request) (purser.Caller, purser.AuthSource, bool, bool) {
	c, err := m.authenticator.Authenticate(r)
	if err != nil {
		unavailable := isUnavailable(err)
		if unavailable {
			m.logUnavailable(r, err)
		}
		if m.enforce {
			if unavailable {
				writeUnavailable(w)
			} else {
				m.log.DebugContext(r.Context(), "purser: authentication rejected",
					"source", m.authenticator.Source(), "err", scrubbed(r, err))
				m.writeUnauthorized(w, err)
			}
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

// isUnavailable reports whether err leaves the credential undecided
// rather than rejected. See NewCaller, "401 or 503".
func isUnavailable(err error) bool {
	return errors.Is(err, purser.ErrUnavailable) || !errors.Is(err, purser.ErrUnauthenticated)
}

// logUnavailable records an authenticator that could not reach a
// verdict.
//
// A request whose client has already gone is the exception. net/http
// cancels its context, the authenticator's remote call fails with it,
// and that is no outage: logging it at Warn would alert on every user
// who closed a tab mid-request.
//
// Canceled only, not any ended context. A deadline the server set
// itself — http.TimeoutHandler, a context.WithTimeout further out —
// ends it with DeadlineExceeded, and an authenticator whose dependency
// is slow enough to trip that is exactly the outage this line reports.
func (m *CallerMiddleware) logUnavailable(r *http.Request, err error) {
	ctx := r.Context()
	if errors.Is(ctx.Err(), context.Canceled) {
		m.log.DebugContext(ctx, "purser: authenticator could not reach a verdict; the client had already gone",
			"source", m.authenticator.Source(), "err", scrubbed(r, err))
		return
	}
	m.log.WarnContext(ctx, "purser: authenticator could not reach a verdict",
		"source", m.authenticator.Source(), "enforce", m.enforce, "err", scrubbed(r, err))
}

// redacted stands in for credential material removed from a log line.
const redacted = "[REDACTED]"

// minScrubLen is the shortest credential scrubbed is willing to remove.
// Below it, replacing every occurrence would make the line unreadable —
// a two-byte token turns every word containing those two bytes into a
// redaction — while protecting a credential short enough to guess.
const minScrubLen = 8

// scrubbed returns err's text with the request's own credential removed.
//
// The errors these log lines record come from the authenticator, which
// may not be purser's: a third-party implementation that quotes the
// token it rejected ("unknown token %q") would otherwise put a live
// credential into the log, at Debug for every bad one and at Warn for
// every one presented during an outage. purser's own authenticators and
// steward's never do; this makes it impossible rather than unlikely.
//
// It is a backstop, not a guarantee. It removes what this request
// carried in the headers purser's authenticators read — Authorization,
// whole and with its scheme stripped, and authn.HeaderAttachToken — as
// sent and in both URL encodings, since an error from net/url or a
// request built from the token quotes it that way. A credential the
// authenticator read from somewhere else, or transformed before quoting
// (truncated, decoded, re-encoded), passes through, as does a second
// value of either header. Not quoting the credential remains the
// authenticator's job.
//
// A client can choose its own credential, and so choose what is
// redacted from the lines its own failed requests produce: an
// Authorization of "Bearer connection refused" blanks that phrase out of
// its own Warn. That hides nothing about anyone else's request, and the
// line itself — source, level, the fact of the failure — still appears.
func scrubbed(r *http.Request, err error) string {
	msg := err.Error()
	for _, secret := range credentials(r) {
		msg = strings.ReplaceAll(msg, secret, redacted)
	}
	return msg
}

// credentials lists every form of the request's credential that
// scrubbed removes. Longest first, so a whole header value is replaced
// as one redaction before the bare token inside it is looked for.
func credentials(r *http.Request) []string {
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if len(v) < minScrubLen {
			return
		}
		for _, form := range []string{v, url.QueryEscape(v), url.PathEscape(v)} {
			if !slices.Contains(out, form) {
				out = append(out, form)
			}
		}
	}
	// The first value of each header only — what Header.Get returns, and
	// so what an authenticator reads. Every value would let a client
	// that sends thousands of Authorization lines, inside net/http's
	// header limit, choose how much work each rejected request costs.
	auth := r.Header.Get("Authorization")
	add(auth)
	// The token without its scheme, which is what an authenticator that
	// parsed the header would quote. The scheme itself is never a
	// candidate: "Bearer" is in half the messages worth logging.
	if _, cred, ok := strings.Cut(strings.TrimSpace(auth), " "); ok {
		add(cred)
	}
	add(r.Header.Get(authn.HeaderAttachToken))
	slices.SortStableFunc(out, func(a, b string) int { return len(b) - len(a) })
	return out
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
// it is on the log line: Debug for a rejected credential, which every
// unauthenticated probe on the internet would otherwise turn into a
// Warn, and Warn for a rejected assertion, which is a security event.
// The challenge is CallerOptions.Challenge.
func (m *CallerMiddleware) writeUnauthorized(w http.ResponseWriter, err error) {
	w.Header().Set("WWW-Authenticate", m.challenge)
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

// retryAfter is the Retry-After on a 503, in seconds. It is a hint and
// deliberately short: an authenticator's dependency coming back is
// noticed on the next request, so the cost of a client retrying early
// is one more cheap 503, and the cost of it waiting too long is a user
// locked out after the outage has ended.
const retryAfter = "10"

// writeUnavailable writes the 503 for an authenticator that could not
// reach a verdict.
//
// No WWW-Authenticate. A challenge is an invitation to authenticate
// afresh, which is the reaction this status exists to prevent: the
// credential the client already holds may be perfectly good.
func writeUnavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", retryAfter)
	http.Error(w, "service unavailable: the credential could not be verified; retry", http.StatusServiceUnavailable)
}

// validFieldValue reports whether v may be sent as an HTTP header value:
// no control bytes except horizontal tab (RFC 9110 §5.5). Bytes at or
// above 0x80 are obs-text and allowed. It checks bytes, not runes, the
// way golang.org/x/net/http/httpguts.ValidHeaderFieldValue does, so an
// invalid UTF-8 sequence is judged by what is actually on the wire.
func validFieldValue(v string) bool {
	for i := 0; i < len(v); i++ {
		if b := v[i]; (b < 0x20 && b != '\t') || b == 0x7f {
			return false
		}
	}
	return true
}
