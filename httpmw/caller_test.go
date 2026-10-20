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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
	"github.com/go-steer/purser/authn/bearer"
)

// seen records what a handler behind the middleware found on the
// request context.
type seen struct {
	caller    purser.Caller
	hasCaller bool
	proxyBy   string
	source    purser.AuthSource
	hasSource bool
	ran       bool
}

// capture returns a handler that records the context values the
// middleware attached. A 200 means it ran at all, which several tests
// care about more than the body.
func capture(got *seen) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.ran = true
		got.caller, got.hasCaller = purser.CallerFromContext(r.Context())
		got.proxyBy, _ = purser.ProxyByFromContext(r.Context())
		got.source, got.hasSource = purser.AuthSourceFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

// mustCaller builds the middleware or fails the test. Most cases are
// about behavior, not construction.
func mustCaller(t *testing.T, opts CallerOptions) Middleware {
	t.Helper()
	return newCaller(t, opts).Middleware()
}

func newCaller(t *testing.T, opts CallerOptions) *CallerMiddleware {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = discardLogger()
	}
	m, err := NewCaller(opts)
	if err != nil {
		t.Fatalf("NewCaller(%+v): %v", opts, err)
	}
	return m
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
}

// serve runs one request through the middleware and returns what the
// handler saw plus the response.
func serve(t *testing.T, mw Middleware, r *http.Request) (*seen, *httptest.ResponseRecorder) {
	t.Helper()
	var got seen
	rec := httptest.NewRecorder()
	mw(capture(&got)).ServeHTTP(rec, r)
	return &got, rec
}

func get() *http.Request { return httptest.NewRequest(http.MethodGet, "/", nil) }

// tableAuth is the two-identity bearer table the proxy cases use:
// sa:slack-bot may proxy, alice may not.
func tableAuth(t *testing.T) *bearer.Auth {
	t.Helper()
	a, err := bearer.New(bearer.Options{
		Users: []bearer.User{
			{Identity: "sa:slack-bot", Token: "tok_bot", Labels: map[string]string{"kind": "service"}},
			{Identity: "alice@example.com", Token: "tok_alice", Labels: map[string]string{"team": "platform"}},
		},
		ProxyIdentities: []string{"sa:slack-bot"},
	})
	if err != nil {
		t.Fatalf("bearer.New: %v", err)
	}
	return a
}

// ---------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------

func TestCallerNilAuthenticatorResolvesAnonymous(t *testing.T) {
	t.Parallel()
	got, rec := serve(t, mustCaller(t, CallerOptions{}), get())

	if !got.hasCaller {
		t.Fatal("no Caller on the context; the middleware must always attach one")
	}
	if got.caller.Identity != purser.AnonymousIdentity {
		t.Errorf("identity = %q, want %q", got.caller.Identity, purser.AnonymousIdentity)
	}
	if got.source != purser.AuthSourceAnonymous {
		t.Errorf("auth source = %q, want anonymous", got.source)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestCallerFallbackIsHonoured(t *testing.T) {
	t.Parallel()
	got, _ := serve(t, mustCaller(t, CallerOptions{
		Fallback: purser.Caller{Identity: "daemon-user"},
	}), get())

	if got.caller.Identity != "daemon-user" {
		t.Errorf("identity = %q, want daemon-user", got.caller.Identity)
	}
}

func TestCallerResolvesIdentityAndLabels(t *testing.T) {
	t.Parallel()
	mw := mustCaller(t, CallerOptions{Authenticator: tableAuth(t)})

	r := get()
	r.Header.Set("Authorization", "Bearer tok_alice")
	got, _ := serve(t, mw, r)

	if got.caller.Identity != "alice@example.com" {
		t.Errorf("identity = %q, want alice@example.com", got.caller.Identity)
	}
	if got.caller.Label("team") != "platform" {
		t.Errorf("labels = %v, want team=platform", got.caller.Labels)
	}
	if got.source != purser.AuthSourceBearer {
		t.Errorf("auth source = %q, want bearer", got.source)
	}
}

func TestCallerFailedAuthFallsBackWhenNotEnforcing(t *testing.T) {
	t.Parallel()
	mw := mustCaller(t, CallerOptions{
		Authenticator: tableAuth(t),
		Fallback:      purser.Caller{Identity: "anon"},
	})

	// No Authorization header: ErrUnauthenticated, and the
	// non-enforcing posture serves the request anyway.
	got, rec := serve(t, mw, get())

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: a non-enforcing surface must not 401", rec.Code)
	}
	if got.caller.Identity != "anon" {
		t.Errorf("identity = %q, want anon", got.caller.Identity)
	}
	if got.source != purser.AuthSourceAnonymous {
		t.Errorf("auth source = %q, want anonymous: nothing was verified", got.source)
	}
}

// TestCallerChallenge pins the WWW-Authenticate value on both paths that
// write a 401: an enforced authentication failure, and a refused proxy
// assertion. An MCP client reads resource_metadata from it to discover
// how to sign in, so a path that sent the default instead would leave
// that client stuck.
func TestCallerChallenge(t *testing.T) {
	t.Parallel()
	const custom = `Bearer resource_metadata="https://lookout.example/.well-known/oauth-protected-resource/mcp"`
	for _, c := range []struct{ challenge, want string }{
		{"", `Bearer realm="purser"`},
		{custom, custom},
	} {
		enforced := mustCaller(t, CallerOptions{Authenticator: tableAuth(t), Enforce: true, Challenge: c.challenge})
		_, rec := serve(t, enforced, get())
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("enforced: status = %d, want 401", rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != c.want {
			t.Errorf("enforced, Challenge %q: WWW-Authenticate = %q, want %q", c.challenge, got, c.want)
		}

		// No credential plus an assertion: refused on the proxy path,
		// which writes its own 401 even though Enforce is off.
		lenient := mustCaller(t, CallerOptions{Authenticator: tableAuth(t), Challenge: c.challenge})
		r := get()
		r.Header.Set(authn.HeaderAssertedCaller, "alice@example.com")
		_, rec = serve(t, lenient, r)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("proxy: status = %d, want 401", rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != c.want {
			t.Errorf("proxy, Challenge %q: WWW-Authenticate = %q, want %q", c.challenge, got, c.want)
		}
	}
}

// TestNewCallerChallengeMustBeAValidFieldValue pins the RFC 9110 §5.5
// rule NewCaller applies, byte by byte as net/http's own check does: no
// control bytes except tab; obs-text (bytes ≥ 0x80, valid UTF-8 or not)
// is allowed.
func TestNewCallerChallengeMustBeAValidFieldValue(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, challenge string
		ok              bool
	}{
		{"header injection", "Bearer realm=\"x\"\r\nSet-Cookie: a=b", false},
		{"trailing LF", "Bearer realm=\"x\"\n", false},
		{"NUL", "Bearer \x00", false},
		{"other C0", "Bearer \x1b", false},
		{"DEL", "Bearer \x7f", false},
		{"ordinary", `Bearer resource_metadata="https://x.example/m", scope="a b"`, true},
		{"tab", "Bearer\trealm=\"x\"", true},
		{"obs-text, valid UTF-8", "Bearer realm=\"café\"", true},
		{"obs-text, raw byte", "Bearer realm=\"\x85\"", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewCaller(CallerOptions{Challenge: c.challenge, Logger: discardLogger()})
			if c.ok && err != nil {
				t.Errorf("NewCaller refused %q: %v", c.challenge, err)
			}
			if !c.ok && err == nil {
				t.Errorf("NewCaller accepted %q; want a control-byte error", c.challenge)
			}
		})
	}
}

func TestCallerEnforceRejects(t *testing.T) {
	t.Parallel()
	mw := mustCaller(t, CallerOptions{Authenticator: tableAuth(t), Enforce: true})

	got, rec := serve(t, mw, get())

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got.ran {
		t.Error("the handler ran on a rejected request")
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("no WWW-Authenticate header on the 401")
	}
}

// The 401 body names the category. What it must not carry is the
// authenticator's account of why the credential failed, which tells a
// prober which identities exist.
func TestCallerRejectionDoesNotLeakTheReason(t *testing.T) {
	t.Parallel()
	const detail = "token 3f9a is not in the table"
	mw := mustCaller(t, CallerOptions{
		Authenticator: fakeAuth{err: fmt.Errorf("%s: %w", detail, purser.ErrUnauthenticated)},
		Enforce:       true,
	})

	_, rec := serve(t, mw, get())

	if strings.Contains(rec.Body.String(), detail) {
		t.Errorf("401 body leaked the reason: %q", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "no valid credential") {
		t.Errorf("401 body = %q, want the category", rec.Body)
	}
}

// An authenticator that returns something other than
// ErrUnauthenticated — a JWKS fetch that failed, a torn credential
// file — must not be treated as a successful authentication. It has no
// identity to offer either way. Enforced, it is a 503 rather than a
// 401; see TestCallerUndecidedIs503.
func TestCallerNonSentinelErrorIsStillAFailure(t *testing.T) {
	t.Parallel()
	boom := errors.New("purser: issuer keys unavailable")

	got, rec := serve(t, mustCaller(t, CallerOptions{
		Authenticator: fakeAuth{err: boom, source: purser.AuthSourceOIDC},
		Fallback:      purser.Caller{Identity: "anon"},
	}), get())
	if rec.Code != http.StatusOK {
		t.Fatalf("non-enforcing status = %d, want 200", rec.Code)
	}
	if got.caller.Identity != "anon" {
		t.Errorf("identity = %q, want the fallback", got.caller.Identity)
	}
	if got.source != purser.AuthSourceAnonymous {
		t.Errorf("auth source = %q, want anonymous: the authenticator failed", got.source)
	}

	got, rec = serve(t, mustCaller(t, CallerOptions{
		Authenticator: fakeAuth{err: boom, source: purser.AuthSourceOIDC},
		Enforce:       true,
	}), get())
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("enforcing status = %d, want 503", rec.Code)
	}
	if got.ran {
		t.Error("the handler ran on a request whose authenticator failed")
	}
}

// TestCallerUndecidedIs503 is go-steer/purser#23. An authenticator that
// could not reach a verdict — its issuer down, its directory
// unreachable — must not answer 401, because a client reads 401 as "your
// credential is bad" and signs in again: an MCP client re-runs OAuth,
// for every user, for a credential that was fine.
func TestCallerUndecidedIs503(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"ErrUnauthenticated", fmt.Errorf("bad token: %w", purser.ErrUnauthenticated), http.StatusUnauthorized},
		{"ErrUnavailable", fmt.Errorf("issuer down: %w", purser.ErrUnavailable), http.StatusServiceUnavailable},
		{"neither", errors.New("torn credential file"), http.StatusServiceUnavailable},
		// Precedence. A composite authenticator that tried two
		// verifiers, one of which could not answer, has not rejected
		// the credential: the one that could not answer might have
		// accepted it.
		{"both", errors.Join(purser.ErrUnauthenticated, purser.ErrUnavailable), http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, rec := serve(t, mustCaller(t, CallerOptions{
				Authenticator: fakeAuth{err: tc.err, source: purser.AuthSourceOIDC},
				Enforce:       true,
			}), get())

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if got.ran {
				t.Error("the handler ran on a request that did not authenticate")
			}
			challenge := rec.Header().Get("WWW-Authenticate")
			retry := rec.Header().Get("Retry-After")
			if tc.want == http.StatusServiceUnavailable {
				// A challenge is an invitation to sign in afresh,
				// which is the reaction the 503 exists to prevent.
				if challenge != "" {
					t.Errorf("WWW-Authenticate = %q on a 503, want none", challenge)
				}
				if retry == "" {
					t.Error("no Retry-After on the 503")
				}
				if strings.Contains(rec.Body.String(), "issuer down") || strings.Contains(rec.Body.String(), "torn") {
					t.Errorf("503 body leaked the reason: %q", rec.Body)
				}
				return
			}
			if challenge == "" {
				t.Error("no WWW-Authenticate on the 401")
			}
			if retry != "" {
				t.Errorf("Retry-After = %q on a 401: retrying a rejected credential cannot succeed", retry)
			}
		})
	}
}

// The issue's second half: "the operator sees nothing". An outage is
// logged at Warn with the authenticator's source and reason, and so is
// one behind a non-enforcing surface, where the request proceeds as the
// fallback and a signed-in user would otherwise be served as anonymous
// with no trace anywhere.
func TestCallerUndecidedIsLogged(t *testing.T) {
	t.Parallel()
	for _, enforce := range []bool{true, false} {
		t.Run(fmt.Sprintf("enforce=%v", enforce), func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			mw := mustCaller(t, CallerOptions{
				Authenticator: fakeAuth{err: fmt.Errorf("jwks: connection refused: %w", purser.ErrUnavailable), source: purser.AuthSourceOIDC},
				Enforce:       enforce,
				Logger:        slog.New(slog.NewTextHandler(&logs, nil)),
			})
			serve(t, mw, get())

			out := logs.String()
			for _, want := range []string{"level=WARN", "source=oidc", "connection refused"} {
				if !strings.Contains(out, want) {
					t.Errorf("log = %q, want it to contain %q", out, want)
				}
			}
		})
	}
}

// A 401 is logged too, which the writeUnauthorized doc comment always
// promised and resolve never did — but at Debug, since every
// unauthenticated request on the internet produces one.
func TestCallerRejectionIsLoggedAtDebug(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	mw := mustCaller(t, CallerOptions{
		Authenticator: tableAuth(t),
		Enforce:       true,
		Logger:        slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	r := get()
	r.Header.Set("Authorization", "Bearer tok_nobody")
	serve(t, mw, r)

	out := logs.String()
	if !strings.Contains(out, "level=DEBUG") || !strings.Contains(out, "unknown token") {
		t.Errorf("log = %q, want a Debug line carrying the authenticator's reason", out)
	}
	if strings.Contains(out, "level=WARN") {
		t.Errorf("log = %q: a rejected credential is not an outage", out)
	}
}

// A client that hangs up mid-request cancels its context, the
// authenticator's remote call fails with it, and that is not an outage.
// Logging it at Warn would alert on every closed tab.
func TestCallerUndecidedAfterClientLeftIsNotAWarning(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	mw := mustCaller(t, CallerOptions{
		Authenticator: fakeAuth{err: fmt.Errorf("introspect: %w: %w", context.Canceled, purser.ErrUnavailable), source: purser.AuthSourceOIDC},
		Enforce:       true,
		Logger:        slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	serve(t, mw, get().WithContext(ctx))

	out := logs.String()
	if strings.Contains(out, "level=WARN") {
		t.Errorf("log = %q, want no Warn for a client that had already gone", out)
	}
	if !strings.Contains(out, "level=DEBUG") {
		t.Errorf("log = %q, want it kept at Debug", out)
	}
}

// The exception is the client leaving, not the context ending. A
// deadline the server set itself — http.TimeoutHandler, say — ends it
// with DeadlineExceeded, and an authenticator whose dependency is slow
// enough to trip that is the outage, not a closed tab.
func TestCallerUndecidedAtServerDeadlineIsAWarning(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	mw := mustCaller(t, CallerOptions{
		Authenticator: fakeAuth{err: fmt.Errorf("tokeninfo: %w: %w", context.DeadlineExceeded, purser.ErrUnavailable), source: purser.AuthSourceGoogleAccessToken},
		Enforce:       true,
		Logger:        slog.New(slog.NewTextHandler(&logs, nil)),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	<-ctx.Done()
	_, rec := serve(t, mw, get().WithContext(ctx))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if out := logs.String(); !strings.Contains(out, "level=WARN") {
		t.Errorf("log = %q, want a Warn: the server's own deadline expiring is not the client leaving", out)
	}
}

// The log lines #23 added record the authenticator's error, and the
// authenticator may not be purser's. One that quotes the token it was
// handed must not put a live credential in the log — at Warn on the
// outage path, at Debug on the rejection path.
func TestCallerLogLinesDoNotCarryTheCredential(t *testing.T) {
	t.Parallel()
	const token = "tok_live_9f8e7d6c5b4a" //nolint:gosec // G101: a test value, not a credential
	cases := []struct {
		name string
		err  error
	}{
		{"outage, logged at Warn", fmt.Errorf("introspecting %q: %w", token, purser.ErrUnavailable)},
		{"rejection, logged at Debug", fmt.Errorf("unknown token %s: %w", token, purser.ErrUnauthenticated)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			mw := mustCaller(t, CallerOptions{
				Authenticator: fakeAuth{err: tc.err, source: purser.AuthSourceBearer},
				Enforce:       true,
				Logger:        slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
			})
			r := get()
			r.Header.Set("Authorization", "Bearer "+token)
			serve(t, mw, r)

			out := logs.String()
			if out == "" {
				t.Fatal("nothing was logged; the test would pass without scrubbing")
			}
			if strings.Contains(out, token) {
				t.Errorf("log = %q, carries the request's credential", out)
			}
			if !strings.Contains(out, redacted) {
				t.Errorf("log = %q, want the credential replaced by %s", out, redacted)
			}
		})
	}
}

// TestScrubbedForms covers each form a credential can take on its way
// into an error message.
func TestScrubbedForms(t *testing.T) {
	t.Parallel()
	// Characters that both URL encodings change, so the escaped forms
	// differ from the raw one and from each other.
	const token = "abc/def+ghi=jkl mno" //nolint:gosec // G101: a test value, not a credential
	cases := []struct {
		name   string
		header string
		value  string
		msg    string
	}{
		{"bare token from Authorization", "Authorization", "Bearer " + token, "unknown token " + token},
		{"whole Authorization value", "Authorization", "Bearer " + token, `bad header "Bearer ` + token + `"`},
		{"query-escaped", "Authorization", "Bearer " + token, "GET https://idp.example/introspect?token=" + url.QueryEscape(token)},
		{"path-escaped", "Authorization", "Bearer " + token, "GET https://idp.example/tokens/" + url.PathEscape(token)},
		{"side-channel header", authn.HeaderAttachToken, token, "unknown attach token " + token},
		{"scheme in another case", "Authorization", "bearer " + token, "unknown token " + token},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := get()
			r.Header.Set(tc.header, tc.value)
			got := scrubbed(r, errors.New(tc.msg))

			for _, leaked := range []string{token, url.QueryEscape(token), url.PathEscape(token)} {
				if strings.Contains(got, leaked) {
					t.Errorf("scrubbed = %q, still carries %q", got, leaked)
				}
			}
			if !strings.Contains(got, redacted) {
				t.Errorf("scrubbed = %q, want %s in it", got, redacted)
			}
		})
	}
}

// Scrubbing must not cost the line its meaning: the scheme is not a
// secret, a request with no credential has nothing to remove, and a
// credential under minScrubLen is left alone rather than redacting every
// word that happens to contain it.
func TestScrubbedLeavesTheRestReadable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		value string
		msg   string
	}{
		{"the scheme", "Bearer tok_live_9f8e7d6c5b4a", "Bearer scheme required, got Basic"},
		{"no credential", "", "no token presented"},
		{"a credential under the threshold", "Bearer ab", "unknown token: absent from table"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := get()
			if tc.value != "" {
				r.Header.Set("Authorization", tc.value)
			}
			if got := scrubbed(r, errors.New(tc.msg)); got != tc.msg {
				t.Errorf("scrubbed = %q, want it unchanged: %q", got, tc.msg)
			}
		})
	}
}

// Only the first value of each header is a candidate — what Header.Get
// returns and authenticators read. Considering every value would let a
// client that sends thousands of Authorization lines set the cost of
// each rejected request.
func TestScrubbedConsidersTheFirstValueOnly(t *testing.T) {
	t.Parallel()
	r := get()
	r.Header.Add("Authorization", "Bearer first_token_value")
	for i := 0; i < 1000; i++ {
		r.Header.Add("Authorization", fmt.Sprintf("Bearer filler_token_%04d", i))
	}

	got := credentials(r)
	for _, c := range got {
		if strings.Contains(c, "filler") {
			t.Fatalf("credentials = %d candidates including %q; want only the first header value's forms", len(got), c)
		}
	}
	if !slices.Contains(got, "first_token_value") {
		t.Errorf("credentials = %q, want the first value's token among them", got)
	}
}

// The fallback is one value captured in the closure. Handing out its
// Labels map would let one request's mutation rewrite what every later
// unauthenticated request sees.
//
// Two paths reach the fallback and each has to clone: the anonymous
// default authenticator returns it as its result, and a real
// authenticator's failure has the middleware hand it out directly.
func TestCallerFallbackLabelsAreNotShared(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		auth authn.Authenticator
	}{
		{"the anonymous default", nil},
		{"a failed authentication", tableAuth(t)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			mw := mustCaller(t, CallerOptions{
				Authenticator: c.auth,
				Fallback:      purser.Caller{Identity: "anon", Labels: map[string]string{"tier": "public"}},
			})

			// No Authorization header, so tableAuth fails and the
			// middleware falls back.
			first, _ := serve(t, mw, get())
			if first.caller.Identity != "anon" {
				t.Fatalf("identity = %q, want the fallback", first.caller.Identity)
			}
			first.caller.Labels["tier"] = "admin"

			second, _ := serve(t, mw, get())
			if got := second.caller.Label("tier"); got != "public" {
				t.Errorf("second request saw tier=%q; the first request's mutation escaped into the fallback", got)
			}
		})
	}
}

// ---------------------------------------------------------------
// The auth-source verdict
// ---------------------------------------------------------------

// The regression this package exists to prevent. Middleware that reads
// "mtls" off a populated VerifiedChains is right for the PKI profile
// and wrong for SPIFFE, where a good connection leaves VerifiedChains
// empty. Both directions are pinned: the verdict follows Source() and
// nothing else.
func TestCallerVerdictComesFromTheAuthenticatorNotTheTLSState(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		source     purser.AuthSource
		tlsState   *tls.ConnectionState
		wantVerdit purser.AuthSource
	}{
		{
			name:       "SPIFFE over a connection with no verified chains",
			source:     purser.AuthSourceSPIFFE,
			tlsState:   &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}},
			wantVerdit: purser.AuthSourceSPIFFE,
		},
		{
			name:       "PKI over a connection with verified chains",
			source:     purser.AuthSourceMTLS,
			tlsState:   &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}},
			wantVerdit: purser.AuthSourceMTLS,
		},
		{
			name:   "an anonymous authenticator over a verified connection stays anonymous",
			source: purser.AuthSourceAnonymous,
			// Verified chains are present, but nothing here verified
			// an identity from them. Inferring "mtls" would report a
			// caller as mutually authenticated on the strength of a
			// certificate no authenticator ever read.
			tlsState:   &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}},
			wantVerdit: purser.AuthSourceAnonymous,
		},
		{
			name:       "bearer over plaintext",
			source:     purser.AuthSourceBearer,
			tlsState:   nil,
			wantVerdit: purser.AuthSourceBearer,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			mw := mustCaller(t, CallerOptions{
				Authenticator: fakeAuth{
					caller: purser.Caller{Identity: "peer"},
					source: c.source,
				},
			})
			r := get()
			r.TLS = c.tlsState
			got, _ := serve(t, mw, r)

			if got.source != c.wantVerdit {
				t.Errorf("auth source = %q, want %q", got.source, c.wantVerdit)
			}
		})
	}
}

// A gate that verified the shared token stamps its verdict on the
// context. An anonymous authenticator inside verified nothing itself,
// so it must not overwrite that with "anonymous" — the request did not
// get in anonymously.
func TestCallerInheritsAnOuterVerdict(t *testing.T) {
	t.Parallel()
	gate, err := NewTokenGate(TokenGateOptions{Token: "s3cret"})
	if err != nil {
		t.Fatalf("NewTokenGate: %v", err)
	}
	chain := Chain(gate.Middleware(), mustCaller(t, CallerOptions{}))

	var got seen
	rec := httptest.NewRecorder()
	r := get()
	r.Header.Set("Authorization", "Bearer s3cret")
	chain(capture(&got)).ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got.source != purser.AuthSourceBearer {
		t.Errorf("auth source = %q, want bearer: the gate verified the token even though the authenticator verified nothing", got.source)
	}
	if got.caller.Identity != purser.AnonymousIdentity {
		t.Errorf("identity = %q, want anon: a shared token is not an identity", got.caller.Identity)
	}
}

// Inheritance covers the rejected credential too, and the identity
// does not follow it. The gate verified the transport token, so the
// request did not get in anonymously and reporting that it did would
// be the lie; the per-caller token it also carried was rubbish, so
// there is no identity to show.
func TestCallerInheritsAnOuterVerdictOnARejectedCredential(t *testing.T) {
	t.Parallel()
	gate := mustGate(t, TokenGateOptions{Token: "s3cret"})
	chain := Chain(gate.Middleware(), mustCaller(t, CallerOptions{Authenticator: tableAuth(t)}))

	var got seen
	rec := httptest.NewRecorder()
	r := get()
	r.Header.Set(authn.HeaderAttachToken, "s3cret")
	r.Header.Set("Authorization", "Bearer definitely-not-a-token")
	chain(capture(&got)).ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: the surface is not enforcing", rec.Code)
	}
	if got.source != purser.AuthSourceBearer {
		t.Errorf("auth source = %q, want bearer: the gate's token is what got this request in", got.source)
	}
	if got.caller.Identity != purser.AnonymousIdentity {
		t.Errorf("identity = %q, want anon: the per-caller token was rejected", got.caller.Identity)
	}
}

// Inheritance only fills an anonymous verdict. An authenticator that
// verified a credential of its own reports that, whatever ran outside.
func TestCallerVerdictBeatsAnOuterVerdict(t *testing.T) {
	t.Parallel()
	mw := mustCaller(t, CallerOptions{
		Authenticator: fakeAuth{
			caller: purser.Caller{Identity: "spiffe://example.org/ns/a/sa/b"},
			source: purser.AuthSourceSPIFFE,
		},
	})

	r := get()
	r = r.WithContext(purser.WithAuthSource(r.Context(), purser.AuthSourceBearer))
	got, _ := serve(t, mw, r)

	if got.source != purser.AuthSourceSPIFFE {
		t.Errorf("auth source = %q, want spiffe", got.source)
	}
}

// ---------------------------------------------------------------
// Proxy assertions
// ---------------------------------------------------------------

func TestCallerProxyAssertionSucceeds(t *testing.T) {
	t.Parallel()
	mw := mustCaller(t, CallerOptions{Authenticator: tableAuth(t)})

	r := get()
	r.Header.Set("Authorization", "Bearer tok_bot")
	r.Header.Set(authn.HeaderAssertedCaller, "alice@example.com")
	got, rec := serve(t, mw, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body)
	}
	if got.caller.Identity != "alice@example.com" {
		t.Errorf("effective identity = %q, want alice@example.com", got.caller.Identity)
	}
	if got.caller.Label("team") != "platform" {
		t.Errorf("labels = %v, want the asserted identity's table entry", got.caller.Labels)
	}
	if got.proxyBy != "sa:slack-bot" {
		t.Errorf("proxy_by = %q, want sa:slack-bot", got.proxyBy)
	}
	if got.source != purser.AuthSourceAsserted {
		t.Errorf("auth source = %q, want asserted", got.source)
	}
}

func TestCallerProxyAssertionRejections(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		auth     authn.Authenticator
		token    string
		asserted string
		wantBody string
	}{
		{
			name:     "the caller is not on the proxy allowlist",
			auth:     tableAuth(t),
			token:    "tok_alice",
			asserted: "bob@example.com",
			wantBody: "not permitted to assert",
		},
		{
			name:     "the asserted identity is not provisioned",
			auth:     tableAuth(t),
			token:    "tok_bot",
			asserted: "ghost@example.com",
			wantBody: "not provisioned",
		},
		{
			name: "the authenticator has no proxy capability at all",
			// Silently dropping the header would leave an operator
			// who configured proxying believing it worked.
			auth:     authn.Anonymous{},
			asserted: "alice@example.com",
			wantBody: "not permitted to assert",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			mw := mustCaller(t, CallerOptions{Authenticator: c.auth})

			r := get()
			if c.token != "" {
				r.Header.Set("Authorization", "Bearer "+c.token)
			}
			r.Header.Set(authn.HeaderAssertedCaller, c.asserted)
			got, rec := serve(t, mw, r)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if got.ran {
				t.Error("the handler ran on a rejected assertion")
			}
			if !strings.Contains(rec.Body.String(), c.wantBody) {
				t.Errorf("body = %q, want it to mention %q", rec.Body, c.wantBody)
			}
		})
	}
}

// The hole this middleware has to close on its own. On the
// non-enforcing path the requester handed to the proxy check is the
// *fallback*, which is a perfectly ordinary Caller — so
// AuthenticatorWithProxy's documented guard ("must return false for the
// zero Caller") never fires, and an allowlist naming the fallback's
// identity, or a claim-based CanProxyAs that only checks IsZero, would
// let a request carrying no credential at all walk away with a
// provisioned one.
func TestCallerUnauthenticatedRequestCannotAssert(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		opts CallerOptions
		want string
	}{
		{
			// The fallback identity is itself on the proxy allowlist,
			// so CanProxyAs says yes to the Caller it is handed.
			name: "a fallback that is on the proxy allowlist",
			opts: CallerOptions{
				Authenticator: tableAuth(t),
				Fallback:      purser.Caller{Identity: "sa:slack-bot"},
			},
			want: "alice@example.com",
		},
		{
			// A claim-based authenticator implementing exactly the
			// documented minimum. purser.Anonymous() is not zero.
			name: "a CanProxyAs that only refuses the zero Caller",
			opts: CallerOptions{
				Authenticator: proxyAuthNoTable{fakeAuth{
					err:    purser.ErrUnauthenticated,
					source: purser.AuthSourceOIDC,
				}},
			},
			want: "carol@example.com",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			mw := mustCaller(t, c.opts)

			// No Authorization header anywhere: nothing verified this
			// request.
			r := get()
			r.Header.Set(authn.HeaderAssertedCaller, c.want)
			got, rec := serve(t, mw, r)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; the handler saw identity %q, proxy_by %q, source %q",
					rec.Code, got.caller.Identity, got.proxyBy, got.source)
			}
			if got.ran {
				t.Error("the handler ran on an assertion by an unauthenticated request")
			}
			if !strings.Contains(rec.Body.String(), "not permitted to assert") {
				t.Errorf("body = %q, want the forbidden category", rec.Body)
			}
		})
	}
}

// An authenticator that verifies nothing has not authenticated anybody,
// however cleanly it returns. It must not reach the proxy path either.
func TestCallerAnonymousAuthenticatorCannotAssert(t *testing.T) {
	t.Parallel()
	mw := mustCaller(t, CallerOptions{
		Authenticator: alwaysProxy{authn.Anonymous{Caller: purser.Caller{Identity: "daemon"}}},
	})

	r := get()
	r.Header.Set(authn.HeaderAssertedCaller, "alice@example.com")
	_, rec := serve(t, mw, r)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401: authn.Anonymous never errors, but it verifies nothing", rec.Code)
	}
}

// A present-but-blank header asserts nothing. Reading it as "no
// assertion was made" would let it through as the underlying caller;
// taking it at face value would mint an identity of three spaces, whose
// IsZero is false and which every downstream rule would treat as real.
func TestCallerBlankAssertionIsRejected(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		auth authn.Authenticator
	}{
		{"a table-backed authenticator", tableAuth(t)},
		{"a claim-based authenticator with no table", proxyAuthNoTable{fakeAuth{
			caller: purser.Caller{Identity: "sa:gateway"},
			source: purser.AuthSourceOIDC,
		}}},
	}
	for _, c := range cases {
		for _, blank := range []string{" ", "   ", "\t"} {
			t.Run(c.name+"/"+strconv.Quote(blank), func(t *testing.T) {
				t.Parallel()
				mw := mustCaller(t, CallerOptions{Authenticator: c.auth})

				r := get()
				r.Header.Set("Authorization", "Bearer tok_bot")
				r.Header.Set(authn.HeaderAssertedCaller, blank)
				got, rec := serve(t, mw, r)

				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d, want 401; the handler saw identity %q", rec.Code, got.caller.Identity)
				}
				if !strings.Contains(rec.Body.String(), "not provisioned") {
					t.Errorf("body = %q, want the unknown-identity category", rec.Body)
				}
			})
		}
	}
}

// The asserted identity is trimmed before it is looked up, so a proxy
// that pads the header still resolves the identity it meant.
func TestCallerAssertionIsTrimmed(t *testing.T) {
	t.Parallel()
	mw := mustCaller(t, CallerOptions{Authenticator: tableAuth(t)})

	r := get()
	r.Header.Set("Authorization", "Bearer tok_bot")
	r.Header.Set(authn.HeaderAssertedCaller, "  alice@example.com  ")
	got, rec := serve(t, mw, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body)
	}
	if got.caller.Identity != "alice@example.com" {
		t.Errorf("identity = %q, want it trimmed", got.caller.Identity)
	}
}

// The middleware clones what LookupIdentity hands back. The contract
// asks implementations to clone too, but this one hands the result
// straight to a handler, and an implementation that returns its table
// entry — a reasonable reading before the contract said otherwise —
// would have one request's mutation rewrite a provisioned identity for
// every request after it.
func TestCallerAssertedLabelsAreNotShared(t *testing.T) {
	t.Parallel()
	auth := &leakyLookup{table: map[string]purser.Caller{
		"alice@example.com": {Identity: "alice@example.com", Labels: map[string]string{"team": "platform"}},
	}}
	mw := mustCaller(t, CallerOptions{Authenticator: auth})

	assert := func() *seen {
		r := get()
		r.Header.Set(authn.HeaderAssertedCaller, "alice@example.com")
		got, rec := serve(t, mw, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body)
		}
		return got
	}

	first := assert()
	first.caller.Labels["team"] = "pwned"

	if got := assert().caller.Label("team"); got != "platform" {
		t.Errorf("second request saw team=%q; the first request's mutation reached the identity table", got)
	}
	if got := auth.table["alice@example.com"].Labels["team"]; got != "platform" {
		t.Errorf("the authenticator's own table now reads team=%q", got)
	}
}

func TestCallerProxyAssertionIsLogged(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	mw := mustCaller(t, CallerOptions{
		Authenticator: tableAuth(t),
		Logger:        slog.New(slog.NewTextHandler(&logs, nil)),
	})

	r := get()
	r.Header.Set("Authorization", "Bearer tok_alice")
	r.Header.Set(authn.HeaderAssertedCaller, "bob@example.com")
	serve(t, mw, r)

	out := logs.String()
	// The requesting identity is what correlates the attempt with a
	// credential; the asserted value is what was attempted.
	if !strings.Contains(out, "alice@example.com") || !strings.Contains(out, "bob@example.com") {
		t.Errorf("audit line = %q, want both the requester and the asserted identity", out)
	}
}

func TestCallerWithoutTheProxyHeaderStaysItself(t *testing.T) {
	t.Parallel()
	mw := mustCaller(t, CallerOptions{Authenticator: tableAuth(t)})

	r := get()
	r.Header.Set("Authorization", "Bearer tok_bot")
	got, rec := serve(t, mw, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got.caller.Identity != "sa:slack-bot" {
		t.Errorf("identity = %q, want sa:slack-bot", got.caller.Identity)
	}
	if got.proxyBy != "" {
		t.Errorf("proxy_by = %q, want empty", got.proxyBy)
	}
	if got.source != purser.AuthSourceBearer {
		t.Errorf("auth source = %q, want bearer, not asserted", got.source)
	}
}

func TestCallerProxyHeaderIsConfigurable(t *testing.T) {
	t.Parallel()
	mw := mustCaller(t, CallerOptions{
		Authenticator: tableAuth(t),
		ProxyHeader:   "X-On-Behalf-Of",
	})

	r := get()
	r.Header.Set("Authorization", "Bearer tok_bot")
	r.Header.Set("X-On-Behalf-Of", "alice@example.com")
	got, rec := serve(t, mw, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got.caller.Identity != "alice@example.com" {
		t.Errorf("identity = %q, want the asserted one", got.caller.Identity)
	}

	// And the default name is then inert: honouring both would give a
	// caller two chances at an assertion the operator meant to name
	// once.
	r = get()
	r.Header.Set("Authorization", "Bearer tok_bot")
	r.Header.Set(authn.HeaderAssertedCaller, "alice@example.com")
	got, rec = serve(t, mw, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got.caller.Identity != "sa:slack-bot" {
		t.Errorf("identity = %q, want sa:slack-bot: the default header must be ignored once ProxyHeader is set", got.caller.Identity)
	}
}

// An authenticator that permits proxying but has no identity table —
// a claim-based one — takes the asserted name at face value. The
// allowlist is the whole control there, which is the documented
// contract for authn.IdentityLookup.
func TestCallerProxyWithoutAnIdentityTable(t *testing.T) {
	t.Parallel()
	mw := mustCaller(t, CallerOptions{
		Authenticator: proxyAuthNoTable{fakeAuth{
			caller: purser.Caller{Identity: "sa:gateway"},
			source: purser.AuthSourceOIDC,
		}},
	})

	r := get()
	r.Header.Set(authn.HeaderAssertedCaller, "carol@example.com")
	got, rec := serve(t, mw, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body)
	}
	if got.caller.Identity != "carol@example.com" {
		t.Errorf("identity = %q, want carol@example.com", got.caller.Identity)
	}
	if got.proxyBy != "sa:gateway" {
		t.Errorf("proxy_by = %q, want sa:gateway", got.proxyBy)
	}
}

// ---------------------------------------------------------------
// Construction
// ---------------------------------------------------------------

// Each of these reads as "require a credential" and would behave as
// "do not". They are refused at construction because at runtime they
// are indistinguishable from a working enforced surface.
func TestNewCallerRefusesContradictoryEnforcement(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		opts CallerOptions
		want string
	}{
		{
			name: "no authenticator",
			opts: CallerOptions{Enforce: true},
			want: "nothing would ever be enforced",
		},
		{
			name: "a fallback that can never be reached",
			opts: CallerOptions{
				Enforce:       true,
				Authenticator: tableAuth(t),
				Fallback:      purser.Caller{Identity: "anon"},
			},
			want: "contradictory",
		},
		{
			name: "an authenticator that admits unverified requests",
			opts: CallerOptions{Enforce: true, Authenticator: authn.Anonymous{}},
			want: "GatesCredentials() == false",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			m, err := NewCaller(c.opts)
			if err == nil {
				t.Fatal("NewCaller accepted a contradictory configuration")
			}
			if m != nil {
				t.Error("NewCaller returned a middleware alongside an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %q, want it to mention %q", err, c.want)
			}
		})
	}
}

// The same options minus Enforce are all fine — the refusals above are
// about the combination, not about the fields.
func TestNewCallerAcceptsTheSameOptionsWithoutEnforce(t *testing.T) {
	t.Parallel()
	for i, opts := range []CallerOptions{
		{},
		{Authenticator: tableAuth(t), Fallback: purser.Caller{Identity: "anon"}},
		{Authenticator: authn.Anonymous{}},
	} {
		if _, err := NewCaller(opts); err != nil {
			t.Errorf("case %d: NewCaller: %v", i, err)
		}
	}
}

// ---------------------------------------------------------------
// What the bind policy is told
// ---------------------------------------------------------------

// The middleware answers for the surface, not for the authenticator.
// A bearer table truthfully reports that it gates credentials, and the
// surface in front of it still admits every anonymous request unless
// Enforce is set — so CheckBind has to be given the middleware.
func TestCallerGatesCredentialsTracksEnforce(t *testing.T) {
	t.Parallel()
	auth := tableAuth(t)

	if got := auth.GatesCredentials(); !got {
		t.Fatal("precondition: the bearer table should report that it gates credentials")
	}

	permissive := newCaller(t, CallerOptions{Authenticator: auth})
	if permissive.GatesCredentials() {
		t.Error("a non-enforcing middleware reported that it gates credentials")
	}
	if err := CheckBind("0.0.0.0:8443", permissive); err == nil {
		t.Error("CheckBind approved a network address in front of a surface that serves unauthenticated requests")
	}

	enforcing := newCaller(t, CallerOptions{Authenticator: auth, Enforce: true})
	if !enforcing.GatesCredentials() {
		t.Error("an enforcing middleware reported that it does not gate credentials")
	}
	if err := CheckBind("0.0.0.0:8443", enforcing); err != nil {
		t.Errorf("CheckBind refused an enforcing surface: %v", err)
	}

	// A nil middleware is "not configured", not a panic — the same
	// reading CheckBind gives a nil Gate.
	var none *CallerMiddleware
	if none.GatesCredentials() {
		t.Error("a nil *CallerMiddleware reported that it gates credentials")
	}
}

// Enforcement is the middleware's own property, so an authenticator
// that does not implement authn.CredentialGate — a future OIDC one —
// still yields a surface CheckBind will approve. The check this
// replaces had the opposite failure: it refused a listener that was
// enforcing perfectly well because it could not recognise how.
func TestCallerGatesCredentialsWithoutACredentialGate(t *testing.T) {
	t.Parallel()
	plain := fakeAuth{caller: purser.Caller{Identity: "peer"}, source: purser.AuthSourceOIDC}
	if _, ok := authn.Authenticator(plain).(authn.CredentialGate); ok {
		t.Fatal("precondition: this authenticator should not implement authn.CredentialGate")
	}

	m := newCaller(t, CallerOptions{Authenticator: plain, Enforce: true})
	if err := CheckBind("0.0.0.0:8443", m); err != nil {
		t.Errorf("CheckBind refused an enforcing surface: %v", err)
	}
}

// ---------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------

// fakeAuth is an authenticator with a fixed verdict, for the cases
// where a real one would only add setup.
type fakeAuth struct {
	caller purser.Caller
	err    error
	source purser.AuthSource
}

func (f fakeAuth) Authenticate(*http.Request) (purser.Caller, error) {
	if f.err != nil {
		return purser.Caller{}, f.err
	}
	return f.caller.Clone(), nil
}

func (f fakeAuth) Source() purser.AuthSource { return f.source }

// proxyAuthNoTable permits every caller to proxy and has no identity
// table, the shape a claim-based authenticator has. CanProxyAs is
// exactly the documented minimum, which is the point: the middleware,
// not the implementation, is what stops an unauthenticated request
// reaching it.
type proxyAuthNoTable struct{ fakeAuth }

func (proxyAuthNoTable) CanProxyAs(c purser.Caller) bool { return !c.IsZero() }

// alwaysProxy bolts proxy permission onto any authenticator.
type alwaysProxy struct{ authn.Authenticator }

func (alwaysProxy) CanProxyAs(purser.Caller) bool { return true }

// leakyLookup returns its table entries without cloning — the reading
// of authn.IdentityLookup that the contract now rules out and that the
// middleware defends against anyway.
type leakyLookup struct{ table map[string]purser.Caller }

func (l *leakyLookup) Authenticate(*http.Request) (purser.Caller, error) {
	return purser.Caller{Identity: "sa:gateway"}, nil
}
func (l *leakyLookup) Source() purser.AuthSource     { return purser.AuthSourceOIDC }
func (l *leakyLookup) CanProxyAs(purser.Caller) bool { return true }
func (l *leakyLookup) LookupIdentity(id string) (purser.Caller, bool) {
	c, ok := l.table[id]
	return c, ok
}

var (
	_ authn.Authenticator          = fakeAuth{}
	_ authn.AuthenticatorWithProxy = proxyAuthNoTable{}
	_ authn.AuthenticatorWithProxy = alwaysProxy{}
	_ authn.AuthenticatorWithProxy = (*leakyLookup)(nil)
	_ authn.IdentityLookup         = (*leakyLookup)(nil)
)
