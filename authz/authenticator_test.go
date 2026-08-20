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

package authz_test

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
	"github.com/go-steer/purser/authn/bearer"
	"github.com/go-steer/purser/authtest"
	"github.com/go-steer/purser/authz"
	"github.com/go-steer/purser/httpmw"
)

// The fixture the tests below share: a token table with a human and a
// bot, and a rule set that makes the human an admin by label and lets
// the bot proxy by identity. Neither grant is in the token table, which
// is the point — rules are how a deployment expresses policy without
// reissuing credentials.
const (
	aliceToken = "alice-token-0123456789"
	botToken   = "bot-token-0123456789"
	aliceID    = "alice@example.com"
	botID      = "sa:slack-bot"
	strangerID = "stranger@example.com"
)

func newBearer(t *testing.T, opts ...func(*bearer.Options)) *bearer.Auth {
	t.Helper()

	o := bearer.Options{
		Users: []bearer.User{
			{Identity: aliceID, Token: aliceToken, Labels: map[string]string{"group": "platform"}},
			{Identity: botID, Token: botToken},
		},
	}
	for _, fn := range opts {
		fn(&o)
	}
	a, err := bearer.New(o)
	if err != nil {
		t.Fatalf("bearer.New: %v", err)
	}
	return a
}

func newRules(t *testing.T) *authz.Rules {
	t.Helper()

	rules, err := authz.NewRules(
		authz.Rule{Name: "platform-admins", Match: authz.MatchLabel("group", "platform"), Admin: true},
		authz.Rule{Name: "chat-bridge", Match: authz.MatchIdentity(botID), Proxy: true},
	)
	if err != nil {
		t.Fatalf("NewRules: %v", err)
	}
	return rules
}

func tokenRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// TestWithRulesPassesTheConformanceSuite runs the authenticator
// contract against the decorated authenticator, not just the one it
// wraps. A decorator is an authenticator; nothing about wrapping one
// exempts it from the floor every implementation is held to.
func TestWithRulesPassesTheConformanceSuite(t *testing.T) {
	t.Parallel()

	wrapped, err := authz.WithRules(newBearer(t), newRules(t))
	if err != nil {
		t.Fatalf("WithRules: %v", err)
	}

	authtest.RunAuthenticatorSuite(t, authtest.Subject{
		Authenticator: wrapped,
		WantSource:    purser.AuthSourceBearer,
		Valid: func() (*http.Request, purser.Caller) {
			// Admin is true by rule, not by the table: bearer.Options
			// here names no AdminIdentities.
			return tokenRequest(aliceToken), purser.Caller{
				Identity: aliceID,
				Labels:   map[string]string{"group": "platform"},
				Admin:    true,
			}
		},
		Malformed: []authtest.MalformedCase{
			{Name: "unknown token", Request: func() *http.Request { return tokenRequest("not-a-real-token") }},
			{Name: "empty token", Request: func() *http.Request { return tokenRequest("") }},
			{Name: "wrong scheme", Request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Authorization", "Basic "+aliceToken)
				return r
			}},
		},
		// alice authenticates fine and may not proxy: the proxy rule
		// names the bot.
		ProxyDenied:           func() *http.Request { return tokenRequest(aliceToken) },
		ProvisionedIdentity:   aliceID,
		UnprovisionedIdentity: strangerID,
	})
}

// TestWithRulesPreservesTheOptionalInterfaces is the test the four-way
// type switch in WithRules exists for. Both directions are failures:
// an extension dropped changes how httpmw treats an assertion, and an
// extension invented does the same.
func TestWithRulesPreservesTheOptionalInterfaces(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		inner      authn.Authenticator
		wantLookup bool
		wantGate   bool
	}{
		{"plain", plainAuth{}, false, false},
		{"lookup only", lookupAuth{}, true, false},
		{"gate only", gateAuth{}, false, true},
		{"lookup and gate", lookupGateAuth{}, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := authz.WithRules(tt.inner, newRules(t))
			if err != nil {
				t.Fatalf("WithRules: %v", err)
			}
			if _, ok := got.(authn.IdentityLookup); ok != tt.wantLookup {
				t.Errorf("wrapping a %s authenticator: implements authn.IdentityLookup = %v, want %v",
					tt.name, ok, tt.wantLookup)
			}
			if _, ok := got.(authn.CredentialGate); ok != tt.wantGate {
				t.Errorf("wrapping a %s authenticator: implements authn.CredentialGate = %v, want %v",
					tt.name, ok, tt.wantGate)
			}
			// Always, whatever the inner authenticator does: rules may
			// grant the right to proxy on their own.
			if _, ok := got.(authn.AuthenticatorWithProxy); !ok {
				t.Errorf("wrapping a %s authenticator: does not implement authn.AuthenticatorWithProxy", tt.name)
			}
		})
	}
}

func TestWithRulesAppliesRulesToAuthenticate(t *testing.T) {
	t.Parallel()

	wrapped, err := authz.WithRules(newBearer(t), newRules(t))
	if err != nil {
		t.Fatalf("WithRules: %v", err)
	}

	c, err := wrapped.Authenticate(tokenRequest(aliceToken))
	if err != nil {
		t.Fatalf("Authenticate(alice): %v", err)
	}
	if c.Identity != aliceID {
		t.Errorf("Identity = %q, want %q", c.Identity, aliceID)
	}
	if !c.Admin {
		t.Error("Admin = false; the platform-admins rule matches alice's group label")
	}
	if got := c.Label("group"); got != "platform" {
		t.Errorf("Label(group) = %q, want platform; the rules dropped the labels", got)
	}
	if got := wrapped.Source(); got != purser.AuthSourceBearer {
		t.Errorf("Source() = %q, want %q; rules change what a caller may do, not how they authenticated",
			got, purser.AuthSourceBearer)
	}

	// The bot matches no admin rule and stays unprivileged.
	bot, err := wrapped.Authenticate(tokenRequest(botToken))
	if err != nil {
		t.Fatalf("Authenticate(bot): %v", err)
	}
	if bot.Admin {
		t.Error("the bot came back Admin; no rule grants it")
	}
}

func TestWithRulesAppliesRulesToLookupIdentity(t *testing.T) {
	t.Parallel()

	wrapped, err := authz.WithRules(newBearer(t), newRules(t))
	if err != nil {
		t.Fatalf("WithRules: %v", err)
	}
	lookup, ok := wrapped.(authn.IdentityLookup)
	if !ok {
		t.Fatal("wrapping bearer.Auth dropped authn.IdentityLookup")
	}

	c, found := lookup.LookupIdentity(aliceID)
	if !found {
		t.Fatalf("LookupIdentity(%q) not found", aliceID)
	}
	if !c.Admin {
		t.Error("an identity reached by lookup did not get the grant it gets by authenticating; " +
			"proxying to a caller must not change what that caller is")
	}
	if _, found := lookup.LookupIdentity(strangerID); found {
		t.Errorf("LookupIdentity(%q) resolved an identity nobody provisioned", strangerID)
	}
}

func TestWithRulesProxyIsTheUnionWithTheInnerAllowlist(t *testing.T) {
	t.Parallel()

	// The deployment mid-migration: a legacy ProxyIdentities entry the
	// rules do not repeat, and a rule the token table knows nothing of.
	inner := newBearer(t, func(o *bearer.Options) { o.ProxyIdentities = []string{aliceID} })
	wrapped, err := authz.WithRules(inner, newRules(t))
	if err != nil {
		t.Fatalf("WithRules: %v", err)
	}
	proxy, ok := wrapped.(authn.AuthenticatorWithProxy)
	if !ok {
		t.Fatal("the wrapper does not implement authn.AuthenticatorWithProxy")
	}

	tests := []struct {
		name   string
		caller purser.Caller
		want   bool
	}{
		{"granted by a rule", purser.Caller{Identity: botID}, true},
		{"granted by the wrapped allowlist", purser.Caller{Identity: aliceID}, true},
		{"granted by neither", purser.Caller{Identity: strangerID}, false},
		{"no identity", purser.Caller{}, false},
		{"no identity but Admin", purser.Caller{Admin: true}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := proxy.CanProxyAs(tt.caller); got != tt.want {
				t.Errorf("CanProxyAs(%q) = %v, want %v", tt.caller.Identity, got, tt.want)
			}
		})
	}
}

// TestWithRulesReturnsNoCallerWithAnError pins that a misbehaving
// wrapped authenticator — one returning a Caller alongside an error,
// which the contract forbids — cannot get that Caller past the
// decorator with rules applied to it.
func TestWithRulesReturnsNoCallerWithAnError(t *testing.T) {
	t.Parallel()

	inner := plainAuth{
		caller: purser.Caller{Identity: aliceID, Labels: map[string]string{"group": "platform"}},
		err:    purser.ErrUnauthenticated,
	}
	wrapped, err := authz.WithRules(inner, newRules(t))
	if err != nil {
		t.Fatalf("WithRules: %v", err)
	}

	c, err := wrapped.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, purser.ErrUnauthenticated) {
		t.Errorf("Authenticate error = %v, want purser.ErrUnauthenticated", err)
	}
	if !c.IsZero() {
		t.Errorf("Authenticate returned Caller %+v alongside an error; a credential that did not "+
			"verify must not collect grants", c)
	}
}

func TestWithRulesRejectsUnusableArguments(t *testing.T) {
	t.Parallel()

	empty, err := authz.NewRules()
	if err != nil {
		t.Fatalf("NewRules(): %v", err)
	}

	tests := []struct {
		name  string
		auth  authn.Authenticator
		rules *authz.Rules
		want  string
	}{
		{"nil authenticator", nil, newRules(t), "Authenticator is nil"},
		{"nil rules", plainAuth{}, nil, "no rules"},
		{"empty rules", plainAuth{}, empty, "no rules"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := authz.WithRules(tt.auth, tt.rules)
			if err == nil {
				t.Fatalf("WithRules(%s) = %v, nil; want an error", tt.name, got)
			}
			if got != nil {
				t.Errorf("WithRules(%s) returned %v alongside an error", tt.name, got)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("WithRules(%s) error = %q, want it to mention %q", tt.name, err, tt.want)
			}
		})
	}
}

func TestWithRulesForwardsGatesCredentials(t *testing.T) {
	t.Parallel()

	for _, gates := range []bool{true, false} {
		t.Run(fmt.Sprint(gates), func(t *testing.T) {
			t.Parallel()

			wrapped, err := authz.WithRules(gateAuth{gates: gates}, newRules(t))
			if err != nil {
				t.Fatalf("WithRules: %v", err)
			}
			gate, ok := wrapped.(authn.CredentialGate)
			if !ok {
				t.Fatal("the wrapper dropped authn.CredentialGate")
			}
			if got := gate.GatesCredentials(); got != gates {
				t.Errorf("GatesCredentials() = %v, want %v", got, gates)
			}
		})
	}
}

// TestWithRulesRefusesAnAuthenticatorThatVerifiesNothing is the guard
// against the composition that reads as policy and behaves as a
// giveaway. authn.Anonymous resolves every request — including one
// carrying no credential at all — to purser.Anonymous(), whose Identity
// is "anon" and therefore not the zero Caller that Rules screens out on
// its own. Wrapping it in a rule set wide enough to match would put the
// Admin bit on unauthenticated requests, so the composition is refused
// where it is written rather than defended per request.
func TestWithRulesRefusesAnAuthenticatorThatVerifiesNothing(t *testing.T) {
	t.Parallel()

	if got, err := authz.WithRules(authn.Anonymous{}, newRules(t)); err == nil {
		t.Errorf("WithRules(authn.Anonymous{}, rules) = %v, nil; want an error", got)
	}

	// Belt and braces: even reaching the rules directly with what such
	// an authenticator produces grants nothing.
	everyone := authz.Matcher(func(purser.Caller) bool { return true })
	rules, err := authz.NewRules(authz.Rule{Name: "everyone", Match: everyone, Admin: true, Proxy: true})
	if err != nil {
		t.Fatalf("NewRules: %v", err)
	}
	if rules.Apply(purser.Anonymous()).Admin {
		t.Error("a rule matching everyone granted Admin to the anonymous identity")
	}
}

// TestWithRulesDoesNotInventACredentialGate is the other half of the
// interface-preservation contract, at the surface where it bites. An
// authenticator that admits unverified requests must keep saying so
// through the wrapper, so that httpmw.NewCaller still refuses to call
// the surface enforced — and CheckBind still refuses to call it safe to
// bind off loopback.
func TestWithRulesDoesNotInventACredentialGate(t *testing.T) {
	t.Parallel()

	auth, err := authz.WithRules(gateAuth{
		plainAuth: plainAuth{caller: purser.Caller{Identity: aliceID}},
		gates:     false,
	}, newRules(t))
	if err != nil {
		t.Fatalf("WithRules: %v", err)
	}
	gate, ok := auth.(authn.CredentialGate)
	if !ok {
		t.Fatal("the wrapper dropped authn.CredentialGate")
	}
	if gate.GatesCredentials() {
		t.Error("the wrapper reports that an authenticator admitting unverified requests gates credentials")
	}
	if _, err := httpmw.NewCaller(httpmw.CallerOptions{Authenticator: auth, Enforce: true}); err == nil {
		t.Error("NewCaller accepted Enforce over a wrapped authenticator that gates no credentials")
	}
}

// TestWithRulesThroughTheMiddleware is the composition the package
// exists for, end to end: a token table that grants nothing, a rule set
// that grants everything policy says, and httpmw resolving requests
// against the pair.
func TestWithRulesThroughTheMiddleware(t *testing.T) {
	t.Parallel()

	auth, err := authz.WithRules(newBearer(t), newRules(t))
	if err != nil {
		t.Fatalf("WithRules: %v", err)
	}
	mw, err := httpmw.NewCaller(httpmw.CallerOptions{Authenticator: auth, Enforce: true})
	if err != nil {
		t.Fatalf("NewCaller: %v", err)
	}
	// The wrapper kept authn.CredentialGate, so the middleware is
	// willing to say this surface is safe to bind off loopback.
	if !mw.GatesCredentials() {
		t.Error("the middleware does not report gating credentials; the wrapper lost authn.CredentialGate")
	}

	srv := httptest.NewServer(mw.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := purser.CallerFromContext(r.Context())
		if !ok {
			http.Error(w, "no caller on the context", http.StatusInternalServerError)
			return
		}
		by, _ := purser.ProxyByFromContext(r.Context())
		src, _ := purser.AuthSourceFromContext(r.Context())
		fmt.Fprintf(w, "%s admin=%v by=%q src=%s", c.Identity, c.Admin, by, src)
	})))
	t.Cleanup(srv.Close)

	tests := []struct {
		name     string
		token    string
		asserted string
		wantCode int
		wantBody string
	}{
		{
			name:     "a rule makes the caller an admin",
			token:    aliceToken,
			wantCode: http.StatusOK,
			wantBody: `alice@example.com admin=true by="" src=bearer`,
		},
		{
			name:     "an unmatched caller is nobody in particular",
			token:    botToken,
			wantCode: http.StatusOK,
			wantBody: `sa:slack-bot admin=false by="" src=bearer`,
		},
		{
			name:     "a rule lets the bot assert the human",
			token:    botToken,
			asserted: aliceID,
			wantCode: http.StatusOK,
			// The asserted Caller carries the grants it would have had
			// authenticating directly, and the bot's identity is kept
			// alongside it for the audit record.
			wantBody: `alice@example.com admin=true by="sa:slack-bot" src=asserted`,
		},
		{
			name:     "no rule lets the human assert anyone",
			token:    aliceToken,
			asserted: botID,
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "the bot may not assert an identity nobody provisioned",
			token:    botToken,
			asserted: strangerID,
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "no credential",
			wantCode: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			if tt.asserted != "" {
				req.Header.Set(authn.HeaderAssertedCaller, tt.asserted)
			}

			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantCode {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantCode)
			}
			if tt.wantBody == "" {
				return
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("reading the body: %v", err)
			}
			if got := string(body); got != tt.wantBody {
				t.Errorf("body = %q, want %q", got, tt.wantBody)
			}
		})
	}
}

// The authenticators below exist to produce each combination of authn's
// optional extensions. They are separate types rather than one type
// with flags because the extensions are discovered by type assertion,
// and a single type either has the method or does not.

type plainAuth struct {
	caller purser.Caller
	err    error
}

func (a plainAuth) Authenticate(*http.Request) (purser.Caller, error) {
	if a.err != nil {
		return a.caller, a.err
	}
	if a.caller.IsZero() {
		return purser.Caller{}, purser.ErrUnauthenticated
	}
	return a.caller, nil
}

func (plainAuth) Source() purser.AuthSource { return purser.AuthSourceBearer }

type lookupAuth struct{ plainAuth }

func (lookupAuth) LookupIdentity(string) (purser.Caller, bool) { return purser.Caller{}, false }

type gateAuth struct {
	plainAuth
	gates bool
}

func (a gateAuth) GatesCredentials() bool { return a.gates }

type lookupGateAuth struct{ lookupAuth }

func (lookupGateAuth) GatesCredentials() bool { return true }
