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

package bearer_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
	"github.com/go-steer/purser/authn/bearer"
	"github.com/go-steer/purser/authtest"
)

const (
	aliceIdentity = "alice@example.com"
	aliceToken    = "alice-token-3f9c"
	botIdentity   = "sa:slack-bot"
	botToken      = "bot-token-71ad"
	carolIdentity = "carol@example.com"
	carolToken    = "carol-token-c0de"
)

// fixture builds the table every test in this file authenticates
// against: an admin human, a proxy-permitted bot, and a plain human who
// is neither.
func fixture(tb testing.TB) *bearer.Auth {
	tb.Helper()
	a, err := bearer.New(bearer.Options{
		Users: []bearer.User{
			{Identity: aliceIdentity, Token: aliceToken, Labels: map[string]string{"team": "platform"}},
			{Identity: botIdentity, Token: botToken},
			{Identity: carolIdentity, Token: carolToken, Labels: map[string]string{"team": "support"}},
		},
		AdminIdentities: []string{aliceIdentity},
		ProxyIdentities: []string{botIdentity},
	})
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	return a
}

// authorized returns a request presenting token in an Authorization
// header.
func authorized(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func TestConformance(t *testing.T) {
	t.Parallel()

	a := fixture(t)
	authtest.RunAuthenticatorSuite(t, authtest.Subject{
		Authenticator: a,
		WantSource:    purser.AuthSourceBearer,
		Valid: func() (*http.Request, purser.Caller) {
			return authorized(aliceToken), purser.Caller{
				Identity: aliceIdentity,
				Labels:   map[string]string{"team": "platform"},
				Admin:    true,
			}
		},
		Malformed: []authtest.MalformedCase{
			{Name: "unknown token", Request: func() *http.Request { return authorized("not-a-real-token") }},
			// A token sharing a long prefix with a real one. The digest
			// map makes this indistinguishable from any other miss; an
			// implementation that compared cleartext byte by byte would
			// leak the prefix length through timing.
			{Name: "near miss", Request: func() *http.Request { return authorized(aliceToken[:len(aliceToken)-1] + "x") }},
			{Name: "empty bearer value", Request: func() *http.Request { return authorized("") }},
			{Name: "wrong scheme", Request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Authorization", "Basic "+aliceToken)
				return r
			}},
			{Name: "scheme with no value", Request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Authorization", "Bearer")
				return r
			}},
			{Name: "token in the side-channel header", Request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set(bearer.HeaderAttachToken, "not-a-real-token")
				return r
			}},
		},
		ProxyDenied:           func() *http.Request { return authorized(carolToken) },
		UnprovisionedIdentity: "dave@example.com",
		ProvisionedIdentity:   aliceIdentity,
	})
}

func TestInterfaces(t *testing.T) {
	t.Parallel()

	a := fixture(t)
	if got := a.Source(); got != purser.AuthSourceBearer {
		t.Errorf("Source() = %q, want %q", got, purser.AuthSourceBearer)
	}
	// A bearer table verifies a secret, so a surface may treat it as
	// sufficient on its own; authn.Anonymous, which does not, reports
	// false. Getting this backwards would let a surface skip the
	// transport-level admission it still needs.
	if !a.GatesCredentials() {
		t.Error("GatesCredentials() = false, want true")
	}
	if got := a.Len(); got != 3 {
		t.Errorf("Len() = %d, want 3", got)
	}
}

func TestAuthenticateAcceptsEveryPresentationOfTheToken(t *testing.T) {
	t.Parallel()

	a := fixture(t)
	tests := []struct {
		name    string
		header  string
		value   string
		wantErr bool
	}{
		{"canonical scheme", "Authorization", "Bearer " + aliceToken, false},
		// RFC 7235 §2.1 makes the scheme case-insensitive; core-agent's
		// loader matched "Bearer " literally, so a client sending the
		// lowercase form was rejected for no good reason.
		{"lowercase scheme", "Authorization", "bearer " + aliceToken, false},
		{"uppercase scheme", "Authorization", "BEARER " + aliceToken, false},
		{"padded value", "Authorization", "Bearer   " + aliceToken + "  ", false},
		{"side-channel header", bearer.HeaderAttachToken, aliceToken, false},
		{"side-channel header padded", bearer.HeaderAttachToken, "  " + aliceToken + "  ", false},
		{"scheme is not a token", "Authorization", aliceToken, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set(tt.header, tt.value)

			c, err := a.Authenticate(r)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Authenticate() resolved %q, want rejection", c.Identity)
				}
				return
			}
			if err != nil {
				t.Fatalf("Authenticate() = %v, want success", err)
			}
			if c.Identity != aliceIdentity {
				t.Errorf("Authenticate() identity = %q, want %q", c.Identity, aliceIdentity)
			}
		})
	}
}

func TestAuthenticatePrefersTheSideChannelHeader(t *testing.T) {
	t.Parallel()

	// The header exists for deployments where an identity gateway owns
	// Authorization, so whatever is in Authorization there is not ours
	// to interpret.
	a := fixture(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(bearer.HeaderAttachToken, carolToken)
	r.Header.Set("Authorization", "Bearer "+aliceToken)

	c, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("Authenticate() = %v, want success", err)
	}
	if c.Identity != carolIdentity {
		t.Errorf("Authenticate() identity = %q, want %q from the side-channel header",
			c.Identity, carolIdentity)
	}
}

func TestAuthenticateFallsBackWhenTheSideChannelHeaderIsBlank(t *testing.T) {
	t.Parallel()

	a := fixture(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(bearer.HeaderAttachToken, "   ")
	r.Header.Set("Authorization", "Bearer "+aliceToken)

	c, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("Authenticate() = %v, want success", err)
	}
	if c.Identity != aliceIdentity {
		t.Errorf("Authenticate() identity = %q, want %q", c.Identity, aliceIdentity)
	}
}

func TestAuthenticateResolvesAdminAndLabels(t *testing.T) {
	t.Parallel()

	a := fixture(t)
	tests := []struct {
		name      string
		token     string
		wantID    string
		wantAdmin bool
		wantTeam  string
	}{
		{"admin", aliceToken, aliceIdentity, true, "platform"},
		{"not admin", carolToken, carolIdentity, false, "support"},
		{"no labels", botToken, botIdentity, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := a.Authenticate(authorized(tt.token))
			if err != nil {
				t.Fatalf("Authenticate() = %v, want success", err)
			}
			if c.Identity != tt.wantID {
				t.Errorf("identity = %q, want %q", c.Identity, tt.wantID)
			}
			if c.Admin != tt.wantAdmin {
				t.Errorf("admin = %v, want %v", c.Admin, tt.wantAdmin)
			}
			if got := c.Label("team"); got != tt.wantTeam {
				t.Errorf("label team = %q, want %q", got, tt.wantTeam)
			}
		})
	}
}

func TestAuthenticateErrorsAreUnauthenticated(t *testing.T) {
	t.Parallel()

	a := fixture(t)
	tests := []struct {
		name string
		req  *http.Request
	}{
		{"no credential", httptest.NewRequest(http.MethodGet, "/", nil)},
		{"unknown token", authorized("nope")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := a.Authenticate(tt.req)
			if !errors.Is(err, purser.ErrUnauthenticated) {
				t.Errorf("Authenticate() error = %v, want purser.ErrUnauthenticated", err)
			}
		})
	}
}

func TestNewRejectsUnsafeTables(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		users   []bearer.User
		wantErr string
	}{
		{
			// Would authenticate a request presenting no credential at
			// all, since extractToken returns "" for both.
			name:    "empty token",
			users:   []bearer.User{{Identity: aliceIdentity}},
			wantErr: "token is required",
		},
		{
			name:    "empty identity",
			users:   []bearer.User{{Token: aliceToken}},
			wantErr: "identity is required",
		},
		{
			// extractToken trims the header value, so a padded token can
			// never be presented. The row fails closed — safe, but the
			// operator sees a user who cannot log in and nothing that
			// says why.
			name:    "padded token",
			users:   []bearer.User{{Identity: aliceIdentity, Token: " " + aliceToken + "\n"}},
			wantErr: "leading or trailing whitespace",
		},
		{
			name:    "whitespace-only token",
			users:   []bearer.User{{Identity: aliceIdentity, Token: "   "}},
			wantErr: "leading or trailing whitespace",
		},
		{
			// Resolves to whichever row was written last, which is not a
			// property an operator can reason about.
			name: "duplicate token",
			users: []bearer.User{
				{Identity: aliceIdentity, Token: aliceToken},
				{Identity: carolIdentity, Token: aliceToken},
			},
			wantErr: "collides",
		},
		{
			name: "duplicate identity",
			users: []bearer.User{
				{Identity: aliceIdentity, Token: aliceToken},
				{Identity: aliceIdentity, Token: carolToken},
			},
			wantErr: "duplicate identity",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, err := bearer.New(bearer.Options{Users: tt.users})
			if err == nil {
				t.Fatalf("New() = %+v, want an error mentioning %q", a, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("New() error = %v, want it to mention %q", err, tt.wantErr)
			}
			if a != nil {
				t.Errorf("New() returned a non-nil Auth alongside an error")
			}
		})
	}
}

func TestNewRejectsATokenCollisionWithoutPrintingTheToken(t *testing.T) {
	t.Parallel()

	// The error reaches operator logs, which are not a place to put a
	// live credential.
	_, err := bearer.New(bearer.Options{Users: []bearer.User{
		{Identity: aliceIdentity, Token: aliceToken},
		{Identity: carolIdentity, Token: aliceToken},
	}})
	if err == nil {
		t.Fatal("New() = nil error, want a collision error")
	}
	if strings.Contains(err.Error(), aliceToken) {
		t.Errorf("New() error contains the token: %v", err)
	}
}

func TestNewToleratesPolicyIdentitiesAbsentFromTheTable(t *testing.T) {
	t.Parallel()

	// Admin and proxy lists are service-wide policy: a deployment
	// running a bearer table alongside an mTLS authenticator will list
	// identities this table has never heard of. Rejecting them would
	// make the two authenticators impossible to configure together.
	a, err := bearer.New(bearer.Options{
		Users:           []bearer.User{{Identity: aliceIdentity, Token: aliceToken}},
		AdminIdentities: []string{"spiffe://example.org/ns/prod/sa/api", ""},
		ProxyIdentities: []string{"sa:some-other-gateway", ""},
	})
	if err != nil {
		t.Fatalf("New() = %v, want success", err)
	}
	// The empty entries must not have become grants: an empty identity
	// is what a zero Caller carries.
	if a.CanProxyAs(purser.Caller{}) {
		t.Error("CanProxyAs(zero Caller) = true; an empty ProxyIdentities entry became a grant")
	}
	c, err := a.Authenticate(authorized(aliceToken))
	if err != nil {
		t.Fatalf("Authenticate() = %v, want success", err)
	}
	if c.Admin {
		t.Error("resolved caller is Admin; an empty AdminIdentities entry became a grant")
	}
}

func TestNewCopiesLabelsOutOfOptions(t *testing.T) {
	t.Parallel()

	// The caller of New keeps its Users slice. If the table held the
	// row's map, a later mutation would rewrite an identity the daemon
	// is already serving.
	labels := map[string]string{"team": "platform"}
	a, err := bearer.New(bearer.Options{
		Users: []bearer.User{{Identity: aliceIdentity, Token: aliceToken, Labels: labels}},
	})
	if err != nil {
		t.Fatalf("New() = %v, want success", err)
	}
	labels["team"] = "attacker"
	labels["admin"] = "true"

	c, err := a.Authenticate(authorized(aliceToken))
	if err != nil {
		t.Fatalf("Authenticate() = %v, want success", err)
	}
	if got := c.Label("team"); got != "platform" {
		t.Errorf("label team = %q, want %q: the table aliases the Options map", got, "platform")
	}
	if got := c.Label("admin"); got != "" {
		t.Errorf("label admin = %q, want it absent: the table aliases the Options map", got)
	}
}

func TestNewAcceptsAnEmptyTable(t *testing.T) {
	t.Parallel()

	// "Authenticate nobody" is a legitimate state for a table another
	// authenticator supplements. NewFromFile is the one that treats it
	// as a truncated file.
	a, err := bearer.New(bearer.Options{})
	if err != nil {
		t.Fatalf("New() = %v, want success", err)
	}
	if got := a.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0", got)
	}
	if _, err := a.Authenticate(authorized(aliceToken)); !errors.Is(err, purser.ErrUnauthenticated) {
		t.Errorf("Authenticate() against an empty table = %v, want purser.ErrUnauthenticated", err)
	}
}

func TestCanProxyAs(t *testing.T) {
	t.Parallel()

	a := fixture(t)
	tests := []struct {
		name string
		in   purser.Caller
		want bool
	}{
		{"allowlisted", purser.Caller{Identity: botIdentity}, true},
		{"provisioned but not allowlisted", purser.Caller{Identity: aliceIdentity}, false},
		{"unprovisioned", purser.Caller{Identity: "dave@example.com"}, false},
		{"zero caller", purser.Caller{}, false},
		// Admin is a role, not a proxy grant: an operator who can see
		// everything still must not be able to act as someone else
		// without being listed.
		{"admin", purser.Caller{Identity: aliceIdentity, Admin: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := a.CanProxyAs(tt.in); got != tt.want {
				t.Errorf("CanProxyAs(%+v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestLookupIdentity(t *testing.T) {
	t.Parallel()

	a := fixture(t)

	c, ok := a.LookupIdentity(aliceIdentity)
	if !ok {
		t.Fatalf("LookupIdentity(%q) = not found", aliceIdentity)
	}
	// The asserted caller must carry everything a direct
	// authentication would have: a proxied admin who arrives without
	// their Admin bit is a silent privilege loss, and a proxied caller
	// without labels breaks label-based authorization rules.
	if c.Identity != aliceIdentity {
		t.Errorf("identity = %q, want %q", c.Identity, aliceIdentity)
	}
	if !c.Admin {
		t.Error("admin = false, want true: the looked-up caller lost its role")
	}
	if got := c.Label("team"); got != "platform" {
		t.Errorf("label team = %q, want %q", got, "platform")
	}

	for _, id := range []string{"", "dave@example.com", aliceToken} {
		if got, ok := a.LookupIdentity(id); ok {
			t.Errorf("LookupIdentity(%q) = (%q, true), want not found", id, got.Identity)
		}
	}
}

// TestLookupIdentityDoesNotTakeTokens pins that the two maps are keyed
// separately: a token is not an identity, and a client that discovered
// one must not be able to assert its way in through the proxy header.
func TestLookupIdentityDoesNotTakeTokens(t *testing.T) {
	t.Parallel()

	a := fixture(t)
	if c, ok := a.LookupIdentity(aliceToken); ok {
		t.Errorf("LookupIdentity(<a token>) = (%q, true), want not found", c.Identity)
	}
}

func TestImplementsTheOptionalInterfaces(t *testing.T) {
	t.Parallel()

	// A surface feature-detects these; losing one is a silent
	// downgrade rather than a compile error at the consumer.
	var a authn.Authenticator = fixture(t)
	if _, ok := a.(authn.AuthenticatorWithProxy); !ok {
		t.Error("*bearer.Auth does not implement authn.AuthenticatorWithProxy")
	}
	if _, ok := a.(authn.IdentityLookup); !ok {
		t.Error("*bearer.Auth does not implement authn.IdentityLookup")
	}
	if _, ok := a.(authn.CredentialGate); !ok {
		t.Error("*bearer.Auth does not implement authn.CredentialGate")
	}
}
