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
	"slices"
	"strings"
	"testing"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn/mtls"
	"github.com/go-steer/purser/authz"
)

// caller is a Caller with labels, spelled compactly for the matcher
// tables below.
func caller(identity string, labels map[string]string) purser.Caller {
	return purser.Caller{Identity: identity, Labels: labels}
}

func TestMatchIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		identities []string
		caller     purser.Caller
		want       bool
	}{
		{"exact", []string{"alice@example.com"}, caller("alice@example.com", nil), true},
		{"one of several", []string{"bob@example.com", "alice@example.com"}, caller("alice@example.com", nil), true},
		{"not listed", []string{"bob@example.com"}, caller("alice@example.com", nil), false},
		{"case sensitive", []string{"Alice@example.com"}, caller("alice@example.com", nil), false},
		{"prefix is not a match", []string{"alice@example.com"}, caller("alice@example.com.evil.test", nil), false},
		{"no identities matches nobody", nil, caller("alice@example.com", nil), false},
		{"only empty identities matches nobody", []string{"", ""}, caller("alice@example.com", nil), false},
		{"empty entry does not match an empty identity", []string{""}, purser.Caller{}, false},
		{"caller with no identity", []string{"alice@example.com"}, purser.Caller{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := authz.MatchIdentity(tt.identities...)(tt.caller); got != tt.want {
				t.Errorf("MatchIdentity(%q)(%q) = %v, want %v", tt.identities, tt.caller.Identity, got, tt.want)
			}
		})
	}
}

// TestMatchEmailDomainIsAnchored is the named adversarial case for the
// email side. strings.HasSuffix(identity, "example.com") admits
// alice@notexample.com, which is one domain registration away from
// being an admin grant.
func TestMatchEmailDomainIsAnchored(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		domain   string
		identity string
		want     bool
	}{
		{"in domain", "example.com", "alice@example.com", true},
		{"domain case is ignored", "EXAMPLE.com", "alice@example.COM", true},
		// strings.EqualFold would accept both of these: Unicode simple
		// folding maps U+017F and U+212A onto ASCII s and k, so a rule
		// naming a domain with an s or a k in it would be satisfied by a
		// separately registrable IDN domain.
		{"long s does not fold onto s", "slack.com", "attacker@ſlack.com", false},
		{"kelvin sign does not fold onto k", "slack.com", "attacker@slacK.com", false},
		{"a punycode domain matches its own bytes", "xn--80ak6aa92e.com", "alice@xn--80ak6aa92e.com", true},
		{"local part with an at sign takes the last one", "example.com", `"a@b"@example.com`, true},
		{"lookalike domain", "example.com", "alice@notexample.com", false},
		{"subdomain is a different domain", "example.com", "alice@corp.example.com", false},
		{"domain as a local part", "example.com", "example.com@evil.test", false},
		{"no at sign", "example.com", "sa:platform-agent", false},
		{"empty domain matches nobody", "", "alice@example.com", false},
		{"empty domain does not match a bare identity", "", "alice@", false},
		{"a domain carrying an at sign matches nobody", "@example.com", "alice@example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := authz.MatchEmailDomain(tt.domain)(caller(tt.identity, nil)); got != tt.want {
				t.Errorf("MatchEmailDomain(%q)(%q) = %v, want %v", tt.domain, tt.identity, got, tt.want)
			}
		})
	}
}

func TestMatchLabel(t *testing.T) {
	t.Parallel()

	labelled := caller("alice@example.com", map[string]string{"group": "platform", "iss": "https://accounts.example.com"})

	tests := []struct {
		name   string
		key    string
		values []string
		caller purser.Caller
		want   bool
	}{
		{"present with the value", "group", []string{"platform"}, labelled, true},
		{"one of several values", "group", []string{"storage", "platform"}, labelled, true},
		{"present with another value", "group", []string{"storage"}, labelled, false},
		{"absent label", "team", []string{"platform"}, labelled, false},
		{"no labels at all", "group", []string{"platform"}, caller("alice@example.com", nil), false},
		{"empty key matches nobody", "", []string{"platform"}, labelled, false},
		{"no values matches nobody", "group", nil, labelled, false},
		// The sharp one: Caller.Label returns "" for an absent label,
		// so an unset configuration value would otherwise match every
		// caller that does not carry the label at all.
		{"empty value matches nobody", "group", []string{""}, labelled, false},
		{"empty value does not match a caller without the label", "team", []string{""}, labelled, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := authz.MatchLabel(tt.key, tt.values...)(tt.caller); got != tt.want {
				t.Errorf("MatchLabel(%q, %q)(%+v) = %v, want %v", tt.key, tt.values, tt.caller.Labels, got, tt.want)
			}
		})
	}
}

// TestMatchPathIsSegmentAnchored is the escape the design names
// explicitly: substring and prefix matching on a structured path both
// admit identities the rule never meant to name.
func TestMatchPathIsSegmentAnchored(t *testing.T) {
	t.Parallel()

	const key = "spiffe.path"

	tests := []struct {
		name     string
		matcher  authz.Matcher
		path     string
		want     bool
		hazardOf string
	}{
		{
			name:    "prefix admits the namespace itself",
			matcher: authz.MatchPathPrefix(key, "ns", "prod"),
			path:    "/ns/prod",
			want:    true,
		},
		{
			name:    "prefix admits below the namespace",
			matcher: authz.MatchPathPrefix(key, "ns", "prod"),
			path:    "/ns/prod/sa/api",
			want:    true,
		},
		{
			name:     "prefix rejects a path that merely contains the segments",
			matcher:  authz.MatchPathPrefix(key, "ns", "prod"),
			path:     "/ns/attacker/x/ns/prod/sa/y",
			want:     false,
			hazardOf: `strings.Contains(path, "/ns/prod")`,
		},
		{
			name:     "prefix rejects a longer segment with the same start",
			matcher:  authz.MatchPathPrefix(key, "ns", "prod"),
			path:     "/ns/production/sa/api",
			want:     false,
			hazardOf: `strings.HasPrefix(path, "/ns/prod")`,
		},
		{
			name:    "segments match exactly",
			matcher: authz.MatchPathSegments(key, "ns", "prod", "sa", "api"),
			path:    "/ns/prod/sa/api",
			want:    true,
		},
		{
			name:    "segments do not match a longer path",
			matcher: authz.MatchPathSegments(key, "ns", "prod"),
			path:    "/ns/prod/sa/api",
			want:    false,
		},
		{
			name:    "a trailing separator is not a segment",
			matcher: authz.MatchPathSegments(key, "ns", "prod"),
			path:    "/ns/prod/",
			want:    true,
		},
		{
			name:    "an interior empty segment is not elided",
			matcher: authz.MatchPathSegments(key, "ns", "prod"),
			path:    "/ns//prod",
			want:    false,
		},
		{
			name:    "a segment carrying a separator matches nobody",
			matcher: authz.MatchPathPrefix(key, "ns/prod"),
			path:    "/ns/prod/sa/api",
			want:    false,
		},
		{
			name:    "an empty segment matches nobody",
			matcher: authz.MatchPathPrefix(key, "ns", ""),
			path:    "/ns/prod",
			want:    false,
		},
		{
			name:    "no segments matches nobody",
			matcher: authz.MatchPathPrefix(key),
			path:    "/ns/prod",
			want:    false,
		},
		{
			name:    "no segments does not match an empty path",
			matcher: authz.MatchPathSegments(key),
			path:    "",
			want:    false,
		},
		{
			name:    "an empty key matches nobody",
			matcher: authz.MatchPathPrefix("", "ns", "prod"),
			path:    "/ns/prod",
			want:    false,
		},
		{
			name:    "a caller carrying no such label",
			matcher: authz.MatchPathPrefix("other.path", "ns", "prod"),
			path:    "/ns/prod",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := caller("spiffe://example.org"+tt.path, map[string]string{key: tt.path})
			if got := tt.matcher(c); got != tt.want {
				msg := ""
				if tt.hazardOf != "" {
					msg = "; this is the case " + tt.hazardOf + " gets wrong"
				}
				t.Errorf("matcher(%q) = %v, want %v%s", tt.path, got, tt.want, msg)
			}
		})
	}
}

// TestMatchPathUsesTheLabelTheAuthenticatorSets pins the agreement
// between this package and the one that produces the labels. authz is
// stdlib-only and cannot import authn/mtls, so the key is an argument
// and nothing but a test can catch the two spellings drifting apart.
func TestMatchPathUsesTheLabelTheAuthenticatorSets(t *testing.T) {
	t.Parallel()

	c := caller("spiffe://example.org/ns/prod/sa/api", map[string]string{
		mtls.LabelTrustDomain: "example.org",
		mtls.LabelPath:        "/ns/prod/sa/api",
	})

	inProd := authz.MatchAll(
		authz.MatchLabel(mtls.LabelTrustDomain, "example.org"),
		authz.MatchPathPrefix(mtls.LabelPath, "ns", "prod"),
	)
	if !inProd(c) {
		t.Fatalf("a SPIFFE caller labelled by authn/mtls did not match a rule written against mtls.LabelPath (%q) and mtls.LabelTrustDomain (%q)",
			mtls.LabelPath, mtls.LabelTrustDomain)
	}
	// Same path, different trust domain: the path alone is not unique.
	other := caller("spiffe://evil.test/ns/prod/sa/api", map[string]string{
		mtls.LabelTrustDomain: "evil.test",
		mtls.LabelPath:        "/ns/prod/sa/api",
	})
	if inProd(other) {
		t.Error("a caller from another trust domain matched a rule pinned to example.org")
	}
}

func TestMatchCombinators(t *testing.T) {
	t.Parallel()

	alice := caller("alice@example.com", nil)
	yes := func(purser.Caller) bool { return true }
	no := func(purser.Caller) bool { return false }

	tests := []struct {
		name    string
		matcher authz.Matcher
		want    bool
	}{
		// The empty and nil cases all deny. Unset configuration closes
		// the door, with no exception for the combinator that would open
		// it widest: MatchAll(cfg.Matchers...) over a config section
		// nobody filled in is a grant to everybody.
		{"all of none matches nobody", authz.MatchAll(), false},
		{"all with every matcher matching", authz.MatchAll(yes, yes), true},
		{"all with one matcher failing", authz.MatchAll(yes, no), false},
		{"all treats a nil matcher as no match", authz.MatchAll(yes, nil), false},
		{"any of none matches nobody", authz.MatchAnyOf(), false},
		{"any with one matcher matching", authz.MatchAnyOf(no, yes), true},
		{"any with no matcher matching", authz.MatchAnyOf(no, no), false},
		{"any skips a nil matcher", authz.MatchAnyOf(nil, yes), true},
		{"any of only nil matchers matches nobody", authz.MatchAnyOf(nil, nil), false},
		{"not inverts", authz.MatchNot(no), true},
		{"not inverts a match", authz.MatchNot(yes), false},
		// Logically not(nobody) is everyone. Read that way, an exception
		// built from configuration that was never set would inflate into
		// a blanket grant, so it denies instead.
		{"not of nil matches nobody", authz.MatchNot(nil), false},
		// The limit of that defense, pinned so it is not mistaken for a
		// promise: a nil matcher is recognisable, an empty combinator is
		// just a closure that matches nobody, and negating one is
		// indistinguishable from deliberately negating a matcher that
		// happens to match nobody today.
		{"not of an empty conjunction still matches everyone", authz.MatchNot(authz.MatchAll()), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.matcher(alice); got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// TestMatchNotWritesTheException shows the shape the package
// recommends instead of an ordered deny rule: the exception lives in
// the matcher that grants.
func TestMatchNotWritesTheException(t *testing.T) {
	t.Parallel()

	const key = "spiffe.path"
	m := authz.MatchAll(
		authz.MatchPathPrefix(key, "ns", "prod"),
		authz.MatchNot(authz.MatchIdentity("spiffe://example.org/ns/prod/sa/batch")),
	)

	api := caller("spiffe://example.org/ns/prod/sa/api", map[string]string{key: "/ns/prod/sa/api"})
	batch := caller("spiffe://example.org/ns/prod/sa/batch", map[string]string{key: "/ns/prod/sa/batch"})

	if !m(api) {
		t.Error("the api workload did not match the namespace rule")
	}
	if m(batch) {
		t.Error("the excepted batch workload matched the namespace rule")
	}
}

func TestNewRulesRejectsUnusableRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		rules []authz.Rule
		want  string
	}{
		{
			name:  "no name",
			rules: []authz.Rule{{Match: authz.MatchAll(), Admin: true}},
			want:  "has no Name",
		},
		{
			name: "duplicate name",
			rules: []authz.Rule{
				{Name: "admins", Match: authz.MatchIdentity("a"), Admin: true},
				{Name: "admins", Match: authz.MatchIdentity("b"), Admin: true},
			},
			want: "declared twice",
		},
		{
			name:  "nil matcher",
			rules: []authz.Rule{{Name: "admins", Admin: true}},
			want:  "nil Match",
		},
		{
			name:  "grants nothing",
			rules: []authz.Rule{{Name: "admins", Match: authz.MatchAll()}},
			want:  "grants nothing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := authz.NewRules(tt.rules...)
			if err == nil {
				t.Fatalf("NewRules(%s) = %v, nil; want an error", tt.name, got)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("NewRules(%s) error = %q, want it to mention %q", tt.name, err, tt.want)
			}
		})
	}
}

// TestNewRulesCopiesTheRules pins that a caller mutating the slice it
// passed cannot rewrite policy in a running process.
func TestNewRulesCopiesTheRules(t *testing.T) {
	t.Parallel()

	given := []authz.Rule{{Name: "admins", Match: authz.MatchIdentity("alice@example.com"), Admin: true}}
	rules, err := authz.NewRules(given...)
	if err != nil {
		t.Fatalf("NewRules: %v", err)
	}
	given[0] = authz.Rule{Name: "mallory", Match: authz.MatchIdentity("mallory@example.com"), Admin: true}

	if got := rules.Apply(caller("mallory@example.com", nil)); got.Admin {
		t.Error("mutating the slice passed to NewRules changed what the rule set grants")
	}
}

func TestRulesGrant(t *testing.T) {
	t.Parallel()

	rules, err := authz.NewRules(
		authz.Rule{Name: "platform-admins", Match: authz.MatchLabel("group", "platform"), Admin: true},
		authz.Rule{Name: "chat-bridge", Match: authz.MatchIdentity("sa:slack-bot"), Proxy: true},
		authz.Rule{Name: "break-glass", Match: authz.MatchIdentity("ops@example.com"), Admin: true, Proxy: true},
	)
	if err != nil {
		t.Fatalf("NewRules: %v", err)
	}
	if got := rules.Len(); got != 3 {
		t.Errorf("Len() = %d, want 3", got)
	}

	tests := []struct {
		name       string
		caller     purser.Caller
		wantAdmin  bool
		wantProxy  bool
		wantRuleID []string
	}{
		{
			name:       "matched by a label rule",
			caller:     caller("alice@example.com", map[string]string{"group": "platform"}),
			wantAdmin:  true,
			wantRuleID: []string{"platform-admins"},
		},
		{
			name:       "matched by an identity rule",
			caller:     caller("sa:slack-bot", nil),
			wantProxy:  true,
			wantRuleID: []string{"chat-bridge"},
		},
		{
			name:       "one rule granting both",
			caller:     caller("ops@example.com", nil),
			wantAdmin:  true,
			wantProxy:  true,
			wantRuleID: []string{"break-glass"},
		},
		{
			name:       "two rules, union of the grants",
			caller:     caller("sa:slack-bot", map[string]string{"group": "platform"}),
			wantAdmin:  true,
			wantProxy:  true,
			wantRuleID: []string{"platform-admins", "chat-bridge"},
		},
		{
			name:   "matched by nothing",
			caller: caller("stranger@example.com", nil),
		},
		{
			name:   "no identity",
			caller: purser.Caller{Labels: map[string]string{"group": "platform"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := rules.Apply(tt.caller); got.Admin != tt.wantAdmin {
				t.Errorf("Apply(%q).Admin = %v, want %v", tt.caller.Identity, got.Admin, tt.wantAdmin)
			}
			if got := rules.CanProxyAs(tt.caller); got != tt.wantProxy {
				t.Errorf("CanProxyAs(%q) = %v, want %v", tt.caller.Identity, got, tt.wantProxy)
			}
			if got := rules.Matching(tt.caller); !slices.Equal(got, tt.wantRuleID) {
				t.Errorf("Matching(%q) = %v, want %v", tt.caller.Identity, got, tt.wantRuleID)
			}
		})
	}
}

// TestRulesNeverDemote pins that a rule set which grants nothing to a
// caller leaves an Admin bit somebody else set alone. A deployment
// migrating from bearer.Options.AdminIdentities to rules runs both for
// a release.
func TestRulesNeverDemote(t *testing.T) {
	t.Parallel()

	rules, err := authz.NewRules(authz.Rule{Name: "admins", Match: authz.MatchIdentity("alice@example.com"), Admin: true})
	if err != nil {
		t.Fatalf("NewRules: %v", err)
	}
	c := purser.Caller{Identity: "ops@example.com", Admin: true}
	if got := rules.Apply(c); !got.Admin {
		t.Error("Apply stripped the Admin bit from a caller no rule matched")
	}
}

// TestRulesDoNotMutateTheirArgument pins that Apply hands back a copy.
// The Caller it is given belongs to the request, and every matcher in
// the set sees the same one.
func TestRulesDoNotMutateTheirArgument(t *testing.T) {
	t.Parallel()

	rules, err := authz.NewRules(authz.Rule{Name: "admins", Match: authz.MatchIdentity("alice@example.com"), Admin: true})
	if err != nil {
		t.Fatalf("NewRules: %v", err)
	}
	c := caller("alice@example.com", map[string]string{"group": "platform"})
	got := rules.Apply(c)

	if c.Admin {
		t.Error("Apply set Admin on the Caller it was given")
	}
	if !got.Admin {
		t.Fatal("Apply did not grant Admin")
	}
	if got.Label("group") != "platform" {
		t.Errorf("Apply lost a label: %v", got.Labels)
	}
}

// TestApplySharesTheLabelMap pins the aliasing Apply documents rather
// than leaving a reader to assume the copy is deep. It is not: the
// returned Caller carries the argument's map, and a handler that writes
// to it writes to whatever else holds a reference. Apply does not clone
// because the Caller it is given already came from an authenticator
// that did — cloning again on every request would pay twice for the
// same guarantee — but a consumer building Callers by hand needs to
// know which it has.
func TestApplySharesTheLabelMap(t *testing.T) {
	t.Parallel()

	rules, err := authz.NewRules(authz.Rule{Name: "admins", Match: authz.MatchIdentity("alice@example.com"), Admin: true})
	if err != nil {
		t.Fatalf("NewRules: %v", err)
	}
	c := caller("alice@example.com", map[string]string{"group": "platform"})
	got := rules.Apply(c)

	got.Labels["group"] = "rewritten"
	if c.Label("group") != "rewritten" {
		t.Errorf("Apply's result no longer shares the argument's Labels map; the doc comment says it does "+
			"and tells consumers to Clone when they need it detached (argument now %q)", c.Label("group"))
	}
}

// TestAnExceptionMustMatchTheGrantsComparison pins a sharp edge rather
// than a defect, because the alternative is a consumer discovering it
// in production. MatchEmailDomain folds the case of the domain;
// MatchIdentity is byte-exact, as ACL membership is. An exception
// written in the narrower comparison leaves the account it names a way
// through — which is why MatchNot's doc says to except on the property
// the grant is written in.
func TestAnExceptionMustMatchTheGrantsComparison(t *testing.T) {
	t.Parallel()

	evadable := authz.MatchAll(
		authz.MatchEmailDomain("example.com"),
		authz.MatchNot(authz.MatchIdentity("mallory@example.com")),
	)
	if evadable(caller("mallory@example.com", nil)) {
		t.Error("the exception did not except the identity it names")
	}
	if !evadable(caller("Mallory@example.com", nil)) {
		t.Error("a case-varied identity was excepted; if purser has started folding identity case, " +
			"MatchNot's warning about mismatched comparisons is now stale and should be rewritten")
	}

	// The shape the doc recommends instead: except on the same property
	// the grant is written in, so both sides compare alike.
	sound := authz.MatchAll(
		authz.MatchLabel("team", "platform"),
		authz.MatchNot(authz.MatchLabel("role", "intern")),
	)
	if !sound(caller("alice@example.com", map[string]string{"team": "platform"})) {
		t.Error("the label rule did not match the caller it names")
	}
	if sound(caller("intern@example.com", map[string]string{"team": "platform", "role": "intern"})) {
		t.Error("the label exception did not except the caller it names")
	}
}

// TestNilRulesGrantNothing covers the service that has no rules
// configured and passes the nil *Rules around rather than a nil check.
func TestNilRulesGrantNothing(t *testing.T) {
	t.Parallel()

	var rules *authz.Rules
	c := caller("alice@example.com", nil)

	if rules.Len() != 0 {
		t.Errorf("(*Rules)(nil).Len() = %d, want 0", rules.Len())
	}
	if rules.Apply(c).Admin {
		t.Error("(*Rules)(nil).Apply granted Admin")
	}
	if rules.CanProxyAs(c) {
		t.Error("(*Rules)(nil).CanProxyAs = true")
	}
	if got := rules.Matching(c); got != nil {
		t.Errorf("(*Rules)(nil).Matching = %v, want nil", got)
	}
}

// TestRulesIgnoreAnUnauthenticatedCaller is the guard that matters
// most: a rule that tests something other than the identity must not
// hand grants to a Caller no authenticator produced.
//
// Two Callers qualify, and the second is the one that bites. The zero
// Caller is obvious. purser.Anonymous() is not zero — its Identity is
// "anon" — and it is what an unauthenticated request resolves to
// wherever anonymous access is allowed, so a matcher wide enough to
// cover it would grant on the strength of presenting nothing.
func TestRulesIgnoreAnUnauthenticatedCaller(t *testing.T) {
	t.Parallel()

	// The spelling for "everyone" that this package deliberately does
	// not supply, written out here because that is exactly the rule the
	// guard has to survive.
	everyone := authz.Matcher(func(purser.Caller) bool { return true })
	rules, err := authz.NewRules(authz.Rule{Name: "everyone", Match: everyone, Admin: true, Proxy: true})
	if err != nil {
		t.Fatalf("NewRules: %v", err)
	}

	for _, c := range []purser.Caller{
		{},
		purser.Anonymous(),
		{Identity: purser.AnonymousIdentity, Labels: map[string]string{"group": "platform"}},
	} {
		if rules.Apply(c).Admin {
			t.Errorf("a rule matching everyone granted Admin to Caller{Identity: %q}", c.Identity)
		}
		if rules.CanProxyAs(c) {
			t.Errorf("a rule matching everyone let Caller{Identity: %q} proxy", c.Identity)
		}
		if got := rules.Matching(c); got != nil {
			t.Errorf("Matching(Caller{Identity: %q}) = %v, want nil", c.Identity, got)
		}
	}

	// A caller an authenticator did resolve still gets the grant; the
	// guard is about who, not about switching the rule off.
	if !rules.Apply(caller("alice@example.com", nil)).Admin {
		t.Error("the rule did not apply to an authenticated caller")
	}
}
