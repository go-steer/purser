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

package authz

import (
	"fmt"
	"strings"

	"github.com/go-steer/purser"
)

// This file is the answer to the objection that motivated purser: a
// per-identity row does not scale. core-agent grants the admin bit and
// the right to proxy from two exact-match []string lists, which have to
// be edited every time somebody joins, leaves, or is re-issued an
// identity — the same failure mode as the token table they sit next to.
//
// A Rule states the property instead of the person: everyone in this
// SPIFFE namespace, everyone whose OIDC token came from this issuer with
// this group claim, everyone whose certificate this CA signed. The
// exact-match list remains expressible — MatchIdentity is the degenerate
// rule — so a deployment can port its configuration unchanged and
// generalize it later.
//
// Every matcher here is anchored. The tempting shorthands are all
// wrong on structured identities: strings.Contains(path, "/ns/prod")
// admits spiffe://td/ns/attacker/x/ns/prod/sa/y, and
// strings.HasSuffix(identity, "example.com") admits
// alice@notexample.com. Both are one registration or one deployment
// away from being an authorization bypass, so purser ships the
// structured form rather than leaving each consumer to hand-roll it.

// Matcher reports whether a Caller has some property. It is the unit a
// Rule is built from.
//
// It is a function type, so a consumer with a predicate purser cannot
// anticipate simply writes one:
//
//	var afterHours authz.Matcher = func(c purser.Caller) bool { … }
//
// A Matcher must not mutate the Caller it is given, and in particular
// must not write to its Labels: the map is shared with the request's
// own Caller and with every other matcher in the list.
type Matcher func(c purser.Caller) bool

// MatchIdentity matches a caller whose Identity is exactly one of
// identities. This is the degenerate rule — the exact-match list
// core-agent configures today, expressible unchanged.
//
// The comparison is byte for byte, with no case folding and no
// normalization, the same discipline ACL membership uses. An identity
// is an opaque string minted by an authenticator, and purser is not the
// layer that knows whether "Alice@example.com" and "alice@example.com"
// are one person — canonicalizing it is the authenticator's job, at the
// point where the credential's own rules are known. The consequence is
// stated on MatchNot, where it has teeth.
//
// With no identities, or only empty ones, it matches nobody: a list
// that came back empty from configuration must not read as "anyone".
func MatchIdentity(identities ...string) Matcher {
	want := make(map[string]struct{}, len(identities))
	for _, id := range identities {
		if id == "" {
			continue
		}
		want[id] = struct{}{}
	}
	return func(c purser.Caller) bool {
		if c.Identity == "" {
			return false
		}
		_, ok := want[c.Identity]
		return ok
	}
}

// MatchEmailDomain matches a caller whose Identity is an email address
// in domain — the shape an OIDC token or an email-SAN client
// certificate produces.
//
// The match is anchored on the last "@", which is the difference
// between "@example.com" and every attacker-registered domain ending in
// those characters. An empty domain, or one containing "@", matches
// nobody.
//
// The domain is compared case-insensitively — DNS labels are — but
// only over ASCII. strings.EqualFold applies Unicode simple folding,
// under which "ſlack.com" (U+017F) equals "slack.com" and "slacK.com"
// (U+212A, the Kelvin sign) equals "slack.com": separately registrable
// IDN domains that would satisfy a rule naming neither. Folding only
// A–Z keeps the comparison to what DNS actually treats as equal. A
// non-ASCII domain therefore matches only its exact bytes; configure
// such a domain in punycode, the form a certificate or an OIDC claim
// carries anyway.
//
// The local part is not examined at all. Only the domain is folded, so
// this matcher is deliberately wider than MatchIdentity in a way that
// matters when the two are combined — see MatchNot.
func MatchEmailDomain(domain string) Matcher {
	valid := domain != "" && !strings.Contains(domain, "@")
	return func(c purser.Caller) bool {
		if !valid {
			return false
		}
		at := strings.LastIndex(c.Identity, "@")
		if at < 0 {
			return false
		}
		return equalFoldASCII(c.Identity[at+1:], domain)
	}
}

// equalFoldASCII reports whether a and b are equal under ASCII case
// folding. Bytes outside A–Z and a–z must match exactly, so no Unicode
// character folds onto an ASCII one. See MatchEmailDomain.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

// lowerASCII lowercases one ASCII letter and leaves every other byte,
// including every byte of a multi-byte rune, untouched.
func lowerASCII(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// MatchLabel matches a caller carrying key with any of values.
//
// Labels are where the credential's structure lives: the SPIFFE trust
// domain and path (mtls.LabelTrustDomain, mtls.LabelPath), the issuing
// CA and serial (mtls.LabelIssuerDN, mtls.LabelSerial), and an OIDC
// token's residual claims. The key is an argument rather than a
// constant declared here because this package is stdlib-only and the
// packages that set those labels are not — a second spelling of
// "spiffe.path" living here is exactly the drift that would make a rule
// silently stop matching.
//
// An empty key, no values, or only empty values match nobody. The empty
// value is the sharp one: purser.Caller.Label returns "" for a label
// that is absent, so a rule written as MatchLabel("group", cfg.Group)
// with Group unset would otherwise match every caller that has no group
// at all.
func MatchLabel(key string, values ...string) Matcher {
	want := make(map[string]struct{}, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		want[v] = struct{}{}
	}
	valid := key != "" && len(want) > 0
	return func(c purser.Caller) bool {
		if !valid {
			return false
		}
		got := c.Label(key)
		if got == "" {
			return false
		}
		_, ok := want[got]
		return ok
	}
}

// MatchPathSegments matches a caller whose label named by key is
// exactly the slash-joined segments — MatchPathSegments(mtls.LabelPath,
// "ns", "prod", "sa", "api") matches the caller whose SPIFFE ID path is
// /ns/prod/sa/api, in any trust domain.
//
// Pair it with MatchLabel(mtls.LabelTrustDomain, td) inside MatchAll to
// pin the trust domain too. A path is only unique within one.
//
// Segments are passed separately rather than as one "/ns/prod/sa/api"
// string so that a segment interpolated from configuration cannot
// smuggle a separator in and widen the rule. An empty segment, a
// segment containing "/", or no segments at all yield a matcher that
// matches nobody.
func MatchPathSegments(key string, segments ...string) Matcher {
	want, valid := joinSegments(segments)
	return func(c purser.Caller) bool {
		if !valid || key == "" {
			return false
		}
		return normalizePath(c.Label(key)) == want
	}
}

// MatchPathPrefix matches a caller whose label named by key is those
// segments or lies beneath them: MatchPathPrefix(mtls.LabelPath, "ns",
// "prod") matches /ns/prod and /ns/prod/sa/api, and does not match
// /ns/production.
//
// The prefix is anchored on a segment boundary, which is the whole
// difference between "the prod namespace" and "any namespace whose name
// starts with prod". As with MatchPathSegments, an invalid or empty
// segment list matches nobody.
func MatchPathPrefix(key string, segments ...string) Matcher {
	want, valid := joinSegments(segments)
	return func(c purser.Caller) bool {
		if !valid || key == "" {
			return false
		}
		got := normalizePath(c.Label(key))
		return got == want || strings.HasPrefix(got, want+"/")
	}
}

// MatchAll matches a caller every matcher matches. With no matchers,
// or with any nil matcher among them, it matches nobody.
//
// That empty case is the opposite of mtls.MatchCertAll's, deliberately.
// An admission matcher is an *additional* restriction on a peer the TLS
// stack already verified, so an empty conjunction there removes a
// constraint and admits what verification already allowed. Here the
// conjunction is the entire predicate of a grant, so an empty one would
// *be* the grant — MatchAll(cfg.Matchers...) over a configuration
// section nobody filled in would hand the Admin bit to every caller.
// The rule of this package is that unset configuration closes the door,
// and it does not get an exception for the case that would silently
// open it widest.
//
// A rule that genuinely applies to every caller therefore has no
// spelling in this package. Write the predicate in the consuming
// service, where it is visible in the source and turns up in a review:
//
//	Match: func(purser.Caller) bool { return true }
func MatchAll(matchers ...Matcher) Matcher {
	return func(c purser.Caller) bool {
		if len(matchers) == 0 {
			return false
		}
		for _, m := range matchers {
			if m == nil || !m(c) {
				return false
			}
		}
		return true
	}
}

// MatchAnyOf matches a caller any matcher matches. With no matchers, or
// only nil ones, it matches nobody — an empty disjunction offers no way
// in, and neither does an empty conjunction here. See MatchAll.
func MatchAnyOf(matchers ...Matcher) Matcher {
	return func(c purser.Caller) bool {
		for _, m := range matchers {
			if m != nil && m(c) {
				return true
			}
		}
		return false
	}
}

// MatchNot matches a caller m does not match. A nil m matches nobody,
// the same as everywhere else in this package: an exception that was
// never configured must not inflate into a blanket grant, which is what
// the logically pure reading — not(nobody) is everyone — would make of
// it. Only a nil is recognisable that way. MatchNot(MatchAll()) is an
// empty conjunction negated, and a closure that matches nobody cannot
// be told from one that deliberately matches nobody today, so it does
// mean everyone. Build the exception's matcher directly rather than
// through a combinator over a slice that may be empty.
//
// It exists so that an exception can be written into the rule that
// grants — "everyone in this namespace except the batch account" —
// rather than by ordering a deny rule ahead of an allow rule. Rules are
// a union and have no deny, which is what makes their order irrelevant
// and their meaning independent of how a configuration file happened to
// be assembled.
//
// # An exception must be as wide as the grant it sits inside
//
// The matchers here do not all compare the same way: MatchEmailDomain
// folds the case of the domain, MatchIdentity and ACL membership are
// byte-exact. An exception written in a narrower comparison than the
// grant leaves a gap, and the gap is the account the exception names:
//
//	// evadable: "Mallory@example.com" is granted and not excepted
//	MatchAll(
//		MatchEmailDomain("example.com"),
//		MatchNot(MatchIdentity("mallory@example.com")),
//	)
//
// Whether that is reachable depends on whether the identity's own
// spelling is pinned — an authenticator that canonicalizes what it
// mints leaves nothing to evade, and one that copies an OIDC claim
// through unchanged may not. Where it is not pinned, except on the
// property the grant is written in (the label, the path prefix, the
// domain) rather than on an identity string, or write the exception's
// own comparison as a Matcher of your own.
func MatchNot(m Matcher) Matcher {
	return func(c purser.Caller) bool {
		return m != nil && !m(c)
	}
}

// joinSegments builds the path a matcher compares against. valid is
// false for an empty list or a segment that is empty or carries a
// separator — the cases where the pattern came from configuration that
// was never set, and where matching would widen rather than narrow.
func joinSegments(segments []string) (path string, valid bool) {
	if len(segments) == 0 {
		return "", false
	}
	for _, s := range segments {
		if s == "" || strings.Contains(s, "/") {
			return "", false
		}
	}
	return "/" + strings.Join(segments, "/"), true
}

// normalizePath puts a label's value in the form joinSegments produces:
// leading and trailing separators trimmed, then one leading separator
// added back. Interior separators are left alone, so "/ns//prod" stays
// distinct from "/ns/prod" and cannot be matched by a pattern for the
// latter.
func normalizePath(v string) string {
	return "/" + strings.Trim(v, "/")
}

// Rule grants a capability to every caller its Matcher matches.
//
// A rule can only grant. There is no deny, and so no precedence to get
// wrong: the effect of a rule list is the union of the rules that
// match, and reordering the list cannot change a decision. An exception
// is expressed inside the matcher with MatchNot, where it is visible in
// the rule that grants rather than in the distance between two rules.
type Rule struct {
	// Name identifies the rule in diagnostics and audit records —
	// Rules.Matching returns these. It is required and must be unique
	// within a rule set: a grant that cannot be named in a log line is
	// a grant nobody can trace back to the configuration that made it.
	Name string

	// Match selects the callers this rule applies to. Required; nil is
	// refused by NewRules rather than read as "everyone" or "nobody".
	// No matcher in this package matches every caller — see MatchAll.
	Match Matcher

	// Admin grants purser.Caller.Admin — the see-everything role,
	// authz.RoleAdmin against every ACL.
	Admin bool

	// Proxy grants the right to act on behalf of other identities via
	// the asserted-caller header. See WithRules, which is what connects
	// this to an authenticator, and authn.AuthenticatorWithProxy for
	// what the capability means.
	Proxy bool
}

// Rules is an evaluated rule set. It is safe for concurrent use and
// immutable after NewRules; a nil *Rules grants nothing, so a service
// that has not configured any can pass one around without a nil check.
type Rules struct {
	rules []Rule
}

// NewRules validates and freezes a rule set.
//
// It refuses a rule with no Name, a duplicate Name, a nil Match, or one
// that grants nothing. Each is a rule that either cannot be traced or
// cannot do anything, and every one of them is far more likely to be a
// half-finished configuration than an intent — so it fails at startup
// rather than at the first request that needed it.
//
// The rules are copied, so a caller may reuse or modify its slice.
func NewRules(rules ...Rule) (*Rules, error) {
	seen := make(map[string]struct{}, len(rules))
	for i, r := range rules {
		switch {
		case r.Name == "":
			return nil, fmt.Errorf("authz: NewRules: rule %d has no Name; a grant that cannot be named cannot be audited", i)
		case r.Match == nil:
			return nil, fmt.Errorf("authz: NewRules: rule %q has a nil Match; a rule that selects nobody cannot be distinguished from one somebody forgot to finish", r.Name)
		case !r.Admin && !r.Proxy:
			return nil, fmt.Errorf("authz: NewRules: rule %q grants nothing; set Admin, Proxy, or remove it", r.Name)
		}
		if _, dup := seen[r.Name]; dup {
			return nil, fmt.Errorf("authz: NewRules: rule %q is declared twice; names identify a grant in audit records and must be unique", r.Name)
		}
		seen[r.Name] = struct{}{}
	}
	return &Rules{rules: append([]Rule(nil), rules...)}, nil
}

// Len reports how many rules the set holds. Useful to a surface logging
// its configuration at startup.
func (r *Rules) Len() int {
	if r == nil {
		return 0
	}
	return len(r.rules)
}

// Apply returns c with the grants its matching rules confer — today,
// the Admin bit.
//
// It never demotes. A caller that already arrived with Admin keeps it,
// because rules compose with whatever set it rather than overruling
// them: a deployment migrating from an authenticator's own admin list
// to rules runs both for a release, and a rule set that had not been
// written yet must not quietly strip an operator's access.
//
// A caller nothing authenticated gets nothing — see evaluate for what
// that means and why the check is not simply IsZero.
//
// Labels are read, by any rule that matches on one, and the map is not
// copied: the returned Caller shares the argument's. Call
// purser.Caller.Clone if you need to detach it.
func (r *Rules) Apply(c purser.Caller) purser.Caller {
	admin, _ := r.evaluate(c)
	if admin {
		c.Admin = true
	}
	return c
}

// CanProxyAs reports whether c is granted the right to assert other
// identities. It is false for a caller nothing authenticated, whatever
// the rules say, which is the contract authn.AuthenticatorWithProxy
// states.
func (r *Rules) CanProxyAs(c purser.Caller) bool {
	_, proxy := r.evaluate(c)
	return proxy
}

// Matching returns the names of the rules that match c, in declaration
// order, for the audit record that explains why a caller had the access
// it did. It returns nil when none match — including for a caller
// nothing authenticated, which no rule is ever evaluated against.
func (r *Rules) Matching(c purser.Caller) []string {
	if r == nil || unresolved(c) {
		return nil
	}
	var names []string
	for _, rule := range r.rules {
		if rule.Match(c) {
			names = append(names, rule.Name)
		}
	}
	return names
}

// evaluate is the single place a rule set is walked. The guard against
// granting to a caller nothing authenticated lives here so that no
// exported method can be the one that forgot it.
func (r *Rules) evaluate(c purser.Caller) (admin, proxy bool) {
	if r == nil || unresolved(c) {
		return false, false
	}
	for _, rule := range r.rules {
		// Short-circuit only once both bits are set: every rule is
		// evaluated otherwise, because a later one may grant what an
		// earlier one did not.
		if admin && proxy {
			return true, true
		}
		if !rule.Match(c) {
			continue
		}
		admin = admin || rule.Admin
		proxy = proxy || rule.Proxy
	}
	return admin, proxy
}

// unresolved reports whether c is a Caller no authenticator resolved,
// and which therefore collects no grants however the rules are written.
//
// Two spellings, because there are two ways to have not authenticated.
// The zero Caller is the obvious one. purser.AnonymousIdentity is the
// one worth the extra line: it is the identity purser hands an
// unauthenticated request where anonymous access is allowed, so a rule
// naming it — or any matcher wide enough to cover it — would grant on
// the strength of having presented nothing. authn.Anonymous resolves
// every request to exactly that Caller, and WithRules refuses to wrap
// it for the same reason, but a service composing Rules by hand does
// not go through WithRules and this is the layer that cannot be
// bypassed.
//
// A deployment that configured some other fallback identity is covered
// by the same WithRules refusal, which keys on the authenticator's
// AuthSource rather than on the identity's spelling.
func unresolved(c purser.Caller) bool {
	return c.IsZero() || c.Identity == purser.AnonymousIdentity
}
