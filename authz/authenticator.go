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
	"errors"
	"fmt"
	"net/http"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
)

// WithRules returns an Authenticator that applies rules to every Caller
// a resolves. It is what connects a rule set to a running surface:
// without it, Rules is data nothing consults.
//
//	auth, err := bearer.New(bearer.Options{Users: users})
//	rules, err := authz.NewRules(
//		authz.Rule{
//			Name:  "platform-admins",
//			Match: authz.MatchLabel("group", "platform-oncall"),
//			Admin: true,
//		},
//		authz.Rule{
//			Name:  "chat-bridge",
//			Match: authz.MatchIdentity("sa:slack-bot"),
//			Proxy: true,
//		},
//	)
//	auth, err := authz.WithRules(auth, rules)
//	caller, err := httpmw.NewCaller(httpmw.CallerOptions{Authenticator: auth, Enforce: true})
//
// Three things it does, and one it deliberately does not:
//
//   - A successful Authenticate has its Caller passed through
//     Rules.Apply, so the Admin bit reflects policy rather than
//     whatever the credential itself carried.
//   - CanProxyAs is the union of the rules and whatever the wrapped
//     authenticator already permitted, so a deployment moving from
//     bearer.Options.ProxyIdentities to rules can run both during the
//     migration and lose nobody.
//   - An asserted identity resolved through authn.IdentityLookup gets
//     the same treatment, so proxying to an identity does not silently
//     hand it a different set of grants than authenticating as it.
//   - It never grants anything to a caller nothing authenticated. Two
//     things enforce that, because one of them is not enough. Rules
//     themselves refuse the zero Caller and purser.AnonymousIdentity;
//     and WithRules refuses outright an authenticator that reports
//     purser.AuthSourceAnonymous, since applying policy to an
//     authenticator that verifies nothing means granting the Admin bit
//     to requests that presented no credential — authn.Anonymous
//     resolves every one of them to a Caller that is not zero and would
//     otherwise be matched like any other.
//
// # Preserving the optional interfaces
//
// authn's optional extensions are discovered by type assertion, so a
// decorator that implements too few of them silently downgrades the
// surface — and one that implements too many does the same. Both
// directions have teeth here: a wrapper that dropped
// authn.IdentityLookup would make httpmw take every asserted identity
// at face value instead of resolving it against the table, and a
// wrapper that added it to an authenticator with no table would make
// httpmw reject every assertion as unprovisioned.
//
// So the returned value implements exactly the extensions a implements,
// plus authn.AuthenticatorWithProxy, which rules may grant on their own
// — and which reads the same as not implementing it when neither the
// rules nor a permit anyone to proxy.
func WithRules(a authn.Authenticator, rules *Rules) (authn.Authenticator, error) {
	if a == nil {
		return nil, errors.New("authz: WithRules: Authenticator is nil; there is nothing for the rules to apply to")
	}
	if rules.Len() == 0 {
		return nil, errors.New("authz: WithRules: no rules; wrapping an authenticator in a rule set that grants nothing hides it behind an indirection that does nothing")
	}
	if src := a.Source(); src == purser.AuthSourceAnonymous {
		return nil, fmt.Errorf("authz: WithRules: %T reports Source() == %q: it verifies no credential, so every request it resolves would collect whatever the rules grant", a, src)
	}

	base := ruleAuth{inner: a, rules: rules}
	lookup, hasLookup := a.(authn.IdentityLookup)
	gate, hasGate := a.(authn.CredentialGate)
	switch {
	case hasLookup && hasGate:
		return ruleAuthLookupGate{ruleAuthLookup: ruleAuthLookup{ruleAuth: base, lookup: lookup}, gate: gate}, nil
	case hasLookup:
		return ruleAuthLookup{ruleAuth: base, lookup: lookup}, nil
	case hasGate:
		return ruleAuthGate{ruleAuth: base, gate: gate}, nil
	}
	return base, nil
}

// ruleAuth is the wrapper every variant embeds: an authenticator whose
// results pass through a rule set.
type ruleAuth struct {
	inner authn.Authenticator
	rules *Rules
}

var (
	_ authn.Authenticator          = ruleAuth{}
	_ authn.AuthenticatorWithProxy = ruleAuth{}
)

// Authenticate resolves the credential with the wrapped authenticator
// and applies the rules to the result.
func (w ruleAuth) Authenticate(r *http.Request) (purser.Caller, error) {
	c, err := w.inner.Authenticate(r)
	if err != nil {
		// Never a Caller alongside an error, whatever the wrapped
		// implementation returned: the contract says the two are
		// exclusive, and applying rules to a Caller that failed
		// authentication would be granting on the strength of a
		// credential that did not verify.
		return purser.Caller{}, err
	}
	return w.rules.Apply(c), nil
}

// Source reports the wrapped authenticator's credential class. Rules
// change what a caller may do, never how they authenticated.
func (w ruleAuth) Source() purser.AuthSource { return w.inner.Source() }

// CanProxyAs reports whether c may assert other identities, by the
// rules or by the wrapped authenticator's own allowlist.
func (w ruleAuth) CanProxyAs(c purser.Caller) bool {
	if unresolved(c) {
		return false
	}
	if w.rules.CanProxyAs(c) {
		return true
	}
	if p, ok := w.inner.(authn.AuthenticatorWithProxy); ok {
		return p.CanProxyAs(c)
	}
	return false
}

// ruleAuthLookup is the variant for a wrapped authenticator backed by a
// table of provisioned identities.
type ruleAuthLookup struct {
	ruleAuth
	lookup authn.IdentityLookup
}

var _ authn.IdentityLookup = ruleAuthLookup{}

// LookupIdentity resolves a provisioned identity and applies the rules
// to it, so an identity reached by proxy carries the same grants it
// would have carried had it authenticated directly.
func (w ruleAuthLookup) LookupIdentity(identity string) (purser.Caller, bool) {
	c, ok := w.lookup.LookupIdentity(identity)
	if !ok {
		return purser.Caller{}, false
	}
	return w.rules.Apply(c), true
}

// ruleAuthGate is the variant for a wrapped authenticator that declares
// itself a credential gate.
type ruleAuthGate struct {
	ruleAuth
	gate authn.CredentialGate
}

var _ authn.CredentialGate = ruleAuthGate{}

// GatesCredentials forwards the wrapped authenticator's answer. Rules
// grant capabilities to callers that authenticated; they have no view
// of whether one had to.
func (w ruleAuthGate) GatesCredentials() bool { return w.gate.GatesCredentials() }

// ruleAuthLookupGate is the variant for a wrapped authenticator that is
// both — the shape authn/bearer takes.
type ruleAuthLookupGate struct {
	ruleAuthLookup
	gate authn.CredentialGate
}

var (
	_ authn.IdentityLookup = ruleAuthLookupGate{}
	_ authn.CredentialGate = ruleAuthLookupGate{}
)

// GatesCredentials forwards the wrapped authenticator's answer.
func (w ruleAuthLookupGate) GatesCredentials() bool { return w.gate.GatesCredentials() }
