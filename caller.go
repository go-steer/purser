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

package purser

import (
	"context"
	"errors"
	"maps"
)

// Caller is the identity attached to every request entering an
// authenticated surface. It is the output of an authn.Authenticator and
// the input to authorization and audit.
//
// Identity is a stable opaque ID. Its shape depends on the credential
// that produced it: an email ("alice@example.com") for OIDC or an
// email-SAN client certificate, a SPIFFE ID
// ("spiffe://example.org/ns/prod/sa/api") for the SPIFFE mTLS profile,
// a service-account marker ("sa:platform-agent") for the bearer table,
// or "anon" for unauthenticated requests where anonymous access is
// allowed. Identity is the only field compared for equality; consumers
// must not parse it to recover structure that Labels already carries.
//
// Labels carry free-form metadata from the credential — the OIDC
// issuer and residual claims, a certificate's issuer DN and serial, a
// SPIFFE trust domain and path. They are available to authorization
// rules and audit consumers.
//
// Labels must be treated as read-only by everything downstream of the
// authenticator. An authenticator that resolves a Caller from a static
// table would otherwise hand every request a pointer into its own
// state, where one consumer's mutation silently rewrites another
// caller's metadata. Authenticators that retain their Labels maps
// return Clone; consumers that need to add a label call Clone
// themselves. The authtest conformance suite checks this.
//
// Admin grants the see-everything role. It is set by the consuming
// service's policy (authz rules), never by a credential's own claim —
// a token that could assert its own admin bit would be a privilege
// escalation.
type Caller struct {
	Identity string
	Labels   map[string]string
	Admin    bool
}

// Clone returns a deep copy of c: the returned Caller shares no map
// with the receiver, so the caller may mutate its Labels freely.
// Cloning a Caller with nil Labels yields nil Labels.
func (c Caller) Clone() Caller {
	c.Labels = maps.Clone(c.Labels)
	return c
}

// Label returns the value of the named label, or "" when absent. A
// convenience over indexing a possibly-nil map.
func (c Caller) Label(key string) string {
	return c.Labels[key]
}

// IsZero reports whether c carries no identity. A zero Caller is never
// a valid authentication result — an authenticator that returns one
// alongside a nil error has a bug, which the authtest conformance
// suite rejects.
func (c Caller) IsZero() bool {
	return c.Identity == ""
}

// AnonymousIdentity is the Identity of the conventional unauthenticated
// Caller. Compare against it rather than against a Caller value: Caller
// contains a map and so is not comparable with ==.
const AnonymousIdentity = "anon"

// Anonymous returns the conventional Caller for unauthenticated
// requests where anonymous access is allowed. Consumers may configure a
// different default identity, but "anon" is the documented one.
//
// It is a function rather than a package-level variable so that no
// importer can reassign the identity every unauthenticated request in
// the process resolves to. Each call returns a fresh value carrying no
// Labels, so there is no shared map to alias either.
func Anonymous() Caller {
	return Caller{Identity: AnonymousIdentity}
}

// ErrUnauthenticated is returned by an Authenticator when no valid
// credential is present on the request. HTTP surfaces map it to 401.
//
// It deliberately does not distinguish "no credential presented" from
// "credential presented but invalid": the difference is useful to an
// attacker probing which identities exist and useless to a legitimate
// client, which must retry with a good credential either way.
var ErrUnauthenticated = errors.New("purser: unauthenticated")

// ErrAssertedCallerForbidden is returned when a Caller that is not
// permitted to proxy attempts to assert another identity. Surfaces map
// it to 401 and should log the attempt: it indicates either
// misconfiguration or a credential that should not be assertable.
var ErrAssertedCallerForbidden = errors.New("purser: caller is not permitted to assert identities")

// ErrAssertedCallerUnknown is returned when a proxy-permitted Caller
// asserts an identity that is not provisioned. Surfaces map it to 401.
var ErrAssertedCallerUnknown = errors.New("purser: asserted identity is not provisioned")

type callerKey struct{}
type proxyByKey struct{}

// WithCaller returns a copy of ctx carrying c. Called by the
// middleware that resolved the request's Caller; downstream code reads
// it back with CallerFromContext.
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerFromContext returns the Caller stored on ctx by WithCaller. ok
// is false when no Caller is present — a code path reached before the
// authentication middleware, or a handler exercised directly in a
// test. Absence must be treated as unauthenticated, never as a
// permissive default.
func CallerFromContext(ctx context.Context) (c Caller, ok bool) {
	c, ok = ctx.Value(callerKey{}).(Caller)
	return c, ok
}

// WithProxyBy returns a copy of ctx carrying the proxying identity
// alongside the effective Caller, so audit records capture both: the
// human the request acts for and the credential that asserted them
// (effective="alice@example.com", proxy_by="sa:slack-bot").
//
// Pair it with WithCaller, which carries the effective identity.
func WithProxyBy(ctx context.Context, by string) context.Context {
	return context.WithValue(ctx, proxyByKey{}, by)
}

// ProxyByFromContext returns the proxying identity stored on ctx by
// WithProxyBy. ok is false, and the string empty, when the request did
// not take the proxy path.
func ProxyByFromContext(ctx context.Context) (by string, ok bool) {
	by, ok = ctx.Value(proxyByKey{}).(string)
	if !ok || by == "" {
		return "", false
	}
	return by, true
}
