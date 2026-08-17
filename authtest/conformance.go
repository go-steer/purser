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

package authtest

import (
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
)

// canaryLabel is written into a Caller's Labels to detect an
// authenticator handing out a map it retains. Prefixed so it cannot
// collide with a real label.
const canaryLabel = "purser.authtest/canary"

// unprovisioned is an identity no real deployment provisions, used to
// probe default-deny paths.
const unprovisioned = "purser.authtest/unprovisioned-identity"

// Subject describes an Authenticator under test, plus the minimum a
// caller must supply for the suite to exercise it: one request that
// must succeed, and at least one that must fail.
//
// The failing cases are not optional politeness. An authenticator that
// is only ever shown a good credential passes identically to one whose
// verification is commented out.
type Subject struct {
	// Authenticator under test. Required.
	Authenticator authn.Authenticator

	// WantSource is the credential class Authenticator must report.
	// Required: an authenticator whose Source is not pinned by a test
	// can start mis-reporting how requests were authenticated without
	// anything failing.
	WantSource purser.AuthSource

	// Valid returns a request carrying a credential Authenticator must
	// accept, and the Caller it must resolve to. Called repeatedly, so
	// it must return an equivalent fresh request each time.
	//
	// Only Identity and Admin are compared, plus Labels when the
	// returned Caller carries any — a subject that does not care about
	// Labels returns none.
	//
	// Required unless AcceptsUncredentialed.
	Valid func() (*http.Request, purser.Caller)

	// Malformed returns requests whose credentials must be rejected:
	// the wrong token, a truncated header, a certificate lacking the
	// configured subject field. Required unless AcceptsUncredentialed.
	Malformed []MalformedCase

	// AcceptsUncredentialed marks an authenticator that resolves every
	// request by design, such as authn.Anonymous. It inverts the
	// no-credential check and waives the requirement for failing
	// cases. Set it only for an authenticator that verifies nothing;
	// setting it to quiet the suite disables the checks that matter.
	AcceptsUncredentialed bool

	// ProxyDenied returns a request whose credential is valid but not
	// permitted to assert other identities. Optional; only meaningful
	// for an authenticator implementing authn.AuthenticatorWithProxy.
	ProxyDenied func() *http.Request

	// UnprovisionedIdentity is an identity the authenticator's table
	// does not contain. Optional; only meaningful for an
	// authenticator implementing authn.IdentityLookup.
	UnprovisionedIdentity string

	// ProvisionedIdentity is an identity the authenticator's table does
	// contain. Optional; only meaningful for an authenticator
	// implementing authn.IdentityLookup, where it lets the suite check
	// that a looked-up Caller aliases no table state — the same hazard
	// as on the Authenticate path, reached instead through the proxy
	// path that materializes an asserted Caller.
	ProvisionedIdentity string
}

// MalformedCase is one credential that must be rejected.
type MalformedCase struct {
	// Name identifies the case in test output.
	Name string
	// Request returns the request carrying the bad credential.
	Request func() *http.Request
}

// reporter is the subset of testing.TB the individual checks use.
//
// It is an interface, rather than *testing.T, so that this package's
// own tests can run every check against a deliberately broken
// authenticator and assert the check reports a failure. A conformance
// suite that has never been observed to fail is not known to work —
// the same reason the repository's review gate was proven in both
// directions before it was trusted.
type reporter interface {
	Helper()
	Errorf(format string, args ...any)
}

// check is one named property of the Authenticator contract.
type check struct {
	name string
	run  func(r reporter, s Subject)
}

// checks is the conformance contract, in the order it is run.
var checks = []check{
	{"Subject", checkSubject},
	{"Source", checkSource},
	{"NoCredential", checkNoCredential},
	{"ValidCredential", checkValidCredential},
	{"MalformedCredential", checkMalformedCredential},
	{"LabelsNotAliased", checkLabelsNotAliased},
	{"ProxyDefaultDeny", checkProxyDefaultDeny},
	{"UnknownAssertedIdentity", checkUnknownAssertedIdentity},
	{"Concurrent", checkConcurrent},
}

// RunAuthenticatorSuite runs the conformance suite against s. Every
// authn.Authenticator, in this module and in consuming repositories,
// is expected to pass it:
//
//	func TestMyAuth(t *testing.T) {
//	    authtest.RunAuthenticatorSuite(t, authtest.Subject{
//	        Authenticator: myAuth,
//	        WantSource:    purser.AuthSourceBearer,
//	        Valid:         func() (*http.Request, purser.Caller) { ... },
//	        Malformed:     []authtest.MalformedCase{ ... },
//	    })
//	}
//
// Passing the suite is a floor, not a substitute for tests of what the
// authenticator specifically does. The suite knows nothing about
// issuers, claims, or trust domains.
func RunAuthenticatorSuite(t *testing.T, s Subject) {
	t.Helper()

	if s.Authenticator == nil {
		t.Fatalf("authtest: Subject.Authenticator is nil")
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			c.run(t, s)
		})
	}
}

// checkSubject reports a Subject that cannot exercise the contract,
// separately from the authenticator's own behavior — otherwise an
// under-specified subject reads as a passing authenticator.
func checkSubject(r reporter, s Subject) {
	r.Helper()
	if s.WantSource == "" {
		r.Errorf("Subject.WantSource is unset: the reported auth source is unpinned")
	}
	if s.AcceptsUncredentialed {
		return
	}
	if s.Valid == nil {
		r.Errorf("Subject.Valid is nil: no credential the authenticator must accept")
	}
	if len(s.Malformed) == 0 {
		r.Errorf("Subject.Malformed is empty: no credential the authenticator must reject, " +
			"so the suite cannot tell verification from a no-op")
	}
}

// checkSource pins the reported credential class, and that it does not
// change between calls.
func checkSource(r reporter, s Subject) {
	r.Helper()
	got := s.Authenticator.Source()
	if got == "" {
		r.Errorf("Source() = %q, want a non-empty credential class", got)
		return
	}
	if !got.Known() {
		r.Errorf("Source() = %q, which purser does not define; add a constant in source.go "+
			"rather than inventing a value the rest of the stack cannot interpret", got)
	}
	if s.WantSource != "" && got != s.WantSource {
		r.Errorf("Source() = %q, want %q", got, s.WantSource)
	}
	if again := s.Authenticator.Source(); again != got {
		r.Errorf("Source() = %q on first call, %q on second: it must be constant", got, again)
	}
}

// checkNoCredential covers the request that presents nothing.
func checkNoCredential(r reporter, s Subject) {
	r.Helper()
	c, err := s.Authenticator.Authenticate(bareRequest())

	if s.AcceptsUncredentialed {
		if err != nil {
			r.Errorf("Authenticate(no credential) = %v, want success "+
				"(Subject.AcceptsUncredentialed is set)", err)
			return
		}
		if c.IsZero() {
			r.Errorf("Authenticate(no credential) returned a zero Caller with a nil error; " +
				"an authenticator that resolves every request must resolve to some identity")
		}
		return
	}

	if !errors.Is(err, purser.ErrUnauthenticated) {
		r.Errorf("Authenticate(no credential) error = %v, want purser.ErrUnauthenticated", err)
	}
	if !c.IsZero() {
		r.Errorf("Authenticate(no credential) returned Caller %q alongside an error; "+
			"a consumer that ignores the error would act on an unverified identity", c.Identity)
	}
}

// checkValidCredential covers the request that must be accepted.
func checkValidCredential(r reporter, s Subject) {
	r.Helper()
	if s.Valid == nil {
		return // reported by checkSubject
	}
	req, want := s.Valid()
	got, err := s.Authenticator.Authenticate(req)
	if err != nil {
		r.Errorf("Authenticate(valid credential) = %v, want success", err)
		return
	}
	if got.IsZero() {
		r.Errorf("Authenticate(valid credential) returned a zero Caller with a nil error; " +
			"downstream code reads a non-error result as proof of identity")
		return
	}
	if got.Identity != want.Identity {
		r.Errorf("Authenticate(valid credential) identity = %q, want %q", got.Identity, want.Identity)
	}
	if got.Admin != want.Admin {
		r.Errorf("Authenticate(valid credential) admin = %v, want %v", got.Admin, want.Admin)
	}
	if len(want.Labels) > 0 && !maps.Equal(got.Labels, want.Labels) {
		r.Errorf("Authenticate(valid credential) labels = %v, want %v", got.Labels, want.Labels)
	}
}

// checkMalformedCredential covers credentials that must be rejected —
// without panicking, since the bytes are attacker-controlled.
func checkMalformedCredential(r reporter, s Subject) {
	r.Helper()
	for _, mc := range s.Malformed {
		c, panicked, err := authenticateNoPanic(s.Authenticator, mc.Request())
		if panicked != nil {
			r.Errorf("Authenticate(malformed %q) panicked: %v", mc.Name, panicked)
			continue
		}
		if err == nil {
			r.Errorf("Authenticate(malformed %q) succeeded as %q, want rejection", mc.Name, c.Identity)
			continue
		}
		if !errors.Is(err, purser.ErrUnauthenticated) {
			r.Errorf("Authenticate(malformed %q) error = %v, want purser.ErrUnauthenticated so "+
				"surfaces can map it to 401", mc.Name, err)
		}
		if !c.IsZero() {
			r.Errorf("Authenticate(malformed %q) returned Caller %q alongside an error",
				mc.Name, c.Identity)
		}
	}
}

// checkLabelsNotAliased catches an authenticator handing every request
// a map into its own state, where one consumer's mutation rewrites
// another caller's metadata. It probes both paths that hand out a
// Caller: Authenticate, and LookupIdentity where implemented.
func checkLabelsNotAliased(r reporter, s Subject) {
	r.Helper()
	checkAuthenticateLabelsNotAliased(r, s)
	checkLookupLabelsNotAliased(r, s)
}

func checkAuthenticateLabelsNotAliased(r reporter, s Subject) {
	r.Helper()
	if s.Valid == nil {
		return // reported by checkSubject
	}
	req, _ := s.Valid()
	first, err := s.Authenticator.Authenticate(req)
	if err != nil || len(first.Labels) == 0 {
		return // nothing resolved, or no labels to alias
	}
	first.Labels[canaryLabel] = "written by the conformance suite"

	req, _ = s.Valid()
	second, err := s.Authenticator.Authenticate(req)
	if err != nil {
		return
	}
	if _, leaked := second.Labels[canaryLabel]; leaked {
		r.Errorf("Labels from a previous Authenticate alias the authenticator's own state: "+
			"mutating one caller's labels changed a later caller's (%q is present). "+
			"Return purser.Caller.Clone when resolving from a table", canaryLabel)
	}
}

// checkLookupLabelsNotAliased covers the proxy path. A table-backed
// authenticator typically returns a cloned Caller from Authenticate and
// then hands out the raw table entry from LookupIdentity, because the
// two are written months apart.
func checkLookupLabelsNotAliased(r reporter, s Subject) {
	r.Helper()
	l, ok := s.Authenticator.(authn.IdentityLookup)
	if !ok || s.ProvisionedIdentity == "" {
		return
	}
	first, found := l.LookupIdentity(s.ProvisionedIdentity)
	if !found {
		r.Errorf("LookupIdentity(%q) = not-found, but Subject.ProvisionedIdentity names an "+
			"identity the table is expected to contain", s.ProvisionedIdentity)
		return
	}
	if first.IsZero() {
		r.Errorf("LookupIdentity(%q) returned a zero Caller with found=true", s.ProvisionedIdentity)
		return
	}
	if len(first.Labels) == 0 {
		return // no labels to alias
	}
	first.Labels[canaryLabel] = "written by the conformance suite"

	second, found := l.LookupIdentity(s.ProvisionedIdentity)
	if !found {
		return
	}
	if _, leaked := second.Labels[canaryLabel]; leaked {
		r.Errorf("Labels from LookupIdentity alias the authenticator's own table: mutating a "+
			"looked-up caller's labels changed a later lookup's (%q is present). "+
			"Return purser.Caller.Clone from LookupIdentity too", canaryLabel)
	}
}

// checkProxyDefaultDeny pins that proxy permission is granted, never
// assumed.
func checkProxyDefaultDeny(r reporter, s Subject) {
	r.Helper()
	p, ok := s.Authenticator.(authn.AuthenticatorWithProxy)
	if !ok {
		return // not implementing the interface denies every assertion
	}
	if p.CanProxyAs(purser.Caller{}) {
		r.Errorf("CanProxyAs(zero Caller) = true; an unresolved caller must never reach the proxy path")
	}
	if p.CanProxyAs(purser.Caller{Identity: unprovisioned}) {
		r.Errorf("CanProxyAs(%q) = true for an identity that was never provisioned", unprovisioned)
	}
	if s.ProxyDenied == nil {
		return
	}
	c, err := s.Authenticator.Authenticate(s.ProxyDenied())
	if err != nil {
		r.Errorf("Authenticate(Subject.ProxyDenied) = %v, want a valid credential that simply "+
			"may not proxy", err)
		return
	}
	if p.CanProxyAs(c) {
		r.Errorf("CanProxyAs(%q) = true, want false: Subject.ProxyDenied is not on the allowlist",
			c.Identity)
	}
}

// checkUnknownAssertedIdentity pins that an identity table reports
// absence rather than inventing a Caller.
func checkUnknownAssertedIdentity(r reporter, s Subject) {
	r.Helper()
	l, ok := s.Authenticator.(authn.IdentityLookup)
	if !ok {
		return
	}
	if c, found := l.LookupIdentity(""); found {
		r.Errorf("LookupIdentity(\"\") resolved to %q, want not-found", c.Identity)
	}
	for _, id := range []string{unprovisioned, s.UnprovisionedIdentity} {
		if id == "" {
			continue
		}
		c, found := l.LookupIdentity(id)
		if found {
			r.Errorf("LookupIdentity(%q) resolved to %q, want not-found", id, c.Identity)
			continue
		}
		if !c.IsZero() {
			r.Errorf("LookupIdentity(%q) returned Caller %q with found=false", id, c.Identity)
		}
	}
}

// checkConcurrent runs the accepted credential from several goroutines
// at once. Under -race this catches an authenticator mutating shared
// state per request — a lazily populated cache, a reused buffer.
func checkConcurrent(r reporter, s Subject) {
	r.Helper()
	if s.Valid == nil {
		return // reported by checkSubject
	}

	const n = 8
	reqs := make([]*http.Request, n)
	wants := make([]purser.Caller, n)
	for i := range reqs {
		reqs[i], wants[i] = s.Valid()
	}

	type result struct {
		caller purser.Caller
		err    error
	}
	got := make([]result, n)
	var wg sync.WaitGroup
	for i := range reqs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := s.Authenticator.Authenticate(reqs[i])
			got[i] = result{caller: c, err: err}
		}()
	}
	wg.Wait()

	// Reported after Wait rather than from the goroutines: a reporter
	// need not be safe for concurrent use.
	for i, res := range got {
		if res.err != nil {
			r.Errorf("concurrent Authenticate[%d] = %v, want success", i, res.err)
			continue
		}
		if res.caller.Identity != wants[i].Identity {
			r.Errorf("concurrent Authenticate[%d] identity = %q, want %q",
				i, res.caller.Identity, wants[i].Identity)
		}
	}
}

// authenticateNoPanic calls Authenticate, converting a panic into a
// value the caller can report. A panic on malformed input is a denial
// of service on any surface that does not recover.
func authenticateNoPanic(a authn.Authenticator, r *http.Request) (c purser.Caller, panicked any, err error) {
	defer func() { panicked = recover() }()
	c, err = a.Authenticate(r)
	return c, nil, err
}

// bareRequest returns a request carrying no credential of any kind.
func bareRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/", nil)
}
