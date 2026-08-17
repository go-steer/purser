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

// This file is the conformance suite's own conformance test. Every
// check is run twice: once against an authenticator that honors the
// contract, asserting silence, and once against one that violates it,
// asserting the violation is reported. A check that has never been
// observed to fail is not known to work.
//
// It is an internal test (package authtest, not authtest_test) because
// it drives the unexported check table and reporter directly. That is
// the whole reason reporter exists: testing.TB cannot be implemented
// outside the testing package, so the checks take a narrower interface
// a fake can satisfy.

package authtest

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
)

const (
	refToken      = "ref-good-token"
	refIdentity   = "alice@example.com"
	proxyToken    = "ref-gateway-token"
	proxyIdentity = "sa:gateway"
)

// recorder is a reporter that collects failures instead of failing.
type recorder struct {
	helperCalls int
	msgs        []string
}

func (rec *recorder) Helper() { rec.helperCalls++ }

func (rec *recorder) Errorf(format string, args ...any) {
	rec.msgs = append(rec.msgs, fmt.Sprintf(format, args...))
}

// runCheck runs the single named check against s and returns whatever
// it reported. Looking the check up by name keeps the test honest: a
// renamed or deleted check fails here rather than silently ceasing to
// be exercised.
func runCheck(t *testing.T, name string, s Subject) []string {
	t.Helper()
	for _, c := range checks {
		if c.name != name {
			continue
		}
		rec := &recorder{}
		c.run(rec, s)
		if rec.helperCalls == 0 {
			t.Errorf("check %q did not call Helper(); failures will point at the suite, "+
				"not at the test that invoked it", name)
		}
		return rec.msgs
	}
	t.Fatalf("no check named %q in the conformance table", name)
	return nil
}

func wantReported(t *testing.T, msgs []string, what string) {
	t.Helper()
	if len(msgs) == 0 {
		t.Errorf("check passed an authenticator that %s; the check does not detect it", what)
	}
}

func wantClean(t *testing.T, msgs []string, what string) {
	t.Helper()
	if len(msgs) != 0 {
		t.Errorf("check reported %d failure(s) for %s: %s", len(msgs), what, strings.Join(msgs, "; "))
	}
}

// --- a reference authenticator that honors the contract ---------------------

// refAuth is a minimal bearer-shaped authenticator: enough of a real
// implementation that the checks have something faithful to pass, and
// small enough that its deliberate breakages are unambiguous.
type refAuth struct {
	table map[string]purser.Caller // token -> caller
	clone bool                     // false reproduces the label-aliasing bug
}

func newRefAuth() *refAuth {
	return &refAuth{
		table: map[string]purser.Caller{
			refToken:   {Identity: refIdentity, Labels: map[string]string{"team": "platform"}},
			proxyToken: {Identity: proxyIdentity},
		},
		clone: true,
	}
}

func (a *refAuth) Source() purser.AuthSource { return purser.AuthSourceBearer }

func (a *refAuth) Authenticate(r *http.Request) (purser.Caller, error) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		return purser.Caller{}, fmt.Errorf("refauth: no token: %w", purser.ErrUnauthenticated)
	}
	c, ok := a.table[token]
	if !ok {
		return purser.Caller{}, fmt.Errorf("refauth: unknown token: %w", purser.ErrUnauthenticated)
	}
	if a.clone {
		return c.Clone(), nil
	}
	return c, nil
}

func (a *refAuth) CanProxyAs(c purser.Caller) bool { return c.Identity == proxyIdentity }

func (a *refAuth) LookupIdentity(identity string) (purser.Caller, bool) {
	if identity == "" {
		return purser.Caller{}, false
	}
	for _, c := range a.table {
		if c.Identity != identity {
			continue
		}
		if a.clone {
			return c.Clone(), true
		}
		return c, true
	}
	return purser.Caller{}, false
}

var (
	_ authn.Authenticator          = (*refAuth)(nil)
	_ authn.AuthenticatorWithProxy = (*refAuth)(nil)
	_ authn.IdentityLookup         = (*refAuth)(nil)
)

func bearerRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// refSubject is a fully specified Subject for a. Individual tests
// mutate one field of the returned value to isolate one property.
func refSubject(a authn.Authenticator) Subject {
	return Subject{
		Authenticator: a,
		WantSource:    purser.AuthSourceBearer,
		Valid: func() (*http.Request, purser.Caller) {
			return bearerRequest(refToken), purser.Caller{
				Identity: refIdentity,
				Labels:   map[string]string{"team": "platform"},
			}
		},
		Malformed: []MalformedCase{
			{"unknown token", func() *http.Request { return bearerRequest("nope") }},
			{"wrong scheme", func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Authorization", "Basic YWxpY2U6aHVudGVyMg==")
				return r
			}},
		},
		// The reference authenticator resolves alice, who is a valid
		// caller that is nonetheless not on the proxy allowlist.
		ProxyDenied:         func() *http.Request { return bearerRequest(refToken) },
		ProvisionedIdentity: refIdentity,
	}
}

// --- a stub whose every behavior can be broken independently ----------------

type stubAuth struct {
	sourceFn func() purser.AuthSource
	authFn   func(*http.Request) (purser.Caller, error)
}

func (s stubAuth) Source() purser.AuthSource {
	if s.sourceFn == nil {
		return purser.AuthSourceBearer
	}
	return s.sourceFn()
}

func (s stubAuth) Authenticate(r *http.Request) (purser.Caller, error) {
	if s.authFn == nil {
		return purser.Caller{Identity: refIdentity}, nil
	}
	return s.authFn(r)
}

type stubProxy struct {
	stubAuth
	canProxyFn func(purser.Caller) bool
}

func (s stubProxy) CanProxyAs(c purser.Caller) bool { return s.canProxyFn(c) }

type stubLookup struct {
	stubAuth
	lookupFn func(string) (purser.Caller, bool)
}

func (s stubLookup) LookupIdentity(identity string) (purser.Caller, bool) {
	return s.lookupFn(identity)
}

// --- the suite as a whole ---------------------------------------------------

// TestReferenceAuthenticatorPassesTheSuite drives the public entry
// point, so the wiring between RunAuthenticatorSuite and the check
// table is exercised, not just the checks in isolation.
func TestReferenceAuthenticatorPassesTheSuite(t *testing.T) {
	t.Parallel()

	RunAuthenticatorSuite(t, refSubject(newRefAuth()))
}

func TestEveryCheckIsCleanOnTheReferenceAuthenticator(t *testing.T) {
	t.Parallel()

	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			wantClean(t, runCheck(t, c.name, refSubject(newRefAuth())), "the reference authenticator")
		})
	}
}

func TestCheckNamesAreUniqueAndNonEmpty(t *testing.T) {
	t.Parallel()

	// Duplicate names would make t.Run emit "Name#01", and runCheck
	// above would silently exercise only the first of the pair.
	seen := map[string]bool{}
	for i, c := range checks {
		if c.name == "" {
			t.Errorf("checks[%d] has an empty name", i)
		}
		if seen[c.name] {
			t.Errorf("checks[%d]: duplicate name %q", i, c.name)
		}
		seen[c.name] = true
		if c.run == nil {
			t.Errorf("checks[%d] (%q) has a nil run function", i, c.name)
		}
	}
}

// --- Subject ----------------------------------------------------------------

func TestCheckSubjectRejectsUnderSpecifiedSubjects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Subject)
		broken  string
		wantMsg bool
	}{
		{
			name:    "unset WantSource",
			mutate:  func(s *Subject) { s.WantSource = "" },
			broken:  "leaves the reported auth source unpinned",
			wantMsg: true,
		},
		{
			name:    "nil Valid",
			mutate:  func(s *Subject) { s.Valid = nil },
			broken:  "names no credential that must be accepted",
			wantMsg: true,
		},
		{
			name:    "no Malformed cases",
			mutate:  func(s *Subject) { s.Malformed = nil },
			broken:  "names no credential that must be rejected",
			wantMsg: true,
		},
		{
			name: "AcceptsUncredentialed waives the credential cases",
			mutate: func(s *Subject) {
				s.AcceptsUncredentialed = true
				s.Malformed = nil
			},
			broken:  "an authenticator that verifies nothing by design",
			wantMsg: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := refSubject(newRefAuth())
			tt.mutate(&s)
			msgs := runCheck(t, "Subject", s)
			if tt.wantMsg {
				wantReported(t, msgs, tt.broken)
			} else {
				wantClean(t, msgs, tt.broken)
			}
		})
	}
}

// TestCheckSubjectStillPinsSourceWhenUncredentialed guards the waiver
// from growing into a blanket opt-out.
func TestCheckSubjectStillPinsSourceWhenUncredentialed(t *testing.T) {
	t.Parallel()

	s := refSubject(newRefAuth())
	s.AcceptsUncredentialed = true
	s.WantSource = ""
	wantReported(t, runCheck(t, "Subject", s), "sets AcceptsUncredentialed and leaves WantSource unset")
}

// --- Source -----------------------------------------------------------------

func TestCheckSourceDetectsBadSources(t *testing.T) {
	t.Parallel()

	alternating := func() func() purser.AuthSource {
		n := 0
		return func() purser.AuthSource {
			n++
			if n > 1 {
				return purser.AuthSourceMTLS
			}
			return purser.AuthSourceBearer
		}
	}

	tests := []struct {
		name   string
		source func() purser.AuthSource
		broken string
	}{
		{"empty", func() purser.AuthSource { return "" }, "reports an empty source"},
		{"undefined value", func() purser.AuthSource { return "totally-legit" },
			"reports a source purser does not define"},
		{"wrong class", func() purser.AuthSource { return purser.AuthSourceOIDC },
			"reports a source other than the one the subject pins"},
		{"not constant", alternating(), "reports a different source on each call"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := refSubject(stubAuth{sourceFn: tt.source})
			wantReported(t, runCheck(t, "Source", s), tt.broken)
		})
	}
}

// --- NoCredential -----------------------------------------------------------

func TestCheckNoCredentialDetectsOpenAuthenticator(t *testing.T) {
	t.Parallel()

	// The single most consequential failure: an authenticator that
	// resolves a request presenting nothing at all.
	s := refSubject(stubAuth{authFn: func(*http.Request) (purser.Caller, error) {
		return purser.Caller{Identity: refIdentity}, nil
	}})
	wantReported(t, runCheck(t, "NoCredential", s), "accepts a request carrying no credential")
}

func TestCheckNoCredentialDetectsWrongSentinel(t *testing.T) {
	t.Parallel()

	// Rejecting with an error a surface cannot map to 401 turns an
	// authentication failure into a 500.
	s := refSubject(stubAuth{authFn: func(*http.Request) (purser.Caller, error) {
		return purser.Caller{}, errors.New("nope")
	}})
	wantReported(t, runCheck(t, "NoCredential", s), "rejects without wrapping ErrUnauthenticated")
}

func TestCheckNoCredentialDetectsCallerAlongsideError(t *testing.T) {
	t.Parallel()

	s := refSubject(stubAuth{authFn: func(*http.Request) (purser.Caller, error) {
		return purser.Caller{Identity: refIdentity}, purser.ErrUnauthenticated
	}})
	wantReported(t, runCheck(t, "NoCredential", s), "returns a populated Caller alongside its error")
}

func TestCheckNoCredentialDetectsUncredentialedZeroCaller(t *testing.T) {
	t.Parallel()

	// AcceptsUncredentialed does not license returning nothing: a
	// consumer would read the nil error as proof of an identity.
	s := refSubject(stubAuth{authFn: func(*http.Request) (purser.Caller, error) {
		return purser.Caller{}, nil
	}})
	s.AcceptsUncredentialed = true
	wantReported(t, runCheck(t, "NoCredential", s), "resolves every request to a zero Caller")
}

func TestCheckNoCredentialDetectsUncredentialedRejection(t *testing.T) {
	t.Parallel()

	s := refSubject(newRefAuth())
	s.AcceptsUncredentialed = true
	wantReported(t, runCheck(t, "NoCredential", s), "rejects despite AcceptsUncredentialed")
}

// --- ValidCredential --------------------------------------------------------

func TestCheckValidCredentialDetectsBadResults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		auth   func(*http.Request) (purser.Caller, error)
		broken string
	}{
		{
			"rejects the valid credential",
			func(*http.Request) (purser.Caller, error) {
				return purser.Caller{}, purser.ErrUnauthenticated
			},
			"rejects a credential it must accept",
		},
		{
			"zero caller with no error",
			func(*http.Request) (purser.Caller, error) { return purser.Caller{}, nil },
			"returns a zero Caller with a nil error",
		},
		{
			"wrong identity",
			func(*http.Request) (purser.Caller, error) {
				return purser.Caller{Identity: "mallory@example.com"}, nil
			},
			"resolves the credential to the wrong identity",
		},
		{
			"unearned admin",
			func(*http.Request) (purser.Caller, error) {
				return purser.Caller{Identity: refIdentity, Admin: true,
					Labels: map[string]string{"team": "platform"}}, nil
			},
			"grants admin the subject did not ask for",
		},
		{
			"wrong labels",
			func(*http.Request) (purser.Caller, error) {
				return purser.Caller{Identity: refIdentity,
					Labels: map[string]string{"team": "security"}}, nil
			},
			"resolves the credential with the wrong labels",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := refSubject(stubAuth{authFn: tt.auth})
			wantReported(t, runCheck(t, "ValidCredential", s), tt.broken)
		})
	}
}

// --- MalformedCredential ----------------------------------------------------

func TestCheckMalformedCredentialDetectsAcceptance(t *testing.T) {
	t.Parallel()

	s := refSubject(stubAuth{authFn: func(*http.Request) (purser.Caller, error) {
		return purser.Caller{Identity: refIdentity}, nil
	}})
	wantReported(t, runCheck(t, "MalformedCredential", s), "accepts a malformed credential")
}

func TestCheckMalformedCredentialSurvivesAPanic(t *testing.T) {
	t.Parallel()

	// A panic on attacker-controlled bytes is a denial of service on
	// any surface that does not recover. The check must report it
	// rather than take the test binary down with it.
	s := refSubject(stubAuth{authFn: func(r *http.Request) (purser.Caller, error) {
		if r.Header.Get("Authorization") != "Bearer "+refToken {
			panic("refauth: index out of range")
		}
		return purser.Caller{Identity: refIdentity}, nil
	}})
	msgs := runCheck(t, "MalformedCredential", s)
	wantReported(t, msgs, "panics on a malformed credential")
	for _, m := range msgs {
		if strings.Contains(m, "panicked") {
			return
		}
	}
	t.Errorf("failures do not mention the panic: %s", strings.Join(msgs, "; "))
}

func TestCheckMalformedCredentialDetectsWrongSentinel(t *testing.T) {
	t.Parallel()

	s := refSubject(stubAuth{authFn: func(*http.Request) (purser.Caller, error) {
		return purser.Caller{}, errors.New("malformed")
	}})
	wantReported(t, runCheck(t, "MalformedCredential", s), "rejects without wrapping ErrUnauthenticated")
}

func TestCheckMalformedCredentialDetectsCallerAlongsideError(t *testing.T) {
	t.Parallel()

	s := refSubject(stubAuth{authFn: func(*http.Request) (purser.Caller, error) {
		return purser.Caller{Identity: refIdentity}, purser.ErrUnauthenticated
	}})
	wantReported(t, runCheck(t, "MalformedCredential", s), "returns a Caller alongside its rejection")
}

// --- LabelsNotAliased -------------------------------------------------------

// TestCheckLabelsNotAliasedDetectsSharedMap reproduces the aliasing bug
// this check exists for: a table-backed authenticator that hands every
// caller the same map, so one consumer's write rewrites another
// caller's metadata.
func TestCheckLabelsNotAliasedDetectsSharedMap(t *testing.T) {
	t.Parallel()

	leaky := newRefAuth()
	leaky.clone = false
	wantReported(t, runCheck(t, "LabelsNotAliased", refSubject(leaky)),
		"hands out a map into its own table")
}

// TestCheckLabelsNotAliasedCoversTheLookupPath is the half a
// table-backed authenticator is most likely to get wrong: Authenticate
// clones, LookupIdentity does not.
func TestCheckLabelsNotAliasedCoversTheLookupPath(t *testing.T) {
	t.Parallel()

	honest := newRefAuth()
	s := refSubject(stubLookup{
		stubAuth: stubAuth{authFn: func(r *http.Request) (purser.Caller, error) {
			return honest.Authenticate(r) // clones, so only the lookup path is broken
		}},
		lookupFn: func(id string) (purser.Caller, bool) {
			c, ok := honest.table[refToken]
			if !ok || c.Identity != id {
				return purser.Caller{}, false
			}
			return c, true // the raw table entry
		},
	})
	wantReported(t, runCheck(t, "LabelsNotAliased", s),
		"clones on Authenticate but hands out its raw table entry from LookupIdentity")
}

func TestCheckLabelsNotAliasedDetectsAbsentProvisionedIdentity(t *testing.T) {
	t.Parallel()

	// A Subject naming an identity the table does not hold would
	// otherwise skip the lookup probe silently.
	s := refSubject(newRefAuth())
	s.ProvisionedIdentity = "bob@example.com"
	wantReported(t, runCheck(t, "LabelsNotAliased", s),
		"does not contain the identity Subject.ProvisionedIdentity names")
}

func TestCheckLabelsNotAliasedDetectsZeroLookupResult(t *testing.T) {
	t.Parallel()

	s := refSubject(stubLookup{lookupFn: func(string) (purser.Caller, bool) {
		return purser.Caller{}, true
	}})
	s.ProvisionedIdentity = refIdentity
	wantReported(t, runCheck(t, "LabelsNotAliased", s),
		"reports found=true with a zero Caller")
}

func TestCheckLabelsNotAliasedIgnoresLabellessCallers(t *testing.T) {
	t.Parallel()

	// Nothing to alias is not a failure.
	s := refSubject(stubAuth{authFn: func(*http.Request) (purser.Caller, error) {
		return purser.Caller{Identity: refIdentity}, nil
	}})
	wantClean(t, runCheck(t, "LabelsNotAliased", s), "an authenticator that resolves no labels")
}

// --- ProxyDefaultDeny -------------------------------------------------------

func TestCheckProxyDefaultDenyDetectsPermissiveProxies(t *testing.T) {
	t.Parallel()

	valid := func(*http.Request) (purser.Caller, error) {
		return purser.Caller{Identity: refIdentity, Labels: map[string]string{"team": "platform"}}, nil
	}

	tests := []struct {
		name     string
		canProxy func(purser.Caller) bool
		broken   string
	}{
		{"allows everyone", func(purser.Caller) bool { return true },
			"lets any caller assert any identity"},
		{"allows the zero caller", func(c purser.Caller) bool { return c.IsZero() },
			"lets an unresolved caller reach the proxy path"},
		{"allows an unprovisioned identity", func(c purser.Caller) bool { return c.Identity == unprovisioned },
			"proxies an identity that was never provisioned"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := refSubject(stubProxy{
				stubAuth:   stubAuth{authFn: valid},
				canProxyFn: tt.canProxy,
			})
			wantReported(t, runCheck(t, "ProxyDefaultDeny", s), tt.broken)
		})
	}
}

func TestCheckProxyDefaultDenySkipsNonProxies(t *testing.T) {
	t.Parallel()

	// Not implementing the interface is the strongest possible denial.
	s := refSubject(stubAuth{})
	wantClean(t, runCheck(t, "ProxyDefaultDeny", s), "an authenticator that cannot proxy at all")
}

func TestCheckProxyDefaultDenyWithoutAProxyDeniedRequest(t *testing.T) {
	t.Parallel()

	// ProxyDenied is optional: the two probes that need no subject
	// input still run, and a well-behaved proxy stays clean.
	s := refSubject(newRefAuth())
	s.ProxyDenied = nil
	wantClean(t, runCheck(t, "ProxyDefaultDeny", s), "a default-deny proxy with no ProxyDenied request")
}

func TestCheckProxyDefaultDenyRequiresProxyDeniedToAuthenticate(t *testing.T) {
	t.Parallel()

	// A Subject whose ProxyDenied request is itself rejected proves
	// nothing about the proxy allowlist, so the check says so rather
	// than passing.
	s := refSubject(newRefAuth())
	s.ProxyDenied = func() *http.Request { return bearerRequest("not-a-token") }
	wantReported(t, runCheck(t, "ProxyDefaultDeny", s), "supplies a ProxyDenied request that fails to authenticate")
}

// --- UnknownAssertedIdentity ------------------------------------------------

func TestCheckUnknownAssertedIdentityDetectsInventedCallers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		lookup func(string) (purser.Caller, bool)
		broken string
	}{
		{"resolves anything", func(id string) (purser.Caller, bool) {
			return purser.Caller{Identity: id}, true
		}, "invents a Caller for any identity it is asked about"},
		{"resolves the empty identity", func(id string) (purser.Caller, bool) {
			return purser.Caller{Identity: refIdentity}, id == ""
		}, "resolves the empty identity"},
		{"caller alongside not-found", func(string) (purser.Caller, bool) {
			return purser.Caller{Identity: refIdentity}, false
		}, "returns a populated Caller with found=false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := refSubject(stubLookup{lookupFn: tt.lookup})
			s.UnprovisionedIdentity = "bob@example.com"
			wantReported(t, runCheck(t, "UnknownAssertedIdentity", s), tt.broken)
		})
	}
}

func TestCheckUnknownAssertedIdentityHonorsSubjectSuppliedIdentity(t *testing.T) {
	t.Parallel()

	// The suite's own probe identity is deliberately unrealistic; a
	// table that only rejects unrealistic identities must still be
	// caught by the one the subject names.
	s := refSubject(stubLookup{lookupFn: func(id string) (purser.Caller, bool) {
		if id == unprovisioned || id == "" {
			return purser.Caller{}, false
		}
		return purser.Caller{Identity: id}, true
	}})
	s.UnprovisionedIdentity = "bob@example.com"
	wantReported(t, runCheck(t, "UnknownAssertedIdentity", s),
		"resolves the unprovisioned identity the subject named")
}

// --- Concurrent -------------------------------------------------------------

func TestCheckConcurrentReportsPerRequestFailures(t *testing.T) {
	t.Parallel()

	// Runs with -race in CI, which is where this check earns its keep;
	// what is assertable without a race is that failures surface.
	s := refSubject(stubAuth{authFn: func(*http.Request) (purser.Caller, error) {
		return purser.Caller{}, purser.ErrUnauthenticated
	}})
	msgs := runCheck(t, "Concurrent", s)
	wantReported(t, msgs, "fails under concurrent use")
	if len(msgs) != 8 {
		t.Errorf("got %d failures, want one per concurrent request (8)", len(msgs))
	}
}

func TestCheckConcurrentDetectsIdentityConfusion(t *testing.T) {
	t.Parallel()

	s := refSubject(stubAuth{authFn: func(*http.Request) (purser.Caller, error) {
		return purser.Caller{Identity: "mallory@example.com"}, nil
	}})
	wantReported(t, runCheck(t, "Concurrent", s), "resolves concurrent requests to the wrong identity")
}

// --- helpers ----------------------------------------------------------------

func TestAuthenticateNoPanicPassesResultsThrough(t *testing.T) {
	t.Parallel()

	want := purser.Caller{Identity: refIdentity}
	wantErr := errors.New("boom")
	got, panicked, err := authenticateNoPanic(
		stubAuth{authFn: func(*http.Request) (purser.Caller, error) { return want, wantErr }},
		bareRequest())
	if panicked != nil {
		t.Errorf("panicked = %v, want nil", panicked)
	}
	if got.Identity != want.Identity || !errors.Is(err, wantErr) {
		t.Errorf("authenticateNoPanic() = (%+v, %v), want (%+v, %v)", got, err, want, wantErr)
	}
}

func TestAuthenticateNoPanicRecovers(t *testing.T) {
	t.Parallel()

	got, panicked, err := authenticateNoPanic(
		stubAuth{authFn: func(*http.Request) (purser.Caller, error) { panic("boom") }},
		bareRequest())
	if panicked == nil {
		t.Fatal("panicked = nil, want the recovered value")
	}
	if !got.IsZero() || err != nil {
		t.Errorf("authenticateNoPanic() = (%+v, %v) after a panic, want (zero, nil)", got, err)
	}
}

func TestBareRequestCarriesNoCredential(t *testing.T) {
	t.Parallel()

	r := bareRequest()
	if len(r.Header) != 0 {
		t.Errorf("bareRequest() carries headers %v, want none", r.Header)
	}
	if r.TLS != nil {
		t.Error("bareRequest() carries a TLS connection state, want none")
	}
}
