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

package mtls_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/go-steer/purser/authn/mtls"
)

// mustID parses a SPIFFE ID or fails the test.
func mustID(tb testing.TB, s string) spiffeid.ID {
	tb.Helper()
	id, err := spiffeid.FromString(s)
	if err != nil {
		tb.Fatalf("parse SPIFFE ID %q: %v", s, err)
	}
	return id
}

func TestSPIFFEMatchers(t *testing.T) {
	t.Parallel()

	const (
		prodAPI  = "spiffe://example.org/ns/prod/sa/api"
		prodJobs = "spiffe://example.org/ns/prod/sa/jobs"
		staging  = "spiffe://example.org/ns/staging/sa/api"
		// The near-miss an unanchored prefix test would admit.
		production = "spiffe://example.org/ns/production/sa/api"
		// The near-miss a strings.Contains test would admit.
		nested  = "spiffe://example.org/tenants/evil/ns/prod/sa/api"
		foreign = "spiffe://other.example/ns/prod/sa/api"
		bareTD  = "spiffe://example.org"
	)

	for name, tc := range map[string]struct {
		matcher spiffeid.Matcher
		id      string
		admit   bool
	}{
		"path segments, exact":        {mtls.MatchPathSegments("ns", "prod", "sa", "api"), prodAPI, true},
		"path segments, other SA":     {mtls.MatchPathSegments("ns", "prod", "sa", "api"), prodJobs, false},
		"path segments ignore the TD": {mtls.MatchPathSegments("ns", "prod", "sa", "api"), foreign, true},
		"path segments, prefix only":  {mtls.MatchPathSegments("ns", "prod"), prodAPI, false},
		"path segments, nested under another prefix": {
			mtls.MatchPathSegments("ns", "prod", "sa", "api"), nested, false,
		},
		"path segments, none configured": {mtls.MatchPathSegments(), prodAPI, false},
		"path segments, none configured admits nobody, not even the bare trust domain": {
			mtls.MatchPathSegments(), bareTD, false,
		},
		"path segments, separator smuggled into a segment": {
			mtls.MatchPathSegments("ns", "prod/sa/api"), prodAPI, false,
		},
		"path segments, empty segment": {mtls.MatchPathSegments("ns", ""), prodAPI, false},

		"path prefix, under":               {mtls.MatchPathPrefix("ns", "prod"), prodAPI, true},
		"path prefix, exact":               {mtls.MatchPathPrefix("ns", "prod", "sa", "api"), prodAPI, true},
		"path prefix, sibling":             {mtls.MatchPathPrefix("ns", "prod"), staging, false},
		"path prefix, longer namespace":    {mtls.MatchPathPrefix("ns", "prod"), production, false},
		"path prefix, not at the root":     {mtls.MatchPathPrefix("ns", "prod"), nested, false},
		"path prefix, none configured":     {mtls.MatchPathPrefix(), prodAPI, false},
		"path prefix, invalid segment":     {mtls.MatchPathPrefix("ns", ".."), prodAPI, false},
		"path prefix, deeper than the ID":  {mtls.MatchPathPrefix("ns", "prod", "sa", "api", "x"), prodAPI, false},
		"path prefix, bare trust domain":   {mtls.MatchPathPrefix("ns", "prod"), bareTD, false},
		"GKE workload, match":              {mtls.MatchGKEWorkload("my-proj", "prod", "api"), "spiffe://my-proj.svc.id.goog/ns/prod/sa/api", true},
		"GKE workload, other namespace":    {mtls.MatchGKEWorkload("my-proj", "prod", "api"), "spiffe://my-proj.svc.id.goog/ns/staging/sa/api", false},
		"GKE workload, other project":      {mtls.MatchGKEWorkload("my-proj", "prod", "api"), "spiffe://other-proj.svc.id.goog/ns/prod/sa/api", false},
		"GKE workload, unset project":      {mtls.MatchGKEWorkload("", "prod", "api"), prodAPI, false},
		"GKE workload, unset namespace":    {mtls.MatchGKEWorkload("my-proj", "", "api"), prodAPI, false},
		"GKE workload, unset SA":           {mtls.MatchGKEWorkload("my-proj", "prod", ""), prodAPI, false},
		"GKE workload, malformed project":  {mtls.MatchGKEWorkload("my proj", "prod", "api"), prodAPI, false},
		"GKE workload, malformed SA":       {mtls.MatchGKEWorkload("my-proj", "prod", "api/../root"), prodAPI, false},
		"all, empty admits everything":     {mtls.MatchAll(), prodAPI, true},
		"any-of, empty admits nobody":      {mtls.MatchAnyOf(), prodAPI, false},
		"all, every matcher agrees":        {mtls.MatchAll(spiffeid.MatchMemberOf(mustTD(t, "example.org")), mtls.MatchPathPrefix("ns", "prod")), prodAPI, true},
		"all, one matcher dissents":        {mtls.MatchAll(spiffeid.MatchMemberOf(mustTD(t, "example.org")), mtls.MatchPathPrefix("ns", "prod")), staging, false},
		"all, wrong trust domain":          {mtls.MatchAll(spiffeid.MatchMemberOf(mustTD(t, "example.org")), mtls.MatchPathPrefix("ns", "prod")), foreign, false},
		"any-of, second alternative wins":  {mtls.MatchAnyOf(mtls.MatchPathPrefix("ns", "staging"), mtls.MatchPathPrefix("ns", "prod")), prodAPI, true},
		"any-of, no alternative admits it": {mtls.MatchAnyOf(mtls.MatchPathPrefix("ns", "staging"), mtls.MatchPathPrefix("ns", "dev")), prodAPI, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := tc.matcher(mustID(t, tc.id))
			if tc.admit && err != nil {
				t.Errorf("matcher(%s) = %v, want it admitted", tc.id, err)
			}
			if !tc.admit && err == nil {
				t.Errorf("matcher(%s) admitted the peer, want it rejected", tc.id)
			}
		})
	}
}

// mustTD parses a trust domain or fails the test.
func mustTD(tb testing.TB, s string) spiffeid.TrustDomain {
	tb.Helper()
	td, err := spiffeid.TrustDomainFromString(s)
	if err != nil {
		tb.Fatalf("parse trust domain %q: %v", s, err)
	}
	return td
}

// TestSPIFFEEmptyMatcherAsymmetry pins the deliberate difference
// between the two empty cases. An empty conjunction adds no constraint;
// an empty disjunction offers no way in. Spelling them the same way is
// how "no rules configured" comes to mean "admit everyone".
func TestSPIFFEEmptyMatcherAsymmetry(t *testing.T) {
	t.Parallel()

	id := mustID(t, "spiffe://example.org/ns/prod/sa/api")
	if err := mtls.MatchAll()(id); err != nil {
		t.Errorf("MatchAll() = %v, want it to admit: an empty conjunction constrains nothing", err)
	}
	if err := mtls.MatchAnyOf()(id); err == nil {
		t.Error("MatchAnyOf() admitted a peer: an empty disjunction must offer no way in")
	}
}

// TestMatchAnyOfReportsEveryReason keeps the operator-facing half
// honest: the error reaching the TLS log is the only account of why a
// handshake failed, and one that names a single alternative sends
// whoever reads it looking in the wrong place.
func TestSPIFFEMatchAnyOfReportsEveryReason(t *testing.T) {
	t.Parallel()

	err := mtls.MatchAnyOf(
		mtls.MatchPathPrefix("ns", "staging"),
		mtls.MatchPathPrefix("ns", "dev"),
	)(mustID(t, "spiffe://example.org/ns/prod/sa/api"))
	if err == nil {
		t.Fatal("MatchAnyOf admitted a peer no alternative matches")
	}
	for _, want := range []string{"/ns/staging", "/ns/dev"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention the failed alternative %q", err, want)
		}
	}
}

// TestMatchPathSegmentsRejectsSmuggledSeparators is the anchoring
// property stated on its own, because it is the one a future
// refactoring is most likely to lose: segments are validated
// individually, so a value interpolated from configuration cannot widen
// the rule by carrying a slash.
func TestMatchPathSegmentsRejectsSmuggledSeparators(t *testing.T) {
	t.Parallel()

	// A rule meant to name one workload, with the service-account name
	// taken from configuration an attacker influenced.
	matcher := mtls.MatchPathSegments("ns", "prod", "sa", "api/../../ns/admin/sa/root")
	for _, id := range []string{
		"spiffe://example.org/ns/admin/sa/root",
		"spiffe://example.org/ns/prod/sa/api",
	} {
		if err := matcher(mustID(t, id)); err == nil {
			t.Errorf("a matcher built from a segment containing separators admitted %q", id)
		}
	}
}

// TestMatchersRejectWithoutPanicking covers the zero SPIFFE ID, which a
// matcher can be handed by any authorizer that does not check first.
func TestSPIFFEMatchersRejectTheZeroID(t *testing.T) {
	t.Parallel()

	var zero spiffeid.ID
	for name, m := range map[string]spiffeid.Matcher{
		"MatchPathSegments": mtls.MatchPathSegments("ns", "prod"),
		"MatchPathPrefix":   mtls.MatchPathPrefix("ns", "prod"),
		"MatchGKEWorkload":  mtls.MatchGKEWorkload("my-proj", "prod", "api"),
		"MatchAnyOf":        mtls.MatchAnyOf(mtls.MatchPathPrefix("ns", "prod")),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var err error
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("%s panicked on the zero ID: %v", name, p)
					}
				}()
				err = m(zero)
			}()
			if err == nil {
				t.Errorf("%s admitted the zero SPIFFE ID", name)
			}
		})
	}
}

// TestMatchAllShortCircuits pins that a conjunction stops at the first
// refusal, so a matcher may assume the ones before it agreed.
func TestSPIFFEMatchAllShortCircuits(t *testing.T) {
	t.Parallel()

	reached := false
	err := mtls.MatchAll(
		func(spiffeid.ID) error { return errors.New("refused") },
		func(spiffeid.ID) error { reached = true; return nil },
	)(mustID(t, "spiffe://example.org/ns/prod/sa/api"))
	if err == nil {
		t.Fatal("MatchAll admitted a peer one of its matchers refused")
	}
	if reached {
		t.Error("MatchAll called a later matcher after an earlier one refused")
	}
}
