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

package purser_test

import (
	"context"
	"errors"
	"testing"

	"github.com/go-steer/purser"
)

func TestCallerCloneBreaksLabelAliasing(t *testing.T) {
	t.Parallel()

	original := purser.Caller{
		Identity: "alice@example.com",
		Labels:   map[string]string{"team": "platform"},
		Admin:    true,
	}

	clone := original.Clone()
	clone.Labels["team"] = "security"
	clone.Labels["added"] = "yes"

	if got := original.Labels["team"]; got != "platform" {
		t.Errorf("mutating the clone changed the original: team = %q, want %q", got, "platform")
	}
	if _, ok := original.Labels["added"]; ok {
		t.Error("mutating the clone added a label to the original")
	}
	if clone.Identity != original.Identity || clone.Admin != original.Admin {
		t.Errorf("Clone() = %+v, want the same scalars as %+v", clone, original)
	}
}

func TestCallerCloneNilLabels(t *testing.T) {
	t.Parallel()

	// Regression guard: Anonymous carries no Labels, and cloning it is
	// on the hot path for every unauthenticated request.
	anon := purser.Anonymous()
	clone := anon.Clone()
	if clone.Labels != nil {
		t.Errorf("Clone().Labels = %v, want nil", clone.Labels)
	}
	if clone.Identity != anon.Identity || clone.Admin != anon.Admin {
		t.Errorf("Clone() = %+v, want %+v", clone, anon)
	}
}

// TestAnonymousIsFreshEachCall pins why Anonymous is a function: a
// package-level variable could be reassigned by any importer, and every
// unauthenticated request in the process would resolve to whatever they
// put there.
func TestAnonymousIsFreshEachCall(t *testing.T) {
	t.Parallel()

	first := purser.Anonymous()
	first.Identity = "root"
	first.Admin = true

	second := purser.Anonymous()
	if second.Identity != purser.AnonymousIdentity {
		t.Errorf("Anonymous().Identity = %q after a caller mutated an earlier value, want %q",
			second.Identity, purser.AnonymousIdentity)
	}
	if second.Admin {
		t.Error("Anonymous().Admin = true; the anonymous caller is never an admin")
	}
	if second.Labels != nil {
		t.Errorf("Anonymous().Labels = %v, want nil", second.Labels)
	}
}

func TestCallerLabelAbsentOnNilMap(t *testing.T) {
	t.Parallel()

	var c purser.Caller
	if got := c.Label("team"); got != "" {
		t.Errorf("Label on a zero Caller = %q, want %q", got, "")
	}
}

func TestCallerIsZero(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   purser.Caller
		want bool
	}{
		{"zero value", purser.Caller{}, true},
		{"labels but no identity", purser.Caller{Labels: map[string]string{"a": "b"}}, true},
		{"admin but no identity", purser.Caller{Admin: true}, true},
		{"identity", purser.Caller{Identity: "alice@example.com"}, false},
		{"anonymous", purser.Anonymous(), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.in.IsZero(); got != tt.want {
				t.Errorf("IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCallerRoundTripsThroughContext(t *testing.T) {
	t.Parallel()

	want := purser.Caller{Identity: "sa:platform-agent", Labels: map[string]string{"team": "platform"}}
	ctx := purser.WithCaller(context.Background(), want)

	got, ok := purser.CallerFromContext(ctx)
	if !ok {
		t.Fatal("CallerFromContext: ok = false after WithCaller")
	}
	if got.Identity != want.Identity || got.Label("team") != "platform" {
		t.Errorf("CallerFromContext() = %+v, want %+v", got, want)
	}
}

func TestCallerFromContextAbsent(t *testing.T) {
	t.Parallel()

	// The security-relevant case: a handler reached without the
	// authentication middleware must see "no caller", not a usable one.
	got, ok := purser.CallerFromContext(context.Background())
	if ok {
		t.Errorf("CallerFromContext(bare context): ok = true, caller = %+v", got)
	}
	if !got.IsZero() {
		t.Errorf("CallerFromContext(bare context) = %+v, want the zero Caller", got)
	}
}

func TestProxyByRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := purser.WithProxyBy(context.Background(), "sa:slack-bot")
	got, ok := purser.ProxyByFromContext(ctx)
	if !ok || got != "sa:slack-bot" {
		t.Errorf("ProxyByFromContext() = (%q, %v), want (%q, true)", got, ok, "sa:slack-bot")
	}
}

func TestProxyByFromContextAbsentOrEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ctx  context.Context
	}{
		{"never set", context.Background()},
		// An empty proxy identity means the request did not take the
		// proxy path; reporting ok=true would put an empty string into
		// audit records as if it were an identity.
		{"set to empty", purser.WithProxyBy(context.Background(), "")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := purser.ProxyByFromContext(tt.ctx)
			if ok || got != "" {
				t.Errorf("ProxyByFromContext() = (%q, %v), want (%q, false)", got, ok, "")
			}
		})
	}
}

func TestCallerAndProxyByUseDistinctContextKeys(t *testing.T) {
	t.Parallel()

	// Both values are strings-in-a-context; a shared key would let one
	// silently overwrite the other.
	ctx := purser.WithCaller(context.Background(), purser.Caller{Identity: "alice@example.com"})
	ctx = purser.WithProxyBy(ctx, "sa:slack-bot")

	c, ok := purser.CallerFromContext(ctx)
	if !ok || c.Identity != "alice@example.com" {
		t.Errorf("CallerFromContext() = (%+v, %v), want alice@example.com", c, ok)
	}
	by, ok := purser.ProxyByFromContext(ctx)
	if !ok || by != "sa:slack-bot" {
		t.Errorf("ProxyByFromContext() = (%q, %v), want sa:slack-bot", by, ok)
	}
}

func TestSentinelErrorsAreDistinct(t *testing.T) {
	t.Parallel()

	all := []error{
		purser.ErrUnauthenticated,
		purser.ErrAssertedCallerForbidden,
		purser.ErrAssertedCallerUnknown,
	}
	for i, a := range all {
		for j, b := range all {
			if i == j {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("errors.Is(%v, %v) = true, want distinct sentinels", a, b)
			}
		}
	}
}

func TestSentinelErrorsSurviveWrapping(t *testing.T) {
	t.Parallel()

	// Authenticators wrap the sentinels with detail; surfaces map the
	// sentinel to a status code. Both have to keep working.
	wrapped := errors.Join(errors.New("oidc: audience mismatch"), purser.ErrUnauthenticated)
	if !errors.Is(wrapped, purser.ErrUnauthenticated) {
		t.Error("errors.Is(joined, ErrUnauthenticated) = false")
	}
	if errors.Is(wrapped, purser.ErrAssertedCallerForbidden) {
		t.Error("errors.Is(joined, ErrAssertedCallerForbidden) = true, want false")
	}
}
