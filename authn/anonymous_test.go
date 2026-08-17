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

package authn_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
	"github.com/go-steer/purser/authtest"
)

func TestAnonymousConformance(t *testing.T) {
	t.Parallel()

	authtest.RunAuthenticatorSuite(t, authtest.Subject{
		Authenticator:         authn.Anonymous{},
		WantSource:            purser.AuthSourceAnonymous,
		AcceptsUncredentialed: true,
		Valid: func() (*http.Request, purser.Caller) {
			return httptest.NewRequest(http.MethodGet, "/", nil), purser.Anonymous()
		},
	})
}

func TestAnonymousWithConfiguredCallerConformance(t *testing.T) {
	t.Parallel()

	caller := purser.Caller{
		Identity: "local-operator",
		Labels:   map[string]string{"deployment": "single-user"},
	}
	authtest.RunAuthenticatorSuite(t, authtest.Subject{
		Authenticator:         authn.Anonymous{Caller: caller},
		WantSource:            purser.AuthSourceAnonymous,
		AcceptsUncredentialed: true,
		Valid: func() (*http.Request, purser.Caller) {
			return httptest.NewRequest(http.MethodGet, "/", nil), caller
		},
	})
}

func TestAnonymousZeroValueResolvesToAnonymous(t *testing.T) {
	t.Parallel()

	got, err := authn.Anonymous{}.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("Authenticate() = %v, want success", err)
	}
	if got.Identity != purser.AnonymousIdentity || got.Admin || len(got.Labels) != 0 {
		t.Errorf("Authenticate() = %+v, want %+v", got, purser.Anonymous())
	}
}

func TestAnonymousIgnoresPresentedCredentials(t *testing.T) {
	t.Parallel()

	// Presenting a credential nobody validates must not change the
	// outcome, and must not change the reported source to something
	// that implies it was checked.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer some-token-nobody-configured")
	r.Header.Set("X-Attach-Token", "another-one")

	a := authn.Anonymous{}
	got, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("Authenticate() = %v, want success", err)
	}
	if got.Identity != purser.AnonymousIdentity || got.Admin || len(got.Labels) != 0 {
		t.Errorf("Authenticate() = %+v, want %+v", got, purser.Anonymous())
	}
	if src := a.Source(); src != purser.AuthSourceAnonymous {
		t.Errorf("Source() = %q, want %q", src, purser.AuthSourceAnonymous)
	}
}

func TestAnonymousDoesNotAliasItsCallerLabels(t *testing.T) {
	t.Parallel()

	a := authn.Anonymous{Caller: purser.Caller{
		Identity: "local-operator",
		Labels:   map[string]string{"deployment": "single-user"},
	}}

	first, err := a.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("Authenticate() = %v", err)
	}
	first.Labels["deployment"] = "tampered"

	second, err := a.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("Authenticate() = %v", err)
	}
	if got := second.Label("deployment"); got != "single-user" {
		t.Errorf("a handler's mutation leaked into a later request: deployment = %q, want %q",
			got, "single-user")
	}
	if got := a.Caller.Label("deployment"); got != "single-user" {
		t.Errorf("a handler's mutation reached the authenticator's own state: deployment = %q, want %q",
			got, "single-user")
	}
}

func TestAnonymousDoesNotGateCredentials(t *testing.T) {
	t.Parallel()

	// The property that keeps a surface from binding a non-loopback
	// address on the strength of an authenticator that checks nothing.
	var gate authn.CredentialGate = authn.Anonymous{}
	if gate.GatesCredentials() {
		t.Error("GatesCredentials() = true; the anonymous authenticator verifies nothing")
	}
}

func TestAnonymousDoesNotImplementProxy(t *testing.T) {
	t.Parallel()

	// Implicit default-deny: an authenticator that resolves every
	// request to one identity must never be able to assert others.
	if _, ok := any(authn.Anonymous{}).(authn.AuthenticatorWithProxy); ok {
		t.Error("authn.Anonymous implements AuthenticatorWithProxy; it must not be able to proxy")
	}
}
