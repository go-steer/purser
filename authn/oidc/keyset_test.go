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

package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn/oidc"
	"github.com/go-steer/purser/authtest"
)

// TestKeysAreFetchedOnceAndCached pins that a verification is not a
// round trip to the IdP.
func TestKeysAreFetchedOnceAndCached(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, nil)
	for i := 0; i < 20; i++ {
		if _, err := authenticate(t, a, iss.Mint(t, authtest.TokenOptions{Email: alice})); err != nil {
			t.Fatalf("Authenticate #%d: %v", i, err)
		}
	}
	if got := iss.JWKSRequests(); got != 1 {
		t.Errorf("JWKS fetches = %d after 20 verifications, want 1", got)
	}
	if got := iss.DiscoveryRequests(); got != 1 {
		t.Errorf("discovery fetches = %d, want 1", got)
	}
}

// TestNoFetchBeforeTheFirstToken pins that New does no network I/O: a
// service must come up with an unreachable IdP, and must not come up
// holding an authenticator that silently rejects everything because the
// fetch at construction failed.
func TestNoFetchBeforeTheFirstToken(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, nil)
	if got := iss.DiscoveryRequests(); got != 0 {
		t.Errorf("discovery fetches = %d before any request, want 0", got)
	}
	if got := iss.JWKSRequests(); got != 0 {
		t.Errorf("JWKS fetches = %d before any request, want 0", got)
	}

	// Nor for a request that presents nothing.
	if _, err := a.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Fatal("Authenticate(no credential) succeeded")
	}
	if got := iss.JWKSRequests(); got != 0 {
		t.Errorf("JWKS fetches = %d after an uncredentialed request, want 0", got)
	}
}

// TestJWKSURLSkipsDiscovery covers the provider that publishes keys
// without a discovery document.
func TestJWKSURLSkipsDiscovery(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)
	a, err := oidc.New(oidc.Options{
		Issuer:     iss.URL(),
		Audiences:  []string{authtest.DefaultAudience},
		JWKSURL:    iss.JWKSURL(),
		HTTPClient: iss.Client(),
	})
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}

	if _, err := authenticate(t, a, iss.Mint(t, authtest.TokenOptions{Email: alice})); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got := iss.DiscoveryRequests(); got != 0 {
		t.Errorf("discovery fetches = %d, want 0 when JWKSURL is configured", got)
	}
	if got := iss.JWKSRequests(); got != 1 {
		t.Errorf("JWKS fetches = %d, want 1", got)
	}
}

// TestUnknownKeyIDTriggersOneRefetch covers the gradual rotation: the
// issuer publishes a new key and signs with it, and this process, which
// has never seen that key ID, refetches on demand.
func TestUnknownKeyIDTriggersOneRefetch(t *testing.T) {
	t.Parallel()

	// No floor to wait out: this test is about the demand-driven path,
	// not the rate limit.
	iss, a := newAuth(t, func(o *oidc.Options) { o.KeyRefreshFloor = time.Nanosecond })
	if _, err := authenticate(t, a, iss.Mint(t, authtest.TokenOptions{Email: alice})); err != nil {
		t.Fatalf("Authenticate before rotation: %v", err)
	}

	iss.AddKey(t, "RS256")
	if _, err := authenticate(t, a, iss.Mint(t, authtest.TokenOptions{Email: alice})); err != nil {
		t.Fatalf("Authenticate with the newly published key: %v", err)
	}
	if got := iss.JWKSRequests(); got != 2 {
		t.Errorf("JWKS fetches = %d, want 2: the unknown key ID costs exactly one refetch", got)
	}
}

// TestRefetchFloorBoundsAmplification is the reason the floor exists.
// A key ID is read from an unverified header, so anyone who can reach
// the surface can name one this process has never cached. Without the
// floor each such request is a fetch against the IdP, and the service
// becomes an amplifier pointed at it.
func TestRefetchFloorBoundsAmplification(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, func(o *oidc.Options) { o.KeyRefreshFloor = time.Hour })

	// Warm the cache with a real token, so the flood below is measured
	// against a cache that already has keys in it.
	if _, err := authenticate(t, a, iss.Mint(t, authtest.TokenOptions{Email: alice})); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	for i := 0; i < 50; i++ {
		token := iss.Mint(t, authtest.TokenOptions{Email: alice, UnpublishedKey: true})
		if _, err := authenticate(t, a, token); !errors.Is(err, purser.ErrUnauthenticated) {
			t.Fatalf("Authenticate(unpublished key) #%d = %v, want ErrUnauthenticated", i, err)
		}
	}
	if got := iss.JWKSRequests(); got != 1 {
		t.Errorf("JWKS fetches = %d after 50 unknown key IDs under an hour-long floor, want 1", got)
	}

	// The refusal says the floor is why, so an operator reading the log
	// during a real rotation knows to wait rather than to restart.
	token := iss.Mint(t, authtest.TokenOptions{Email: alice, UnpublishedKey: true})
	_, err := authenticate(t, a, token)
	if !strings.Contains(err.Error(), "under the 1h0m0s floor") {
		t.Errorf("error = %v, want it to name the floor", err)
	}
}

// TestAgeTriggersRefetch pins the other half: a key the issuer withdrew
// stops verifying tokens here within KeyRefresh, rather than never. The
// demand-driven path cannot do this on its own, because the withdrawn
// key ID is one the cache has seen.
func TestAgeTriggersRefetch(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, func(o *oidc.Options) {
		o.KeyRefresh = 15 * time.Minute
		o.KeyRefreshFloor = 30 * time.Second
	})

	clock := time.Now()
	oidc.SetClock(a, func() time.Time { return clock })

	// A long-lived token signed by the key that is about to be withdrawn.
	withdrawn := iss.Mint(t, authtest.TokenOptions{Email: alice, Expiry: clock.Add(24 * time.Hour)})
	if _, err := authenticate(t, a, withdrawn); err != nil {
		t.Fatalf("Authenticate before withdrawal: %v", err)
	}

	iss.Rotate(t)

	// The cache is still fresh, so the withdrawn key keeps working.
	clock = clock.Add(5 * time.Minute)
	if _, err := authenticate(t, a, withdrawn); err != nil {
		t.Fatalf("Authenticate inside KeyRefresh: %v", err)
	}
	if got := iss.JWKSRequests(); got != 1 {
		t.Errorf("JWKS fetches = %d while the cache was fresh, want 1", got)
	}

	// Past KeyRefresh the set is refetched, and the withdrawn key is
	// gone from it.
	clock = clock.Add(20 * time.Minute)
	_, err := authenticate(t, a, withdrawn)
	if !errors.Is(err, purser.ErrUnauthenticated) {
		t.Fatalf("Authenticate(withdrawn key) = %v, want ErrUnauthenticated", err)
	}
	if got := iss.JWKSRequests(); got != 2 {
		t.Errorf("JWKS fetches = %d after the cache aged out, want 2", got)
	}

	// And the key that replaced it verifies.
	if _, err := authenticate(t, a, iss.Mint(t, authtest.TokenOptions{Email: alice})); err != nil {
		t.Fatalf("Authenticate with the replacement key: %v", err)
	}
}

// TestCachedKeysSurviveAnIssuerOutage pins the fallback: an IdP that is
// briefly down must not log every operator out of every service. The
// token still has to be signed by a cached key and inside its validity
// window.
func TestCachedKeysSurviveAnIssuerOutage(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, func(o *oidc.Options) {
		o.KeyRefresh = time.Nanosecond // every request refetches
		o.KeyRefreshFloor = time.Nanosecond
	})

	token := iss.Mint(t, authtest.TokenOptions{Email: alice})
	if _, err := authenticate(t, a, token); err != nil {
		t.Fatalf("Authenticate while the issuer was up: %v", err)
	}

	iss.Close()

	c, err := authenticate(t, a, token)
	if err != nil {
		t.Fatalf("Authenticate after the issuer went down: %v, want the cached keys to be used", err)
	}
	if c.Identity != alice {
		t.Errorf("identity = %q, want %q", c.Identity, alice)
	}

	// An expired token is still refused: the fallback serves stale keys,
	// not stale claims.
	expired := iss.Mint(t, authtest.TokenOptions{Email: alice, Expiry: time.Now().Add(-time.Hour)})
	if _, err := authenticate(t, a, expired); !errors.Is(err, purser.ErrUnauthenticated) {
		t.Errorf("Authenticate(expired, issuer down) = %v, want ErrUnauthenticated", err)
	}
}

// TestFirstFetchFailureIsReported covers the cold cache: with nothing
// to fall back on, the outage is the answer.
func TestFirstFetchFailureIsReported(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, nil)
	token := iss.Mint(t, authtest.TokenOptions{Email: alice})
	iss.Close()

	_, err := authenticate(t, a, token)
	if !errors.Is(err, purser.ErrUnauthenticated) {
		t.Fatalf("Authenticate with an unreachable issuer = %v, want ErrUnauthenticated", err)
	}
	if !strings.Contains(err.Error(), "discovering") {
		t.Errorf("error = %v, want it to name the failed discovery", err)
	}
}

// TestConcurrentFirstUseFetchesOnce pins the single flight. Twenty
// requests arriving together at a cold cache are one fetch, not twenty:
// a service restarting under load must not stampede its IdP.
func TestConcurrentFirstUseFetchesOnce(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, nil)

	const n = 20
	tokens := make([]string, n)
	for i := range tokens {
		tokens[i] = iss.Mint(t, authtest.TokenOptions{Email: alice})
	}

	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := range tokens {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = a.Authenticate(request(tokens[i]))
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent Authenticate[%d]: %v", i, err)
		}
	}
	if got := iss.DiscoveryRequests(); got != 1 {
		t.Errorf("discovery fetches = %d for %d concurrent cold-cache requests, want 1", got, n)
	}
	if got := iss.JWKSRequests(); got != 1 {
		t.Errorf("JWKS fetches = %d for %d concurrent cold-cache requests, want 1", got, n)
	}
}

// TestFetchOutlivesTheRequestThatTriggeredIt pins that the shared fetch
// is detached from one caller's context. Otherwise the first client to
// hang up cancels the fetch for every request waiting behind it.
func TestFetchOutlivesTheRequestThatTriggeredIt(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, nil)
	token := iss.Mint(t, authtest.TokenOptions{Email: alice})

	// A request whose context is already cancelled. The fetch it starts
	// must still complete and populate the cache.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := request(token)
	if _, err := a.Authenticate(r.WithContext(ctx)); err != nil {
		t.Fatalf("Authenticate on a cancelled context: %v", err)
	}
	if got := iss.JWKSRequests(); got != 1 {
		t.Errorf("JWKS fetches = %d, want 1", got)
	}
}

// TestUnusableKeysAreSkippedNotFatal covers a key set carrying
// something this build cannot use — an encryption key, an unknown key
// type. The usable keys in the same document must still verify tokens.
func TestUnusableKeysAreSkippedNotFatal(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)

	// The issuer's real set, prefixed with entries of the kinds a
	// provider legitimately publishes and this package must ignore: a
	// symmetric key, an encryption key, and a key type this build of
	// go-jose cannot represent.
	var doc map[string]any
	if err := json.Unmarshal([]byte(iss.JWKS(t)), &doc); err != nil {
		t.Fatalf("decoding the issuer's key set: %v", err)
	}
	doc["keys"] = append([]any{
		map[string]any{"kty": "oct", "k": "c2VjcmV0LWtleS1tYXRlcmlhbA", "kid": "symmetric", "use": "sig"},
		map[string]any{"kty": "RSA", "use": "enc", "kid": "encryption", "n": "bm90LWEtbW9kdWx1cw", "e": "AQAB"},
		map[string]any{"kty": "UNKNOWN-2049", "kid": "from-the-future"},
	}, doc["keys"].([]any)...)
	mixed, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encoding the doctored key set: %v", err)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(mixed); err != nil {
			t.Errorf("writing the key set: %v", err)
		}
	}))
	defer srv.Close()

	// The keys are served from the second server, so that is the one the
	// client must trust; the tokens still come from iss.
	a, err := oidc.New(oidc.Options{
		Issuer:     iss.URL(),
		Audiences:  []string{authtest.DefaultAudience},
		JWKSURL:    srv.URL,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	if _, err := authenticate(t, a, iss.Mint(t, authtest.TokenOptions{Email: alice})); err != nil {
		t.Fatalf("Authenticate against a key set with unusable entries: %v", err)
	}
}

// TestBadKeyEndpoints walks the responses a key endpoint must not be
// believed on.
func TestBadKeyEndpoints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{
			name: "a set with nothing usable in it",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeBody(w, r, []byte(`{"keys":[]}`))
			},
			wantErr: "no usable public signing key",
		},
		{
			name: "not JSON",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeBody(w, r, []byte(`<html>sign in to continue</html>`))
			},
			wantErr: "decoding the JWK Set",
		},
		{
			name: "an error from the provider",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "the provider is having a day", http.StatusServiceUnavailable)
			},
			wantErr: "503",
		},
		{
			name: "a response too large to read",
			handler: func(w http.ResponseWriter, r *http.Request) {
				// Past the megabyte bound, so the read is refused rather
				// than the truncation handed to the JSON decoder. An
				// endpoint that streams forever must not be a way to
				// exhaust this process's memory.
				w.Header().Set("Content-Type", "application/json")
				chunk := make([]byte, 64<<10)
				for i := 0; i < 20; i++ {
					if _, err := w.Write(chunk); err != nil {
						return // the reader gave up, which is the point
					}
				}
			},
			wantErr: "returned more than",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			iss := authtest.NewIssuer(t)
			srv := httptest.NewTLSServer(tt.handler)
			defer srv.Close()

			a, err := oidc.New(oidc.Options{
				Issuer:     iss.URL(),
				Audiences:  []string{authtest.DefaultAudience},
				JWKSURL:    srv.URL,
				HTTPClient: srv.Client(),
			})
			if err != nil {
				t.Fatalf("oidc.New: %v", err)
			}

			c, err := authenticate(t, a, iss.Mint(t, authtest.TokenOptions{Email: alice}))
			if err == nil {
				t.Fatalf("Authenticate succeeded as %q against a key endpoint that must not be "+
					"believed", c.Identity)
			}
			if !errors.Is(err, purser.ErrUnauthenticated) {
				t.Errorf("error = %v, want purser.ErrUnauthenticated", err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func writeBody(w http.ResponseWriter, r *http.Request, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(body); err != nil {
		_ = r
	}
}
