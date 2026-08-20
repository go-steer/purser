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

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// fetchTimeout bounds one attempt at the discovery document or the key
// set. It applies even when the caller supplies an http.Client with no
// timeout of its own, because a fetch that never returns holds the
// single-flight slot and every request waiting behind it.
const fetchTimeout = 10 * time.Second

// maxJWKSBytes bounds the response this package will read from the
// issuer's endpoints. Google's key set is under 2 KiB; a megabyte is
// four orders of magnitude of headroom and still a bound.
const maxJWKSBytes = 1 << 20

// keySet is the cache of the issuer's published verification keys.
//
// Refetching is demand-driven — a key ID the cache has never seen — and
// age-driven, so a key the issuer withdrew stops verifying tokens here
// within KeyRefresh rather than never. Both paths go through one
// rate-limited, single-flighted fetch.
type keySet struct {
	issuer  string
	jwksURL string // from Options.JWKSURL; discovered when empty
	client  *http.Client
	refresh time.Duration
	floor   time.Duration

	// now is time.Now, replaced in tests.
	now func() time.Time

	mu          sync.Mutex
	discovered  string // jwks_uri from the discovery document
	keys        []jose.JSONWebKey
	fetchedAt   time.Time // last successful fetch
	lastAttempt time.Time // last attempt, successful or not: the floor
	inflight    *inflight
}

type keySetOptions struct {
	Issuer       string
	JWKSURL      string
	HTTPClient   *http.Client
	Refresh      time.Duration
	RefreshFloor time.Duration
}

func newKeySet(opts keySetOptions) *keySet {
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: fetchTimeout}
	}
	return &keySet{
		issuer:  opts.Issuer,
		jwksURL: opts.JWKSURL,
		client:  client,
		refresh: opts.Refresh,
		floor:   opts.RefreshFloor,
		now:     time.Now,
	}
}

// inflight is one fetch several goroutines wait on. The fields are
// written before done is closed and read only after it is, so the close
// is what publishes them.
type inflight struct {
	done chan struct{}
	keys []jose.JSONWebKey
	err  error
}

// keysFor returns the published keys that could have produced a
// signature with this key ID and algorithm, most likely first. It
// returns an error only when there is nothing to try.
func (k *keySet) keysFor(ctx context.Context, kid, alg string) ([]jose.JSONWebKey, error) {
	cached, fetchedAt := k.snapshot()
	match := selectKeys(cached, kid, alg)
	if len(match) > 0 && k.now().Sub(fetchedAt) < k.refresh {
		return match, nil
	}

	refreshed, err := k.refreshKeys(ctx, fetchedAt)
	if err != nil {
		if len(match) > 0 {
			// The issuer is unreachable, or the floor has not elapsed,
			// and a key that matches is already cached. Serve it. An
			// IdP that is briefly down should not log every operator
			// out of every service — and the request still has to
			// present a token signed by that key and inside its
			// validity window.
			return match, nil
		}
		return nil, err
	}

	if match := selectKeys(refreshed, kid, alg); len(match) > 0 {
		return match, nil
	}
	return nil, fmt.Errorf("issuer %s publishes no key matching the token's key ID %q and algorithm %q",
		k.issuer, kid, alg)
}

func (k *keySet) snapshot() ([]jose.JSONWebKey, time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	// The slice is never appended to after publication — refreshKeys
	// replaces it wholesale — so handing out the header is safe.
	return k.keys, k.fetchedAt
}

// refreshKeys fetches the key set, at most one fetch at a time and at
// most one per KeyRefreshFloor.
//
// since is when the caller last saw the cache filled. A successful
// fetch by somebody else after that instant is as good as one of our
// own, and is returned instead of a fetch — otherwise a request that
// arrived a microsecond behind a concurrent refresh would be refused by
// the floor with a current key set sitting right in front of it.
func (k *keySet) refreshKeys(ctx context.Context, since time.Time) ([]jose.JSONWebKey, error) {
	k.mu.Lock()
	if k.fetchedAt.After(since) {
		keys := k.keys
		k.mu.Unlock()
		return keys, nil
	}
	if f := k.inflight; f != nil {
		k.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.done:
			return f.keys, f.err
		}
	}
	if !k.lastAttempt.IsZero() {
		if since := k.now().Sub(k.lastAttempt); since < k.floor {
			k.mu.Unlock()
			return nil, fmt.Errorf("declined to refetch the key set from %s: last attempt was %s ago, "+
				"under the %s floor", k.issuer, since.Round(time.Millisecond), k.floor)
		}
	}
	f := &inflight{done: make(chan struct{})}
	k.inflight = f
	k.lastAttempt = k.now()
	k.mu.Unlock()

	keys, err := k.fetch(ctx)

	k.mu.Lock()
	f.keys, f.err = keys, err
	if err == nil {
		k.keys = keys
		k.fetchedAt = k.now()
	}
	k.inflight = nil
	k.mu.Unlock()
	close(f.done)

	return keys, err
}

// fetch resolves the key endpoint, discovering it if necessary, and
// reads the published keys.
func (k *keySet) fetch(ctx context.Context) ([]jose.JSONWebKey, error) {
	// Detached from the request that triggered it: the result is shared
	// with every goroutine waiting on this inflight, so the first
	// client to hang up must not cancel the fetch for the rest. They
	// keep their own cancellation — see the select in refreshKeys.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
	defer cancel()

	url, err := k.resolveJWKSURL(ctx)
	if err != nil {
		return nil, err
	}
	body, err := getJSON(ctx, k.client, url)
	if err != nil {
		return nil, fmt.Errorf("fetching the key set: %w", err)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return nil, fmt.Errorf("reading the key set from %s: %w", url, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("the key set at %s contains no usable public signing key", url)
	}
	return keys, nil
}

// resolveJWKSURL returns the configured key endpoint, or discovers it
// once and remembers it.
func (k *keySet) resolveJWKSURL(ctx context.Context) (string, error) {
	if k.jwksURL != "" {
		return k.jwksURL, nil
	}
	k.mu.Lock()
	cached := k.discovered
	k.mu.Unlock()
	if cached != "" {
		return cached, nil
	}

	url, err := discover(ctx, k.client, k.issuer)
	if err != nil {
		return "", err
	}
	k.mu.Lock()
	k.discovered = url
	k.mu.Unlock()
	return url, nil
}

// selectKeys returns the cached keys that could have made this
// signature.
//
// A token naming a key ID is matched against that ID alone. A token
// naming none — legal, and what a provider with a single key sometimes
// emits — is matched against every key, which is why the caller tries
// them in turn rather than trusting the first.
func selectKeys(keys []jose.JSONWebKey, kid, alg string) []jose.JSONWebKey {
	var out []jose.JSONWebKey
	for i := range keys {
		key := keys[i]
		if kid != "" && key.KeyID != kid {
			continue
		}
		// A key published for one algorithm must not verify another.
		// Without this a provider's RSA key published as PS256 would
		// also verify RS256 — different padding, same key, and the
		// issuer said which one it signs with.
		if key.Algorithm != "" && alg != "" && key.Algorithm != alg {
			continue
		}
		out = append(out, key)
	}
	return out
}

// parseJWKS decodes a JWK Set, skipping keys it cannot use rather than
// failing the set.
//
// A provider legitimately publishes encryption keys alongside signing
// keys, and may publish a key type this build of go-jose does not
// implement. Failing the whole document over one of those would take
// authentication down for every caller, including the ones whose key
// is right there in the same response.
func parseJWKS(body []byte) ([]jose.JSONWebKey, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decoding the JWK Set: %w", err)
	}
	out := make([]jose.JSONWebKey, 0, len(doc.Keys))
	for _, raw := range doc.Keys {
		var key jose.JSONWebKey
		if err := key.UnmarshalJSON(raw); err != nil {
			continue // a key type this build cannot represent
		}
		// "enc" keys are for encryption; a key with no "use" may be
		// used for either, per RFC 7517 §4.2.
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		// IsPublic excludes a symmetric key, which must never become a
		// verification key here: that is the other half of the HS256
		// confusion the algorithm allowlist closes.
		if !key.IsPublic() || !key.Valid() {
			continue
		}
		out = append(out, key)
	}
	return out, nil
}

// getJSON performs a bounded GET and returns the body.
func getJSON(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building the request for %s: %w", url, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", url, err)
	}
	defer func() {
		// Drained so the connection can be reused: the next fetch of
		// this endpoint is the common case.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxJWKSBytes))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", url, resp.Status)
	}
	// One byte over the limit so truncation is detected rather than
	// handed to the JSON decoder as a malformed document.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", url, err)
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("%s returned more than %d bytes", url, maxJWKSBytes)
	}
	return body, nil
}
