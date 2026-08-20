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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// DefaultAudience is the audience Issuer.Mint puts on a token when
// TokenOptions.Audience is empty. Configure the authenticator under
// test with it, or set an audience explicitly on both sides.
const DefaultAudience = "purser.authtest/audience"

// defaultSubject is the "sub" claim Mint uses when the caller supplies
// none. Every token needs one — a token without "sub" is rejected — and
// most tests do not care what it is.
const defaultSubject = "purser.authtest/subject"

// Issuer is an OpenID Connect provider backed by an httptest server. It
// serves a discovery document and a JWK Set, and mints tokens signed by
// the keys it publishes.
//
// It runs over TLS, because purser's OIDC authenticator refuses a
// plaintext issuer: the transport is what authenticates the published
// keys. Pass Client to the authenticator's Options.HTTPClient so it
// trusts the server's ephemeral certificate.
//
// Every method reports failure through testing.TB. A provider that
// cannot mint is a broken test, not a case under test. The server is
// closed by a t.Cleanup registered in NewIssuer.
type Issuer struct {
	srv *httptest.Server

	mu           sync.Mutex
	keys         []signingKey // published, in order; the last is current
	minted       int          // names successive keys
	jwksHits     int
	discoveryHit int
}

// signingKey is one published key and the private half that signs with
// it.
type signingKey struct {
	id   string
	alg  jose.SignatureAlgorithm
	priv crypto.Signer
}

// NewIssuer starts a provider with a single RS256 key.
//
// RS256 rather than something quicker to generate because it is what
// OpenID Connect requires every provider to support and what the real
// ones use; a test suite that only ever sees elliptic keys would not
// notice an authenticator that mishandles the common case. Use AddKey
// for the others.
func NewIssuer(tb testing.TB) *Issuer {
	tb.Helper()

	i := &Issuer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", i.serveDiscovery)
	mux.HandleFunc("/jwks", i.serveJWKS)
	i.srv = httptest.NewTLSServer(mux)
	tb.Cleanup(i.srv.Close)

	i.AddKey(tb, string(jose.RS256))
	return i
}

// URL is the issuer URL: what goes in the authenticator's
// Options.Issuer, and what appears in the "iss" claim of minted tokens.
func (i *Issuer) URL() string { return i.srv.URL }

// JWKSURL is the key endpoint, for a test that configures it directly
// rather than letting the authenticator discover it.
func (i *Issuer) JWKSURL() string { return i.srv.URL + "/jwks" }

// Client returns an http.Client that trusts this server's certificate.
func (i *Issuer) Client() *http.Client { return i.srv.Client() }

// Certificate is the server's ephemeral TLS certificate, for a test
// that has to build a client trusting this issuer alongside something
// else.
func (i *Issuer) Certificate() *x509.Certificate { return i.srv.Certificate() }

// Close stops the server, for a test that needs the provider to become
// unreachable: a key cache that must serve what it already has, or a
// cold cache that must report the outage. Idempotent, and harmless
// alongside the cleanup NewIssuer registers.
//
// Mint keeps working afterwards. The keys are held in this process, so
// a closed issuer still mints the token whose verification is the thing
// under test.
func (i *Issuer) Close() { i.srv.Close() }

// JWKS returns the key set exactly as the endpoint serves it, for a
// test that needs to serve a doctored version of it from somewhere
// else. It does not count as a fetch.
func (i *Issuer) JWKS(tb testing.TB) string {
	tb.Helper()

	i.mu.Lock()
	defer i.mu.Unlock()
	body, err := json.Marshal(i.keySet())
	if err != nil {
		tb.Fatalf("authtest: marshalling the key set: %v", err)
	}
	return string(body)
}

// JWKSRequests reports how many times the key endpoint has been
// fetched. It is what a test asserts against to pin a key cache: that
// a hundred verifications cost one fetch, and that a flood of
// unknown-key tokens does not cost a hundred.
func (i *Issuer) JWKSRequests() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.jwksHits
}

// DiscoveryRequests reports how many times the discovery document has
// been fetched.
func (i *Issuer) DiscoveryRequests() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.discoveryHit
}

// AddKey generates a key for alg, publishes it, and makes it the one
// Mint signs with. It returns the new key's ID.
//
// The keys already published stay published, which is what a real
// rotation looks like: the new key appears in the JWK Set before
// anything is signed with it, and the old one stays until the tokens it
// signed have expired. Use Rotate for the abrupt version.
func (i *Issuer) AddKey(tb testing.TB, alg string) string {
	tb.Helper()
	key := i.generate(tb, jose.SignatureAlgorithm(alg))

	i.mu.Lock()
	defer i.mu.Unlock()
	i.keys = append(i.keys, key)
	return key.id
}

// Rotate replaces the published key set with a single new key of the
// same algorithm as the current one, and returns its ID.
//
// This is the abrupt rotation: tokens signed by the old key stop
// verifying as soon as anything refetches the set. It is how a test
// pins that a key withdrawn by the issuer eventually stops being
// accepted here, which is a property no gradual rotation can
// demonstrate.
func (i *Issuer) Rotate(tb testing.TB) string {
	tb.Helper()
	key := i.generate(tb, i.currentKey(tb).alg)

	i.mu.Lock()
	defer i.mu.Unlock()
	i.keys = []signingKey{key}
	return key.id
}

// TokenOptions describes a token to mint. The zero value yields a
// token that a correctly configured authenticator accepts: the issuer's
// own URL, DefaultAudience, a subject, and an hour of validity.
type TokenOptions struct {
	// Subject is the "sub" claim. Defaults to a fixed placeholder.
	Subject string

	// Email is the "email" claim, omitted when empty. Setting it also
	// sets "email_verified" to true, unless EmailUnverified says
	// otherwise.
	Email string

	// EmailUnverified mints "email_verified": false. Only meaningful
	// alongside Email.
	EmailUnverified bool

	// Audience is the "aud" claim. Defaults to DefaultAudience.
	Audience []string

	// Issuer overrides the "iss" claim, for the token that was minted
	// by somebody else and offered here.
	Issuer string

	// IssuedAt, NotBefore and Expiry are the validity window. IssuedAt
	// defaults to now and Expiry to an hour from now; NotBefore is
	// omitted when zero.
	IssuedAt  time.Time
	NotBefore time.Time
	Expiry    time.Time

	// Claims are merged into the payload last, so they override
	// anything above. A nil value removes the claim instead of setting
	// it to JSON null:
	//
	//	Claims: map[string]any{"exp": nil}          // no expiry at all
	//	Claims: map[string]any{"exp": "next week"}  // wrong type
	//	Claims: map[string]any{"hd": "example.com"} // an extra claim
	//
	// which is how a test reaches the malformed shapes that a
	// well-behaved provider never emits and an attacker will.
	Claims map[string]any

	// KeyID names the published key to sign with. Defaults to the
	// current one — the most recently added.
	KeyID string

	// UnpublishedKey signs with a freshly generated key that is not in
	// the JWK Set: a well-formed token from the wrong signer.
	UnpublishedKey bool
}

// Mint returns a signed, compact-serialized token.
func (i *Issuer) Mint(tb testing.TB, opts TokenOptions) string {
	tb.Helper()

	now := time.Now()
	claims := map[string]any{
		"iss": i.srv.URL,
		"sub": defaultSubject,
		"aud": []string{DefaultAudience},
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	if opts.Issuer != "" {
		claims["iss"] = opts.Issuer
	}
	if opts.Subject != "" {
		claims["sub"] = opts.Subject
	}
	if len(opts.Audience) > 0 {
		claims["aud"] = opts.Audience
	}
	if !opts.IssuedAt.IsZero() {
		claims["iat"] = opts.IssuedAt.Unix()
	}
	if !opts.NotBefore.IsZero() {
		claims["nbf"] = opts.NotBefore.Unix()
	}
	if !opts.Expiry.IsZero() {
		claims["exp"] = opts.Expiry.Unix()
	}
	if opts.Email != "" {
		claims["email"] = opts.Email
		claims["email_verified"] = !opts.EmailUnverified
	}
	for k, v := range opts.Claims {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		tb.Fatalf("authtest: marshalling claims: %v", err)
	}
	return i.sign(tb, opts, payload)
}

// sign serializes payload as a compact JWS under the selected key.
func (i *Issuer) sign(tb testing.TB, opts TokenOptions, payload []byte) string {
	tb.Helper()

	key := i.currentKey(tb)
	switch {
	case opts.UnpublishedKey:
		key = i.generate(tb, key.alg)
	case opts.KeyID != "":
		key = i.keyByID(tb, opts.KeyID)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: key.alg, Key: jose.JSONWebKey{Key: key.priv, KeyID: key.id}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		tb.Fatalf("authtest: building a signer for %s: %v", key.alg, err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		tb.Fatalf("authtest: signing: %v", err)
	}
	token, err := jws.CompactSerialize()
	if err != nil {
		tb.Fatalf("authtest: serializing: %v", err)
	}
	return token
}

func (i *Issuer) currentKey(tb testing.TB) signingKey {
	tb.Helper()
	i.mu.Lock()
	defer i.mu.Unlock()
	if len(i.keys) == 0 {
		tb.Fatalf("authtest: the issuer has no keys")
	}
	return i.keys[len(i.keys)-1]
}

func (i *Issuer) keyByID(tb testing.TB, id string) signingKey {
	tb.Helper()
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, k := range i.keys {
		if k.id == id {
			return k
		}
	}
	tb.Fatalf("authtest: no published key with ID %q", id)
	return signingKey{}
}

// generate makes a key of the right type for alg. The IDs are
// sequential rather than random so a failure message names the same key
// on every run.
func (i *Issuer) generate(tb testing.TB, alg jose.SignatureAlgorithm) signingKey {
	tb.Helper()

	i.mu.Lock()
	i.minted++
	id := fmt.Sprintf("key-%d", i.minted)
	i.mu.Unlock()

	var priv crypto.Signer
	var err error
	switch alg {
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case jose.ES256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jose.ES384:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case jose.ES512:
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case jose.EdDSA:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	default:
		tb.Fatalf("authtest: unsupported signature algorithm %q", alg)
	}
	if err != nil {
		tb.Fatalf("authtest: generating a %s key: %v", alg, err)
	}
	return signingKey{id: id, alg: alg, priv: priv}
}

func (i *Issuer) serveDiscovery(w http.ResponseWriter, r *http.Request) {
	i.mu.Lock()
	i.discoveryHit++
	algs := make([]string, 0, len(i.keys))
	for _, k := range i.keys {
		algs = append(algs, string(k.alg))
	}
	i.mu.Unlock()

	writeJSON(w, r, map[string]any{
		"issuer":                                i.srv.URL,
		"jwks_uri":                              i.srv.URL + "/jwks",
		"id_token_signing_alg_values_supported": algs,
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
	})
}

func (i *Issuer) serveJWKS(w http.ResponseWriter, r *http.Request) {
	i.mu.Lock()
	set := i.keySet()
	i.jwksHits++
	i.mu.Unlock()

	writeJSON(w, r, set)
}

// keySet builds the published document. Callers hold i.mu.
func (i *Issuer) keySet() jose.JSONWebKeySet {
	set := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(i.keys))}
	for _, k := range i.keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key:       k.priv.Public(),
			KeyID:     k.id,
			Algorithm: string(k.alg),
			Use:       "sig",
		})
	}
	return set
}

func writeJSON(w http.ResponseWriter, r *http.Request, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(body); err != nil {
		// The client hung up mid-response. Nothing to do about it here,
		// and a test that cares is asserting on its own side of the
		// connection.
		_ = r
	}
}
