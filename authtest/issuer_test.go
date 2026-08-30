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

package authtest_test

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/go-steer/purser/authtest"
)

// allAlgs is every algorithm Issuer.AddKey must be able to generate a
// key for. It is the intersection of what go-jose signs with and what
// purser's OIDC authenticator will accept.
var allAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512", "EdDSA"}

// payloadOf verifies a minted token against the issuer's published keys
// and returns its claims. Verifying here rather than merely decoding is
// the point: a provider that mints tokens its own key set cannot verify
// would make every authenticator test meaningless.
func payloadOf(tb testing.TB, iss *authtest.Issuer, token string) map[string]any {
	tb.Helper()

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(iss.JWKS(tb), &set); err != nil {
		tb.Fatalf("decoding the key set: %v", err)
	}
	algs := make([]jose.SignatureAlgorithm, 0, len(allAlgs))
	for _, alg := range allAlgs {
		algs = append(algs, jose.SignatureAlgorithm(alg))
	}
	jws, err := jose.ParseSignedCompact(token, algs)
	if err != nil {
		tb.Fatalf("parsing the minted token: %v", err)
	}
	for _, key := range set.Keys {
		if payload, err := jws.Verify(key.Key); err == nil {
			var claims map[string]any
			if err := json.Unmarshal(payload, &claims); err != nil {
				tb.Fatalf("decoding the payload: %v", err)
			}
			return claims
		}
	}
	tb.Fatalf("the minted token verifies against none of the %d published keys", len(set.Keys))
	return nil
}

func TestIssuerMintsAVerifiableToken(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)
	before := time.Now().Add(-time.Second).Unix()
	claims := payloadOf(t, iss, iss.Mint(t, authtest.TokenOptions{}))

	if got := claims["iss"]; got != iss.URL() {
		t.Errorf("iss = %v, want %q", got, iss.URL())
	}
	if got, _ := claims["sub"].(string); got == "" {
		t.Errorf("sub = %v, want a non-empty default", claims["sub"])
	}
	aud, ok := claims["aud"].([]any)
	if !ok || len(aud) != 1 || aud[0] != authtest.DefaultAudience {
		t.Errorf("aud = %v, want [%q]", claims["aud"], authtest.DefaultAudience)
	}
	iat, ok := claims["iat"].(float64)
	if !ok || int64(iat) < before {
		t.Errorf("iat = %v, want a timestamp no older than the start of this test", claims["iat"])
	}
	exp, ok := claims["exp"].(float64)
	if !ok || exp <= iat {
		t.Errorf("exp = %v, want it after iat (%v)", claims["exp"], claims["iat"])
	}
	if _, present := claims["email"]; present {
		t.Errorf("email = %v, want it omitted when TokenOptions.Email is empty", claims["email"])
	}
	if _, present := claims["nbf"]; present {
		t.Errorf("nbf = %v, want it omitted when TokenOptions.NotBefore is zero", claims["nbf"])
	}
}

func TestMintOptions(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)
	nbf := time.Now().Add(-time.Minute).Truncate(time.Second)
	exp := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	claims := payloadOf(t, iss, iss.Mint(t, authtest.TokenOptions{
		Subject:   "sub-9",
		Email:     "alice@example.com",
		Audience:  []string{"a", "b"},
		Issuer:    "https://elsewhere.example",
		NotBefore: nbf,
		Expiry:    exp,
	}))

	want := map[string]any{
		"iss":            "https://elsewhere.example",
		"sub":            "sub-9",
		"email":          "alice@example.com",
		"email_verified": true,
		"nbf":            float64(nbf.Unix()),
		"exp":            float64(exp.Unix()),
	}
	for key, wantValue := range want {
		if got := claims[key]; got != wantValue {
			t.Errorf("%s = %v, want %v", key, got, wantValue)
		}
	}
	aud, _ := claims["aud"].([]any)
	if len(aud) != 2 || aud[0] != "a" || aud[1] != "b" {
		t.Errorf("aud = %v, want [a b]", claims["aud"])
	}
}

func TestEmailUnverified(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)
	claims := payloadOf(t, iss, iss.Mint(t, authtest.TokenOptions{
		Email:           "alice@example.com",
		EmailUnverified: true,
	}))
	if got := claims["email_verified"]; got != false {
		t.Errorf("email_verified = %v, want false", got)
	}
}

// TestClaimsOverrideAndRemove pins the escape hatch that lets a test
// reach the payloads a well-behaved provider never emits: overriding a
// claim with the wrong type, and removing one entirely.
func TestClaimsOverrideAndRemove(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)
	claims := payloadOf(t, iss, iss.Mint(t, authtest.TokenOptions{
		Subject: "ignored",
		Claims: map[string]any{
			"sub": "from-Claims",
			"exp": nil,
			"hd":  "example.com",
		},
	}))

	if got := claims["sub"]; got != "from-Claims" {
		t.Errorf("sub = %v, want the value from Claims to win", got)
	}
	if got, present := claims["exp"]; present {
		t.Errorf("exp = %v, want a nil value in Claims to remove the claim rather than set it to null", got)
	}
	if got := claims["hd"]; got != "example.com" {
		t.Errorf("hd = %v, want the extra claim to be merged in", got)
	}
}

// TestAddKeyIsAGradualRotation pins that adding a key leaves the
// previous ones published: the shape of a real rotation, where a new
// key appears in the set before anything is signed with it.
func TestAddKeyIsAGradualRotation(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)
	first := publishedIDs(t, iss)
	if len(first) != 1 {
		t.Fatalf("a new issuer publishes %d keys, want 1", len(first))
	}

	second := iss.AddKey(t, "ES256")
	after := publishedIDs(t, iss)
	if want := append(slices.Clone(first), second); !slices.Equal(after, want) {
		t.Errorf("published keys = %v, want %v", after, want)
	}

	// The new key is the one Mint signs with, and the old one still
	// verifies what it signed.
	older := iss.Mint(t, authtest.TokenOptions{KeyID: first[0]})
	newer := iss.Mint(t, authtest.TokenOptions{})
	if got := keyIDOf(t, older); got != first[0] {
		t.Errorf("KeyID: %q minted a token signed by %q", first[0], got)
	}
	if got := keyIDOf(t, newer); got != second {
		t.Errorf("the default key is %q, want the most recently added (%q)", got, second)
	}
	payloadOf(t, iss, older)
	payloadOf(t, iss, newer)
}

// TestRotateWithdrawsTheOldKey pins the abrupt rotation, which is the
// only way a test can show that a withdrawn key stops being accepted.
func TestRotateWithdrawsTheOldKey(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)
	before := publishedIDs(t, iss)
	old := iss.Mint(t, authtest.TokenOptions{})

	replacement := iss.Rotate(t)
	if after := publishedIDs(t, iss); !slices.Equal(after, []string{replacement}) {
		t.Errorf("published keys = %v, want only %q", after, replacement)
	}
	if slices.Contains(before, replacement) {
		t.Errorf("Rotate returned an already-published key ID %q", replacement)
	}
	if got := keyIDOf(t, old); got != before[0] {
		t.Errorf("the pre-rotation token names key %q, want %q", got, before[0])
	}

	// The old token no longer verifies against anything published.
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(iss.JWKS(t), &set); err != nil {
		t.Fatalf("decoding the key set: %v", err)
	}
	jws, err := jose.ParseSignedCompact(old, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parsing the pre-rotation token: %v", err)
	}
	for _, key := range set.Keys {
		if _, err := jws.Verify(key.Key); err == nil {
			t.Fatalf("the pre-rotation token still verifies against published key %q", key.KeyID)
		}
	}
}

// TestUnpublishedKey covers the well-formed token from the wrong
// signer.
func TestUnpublishedKey(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)
	token := iss.Mint(t, authtest.TokenOptions{UnpublishedKey: true})

	if slices.Contains(publishedIDs(t, iss), keyIDOf(t, token)) {
		t.Errorf("the token names key %q, which is in the published set", keyIDOf(t, token))
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(iss.JWKS(t), &set); err != nil {
		t.Fatalf("decoding the key set: %v", err)
	}
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parsing the token: %v", err)
	}
	for _, key := range set.Keys {
		if _, err := jws.Verify(key.Key); err == nil {
			t.Fatalf("a token minted with UnpublishedKey verifies against published key %q", key.KeyID)
		}
	}
}

// TestEveryAlgorithmMints pins that AddKey covers the whole allowlist
// purser's OIDC authenticator accepts. A test that wants to exercise
// EdDSA should not discover here that the provider cannot mint one.
func TestEveryAlgorithmMints(t *testing.T) {
	t.Parallel()

	for _, alg := range allAlgs {
		t.Run(alg, func(t *testing.T) {
			t.Parallel()
			iss := authtest.NewIssuer(t)
			kid := iss.AddKey(t, alg)
			token := iss.Mint(t, authtest.TokenOptions{KeyID: kid})
			if got := keyIDOf(t, token); got != kid {
				t.Errorf("token key ID = %q, want %q", got, kid)
			}
			payloadOf(t, iss, token)
		})
	}
}

// TestRequestCounters pins the numbers a key-cache test asserts
// against, including that JWKS does not count as a fetch.
func TestRequestCounters(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)
	if got, want := iss.JWKSRequests(), 0; got != want {
		t.Errorf("JWKSRequests() = %d before any request, want %d", got, want)
	}
	if got, want := iss.DiscoveryRequests(), 0; got != want {
		t.Errorf("DiscoveryRequests() = %d before any request, want %d", got, want)
	}

	iss.JWKS(t)
	if got := iss.JWKSRequests(); got != 0 {
		t.Errorf("JWKSRequests() = %d after JWKS(), want 0: reading the set in-process is not a fetch", got)
	}

	get(t, iss.Client(), iss.JWKSURL())
	get(t, iss.Client(), iss.URL()+"/.well-known/openid-configuration")
	get(t, iss.Client(), iss.JWKSURL())
	if got, want := iss.JWKSRequests(), 2; got != want {
		t.Errorf("JWKSRequests() = %d, want %d", got, want)
	}
	if got, want := iss.DiscoveryRequests(), 1; got != want {
		t.Errorf("DiscoveryRequests() = %d, want %d", got, want)
	}
}

// TestDiscoveryDocument pins the two fields anything reading it needs.
func TestDiscoveryDocument(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(get(t, iss.Client(), iss.URL()+"/.well-known/openid-configuration"), &doc); err != nil {
		t.Fatalf("decoding the discovery document: %v", err)
	}
	if doc.Issuer != iss.URL() {
		t.Errorf("issuer = %q, want %q", doc.Issuer, iss.URL())
	}
	if doc.JWKSURI != iss.JWKSURL() {
		t.Errorf("jwks_uri = %q, want %q", doc.JWKSURI, iss.JWKSURL())
	}
}

// TestPublishedKeysArePublic pins that the JWK Set carries no private
// key material. The signing halves stay in the process.
func TestPublishedKeysArePublic(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)
	iss.AddKey(t, "ES256")
	iss.AddKey(t, "EdDSA")

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(iss.JWKS(t), &set); err != nil {
		t.Fatalf("decoding the key set: %v", err)
	}
	if len(set.Keys) != 3 {
		t.Fatalf("published %d keys, want 3", len(set.Keys))
	}
	for _, key := range set.Keys {
		if !key.IsPublic() {
			t.Errorf("published key %q carries private material", key.KeyID)
		}
		if !key.Valid() {
			t.Errorf("published key %q is not valid", key.KeyID)
		}
		if key.Use != "sig" {
			t.Errorf("published key %q has use %q, want \"sig\"", key.KeyID, key.Use)
		}
		if key.Algorithm == "" {
			t.Errorf("published key %q names no algorithm", key.KeyID)
		}
	}
}

// TestCloseStopsServingButKeepsMinting pins the outage helper: the keys
// live in this process, so a closed issuer still mints the token whose
// verification is the thing under test.
func TestCloseStopsServingButKeepsMinting(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)
	iss.Close()
	iss.Close() // idempotent, and the cleanup will close it a third time

	if _, err := iss.Client().Get(iss.JWKSURL()); err == nil {
		t.Errorf("the key endpoint answered after Close")
	}
	if token := iss.Mint(t, authtest.TokenOptions{}); token == "" {
		t.Errorf("Mint returned an empty token after Close")
	}
}

// TestKeyIDAndPublicKeyNameTheSigningKey pins the two accessors a test
// needs to build a header by hand.
func TestKeyIDAndPublicKeyNameTheSigningKey(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)
	first := iss.KeyID(t)
	if got := keyIDOf(t, iss.Mint(t, authtest.TokenOptions{})); got != first {
		t.Errorf("KeyID = %q but Mint signed with %q", first, got)
	}

	second := iss.AddKey(t, "ES256")
	if got := iss.KeyID(t); got != second {
		t.Errorf("KeyID = %q after AddKey, want the new key %q", got, second)
	}

	// PublicKey is the DER of the same public half the JWK Set carries,
	// which is what makes it the right secret for an algorithm-confusion
	// token.
	for _, keyID := range publishedIDs(t, iss) {
		want, err := x509.MarshalPKIXPublicKey(publishedKey(t, iss, keyID))
		if err != nil {
			t.Fatalf("marshalling the published key %q: %v", keyID, err)
		}
		if got := iss.PublicKey(t, keyID); !bytes.Equal(got, want) {
			t.Errorf("PublicKey(%q) does not match the published key", keyID)
		}
	}
	if got := iss.PublicKey(t, ""); !bytes.Equal(got, iss.PublicKey(t, second)) {
		t.Errorf(`PublicKey("") is not the current key`)
	}
}

// TestClaimsIsWhatMintSigns pins that the payload Claims hands back is
// the one Mint would have signed, so a test can take those claims and
// put its own header over them.
func TestClaimsIsWhatMintSigns(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)
	opts := authtest.TokenOptions{Subject: "sub-9", Email: "someone@example.com"}

	var direct map[string]any
	if err := json.Unmarshal(iss.Claims(t, opts), &direct); err != nil {
		t.Fatalf("decoding the claims: %v", err)
	}
	signed := payloadOf(t, iss, iss.Mint(t, opts))

	// iat and exp are read from the clock at each call, so they differ
	// by however long the two took — compared within a tolerance rather
	// than dropped, since dropping them would hide a Mint that signed a
	// different expiry from the one Claims reports, which is exactly the
	// divergence this test exists to catch.
	for _, drifting := range []string{"iat", "exp"} {
		a, b := seconds(t, direct, drifting), seconds(t, signed, drifting)
		if d := a - b; d < -5 || d > 5 {
			t.Errorf("%q is %d from Claims and %d from Mint, %ds apart", drifting, a, b, d)
		}
		delete(direct, drifting)
		delete(signed, drifting)
	}
	if !maps.Equal(toStrings(t, direct), toStrings(t, signed)) {
		t.Errorf("Claims produced\n\t%v\nbut Mint signed\n\t%v", direct, signed)
	}
}

// seconds reads a NumericDate claim, failing if it is absent or is not
// a number.
func seconds(tb testing.TB, claims map[string]any, name string) int64 {
	tb.Helper()

	v, ok := claims[name]
	if !ok {
		tb.Fatalf("there is no %q claim in %v", name, claims)
	}
	f, ok := v.(float64)
	if !ok {
		tb.Fatalf("the %q claim is %#v, want a number", name, v)
	}
	return int64(f)
}

// toStrings renders a claims map for comparison, so a nested value
// compares by its JSON rather than by pointer identity.
func toStrings(tb testing.TB, claims map[string]any) map[string]string {
	tb.Helper()
	out := make(map[string]string, len(claims))
	for k, v := range claims {
		b, err := json.Marshal(v)
		if err != nil {
			tb.Fatalf("marshalling the %q claim: %v", k, err)
		}
		out[k] = string(b)
	}
	return out
}

// TestRawTokenBuildsHeadersThatLie pins the harness capability the
// authenticator tests depend on: a token whose header disagrees with
// the signature under it. If RawToken quietly produced an honest token
// instead, every test built on it would pass while testing nothing.
func TestRawTokenBuildsHeadersThatLie(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)
	first := iss.KeyID(t)
	second := iss.AddKey(t, "RS256")
	payload := iss.Claims(t, authtest.TokenOptions{})

	t.Run("the default is an honest token", func(t *testing.T) {
		t.Parallel()

		token := iss.RawToken(t, authtest.RawTokenOptions{Payload: payload})
		header := headerOf(t, token)
		if got := keyIDOf(t, token); got != second {
			t.Errorf("kid = %q, want the current key %q", got, second)
		}
		if got := header["alg"]; got != "RS256" {
			t.Errorf("alg = %v, want RS256", got)
		}
		if got := header["typ"]; got != "JWT" {
			t.Errorf("typ = %v, want JWT", got)
		}
		payloadOf(t, iss, token) // must verify against the published set
	})

	t.Run("the default alg is the key's own", func(t *testing.T) {
		t.Parallel()

		// Not RS256, which is what every other case here signs with and
		// so cannot distinguish from a hardcoded default.
		for _, alg := range []string{"ES256", "EdDSA", "PS384"} {
			iss := authtest.NewIssuer(t)
			iss.AddKey(t, alg)
			token := iss.RawToken(t, authtest.RawTokenOptions{Payload: iss.Claims(t, authtest.TokenOptions{})})
			if got := headerOf(t, token)["alg"]; got != alg {
				t.Errorf("alg = %v for a %s key, want %s", got, alg, alg)
			}
		}
	})

	t.Run("a kid naming another key", func(t *testing.T) {
		t.Parallel()

		// SignWith names the older key and the header names the newer, so
		// neither is the one the other default would pick: the signature
		// is wrong if SignWith is ignored, and the kid is wrong if the
		// header override is.
		token := iss.RawToken(t, authtest.RawTokenOptions{
			Payload:  payload,
			SignWith: first,
			Header:   map[string]any{"kid": second},
		})
		if got := keyIDOf(t, token); got != second {
			t.Errorf("kid = %q, want the overridden %q", got, second)
		}
		if verifiesUnder(t, iss, token, second) {
			t.Errorf("the token verifies under %q, the key it falsely names", second)
		}
		if !verifiesUnder(t, iss, token, first) {
			t.Errorf("the token does not verify under %q, the key SignWith named", first)
		}
	})

	t.Run("an alg the key was not published for", func(t *testing.T) {
		t.Parallel()

		// Its own issuer: AddKey moves the current key, and the sibling
		// cases above assert on which key that is. A third key after the
		// PS256 one, so SignWith is naming something other than whatever
		// the default would have picked.
		iss := authtest.NewIssuer(t)
		ps := iss.AddKey(t, "PS256")
		iss.AddKey(t, "ES256")
		token := iss.RawToken(t, authtest.RawTokenOptions{
			Payload:   iss.Claims(t, authtest.TokenOptions{}),
			SignWith:  ps,
			Algorithm: "RS256",
		})
		if got := headerOf(t, token)["alg"]; got != "RS256" {
			t.Errorf("alg = %v, want the overridden RS256", got)
		}
		// A real RS256 signature by the key material, not a spliced one.
		jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.RS256})
		if err != nil {
			t.Fatalf("parsing: %v", err)
		}
		if _, err := jws.Verify(publishedKey(t, iss, ps)); err != nil {
			t.Errorf("the RS256 signature does not verify under the published key material: %v", err)
		}
	})

	t.Run("no kid at all", func(t *testing.T) {
		t.Parallel()

		token := iss.RawToken(t, authtest.RawTokenOptions{Payload: payload, OmitKeyID: true})
		if _, present := headerOf(t, token)["kid"]; present {
			t.Errorf("kid is present, want it omitted")
		}
		payloadOf(t, iss, token) // still a real signature
	})

	t.Run("alg none", func(t *testing.T) {
		t.Parallel()

		token := iss.RawToken(t, authtest.RawTokenOptions{
			Payload:  payload,
			Unsigned: true,
			// The header is spliced rather than signed on this path, since
			// go-jose will not sign "none" — so the override has to be
			// pinned here separately from the signed path above.
			Header: map[string]any{"kid": first},
		})
		header := headerOf(t, token)
		if got := header["alg"]; got != "none" {
			t.Errorf("alg = %v, want none", got)
		}
		if got := header["kid"]; got != first {
			t.Errorf("kid = %v, want the overridden %q", got, first)
		}
		if got := strings.Count(token, "."); got != 2 {
			t.Errorf("the token has %d dots, want 2", got)
		}
		if !strings.HasSuffix(token, ".") {
			t.Errorf("the signature segment is not empty: %s", token)
		}
		// The claims still have to be there. A refusal test that names the
		// algorithm but is handed "header.." would be refused for having
		// no claims instead, and would read as passing.
		_, rest, _ := strings.Cut(token, ".")
		body, _, _ := strings.Cut(rest, ".")
		got, err := base64.RawURLEncoding.DecodeString(body)
		if err != nil {
			t.Fatalf("decoding the payload segment: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("payload = %s, want it carried through verbatim", got)
		}
	})

	t.Run("an HMAC over the published key", func(t *testing.T) {
		t.Parallel()

		secret := iss.PublicKey(t, "")
		token := iss.RawToken(t, authtest.RawTokenOptions{Payload: payload, HMACKey: secret})
		if got := headerOf(t, token)["alg"]; got != "HS256" {
			t.Errorf("alg = %v, want HS256", got)
		}
		// Keyed by the published material, which is the whole attack: a
		// verifier that accepted HS256 could check this and it would pass.
		jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.HS256})
		if err != nil {
			t.Fatalf("parsing: %v", err)
		}
		if _, err := jws.Verify(secret); err != nil {
			t.Errorf("the HMAC does not verify under the published key: %v", err)
		}
	})

	t.Run("an unpublished key", func(t *testing.T) {
		t.Parallel()

		token := iss.RawToken(t, authtest.RawTokenOptions{Payload: payload, UnpublishedKey: true})
		kid := keyIDOf(t, token)
		if slices.Contains(publishedIDs(t, iss), kid) {
			t.Errorf("kid %q is in the published set", kid)
		}
	})

	t.Run("a payload that is not a JSON object", func(t *testing.T) {
		t.Parallel()

		token := iss.RawToken(t, authtest.RawTokenOptions{Payload: []byte("not json")})
		jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.RS256})
		if err != nil {
			t.Fatalf("parsing: %v", err)
		}
		got, err := jws.Verify(publishedKey(t, iss, keyIDOf(t, token)))
		if err != nil {
			t.Fatalf("verifying: %v", err)
		}
		if string(got) != "not json" {
			t.Errorf("payload = %q, want it carried through verbatim", got)
		}
	})
}

// headerOf decodes a compact token's protected header without verifying
// it, which is the only way to see a header that lies.
func headerOf(tb testing.TB, token string) map[string]any {
	tb.Helper()

	segment, _, ok := strings.Cut(token, ".")
	if !ok {
		tb.Fatalf("the token has no header segment: %s", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		tb.Fatalf("decoding the header segment: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		tb.Fatalf("decoding the header: %v", err)
	}
	return header
}

// publishedKey is the public key the JWK Set carries under the given ID.
func publishedKey(tb testing.TB, iss *authtest.Issuer, keyID string) any {
	tb.Helper()

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(iss.JWKS(tb), &set); err != nil {
		tb.Fatalf("decoding the key set: %v", err)
	}
	i := slices.IndexFunc(set.Keys, func(k jose.JSONWebKey) bool { return k.KeyID == keyID })
	if i < 0 {
		tb.Fatalf("the key set does not carry %q", keyID)
	}
	return set.Keys[i].Key
}

// verifiesUnder reports whether the token's signature checks out under
// the named published key.
func verifiesUnder(tb testing.TB, iss *authtest.Issuer, token, keyID string) bool {
	tb.Helper()

	algs := make([]jose.SignatureAlgorithm, 0, len(allAlgs))
	for _, alg := range allAlgs {
		algs = append(algs, jose.SignatureAlgorithm(alg))
	}
	jws, err := jose.ParseSignedCompact(token, algs)
	if err != nil {
		tb.Fatalf("parsing the token: %v", err)
	}
	_, err = jws.Verify(publishedKey(tb, iss, keyID))
	return err == nil
}

// publishedIDs lists the key IDs in the published set, in order.
func publishedIDs(tb testing.TB, iss *authtest.Issuer) []string {
	tb.Helper()
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(iss.JWKS(tb), &set); err != nil {
		tb.Fatalf("decoding the key set: %v", err)
	}
	ids := make([]string, 0, len(set.Keys))
	for _, key := range set.Keys {
		ids = append(ids, key.KeyID)
	}
	return ids
}

// keyIDOf reads the "kid" from a token's header without verifying it.
func keyIDOf(tb testing.TB, token string) string {
	tb.Helper()
	algs := make([]jose.SignatureAlgorithm, 0, len(allAlgs))
	for _, alg := range allAlgs {
		algs = append(algs, jose.SignatureAlgorithm(alg))
	}
	jws, err := jose.ParseSignedCompact(token, algs)
	if err != nil {
		tb.Fatalf("parsing the token: %v", err)
	}
	if len(jws.Signatures) != 1 {
		tb.Fatalf("the token carries %d signatures, want 1", len(jws.Signatures))
	}
	return jws.Signatures[0].Header.KeyID
}

func get(tb testing.TB, client *http.Client, url string) []byte {
	tb.Helper()
	resp, err := client.Get(url)
	if err != nil {
		tb.Fatalf("GET %s: %v", url, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			tb.Errorf("closing the response body: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		tb.Fatalf("GET %s returned %s", url, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("reading %s: %v", url, err)
	}
	return body
}
