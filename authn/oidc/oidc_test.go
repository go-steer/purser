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
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
	"github.com/go-steer/purser/authn/oidc"
	"github.com/go-steer/purser/authtest"
)

const (
	alice = "alice@example.com"
	bot   = "bot@example.com"
)

// newAuth starts an issuer and builds an authenticator that trusts it.
// mutate adjusts the options before construction.
func newAuth(t *testing.T, mutate func(*oidc.Options)) (*authtest.Issuer, *oidc.Auth) {
	t.Helper()

	iss := authtest.NewIssuer(t)
	opts := oidc.Options{
		Issuer:     iss.URL(),
		Audiences:  []string{authtest.DefaultAudience},
		HTTPClient: iss.Client(),
	}
	if mutate != nil {
		mutate(&opts)
	}
	a, err := oidc.New(opts)
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	return iss, a
}

// request returns a GET carrying token as a bearer credential.
func request(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// authenticate is the common shape: mint, present, resolve.
func authenticate(t *testing.T, a *oidc.Auth, token string) (purser.Caller, error) {
	t.Helper()
	return a.Authenticate(request(token))
}

func TestConformance(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, func(o *oidc.Options) {
		o.ProxyIdentities = []string{bot}
	})

	authtest.RunAuthenticatorSuite(t, authtest.Subject{
		Authenticator: a,
		WantSource:    purser.AuthSourceOIDC,
		Valid: func() (*http.Request, purser.Caller) {
			token := iss.Mint(t, authtest.TokenOptions{Email: alice})
			return request(token), purser.Caller{Identity: alice}
		},
		ProxyDenied: func() *http.Request {
			// A perfectly good credential that is simply not on the
			// proxy list.
			return request(iss.Mint(t, authtest.TokenOptions{Email: alice}))
		},
		Malformed: []authtest.MalformedCase{
			{Name: "not a JWT", Request: func() *http.Request { return request("not-a-token") }},
			{Name: "three empty segments", Request: func() *http.Request { return request("..") }},
			{Name: "truncated", Request: func() *http.Request {
				token := iss.Mint(t, authtest.TokenOptions{Email: alice})
				return request(token[:len(token)-8])
			}},
			{Name: "signature from an unpublished key", Request: func() *http.Request {
				return request(iss.Mint(t, authtest.TokenOptions{Email: alice, UnpublishedKey: true}))
			}},
			{Name: "wrong audience", Request: func() *http.Request {
				return request(iss.Mint(t, authtest.TokenOptions{
					Email: alice, Audience: []string{"some-other-service"},
				}))
			}},
			{Name: "expired", Request: func() *http.Request {
				return request(iss.Mint(t, authtest.TokenOptions{
					Email: alice, Expiry: time.Now().Add(-time.Hour),
				}))
			}},
			{Name: "another issuer", Request: func() *http.Request {
				return request(iss.Mint(t, authtest.TokenOptions{
					Email: alice, Issuer: "https://accounts.example.net",
				}))
			}},
		},
	})
}

func TestAuthenticateResolvesTheCaller(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, nil)
	expiry := time.Now().Add(30 * time.Minute).Truncate(time.Second)
	token := iss.Mint(t, authtest.TokenOptions{
		Subject: "1234567890",
		Email:   alice,
		Expiry:  expiry,
		Claims:  map[string]any{"hd": "example.com", "azp": "some-client-id"},
	})

	c, err := authenticate(t, a, token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if c.Identity != alice {
		t.Errorf("identity = %q, want %q", c.Identity, alice)
	}
	if c.Admin {
		t.Errorf("admin = true, want false")
	}
	want := map[string]string{
		oidc.LabelIssuer:                         iss.URL(),
		oidc.LabelSubject:                        "1234567890",
		oidc.LabelEmail:                          alice,
		oidc.LabelExpiry:                         expiry.UTC().Format(time.RFC3339),
		oidc.LabelClaimPrefix + "email_verified": "true",
		oidc.LabelClaimPrefix + "hd":             "example.com",
		oidc.LabelClaimPrefix + "azp":            "some-client-id",
	}
	if !maps.Equal(c.Labels, want) {
		t.Errorf("labels =\n\t%v\nwant\n\t%v", c.Labels, want)
	}
}

// TestAdminIsNeverReadFromAClaim pins the escalation this package
// refuses: a provider whose users can add arbitrary claims to their own
// tokens must not be able to grant themselves the admin bit.
func TestAdminIsNeverReadFromAClaim(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, nil)
	for _, claim := range []string{"admin", "Admin", "purser.admin", "roles"} {
		token := iss.Mint(t, authtest.TokenOptions{
			Email:  alice,
			Claims: map[string]any{claim: true},
		})
		c, err := authenticate(t, a, token)
		if err != nil {
			t.Fatalf("Authenticate with claim %q: %v", claim, err)
		}
		if c.Admin {
			t.Errorf("a token asserting %q: true resolved to an Admin caller", claim)
		}
		if got := c.Label(oidc.LabelClaimPrefix + claim); got != "true" {
			t.Errorf("claim %q label = %q, want %q: the claim should reach policy as a label", claim, got, "true")
		}
	}
}

func TestSideChannelHeaderIsAccepted(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, nil)
	token := iss.Mint(t, authtest.TokenOptions{Email: alice})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(authn.HeaderAttachToken, token)
	c, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("Authenticate via %s: %v", authn.HeaderAttachToken, err)
	}
	if c.Identity != alice {
		t.Errorf("identity = %q, want %q", c.Identity, alice)
	}
}

func TestAuthorizationSchemeIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, nil)
	token := iss.Mint(t, authtest.TokenOptions{Email: alice})

	for _, scheme := range []string{"Bearer", "bearer", "BEARER", "BeArEr"} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", scheme+" "+token)
		if _, err := a.Authenticate(r); err != nil {
			t.Errorf("Authenticate with scheme %q: %v", scheme, err)
		}
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Basic "+token)
	if _, err := a.Authenticate(r); !errors.Is(err, purser.ErrUnauthenticated) {
		t.Errorf("Authenticate with a Basic scheme = %v, want ErrUnauthenticated", err)
	}
}

// TestOversizeTokenIsRefusedBeforeParsing pins the bound on work done
// for a request that has proved nothing.
func TestOversizeTokenIsRefusedBeforeParsing(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, func(o *oidc.Options) { o.MaxTokenBytes = 256 })
	token := iss.Mint(t, authtest.TokenOptions{Email: alice})
	if len(token) <= 256 {
		t.Fatalf("token is %d bytes, expected the 256-byte limit to reject it", len(token))
	}

	_, err := authenticate(t, a, token)
	if !errors.Is(err, purser.ErrUnauthenticated) {
		t.Fatalf("Authenticate(oversize) = %v, want ErrUnauthenticated", err)
	}
	if !strings.Contains(err.Error(), "over the 256-byte limit") {
		t.Errorf("error = %v, want it to name the limit", err)
	}
	if got := iss.JWKSRequests(); got != 0 {
		t.Errorf("JWKS fetches = %d, want 0: an oversize token must be refused before any key work", got)
	}
}

// TestAlgorithmConfusionIsRefused covers the two classic JWS attacks.
// Both are refused at parse, by the allowlist, before any key is
// consulted.
//
// Each case asserts on the reason as well as the refusal. Every token
// here is also malformed in some way an unrelated check would catch —
// an empty signature, a subject nobody provisioned — so a bare
// ErrUnauthenticated would be satisfied by a verifier that had no
// allowlist at all. That the key endpoint was never touched is the
// other half: it holds whatever go-jose words its error as.
func TestAlgorithmConfusionIsRefused(t *testing.T) {
	t.Parallel()

	claims := func(iss *authtest.Issuer) []byte {
		return iss.Claims(t, authtest.TokenOptions{Subject: "attacker", Email: alice})
	}

	t.Run("alg none", func(t *testing.T) {
		t.Parallel()

		iss, a := newAuth(t, nil)
		token := iss.RawToken(t, authtest.RawTokenOptions{
			Payload:  claims(iss),
			Unsigned: true,
		})

		_, err := authenticate(t, a, token)
		if !errors.Is(err, purser.ErrUnauthenticated) {
			t.Fatalf("Authenticate(alg=none) = %v, want ErrUnauthenticated", err)
		}
		if !strings.Contains(err.Error(), `unexpected signature algorithm "none"`) {
			t.Errorf("error = %v, want the allowlist to be what refused it", err)
		}
		if got := iss.JWKSRequests(); got != 0 {
			t.Errorf("JWKS fetches = %d, want 0: an unlisted algorithm is refused before any key work", got)
		}
	})

	t.Run("HMAC keyed by the issuer's public key", func(t *testing.T) {
		t.Parallel()

		// The attack in its real form: the secret is the verification
		// key the issuer publishes, so a verifier that accepted HS256
		// would find this signature valid. A test that used a random
		// secret would pass against that verifier too.
		iss, a := newAuth(t, nil)
		token := iss.RawToken(t, authtest.RawTokenOptions{
			Payload: claims(iss),
			HMACKey: iss.PublicKey(t, ""),
			Header:  map[string]any{"kid": iss.KeyID(t)},
		})

		_, err := authenticate(t, a, token)
		if !errors.Is(err, purser.ErrUnauthenticated) {
			t.Fatalf("Authenticate(HS256 over the published key) = %v, want ErrUnauthenticated", err)
		}
		if !strings.Contains(err.Error(), `unexpected signature algorithm "HS256"`) {
			t.Errorf("error = %v, want the allowlist to be what refused it", err)
		}
		if got := iss.JWKSRequests(); got != 0 {
			t.Errorf("JWKS fetches = %d, want 0: an unlisted algorithm is refused before any key work", got)
		}
	})

	t.Run("HMAC named in the header over a real RS256 signature", func(t *testing.T) {
		t.Parallel()

		// The header says HS256; underneath is a genuine RS256 signature
		// by the issuer's key. The allowlist reads the header, so this is
		// refused for the same reason — and pins that the header's "alg"
		// is what the allowlist is applied to, not whatever the key
		// happens to be.
		iss, a := newAuth(t, nil)
		token := iss.RawToken(t, authtest.RawTokenOptions{
			Payload: claims(iss),
			Header:  map[string]any{"alg": "HS256"},
		})

		_, err := authenticate(t, a, token)
		if !errors.Is(err, purser.ErrUnauthenticated) {
			t.Fatalf("Authenticate(HS256 header, RS256 signature) = %v, want ErrUnauthenticated", err)
		}
		if !strings.Contains(err.Error(), `unexpected signature algorithm "HS256"`) {
			t.Errorf("error = %v, want the allowlist to be what refused it", err)
		}
	})
}

// TestKeyIDConfusionIsRefused pins that the key named in the header is
// the key the signature is checked against. A verifier that fell back
// to trying every published key would accept this, and a rotation would
// then never take a compromised key out of service.
func TestKeyIDConfusionIsRefused(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, func(o *oidc.Options) { o.KeyRefreshFloor = time.Nanosecond })
	first := iss.KeyID(t)
	second := iss.AddKey(t, "RS256")

	// Signed by the second key, labelled as the first. Both are
	// published, both are RS256, and the signature is a real one.
	token := iss.RawToken(t, authtest.RawTokenOptions{
		Payload:  iss.Claims(t, authtest.TokenOptions{Email: alice}),
		SignWith: second,
		Header:   map[string]any{"kid": first},
	})

	_, err := authenticate(t, a, token)
	if !errors.Is(err, purser.ErrUnauthenticated) {
		t.Fatalf("Authenticate(signed by %s, labelled %s) = %v, want ErrUnauthenticated", second, first, err)
	}
	if !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("error = %v, want the signature check to be what refused it", err)
	}

	// The same signature under its own key ID is accepted, so the
	// refusal above is the label and nothing else.
	honest := iss.RawToken(t, authtest.RawTokenOptions{
		Payload:  iss.Claims(t, authtest.TokenOptions{Email: alice}),
		SignWith: second,
	})
	if _, err := authenticate(t, a, honest); err != nil {
		t.Fatalf("Authenticate(signed by %s, labelled %s): %v", second, second, err)
	}
}

// TestTokenWithNoKeyIDIsVerifiedAgainstEveryKey covers the header a
// single-key provider legitimately emits. "kid" is optional, and a
// verifier that required it would reject those providers outright.
func TestTokenWithNoKeyIDIsVerifiedAgainstEveryKey(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, func(o *oidc.Options) { o.KeyRefreshFloor = time.Nanosecond })
	iss.AddKey(t, "RS256")
	third := iss.AddKey(t, "RS256")

	// The last of three published keys, with nothing in the header to
	// say so: the two before it are tried and fail before it is reached.
	token := iss.RawToken(t, authtest.RawTokenOptions{
		Payload:   iss.Claims(t, authtest.TokenOptions{Email: alice}),
		SignWith:  third,
		OmitKeyID: true,
	})
	c, err := authenticate(t, a, token)
	if err != nil {
		t.Fatalf("Authenticate(no kid): %v", err)
	}
	if c.Identity != alice {
		t.Errorf("identity = %q, want %q", c.Identity, alice)
	}

	// An unpublished key with no "kid" is still refused: trying every
	// key is not the same as trusting any.
	forged := iss.RawToken(t, authtest.RawTokenOptions{
		Payload:        iss.Claims(t, authtest.TokenOptions{Email: alice}),
		UnpublishedKey: true,
		OmitKeyID:      true,
	})
	if _, err := authenticate(t, a, forged); !errors.Is(err, purser.ErrUnauthenticated) {
		t.Fatalf("Authenticate(no kid, unpublished key) = %v, want ErrUnauthenticated", err)
	}
}

// TestJSONSerializationIsRefused pins the choice of
// jose.ParseSignedCompact over jose.ParseSigned. The JSON serialization
// can carry several signatures, and a verifier that accepts it has to
// decide which one counts.
func TestJSONSerializationIsRefused(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, nil)
	compact := iss.Mint(t, authtest.TokenOptions{Email: alice})
	if _, err := authenticate(t, a, compact); err != nil {
		t.Fatalf("the compact form must be accepted first: %v", err)
	}

	jws, err := jose.ParseSignedCompact(compact, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parsing the minted token: %v", err)
	}
	if _, err := authenticate(t, a, jws.FullSerialize()); !errors.Is(err, purser.ErrUnauthenticated) {
		t.Fatalf("Authenticate(JSON serialization) = %v, want ErrUnauthenticated", err)
	}
}

func TestEllipticAndRSAKeysBothVerify(t *testing.T) {
	t.Parallel()

	// No floor: each new key is an unknown key ID, and the rate limit on
	// refetching is a different test's subject.
	iss, a := newAuth(t, func(o *oidc.Options) { o.KeyRefreshFloor = time.Nanosecond })
	for _, alg := range []string{"ES256", "RS256"} {
		kid := iss.AddKey(t, alg)
		token := iss.Mint(t, authtest.TokenOptions{Email: alice, KeyID: kid})
		if _, err := authenticate(t, a, token); err != nil {
			t.Errorf("Authenticate with a %s key: %v", alg, err)
		}
	}
}

// TestKeyPublishedForAnotherAlgorithmIsNotUsed pins that the "alg" a
// key is published under is honored: an RSA key published for PS256
// must not verify an RS256 signature, even though the key material
// would.
func TestKeyPublishedForAnotherAlgorithmIsNotUsed(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, func(o *oidc.Options) {
		o.SignatureAlgorithms = []string{"RS256", "PS256"}
	})
	kid := iss.AddKey(t, "PS256")

	// A genuine RS256 signature by the key the JWK Set publishes as
	// PS256: the same modulus, the padding the issuer did not sanction.
	// The signature verifies against that key material, so the only
	// thing that can refuse this token is the "alg" the key is published
	// under — which is exactly what is under test. Splicing an RS256
	// header onto a PS256 signature would not do: that token is refused
	// by the signature check whether the binding exists or not.
	forged := iss.RawToken(t, authtest.RawTokenOptions{
		Payload:   iss.Claims(t, authtest.TokenOptions{Email: alice}),
		SignWith:  kid,
		Algorithm: "RS256",
	})

	_, err := authenticate(t, a, forged)
	if !errors.Is(err, purser.ErrUnauthenticated) {
		t.Fatalf("Authenticate(RS256 signature by a key published as PS256) = %v, want ErrUnauthenticated", err)
	}
	if !strings.Contains(err.Error(), "publishes no key matching") {
		t.Errorf("error = %v, want the key selection to be what refused it", err)
	}

	// The same key signing what it was published for is accepted, so the
	// refusal above is the algorithm binding and not the key.
	honest := iss.Mint(t, authtest.TokenOptions{Email: alice, KeyID: kid})
	if _, err := authenticate(t, a, honest); err != nil {
		t.Fatalf("Authenticate(PS256 signature by the PS256 key): %v", err)
	}
}

// TestNilRequest pins that the entry point tolerates one. A surface
// that reaches Authenticate with no request is broken, but a nil panic
// inside an authenticator is a worse way to find out.
func TestNilRequest(t *testing.T) {
	t.Parallel()

	_, a := newAuth(t, nil)
	c, err := a.Authenticate(nil)
	if !errors.Is(err, purser.ErrUnauthenticated) {
		t.Fatalf("Authenticate(nil) = %v, want ErrUnauthenticated", err)
	}
	if !c.IsZero() {
		t.Errorf("Authenticate(nil) returned Caller %q", c.Identity)
	}
}

func TestProxyIsGrantedByListOnly(t *testing.T) {
	t.Parallel()

	// The empty string is dropped rather than becoming an identity that
	// may proxy: a configuration value that never got set must not turn
	// into a grant.
	iss, a := newAuth(t, func(o *oidc.Options) { o.ProxyIdentities = []string{bot, ""} })

	botCaller, err := authenticate(t, a, iss.Mint(t, authtest.TokenOptions{Email: bot}))
	if err != nil {
		t.Fatalf("Authenticate(bot): %v", err)
	}
	if !a.CanProxyAs(botCaller) {
		t.Errorf("CanProxyAs(%q) = false, want true", botCaller.Identity)
	}

	aliceCaller, err := authenticate(t, a, iss.Mint(t, authtest.TokenOptions{Email: alice}))
	if err != nil {
		t.Fatalf("Authenticate(alice): %v", err)
	}
	if a.CanProxyAs(aliceCaller) {
		t.Errorf("CanProxyAs(%q) = true, want false", aliceCaller.Identity)
	}
	if a.CanProxyAs(purser.Caller{}) {
		t.Errorf("CanProxyAs(zero Caller) = true, want false")
	}
}

// TestNoIdentityLookup pins the deliberate absence. authn documents
// that a claim-based authenticator has no table of provisioned
// identities; implementing the interface anyway would either invent
// Callers or reject every assertion a proxy makes.
func TestNoIdentityLookup(t *testing.T) {
	t.Parallel()

	_, a := newAuth(t, nil)
	if _, ok := any(a).(authn.IdentityLookup); ok {
		t.Errorf("*oidc.Auth implements authn.IdentityLookup; it has no identity table to answer from")
	}
}

func TestSourceAndCredentialGate(t *testing.T) {
	t.Parallel()

	_, a := newAuth(t, nil)
	if got := a.Source(); got != purser.AuthSourceOIDC {
		t.Errorf("Source() = %q, want %q", got, purser.AuthSourceOIDC)
	}
	if !a.GatesCredentials() {
		t.Errorf("GatesCredentials() = false, want true")
	}
}

func TestIssuerAccessor(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, nil)
	if got := a.Issuer(); got != iss.URL() {
		t.Errorf("Issuer() = %q, want %q", got, iss.URL())
	}
}

func TestNewRefusesBadOptions(t *testing.T) {
	t.Parallel()

	valid := oidc.Options{Issuer: "https://accounts.example.com", Audiences: []string{"aud"}}

	tests := []struct {
		name   string
		mutate func(*oidc.Options)
		want   string
	}{
		{"no issuer", func(o *oidc.Options) { o.Issuer = "" }, "Issuer is required"},
		{"plaintext issuer", func(o *oidc.Options) { o.Issuer = "http://accounts.example.com" }, "not https"},
		{"issuer with a trailing slash", func(o *oidc.Options) {
			o.Issuer = "https://accounts.example.com/"
		}, "trailing slash"},
		{"issuer with a query", func(o *oidc.Options) {
			o.Issuer = "https://accounts.example.com?tenant=1"
		}, "query or fragment"},
		{"issuer with a fragment", func(o *oidc.Options) {
			o.Issuer = "https://accounts.example.com#frag"
		}, "query or fragment"},
		{"issuer with no host", func(o *oidc.Options) { o.Issuer = "https:" }, "has no host"},
		{"unparseable issuer", func(o *oidc.Options) { o.Issuer = "https://accounts.example.com\x7f" },
			"is not a URL"},
		{"no audience", func(o *oidc.Options) { o.Audiences = nil }, "Audiences is empty"},
		{"empty audience", func(o *oidc.Options) { o.Audiences = []string{"aud", ""} }, "empty string"},
		{"plaintext JWKS URL", func(o *oidc.Options) { o.JWKSURL = "http://keys.example.com/jwks" }, "not https"},
		{"JWKS URL with no host", func(o *oidc.Options) { o.JWKSURL = "https:///jwks" }, "has no host"},
		{"unparseable JWKS URL", func(o *oidc.Options) { o.JWKSURL = "https://keys.example.com\x7f" },
			"is not a URL"},
		{"symmetric algorithm", func(o *oidc.Options) {
			o.SignatureAlgorithms = []string{"HS256"}
		}, "not one of"},
		{"alg none", func(o *oidc.Options) { o.SignatureAlgorithms = []string{"none"} }, "not one of"},
		{"negative leeway", func(o *oidc.Options) { o.Leeway = -time.Second }, "negative"},
		{"absurd leeway", func(o *oidc.Options) { o.Leeway = time.Hour }, "over the 5m0s limit"},
		{"negative token bound", func(o *oidc.Options) { o.MaxTokenBytes = -1 }, "MaxTokenBytes is negative"},
		{"negative refresh", func(o *oidc.Options) { o.KeyRefresh = -time.Second }, "KeyRefresh is negative"},
		{"negative floor", func(o *oidc.Options) {
			o.KeyRefreshFloor = -time.Second
		}, "KeyRefreshFloor is negative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := valid
			tt.mutate(&opts)
			a, err := oidc.New(opts)
			if err == nil {
				t.Fatalf("New(%s) succeeded, want an error", tt.name)
			}
			if a != nil {
				t.Errorf("New returned a non-nil Auth alongside an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestNewAcceptsGoodOptions(t *testing.T) {
	t.Parallel()

	a, err := oidc.New(oidc.Options{
		Issuer:              "https://accounts.example.com",
		Audiences:           []string{"aud", "aud", "other"},
		JWKSURL:             "https://keys.example.com/jwks",
		SignatureAlgorithms: []string{"RS256", "ES384", "EdDSA"},
		Leeway:              30 * time.Second,
		MaxTokenBytes:       4096,
		KeyRefresh:          time.Hour,
		KeyRefreshFloor:     time.Minute,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a == nil {
		t.Fatal("New returned a nil Auth with a nil error")
	}
}
