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
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn/oidc"
	"github.com/go-steer/purser/authtest"
)

// TestClaimValidation walks the claims a token must carry and the
// shapes it must not.
func TestClaimValidation(t *testing.T) {
	t.Parallel()

	// The authenticator's clock is pinned here, so the rows that sit
	// inside and outside the leeway are exact rather than a margin
	// against however long the test binary takes to reach them. Tokens
	// are still minted against the real clock, which is a few
	// milliseconds later; every row's window is seconds wide.
	now := time.Now().Truncate(time.Second)

	tests := []struct {
		name string
		// mutate adjusts the token before minting.
		token func(*authtest.TokenOptions)
		// opts adjusts the authenticator. Nil for the default.
		opts func(*oidc.Options)
		// wantIdentity is the identity the token must resolve to;
		// empty means the token must be refused.
		wantIdentity string
		// wantErr is a substring of the refusal message.
		wantErr string
	}{
		{
			name:         "email identity",
			token:        func(o *authtest.TokenOptions) { o.Email = alice },
			wantIdentity: alice,
		},
		{
			name:         "no email falls back to sub",
			token:        func(o *authtest.TokenOptions) { o.Subject = "sub-42" },
			wantIdentity: "sub-42",
		},
		{
			name: "unverified email is refused",
			token: func(o *authtest.TokenOptions) {
				o.Email, o.EmailUnverified = alice, true
			},
			wantErr: "not verified",
		},
		{
			name: "unverified email is accepted when the deployment says so",
			token: func(o *authtest.TokenOptions) {
				o.Email, o.EmailUnverified = alice, true
			},
			opts:         func(o *oidc.Options) { o.AllowUnverifiedEmail = true },
			wantIdentity: alice,
		},
		{
			name: "email with no email_verified claim is refused",
			token: func(o *authtest.TokenOptions) {
				o.Email = alice
				o.Claims = map[string]any{"email_verified": nil}
			},
			wantErr: "no \"email_verified\" claim",
		},
		{
			name: "email_verified may be the quoted spelling",
			token: func(o *authtest.TokenOptions) {
				o.Email = alice
				o.Claims = map[string]any{"email_verified": "true"}
			},
			wantIdentity: alice,
		},
		{
			name: "email_verified quoted false is still false",
			token: func(o *authtest.TokenOptions) {
				o.Email = alice
				o.Claims = map[string]any{"email_verified": "false"}
			},
			wantErr: "not verified",
		},
		{
			name: "email_verified of another type is an error, not a false",
			token: func(o *authtest.TokenOptions) {
				o.Email = alice
				o.Claims = map[string]any{"email_verified": "yes"}
			},
			wantErr: "decoding claims",
		},
		{
			name:    "no subject",
			token:   func(o *authtest.TokenOptions) { o.Claims = map[string]any{"sub": nil} },
			wantErr: "no \"sub\" claim",
		},
		{
			name:    "empty subject",
			token:   func(o *authtest.TokenOptions) { o.Claims = map[string]any{"sub": ""} },
			wantErr: "no \"sub\" claim",
		},
		{
			name:         "audience as a bare string",
			token:        func(o *authtest.TokenOptions) { o.Claims = map[string]any{"aud": authtest.DefaultAudience} },
			wantIdentity: "purser.authtest/subject",
		},
		{
			name: "audience array containing ours",
			token: func(o *authtest.TokenOptions) {
				o.Audience = []string{"someone-else", authtest.DefaultAudience}
			},
			wantIdentity: "purser.authtest/subject",
		},
		{
			name:    "audience array without ours",
			token:   func(o *authtest.TokenOptions) { o.Audience = []string{"someone-else"} },
			wantErr: "does not include any of",
		},
		{
			name:    "no audience at all",
			token:   func(o *authtest.TokenOptions) { o.Claims = map[string]any{"aud": nil} },
			wantErr: "does not include any of",
		},
		{
			name:    "audience of the wrong type",
			token:   func(o *authtest.TokenOptions) { o.Claims = map[string]any{"aud": 42} },
			wantErr: "neither a string nor an array",
		},
		{
			name: "any configured audience matches",
			token: func(o *authtest.TokenOptions) {
				o.Audience = []string{"second-audience"}
			},
			opts: func(o *oidc.Options) {
				o.Audiences = []string{authtest.DefaultAudience, "second-audience"}
			},
			wantIdentity: "purser.authtest/subject",
		},
		{
			name:    "another issuer",
			token:   func(o *authtest.TokenOptions) { o.Issuer = "https://accounts.example.net" },
			wantErr: "was issued by",
		},
		{
			name:    "no issuer claim",
			token:   func(o *authtest.TokenOptions) { o.Claims = map[string]any{"iss": nil} },
			wantErr: "was issued by",
		},
		{
			name:    "no expiry",
			token:   func(o *authtest.TokenOptions) { o.Claims = map[string]any{"exp": nil} },
			wantErr: "no \"exp\" claim",
		},
		{
			name:    "expired",
			token:   func(o *authtest.TokenOptions) { o.Expiry = now.Add(-time.Hour) },
			wantErr: "expired at",
		},
		{
			name:         "expired inside the leeway",
			token:        func(o *authtest.TokenOptions) { o.Expiry = now.Add(-30 * time.Second) },
			wantIdentity: "purser.authtest/subject",
		},
		{
			name:    "expired just outside the leeway",
			token:   func(o *authtest.TokenOptions) { o.Expiry = now.Add(-90 * time.Second) },
			wantErr: "expired at",
		},
		{
			name:    "expiry as a quoted number",
			token:   func(o *authtest.TokenOptions) { o.Claims = map[string]any{"exp": "9999999999"} },
			wantErr: "timestamp is a string",
		},
		{
			name:    "expiry that is not a number",
			token:   func(o *authtest.TokenOptions) { o.Claims = map[string]any{"exp": "next week"} },
			wantErr: "timestamp is a string",
		},
		{
			name: "expiry too large to represent",
			token: func(o *authtest.TokenOptions) {
				o.Claims = map[string]any{"exp": json.RawMessage("1e400")}
			},
			wantErr: "not representable",
		},
		{
			name:         "fractional expiry",
			token:        func(o *authtest.TokenOptions) { o.Claims = map[string]any{"exp": 9999999999.5} },
			wantIdentity: "purser.authtest/subject",
		},
		{
			name:    "not yet valid",
			token:   func(o *authtest.TokenOptions) { o.NotBefore = now.Add(time.Hour) },
			wantErr: "not valid before",
		},
		{
			name:         "not-before inside the leeway",
			token:        func(o *authtest.TokenOptions) { o.NotBefore = now.Add(30 * time.Second) },
			wantIdentity: "purser.authtest/subject",
		},
		{
			name:    "issued in the future",
			token:   func(o *authtest.TokenOptions) { o.IssuedAt = now.Add(time.Hour) },
			wantErr: "in the future",
		},
		{
			name:         "issued slightly in the future",
			token:        func(o *authtest.TokenOptions) { o.IssuedAt = now.Add(30 * time.Second) },
			wantIdentity: "purser.authtest/subject",
		},
		{
			name: "IdentityClaim names the claim",
			token: func(o *authtest.TokenOptions) {
				o.Email = alice
				o.Claims = map[string]any{"preferred_username": "alice"}
			},
			opts:         func(o *oidc.Options) { o.IdentityClaim = "preferred_username" },
			wantIdentity: "alice",
		},
		{
			name:    "IdentityClaim with no fallback",
			token:   func(o *authtest.TokenOptions) { o.Email = alice },
			opts:    func(o *oidc.Options) { o.IdentityClaim = "preferred_username" },
			wantErr: "has no \"preferred_username\" claim",
		},
		{
			name: "IdentityClaim naming a non-string",
			token: func(o *authtest.TokenOptions) {
				o.Claims = map[string]any{"uid": 12345}
			},
			opts:    func(o *oidc.Options) { o.IdentityClaim = "uid" },
			wantErr: "is not a non-empty string",
		},
		{
			name: "IdentityClaim naming an empty string",
			token: func(o *authtest.TokenOptions) {
				o.Claims = map[string]any{"uid": ""}
			},
			opts:    func(o *oidc.Options) { o.IdentityClaim = "uid" },
			wantErr: "is not a non-empty string",
		},
		{
			name: "IdentityClaim of email still requires verification",
			token: func(o *authtest.TokenOptions) {
				o.Email, o.EmailUnverified = alice, true
			},
			opts:    func(o *oidc.Options) { o.IdentityClaim = "email" },
			wantErr: "not verified",
		},
		{
			name: "IdentityClaim of sub outranks the email default",
			token: func(o *authtest.TokenOptions) {
				o.Subject, o.Email = "sub-7", alice
			},
			opts:         func(o *oidc.Options) { o.IdentityClaim = "sub" },
			wantIdentity: "sub-7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			iss, a := newAuth(t, tt.opts)
			oidc.SetClock(a, func() time.Time { return now })
			var to authtest.TokenOptions
			if tt.token != nil {
				tt.token(&to)
			}
			c, err := authenticate(t, a, iss.Mint(t, to))

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Authenticate succeeded as %q, want a refusal mentioning %q",
						c.Identity, tt.wantErr)
				}
				if !errors.Is(err, purser.ErrUnauthenticated) {
					t.Errorf("error = %v, want purser.ErrUnauthenticated", err)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %v, want it to mention %q", err, tt.wantErr)
				}
				if !c.IsZero() {
					t.Errorf("a refused token resolved to Caller %q", c.Identity)
				}
				return
			}
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if c.Identity != tt.wantIdentity {
				t.Errorf("identity = %q, want %q", c.Identity, tt.wantIdentity)
			}
		})
	}
}

// TestCaseFoldedClaimsDoNotOverrideTheRealOnes is a regression test.
//
// encoding/json matches an object key to a struct field
// case-insensitively when no exact match exists, and of two keys that
// fold-equal the last in the payload wins. A payload decoded straight
// into the claims struct therefore reads "AUD" as the audience — while a
// second, exact-keyed decode for the labels reports the real "aud", so
// the two disagree and the decision uses the wrong one.
//
// Every claim here is delivered on a genuinely issuer-signed token,
// because the case variants of the registered names are reserved by no
// provider and several let an application append claims of its own.
func TestCaseFoldedClaimsDoNotOverrideTheRealOnes(t *testing.T) {
	t.Parallel()

	// Each variant is appended after the real claim, because that is the
	// order the fallback rewards and json.Marshal of a map never
	// produces: it sorts its keys, and every case variant of a
	// registered name sorts before the lowercase spelling. A test that
	// went through TokenOptions.Claims would put the variant first and
	// pass against the unfixed code.
	tests := []struct {
		name    string
		variant string
		// label is the value the variant must reach policy as, when it
		// has a scalar form.
		label string
	}{
		{name: "AUD", variant: `"AUD":["some-other-service"]`},
		{name: "Aud", variant: `"Aud":["some-other-service"]`},
		{name: "SUB", variant: `"SUB":"impostor"`, label: "impostor"},
		{name: "ISS", variant: `"ISS":"https://accounts.example.net"`, label: "https://accounts.example.net"},
		{name: "EXP", variant: `"EXP":99999999999`, label: "99999999999"},
		{name: "Email", variant: `"Email":"root@example.com"`, label: "root@example.com"},
		{name: "Email_Verified", variant: `"Email_Verified":true`, label: "true"},
		{name: "NBF", variant: `"NBF":99999999999`, label: "99999999999"},
		{name: "IAT", variant: `"IAT":99999999999`, label: "99999999999"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			iss, a := newAuth(t, nil)
			payload := appendClaim(t, iss.Claims(t, authtest.TokenOptions{
				Subject: "sub-1",
				Email:   alice,
			}), tt.variant)
			c, err := authenticate(t, a, iss.RawToken(t, authtest.RawTokenOptions{Payload: payload}))
			if err != nil {
				t.Fatalf("Authenticate: %v: the case variant overrode the real claim", err)
			}

			if c.Identity != alice {
				t.Errorf("identity = %q, want %q", c.Identity, alice)
			}
			if got := c.Label(oidc.LabelSubject); got != "sub-1" {
				t.Errorf("%s = %q, want %q", oidc.LabelSubject, got, "sub-1")
			}
			if got := c.Label(oidc.LabelIssuer); got != iss.URL() {
				t.Errorf("%s = %q, want %q", oidc.LabelIssuer, got, iss.URL())
			}
			// Nor is the variant silently dropped: it reaches policy as
			// an ordinary claim, under the prefix that says it is one.
			if tt.label != "" {
				if got := c.Label(oidc.LabelClaimPrefix + tt.name); got != tt.label {
					t.Errorf("label for %q = %q, want %q", tt.name, got, tt.label)
				}
			}
		})
	}

	// The other direction: the real claim is the wrong one and the
	// variant is what a correct token would carry. The refusal must
	// stand.
	refusals := []struct {
		name    string
		claims  map[string]any
		variant string
		wantErr string
	}{
		{
			name:    "AUD cannot rescue a wrong aud",
			claims:  map[string]any{"aud": []string{"some-other-service"}},
			variant: `"AUD":["` + authtest.DefaultAudience + `"]`,
			wantErr: "does not include any of",
		},
		{
			name:    "Email_Verified cannot rescue an unverified email",
			claims:  map[string]any{"email_verified": false},
			variant: `"Email_Verified":true`,
			wantErr: "not verified",
		},
		{
			name:    "EXP cannot rescue an expired token",
			claims:  map[string]any{"exp": 1000000000},
			variant: `"EXP":99999999999`,
			wantErr: "expired at",
		},
		{
			name:    "SUB cannot supply a missing sub",
			claims:  map[string]any{"sub": nil},
			variant: `"SUB":"impostor"`,
			wantErr: `no "sub" claim`,
		},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			iss, a := newAuth(t, nil)
			payload := appendClaim(t, iss.Claims(t, authtest.TokenOptions{
				Email: alice, Claims: tt.claims,
			}), tt.variant)
			c, err := authenticate(t, a, iss.RawToken(t, authtest.RawTokenOptions{Payload: payload}))
			if err == nil {
				t.Fatalf("Authenticate succeeded as %q: the case variant overrode the real claim", c.Identity)
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

// appendClaim splices raw — one "name":value pair — in as the last
// member of a JSON object, which is the one thing json.Marshal of a map
// cannot be asked to do.
func appendClaim(tb testing.TB, payload []byte, raw string) []byte {
	tb.Helper()

	end := bytes.LastIndexByte(payload, '}')
	if end < 0 {
		tb.Fatalf("payload is not a JSON object: %s", payload)
	}
	spliced := string(payload[:end]) + "," + raw + "}"
	if !json.Valid([]byte(spliced)) {
		tb.Fatalf("splicing %s produced invalid JSON: %s", raw, spliced)
	}
	return []byte(spliced)
}

// TestBlankIdentityIsRefused pins that whitespace is not an identity. It
// satisfies every non-empty check in this package and in
// purser.Caller.IsZero, and would then sit in an ACL and an audit record
// as something no operator can see.
func TestBlankIdentityIsRefused(t *testing.T) {
	t.Parallel()

	for _, blank := range []string{" ", "\t", "\n", " ", "  \r\n "} {
		t.Run(strconv.Quote(blank), func(t *testing.T) {
			t.Parallel()

			iss, a := newAuth(t, func(o *oidc.Options) { o.IdentityClaim = "uid" })
			c, err := authenticate(t, a, iss.Mint(t, authtest.TokenOptions{
				Claims: map[string]any{"uid": blank},
			}))
			if !errors.Is(err, purser.ErrUnauthenticated) {
				t.Fatalf("Authenticate = %v (identity %q), want ErrUnauthenticated", err, c.Identity)
			}
			if !strings.Contains(err.Error(), "blank") {
				t.Errorf("error = %v, want it to name the blank identity", err)
			}
		})
	}
}

// TestPayloadThatIsNotAnObject covers the signed bodies that are valid
// JSON and not a claims set. A JWS payload is arbitrary bytes; only the
// convention says it is a JSON object.
func TestPayloadThatIsNotAnObject(t *testing.T) {
	t.Parallel()

	for _, payload := range []string{"null", "[]", `"a string"`, "42", "true", "", "not json at all"} {
		t.Run(strconv.Quote(payload), func(t *testing.T) {
			t.Parallel()

			iss, a := newAuth(t, nil)
			token := iss.RawToken(t, authtest.RawTokenOptions{Payload: []byte(payload)})
			c, err := authenticate(t, a, token)
			if !errors.Is(err, purser.ErrUnauthenticated) {
				t.Fatalf("Authenticate = %v (identity %q), want ErrUnauthenticated", err, c.Identity)
			}
			if !c.IsZero() {
				t.Errorf("a refused token resolved to Caller %q", c.Identity)
			}
		})
	}
}

// TestOutOfRangeTimestampsAreRefused is a regression test.
//
// int64(f) on a float outside int64's range is implementation-defined;
// on amd64 it saturates to math.MinInt64, and time.Unix then wraps to an
// instant in the distant past. An "nbf" of 1e300 read that way is long
// ago, so the not-before check passes: a fail-open on a timestamp
// nobody can read.
func TestOutOfRangeTimestampsAreRefused(t *testing.T) {
	t.Parallel()

	// Floats, not integers: json.Number.Int64 rejects an integer literal
	// this large outright, and it is the Float64 path that saturates.
	for _, claim := range []string{"exp", "nbf", "iat"} {
		for _, value := range []string{"1e300", "-1e300", "1.5e19", "-1.5e19"} {
			t.Run(claim+"="+value, func(t *testing.T) {
				t.Parallel()

				iss, a := newAuth(t, nil)
				c, err := authenticate(t, a, iss.Mint(t, authtest.TokenOptions{
					Email:  alice,
					Claims: map[string]any{claim: json.RawMessage(value)},
				}))
				if !errors.Is(err, purser.ErrUnauthenticated) {
					t.Fatalf("Authenticate(%q: %s) = %v (identity %q), want ErrUnauthenticated",
						claim, value, err, c.Identity)
				}
				if !strings.Contains(err.Error(), "out of range") {
					t.Errorf("error = %v, want it to name the range", err)
				}
			})
		}
	}
}

// TestClockIsHonored pins that the validity window is read against the
// authenticator's clock, at the boundary, without sleeping to it.
func TestClockIsHonored(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, func(o *oidc.Options) { o.Leeway = time.Second })
	base := time.Now()
	expiry := base.Add(time.Hour).Truncate(time.Second)
	token := iss.Mint(t, authtest.TokenOptions{Email: alice, Expiry: expiry})

	var clock time.Time
	oidc.SetClock(a, func() time.Time { return clock })

	for _, tc := range []struct {
		name string
		at   time.Time
		ok   bool
	}{
		{"well inside", expiry.Add(-time.Hour), true},
		{"at the expiry", expiry, true},
		{"inside the leeway", expiry.Add(time.Second), true},
		{"past the leeway", expiry.Add(2 * time.Second), false},
		{"long past", expiry.Add(24 * time.Hour), false},
	} {
		clock = tc.at
		_, err := authenticate(t, a, token)
		if ok := err == nil; ok != tc.ok {
			t.Errorf("at %s (%s): accepted = %v, want %v (err: %v)",
				tc.name, tc.at.UTC().Format(time.RFC3339), ok, tc.ok, err)
		}
	}
}

// TestLabelsFromClaims pins how a claim reaches policy: which claims
// get a dedicated key, which are copied under the prefix, and which are
// dropped for having no faithful string form.
func TestLabelsFromClaims(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, nil)
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	token := iss.Mint(t, authtest.TokenOptions{
		Subject: "sub-1",
		Email:   alice,
		Expiry:  expiry,
		Claims: map[string]any{
			"hd":                 "example.com",
			"locale":             "en",
			"nonce":              "abc123",
			"auth_time":          1700000000,
			"big":                uint64(1234567890123456789),
			"ratio":              1.5,
			"legacy":             false,
			"groups":             []string{"eng", "oncall"},
			"address":            map[string]any{"country": "US"},
			"nothing":            nil, // removed by Mint, not a null claim
			"deliberately_empty": "",
		},
	})

	c, err := authenticate(t, a, token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	want := map[string]string{
		oidc.LabelIssuer:                             iss.URL(),
		oidc.LabelSubject:                            "sub-1",
		oidc.LabelEmail:                              alice,
		oidc.LabelExpiry:                             expiry.UTC().Format(time.RFC3339),
		oidc.LabelClaimPrefix + "email_verified":     "true",
		oidc.LabelClaimPrefix + "hd":                 "example.com",
		oidc.LabelClaimPrefix + "locale":             "en",
		oidc.LabelClaimPrefix + "nonce":              "abc123",
		oidc.LabelClaimPrefix + "auth_time":          "1700000000",
		oidc.LabelClaimPrefix + "big":                "1234567890123456789",
		oidc.LabelClaimPrefix + "ratio":              "1.5",
		oidc.LabelClaimPrefix + "legacy":             "false",
		oidc.LabelClaimPrefix + "deliberately_empty": "",
	}
	for key, wantValue := range want {
		if got, ok := c.Labels[key]; !ok {
			t.Errorf("label %q is missing", key)
		} else if got != wantValue {
			t.Errorf("label %q = %q, want %q", key, got, wantValue)
		}
	}
	for key := range c.Labels {
		if _, expected := want[key]; !expected {
			t.Errorf("unexpected label %q = %q", key, c.Labels[key])
		}
	}
}

// TestIssuerIsComparedByteForByte pins that the issuer check does no
// normalizing. A token from "https://x/" is not a token from
// "https://x", because a check that normalizes is a check with an
// argument about what normalization means.
func TestIssuerIsComparedByteForByte(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, nil)
	token := iss.Mint(t, authtest.TokenOptions{Email: alice, Issuer: iss.URL() + "/"})

	_, err := authenticate(t, a, token)
	if !errors.Is(err, purser.ErrUnauthenticated) {
		t.Fatalf("Authenticate(issuer with a trailing slash) = %v, want ErrUnauthenticated", err)
	}
	if !strings.Contains(err.Error(), "was issued by") {
		t.Errorf("error = %v, want it to name the issuer mismatch", err)
	}
}

// TestLabelsAreNotSharedBetweenCallers pins that two Callers resolved
// from the same authenticator hold independent maps. The conformance
// suite covers the aliasing-into-authenticator-state case; this covers
// the two-callers case directly.
func TestLabelsAreNotSharedBetweenCallers(t *testing.T) {
	t.Parallel()

	iss, a := newAuth(t, nil)
	token := iss.Mint(t, authtest.TokenOptions{Email: alice})

	first, err := authenticate(t, a, token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	first.Labels["scribbled"] = "on"

	second, err := authenticate(t, a, token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, leaked := second.Labels["scribbled"]; leaked {
		t.Errorf("the second Caller shares the first Caller's label map")
	}
}
