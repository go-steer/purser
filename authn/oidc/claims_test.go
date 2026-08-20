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
	"encoding/json"
	"errors"
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
