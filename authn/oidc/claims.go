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
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-steer/purser"
)

// claims are the registered claims this package interprets. Everything
// else in the payload is metadata, and reaches policy as a Label.
type claims struct {
	Issuer        string       `json:"iss"`
	Subject       string       `json:"sub"`
	Audience      audience     `json:"aud"`
	Expiry        *numericDate `json:"exp"`
	NotBefore     *numericDate `json:"nbf"`
	IssuedAt      *numericDate `json:"iat"`
	Email         string       `json:"email"`
	EmailVerified *jsonBool    `json:"email_verified"`
}

// surfacedClaims are the claims that already have a dedicated label or
// have no useful string form, and so are not copied under
// LabelClaimPrefix. Notably absent: email_verified, which a policy has
// every reason to match on.
var surfacedClaims = []string{"iss", "sub", "email", "exp", "aud", "nbf", "iat"}

// callerFromPayload validates the claims of a verified payload and
// builds the Caller they describe.
//
// The signature is checked before this runs, so the bytes are the
// issuer's. What is checked here is whether the issuer meant them for
// this service, now.
func (a *Auth) callerFromPayload(payload []byte) (purser.Caller, error) {
	raw, err := splitClaims(payload)
	if err != nil {
		return purser.Caller{}, fmt.Errorf("purser/oidc: %v: %w", err, purser.ErrUnauthenticated)
	}
	c, err := registeredClaims(raw)
	if err != nil {
		return purser.Caller{}, fmt.Errorf("purser/oidc: decoding claims: %v: %w", err, purser.ErrUnauthenticated)
	}
	all, err := decodeAllClaims(raw)
	if err != nil {
		return purser.Caller{}, fmt.Errorf("purser/oidc: %v: %w", err, purser.ErrUnauthenticated)
	}

	if err := a.validate(c); err != nil {
		return purser.Caller{}, fmt.Errorf("purser/oidc: %v: %w", err, purser.ErrUnauthenticated)
	}
	identity, err := a.identityFrom(c, all)
	if err != nil {
		return purser.Caller{}, fmt.Errorf("purser/oidc: %v: %w", err, purser.ErrUnauthenticated)
	}
	if strings.TrimSpace(identity) == "" {
		// Not merely empty — blank. An identity of " " satisfies every
		// non-empty check in this package and in purser.Caller.IsZero,
		// and then sits in an ACL and an audit record as something no
		// operator can see.
		return purser.Caller{}, fmt.Errorf("purser/oidc: the claim resolving the identity is blank: %w",
			purser.ErrUnauthenticated)
	}

	return purser.Caller{
		Identity: identity,
		Labels:   labelsFrom(c, all),
		// Admin is never read from a claim. Policy decides it, over
		// these labels — see authz.Rules.
		Admin: false,
	}, nil
}

// validate applies the checks that do not depend on which claim becomes
// the identity.
func (a *Auth) validate(c *claims) error {
	if c.Issuer != a.issuer {
		return fmt.Errorf("token was issued by %q, want %q", c.Issuer, a.issuer)
	}
	if c.Subject == "" {
		return fmt.Errorf("token has no \"sub\" claim")
	}
	if !slices.ContainsFunc(a.audiences, func(want string) bool {
		return slices.Contains(c.Audience, want)
	}) {
		// %q, not %v: this is the one claim-derived value in the package
		// that reaches a log message as a list, and an "aud" element
		// carrying a newline would otherwise inject a line into it.
		return fmt.Errorf("token audience %q does not include any of %q", []string(c.Audience), a.audiences)
	}

	now := a.now()
	if c.Expiry == nil {
		// A token with no expiry is a bearer credential valid forever.
		// RFC 7519 makes "exp" optional; this package does not.
		return fmt.Errorf("token has no \"exp\" claim")
	}
	if expiry := c.Expiry.Time(); now.After(expiry.Add(a.leeway)) {
		return fmt.Errorf("token expired at %s", expiry.UTC().Format(time.RFC3339))
	}
	if c.NotBefore != nil {
		if nbf := c.NotBefore.Time(); now.Add(a.leeway).Before(nbf) {
			return fmt.Errorf("token is not valid before %s", nbf.UTC().Format(time.RFC3339))
		}
	}
	if c.IssuedAt != nil {
		// A token issued in the future is a clock problem at the issuer
		// or a forgery attempt at the client; either way the validity
		// window it describes is not one this service can reason about.
		if iat := c.IssuedAt.Time(); now.Add(a.leeway).Before(iat) {
			return fmt.Errorf("token was issued at %s, in the future", iat.UTC().Format(time.RFC3339))
		}
	}
	return nil
}

// identityFrom resolves Caller.Identity.
func (a *Auth) identityFrom(c *claims, all map[string]any) (string, error) {
	if a.identityClaim != "" {
		if a.identityClaim == "email" {
			if err := a.emailUsable(c); err != nil {
				return "", err
			}
		}
		v, ok := all[a.identityClaim]
		if !ok {
			return "", fmt.Errorf("token has no %q claim, which is configured as the identity",
				a.identityClaim)
		}
		s, ok := v.(string)
		if !ok || s == "" {
			return "", fmt.Errorf("the %q claim configured as the identity is not a non-empty string",
				a.identityClaim)
		}
		return s, nil
	}

	if c.Email != "" {
		if err := a.emailUsable(c); err != nil {
			return "", err
		}
		return c.Email, nil
	}
	// Validated above as non-empty.
	return c.Subject, nil
}

// emailUsable reports whether the email claim may become an identity.
//
// An unverified address is refused because on most providers it is a
// self-service profile field: a user who can type an address into their
// own profile could otherwise authenticate here as its owner.
func (a *Auth) emailUsable(c *claims) error {
	if a.allowUnverifiedEmail {
		return nil
	}
	switch {
	case c.EmailVerified == nil:
		return fmt.Errorf("token has an \"email\" claim but no \"email_verified\" claim; set " +
			"AllowUnverifiedEmail only if the provider verifies addresses out of band")
	case !bool(*c.EmailVerified):
		return fmt.Errorf("the \"email\" claim is not verified")
	}
	return nil
}

// labelsFrom builds the Caller's Labels: the four claims with dedicated
// keys, plus every other claim with a scalar value under
// LabelClaimPrefix.
//
// Arrays and objects are skipped. A label is one string, and the
// obvious flattening — joining a "groups" array with commas — produces
// a value that matches no policy anyone would write and looks like it
// should. A deployment that needs to authorize on a group membership
// should say so; that matcher can be added deliberately when a real
// consumer needs it.
func labelsFrom(c *claims, all map[string]any) map[string]string {
	labels := map[string]string{
		LabelIssuer:  c.Issuer,
		LabelSubject: c.Subject,
		LabelExpiry:  c.Expiry.Time().UTC().Format(time.RFC3339),
	}
	if c.Email != "" {
		labels[LabelEmail] = c.Email
	}
	for name, v := range all {
		if slices.Contains(surfacedClaims, name) {
			continue
		}
		if s, ok := scalarString(v); ok {
			labels[LabelClaimPrefix+name] = s
		}
	}
	return labels
}

// scalarString renders a claim value as a label value, reporting false
// for the kinds that have no faithful one.
func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case json.Number:
		// Rendered exactly as the issuer wrote it. Decoding through
		// float64 would turn a 19-digit identifier into 1.234568e+18.
		return t.String(), true
	}
	return "", false
}

// splitClaims separates the payload into its claims, keyed byte for
// byte.
//
// Every claim this package reads is looked up here rather than
// unmarshalled into a tagged struct, and that is a security property,
// not a style. encoding/json matches an object key to a struct field
// case-insensitively when no exact match exists, and of two keys that
// fold-equal, the last one in the payload wins. Unmarshalling the
// payload straight into the claims struct therefore lets a claim named
// "AUD" overwrite the "aud" that gets validated — while a second,
// exact-keyed decode for the labels reports the real one, so the two
// disagree and the decision uses the wrong one. The same trick reaches
// "EXP", "SUB", "ISS" and "Email_Verified".
//
// It is not hypothetical. The registered names are reserved by every
// IdP; their case variants are reserved by none, and several providers
// let an application append claims of its own to the payload. The
// variant then arrives on a genuinely issuer-signed token.
func splitClaims(payload []byte) (map[string]json.RawMessage, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("decoding claims: %w", err)
	}
	if raw == nil {
		return nil, fmt.Errorf("the token payload is JSON null, not an object")
	}
	return raw, nil
}

// registeredClaims fills the claims struct from exact key matches.
func registeredClaims(raw map[string]json.RawMessage) (*claims, error) {
	var c claims
	for _, f := range []struct {
		name string
		dst  any
	}{
		{"iss", &c.Issuer},
		{"sub", &c.Subject},
		{"aud", &c.Audience},
		{"exp", &c.Expiry},
		{"nbf", &c.NotBefore},
		{"iat", &c.IssuedAt},
		{"email", &c.Email},
		{"email_verified", &c.EmailVerified},
	} {
		v, ok := raw[f.name]
		if !ok {
			continue
		}
		if err := json.Unmarshal(v, f.dst); err != nil {
			return nil, fmt.Errorf("%q: %w", f.name, err)
		}
	}
	return &c, nil
}

// decodeAllClaims decodes every claim into a generic value, keeping
// numbers as their literal text.
func decodeAllClaims(raw map[string]json.RawMessage) (map[string]any, error) {
	all := make(map[string]any, len(raw))
	for name, v := range raw {
		dec := json.NewDecoder(bytes.NewReader(v))
		dec.UseNumber()
		var x any
		if err := dec.Decode(&x); err != nil {
			// Unreachable: raw came from a successful decode of the
			// same bytes, so every value in it is well-formed JSON.
			return nil, fmt.Errorf("decoding the %q claim: %w", name, err)
		}
		all[name] = x
	}
	return all, nil
}

// audience is the "aud" claim, which RFC 7519 §4.1.3 allows to be
// either a single string or an array of them.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		*a = audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("\"aud\" is neither a string nor an array of strings")
	}
	*a = many
	return nil
}

// jsonBool is a boolean claim that tolerates the quoted spelling some
// providers emit for "email_verified". It tolerates nothing else: a
// claim that is neither a boolean nor "true"/"false" is an error rather
// than a silent false, because a false read from a malformed claim is
// indistinguishable from a provider saying the address is unverified.
type jsonBool bool

func (v *jsonBool) UnmarshalJSON(b []byte) error {
	switch string(b) {
	case "true", `"true"`:
		*v = true
	case "false", `"false"`:
		*v = false
	default:
		return fmt.Errorf("not a boolean: %s", b)
	}
	return nil
}

// numericDate is a JSON NumericDate: seconds since the Unix epoch,
// possibly fractional (RFC 7519 §2).
type numericDate time.Time

func (d numericDate) Time() time.Time { return time.Time(d) }

func (d *numericDate) UnmarshalJSON(b []byte) error {
	// A quoted number is not a NumericDate. Rejected explicitly because
	// a string that happens to parse as one would otherwise depend on
	// the decoder's tolerance rather than on the spec.
	if len(b) > 0 && b[0] == '"' {
		return fmt.Errorf("timestamp is a string, want a JSON number")
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("timestamp is not a JSON number: %w", err)
	}
	if i, err := n.Int64(); err == nil {
		*d = numericDate(time.Unix(i, 0))
		return nil
	}
	f, err := n.Float64()
	if err != nil {
		return fmt.Errorf("timestamp %s is not representable: %w", n, err)
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return fmt.Errorf("timestamp %s is not a finite number", n)
	}
	sec, frac := math.Modf(f)
	// int64(sec) on an out-of-range float is implementation-defined, and
	// the two architectures this runs on disagree. amd64's CVTTSD2SI
	// returns the "integer indefinite" value, math.MinInt64, whatever
	// the sign of the input, so "nbf": 1e300 reads as an instant long
	// past and the not-before check passes. arm64's FCVTZS saturates
	// toward the input's sign, so the same literal reads as the far
	// future — and there it is "exp": 1e300 that fails open, as a token
	// that never expires. Either way a timestamp nobody can read decides
	// the validity window. Refused instead.
	if sec >= math.MaxInt64 || sec < math.MinInt64 {
		return fmt.Errorf("timestamp %s is out of range", n)
	}
	*d = numericDate(time.Unix(int64(sec), int64(frac*float64(time.Second))))
	return nil
}
