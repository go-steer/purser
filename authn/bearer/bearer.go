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

// Package bearer authenticates callers against a static table of
// tokens.
//
// It is the compatibility path, not the recommended one. A shared
// secret per caller has to be provisioned, distributed, rotated, and
// revoked by hand, which is the objection that motivated purser in the
// first place: it does not scale past a handful of operators. Prefer
// authn/mtls or authn/oidc, where the credential is short-lived and
// issued by an authority rather than copied into a file.
//
// It is here because core-agent and mast ship it today, and phase 2 of
// the purser migration must be a no-op for their existing deployments.
// It is a first-class implementation — it passes the same conformance
// suite as every other authenticator — it is simply not the one to
// reach for in a new deployment.
package bearer

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
)

// HeaderAttachToken is the side-channel header a token may be
// presented in, checked before Authorization. It exists for
// deployments where an identity gateway owns the Authorization header
// and the daemon needs its own channel.
//
// It is authn.HeaderAttachToken, re-exported here so a consumer of the
// token table need not import authn for the header name. One
// definition: httpmw's transport gate accepts the same header, and two
// spellings of it would be a credential that works on one path and is
// ignored on the other.
const HeaderAttachToken = authn.HeaderAttachToken

// schemeBearer is the Authorization scheme, matched case-insensitively
// per RFC 7235 §2.1.
const schemeBearer = "bearer"

// Auth resolves a request's bearer token to a Caller against a static
// table.
//
// The table is keyed by a SHA-256 digest of the token rather than by
// the token itself. That is what makes lookup safe to do with an
// ordinary map: an attacker probing tokens learns nothing from response
// timing, because the digest of a guess is uncorrelated with the digest
// of the secret, and no comparison ever stops early on a shared prefix.
//
// Auth is safe for concurrent use; it is immutable after New.
type Auth struct {
	byToken    map[[sha256.Size]byte]purser.Caller
	byIdentity map[string]purser.Caller
	proxy      map[string]struct{}
}

var (
	_ authn.Authenticator          = (*Auth)(nil)
	_ authn.AuthenticatorWithProxy = (*Auth)(nil)
	_ authn.IdentityLookup         = (*Auth)(nil)
	_ authn.CredentialGate         = (*Auth)(nil)
)

// Options configures New.
type Options struct {
	// Users is the token table, typically the Users field of a
	// UsersFile returned by LoadUsersFile.
	Users []User

	// AdminIdentities names the identities resolved as Admin Callers.
	//
	// Entries naming an identity absent from Users are not an error:
	// this is a service-wide policy list, and a deployment running more
	// than one authenticator will legitimately list identities another
	// one resolves.
	AdminIdentities []string

	// ProxyIdentities names the identities permitted to assert other
	// identities via authn.HeaderAssertedCaller. Same tolerance for
	// identities absent from Users, and for the same reason.
	ProxyIdentities []string
}

// New builds an authenticator from opts. It validates opts.Users the
// same way LoadUsersFile does — see validateUsers — because Options may
// be assembled in code and never pass through a file.
func New(opts Options) (*Auth, error) {
	if err := validateUsers("options", opts.Users); err != nil {
		return nil, err
	}
	admin := stringSet(opts.AdminIdentities)

	a := &Auth{
		byToken:    make(map[[sha256.Size]byte]purser.Caller, len(opts.Users)),
		byIdentity: make(map[string]purser.Caller, len(opts.Users)),
		proxy:      stringSet(opts.ProxyIdentities),
	}
	for _, u := range opts.Users {
		// Cloned so the table owns its Labels: the caller of New keeps
		// its Users slice, and a later mutation of a row's map must not
		// rewrite an identity the daemon is already serving.
		c := purser.Caller{Identity: u.Identity, Labels: u.Labels}.Clone()
		_, c.Admin = admin[u.Identity]

		a.byToken[sha256.Sum256([]byte(u.Token))] = c
		a.byIdentity[u.Identity] = c
	}
	return a, nil
}

// Authenticate resolves the request's token against the table.
func (a *Auth) Authenticate(r *http.Request) (purser.Caller, error) {
	token := extractToken(r)
	if token == "" {
		return purser.Caller{}, fmt.Errorf("purser/bearer: no token presented: %w", purser.ErrUnauthenticated)
	}
	c, ok := a.byToken[sha256.Sum256([]byte(token))]
	if !ok {
		// Deliberately the same error as "no token": which of the two
		// it was is useful to someone probing the table and useless to
		// a client, who must retry with a good token either way.
		return purser.Caller{}, fmt.Errorf("purser/bearer: unknown token: %w", purser.ErrUnauthenticated)
	}
	return c.Clone(), nil
}

// Source reports purser.AuthSourceBearer.
func (a *Auth) Source() purser.AuthSource { return purser.AuthSourceBearer }

// GatesCredentials reports true: every request Authenticate admits
// presented a token found in the table.
func (a *Auth) GatesCredentials() bool { return true }

// CanProxyAs reports whether c may assert other identities. False for
// the zero Caller and for any identity absent from ProxyIdentities.
func (a *Auth) CanProxyAs(c purser.Caller) bool {
	if c.IsZero() {
		return false
	}
	_, ok := a.proxy[c.Identity]
	return ok
}

// LookupIdentity returns the Caller provisioned under identity,
// carrying the Labels and Admin flag a direct authentication would have
// produced. ok is false when the identity is not in the table.
func (a *Auth) LookupIdentity(identity string) (purser.Caller, bool) {
	if identity == "" {
		return purser.Caller{}, false
	}
	c, ok := a.byIdentity[identity]
	if !ok {
		return purser.Caller{}, false
	}
	return c.Clone(), true
}

// Len reports how many identities the table holds. Useful to a surface
// that wants to log its configuration without logging the tokens.
func (a *Auth) Len() int { return len(a.byIdentity) }

// extractToken returns the token presented on r, preferring the
// side-channel header over Authorization. It returns "" when neither
// carries one.
func extractToken(r *http.Request) string {
	if side := strings.TrimSpace(r.Header.Get(HeaderAttachToken)); side != "" {
		return side
	}
	scheme, rest, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, schemeBearer) {
		return ""
	}
	return strings.TrimSpace(rest)
}

func stringSet(xs []string) map[string]struct{} {
	out := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		if x == "" {
			continue
		}
		out[x] = struct{}{}
	}
	return out
}

// ErrNoUsers is returned by NewFromFile when the file parses but holds
// no rows. An empty table authenticates nobody, which is far more often
// a truncated or half-written file than an intent — so the failure is
// at startup rather than on every request. A deployment that really
// wants an empty bearer table can call LoadUsersFile and New directly,
// which tolerate one.
var ErrNoUsers = errors.New("purser/bearer: users file contains no users")

// NewFromFile loads a users file and builds an authenticator from it. A
// convenience over LoadUsersFile followed by New; opts.Users is ignored
// and replaced by the file's rows.
func NewFromFile(path string, opts Options) (*Auth, error) {
	uf, err := LoadUsersFile(path)
	if err != nil {
		return nil, err
	}
	if len(uf.Users) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoUsers, path)
	}
	opts.Users = uf.Users
	return New(opts)
}
