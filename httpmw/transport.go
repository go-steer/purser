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

package httpmw

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
)

// TokenGateOptions configures NewTokenGate.
type TokenGateOptions struct {
	// Token is the shared secret every request must present.
	// Required: a gate with no token would admit everything while
	// reporting that it gates credentials, which is the one lie the
	// bind policy cannot survive.
	Token string

	// SideChannelHeader names a header the token may be presented in
	// instead of Authorization, for deployments where an identity
	// gateway owns Authorization for its own validation. Empty means
	// authn.HeaderAttachToken; set it to "-" to accept the token only
	// on Authorization.
	SideChannelHeader string

	// Realm is the WWW-Authenticate realm on a 401. Empty means
	// "purser".
	Realm string
}

// TokenGate is the transport-level shared-token check: one secret for
// the whole listener, checked before anything else runs.
//
// It is not identity. Every caller presenting the token is
// indistinguishable from every other, so a deployment that needs to
// know *who* called pairs it with an authenticator, or replaces it with
// one. What it is good for is keeping an unauthenticated surface off
// the network — which is exactly what the bind policy asks it about,
// and why it implements Gate.
//
// Prefer mTLS where there is certificate infrastructure. A shared
// token is a bearer secret: anything that sees it can replay it, it
// appears in process listings and shell history, and it does not
// rotate on its own.
type TokenGate struct {
	token             []byte
	sideChannelHeader string
	realm             string
}

var _ Gate = (*TokenGate)(nil)

// NewTokenGate returns a gate requiring opts.Token on every request.
func NewTokenGate(opts TokenGateOptions) (*TokenGate, error) {
	if opts.Token == "" {
		return nil, errors.New("httpmw: NewTokenGate: Token is required; a gate with an empty token admits every request while reporting that it gates credentials")
	}
	header := opts.SideChannelHeader
	switch header {
	case "":
		header = authn.HeaderAttachToken
	case "-":
		header = ""
	}
	realm := opts.Realm
	if realm == "" {
		realm = "purser"
	}
	return &TokenGate{
		token:             []byte(opts.Token),
		sideChannelHeader: header,
		realm:             realm,
	}, nil
}

// Middleware returns the gate as a Middleware. It belongs outermost in
// the chain: it is the cheapest rejection available and it runs before
// anything reads a body.
//
// A request that passes carries purser.AuthSourceBearer on its
// context, so a caller middleware further in whose authenticator
// verified nothing itself still reports how the request actually got
// in. See NewCaller.
func (g *TokenGate) Middleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !g.check(w, r) {
				return
			}
			next.ServeHTTP(w, r.WithContext(
				purser.WithAuthSource(r.Context(), purser.AuthSourceBearer)))
		})
	}
}

// GatesCredentials reports true: every request that gets past this
// gate presented the token.
func (g *TokenGate) GatesCredentials() bool { return g != nil }

// check validates the request's token, writing a 401 and returning
// false when it does not match.
//
// The side-channel header wins when present, right or wrong: an
// operator who explicitly set it wants to hear that it was rejected,
// not have it quietly overridden by an Authorization header they may
// have forgotten was configured. "Present" means present after
// trimming, so a blank header is no header — that matches how
// bearer.Auth reads the same name, and the two must agree about what
// counts as a token being offered.
func (g *TokenGate) check(w http.ResponseWriter, r *http.Request) bool {
	if g.sideChannelHeader != "" {
		if side := strings.TrimSpace(r.Header.Get(g.sideChannelHeader)); side != "" {
			if subtle.ConstantTimeCompare([]byte(side), g.token) == 1 {
				return true
			}
			g.writeUnauthorized(w)
			return false
		}
	}
	got := bearerToken(r.Header.Get("Authorization"))
	if got == "" || subtle.ConstantTimeCompare([]byte(got), g.token) != 1 {
		g.writeUnauthorized(w)
		return false
	}
	return true
}

func (g *TokenGate) writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="`+g.realm+`"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// bearerToken pulls the credential out of an Authorization header. The
// scheme is matched case-insensitively per RFC 7235 §2.1, which is
// what a conforming client is entitled to expect and what
// authn/bearer already does.
func bearerToken(header string) string {
	scheme, rest, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return ""
	}
	return strings.TrimSpace(rest)
}

// ReadOnly returns middleware that refuses every state-changing method
// with 403, whatever credential it carries.
//
// It is a listener-wide switch, not an authorization rule: which
// callers may write is authz's question, and this is the blunter
// "nobody, on this listener" — a read-only mirror, a break-glass
// posture, a surface exposed for observation only.
func ReadOnly() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isWriteMethod(r.Method) {
				http.Error(w, "this listener is read-only; writes are disabled", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Gate is the one question the bind policy asks: does this thing
// guarantee that every request reaching the handler presented a
// credential it verified?
//
// *CallerMiddleware and *TokenGate implement it, as does an mTLS
// authenticator whose paired *tls.Config requires a verified client
// certificate — there the handshake has already refused the
// connection, so the guarantee holds before any middleware runs.
//
// What does *not* answer this question is a non-transport
// authenticator on its own. A bearer table reports
// authn.CredentialGate.GatesCredentials() == true, and it is telling
// the truth about itself: every request *it* admits presented a token
// it checked. Whether a request it rejects still reaches the handler
// is CallerOptions.Enforce, decided a layer up. Pass the
// *CallerMiddleware.
//
// It is deliberately not authn.CredentialGate itself: CheckBind has no
// use for Authenticate or Source, and requiring them would exclude a
// gate that is not an authenticator at all.
type Gate interface {
	GatesCredentials() bool
}

// ErrUnauthenticatedBind is returned by CheckBind for a non-loopback
// address with nothing gating credentials in front of it.
var ErrUnauthenticatedBind = errors.New("purser: refusing to bind a non-loopback address with no credential gate")

// CheckBind reports whether addr is safe to listen on given what gates
// the surface, and returns an error wrapping ErrUnauthenticatedBind
// when it is not.
//
// The rule: a non-loopback address requires at least one gate that
// reports GatesCredentials() == true. Loopback is always permitted —
// a local-development posture where the operating system's own process
// isolation is the boundary — and it is the caller's job to say so
// loudly in a log line, because "any process on this machine may drive
// this surface" is a real statement, just a much smaller one.
//
// This is a TCP policy. A Unix socket is guarded by its file
// permissions, so do not route one through here: SplitHostPort would
// fail on the path and the socket would be refused for the wrong
// reason.
//
// Ask a gate, do not inspect configuration. The check this replaces
// keyed off "is a client-CA file configured", which is true for the
// PKI profile and false for a perfectly good SPIFFE listener that
// verifies against a trust bundle instead — so a working mutually
// authenticated surface got refused as unauthenticated. A gate knows
// what it enforces; a config field only knows how it was spelled.
//
// Ask the right gate, though: the thing that decides whether an
// unverified request reaches the handler, not the thing that inspects
// the credential. For an HTTP surface that is the *CallerMiddleware —
// see Gate, which spells out why an authenticator handed over on its
// own is the one answer that can be true and useless at the same time.
func CheckBind(addr string, gates ...Gate) error {
	if IsLoopback(addr) {
		return nil
	}
	for _, g := range gates {
		// A nil interface is a caller passing "no gate configured"
		// through a variable, which is the honest reading. A typed
		// nil pointer is handled by the implementation's own nil
		// receiver check.
		if g != nil && g.GatesCredentials() {
			return nil
		}
	}
	return fmt.Errorf(
		"%w: %q is reachable from the network and every request would be admitted unauthenticated. "+
			"Bind a loopback address instead, or put a credential gate in front and pass it here: "+
			"mutual TLS (authn/mtls, whose *tls.Config refuses the handshake), "+
			"an authenticator behind httpmw.NewCaller with Enforce set — an authenticator on its own is not "+
			"enough, since it is Enforce that decides whether a request it rejects still reaches the handler — "+
			"or a shared transport token (httpmw.NewTokenGate)",
		ErrUnauthenticatedBind, addr)
}

// IsLoopback reports whether a TCP listen address binds only a
// loopback interface.
//
// Conservative on purpose. An empty host (":8443"), the wildcards
// "0.0.0.0" and "::", and every hostname but "localhost" all count as
// non-loopback: a name resolves to whatever DNS says today, and the
// cost of guessing wrong is an open listener, so anything unproven is
// treated as network-reachable.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
