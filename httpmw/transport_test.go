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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
	"github.com/go-steer/purser/authn/bearer"
)

func mustGate(t *testing.T, opts TokenGateOptions) *TokenGate {
	t.Helper()
	g, err := NewTokenGate(opts)
	if err != nil {
		t.Fatalf("NewTokenGate(%+v): %v", opts, err)
	}
	return g
}

// ---------------------------------------------------------------
// The token gate
// ---------------------------------------------------------------

func TestTokenGate(t *testing.T) {
	t.Parallel()
	const token = "s3cret"

	cases := []struct {
		name          string
		authorization string
		sideChannel   string
		want          int
	}{
		{"the side-channel header", "", token, http.StatusOK},
		{"the Authorization header", "Bearer " + token, "", http.StatusOK},
		// RFC 7235 §2.1: the scheme is matched case-insensitively. This
		// is a deliberate deviation from core-agent's extractBearer,
		// which was case-sensitive and rejected a conforming client.
		{"a lowercase scheme", "bearer " + token, "", http.StatusOK},
		{"an uppercase scheme", "BEARER " + token, "", http.StatusOK},
		{"surrounding whitespace on the token", "Bearer   " + token + "  ", "", http.StatusOK},
		{"both headers, both right", "Bearer " + token, token, http.StatusOK},

		// The side channel wins when present, right or wrong. An
		// operator who explicitly set it wants to hear that it was
		// rejected, not have it quietly overridden by an Authorization
		// header they may have forgotten was configured.
		{"a wrong side channel does not fall through to a right Authorization", "Bearer " + token, "wrong", http.StatusUnauthorized},

		{"a wrong token", "Bearer wrong", "", http.StatusUnauthorized},
		{"a wrong side-channel token", "", "wrong", http.StatusUnauthorized},
		{"no credential at all", "", "", http.StatusUnauthorized},
		{"the token with no scheme", token, "", http.StatusUnauthorized},
		{"the wrong scheme", "Basic " + token, "", http.StatusUnauthorized},
		{"a scheme and nothing else", "Bearer", "", http.StatusUnauthorized},
		{"a scheme and an empty token", "Bearer ", "", http.StatusUnauthorized},
		// Prefixes and extensions of the secret are not the secret.
		{"a prefix of the token", "Bearer s3cre", "", http.StatusUnauthorized},
		{"the token with a suffix", "Bearer s3cretx", "", http.StatusUnauthorized},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			g := mustGate(t, TokenGateOptions{Token: token})

			var ran bool
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if c.authorization != "" {
				r.Header.Set("Authorization", c.authorization)
			}
			if c.sideChannel != "" {
				r.Header.Set(authn.HeaderAttachToken, c.sideChannel)
			}

			rec := httptest.NewRecorder()
			g.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				ran = true
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rec, r)

			if rec.Code != c.want {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, c.want, rec.Body)
			}
			if ran != (c.want == http.StatusOK) {
				t.Errorf("handler ran = %v, want %v", ran, c.want == http.StatusOK)
			}
			if c.want == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") == "" {
				t.Error("no WWW-Authenticate header on the 401")
			}
		})
	}
}

func TestTokenGateStampsItsVerdict(t *testing.T) {
	t.Parallel()
	g := mustGate(t, TokenGateOptions{Token: "s3cret"})

	var got purser.AuthSource
	var ok bool
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(authn.HeaderAttachToken, "s3cret")

	g.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, ok = purser.AuthSourceFromContext(r.Context())
	})).ServeHTTP(httptest.NewRecorder(), r)

	if !ok || got != purser.AuthSourceBearer {
		t.Errorf("auth source = %q (ok %v), want bearer", got, ok)
	}
}

func TestTokenGateSideChannelHeader(t *testing.T) {
	t.Parallel()

	t.Run("configurable", func(t *testing.T) {
		t.Parallel()
		g := mustGate(t, TokenGateOptions{Token: "s3cret", SideChannelHeader: "X-Daemon-Token"})

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Daemon-Token", "s3cret")
		if got := gateStatus(g, r); got != http.StatusOK {
			t.Errorf("the configured header: status = %d, want 200", got)
		}

		// And the default name is then inert.
		r = httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(authn.HeaderAttachToken, "s3cret")
		if got := gateStatus(g, r); got != http.StatusUnauthorized {
			t.Errorf("the default header: status = %d, want 401 once SideChannelHeader is set", got)
		}
	})

	t.Run("disabled with a hyphen", func(t *testing.T) {
		t.Parallel()
		g := mustGate(t, TokenGateOptions{Token: "s3cret", SideChannelHeader: "-"})

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(authn.HeaderAttachToken, "s3cret")
		if got := gateStatus(g, r); got != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401: the side channel is disabled", got)
		}

		r = httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer s3cret")
		if got := gateStatus(g, r); got != http.StatusOK {
			t.Errorf("Authorization: status = %d, want 200", got)
		}
	})
}

func TestTokenGateRealm(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ realm, want string }{
		{"", `Bearer realm="purser"`},
		{"attach", `Bearer realm="attach"`},
	} {
		g := mustGate(t, TokenGateOptions{Token: "s3cret", Realm: c.realm})
		rec := httptest.NewRecorder()
		g.Middleware()(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if got := rec.Header().Get("WWW-Authenticate"); got != c.want {
			t.Errorf("realm %q: WWW-Authenticate = %q, want %q", c.realm, got, c.want)
		}
	}
}

// A gate with no token would admit everything while reporting that it
// gates credentials — the one lie CheckBind cannot survive.
func TestNewTokenGateRequiresAToken(t *testing.T) {
	t.Parallel()
	g, err := NewTokenGate(TokenGateOptions{})
	if err == nil {
		t.Fatal("NewTokenGate accepted an empty token")
	}
	if g != nil {
		t.Error("NewTokenGate returned a gate alongside an error")
	}
}

func gateStatus(g *TokenGate, r *http.Request) int {
	rec := httptest.NewRecorder()
	g.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, r)
	return rec.Code
}

// ---------------------------------------------------------------
// ReadOnly
// ---------------------------------------------------------------

func TestReadOnly(t *testing.T) {
	t.Parallel()
	cases := []struct {
		method string
		want   int
	}{
		{http.MethodGet, http.StatusOK},
		{http.MethodHead, http.StatusOK},
		{http.MethodOptions, http.StatusOK},
		{http.MethodPost, http.StatusForbidden},
		{http.MethodPut, http.StatusForbidden},
		{http.MethodPatch, http.StatusForbidden},
		{http.MethodDelete, http.StatusForbidden},
		{"PROPFIND", http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			ReadOnly()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rec, httptest.NewRequest(c.method, "/", nil))

			if rec.Code != c.want {
				t.Errorf("status = %d, want %d", rec.Code, c.want)
			}
		})
	}
}

// The refusal is unconditional: an admin credential does not buy a
// write on a listener configured read-only. It is a listener-wide
// switch, not an authorization rule.
func TestReadOnlyIgnoresTheCredential(t *testing.T) {
	t.Parallel()
	auth, err := bearer.New(bearer.Options{
		Users:           []bearer.User{{Identity: "root", Token: "tok_root"}},
		AdminIdentities: []string{"root"},
	})
	if err != nil {
		t.Fatalf("bearer.New: %v", err)
	}
	chain := Chain(mustCaller(t, CallerOptions{Authenticator: auth, Enforce: true}), ReadOnly())

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "Bearer tok_root")

	rec := httptest.NewRecorder()
	chain(http.NotFoundHandler()).ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 even for an authenticated admin", rec.Code)
	}
}

// ---------------------------------------------------------------
// The bind policy
// ---------------------------------------------------------------

func TestIsLoopback(t *testing.T) {
	t.Parallel()
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:7777", true},
		{"127.0.0.2:7777", true}, // the whole 127/8 block is loopback
		{"[::1]:7777", true},
		{"localhost:7777", true},
		{"LOCALHOST:7777", true},

		// Conservative on purpose: an empty host and the wildcards bind
		// every interface, and a hostname resolves to whatever DNS says
		// today. The cost of guessing wrong is an open listener.
		{":7777", false},
		{"0.0.0.0:7777", false},
		{"[::]:7777", false},
		{"10.1.2.3:7777", false},
		{"example.com:7777", false},
		{"garbage", false},
		{"", false},
		// A Unix socket path is not a TCP address; it must not be
		// routed through here, and it does not accidentally read as
		// loopback if it is.
		{"/run/purser.sock", false},
	}
	for _, c := range cases {
		t.Run(c.addr, func(t *testing.T) {
			t.Parallel()
			if got := IsLoopback(c.addr); got != c.want {
				t.Errorf("IsLoopback(%q) = %v, want %v", c.addr, got, c.want)
			}
		})
	}
}

func TestCheckBind(t *testing.T) {
	t.Parallel()
	open := mustGate(t, TokenGateOptions{Token: "s3cret"})
	table, err := bearer.New(bearer.Options{Users: []bearer.User{{Identity: "a", Token: "t"}}})
	if err != nil {
		t.Fatalf("bearer.New: %v", err)
	}
	enforcing := newCaller(t, CallerOptions{Authenticator: table, Enforce: true})
	permissive := newCaller(t, CallerOptions{Authenticator: table})

	cases := []struct {
		name    string
		addr    string
		gates   []Gate
		wantErr bool
	}{
		{"loopback needs no gate", "127.0.0.1:7777", nil, false},
		{"localhost needs no gate", "localhost:7777", nil, false},
		{"the wildcard with no gate", "0.0.0.0:7777", nil, true},
		{"a bare port with no gate", ":7777", nil, true},
		{"a routable address with no gate", "10.1.2.3:7777", nil, true},

		{"a routable address behind a token gate", "10.1.2.3:7777", []Gate{open}, false},

		// The middleware, not the authenticator, is what settles
		// whether a request that fails the credential check still
		// reaches the handler. Both of these wrap the same bearer
		// table, whose own GatesCredentials() is true.
		{"a routable address behind an enforcing caller middleware", "10.1.2.3:7777", []Gate{enforcing}, false},
		{"a routable address behind a permissive caller middleware", "10.1.2.3:7777", []Gate{permissive}, true},

		{"an authenticator that admits unverified requests", "10.1.2.3:7777", []Gate{authn.Anonymous{}}, true},
		// One gate that says yes is enough.
		{"one of several gates", "10.1.2.3:7777", []Gate{authn.Anonymous{}, open}, false},
		{"a permissive middleware alongside a token gate", "10.1.2.3:7777", []Gate{permissive, open}, false},
		// "No gate configured" arriving through a variable is the
		// honest reading of a nil, not a panic.
		{"a nil gate", "10.1.2.3:7777", []Gate{nil}, true},
		{"a nil gate alongside a real one", "10.1.2.3:7777", []Gate{nil, open}, false},
		// A typed nil is the same statement, made by a caller who kept
		// its gate in a *TokenGate.
		{"a typed nil gate", "10.1.2.3:7777", []Gate{(*TokenGate)(nil)}, true},
		{"a typed nil caller middleware", "10.1.2.3:7777", []Gate{(*CallerMiddleware)(nil)}, true},
		// Loopback wins whatever the gates say — it is never refused.
		{"loopback with a gate that says no", "127.0.0.1:7777", []Gate{authn.Anonymous{}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := CheckBind(c.addr, c.gates...)

			if (err != nil) != c.wantErr {
				t.Fatalf("CheckBind(%q, %v) = %v, wantErr %v", c.addr, c.gates, err, c.wantErr)
			}
			if err == nil {
				return
			}
			if !errors.Is(err, ErrUnauthenticatedBind) {
				t.Errorf("error %v does not wrap ErrUnauthenticatedBind", err)
			}
			// The refusal has to tell an operator what to do about it,
			// or it is just a startup failure they will work around by
			// deleting the check.
			if !strings.Contains(err.Error(), c.addr) {
				t.Errorf("error %q does not name the address", err)
			}
			for _, want := range []string{"loopback", "authn/mtls", "NewCaller", "Enforce", "NewTokenGate"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

// ---------------------------------------------------------------
// Chain
// ---------------------------------------------------------------

// Chain runs its middleware left to right: the first entry is
// outermost, which is the order the package doc's example is written
// in and the order the ordering constraints are stated in.
func TestChainOrder(t *testing.T) {
	t.Parallel()
	var order []string
	mark := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}

	// A nil entry is skipped, so a caller can write
	// Chain(gate, maybeNil, caller) without a conditional.
	Chain(mark("first"), nil, mark("second"))(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			order = append(order, "handler")
		}),
	).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if got := strings.Join(order, ","); got != "first,second,handler" {
		t.Errorf("order = %q, want first,second,handler", got)
	}
}

func TestChainEmpty(t *testing.T) {
	t.Parallel()
	var ran bool
	Chain()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true })).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if !ran {
		t.Error("an empty chain did not reach the handler")
	}
}

// A short 401 from the outermost middleware stops the chain: nothing
// further in runs, and in particular nothing further in has to
// re-check.
func TestChainShortCircuits(t *testing.T) {
	t.Parallel()
	gate := mustGate(t, TokenGateOptions{Token: "s3cret"})

	var reached bool
	chain := Chain(gate.Middleware(), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			next.ServeHTTP(w, r)
		})
	})

	rec := httptest.NewRecorder()
	chain(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if reached {
		t.Error("middleware behind the gate ran on a rejected request")
	}
}
