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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn/oidc"
	"github.com/go-steer/purser/authtest"
)

// selfURL is the server's own base URL as the request reached it. Taken
// from the request rather than from the httptest.Server value so the
// handler needs no synchronization with the goroutine that started it.
func selfURL(r *http.Request) string { return "https://" + r.Host }

// TestDiscoveryRefusals walks the discovery documents that must not be
// followed.
//
// The issuer check is the one that matters. Without it, anything that
// can answer at the issuer's well-known path points the key fetch at a
// JWK Set of its own, and from there signs tokens for any identity — so
// a wrong "issuer" field is an authentication bypass, not a
// configuration nit.
func TestDiscoveryRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// document is the body served at the well-known path, given the
		// server's own URL. Returning "" serves a 500 instead.
		document func(self string) string
		wantErr  string
	}{
		{
			// Neither URL is ever dialled: the issuer check refuses the
			// document before the key endpoint is fetched, which is the
			// property under test. ".example" is reserved by RFC 6761 §6.5
			// and does not resolve, so a regression that reordered those
			// two steps would fail here rather than reach the network.
			name: "the document names another issuer",
			document: func(self string) string {
				return `{"issuer":"https://evil.example","jwks_uri":"https://evil.example/jwks"}`
			},
			wantErr: "declares issuer",
		},
		{
			name:     "the document names no issuer",
			document: func(self string) string { return fmt.Sprintf(`{"jwks_uri":%q}`, self+"/jwks") },
			wantErr:  "declares issuer",
		},
		{
			name: "the issuer differs only by a trailing slash",
			document: func(self string) string {
				return fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, self+"/", self+"/jwks")
			},
			wantErr: "declares issuer",
		},
		{
			name:     "no jwks_uri",
			document: func(self string) string { return fmt.Sprintf(`{"issuer":%q}`, self) },
			wantErr:  "no jwks_uri",
		},
		{
			name: "a plaintext jwks_uri",
			document: func(self string) string {
				return fmt.Sprintf(`{"issuer":%q,"jwks_uri":"http://keys.example.com/jwks"}`, self)
			},
			wantErr: "non-https jwks_uri",
		},
		{
			name: "a jwks_uri with no host",
			document: func(self string) string {
				return fmt.Sprintf(`{"issuer":%q,"jwks_uri":"https:///jwks"}`, self)
			},
			wantErr: "with no host",
		},
		{
			name:     "not JSON",
			document: func(self string) string { return `<html>sign in to continue</html>` },
			wantErr:  "decoding the discovery document",
		},
		{
			name:     "an error from the provider",
			document: func(self string) string { return "" },
			wantErr:  "500 Internal Server Error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// The token is minted by a real issuer; only the discovery
			// document is doctored. What is under test is which key
			// endpoint gets trusted, not whether a signature is good.
			signer := authtest.NewIssuer(t)

			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := tt.document(selfURL(r))
				if body == "" {
					http.Error(w, "the provider is having a day", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if _, err := w.Write([]byte(body)); err != nil {
					t.Errorf("writing the discovery document: %v", err)
				}
			}))
			defer srv.Close()

			a, err := oidc.New(oidc.Options{
				Issuer:     srv.URL,
				Audiences:  []string{authtest.DefaultAudience},
				HTTPClient: srv.Client(),
			})
			if err != nil {
				t.Fatalf("oidc.New: %v", err)
			}

			token := signer.Mint(t, authtest.TokenOptions{Email: alice, Issuer: srv.URL})
			c, err := authenticate(t, a, token)
			if err == nil {
				t.Fatalf("Authenticate succeeded as %q against a discovery document that must not "+
					"be followed", c.Identity)
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

// TestDiscoveryPath pins where the document is looked for.
func TestDiscoveryPath(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t)

	var mu sync.Mutex
	var paths []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		http.NotFound(w, r)
	}))
	defer srv.Close()

	a, err := oidc.New(oidc.Options{
		Issuer:     srv.URL,
		Audiences:  []string{authtest.DefaultAudience},
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	token := iss.Mint(t, authtest.TokenOptions{Email: alice, Issuer: srv.URL})
	if _, err := authenticate(t, a, token); err == nil {
		t.Fatal("Authenticate succeeded against a provider serving 404s")
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"/.well-known/openid-configuration"}
	if len(paths) != len(want) || paths[0] != want[0] {
		t.Errorf("requested paths = %v, want %v", paths, want)
	}
}

// TestJWKSOnAnotherHostIsAllowed pins that the key endpoint need not
// share the issuer's host: Google's issuer is accounts.google.com and
// its keys are on www.googleapis.com. The issuer check on the document
// is what makes following it safe, so the host is deliberately not
// constrained as well.
func TestJWKSOnAnotherHostIsAllowed(t *testing.T) {
	t.Parallel()

	keys := authtest.NewIssuer(t)

	// A provider that serves only a discovery document, pointing at the
	// other server's key endpoint.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		body := fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, selfURL(r), keys.JWKSURL())
		if _, err := w.Write([]byte(body)); err != nil {
			t.Errorf("writing the discovery document: %v", err)
		}
	}))
	defer srv.Close()

	// One client that trusts both ephemeral certificates. A real
	// deployment's client trusts a public root and needs no such
	// arrangement.
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	pool.AddCert(keys.Certificate())
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}

	a, err := oidc.New(oidc.Options{
		Issuer:     srv.URL,
		Audiences:  []string{authtest.DefaultAudience},
		HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}

	token := keys.Mint(t, authtest.TokenOptions{Email: alice, Issuer: srv.URL})
	if _, err := authenticate(t, a, token); err != nil {
		t.Fatalf("Authenticate with keys on another host: %v", err)
	}
	if got := keys.JWKSRequests(); got != 1 {
		t.Errorf("JWKS fetches on the key host = %d, want 1", got)
	}
}
