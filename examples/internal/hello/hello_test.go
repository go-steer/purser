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

package hello

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
)

// fakeAuth is an authenticator with a fixed verdict.
type fakeAuth struct {
	caller purser.Caller
	err    error
	source purser.AuthSource
}

func (f fakeAuth) Authenticate(*http.Request) (purser.Caller, error) { return f.caller, f.err }
func (f fakeAuth) Source() purser.AuthSource                         { return f.source }

var _ authn.Authenticator = fakeAuth{}

// logTo returns a logger writing into buf, for the tests that assert
// what reached the operator rather than the peer.
func logTo(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHandlerGreetsTheCallerOnTheContext(t *testing.T) {
	h := Handler("replica-7", discardLogger())

	req := httptest.NewRequest(http.MethodGet, Path, nil)
	ctx := purser.WithCaller(req.Context(), purser.Caller{
		Identity: "spiffe://example.org/ns/default/sa/hello-client",
		Labels:   map[string]string{"trust_domain": "example.org"},
	})
	ctx = purser.WithAuthSource(ctx, purser.AuthSourceSPIFFE)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var g Greeting
	if err := json.Unmarshal(rec.Body.Bytes(), &g); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body, err)
	}
	want := Greeting{
		Greeting:   "hello, spiffe://example.org/ns/default/sa/hello-client",
		Caller:     "spiffe://example.org/ns/default/sa/hello-client",
		AuthSource: "spiffe",
		Labels:     map[string]string{"trust_domain": "example.org"},
		ServedBy:   "replica-7",
	}
	if !reflect.DeepEqual(g, want) {
		t.Errorf("greeting = %+v, want %+v", g, want)
	}
}

// A handler that is not behind Authenticate must fail loudly. Answering
// 200 with an empty caller would make an unauthenticated surface look
// like a working one.
func TestHandlerWithoutCallerIsAnError(t *testing.T) {
	var logs bytes.Buffer
	h := Handler("replica-7", logTo(&logs))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, Path, nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if strings.Contains(rec.Body.String(), "hello,") {
		t.Errorf("body greeted an anonymous caller: %q", rec.Body)
	}
	if !strings.Contains(logs.String(), "no caller on the request context") {
		t.Errorf("wiring bug was not logged; got %q", logs.String())
	}
}

func TestHandlerRejectsNonGET(t *testing.T) {
	h := Handler("replica-7", discardLogger())

	req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader("{}"))
	ctx := purser.WithCaller(req.Context(), purser.Caller{Identity: "client"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if got := rec.Header().Get("Allow"); got != http.MethodGet {
		t.Errorf("Allow = %q, want %q", got, http.MethodGet)
	}
}

func TestAuthenticatePassesTheCallerThrough(t *testing.T) {
	auth := fakeAuth{
		caller: purser.Caller{Identity: "hello-client.local"},
		source: purser.AuthSourceMTLS,
	}

	var (
		gotCaller purser.Caller
		gotSource purser.AuthSource
		ran       bool
	)
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ran = true
		gotCaller, _ = purser.CallerFromContext(r.Context())
		gotSource, _ = purser.AuthSourceFromContext(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, Path, nil)
	// A header claiming a different source must not be believed: the
	// auth source is stamped by the code that verified the connection.
	// "oidc" is a real purser.AuthSource and is not the one the
	// authenticator reports, so an Authenticate that ever read this
	// header would fail the gotSource assertion below rather than
	// quietly agree with it.
	req.Header.Set("X-Auth-Source", string(purser.AuthSourceOIDC))
	Authenticate(auth, discardLogger(), next).ServeHTTP(httptest.NewRecorder(), req)

	if !ran {
		t.Fatal("next handler did not run")
	}
	if gotCaller.Identity != "hello-client.local" {
		t.Errorf("caller = %q, want hello-client.local", gotCaller.Identity)
	}
	if gotSource != purser.AuthSourceMTLS {
		t.Errorf("auth source = %q, want %q", gotSource, purser.AuthSourceMTLS)
	}
}

func TestAuthenticateRejectsWithoutDetail(t *testing.T) {
	const detail = "certificate has no URI SAN"
	auth := fakeAuth{err: errors.New(detail), source: purser.AuthSourceSPIFFE}

	var logs bytes.Buffer
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("next handler ran on a rejected request")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, Path, nil)
	Authenticate(auth, logTo(&logs), next).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	var f Fault
	if err := json.Unmarshal(rec.Body.Bytes(), &f); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body, err)
	}
	if f.Error != "unauthenticated" {
		t.Errorf("error = %q, want unauthenticated", f.Error)
	}
	// The peer learns the category; the operator learns the reason.
	if strings.Contains(rec.Body.String(), detail) {
		t.Errorf("response leaked why the peer was rejected: %q", rec.Body)
	}
	if !strings.Contains(logs.String(), detail) {
		t.Errorf("rejection reason was not logged; got %q", logs.String())
	}
}

func TestGreetRoundTrip(t *testing.T) {
	auth := fakeAuth{
		caller: purser.Caller{Identity: "hello-client.local", Labels: map[string]string{"ou": "platform"}},
		source: purser.AuthSourceMTLS,
	}
	mux := http.NewServeMux()
	mux.Handle(Path, Authenticate(auth, discardLogger(), Handler("srv", discardLogger())))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	g, err := Greet(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("Greet: %v", err)
	}
	if g.Caller != "hello-client.local" {
		t.Errorf("caller = %q, want hello-client.local", g.Caller)
	}
	if g.AuthSource != "mtls" {
		t.Errorf("auth source = %q, want mtls", g.AuthSource)
	}
	if g.Labels["ou"] != "platform" {
		t.Errorf("labels = %v, want ou=platform", g.Labels)
	}
	if g.ServedBy != "srv" {
		t.Errorf("served_by = %q, want srv", g.ServedBy)
	}
}

func TestGreetReportsRejection(t *testing.T) {
	auth := fakeAuth{err: errors.New("no"), source: purser.AuthSourceMTLS}
	mux := http.NewServeMux()
	mux.Handle(Path, Authenticate(auth, discardLogger(), Handler("srv", discardLogger())))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := Greet(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("Greet succeeded against a server that rejects everything")
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "unauthenticated") {
		t.Errorf("error = %v, want the status and the fault category", err)
	}
}

// A server that answers an error without a Fault body — a proxy, say,
// or a load balancer — still has to produce a usable error.
func TestGreetReportsNonJSONError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no backend", http.StatusBadGateway)
	}))
	defer srv.Close()

	_, err := Greet(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("Greet succeeded against a 502")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error = %v, want the status", err)
	}
}

func TestGreetHonoursContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("server was reached despite a cancelled context")
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := Greet(ctx, srv.Client(), srv.URL); !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}
