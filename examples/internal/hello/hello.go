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

// Package hello is the REST/JSON service the purser examples
// authenticate.
//
// It is deliberately dull. The service is one GET returning who the
// caller is, because the interesting part of the examples is the
// credential that got them in, not what they asked for.
//
// Nothing here is part of purser's exported API. It is internal to the
// module and exists so the server and client binaries share one wire
// contract rather than two hand-written ones that can disagree.
package hello

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
)

// Path is the one endpoint the service serves.
const Path = "/hello"

// Greeting is the success body: the identity purser resolved, and the
// evidence it resolved it from.
type Greeting struct {
	// Greeting is the human-readable line.
	Greeting string `json:"greeting"`
	// Caller is purser.Caller.Identity — a SPIFFE ID under the SPIFFE
	// profile, whatever SubjectSource names under the PKI one.
	Caller string `json:"caller"`
	// AuthSource is how the server authenticated the request. It comes
	// from the authenticator that did the verifying, never from a
	// request header.
	AuthSource string `json:"auth_source"`
	// Labels is the credential metadata purser attached — issuer DN and
	// serial for PKI, trust domain and path for SPIFFE.
	Labels map[string]string `json:"labels,omitempty"`
	// ServedBy names the server instance, so a reader can tell which
	// replica answered.
	ServedBy string `json:"served_by"`
}

// Fault is the error body.
//
// It carries a category rather than the underlying error text. An
// authentication failure's detail — which field was missing, which
// matcher rejected — is for the server's log, not for the peer that
// failed it: a client that can enumerate why it was rejected can
// enumerate its way to a credential that is not.
type Fault struct {
	Error string `json:"error"`
}

// Handler serves Path from the Caller on the request context.
//
// It assumes Authenticate ran ahead of it. A missing Caller is a wiring
// bug in the server, not an unauthenticated request, and is reported as
// one: returning a cheerful anonymous greeting instead would make an
// unauthenticated surface look like a working one.
func Handler(servedBy string, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeJSON(w, log, http.StatusMethodNotAllowed, Fault{Error: "method not allowed"})
			return
		}

		caller, ok := purser.CallerFromContext(r.Context())
		if !ok {
			log.Error("no caller on the request context; the handler is not behind Authenticate")
			writeJSON(w, log, http.StatusInternalServerError, Fault{Error: "server misconfigured"})
			return
		}
		source, _ := purser.AuthSourceFromContext(r.Context())

		writeJSON(w, log, http.StatusOK, Greeting{
			Greeting:   fmt.Sprintf("hello, %s", caller.Identity),
			Caller:     caller.Identity,
			AuthSource: source.String(),
			Labels:     caller.Labels,
			ServedBy:   servedBy,
		})
	})
}

// Authenticate resolves the caller with a and puts it on the request
// context, or answers 401.
//
// This is what purser's httpmw package will eventually provide. Until
// it does, every consumer writes these fifteen lines, so the example
// writes them where they can be read:
//
//   - The Caller and the AuthSource go on the context together. The
//     source is taken from the authenticator that verified the
//     request — a.Source() — and never from anything the client sent.
//   - An error means no identity. There is no partial success to fall
//     through on, so the handler below never runs.
func Authenticate(a authn.Authenticator, log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, err := a.Authenticate(r)
		if err != nil {
			// The detail goes to the operator; the peer gets the
			// category. See Fault.
			log.Warn("rejected a request",
				"remote", r.RemoteAddr,
				"path", r.URL.Path,
				"err", err)
			writeJSON(w, log, http.StatusUnauthorized, Fault{Error: "unauthenticated"})
			return
		}

		ctx := purser.WithCaller(r.Context(), caller)
		ctx = purser.WithAuthSource(ctx, a.Source())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Greet performs the one request the service serves.
//
// baseURL is the scheme and authority, e.g. "https://127.0.0.1:8443".
func Greet(ctx context.Context, c *http.Client, baseURL string) (Greeting, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+Path, nil)
	if err != nil {
		return Greeting{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return Greeting{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Bound the read: an example that hangs on a hostile server teaches
	// the wrong thing to whoever copies it.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Greeting{}, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var f Fault
		if err := json.Unmarshal(body, &f); err == nil && f.Error != "" {
			return Greeting{}, fmt.Errorf("%s: %s", resp.Status, f.Error)
		}
		return Greeting{}, errors.New(resp.Status)
	}

	var g Greeting
	if err := json.Unmarshal(body, &g); err != nil {
		return Greeting{}, fmt.Errorf("decode response: %w", err)
	}
	return g, nil
}

// writeJSON writes v with the given status.
//
// A failure here means the connection is gone; there is nothing left to
// tell the client, so it is logged and dropped. Writing a second
// response would only corrupt the first.
func writeJSON(w http.ResponseWriter, log *slog.Logger, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Debug("write response", "err", err)
	}
}
