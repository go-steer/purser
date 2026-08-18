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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// guard builds the middleware wrapped around a handler that reports 200
// and records that it ran.
func guard(t *testing.T, origins ...string) (Middleware, *bool) {
	t.Helper()
	mw, err := NewBrowserWriteGuard(BrowserWriteGuardOptions{AllowedOrigins: origins})
	if err != nil {
		t.Fatalf("NewBrowserWriteGuard(%q): %v", origins, err)
	}
	var ran bool
	return mw, &ran
}

// write sends one request through the guard and returns the status.
func through(t *testing.T, mw Middleware, r *http.Request, ran *bool) int {
	t.Helper()
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*ran = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, r)
	return rec.Code
}

// jsonWrite is a POST that would pass the Content-Type check, so a
// non-200 in an Origin test is about the Origin.
func jsonWrite(origin string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://daemon.local/v1/sessions", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

// ---------------------------------------------------------------
// Origin
// ---------------------------------------------------------------

func TestBrowserWriteGuardOrigin(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		origin string
		want   int
	}{
		// The attack this middleware exists for: any page on the
		// internet firing a simple request at a local daemon.
		{"a page on the internet", "https://evil.example.com", http.StatusForbidden},
		{"an https origin that is not this listener", "https://daemon.local.evil.com", http.StatusForbidden},
		// Sandboxed iframes and file:// pages send this. It names no
		// origin, so it gets no trust.
		{"the null origin", "null", http.StatusForbidden},
		{"a value that does not parse as an origin", "://nonsense", http.StatusForbidden},
		{"an origin with no host", "https://", http.StatusForbidden},

		// url.Parse puts everything before the "@" in Userinfo, so
		// these have a Host of daemon.local and would match the self
		// origin on a naive reading. No browser sends userinfo in an
		// Origin, which is exactly why anything that does is not the
		// header this guard is reading.
		{"userinfo hiding another host", "https://evil.example.com@daemon.local", http.StatusForbidden},
		{"userinfo with a password", "http://user:pw@daemon.local", http.StatusForbidden},
		{"userinfo in front of a loopback host", "https://evil.example.com@127.0.0.1", http.StatusForbidden},

		// A native client — curl, a Go SDK, another service — sends no
		// Origin at all and must be untouched.
		{"no Origin header", "", http.StatusOK},

		// The operator's own machine, including a SPA dev server on
		// another local port.
		{"localhost", "http://localhost:8080", http.StatusOK},
		{"LOCALHOST, case-insensitively", "http://LOCALHOST:8080", http.StatusOK},
		{"the loopback IPv4 address", "http://127.0.0.1:3000", http.StatusOK},
		{"a loopback address other than .1", "http://127.0.0.2:3000", http.StatusOK},
		{"the loopback IPv6 address", "http://[::1]:3000", http.StatusOK},

		// The listener's own origin. The request Host is
		// "daemon.local".
		{"the self origin", "http://daemon.local", http.StatusOK},
		{"the self origin over https, behind a terminating proxy", "https://daemon.local", http.StatusOK},
		{"the self host, cased differently", "http://DAEMON.local", http.StatusOK},
		// A different port is a different origin, even on the same
		// host.
		{"the self host on another port", "http://daemon.local:9999", http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			mw, ran := guard(t)
			got := through(t, mw, jsonWrite(c.origin), ran)

			if got != c.want {
				t.Errorf("status = %d, want %d", got, c.want)
			}
			if *ran != (c.want == http.StatusOK) {
				t.Errorf("handler ran = %v, want %v", *ran, c.want == http.StatusOK)
			}
		})
	}
}

func TestBrowserWriteGuardAllowedOrigins(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		origin string
		want   int
	}{
		{"the allowlisted origin", "https://app.example.com", http.StatusOK},
		{"the allowlisted origin, cased differently", "https://APP.example.com", http.StatusOK},
		// An allowlist and nothing more: no wildcard, no suffix match.
		// "*.example.com" would be one subdomain takeover away from
		// being an open door.
		{"a sibling subdomain", "https://other.example.com", http.StatusForbidden},
		{"a subdomain of the allowed host", "https://x.app.example.com", http.StatusForbidden},
		// The port is part of the origin and is not defaulted.
		{"the allowed host on an explicit :443", "https://app.example.com:443", http.StatusForbidden},
		// The scheme is part of the allowlist key even though the self
		// check ignores it: an allowlist entry is what the operator
		// wrote, not an approximation of it.
		{"the allowed host over http", "http://app.example.com", http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			mw, ran := guard(t, "https://app.example.com")
			if got := through(t, mw, jsonWrite(c.origin), ran); got != c.want {
				t.Errorf("status = %d, want %d", got, c.want)
			}
		})
	}
}

func TestNewBrowserWriteGuardRejectsBadOrigins(t *testing.T) {
	t.Parallel()
	for _, o := range []string{
		"",                         // not an origin
		"app.example.com",          // no scheme
		"https://",                 // no host
		"https://app.example.com/", // a path, even the empty one
		"https://app.example.com/admin",
		"https://app.example.com?x=1",
		"https://app.example.com#frag",
		"://nonsense",
		// Reads as an entry for evil.example.com and would register
		// as one for app.example.com.
		"https://evil.example.com@app.example.com",
		"https://user:pw@app.example.com",
	} {
		if _, err := NewBrowserWriteGuard(BrowserWriteGuardOptions{AllowedOrigins: []string{o}}); err == nil {
			t.Errorf("NewBrowserWriteGuard accepted %q", o)
		}
	}
}

// ---------------------------------------------------------------
// Content-Type
// ---------------------------------------------------------------

func TestBrowserWriteGuardContentType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		contentType string
		want        int
	}{
		{"application/json", "application/json", http.StatusOK},
		{"application/json with a charset", "application/json; charset=utf-8", http.StatusOK},
		{"application/json, cased oddly", "Application/JSON", http.StatusOK},

		// The three media types a cross-site simple request can carry.
		// Each of these is the vector.
		{"text/plain", "text/plain", http.StatusUnsupportedMediaType},
		{"a form post", "application/x-www-form-urlencoded", http.StatusUnsupportedMediaType},
		{"a multipart form", "multipart/form-data; boundary=x", http.StatusUnsupportedMediaType},

		// A body-less DELETE still needs the header. A request with no
		// Content-Type at all is precisely a simple request.
		{"no Content-Type", "", http.StatusUnsupportedMediaType},
		{"an unparseable Content-Type", "application/", http.StatusUnsupportedMediaType},
		// Close but not it.
		{"a JSON suffix type", "application/merge-patch+json", http.StatusUnsupportedMediaType},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			mw, ran := guard(t)

			// No Origin: a native client, so only the Content-Type
			// check is in play.
			r := httptest.NewRequest(http.MethodPost, "http://daemon.local/v1/sessions", nil)
			if c.contentType != "" {
				r.Header.Set("Content-Type", c.contentType)
			}
			if got := through(t, mw, r, ran); got != c.want {
				t.Errorf("status = %d, want %d", got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------
// Methods
// ---------------------------------------------------------------

func TestBrowserWriteGuardMethods(t *testing.T) {
	t.Parallel()
	cases := []struct {
		method string
		want   int
	}{
		// Reads are untouched. A cross-origin GET is already unreadable
		// to the attacking page — the server sends no
		// Access-Control-Allow-Origin — and guarding it would break a
		// browser following a link.
		{http.MethodGet, http.StatusOK},
		{http.MethodHead, http.StatusOK},
		{http.MethodOptions, http.StatusOK},

		{http.MethodPost, http.StatusForbidden},
		{http.MethodPut, http.StatusForbidden},
		{http.MethodPatch, http.StatusForbidden},
		{http.MethodDelete, http.StatusForbidden},
		// An unknown method is a write until proven otherwise.
		{"PROPFIND", http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			t.Parallel()
			mw, ran := guard(t)

			r := httptest.NewRequest(c.method, "http://daemon.local/v1/sessions", nil)
			r.Header.Set("Origin", "https://evil.example.com")
			r.Header.Set("Content-Type", "application/json")

			if got := through(t, mw, r, ran); got != c.want {
				t.Errorf("status = %d, want %d", got, c.want)
			}
		})
	}
}

// Both checks fail; the Origin one is the more specific diagnosis and
// is the one reported.
func TestBrowserWriteGuardOriginBeatsContentType(t *testing.T) {
	t.Parallel()
	mw, ran := guard(t)

	r := httptest.NewRequest(http.MethodPost, "http://daemon.local/v1/sessions", strings.NewReader("hi"))
	r.Header.Set("Origin", "https://evil.example.com")
	r.Header.Set("Content-Type", "text/plain")

	if got := through(t, mw, r, ran); got != http.StatusForbidden {
		t.Errorf("status = %d, want 403", got)
	}
}

func TestBrowserWriteGuardConvenienceMatchesTheEmptyOptions(t *testing.T) {
	t.Parallel()
	var ran bool
	if got := through(t, BrowserWriteGuard(), jsonWrite("https://evil.example.com"), &ran); got != http.StatusForbidden {
		t.Errorf("status = %d, want 403", got)
	}
	if got := through(t, BrowserWriteGuard(), jsonWrite(""), &ran); got != http.StatusOK {
		t.Errorf("status = %d, want 200", got)
	}
}
