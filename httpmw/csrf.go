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
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// BrowserWriteGuardOptions configures NewBrowserWriteGuard.
type BrowserWriteGuardOptions struct {
	// AllowedOrigins are additional origins permitted to drive
	// state-changing requests, beyond the loopback and self origins
	// the guard always allows. Each must be a scheme://host[:port]
	// with no path, and is compared case-insensitively on scheme and
	// host.
	//
	// This is for a single-page app served from a different origin
	// than the API. It is an allowlist and nothing else: there is no
	// wildcard and no suffix match, because "*.example.com" is one
	// subdomain takeover away from being an open door.
	AllowedOrigins []string
}

// NewBrowserWriteGuard returns the middleware that blocks the browser
// cross-site request forgery vectors against a JSON API.
//
// A page the operator visits can fire a CORS "simple request" at a
// listener it cannot otherwise reach — a form POST, or fetch with
// Content-Type: text/plain — with no preflight. The response stays
// unreadable to the attacking page, which does not help: the side
// effect has already landed. For a local daemon on a well-known port
// with a well-known resource path, that is a one-line attack from any
// web page.
//
// Two checks run on every state-changing request (any method other
// than GET, HEAD and OPTIONS), regardless of what credential it
// carries:
//
//  1. Origin: when the request has an Origin header it must be a
//     loopback origin, an origin matching the request's own Host, or
//     one of AllowedOrigins. Otherwise 403. Browsers attach Origin to
//     every cross-site write; native clients — curl, a Go SDK, another
//     service — send none and pass untouched.
//  2. Content-Type: application/json is required, otherwise 415. The
//     three media types a cross-site simple request can carry are
//     text/plain, multipart/form-data and
//     application/x-www-form-urlencoded, so requiring JSON forces any
//     browser write through a preflight the server never answers.
//
// Reads are untouched. A cross-origin GET is already unreadable to the
// attacking page because the server sends no
// Access-Control-Allow-Origin, and guarding them would break the
// ordinary case of a browser following a link.
//
// This is defense against the browser, not against a client that can
// set arbitrary headers. Anything with a socket can send
// `Content-Type: application/json` and no Origin; what stops *that* is
// the credential, which is a different middleware.
//
// # What it does not stop
//
// DNS rebinding. The self-origin rule compares the Origin's authority
// against the request's own Host, so a name the attacker controls that
// resolves to the listener's address — `evil.test` with an A record of
// 127.0.0.1, served from `http://evil.test:7777` — is same-origin to
// the browser and passes. The response is readable too, because the
// browser believes it is talking to its own origin. Closing that needs
// a Host allowlist, which belongs to the service that knows its own
// names; the standard mitigation is to reject requests whose Host is
// not one of them, before this middleware runs. Requiring the
// credential on every state-changing endpoint is the other half:
// a rebound page still has to steal one.
func NewBrowserWriteGuard(opts BrowserWriteGuardOptions) (Middleware, error) {
	allowed := make(map[string]struct{}, len(opts.AllowedOrigins))
	for _, o := range opts.AllowedOrigins {
		u, err := url.Parse(o)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("httpmw: NewBrowserWriteGuard: AllowedOrigins entry %q is not a scheme://host origin", o)
		}
		if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("httpmw: NewBrowserWriteGuard: AllowedOrigins entry %q has a path, query or fragment; an origin is scheme://host[:port] only", o)
		}
		if u.User != nil {
			// "https://evil.example.com@app.example.com" parses with a
			// Host of app.example.com, so it would register as that
			// entry while reading to an operator as something else.
			// Refuse it rather than silently allowlist a host they did
			// not think they were naming.
			return nil, fmt.Errorf("httpmw: NewBrowserWriteGuard: AllowedOrigins entry %q carries userinfo; an origin is scheme://host[:port] only, and the host here is %q", o, u.Host)
		}
		allowed[originKey(u)] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isWriteMethod(r.Method) {
				if origin := r.Header.Get("Origin"); origin != "" && !originAllowed(origin, r.Host, allowed) {
					http.Error(w, fmt.Sprintf(
						"cross-origin request rejected: Origin %q is neither a loopback origin, this listener (%q), nor an allowed origin; "+
							"browser pages may not drive this API cross-site. Native clients should omit the Origin header.",
						origin, r.Host), http.StatusForbidden)
					return
				}
				if !isJSONContentType(r.Header.Get("Content-Type")) {
					http.Error(w,
						"unsupported media type: state-changing endpoints require \"Content-Type: application/json\" "+
							"(browser cross-site request forgery protection; send the header even when the request has no body)",
						http.StatusUnsupportedMediaType)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}

// BrowserWriteGuard is NewBrowserWriteGuard with no extra allowed
// origins, for the common case of an API with no cross-origin browser
// client. It cannot fail, so it returns no error.
func BrowserWriteGuard() Middleware {
	mw, err := NewBrowserWriteGuard(BrowserWriteGuardOptions{})
	if err != nil {
		// Unreachable: the only error is a malformed AllowedOrigins
		// entry and there are none.
		panic("httpmw: BrowserWriteGuard: " + err.Error())
	}
	return mw
}

// originKey normalizes an origin to the form compared in the
// allowlist. Scheme and host are case-insensitive per RFC 3986; the
// port is part of the origin and is not defaulted, so
// "https://app.example.com" and "https://app.example.com:443" are
// different entries and an operator who means both writes both.
func originKey(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// isJSONContentType reports whether ct names application/json.
// Parameters such as charset are fine; an empty or unparseable value
// is not, because a write with no Content-Type is precisely the
// body-less simple request being closed off.
func isJSONContentType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "application/json"
}

// originAllowed reports whether a browser-supplied Origin may drive a
// state-changing request.
//
// Permitted: loopback origins (the operator's own machine, including a
// SPA dev server on another local port), the self origin, and the
// configured allowlist. Everything else is refused, including the
// literal "null" that sandboxed iframes and file:// pages send and any
// value that does not parse — an origin nobody can name is not an
// origin anybody should trust.
func originAllowed(origin, requestHost string, allowed map[string]struct{}) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false // includes "null" and malformed values
	}
	// No browser puts userinfo in an Origin, so anything that does is
	// not the header this guard is reading. It matters because
	// "https://evil.example.com@daemon.local" parses with a Host of
	// daemon.local and would otherwise match the self origin.
	if u.User != nil {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	if _, ok := allowed[originKey(u)]; ok {
		return true
	}
	// Self origin: the origin's host:port is the Host the request was
	// addressed to. The scheme is deliberately not compared — behind a
	// TLS-terminating proxy the browser's origin is https while this
	// listener sees http, and the host is the part that carries the
	// meaning.
	return strings.EqualFold(u.Host, requestHost)
}
