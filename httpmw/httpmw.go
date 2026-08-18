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

// Package httpmw is the HTTP layer that turns purser's authenticators
// into a serving surface: it resolves the Caller onto the request
// context, stamps how the request was authenticated, guards the
// browser CSRF vectors, gates a shared transport token, and answers
// whether an address is safe to bind.
//
// The package is stdlib-only. Everything it needs from a credential it
// gets through the interfaces in authn, so a surface that serves SPIFFE
// mTLS and one that serves bearer tokens link the same middleware.
//
// # Ordering
//
// The middlewares are not interchangeable and the order is part of the
// security argument:
//
//	Chain(
//	    gate.Middleware(),      // outermost: shared transport token
//	    BrowserWriteGuard(),    // then the CSRF vectors
//	    caller.Middleware(),    // then per-caller identity
//	)(mux)
//
// The token gate runs outermost because it is the cheapest rejection
// and because passing it is itself a verified auth source that the
// caller middleware inherits. The browser guard runs before the caller
// middleware so a cross-site write is refused whether or not it carries
// a credential. The caller middleware runs innermost, closest to the
// handler that reads the Caller off the context.
//
// Both gate and caller are then what CheckBind is given — they are the
// two things in that chain that can refuse a request for want of a
// credential, and so the two that can answer whether the address is
// safe to expose:
//
//	if err := CheckBind(addr, gate, caller); err != nil {
//	    return err
//	}
//
// # What this package will not do
//
// It never derives an identity, or the verdict on how a request was
// authenticated, from a request header. The one header that can change
// who a request is attributed to — the asserted-caller header — is
// honored only when the authenticator that verified the connection says
// the caller may proxy, and the asserted identity is materialized from
// the authenticator's own table. See NewCaller.
package httpmw

import "net/http"

// Middleware is the decorator every constructor in this package
// returns. It is the conventional shape, named so that a chain reads as
// a list rather than as nested calls.
type Middleware func(next http.Handler) http.Handler

// Chain composes middlewares into one, outermost first: the first
// element sees the request before the second, and the handler passed to
// the result runs last.
//
// Order matters here — see the package documentation — so the
// composition is spelled out rather than left to whatever order the
// wrapping happened to be written in.
func Chain(mw ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(mw) - 1; i >= 0; i-- {
			if mw[i] == nil {
				continue
			}
			next = mw[i](next)
		}
		return next
	}
}

// isWriteMethod reports whether m is a state-changing method. GET,
// HEAD and OPTIONS are reads; everything else — including methods this
// package has never heard of — is a write, because a guard that
// defaults to "read" would wave through the next method someone
// invents.
func isWriteMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}
