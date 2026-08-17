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

package authn

import (
	"net/http"

	"github.com/go-steer/purser"
)

// Anonymous resolves every request to the same Caller without
// verifying anything. It is the authenticator for surfaces that have
// not enabled per-caller identity, so downstream code always finds a
// Caller on the context and never has to special-case its absence.
//
// The zero value resolves to purser.Anonymous(). Set Caller to override
// the identity.
//
// It reports GatesCredentials() == false, so a surface that consults
// CredentialGate before binding a non-loopback address will not
// mistake it for a credential check.
type Anonymous struct {
	// Caller is returned for every request. A zero Caller means
	// purser.Anonymous().
	Caller purser.Caller
}

var (
	_ Authenticator  = Anonymous{}
	_ CredentialGate = Anonymous{}
)

// Authenticate ignores the request and returns the configured Caller.
// It never returns an error.
//
// The Caller is cloned so a handler that adds a label to what it
// believes is its own copy cannot rewrite the identity every
// subsequent request will see.
func (a Anonymous) Authenticate(_ *http.Request) (purser.Caller, error) {
	if a.Caller.IsZero() {
		return purser.Anonymous(), nil
	}
	return a.Caller.Clone(), nil
}

// Source reports purser.AuthSourceAnonymous: this authenticator
// succeeds for every request precisely because it verified nothing.
func (a Anonymous) Source() purser.AuthSource { return purser.AuthSourceAnonymous }

// GatesCredentials reports false. Nothing is verified, so nothing is
// gated.
func (a Anonymous) GatesCredentials() bool { return false }
