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

// Package purser is the root of go-steer's shared authentication and
// authorization module: caller identity derived from SPIFFE X.509-SVIDs,
// standard-CA client certificates, and OIDC tokens.
//
// The root package holds only what every consumer needs and nothing can be
// defined without — the Caller identity, the AuthSource verdict, the sentinel
// errors, and the context plumbing that carries them. It is stdlib-only and
// depends on no other purser package, so it can be imported by a client that
// merely reads an identity off a context.
//
// Everything that verifies a credential lives in a subpackage, so a consumer
// links only the machinery it uses: authn for the Authenticator contract and
// its implementations, authz for the authorization matrix, httpmw for the
// middleware, client for outbound credentials, and authtest for the
// conformance suite and an in-memory CA.
//
// See README.md for the layout and docs/DESIGN.md for the design.
package purser
