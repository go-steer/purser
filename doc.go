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
// The root package deliberately exports nothing. The API lives in
// subpackages, so that a consumer that only needs a client dialer does not
// link a server's verification machinery. See README.md for the layout and
// core-agent's docs/purser-auth-design.md for the design.
package purser

// review-gate verification; branch is throwaway.
