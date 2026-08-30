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

package oidc

import "time"

// SetClock replaces the clock every expiry decision and every key-cache
// deadline reads. Defined in a test file, so it is visible to this
// package's external tests and to nothing else — the exported surface
// gains no way to move a production authenticator's clock.
func SetClock(a *Auth, now func() time.Time) {
	a.now = now
	a.keys.now = now
}
