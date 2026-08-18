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

// Package tlsfloor holds purser's minimum TLS version policy.
//
// It is shared rather than duplicated because the client and the server
// have to agree. A client built below the server's floor cannot
// negotiate, and the failure — a handshake alert with no explanation of
// which side set which bound — is one of the least legible in TLS. One
// definition means the two cannot drift apart.
package tlsfloor

import (
	"crypto/tls"
	"fmt"
)

// Min is the floor a configured MinVersion may not go below. TLS 1.1
// and below have no secure cipher suites left and crypto/tls will not
// negotiate them by default; accepting a request to use one would be a
// promise purser cannot keep.
const Min = tls.VersionTLS12

// Default is the floor when MinVersion is unset.
//
// core-agent's server configures TLS 1.2 today; purser raises the
// default because every first-party client speaks 1.3, and a deployment
// that genuinely needs 1.2 for an older client can ask for it
// explicitly. That is the direction the mistake should point: an
// operator who says nothing gets the stronger setting.
const Default = tls.VersionTLS13

// Resolve validates a configured TLS floor, substituting Default for
// zero. The returned error carries no package prefix; callers add
// their own.
func Resolve(v uint16) (uint16, error) {
	if v == 0 {
		return Default, nil
	}
	if v < Min {
		return 0, fmt.Errorf("MinVersion %#04x is below TLS 1.2 (%#04x), which has no "+
			"secure configuration left", v, uint16(Min))
	}
	return v, nil
}
