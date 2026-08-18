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

package tlsfloor_test

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/go-steer/purser/internal/tlsfloor"
)

func TestResolve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      uint16
		want    uint16
		wantErr string
	}{
		{
			name: "unset takes the default",
			in:   0,
			want: tls.VersionTLS13,
		},
		{
			name: "the floor itself is accepted",
			in:   tls.VersionTLS12,
			want: tls.VersionTLS12,
		},
		{
			name: "above the floor is accepted",
			in:   tls.VersionTLS13,
			want: tls.VersionTLS13,
		},
		{
			name:    "below the floor is rejected",
			in:      tls.VersionTLS11,
			wantErr: "below TLS 1.2",
		},
		{
			name:    "SSL 3.0 is rejected",
			in:      tls.VersionSSL30, //nolint:staticcheck // the point is that it is refused
			wantErr: "below TLS 1.2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tlsfloor.Resolve(tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("Resolve(%#04x) = %#04x, want an error containing %q",
						tc.in, got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve(%#04x): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("Resolve(%#04x) = %#04x, want %#04x", tc.in, got, tc.want)
			}
		})
	}
}

// TestDefaultIsAtOrAboveMin pins the two constants against each other.
// A Default below Min would make the zero value the one setting Resolve
// refuses to accept explicitly.
func TestDefaultIsAtOrAboveMin(t *testing.T) {
	t.Parallel()

	if tlsfloor.Default < tlsfloor.Min {
		t.Errorf("Default (%#04x) is below Min (%#04x)", tlsfloor.Default, tlsfloor.Min)
	}
}
