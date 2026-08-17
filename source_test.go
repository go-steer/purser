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

package purser_test

import (
	"context"
	"testing"

	"github.com/go-steer/purser"
)

// TestAuthSourceWireValues pins the strings. They surface on
// core-agent's /whoami, so changing one is a breaking change for
// anything switching on the response — phase 2 requires the existing
// values to keep their spelling exactly.
func TestAuthSourceWireValues(t *testing.T) {
	t.Parallel()

	want := map[purser.AuthSource]string{
		purser.AuthSourceAnonymous: "anonymous",
		purser.AuthSourceBearer:    "bearer",
		purser.AuthSourceMTLS:      "mtls",
		purser.AuthSourceSPIFFE:    "spiffe",
		purser.AuthSourceOIDC:      "oidc",
		purser.AuthSourceAsserted:  "asserted",
		purser.AuthSourceIAP:       "iap",
	}
	for src, str := range want {
		if got := src.String(); got != str {
			t.Errorf("AuthSource.String() = %q, want %q", got, str)
		}
		if !src.Known() {
			t.Errorf("%q.Known() = false, want true", src)
		}
	}
	if len(want) != 7 {
		t.Fatalf("test covers %d sources; update it alongside source.go", len(want))
	}
}

// TestMTLSAndSPIFFEAreDistinct pins the property that motivates having
// two values: both profiles are mutual TLS, but an operator has to be
// able to tell which one admitted a caller.
func TestMTLSAndSPIFFEAreDistinct(t *testing.T) {
	t.Parallel()

	if purser.AuthSourceMTLS == purser.AuthSourceSPIFFE {
		t.Error("AuthSourceMTLS == AuthSourceSPIFFE; the two profiles must stay distinguishable")
	}
}

func TestAuthSourceKnownRejectsUnknown(t *testing.T) {
	t.Parallel()

	for _, s := range []purser.AuthSource{"", "MTLS", "mtls ", "basic", "trust-me"} {
		if s.Known() {
			t.Errorf("%q.Known() = true, want false", s)
		}
	}
}

func TestAuthSourceRoundTripsThroughContext(t *testing.T) {
	t.Parallel()

	ctx := purser.WithAuthSource(context.Background(), purser.AuthSourceSPIFFE)
	got, ok := purser.AuthSourceFromContext(ctx)
	if !ok || got != purser.AuthSourceSPIFFE {
		t.Errorf("AuthSourceFromContext() = (%q, %v), want (%q, true)", got, ok, purser.AuthSourceSPIFFE)
	}
}

func TestAuthSourceFromContextAbsent(t *testing.T) {
	t.Parallel()

	// No middleware ran, so nothing was verified. The caller must be
	// able to tell that apart from a verified "anonymous".
	got, ok := purser.AuthSourceFromContext(context.Background())
	if ok {
		t.Errorf("AuthSourceFromContext(bare context): ok = true, source = %q", got)
	}
	if got != "" {
		t.Errorf("AuthSourceFromContext(bare context) = %q, want %q", got, "")
	}
}

// TestAuthSourceContextKeyIsPrivate pins that the verdict cannot be
// planted by a caller who guesses the key. The stamp is only
// trustworthy if the code that performed the verification is the only
// thing that can write it.
func TestAuthSourceContextKeyIsPrivate(t *testing.T) {
	t.Parallel()

	//nolint:staticcheck // deliberately using a bare string key, which is what an outsider could do
	ctx := context.WithValue(context.Background(), "authSourceKey", purser.AuthSourceMTLS)
	//nolint:staticcheck // ditto: the unexported struct key is unreachable from here by construction
	ctx = context.WithValue(ctx, struct{ name string }{"authSourceKey"}, purser.AuthSourceMTLS)

	if got, ok := purser.AuthSourceFromContext(ctx); ok {
		t.Errorf("AuthSourceFromContext() = (%q, true) from a forged key, want not-found", got)
	}
}
