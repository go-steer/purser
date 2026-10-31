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

package client

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

// TestCertificateAllowedFIPS checks the mirror of crypto/tls's
// isCertificateAllowedFIPS key by key. FIPS mode cannot be switched on
// inside a running test binary, so the rule is exercised directly and
// the filter's pass-through is checked in whichever mode the binary
// runs.
func TestCertificateAllowedFIPS(t *testing.T) {
	t.Parallel()
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // the point is a too-small key
	if err != nil {
		t.Fatal(err)
	}
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		key  any
		want bool
	}{
		{"RSA 1024", &rsa1024.PublicKey, false},
		{"RSA 2048", &rsa2048.PublicKey, true},
		{"P-256", &p256.PublicKey, true},
		{"P-224", &p224.PublicKey, false},
		{"Ed25519", edPub, true},
		{"unknown", "not a key", false},
	} {
		if got := certificateAllowedFIPS(&x509.Certificate{PublicKey: tc.key}); got != tc.want {
			t.Errorf("%s: allowed = %v, want %v", tc.name, got, tc.want)
		}
	}

	chains := [][]*x509.Certificate{{{PublicKey: &p224.PublicKey}}}
	got, err := fipsAllowedChains(chains)
	if fips140.Enabled() {
		if err == nil {
			t.Errorf("FIPS mode kept a P-224 chain: %v", got)
		}
	} else if err != nil || len(got) != 1 {
		t.Errorf("outside FIPS mode the filter changed the chains: %v, %v", got, err)
	}
}

func TestFilterFIPSChains(t *testing.T) {
	t.Parallel()
	good, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ok := &x509.Certificate{PublicKey: &good.PublicKey}
	weak := &x509.Certificate{PublicKey: &bad.PublicKey}

	got, err := filterFIPSChains([][]*x509.Certificate{{ok, weak}, {ok, ok}, {}})
	if err != nil || len(got) != 1 || len(got[0]) != 2 || got[0][1] != ok {
		t.Fatalf("filter = %v, %v; want only the all-permitted chain", got, err)
	}
	if _, err := filterFIPSChains([][]*x509.Certificate{{weak}}); err == nil {
		t.Fatal("a chain with a non-FIPS key was kept")
	}
}
