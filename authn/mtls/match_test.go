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

package mtls_test

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/go-steer/purser/authn/mtls"
	"github.com/go-steer/purser/authtest"
)

func TestCertMatchers(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	tests := []struct {
		name    string
		matcher mtls.CertMatcher
		leaf    authtest.LeafOptions
		admit   bool
	}{
		{
			name:    "issuer DN matches",
			matcher: mtls.MatchCertIssuerDN("CN=purser-test-ca"),
			admit:   true,
		},
		{
			name:    "issuer DN differs",
			matcher: mtls.MatchCertIssuerDN("CN=some-other-ca"),
		},
		{
			name:    "OU present among several",
			matcher: mtls.MatchCertOrganizationalUnit("Platform"),
			leaf:    authtest.LeafOptions{OrganizationalUnit: []string{"Support", "Platform"}},
			admit:   true,
		},
		{
			name:    "OU absent",
			matcher: mtls.MatchCertOrganizationalUnit("Platform"),
			leaf:    authtest.LeafOptions{OrganizationalUnit: []string{"Support"}},
		},
		{
			name:    "OU comparison is exact, not a prefix",
			matcher: mtls.MatchCertOrganizationalUnit("Platform"),
			leaf:    authtest.LeafOptions{OrganizationalUnit: []string{"Platform-Interns"}},
		},
		{
			name:    "organization present",
			matcher: mtls.MatchCertOrganization("Example"),
			leaf:    authtest.LeafOptions{Organization: []string{"Example"}},
			admit:   true,
		},
		{
			name:    "organization absent",
			matcher: mtls.MatchCertOrganization("Example"),
			leaf:    authtest.LeafOptions{Organization: []string{"Example Contractors"}},
		},
		{
			name:    "email SAN matches exactly",
			matcher: mtls.MatchCertEmailSAN("alice@example.com"),
			leaf:    authtest.LeafOptions{EmailSANs: []string{"bob@example.com", "alice@example.com"}},
			admit:   true,
		},
		{
			name:    "email SAN differs",
			matcher: mtls.MatchCertEmailSAN("alice@example.com"),
			leaf:    authtest.LeafOptions{EmailSANs: []string{"alice@example.com.evil.test"}},
		},
		{
			name:    "email domain matches",
			matcher: mtls.MatchCertEmailDomain("example.com"),
			leaf:    authtest.LeafOptions{EmailSANs: []string{"alice@example.com"}},
			admit:   true,
		},
		{
			name:    "email domain is compared case-insensitively",
			matcher: mtls.MatchCertEmailDomain("Example.COM"),
			leaf:    authtest.LeafOptions{EmailSANs: []string{"alice@EXAMPLE.com"}},
			admit:   true,
		},
		{
			// The anchoring case. A suffix test would admit this, and
			// the attacker only has to register notexample.com.
			name:    "email domain does not match a longer domain ending in it",
			matcher: mtls.MatchCertEmailDomain("example.com"),
			leaf:    authtest.LeafOptions{EmailSANs: []string{"alice@notexample.com"}},
		},
		{
			// Likewise: the domain must be the part after the last "@",
			// not anywhere in the address.
			name:    "email domain does not match when it appears in the local part",
			matcher: mtls.MatchCertEmailDomain("example.com"),
			leaf:    authtest.LeafOptions{EmailSANs: []string{"example.com@evil.test"}},
		},
		{
			name:    "email domain does not match a subdomain",
			matcher: mtls.MatchCertEmailDomain("example.com"),
			leaf:    authtest.LeafOptions{EmailSANs: []string{"alice@corp.example.com"}},
		},
		{
			name:    "email domain skips a SAN with no at sign",
			matcher: mtls.MatchCertEmailDomain("example.com"),
			leaf:    authtest.LeafOptions{EmailSANs: []string{"example.com"}},
		},
		{
			name:    "email domain with no email SANs",
			matcher: mtls.MatchCertEmailDomain("example.com"),
			leaf:    authtest.LeafOptions{CommonName: "alice"},
		},
		{
			// An unset configuration value must not become "admit
			// anyone", which a bare suffix test on "" would.
			name:    "empty email domain admits nobody",
			matcher: mtls.MatchCertEmailDomain(""),
			leaf:    authtest.LeafOptions{EmailSANs: []string{"alice@example.com"}},
		},
		{
			name:    "DNS SAN matches case-insensitively",
			matcher: mtls.MatchCertDNSSAN("api.prod.svc.cluster.local"),
			leaf:    authtest.LeafOptions{DNSSANs: []string{"API.Prod.SVC.cluster.local"}},
			admit:   true,
		},
		{
			name:    "DNS SAN differs",
			matcher: mtls.MatchCertDNSSAN("api.prod.svc.cluster.local"),
			leaf:    authtest.LeafOptions{DNSSANs: []string{"db.prod.svc.cluster.local"}},
		},
		{
			name:    "DNS suffix matches a subdomain",
			matcher: mtls.MatchCertDNSSuffix("svc.cluster.local"),
			leaf:    authtest.LeafOptions{DNSSANs: []string{"api.prod.svc.cluster.local"}},
			admit:   true,
		},
		{
			name:    "DNS suffix tolerates a leading dot in the configured domain",
			matcher: mtls.MatchCertDNSSuffix(".svc.cluster.local"),
			leaf:    authtest.LeafOptions{DNSSANs: []string{"api.svc.cluster.local"}},
			admit:   true,
		},
		{
			// The anchoring case again, on the DNS side.
			name:    "DNS suffix does not match across a label boundary",
			matcher: mtls.MatchCertDNSSuffix("svc.cluster.local"),
			leaf:    authtest.LeafOptions{DNSSANs: []string{"evil-svc.cluster.local"}},
		},
		{
			// The domain itself is not under itself. Admitting it would
			// hand a certificate minted for the apex the same access as
			// every workload beneath it.
			name:    "DNS suffix does not match the domain itself",
			matcher: mtls.MatchCertDNSSuffix("svc.cluster.local"),
			leaf:    authtest.LeafOptions{DNSSANs: []string{"svc.cluster.local"}},
		},
		{
			name:    "DNS suffix does not match a name the domain is a prefix of",
			matcher: mtls.MatchCertDNSSuffix("prod.example.com"),
			leaf:    authtest.LeafOptions{DNSSANs: []string{"prod.example.com.attacker.test"}},
		},
		{
			name:    "empty DNS domain admits nobody",
			matcher: mtls.MatchCertDNSSuffix(""),
			leaf:    authtest.LeafOptions{DNSSANs: []string{"api.svc.cluster.local", "trailing.dot."}},
		},
		{
			name: "all admits when every matcher admits",
			matcher: mtls.MatchCertAll(
				mtls.MatchCertOrganization("Example"),
				mtls.MatchCertEmailDomain("example.com"),
			),
			leaf: authtest.LeafOptions{
				Organization: []string{"Example"},
				EmailSANs:    []string{"alice@example.com"},
			},
			admit: true,
		},
		{
			name: "all rejects when one matcher rejects",
			matcher: mtls.MatchCertAll(
				mtls.MatchCertOrganization("Example"),
				mtls.MatchCertEmailDomain("example.com"),
			),
			leaf: authtest.LeafOptions{
				Organization: []string{"Example"},
				EmailSANs:    []string{"alice@evil.test"},
			},
		},
		{
			name:    "any admits when one matcher admits",
			matcher: mtls.MatchCertAnyOf(mtls.MatchCertOrganization("Nope"), mtls.MatchCertOrganization("Example")),
			leaf:    authtest.LeafOptions{Organization: []string{"Example"}},
			admit:   true,
		},
		{
			name:    "any rejects when no matcher admits",
			matcher: mtls.MatchCertAnyOf(mtls.MatchCertOrganization("Nope"), mtls.MatchCertOrganization("Neither")),
			leaf:    authtest.LeafOptions{Organization: []string{"Example"}},
		},
		{
			name:    "func adapts a predicate",
			matcher: mtls.MatchCertFunc(func(*x509.Certificate) error { return nil }),
			admit:   true,
		},
		{
			name:    "func rejection is propagated",
			matcher: mtls.MatchCertFunc(func(*x509.Certificate) error { return errors.New("no") }),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cert := ca.Issue(t, tt.leaf)

			err := tt.matcher(cert.Leaf)
			if tt.admit && err != nil {
				t.Errorf("matcher rejected an admissible peer: %v", err)
			}
			if !tt.admit && err == nil {
				t.Error("matcher admitted a peer it should have rejected")
			}
		})
	}
}

// TestEmptyMatcherAsymmetry pins the two empty cases against each other.
// They are opposites on purpose, and either one flipped is a security
// change that no other test would notice.
func TestEmptyMatcherAsymmetry(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	cert := ca.Issue(t, authtest.LeafOptions{CommonName: "anyone"})

	// An empty conjunction adds no constraint: building MatchCertAll
	// from a config list that happens to be empty must behave as if no
	// Admit matcher were configured at all.
	if err := mtls.MatchCertAll()(cert.Leaf); err != nil {
		t.Errorf("MatchCertAll() with no matchers rejected a peer: %v", err)
	}
	// An empty disjunction offers no way in: "admit a peer matching one
	// of these" with an empty list must not degrade into "admit
	// everyone", which is how an accidentally-empty allowlist opens a
	// server up.
	err := mtls.MatchCertAnyOf()(cert.Leaf)
	if err == nil {
		t.Fatal("MatchCertAnyOf() with no matchers admitted a peer")
	}
	if !strings.Contains(err.Error(), "no matcher configured") {
		t.Errorf("MatchCertAnyOf() error = %v, want it to name the empty configuration", err)
	}
}

// TestMatchCertAnyOfReportsEveryReason checks the operator-facing half:
// a handshake refused by a disjunction is opaque unless the error says
// what each alternative wanted, since the server's TLS error log is the
// only place the refusal appears.
func TestMatchCertAnyOfReportsEveryReason(t *testing.T) {
	t.Parallel()

	ca := authtest.NewCA(t, "purser-test-ca")
	cert := ca.Issue(t, authtest.LeafOptions{Organization: []string{"Example"}})
	m := mtls.MatchCertAnyOf(
		mtls.MatchCertOrganizationalUnit("Platform"),
		mtls.MatchCertEmailDomain("example.com"),
	)

	err := m(cert.Leaf)
	if err == nil {
		t.Fatal("matcher admitted a peer matching neither alternative")
	}
	for _, want := range []string{"Platform", "example.com"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention the %q alternative", err, want)
		}
	}
}
