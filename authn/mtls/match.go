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

package mtls

import (
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// CertMatcher decides whether a verified peer certificate may open a
// connection. It returns nil to admit, or an error describing why not —
// the error reaches the server's TLS error log, which is the only place
// an operator can see why a handshake failed.
//
// It is the PKI profile's answer to go-spiffe's Authorizer: the
// standard library has no equivalent, so purser supplies the concept
// with the same composition vocabulary, and an operator learns one
// model for both profiles.
//
// A matcher is only ever called with a certificate whose chain has
// already been verified against the configured pool, so it may trust
// the contents it reads.
type CertMatcher func(*x509.Certificate) error

// MatchCertAll admits a peer only if every matcher admits it. With no
// matchers it admits everything, which makes it safe to build from a
// possibly-empty configuration list.
func MatchCertAll(matchers ...CertMatcher) CertMatcher {
	return func(cert *x509.Certificate) error {
		for _, m := range matchers {
			if err := m(cert); err != nil {
				return err
			}
		}
		return nil
	}
}

// MatchCertAnyOf admits a peer if any matcher admits it.
//
// With no matchers it admits *nothing*, the opposite of MatchCertAll's
// empty case. Both are the answer that keeps "unconstrained" from being
// spelled the same way as "no rules configured": an empty conjunction
// adds no constraint, while an empty disjunction offers no way in.
func MatchCertAnyOf(matchers ...CertMatcher) CertMatcher {
	return func(cert *x509.Certificate) error {
		if len(matchers) == 0 {
			return errors.New("no matcher configured to admit any peer")
		}
		errs := make([]error, 0, len(matchers))
		for _, m := range matchers {
			err := m(cert)
			if err == nil {
				return nil
			}
			errs = append(errs, err)
		}
		return fmt.Errorf("no alternative admitted the peer: %w", errors.Join(errs...))
	}
}

// MatchCertIssuerDN admits a peer whose certificate was issued by
// exactly this RFC 2253 distinguished name.
//
// Useful when the pool holds more than one authority and they are not
// equally privileged — an internal CA that issues to services and a
// second one that issues to contractors, say. Chain verification alone
// cannot tell them apart: any CA in the pool can vouch for any name.
func MatchCertIssuerDN(dn string) CertMatcher {
	return func(cert *x509.Certificate) error {
		if got := cert.Issuer.String(); got != dn {
			return fmt.Errorf("issuer DN %q is not %q", got, dn)
		}
		return nil
	}
}

// MatchCertOrganizationalUnit admits a peer whose subject carries this
// OU. A subject with several OUs matches if any of them is ou.
func MatchCertOrganizationalUnit(ou string) CertMatcher {
	return func(cert *x509.Certificate) error {
		if slices.Contains(cert.Subject.OrganizationalUnit, ou) {
			return nil
		}
		return fmt.Errorf("subject OUs %v do not include %q", cert.Subject.OrganizationalUnit, ou)
	}
}

// MatchCertOrganization admits a peer whose subject carries this O. A
// subject with several matches if any of them is o.
func MatchCertOrganization(o string) CertMatcher {
	return func(cert *x509.Certificate) error {
		if slices.Contains(cert.Subject.Organization, o) {
			return nil
		}
		return fmt.Errorf("subject organizations %v do not include %q", cert.Subject.Organization, o)
	}
}

// MatchCertEmailSAN admits a peer carrying this rfc822Name SAN,
// compared exactly. Use MatchCertEmailDomain to admit a whole domain.
func MatchCertEmailSAN(email string) CertMatcher {
	return func(cert *x509.Certificate) error {
		if slices.Contains(cert.EmailAddresses, email) {
			return nil
		}
		return fmt.Errorf("email SANs %v do not include %q", cert.EmailAddresses, email)
	}
}

// MatchCertEmailDomain admits a peer carrying an rfc822Name SAN in this
// domain, compared case-insensitively on the part after the last "@".
//
// It is anchored on that boundary rather than run as a suffix test.
// strings.HasSuffix(email, "example.com") also accepts
// "alice@notexample.com", and an attacker who can register that domain
// picks their own way in.
// An empty domain admits nobody rather than degenerating into a match
// on every address, so a matcher built from an unset configuration value
// closes the door instead of opening it.
func MatchCertEmailDomain(domain string) CertMatcher {
	want := strings.ToLower(domain)
	return func(cert *x509.Certificate) error {
		if want == "" {
			return errors.New("no email domain configured to admit any peer")
		}
		for _, email := range cert.EmailAddresses {
			at := strings.LastIndex(email, "@")
			if at < 0 {
				continue
			}
			if strings.EqualFold(email[at+1:], want) {
				return nil
			}
		}
		return fmt.Errorf("no email SAN in %v is in domain %q", cert.EmailAddresses, domain)
	}
}

// MatchCertDNSSAN admits a peer carrying this dNSName SAN, compared
// case-insensitively as DNS names are.
func MatchCertDNSSAN(name string) CertMatcher {
	return func(cert *x509.Certificate) error {
		for _, got := range cert.DNSNames {
			if strings.EqualFold(got, name) {
				return nil
			}
		}
		return fmt.Errorf("DNS SANs %v do not include %q", cert.DNSNames, name)
	}
}

// MatchCertDNSSuffix admits a peer carrying a dNSName SAN under this
// domain — "svc.cluster.local" admits "api.prod.svc.cluster.local" but
// not the domain itself and not "evil-svc.cluster.local".
//
// The comparison is anchored on a label boundary, for the same reason
// MatchCertEmailDomain is: a bare suffix test on an attacker-influenced
// name is how "prod.example.com" comes to admit
// "prod.example.com.attacker.net" or "notprod.example.com". An empty
// domain likewise admits nobody.
func MatchCertDNSSuffix(domain string) CertMatcher {
	trimmed := strings.ToLower(strings.TrimPrefix(domain, "."))
	want := "." + trimmed
	return func(cert *x509.Certificate) error {
		if trimmed == "" {
			return errors.New("no DNS domain configured to admit any peer")
		}
		for _, got := range cert.DNSNames {
			lower := strings.ToLower(got)
			if strings.HasSuffix(lower, want) && len(lower) > len(want) {
				return nil
			}
		}
		return fmt.Errorf("no DNS SAN in %v is under %q", cert.DNSNames, domain)
	}
}

// MatchCertFunc adapts an arbitrary predicate, for a policy the named
// matchers do not cover. Return nil to admit; the returned error is
// what the operator will see.
func MatchCertFunc(fn func(*x509.Certificate) error) CertMatcher { return fn }
