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

// Package authtest provides the test harness every purser
// authenticator is held to: an in-memory certificate authority and a
// conformance suite.
//
// It exists because the properties that matter in authentication code
// are negative ones. A test that only asserts the happy path passes
// just as well against a check that never runs, so the interesting
// cases are the untrusted issuer, the expired certificate, the
// malformed token, the peer the authorizer should have rejected.
// Writing those once, here, is the reason purser is a shared module
// rather than four copies of the same package.
//
// Certificates are minted in-process. Nothing touches disk, no fixture
// keys live in the repository, and no test rots when a checked-in
// certificate expires.
//
// This package imports testing and is meant for use from tests.
package authtest

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/go-steer/purser/internal/ca"
)

// CA is an in-memory certificate authority. Use it to mint client and
// server certificates for handshake tests, and to build the trust pool
// a verifier is configured with.
//
// A test that needs an untrusted-issuer negative creates a second CA
// and offers its leaf to a verifier configured with the first CA's
// pool.
//
// Every method reports failure through testing.TB, because a CA that
// cannot mint is a broken test rather than a case under test. The
// error-returning form lives in the module's internal/ca package, for
// the examples, which mint credentials outside a test.
type CA struct {
	ca *ca.CA
}

// LeafOptions describes a certificate to mint. The zero value yields a
// client certificate valid from an hour ago until an hour from now,
// with no subject and no SANs — useful in itself, as the certificate
// that carries none of the fields an authenticator might read.
type LeafOptions = ca.LeafOptions

// NewCA returns a fresh self-signed authority named name. The name
// appears in the issuer DN, so give the trusted and untrusted
// authorities in a test distinguishable names: it is the difference
// between a legible failure and "x509: certificate signed by unknown
// authority".
func NewCA(tb testing.TB, name string) *CA {
	tb.Helper()
	inner, err := ca.New(name)
	if err != nil {
		tb.Fatalf("authtest: %v", err)
	}
	return &CA{ca: inner}
}

// Cert returns the authority's own certificate.
func (c *CA) Cert() *x509.Certificate { return c.ca.Cert() }

// Pool returns a certificate pool trusting only this authority. Each
// call returns a fresh pool, so a test may add to one without
// affecting another.
func (c *CA) Pool() *x509.CertPool { return c.ca.Pool() }

// Issue mints and signs a leaf certificate. The returned
// tls.Certificate carries the leaf's parsed form in its Leaf field and
// the issuing CA in its chain, so it can be presented directly by
// either side of a handshake.
func (c *CA) Issue(tb testing.TB, opts LeafOptions) tls.Certificate {
	tb.Helper()
	cert, err := c.ca.Issue(opts)
	if err != nil {
		tb.Fatalf("authtest: %v", err)
	}
	return cert
}

// IssueClient mints a client certificate whose subject CN is cn. A
// shorthand for the common case; reach for Issue when the test cares
// about SANs or validity.
func (c *CA) IssueClient(tb testing.TB, cn string) tls.Certificate {
	tb.Helper()
	return c.Issue(tb, LeafOptions{CommonName: cn})
}

// IssueServer mints a server certificate valid for host, which may be
// a DNS name or an IP literal.
func (c *CA) IssueServer(tb testing.TB, host string) tls.Certificate {
	tb.Helper()
	cert, err := c.ca.IssueServer(host)
	if err != nil {
		tb.Fatalf("authtest: %v", err)
	}
	return cert
}
