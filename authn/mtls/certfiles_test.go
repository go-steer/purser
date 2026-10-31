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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-steer/purser/authn/mtls"
	"github.com/go-steer/purser/internal/ca"
)

// podCertBundle lays out a credential the way a Kubernetes
// podCertificate projection's credentialBundlePath does: the key, then
// the chain.
func podCertBundle(tb testing.TB, cert tls.Certificate) []byte {
	tb.Helper()
	certPEM, keyPEM, err := ca.EncodePEM(cert)
	if err != nil {
		tb.Fatalf("encode: %v", err)
	}
	return append(keyPEM, certPEM...)
}

func writeFile(tb testing.TB, path string, content []byte) {
	tb.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		tb.Fatalf("write %s: %v", path, err)
	}
}

func parseLeaf(tb testing.TB, cert *tls.Certificate) *x509.Certificate {
	tb.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		tb.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

func TestCertificateFileSourceReadsAPodCertificateBundle(t *testing.T) {
	t.Parallel()
	authority := newCoreCA(t, "podidentity")
	want, err := authority.Issue(ca.LeafOptions{URISANs: []string{"spiffe://cluster.local/ns/a/sa/b"}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credential-bundle.pem")
	writeFile(t, path, podCertBundle(t, want))

	src, err := mtls.NewCertificateFileSource(mtls.CertificateFileOptions{
		CredentialBundlePath: path, ReloadInterval: -1,
	})
	if err != nil {
		t.Fatalf("NewCertificateFileSource: %v", err)
	}
	defer func() { _ = src.Close() }()

	for name, get := range map[string]func() (*tls.Certificate, error){
		"GetClientCertificate": func() (*tls.Certificate, error) { return src.GetClientCertificate(nil) },
		"GetCertificate":       func() (*tls.Certificate, error) { return src.GetCertificate(nil) },
	} {
		got, err := get()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got.Certificate[0], want.Certificate[0]) {
			t.Errorf("%s served a different leaf", name)
		}
		if got.Leaf == nil || got.Leaf.URIs[0].String() != "spiffe://cluster.local/ns/a/sa/b" {
			t.Errorf("%s: Leaf not populated from the bundle", name)
		}
	}
}

func TestCertificateFileSourceReadsACertAndKeyPair(t *testing.T) {
	t.Parallel()
	authority := newCoreCA(t, "pki")
	want, err := authority.IssueClient("alice")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.EncodePEM(want)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeFile(t, certPath, certPEM)
	writeFile(t, keyPath, keyPEM)

	src, err := mtls.NewCertificateFileSource(mtls.CertificateFileOptions{
		CertPath: certPath, KeyPath: keyPath, ReloadInterval: -1,
	})
	if err != nil {
		t.Fatalf("NewCertificateFileSource: %v", err)
	}
	defer func() { _ = src.Close() }()
	got, err := src.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if got.Leaf.Subject.CommonName != "alice" {
		t.Errorf("served CN %q, want alice", got.Leaf.Subject.CommonName)
	}
}

func TestCertificateFileSourceReloads(t *testing.T) {
	t.Parallel()
	authority := newCoreCA(t, "rotating")
	first, err := authority.IssueClient("first")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credential-bundle.pem")
	writeFile(t, path, podCertBundle(t, first))

	src, err := mtls.NewCertificateFileSource(mtls.CertificateFileOptions{
		CredentialBundlePath: path, ReloadInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCertificateFileSource: %v", err)
	}
	defer func() { _ = src.Close() }()

	second, err := authority.IssueClient("second")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, podCertBundle(t, second))
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := src.GetClientCertificate(nil)
		if err == nil && got.Leaf.Subject.CommonName == "second" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the rotated certificate was never served (last: %v, %v)", got, err)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCertificateFileSourceKeepsTheLastGoodCertificate(t *testing.T) {
	t.Parallel()
	authority := newCoreCA(t, "keep")
	good, err := authority.IssueClient("good")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credential-bundle.pem")
	writeFile(t, path, podCertBundle(t, good))

	var reported atomic.Int64
	src, err := mtls.NewCertificateFileSource(mtls.CertificateFileOptions{
		CredentialBundlePath: path,
		ReloadInterval:       5 * time.Millisecond,
		OnError:              func(error) { reported.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewCertificateFileSource: %v", err)
	}
	defer func() { _ = src.Close() }()

	// Half a bundle: the key and a truncated certificate block.
	torn := podCertBundle(t, good)
	writeFile(t, path, torn[:len(torn)-40])
	deadline := time.Now().Add(5 * time.Second)
	for reported.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a truncated bundle was accepted or never reported")
		}
		time.Sleep(time.Millisecond)
	}
	got, err := src.GetClientCertificate(nil)
	if err != nil || got.Leaf.Subject.CommonName != "good" {
		t.Fatalf("after a failed reload got %v, %v; want the last good certificate", got, err)
	}
}

func TestCertificateFileSourceRefusesAnExpiredCertificate(t *testing.T) {
	t.Parallel()
	authority := newCoreCA(t, "expiry")
	old, err := authority.Issue(ca.LeafOptions{
		CommonName: "old",
		NotBefore:  time.Now().Add(-2 * time.Hour),
		NotAfter:   time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credential-bundle.pem")
	writeFile(t, path, podCertBundle(t, old))
	src, err := mtls.NewCertificateFileSource(mtls.CertificateFileOptions{
		CredentialBundlePath: path, ReloadInterval: -1,
	})
	if err != nil {
		t.Fatalf("NewCertificateFileSource: %v", err)
	}
	defer func() { _ = src.Close() }()
	if _, err := src.GetClientCertificate(nil); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("GetClientCertificate = %v, want an expiry error", err)
	}
}

func TestCertificateFileSourceRejectsBadInput(t *testing.T) {
	t.Parallel()
	authority := newCoreCA(t, "bad")
	cert, err := authority.IssueClient("x")
	if err != nil {
		t.Fatal(err)
	}
	other, err := authority.IssueClient("y")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.EncodePEM(cert)
	if err != nil {
		t.Fatal(err)
	}
	_, otherKeyPEM, err := ca.EncodePEM(other)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bundle := func(name string, content []byte) string {
		p := filepath.Join(dir, name)
		writeFile(t, p, content)
		return p
	}
	certPath := bundle("tls.crt", certPEM)
	keyPath := bundle("tls.key", keyPEM)

	for _, tc := range []struct {
		name    string
		opts    mtls.CertificateFileOptions
		wantErr string
	}{
		{"nothing", mtls.CertificateFileOptions{}, "CertPath is required"},
		{"cert without key", mtls.CertificateFileOptions{CertPath: certPath}, "KeyPath is required"},
		{"both layouts", mtls.CertificateFileOptions{
			CredentialBundlePath: certPath, CertPath: certPath, KeyPath: keyPath,
		}, "mutually exclusive"},
		{"missing bundle", mtls.CertificateFileOptions{
			CredentialBundlePath: filepath.Join(dir, "absent"),
		}, "read credential bundle"},
		{"missing key", mtls.CertificateFileOptions{
			CertPath: certPath, KeyPath: filepath.Join(dir, "absent"),
		}, "read private key"},
		{"bundle without a key", mtls.CertificateFileOptions{
			CredentialBundlePath: bundle("nokey.pem", certPEM),
		}, "found 0 private keys"},
		{"bundle with two keys", mtls.CertificateFileOptions{
			CredentialBundlePath: bundle("twokeys.pem", append(append(keyPEM, otherKeyPEM...), certPEM...)),
		}, "found 2 private keys"},
		{"bundle without a certificate", mtls.CertificateFileOptions{
			CredentialBundlePath: bundle("nocert.pem", keyPEM),
		}, "no CERTIFICATE block"},
		{"bundle with a foreign block", mtls.CertificateFileOptions{
			CredentialBundlePath: bundle("foreign.pem",
				append(append(keyPEM, certPEM...), []byte("-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n")...)),
		}, "unexpected PEM block"},
		{"bundle with trailing bytes", mtls.CertificateFileOptions{
			CredentialBundlePath: bundle("trailing.pem", append(append(keyPEM, certPEM...), []byte("-----BEGIN CERT")...)),
		}, "trailing data"},
		{"mismatched key", mtls.CertificateFileOptions{
			CredentialBundlePath: bundle("mismatch.pem", append(otherKeyPEM, certPEM...)),
		}, "load certificate"},
		{"chain file with a foreign block", mtls.CertificateFileOptions{
			CertPath: bundle("chain-foreign.crt", append(certPEM, keyPEM...)), KeyPath: keyPath,
		}, "want only CERTIFICATE blocks"},
		{"garbled certificate", mtls.CertificateFileOptions{
			CertPath: bundle("garbled.crt", []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")),
			KeyPath:  keyPath,
		}, "parse certificate 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.ReloadInterval = -1
			src, err := mtls.NewCertificateFileSource(tc.opts)
			if err == nil {
				_ = src.Close()
				t.Fatalf("NewCertificateFileSource succeeded, want an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestCertificateFileSourceClosedZeroAndNil(t *testing.T) {
	t.Parallel()
	authority := newCoreCA(t, "close")
	cert, err := authority.IssueClient("x")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credential-bundle.pem")
	writeFile(t, path, podCertBundle(t, cert))
	src, err := mtls.NewCertificateFileSource(mtls.CertificateFileOptions{CredentialBundlePath: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := src.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := src.GetClientCertificate(nil); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("after Close = %v, want a closed error", err)
	}

	var zero mtls.CertificateFileSource
	if _, err := zero.GetCertificate(nil); err == nil || !strings.Contains(err.Error(), "NewCertificateFileSource") {
		t.Errorf("zero value = %v, want it to point at the constructor", err)
	}
	if err := zero.Close(); err != nil {
		t.Errorf("zero Close = %v", err)
	}
	var nilSrc *mtls.CertificateFileSource
	if _, err := nilSrc.GetClientCertificate(nil); err == nil {
		t.Error("nil source served a certificate")
	}
	if err := nilSrc.Close(); err != nil {
		t.Errorf("nil Close = %v", err)
	}
}

func TestCertPoolFileSource(t *testing.T) {
	t.Parallel()
	first := newCoreCA(t, "first")
	second := newCoreCA(t, "second")
	path := filepath.Join(t.TempDir(), "trust-bundle.pem")
	writeFile(t, path, first.CertPEM())

	var reported atomic.Int64
	src, err := mtls.NewCertPoolFileSource(mtls.CertPoolFileOptions{
		Path: path, ReloadInterval: 5 * time.Millisecond, OnError: func(error) { reported.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewCertPoolFileSource: %v", err)
	}
	defer func() { _ = src.Close() }()

	verifies := func(authority *ca.CA) bool {
		cert, err := authority.IssueServer("router.test")
		if err != nil {
			t.Fatal(err)
		}
		pool, err := src.CertPool()
		if err != nil {
			t.Fatalf("CertPool: %v", err)
		}
		_, err = parseLeaf(t, &cert).Verify(x509.VerifyOptions{Roots: pool, DNSName: "router.test"})
		return err == nil
	}
	if !verifies(first) || verifies(second) {
		t.Fatal("initial pool does not hold exactly the first authority")
	}

	// A returned pool is a copy: adding to it changes nothing for others.
	pool, _ := src.CertPool()
	pool.AddCert(second.Cert())
	if verifies(second) {
		t.Fatal("mutating a returned pool added a trust anchor for everyone")
	}

	// Rotation: both anchors, then only the new one.
	writeFile(t, path, append(first.CertPEM(), second.CertPEM()...))
	deadline := time.Now().Add(5 * time.Second)
	for !verifies(second) {
		if time.Now().After(deadline) {
			t.Fatal("the rotated bundle was never served")
		}
		time.Sleep(time.Millisecond)
	}

	// A bad rewrite keeps the last good pool.
	writeFile(t, path, []byte("not PEM at all"))
	for reported.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a garbage bundle was never reported")
		}
		time.Sleep(time.Millisecond)
	}
	if !verifies(first) || !verifies(second) {
		t.Fatal("a failed reload dropped the last good pool")
	}
}

func TestCertPoolFileSourceRejectsBadInput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	authority := newCoreCA(t, "x")
	cert, err := authority.IssueClient("x")
	if err != nil {
		t.Fatal(err)
	}
	_, keyPEM, err := ca.EncodePEM(cert)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		content []byte
		path    string
		wantErr string
	}{
		{name: "no path", wantErr: "Path is required"},
		{name: "missing", path: filepath.Join(dir, "absent"), wantErr: "read CA bundle"},
		{name: "empty", content: []byte("\n"), wantErr: "no CERTIFICATE block"},
		{name: "a key", content: keyPEM, wantErr: "want only CERTIFICATE blocks"},
		{name: "trailing", content: append(authority.CertPEM(), "-----BEGIN"...), wantErr: "trailing data"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.path
			if tc.content != nil {
				path = filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-"))
				writeFile(t, path, tc.content)
			}
			src, err := mtls.NewCertPoolFileSource(mtls.CertPoolFileOptions{Path: path, ReloadInterval: -1})
			if err == nil {
				_ = src.Close()
				t.Fatalf("NewCertPoolFileSource succeeded, want an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestCertPoolFileSourceClosedZeroAndNil(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "trust-bundle.pem")
	writeFile(t, path, newCoreCA(t, "x").CertPEM())
	src, err := mtls.NewCertPoolFileSource(mtls.CertPoolFileOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	_ = src.Close()
	if _, err := src.CertPool(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("after Close = %v, want a closed error", err)
	}
	var zero mtls.CertPoolFileSource
	if _, err := zero.CertPool(); err == nil || !strings.Contains(err.Error(), "NewCertPoolFileSource") {
		t.Errorf("zero value = %v, want it to point at the constructor", err)
	}
	var nilSrc *mtls.CertPoolFileSource
	if _, err := nilSrc.CertPool(); err == nil {
		t.Error("nil source served a pool")
	}
	if err := nilSrc.Close(); err != nil {
		t.Errorf("nil Close = %v", err)
	}
}

func TestSPIFFEFileSourceReadsAPodCertificateBundle(t *testing.T) {
	t.Parallel()
	authority := newCoreCA(t, "podidentity")
	td := trustDomain(t, "cluster.local")
	const id = "spiffe://cluster.local/ns/lookout/sa/lookout"
	cert, err := authority.Issue(ca.LeafOptions{URISANs: []string{id}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "credential-bundle.pem")
	anchorsPath := filepath.Join(dir, "trust-bundle.pem")
	writeFile(t, bundlePath, podCertBundle(t, cert))
	writeFile(t, anchorsPath, authority.CertPEM())

	src, err := mtls.NewSPIFFEFileSource(mtls.SPIFFEFileOptions{
		CredentialBundlePath: bundlePath,
		BundlePath:           anchorsPath,
		TrustDomain:          td,
		ReloadInterval:       -1,
	})
	if err != nil {
		t.Fatalf("NewSPIFFEFileSource: %v", err)
	}
	defer func() { _ = src.Close() }()
	svid, err := src.GetX509SVID()
	if err != nil {
		t.Fatalf("GetX509SVID: %v", err)
	}
	if svid.ID.String() != id {
		t.Errorf("SVID ID = %q, want %q", svid.ID, id)
	}

	// The bundle layout is exclusive with the two-file layout, and a
	// malformed bundle names the file.
	if _, err := mtls.NewSPIFFEFileSource(mtls.SPIFFEFileOptions{
		CredentialBundlePath: bundlePath, CertPath: bundlePath, KeyPath: bundlePath,
		BundlePath: anchorsPath, TrustDomain: td,
	}); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("both layouts = %v, want a mutual-exclusion error", err)
	}
	broken := filepath.Join(dir, "broken.pem")
	writeFile(t, broken, authority.CertPEM())
	if _, err := mtls.NewSPIFFEFileSource(mtls.SPIFFEFileOptions{
		CredentialBundlePath: broken, BundlePath: anchorsPath, TrustDomain: td, ReloadInterval: -1,
	}); err == nil || !strings.Contains(err.Error(), "broken.pem") {
		t.Errorf("key-less bundle = %v, want an error naming the file", err)
	}
	// A key that does not match the leaf is caught by x509svid.Parse.
	other, err := authority.Issue(ca.LeafOptions{URISANs: []string{id}})
	if err != nil {
		t.Fatal(err)
	}
	mismatched := filepath.Join(dir, "mismatched.pem")
	_, otherKey, _ := ca.EncodePEM(other)
	certOnly, _, _ := ca.EncodePEM(cert)
	writeFile(t, mismatched, append(otherKey, certOnly...))
	if _, err := mtls.NewSPIFFEFileSource(mtls.SPIFFEFileOptions{
		CredentialBundlePath: mismatched, BundlePath: anchorsPath, TrustDomain: td, ReloadInterval: -1,
	}); err == nil || !strings.Contains(err.Error(), "load X509-SVID from") {
		t.Errorf("mismatched bundle = %v, want a load error", err)
	}
}
