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

package credentials

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/go-steer/purser/authn/mtls"
)

// loadLeaf reads and parses one identity's certificate.
func loadLeaf(t *testing.T, dir, certFile, keyFile string) *x509.Certificate {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, certFile), filepath.Join(dir, keyFile))
	if err != nil {
		t.Fatalf("load key pair from %s: %v", dir, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf from %s: %v", dir, err)
	}
	return leaf
}

// checkAnchors verifies the leaf against the anchors written beside it.
// A demo whose CA file does not actually vouch for the certificate next
// to it fails at handshake time with something far less obvious.
func checkAnchors(t *testing.T, leaf *x509.Certificate, anchorPath string) {
	t.Helper()
	pem, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatalf("read %s: %v", anchorPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("%s holds no PEM certificate", anchorPath)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("leaf does not chain to %s: %v", anchorPath, err)
	}
}

func checkPermissions(t *testing.T, dir string, files ...string) {
	t.Helper()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("%s mode = %o, want 700", dir, got)
	}
	for _, name := range files {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("%s mode = %o, want 600", path, got)
		}
	}
}

func TestMintPKI(t *testing.T) {
	dir := t.TempDir()
	set, err := MintPKI(PKIOptions{Dir: dir})
	if err != nil {
		t.Fatalf("MintPKI: %v", err)
	}

	if want := filepath.Join(dir, ServerDir); set.Server.Dir != want {
		t.Errorf("server dir = %q, want %q", set.Server.Dir, want)
	}
	if len(set.All()) != 3 {
		t.Fatalf("minted %d identities, want 3", len(set.All()))
	}

	for _, id := range set.All() {
		checkPermissions(t, id.Dir, PKICertFile, PKIKeyFile, PKICAFile)
		leaf := loadLeaf(t, id.Dir, PKICertFile, PKIKeyFile)
		checkAnchors(t, leaf, filepath.Join(id.Dir, PKICAFile))
	}

	// The server is dialled at 127.0.0.1, so the address has to be an IP
	// SAN. crypto/tls will not match it against a DNS name.
	server := loadLeaf(t, set.Server.Dir, PKICertFile, PKIKeyFile)
	if len(server.IPAddresses) != 1 || server.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("server IP SANs = %v, want [127.0.0.1]", server.IPAddresses)
	}
	if len(server.DNSNames) != 0 {
		t.Errorf("server DNS SANs = %v, want none for an IP host", server.DNSNames)
	}

	// The client's identity is its DNS SAN, which is what the san_dns
	// subject source reads.
	client := loadLeaf(t, set.Client.Dir, PKICertFile, PKIKeyFile)
	if !slices.Contains(client.DNSNames, set.Client.Subject) {
		t.Errorf("client DNS SANs = %v, want to contain %q", client.DNSNames, set.Client.Subject)
	}
	if !slices.Contains(client.Subject.OrganizationalUnit, "platform") {
		t.Errorf("client OUs = %v, want to contain platform", client.Subject.OrganizationalUnit)
	}

	// The third identity differs only in its OU. That is what makes the
	// rejection demonstration about the matcher and not about the CA.
	unauthorized := loadLeaf(t, set.Unauthorized.Dir, PKICertFile, PKIKeyFile)
	if !slices.Contains(unauthorized.Subject.OrganizationalUnit, "interns") {
		t.Errorf("unauthorized OUs = %v, want to contain interns", unauthorized.Subject.OrganizationalUnit)
	}
	if slices.Contains(unauthorized.Subject.OrganizationalUnit, "platform") {
		t.Error("the unauthorized certificate carries the admitted OU, so it would be admitted")
	}
}

func TestMintPKIWithANamedHost(t *testing.T) {
	set, err := MintPKI(PKIOptions{Dir: t.TempDir(), ServerHost: "hello-server.default.svc"})
	if err != nil {
		t.Fatalf("MintPKI: %v", err)
	}
	server := loadLeaf(t, set.Server.Dir, PKICertFile, PKIKeyFile)
	if !slices.Contains(server.DNSNames, "hello-server.default.svc") {
		t.Errorf("server DNS SANs = %v, want to contain the host", server.DNSNames)
	}
	if len(server.IPAddresses) != 0 {
		t.Errorf("server IP SANs = %v, want none for a named host", server.IPAddresses)
	}
}

func TestMintSPIFFE(t *testing.T) {
	set, err := MintSPIFFE(SPIFFEOptions{Dir: t.TempDir(), TrustDomain: "example.org"})
	if err != nil {
		t.Fatalf("MintSPIFFE: %v", err)
	}

	for _, id := range set.All() {
		// The GKE file names, so a -spiffe-dir pointed here is laid out
		// exactly like the managed workload identity mount.
		checkPermissions(t, id.Dir, mtls.GKECertFile, mtls.GKEKeyFile, mtls.GKEBundleFile)
		leaf := loadLeaf(t, id.Dir, mtls.GKECertFile, mtls.GKEKeyFile)
		checkAnchors(t, leaf, filepath.Join(id.Dir, mtls.GKEBundleFile))

		// An X509-SVID carries exactly one URI SAN and it is the ID.
		if len(leaf.URIs) != 1 {
			t.Fatalf("%s URI SANs = %v, want exactly one", id.Name, leaf.URIs)
		}
		if got := leaf.URIs[0].String(); got != id.Subject {
			t.Errorf("%s URI SAN = %q, want %q", id.Name, got, id.Subject)
		}
	}

	if got := set.Client.Subject; got != "spiffe://example.org/ns/default/sa/hello-client" {
		t.Errorf("client ID = %q, unexpected", got)
	}
	if set.Unauthorized.Subject == set.Client.Subject {
		t.Error("the unauthorized SVID shares the client's ID, so it would be admitted")
	}
}

func TestMintSPIFFEHonoursTheTrustDomain(t *testing.T) {
	set, err := MintSPIFFE(SPIFFEOptions{Dir: t.TempDir(), TrustDomain: "my-project.svc.id.goog"})
	if err != nil {
		t.Fatalf("MintSPIFFE: %v", err)
	}
	if want := "spiffe://my-project.svc.id.goog/ns/default/sa/hello-server"; set.Server.Subject != want {
		t.Errorf("server ID = %q, want %q", set.Server.Subject, want)
	}
}

func TestMintRejectsBadInput(t *testing.T) {
	if _, err := MintPKI(PKIOptions{}); err == nil {
		t.Error("MintPKI accepted an empty Dir")
	}
	if _, err := MintSPIFFE(SPIFFEOptions{}); err == nil {
		t.Error("MintSPIFFE accepted an empty Dir")
	}
	if _, err := MintSPIFFE(SPIFFEOptions{Dir: t.TempDir(), TrustDomain: "not a trust domain"}); err == nil {
		t.Error("MintSPIFFE accepted an invalid trust domain")
	}
	if _, err := MintSPIFFE(SPIFFEOptions{Dir: t.TempDir(), ServerPath: "no-leading-slash"}); err == nil {
		t.Error("MintSPIFFE accepted an invalid SVID path")
	}
}
