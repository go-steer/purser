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

// Package credentials mints the throwaway certificates the local
// examples run on.
//
// It stands in for the thing a real deployment already has: an internal
// CA under the PKI profile, a SPIFFE issuer under the SPIFFE one.
// Neither is something purser provides — cert-manager and SPIRE do
// that, and the Kubernetes manifests under examples/k8s use them. This
// exists so the local cells need no infrastructure at all.
//
// Three identities are minted, not two. The third is the one that must
// be turned away: under the PKI profile it carries a different
// organizational unit, under the SPIFFE profile a different SPIFFE ID.
// A demonstration where every credential works shows only that TLS is
// on.
//
// Everything it writes is disposable and expires in an hour. Nothing
// here belongs anywhere near a real deployment, and nothing it writes
// should be committed.
package credentials

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/go-steer/purser/authn/mtls"
	"github.com/go-steer/purser/internal/ca"
)

// Names of the per-identity directories written under Dir.
const (
	ServerDir       = "server"
	ClientDir       = "client"
	UnauthorizedDir = "unauthorized"
)

// File names under the PKI profile. The SPIFFE profile instead uses
// mtls.GKECertFile, mtls.GKEKeyFile and mtls.GKEBundleFile, so a
// -spiffe-dir pointed at one of these directories is laid out exactly
// like GKE's managed workload identity mount.
const (
	PKICertFile = "cert.pem"
	PKIKeyFile  = "key.pem"
	PKICAFile   = "ca.pem"
)

// Identity is one minted credential and where it landed.
type Identity struct {
	// Name is the directory under Dir: ServerDir, ClientDir or
	// UnauthorizedDir.
	Name string
	// Dir is the absolute directory holding the three PEM files.
	Dir string
	// Subject is the identity a purser server will report for a peer
	// presenting this credential — the DNS SAN under the PKI profile,
	// the SPIFFE ID under the SPIFFE one.
	Subject string
}

// Set is the result of a mint: the three identities, in a fixed order.
type Set struct {
	Server       Identity
	Client       Identity
	Unauthorized Identity
}

// All returns the identities in server, client, unauthorized order.
func (s Set) All() []Identity { return []Identity{s.Server, s.Client, s.Unauthorized} }

// PKIOptions configures MintPKI. Zero fields take the defaults named
// in each comment.
type PKIOptions struct {
	// Dir is the directory to write into. Required.
	Dir string
	// ServerHost is the host the server certificate is valid for. An
	// IP lands in an IP SAN, a name in a DNS SAN. Default "127.0.0.1".
	ServerHost string
	// ClientName is the DNS SAN on the client certificate, which the
	// san_dns subject source reads as the identity. Default
	// "hello-client.local".
	ClientName string
	// ClientOU is the organizational unit on the client certificate,
	// for -pki-admit-ou. Default "platform".
	ClientOU string
	// UnauthorizedOU is the organizational unit on the third
	// certificate, the one -pki-admit-ou must reject. Default
	// "interns".
	UnauthorizedOU string
}

func (o *PKIOptions) applyDefaults() {
	if o.ServerHost == "" {
		o.ServerHost = "127.0.0.1"
	}
	if o.ClientName == "" {
		o.ClientName = "hello-client.local"
	}
	if o.ClientOU == "" {
		o.ClientOU = "platform"
	}
	if o.UnauthorizedOU == "" {
		o.UnauthorizedOU = "interns"
	}
}

// MintPKI writes a CA and three standard-CA certificates under
// opts.Dir.
func MintPKI(opts PKIOptions) (Set, error) {
	opts.applyDefaults()
	if opts.Dir == "" {
		return Set{}, fmt.Errorf("credentials: Dir is required")
	}

	authority, err := ca.New("purser examples")
	if err != nil {
		return Set{}, fmt.Errorf("create CA: %w", err)
	}

	leaves := []struct {
		name    string
		subject string
		opts    ca.LeafOptions
	}{
		{
			name:    ServerDir,
			subject: opts.ServerHost,
			opts: ca.LeafOptions{
				CommonName: "hello-server",
				DNSSANs:    dnsSANs(opts.ServerHost),
				IPSANs:     ipSANs(opts.ServerHost),
				// Both usages: the server also presents this certificate
				// when an example has it call onwards.
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			},
		},
		{
			name:    ClientDir,
			subject: opts.ClientName,
			opts: ca.LeafOptions{
				CommonName:         "hello-client",
				OrganizationalUnit: []string{opts.ClientOU},
				DNSSANs:            []string{opts.ClientName},
			},
		},
		{
			name:    UnauthorizedDir,
			subject: "unauthorized." + opts.ClientName,
			opts: ca.LeafOptions{
				CommonName:         "unauthorized-client",
				OrganizationalUnit: []string{opts.UnauthorizedOU},
				DNSSANs:            []string{"unauthorized." + opts.ClientName},
			},
		},
	}

	var set Set
	for _, leaf := range leaves {
		cert, err := authority.Issue(leaf.opts)
		if err != nil {
			return Set{}, fmt.Errorf("issue %s certificate: %w", leaf.name, err)
		}
		dir := filepath.Join(opts.Dir, leaf.name)
		if err := writeIdentity(dir, cert, authority.CertPEM(), PKICertFile, PKIKeyFile, PKICAFile); err != nil {
			return Set{}, err
		}
		set.set(leaf.name, Identity{Name: leaf.name, Dir: dir, Subject: leaf.subject})
	}
	return set, nil
}

// SPIFFEOptions configures MintSPIFFE. Zero fields take the defaults
// named in each comment.
type SPIFFEOptions struct {
	// Dir is the directory to write into. Required.
	Dir string
	// TrustDomain is the domain to mint SVIDs in. Default
	// "example.org".
	TrustDomain string
	// ServerPath, ClientPath and UnauthorizedPath are the SVID paths.
	// Defaults "/ns/default/sa/hello-server", ".../hello-client" and
	// ".../intruder".
	ServerPath       string
	ClientPath       string
	UnauthorizedPath string
}

func (o *SPIFFEOptions) applyDefaults() {
	if o.TrustDomain == "" {
		o.TrustDomain = "example.org"
	}
	if o.ServerPath == "" {
		o.ServerPath = "/ns/default/sa/hello-server"
	}
	if o.ClientPath == "" {
		o.ClientPath = "/ns/default/sa/hello-client"
	}
	if o.UnauthorizedPath == "" {
		o.UnauthorizedPath = "/ns/default/sa/intruder"
	}
}

// MintSPIFFE writes a CA and three X509-SVIDs under opts.Dir, each
// directory laid out like GKE's managed workload identity mount.
func MintSPIFFE(opts SPIFFEOptions) (Set, error) {
	opts.applyDefaults()
	if opts.Dir == "" {
		return Set{}, fmt.Errorf("credentials: Dir is required")
	}
	td, err := spiffeid.TrustDomainFromString(opts.TrustDomain)
	if err != nil {
		return Set{}, fmt.Errorf("trust domain %q: %w", opts.TrustDomain, err)
	}

	authority, err := ca.New("purser examples")
	if err != nil {
		return Set{}, fmt.Errorf("create CA: %w", err)
	}

	leaves := []struct{ name, path string }{
		{ServerDir, opts.ServerPath},
		{ClientDir, opts.ClientPath},
		{UnauthorizedDir, opts.UnauthorizedPath},
	}

	var set Set
	for _, leaf := range leaves {
		id, err := spiffeid.FromPath(td, leaf.path)
		if err != nil {
			return Set{}, fmt.Errorf("%s SVID path %q: %w", leaf.name, leaf.path, err)
		}
		// An X509-SVID is an ordinary leaf whose sole URI SAN is a
		// spiffe:// ID. Both EKUs because every workload here is both a
		// server and a client, which is what SPIRE issues too.
		svid, err := authority.Issue(ca.LeafOptions{
			CommonName:  leaf.name,
			URISANs:     []string{id.String()},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			return Set{}, fmt.Errorf("issue %s SVID: %w", leaf.name, err)
		}
		dir := filepath.Join(opts.Dir, leaf.name)
		if err := writeIdentity(dir, svid, authority.CertPEM(),
			mtls.GKECertFile, mtls.GKEKeyFile, mtls.GKEBundleFile); err != nil {
			return Set{}, err
		}
		set.set(leaf.name, Identity{Name: leaf.name, Dir: dir, Subject: id.String()})
	}
	return set, nil
}

func (s *Set) set(name string, id Identity) {
	switch name {
	case ServerDir:
		s.Server = id
	case ClientDir:
		s.Client = id
	case UnauthorizedDir:
		s.Unauthorized = id
	}
}

// writeIdentity writes one identity's certificate, key and trust
// anchors into its own directory.
func writeIdentity(dir string, cert tls.Certificate, anchors []byte, certName, keyName, caName string) error {
	certPEM, keyPEM, err := ca.EncodePEM(cert)
	if err != nil {
		return fmt.Errorf("encode %s: %w", dir, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	files := []struct {
		name string
		data []byte
	}{
		{certName, certPEM},
		{keyName, keyPEM},
		{caName, anchors},
	}
	for _, f := range files {
		// 0600 throughout. Only the key strictly needs it, but a demo
		// that writes a private key beside a world-readable certificate
		// invites the reader to copy the looser line.
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", filepath.Join(dir, f.name), err)
		}
	}
	return nil
}

// dnsSANs returns host as a DNS SAN, or nothing if it is an IP.
func dnsSANs(host string) []string {
	if net.ParseIP(host) != nil {
		return nil
	}
	return []string{host}
}

// ipSANs returns host as an IP SAN, or nothing if it is a name.
//
// The split matters: crypto/tls matches a dialled IP against IP SANs
// only, so a certificate carrying "127.0.0.1" as a DNS name fails a
// dial to 127.0.0.1 with a complaint about missing IP SANs.
func ipSANs(host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	return nil
}
