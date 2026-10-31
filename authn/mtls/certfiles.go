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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/go-steer/purser/internal/filereload"
)

// CertificateFileOptions configures NewCertificateFileSource.
type CertificateFileOptions struct {
	// CredentialBundlePath is a single PEM file holding a private key
	// and its certificate chain, leaf first. This is the
	// credentialBundlePath layout of a Kubernetes podCertificate
	// projected volume: one PKCS#8 "PRIVATE KEY" block followed by the
	// chain. The kubelet rewrites it in place as the certificate
	// rotates. Exactly one PRIVATE KEY (or EC or RSA PRIVATE KEY) block
	// and at least one CERTIFICATE block are required, and nothing
	// else may be in the file.
	//
	// Set either CredentialBundlePath, or CertPath and KeyPath.
	CredentialBundlePath string

	// CertPath and KeyPath are separate PEM files holding the chain
	// (leaf first) and its private key: the keyPath and
	// certificateChainPath layout of a podCertificate volume, or
	// tls.crt and tls.key of a cert-manager Secret.
	CertPath string
	KeyPath  string

	// ReloadInterval is how often the files are re-read. Zero means 30
	// seconds. A negative interval disables reloading, which is right
	// only when the files provably never change.
	ReloadInterval time.Duration

	// OnError is called when a reload fails and the previous
	// certificate is retained. It behaves exactly as
	// SPIFFEFileOptions.OnError: on a goroutine of the source's own,
	// serialised, panics recovered, and safe to call Close from.
	OnError func(error)
}

// CertificateFileSource serves a certificate and key from files on
// disk, re-reading them so that rotation needs no restart.
//
// It is the PKI profile's counterpart to SPIFFEFileSource. Its methods
// fit the certificate hooks of both profiles' option structs:
// GetCertificate for a listener (PKIOptions.GetCertificate) and
// GetClientCertificate for a dialer (client.PKIOptions).
//
// Nothing here requires the certificate to be an SVID, so it serves a
// standard-CA certificate as well as one from a SPIFFE-aware signer.
// A Kubernetes pod certificate issued by Agent Substrate's podidentity
// signer is both: its leaf carries a SPIFFE ID, but a client presenting
// it to a server whose own certificate is a plain DNS-SAN certificate
// dials with the PKI profile.
//
// Reads are double-checked for torn writes, a failed reload keeps the
// last good certificate, and a certificate that has expired is refused
// rather than presented. See SPIFFEFileSource for the reasoning behind
// each, which applies unchanged.
//
// The returned *tls.Certificate is shared with concurrent handshakes and
// must not be modified.
type CertificateFileSource struct {
	opts   CertificateFileOptions
	reload *filereload.Reloader[tls.Certificate]
}

// NewCertificateFileSource reads the certificate once and, unless
// reloading is disabled, starts a goroutine that re-reads it on an
// interval. The initial read is synchronous and its failure is the
// constructor's. Call Close to stop the reloader.
func NewCertificateFileSource(opts CertificateFileOptions) (*CertificateFileSource, error) {
	if err := validateCredentialPaths("CertificateFileOptions", opts.CredentialBundlePath,
		opts.CertPath, opts.KeyPath); err != nil {
		return nil, err
	}
	s := &CertificateFileSource{opts: opts}
	r, err := filereload.Start(s.load, opts.ReloadInterval, opts.OnError)
	if err != nil {
		return nil, err
	}
	s.reload = r
	return s, nil
}

// GetCertificate returns the current certificate, for a listener's
// PKIOptions.GetCertificate.
func (s *CertificateFileSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.certificate()
}

// GetClientCertificate returns the current certificate, for a dialer's
// client.PKIOptions.GetClientCertificate.
//
// It returns an error, which fails the handshake, rather than an empty
// certificate once the source is closed or its certificate has
// expired. crypto/tls would otherwise send no certificate and leave the
// server to reject the connection with a less useful alert.
func (s *CertificateFileSource) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return s.certificate()
}

// Close stops the reload goroutine; every later call to the getters
// fails. It is idempotent and has SPIFFEFileSource.Close's semantics.
func (s *CertificateFileSource) Close() error {
	if s == nil {
		return nil
	}
	return s.reload.Close()
}

func (s *CertificateFileSource) certificate() (*tls.Certificate, error) {
	if s == nil {
		return nil, errors.New("purser/mtls: CertificateFileSource is nil")
	}
	cert, err := s.reload.Current()
	switch {
	case errors.Is(err, filereload.ErrClosed):
		return nil, errors.New("purser/mtls: CertificateFileSource is closed")
	case err != nil:
		return nil, errors.New("purser/mtls: CertificateFileSource has loaded no certificate; " +
			"it must come from NewCertificateFileSource")
	}
	if notAfter := cert.Leaf.NotAfter; time.Now().After(notAfter) {
		return nil, fmt.Errorf("purser/mtls: CertificateFileSource: the certificate expired at %s "+
			"and has not been replaced; check %q and the OnError callback",
			notAfter.UTC().Format(time.RFC3339), s.source())
	}
	return cert, nil
}

// source names the file the certificate comes from, for messages.
func (s *CertificateFileSource) source() string {
	if s.opts.CredentialBundlePath != "" {
		return s.opts.CredentialBundlePath
	}
	return s.opts.CertPath
}

func (s *CertificateFileSource) load() (*tls.Certificate, error) {
	var certPEM, keyPEM []byte
	if s.opts.CredentialBundlePath != "" {
		got, err := filereload.ReadStable(filereload.File{
			Path: s.opts.CredentialBundlePath, What: "credential bundle",
		})
		if err != nil {
			return nil, fmt.Errorf("purser/mtls: %w", err)
		}
		if certPEM, keyPEM, err = splitCredentialBundle(got[0]); err != nil {
			return nil, fmt.Errorf("purser/mtls: credential bundle at %q: %w",
				s.opts.CredentialBundlePath, err)
		}
	} else {
		got, err := filereload.ReadStable(
			filereload.File{Path: s.opts.CertPath, What: "certificate chain"},
			filereload.File{Path: s.opts.KeyPath, What: "private key"},
		)
		if err != nil {
			return nil, fmt.Errorf("purser/mtls: %w", err)
		}
		certPEM, keyPEM = got[0], got[1]
		// The two-file layout gets the same check the bundle gets: a
		// chain file torn after its first certificate still parses.
		if _, err := pemCertificates(certPEM); err != nil {
			return nil, fmt.Errorf("purser/mtls: certificate chain at %q: %w", s.opts.CertPath, err)
		}
	}
	// X509KeyPair checks that the key matches the leaf, which catches a
	// rotation that replaced one file and not yet the other.
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("purser/mtls: load certificate from %q: %w", s.source(), err)
	}
	if cert.Leaf == nil {
		// Populated by X509KeyPair since Go 1.23; parsed here so the
		// expiry check never depends on that.
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, fmt.Errorf("purser/mtls: parse leaf from %q: %w", s.source(), err)
		}
	}
	return &cert, nil
}

// CertPoolFileOptions configures NewCertPoolFileSource.
type CertPoolFileOptions struct {
	// Path is a PEM file of CA certificates: a Kubernetes
	// clusterTrustBundle projection, a cert-manager ca.crt, or any
	// bundle a platform rewrites in place when an authority rotates.
	// Required. It must hold at least one CERTIFICATE block and
	// nothing else.
	Path string

	// ReloadInterval is how often the file is re-read. Zero means 30
	// seconds; negative disables reloading.
	ReloadInterval time.Duration

	// OnError is called when a reload fails and the previous pool is
	// retained, as SPIFFEFileOptions.OnError.
	OnError func(error)
}

// CertPoolFileSource serves a pool of trust anchors from a file on
// disk, re-reading it so that a CA rotation needs no restart.
//
// Its CertPool method is what client.PKIOptions.RootCAsSource asks for.
//
// A withdrawn authority stays trusted for as long as the file is
// unreadable: a failed reload keeps the last good pool, and there is
// no expiry to bound that, as SPIFFEFileSource's bundle half explains.
// OnError is the only signal, so alert on it.
type CertPoolFileSource struct {
	opts   CertPoolFileOptions
	reload *filereload.Reloader[x509.CertPool]
}

// NewCertPoolFileSource reads the pool once and, unless reloading is
// disabled, starts a goroutine that re-reads it on an interval. Call
// Close to stop the reloader.
func NewCertPoolFileSource(opts CertPoolFileOptions) (*CertPoolFileSource, error) {
	if opts.Path == "" {
		return nil, errors.New("purser/mtls: CertPoolFileOptions: Path is required")
	}
	s := &CertPoolFileSource{opts: opts}
	r, err := filereload.Start(s.load, opts.ReloadInterval, opts.OnError)
	if err != nil {
		return nil, err
	}
	s.reload = r
	return s, nil
}

// CertPool returns a copy of the current pool.
//
// It is cloned per call because x509.CertPool is mutable through
// AddCert and AppendCertsFromPEM: handing out the live pool would let
// any holder add a trust anchor for every concurrent handshake in the
// process.
func (s *CertPoolFileSource) CertPool() (*x509.CertPool, error) {
	if s == nil {
		return nil, errors.New("purser/mtls: CertPoolFileSource is nil")
	}
	pool, err := s.reload.Current()
	switch {
	case errors.Is(err, filereload.ErrClosed):
		return nil, errors.New("purser/mtls: CertPoolFileSource is closed")
	case err != nil:
		return nil, errors.New("purser/mtls: CertPoolFileSource has loaded no pool; " +
			"it must come from NewCertPoolFileSource")
	}
	return pool.Clone(), nil
}

// Close stops the reload goroutine; every later CertPool call fails. It
// is idempotent and has SPIFFEFileSource.Close's semantics.
func (s *CertPoolFileSource) Close() error {
	if s == nil {
		return nil
	}
	return s.reload.Close()
}

func (s *CertPoolFileSource) load() (*x509.CertPool, error) {
	got, err := filereload.ReadStable(filereload.File{Path: s.opts.Path, What: "CA bundle"})
	if err != nil {
		return nil, fmt.Errorf("purser/mtls: %w", err)
	}
	certs, err := pemCertificates(got[0])
	if err != nil {
		return nil, fmt.Errorf("purser/mtls: CA bundle at %q: %w", s.opts.Path, err)
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, nil
}

// validateCredentialPaths checks that exactly one of the two credential
// layouts is configured.
func validateCredentialPaths(kind, bundlePath, certPath, keyPath string) error {
	if bundlePath != "" {
		if certPath != "" || keyPath != "" {
			return fmt.Errorf("purser/mtls: %s: CredentialBundlePath is mutually exclusive "+
				"with CertPath and KeyPath", kind)
		}
		return nil
	}
	switch {
	case certPath == "":
		return fmt.Errorf("purser/mtls: %s: CertPath is required, or CredentialBundlePath", kind)
	case keyPath == "":
		return fmt.Errorf("purser/mtls: %s: KeyPath is required", kind)
	}
	return nil
}

// isPrivateKeyBlock reports whether a PEM block type holds a private
// key in one of the encodings tls.X509KeyPair accepts.
func isPrivateKeyBlock(blockType string) bool {
	switch blockType {
	case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY":
		return true
	}
	return false
}

// splitCredentialBundle separates a podCertificate credential bundle
// into its certificate chain and its private key, each re-encoded as
// PEM.
//
// It is strict on purpose. Exactly one key and at least one
// certificate, no other block types, and nothing after the last
// complete block: encoding/pem stops quietly at a partial block, so
// trailing bytes are how a bundle torn mid-rewrite shows itself, on top
// of the double read that already guards against one.
func splitCredentialBundle(data []byte) (certPEM, keyPEM []byte, err error) {
	var certs, keys int
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case block.Type == "CERTIFICATE":
			certs++
			certPEM = append(certPEM, pem.EncodeToMemory(block)...)
		case isPrivateKeyBlock(block.Type):
			keys++
			keyPEM = pem.EncodeToMemory(block)
		default:
			return nil, nil, fmt.Errorf("unexpected PEM block %q; a credential bundle holds "+
				"one private key and its certificate chain", block.Type)
		}
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("trailing data after the last complete PEM block; " +
			"the file may be mid-rewrite")
	}
	switch {
	case keys != 1:
		return nil, nil, fmt.Errorf("found %d private keys, want exactly 1", keys)
	case certs == 0:
		return nil, nil, errors.New("found no CERTIFICATE block")
	}
	return certPEM, keyPEM, nil
}

// pemCertificates parses every block of a PEM file as a certificate,
// refusing other block types, trailing partial blocks, and an empty
// file, for the same reasons as splitCredentialBundle.
func pemCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q; want only CERTIFICATE blocks", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %d: %w", len(certs)+1, err)
		}
		certs = append(certs, c)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("trailing data after the last complete PEM block; " +
			"the file may be mid-rewrite")
	}
	if len(certs) == 0 {
		return nil, errors.New("found no CERTIFICATE block")
	}
	return certs, nil
}
