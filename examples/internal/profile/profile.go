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

// Package profile turns example command-line flags into the matched
// pair purser hands out: a *tls.Config and, on the server side, the
// authenticator that understands the connections it admits.
//
// Both mTLS profiles are wired here, in one place, so the difference
// between them is a diff rather than two files a reader has to hold in
// their head at once. The server and client binaries are then identical
// across profiles: they take a config, listen or dial, and never learn
// which profile they are running.
//
// Nothing here is part of purser's exported API.
package profile

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/go-steer/purser/authn"
	"github.com/go-steer/purser/authn/mtls"
	"github.com/go-steer/purser/client"
)

// Profile names an mTLS profile.
const (
	PKI    = "pki"
	SPIFFE = "spiffe"
)

// Role is which end of the connection the flags are being registered
// for. The two ends take different flags — a server has an identity
// source to read callers from, a client has a server to authorize —
// and registering only what applies keeps a flag that silently does
// nothing off the help text.
type Role int

// The two roles.
const (
	RoleServer Role = iota
	RoleClient
)

// ALPN is what both ends offer. Set explicitly rather than left to
// crypto/tls so the examples negotiate HTTP/2, which is what a
// service-to-service caller wants and what client.Transport exists to
// preserve.
var ALPN = []string{"h2", "http/1.1"}

// Flags is the credential configuration shared by the example server
// and client.
type Flags struct {
	role Role

	// Profile selects the mTLS profile: PKI or SPIFFE.
	Profile string

	// PKI profile.
	PKICert    string
	PKIKey     string
	PKIPeerCA  string
	PKISubject string
	PKIAdmitOU string

	// SPIFFE profile.
	SPIFFEDir         string
	SPIFFETrustDomain string
	SPIFFEReload      time.Duration
	SPIFFEIDs         stringList
	SPIFFEGKE         stringList
}

// Register declares the flags for role on fs.
func (f *Flags) Register(fs *flag.FlagSet, role Role) {
	f.role = role

	fs.StringVar(&f.Profile, "profile", PKI,
		"mTLS profile: pki (standard CA) or spiffe (X509-SVIDs)")

	fs.StringVar(&f.PKICert, "pki-cert", "",
		"pki: PEM file holding this process's certificate chain")
	fs.StringVar(&f.PKIKey, "pki-key", "",
		"pki: PEM file holding the matching private key")
	fs.StringVar(&f.PKIPeerCA, "pki-peer-ca", "",
		"pki: PEM file of the authorities the peer's certificate must chain to")
	fs.StringVar(&f.PKIAdmitOU, "pki-admit-ou", "",
		"pki: admit only peers whose certificate carries this organizational unit (optional)")

	fs.StringVar(&f.SPIFFEDir, "spiffe-dir", "",
		"spiffe: directory holding "+mtls.GKECertFile+", "+mtls.GKEKeyFile+" and "+
			mtls.GKEBundleFile+"; empty means GKE's managed workload identity mount")
	fs.StringVar(&f.SPIFFETrustDomain, "spiffe-trust-domain", "",
		"spiffe: the trust domain the anchors vouch for, e.g. example.org")
	fs.DurationVar(&f.SPIFFEReload, "spiffe-reload", 0,
		"spiffe: how often to re-read the credential files; 0 means 30s, negative disables reloading")

	switch role {
	case RoleServer:
		fs.StringVar(&f.PKISubject, "pki-subject", string(mtls.SubjectDNSSAN),
			"pki: certificate field the caller's identity is read from "+
				"(san_dns, san_email, san_uri, subject_cn, subject_dn)")
		fs.Var(&f.SPIFFEIDs, "spiffe-admit-id",
			"spiffe: admit this SPIFFE ID; repeatable; empty admits any SVID in the bundle")
		fs.Var(&f.SPIFFEGKE, "spiffe-admit-gke",
			"spiffe: admit this GKE workload as PROJECT/NAMESPACE/SERVICEACCOUNT; repeatable")
	case RoleClient:
		fs.Var(&f.SPIFFEIDs, "spiffe-authorize-id",
			"spiffe: talk only to this server SPIFFE ID; repeatable; required with -spiffe-authorize-gke")
		fs.Var(&f.SPIFFEGKE, "spiffe-authorize-gke",
			"spiffe: talk only to this GKE workload, as PROJECT/NAMESPACE/SERVICEACCOUNT; repeatable")
	}
}

// Closer releases whatever the config holds open — a reloading
// credential source, in the SPIFFE case. Never nil.
type Closer func() error

// Server builds the listener config and the authenticator that reads
// callers off the connections it admits.
//
// The two are returned together because purser returns them together:
// the profiles verify with opposite crypto/tls idioms, and an
// authenticator paired with the wrong listener reads the wrong field.
func (f *Flags) Server(log *slog.Logger) (*tls.Config, authn.Authenticator, Closer, error) {
	switch f.Profile {
	case PKI:
		cfg, auth, err := f.serverPKI()
		return cfg, auth, noopCloser, err
	case SPIFFE:
		return f.serverSPIFFE(log)
	default:
		return nil, nil, noopCloser, fmt.Errorf("unknown -profile %q, want %q or %q", f.Profile, PKI, SPIFFE)
	}
}

// Client builds the dialling config.
//
// There is no authenticator half here: a client verifies the server
// during the handshake and has no inbound request to name.
func (f *Flags) Client(log *slog.Logger) (*tls.Config, Closer, error) {
	switch f.Profile {
	case PKI:
		cfg, err := f.clientPKI()
		return cfg, noopCloser, err
	case SPIFFE:
		return f.clientSPIFFE(log)
	default:
		return nil, noopCloser, fmt.Errorf("unknown -profile %q, want %q or %q", f.Profile, PKI, SPIFFE)
	}
}

func (f *Flags) serverPKI() (*tls.Config, *mtls.PKIAuth, error) {
	cert, pool, err := f.pkiMaterial()
	if err != nil {
		return nil, nil, err
	}
	subject := mtls.SubjectSource(f.PKISubject)
	if !subject.Known() {
		return nil, nil, fmt.Errorf("unknown -pki-subject %q", f.PKISubject)
	}
	return mtls.NewPKI(mtls.PKIOptions{
		Certificate: &cert,
		ClientCAs:   pool,
		Subject:     subject,
		Admit:       f.pkiAdmit(),
		NextProtos:  ALPN,
	})
}

func (f *Flags) clientPKI() (*tls.Config, error) {
	cert, pool, err := f.pkiMaterial()
	if err != nil {
		return nil, err
	}
	return client.NewPKI(client.PKIOptions{
		Certificate: &cert,
		RootCAs:     pool,
		Admit:       f.pkiAdmit(),
		NextProtos:  ALPN,
	})
}

// pkiMaterial loads this process's own certificate and the pool its
// peer must chain to.
func (f *Flags) pkiMaterial() (tls.Certificate, *x509.CertPool, error) {
	var missing []string
	for name, v := range map[string]string{
		"-pki-cert":    f.PKICert,
		"-pki-key":     f.PKIKey,
		"-pki-peer-ca": f.PKIPeerCA,
	} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing) // map order is random; the error text should not be
		return tls.Certificate{}, nil, fmt.Errorf("-profile %s needs %s", PKI, strings.Join(missing, ", "))
	}

	cert, err := tls.LoadX509KeyPair(f.PKICert, f.PKIKey)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("load certificate: %w", err)
	}
	pem, err := os.ReadFile(f.PKIPeerCA)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("read -pki-peer-ca: %w", err)
	}
	// A fresh pool, never x509.SystemCertPool: the peer of an internal
	// service chains to the internal CA, and starting from the system
	// roots would admit every CA a browser trusts.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return tls.Certificate{}, nil, fmt.Errorf("read -pki-peer-ca: %s holds no PEM certificate", f.PKIPeerCA)
	}
	return cert, pool, nil
}

// pkiAdmit is the optional Layer A check. Nil admits every peer whose
// chain verifies, which is a real policy when the pool holds only an
// authority that issues to permitted callers — and the wrong one the
// moment it holds a CA that issues broadly.
func (f *Flags) pkiAdmit() mtls.CertMatcher {
	if f.PKIAdmitOU == "" {
		return nil
	}
	return mtls.MatchCertOrganizationalUnit(f.PKIAdmitOU)
}

func (f *Flags) serverSPIFFE(log *slog.Logger) (*tls.Config, authn.Authenticator, Closer, error) {
	src, err := f.spiffeSource(log)
	if err != nil {
		return nil, nil, noopCloser, err
	}
	admit, err := f.spiffeMatcher()
	if err != nil {
		_ = src.Close()
		return nil, nil, noopCloser, err
	}
	cfg, auth, err := mtls.NewSPIFFE(mtls.SPIFFEOptions{
		SVIDSource:   src,
		BundleSource: src,
		Admit:        admit,
		NextProtos:   ALPN,
	})
	if err != nil {
		_ = src.Close()
		return nil, nil, noopCloser, err
	}
	return cfg, auth, src.Close, nil
}

func (f *Flags) clientSPIFFE(log *slog.Logger) (*tls.Config, Closer, error) {
	src, err := f.spiffeSource(log)
	if err != nil {
		return nil, noopCloser, err
	}
	authorize, err := f.spiffeMatcher()
	if err != nil {
		_ = src.Close()
		return nil, noopCloser, err
	}
	if authorize == nil {
		_ = src.Close()
		return nil, noopCloser, errors.New(
			"-profile spiffe needs -spiffe-authorize-id or -spiffe-authorize-gke: " +
				"a client dials one known service, so it must name it")
	}
	cfg, err := client.NewSPIFFE(client.SPIFFEOptions{
		SVIDSource:   src,
		BundleSource: src,
		Authorize:    authorize,
		NextProtos:   ALPN,
	})
	if err != nil {
		_ = src.Close()
		return nil, noopCloser, err
	}
	return cfg, src.Close, nil
}

// spiffeSource opens the file-backed credential source both ends use.
//
// The examples read SVIDs from files rather than from the SPIFFE
// Workload API because that is what GKE's managed workload identity
// offers — it exposes no agent socket — and because one code path
// serving local, plain-Kubernetes and GKE keeps the three cells
// comparable. Where an agent socket does exist, a
// *workloadapi.X509Source drops into the same two fields.
func (f *Flags) spiffeSource(log *slog.Logger) (*mtls.SPIFFEFileSource, error) {
	if f.SPIFFETrustDomain == "" {
		return nil, fmt.Errorf("-profile %s needs -spiffe-trust-domain", SPIFFE)
	}
	td, err := spiffeid.TrustDomainFromString(f.SPIFFETrustDomain)
	if err != nil {
		return nil, fmt.Errorf("-spiffe-trust-domain: %w", err)
	}

	opts := mtls.GKEFileOptions(td)
	if f.SPIFFEDir != "" {
		opts.CertPath = filepath.Join(f.SPIFFEDir, mtls.GKECertFile)
		opts.KeyPath = filepath.Join(f.SPIFFEDir, mtls.GKEKeyFile)
		opts.BundlePath = filepath.Join(f.SPIFFEDir, mtls.GKEBundleFile)
	}
	opts.ReloadInterval = f.SPIFFEReload
	// A deployment that sets nothing here learns its credentials stopped
	// refreshing only when they expire and every handshake starts
	// failing. Alert on this line in a real service.
	opts.OnError = func(err error) {
		log.Error("SPIFFE credential reload failed; still serving the last good one", "err", err)
	}

	return mtls.NewSPIFFEFileSource(opts)
}

// spiffeMatcher builds the admission (server) or authorization (client)
// matcher from the repeated ID flags. Nil means none was given.
func (f *Flags) spiffeMatcher() (spiffeid.Matcher, error) {
	var matchers []spiffeid.Matcher

	for _, s := range f.SPIFFEIDs {
		id, err := spiffeid.FromString(s)
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", f.idFlagName(), s, err)
		}
		matchers = append(matchers, spiffeid.MatchID(id))
	}
	for _, s := range f.SPIFFEGKE {
		parts := strings.Split(s, "/")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return nil, fmt.Errorf("%s %q: want PROJECT/NAMESPACE/SERVICEACCOUNT", f.gkeFlagName(), s)
		}
		matchers = append(matchers, mtls.MatchGKEWorkload(parts[0], parts[1], parts[2]))
	}

	switch len(matchers) {
	case 0:
		return nil, nil
	case 1:
		return matchers[0], nil
	default:
		// Several named peers are alternatives, not conjuncts: MatchAll
		// of two distinct IDs admits nobody.
		return mtls.MatchAnyOf(matchers...), nil
	}
}

func (f *Flags) idFlagName() string {
	if f.role == RoleClient {
		return "-spiffe-authorize-id"
	}
	return "-spiffe-admit-id"
}

func (f *Flags) gkeFlagName() string {
	if f.role == RoleClient {
		return "-spiffe-authorize-gke"
	}
	return "-spiffe-admit-gke"
}

func noopCloser() error { return nil }

// stringList collects a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	if v == "" {
		return errors.New("empty value")
	}
	*l = append(*l, v)
	return nil
}
