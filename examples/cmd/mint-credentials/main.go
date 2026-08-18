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

// Command mint-credentials writes a throwaway CA and the certificates
// the local examples need.
//
// It stands in for the thing a real deployment already has: an internal
// CA under -profile pki, a SPIFFE issuer under -profile spiffe. Neither
// is something purser provides — cert-manager and SPIRE do that, and
// the Kubernetes manifests under examples/k8s use them. This exists so
// the local cells need no infrastructure at all.
//
// Three identities are minted, not two. The third is the one that must
// be turned away: under -profile pki it carries a different
// organizational unit, under -profile spiffe a different SPIFFE ID. A
// demonstration where every credential works shows only that TLS is on.
//
// The keys it writes are disposable and last an hour. Nothing here
// belongs anywhere near a real deployment, and nothing it writes should
// be committed.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/go-steer/purser/examples/internal/credentials"
	"github.com/go-steer/purser/examples/internal/profile"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "mint-credentials: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("mint-credentials", flag.ContinueOnError)

	dir := fs.String("dir", "", "directory to write credentials into (required)")
	prof := fs.String("profile", profile.PKI, "which credentials to mint: pki or spiffe")

	var pki credentials.PKIOptions
	fs.StringVar(&pki.ServerHost, "server-host", "127.0.0.1",
		"pki: host the server certificate is valid for; an IP lands in an IP SAN, a name in a DNS SAN")
	fs.StringVar(&pki.ClientName, "client-name", "hello-client.local",
		"pki: DNS SAN carried by the client certificate, which -pki-subject san_dns reads as the identity")
	fs.StringVar(&pki.ClientOU, "client-ou", "platform",
		"pki: organizational unit on the client certificate, for -pki-admit-ou")
	fs.StringVar(&pki.UnauthorizedOU, "unauthorized-ou", "interns",
		"pki: organizational unit on the third certificate, the one -pki-admit-ou must reject")

	var spiffe credentials.SPIFFEOptions
	fs.StringVar(&spiffe.TrustDomain, "trust-domain", "example.org", "spiffe: trust domain to mint SVIDs in")
	fs.StringVar(&spiffe.ServerPath, "server-path", "/ns/default/sa/hello-server", "spiffe: path of the server SVID")
	fs.StringVar(&spiffe.ClientPath, "client-path", "/ns/default/sa/hello-client", "spiffe: path of the client SVID")
	fs.StringVar(&spiffe.UnauthorizedPath, "unauthorized-path", "/ns/default/sa/intruder",
		"spiffe: path of the third SVID, the one the admission matcher must reject")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("-dir is required")
	}
	pki.Dir, spiffe.Dir = *dir, *dir

	var (
		set credentials.Set
		err error
	)
	switch *prof {
	case profile.PKI:
		set, err = credentials.MintPKI(pki)
	case profile.SPIFFE:
		set, err = credentials.MintSPIFFE(spiffe)
	default:
		return fmt.Errorf("unknown -profile %q, want %q or %q", *prof, profile.PKI, profile.SPIFFE)
	}
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "wrote %s credentials to %s\n", *prof, *dir)
	for _, id := range set.All() {
		fmt.Fprintf(out, "  %-13s %s\n", id.Name+"/", id.Subject)
	}
	if *prof == profile.PKI {
		fmt.Fprintf(out, "\n%s/ carries OU=%s and is rejected by -pki-admit-ou %s\n",
			credentials.UnauthorizedDir, pki.UnauthorizedOU, pki.ClientOU)
	} else {
		fmt.Fprintf(out, "\n%s/ is rejected by a -spiffe-admit-id naming only %s\n",
			credentials.UnauthorizedDir, set.Client.Subject)
	}
	return nil
}
