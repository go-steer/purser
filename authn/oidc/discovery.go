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

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// discoveryPath is appended to the issuer to reach its metadata, per
// OpenID Connect Discovery 1.0 §4.
const discoveryPath = "/.well-known/openid-configuration"

// discover reads the issuer's metadata and returns its key endpoint.
//
// The document is fetched over the same client as the key set, so
// whatever pins the issuer's TLS pins this too. Only two fields are
// read: everything else in the document describes flows this package
// does not implement.
func discover(ctx context.Context, client *http.Client, issuer string) (string, error) {
	metadataURL := issuer + discoveryPath
	body, err := getJSON(ctx, client, metadataURL)
	if err != nil {
		return "", fmt.Errorf("discovering %s: %w", issuer, err)
	}

	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("decoding the discovery document at %s: %w", metadataURL, err)
	}

	// The document must claim the issuer we asked for. This is the
	// check that makes discovery safe to follow: without it, anything
	// that can answer at the issuer's well-known path can point the key
	// fetch at a JWKS of its own, and from there sign tokens for any
	// identity. RFC 8414 §3.3 requires it, and it is the one field of
	// the document that is not merely informative.
	if doc.Issuer != issuer {
		return "", fmt.Errorf("the discovery document at %s declares issuer %q, want %q",
			metadataURL, doc.Issuer, issuer)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("the discovery document at %s has no jwks_uri", metadataURL)
	}

	u, err := url.Parse(doc.JWKSURI)
	if err != nil {
		return "", fmt.Errorf("the discovery document at %s has an unparseable jwks_uri %q: %w",
			metadataURL, doc.JWKSURI, err)
	}
	// https for the same reason the issuer must be https: the keys
	// arrive with nothing else authenticating them. The endpoint need
	// not share the issuer's host — Google's issuer is
	// accounts.google.com and its keys are on www.googleapis.com — so
	// the scheme is the whole of what can be required here.
	if u.Scheme != "https" {
		return "", fmt.Errorf("the discovery document at %s has a non-https jwks_uri %q",
			metadataURL, doc.JWKSURI)
	}
	if u.Host == "" {
		return "", fmt.Errorf("the discovery document at %s has a jwks_uri %q with no host",
			metadataURL, doc.JWKSURI)
	}
	return doc.JWKSURI, nil
}
