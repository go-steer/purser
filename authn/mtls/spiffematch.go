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
	"errors"
	"fmt"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// The matchers in this file are the SPIFFE profile's counterpart to the
// MatchCert* family, which is the PKI profile's. They build a
// spiffeid.Matcher — go-spiffe's own type, so they compose freely with
// spiffeid.MatchID, MatchOneOf, MatchMemberOf and MatchAny, and can be
// handed to any go-spiffe API that takes one. purser adds only what
// go-spiffe has no equivalent for: conjunction and disjunction, and
// anchored matching on the ID's path.
//
// Anchoring is the point. A SPIFFE ID is a URI, and the tempting
// shorthands are all wrong on it: strings.Contains(id, "/ns/prod")
// admits spiffe://td/ns/prod-copy and spiffe://td/tenants/evil/ns/prod,
// and strings.HasPrefix(path, "/ns/prod") admits /ns/production. Every
// matcher here compares whole path segments.

// MatchAll admits a peer only if every matcher admits it. With no
// matchers it admits everything, which makes it safe to build from a
// possibly-empty configuration list.
func MatchAll(matchers ...spiffeid.Matcher) spiffeid.Matcher {
	return func(id spiffeid.ID) error {
		for _, m := range matchers {
			if err := m(id); err != nil {
				return err
			}
		}
		return nil
	}
}

// MatchAnyOf admits a peer if any matcher admits it.
//
// With no matchers it admits *nothing*, the opposite of MatchAll's
// empty case, and for the same reason MatchCertAnyOf does it: an empty
// conjunction adds no constraint, while an empty disjunction offers no
// way in. Neither should be spellable by accident.
func MatchAnyOf(matchers ...spiffeid.Matcher) spiffeid.Matcher {
	return func(id spiffeid.ID) error {
		if len(matchers) == 0 {
			return errors.New("no matcher configured to admit any peer")
		}
		errs := make([]error, 0, len(matchers))
		for _, m := range matchers {
			err := m(id)
			if err == nil {
				return nil
			}
			errs = append(errs, err)
		}
		return fmt.Errorf("no alternative admitted the peer: %w", errors.Join(errs...))
	}
}

// MatchPathSegments admits a peer whose SPIFFE ID path is exactly these
// segments, whatever its trust domain — MatchPathSegments("ns", "prod",
// "sa", "api") admits spiffe://example.org/ns/prod/sa/api and nothing
// else under any other path.
//
// Segments are passed separately rather than as one "/ns/prod/sa/api"
// string so that a segment interpolated from configuration cannot
// smuggle a separator in and widen the rule. go-spiffe validates them;
// an invalid or empty segment, or no segments at all, yields a matcher
// that admits nobody, so a rule built from unset configuration closes
// the door rather than opening it.
//
// Pair it with spiffeid.MatchMemberOf inside MatchAll to pin the trust
// domain as well, or use spiffeid.MatchID when the whole ID is known.
func MatchPathSegments(segments ...string) spiffeid.Matcher {
	want, err := joinSegments(segments)
	return func(id spiffeid.ID) error {
		if err != nil {
			return err
		}
		if id.Path() != want {
			return fmt.Errorf("path %q is not %q", id.Path(), want)
		}
		return nil
	}
}

// MatchPathPrefix admits a peer whose SPIFFE ID path is these segments
// or lies beneath them: MatchPathPrefix("ns", "prod") admits
// spiffe://example.org/ns/prod and spiffe://example.org/ns/prod/sa/api,
// and rejects spiffe://example.org/ns/production.
//
// The prefix is anchored on a segment boundary, which is the whole
// difference between "the prod namespace" and "any namespace whose name
// starts with prod". As with MatchPathSegments, an invalid or empty
// segment list admits nobody.
func MatchPathPrefix(segments ...string) spiffeid.Matcher {
	want, err := joinSegments(segments)
	return func(id spiffeid.ID) error {
		if err != nil {
			return err
		}
		path := id.Path()
		if path == want || strings.HasPrefix(path, want+"/") {
			return nil
		}
		return fmt.Errorf("path %q is not under %q", path, want)
	}
}

// MatchGKEWorkload admits the GKE workload running as serviceAccount in
// namespace, in the fleet of the given Google Cloud project — the
// identity spiffe://PROJECT.svc.id.goog/ns/NAMESPACE/sa/SERVICEACCOUNT,
// which is the SPIFFE ID GKE workload identity and Cloud Service Mesh
// issue to a pod.
//
// It is a named shorthand for
// spiffeid.MatchID(spiffe://PROJECT.svc.id.goog/ns/NS/sa/SA) and exists
// because that string is easy to assemble by hand and easy to assemble
// wrongly: the trust domain is the *project*, not the cluster, so two
// clusters in one project issue indistinguishable identities, and a
// deployment that means to distinguish them needs more than this
// matcher. An empty argument, or one that is not a valid segment,
// yields a matcher that admits nobody.
func MatchGKEWorkload(project, namespace, serviceAccount string) spiffeid.Matcher {
	id, err := gkeWorkloadID(project, namespace, serviceAccount)
	return func(actual spiffeid.ID) error {
		if err != nil {
			return err
		}
		if actual != id {
			return fmt.Errorf("ID %q is not %q", actual, id)
		}
		return nil
	}
}

// gkeWorkloadID assembles the GKE workload identity SPIFFE ID.
func gkeWorkloadID(project, namespace, serviceAccount string) (spiffeid.ID, error) {
	if project == "" || namespace == "" || serviceAccount == "" {
		return spiffeid.ID{}, errors.New("no GKE project, namespace and service account " +
			"configured to admit any peer")
	}
	td, err := spiffeid.TrustDomainFromString(project + ".svc.id.goog")
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("invalid GKE project %q: %w", project, err)
	}
	id, err := spiffeid.FromSegments(td, "ns", namespace, "sa", serviceAccount)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("invalid GKE namespace %q or service account %q: %w",
			namespace, serviceAccount, err)
	}
	return id, nil
}

// joinSegments builds the path a matcher compares against, rejecting an
// empty list so that "no segments configured" cannot read as "the empty
// path", which every ID that carries no path would match.
func joinSegments(segments []string) (string, error) {
	if len(segments) == 0 {
		return "", errors.New("no path segments configured to admit any peer")
	}
	path, err := spiffeid.JoinPathSegments(segments...)
	if err != nil {
		return "", fmt.Errorf("invalid SPIFFE path segments %q: %w", segments, err)
	}
	return path, nil
}
