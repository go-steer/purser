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

// Package authz decides what an authenticated caller may do.
//
// It holds two mechanisms that are deliberately independent, because
// they answer different questions and a deployment may want either
// alone:
//
//   - Per-resource access, in this file. An ACL names an owner, some
//     viewers and some contributors; RoleOf resolves a caller to a Role
//     against it; Allows says which actions a role may take. Authorize
//     is the two composed.
//   - Service-wide grants, in rules.go. A set of named Rules maps
//     identity patterns, SPIFFE path segments, certificate fields and
//     OIDC claims onto the Admin bit and the right to proxy — replacing
//     the exact-match identity lists that scale no better than the token
//     table purser exists to retire. The set is a union with no deny
//     rules, so its meaning does not depend on its order.
//
// # The vocabulary is the consuming service's
//
// purser supplies the mechanism and stays out of the nouns. There is no
// "session" here, and no daemon: an ACL guards a *resource*, whatever
// the service calls it, and the actions are the four verbs plus the
// scope-wide one. A service maps its own vocabulary onto them and keeps
// its own names in its own audit records:
//
//	// in the consuming service
//	type Action int // session.read, session.write, …
//
//	func Authorize(c purser.Caller, a Action, acl authz.ACL) bool {
//		return authz.Authorize(c, a.authzAction(), acl)
//	}
//
// That indirection is the point. Role names and ACL shapes are policy
// the service owns; what purser owns is that the matrix is enforced the
// same way everywhere, and that a caller with no identity is nobody.
//
// # Deny by default
//
// Every path through this package that does not recognise its input
// denies: an unknown Action — except to RoleAdmin, which is defined as
// everything, including verbs added after this binary was built — a
// Role outside the ones defined here, a
// caller whose Identity is empty or is the anonymous one purser hands
// an unauthenticated request. A matcher assembled from configuration
// that never got set closes the door rather than opening it — including
// MatchAll with no matchers, which is why this package supplies no way
// to spell "everyone" at all.
//
// The package is stdlib-only, so a consumer that only wants the
// authorization matrix links nothing else.
package authz

import "github.com/go-steer/purser"

// Action is a verb a caller may attempt against a resource. The set is
// small on purpose: finer scoping — per-field, per-sub-resource — is
// the consuming service's, layered on top of these.
type Action int

const (
	// ActionList is enumerating the resources of a collection. It is
	// always permitted, including to a caller with no identity: the
	// handler is expected to filter the result to what the caller may
	// actually read. Hiding the existence of unreadable resources is
	// what keeps a listing from leaking activity patterns, and a
	// listing that 403s tells the caller the collection exists.
	ActionList Action = iota

	// ActionRead is reading a resource's state.
	ActionRead

	// ActionWrite is mutating a resource's state.
	ActionWrite

	// ActionAdmin is mutating the resource itself rather than its
	// state — changing its ACL, deleting it.
	ActionAdmin

	// ActionScopeAdmin is anything not bound to a single resource:
	// service-wide configuration, a peer registry, global metrics. No
	// ACL can grant it, because no ACL describes that scope; only an
	// Admin caller may take it.
	ActionScopeAdmin
)

// String returns the action name for diagnostics and audit records.
// Unknown values render as "unknown" rather than a number, so a log
// line from a newer binary is still readable.
//
// The names carry no resource noun. A service that wants one prefixes
// it: "session." + a.String().
func (a Action) String() string {
	switch a {
	case ActionList:
		return "list"
	case ActionRead:
		return "read"
	case ActionWrite:
		return "write"
	case ActionAdmin:
		return "admin"
	case ActionScopeAdmin:
		return "scope.admin"
	}
	return "unknown"
}

// Role is what a caller is to one resource. The constants are ordered
// from least to most capable and that ordering is part of the API:
// Allows compares with >=, and so may a consumer.
//
// A role is not a group and not a claim. It is derived per resource,
// from an ACL, by RoleOf — except RoleAdmin, which comes from
// purser.Caller.Admin and therefore from policy (see Rules), never from
// a credential's own assertion.
type Role int

const (
	// RoleNone is a caller the ACL does not name. It may still list.
	RoleNone Role = iota

	// RoleViewer may read.
	RoleViewer

	// RoleContributor may read and write.
	RoleContributor

	// RoleOwner may read, write, and administer the resource. The owner
	// need not be a person: a synthetic identity such as
	// "channel:#incident-response" is the shape a shared resource takes.
	RoleOwner

	// RoleAdmin sees and does everything, on every resource in every
	// scope. It is the caller's Admin bit, not an ACL entry.
	RoleAdmin
)

// String returns the role name for diagnostics and audit records.
func (r Role) String() string {
	switch r {
	case RoleNone:
		return "none"
	case RoleViewer:
		return "viewer"
	case RoleContributor:
		return "contributor"
	case RoleOwner:
		return "owner"
	case RoleAdmin:
		return "admin"
	}
	return "unknown"
}

// ACL is who may do what to one resource.
//
// The zero value grants nothing to anyone but an Admin caller. That is
// the safe reading of a resource created before the service had an
// authorization story, or of a struct somebody forgot to populate: such
// a resource is administrator-only until an owner is assigned, rather
// than everyone's.
//
// Membership is exact identity equality, not pattern matching. A caller
// named in several lists gets the most capable role, so widening an
// entry can never narrow access.
type ACL struct {
	// Owner is the identity with full control of the resource.
	Owner string

	// Viewers may read.
	Viewers []string

	// Contributors may read and write, but may not change this ACL.
	Contributors []string
}

// RoleOf resolves c's role against acl.
//
// A caller with no identity is RoleNone whatever the ACL says. This is
// the case worth stating: a zero purser.Caller has an empty Identity,
// an ACL that was never populated has an empty Owner, and comparing
// them for equality would make a half-initialized struct grant
// ownership of a resource to a request that never authenticated. The
// same reasoning applies to the Admin bit — a Caller carrying Admin
// with no identity did not come from an authenticator, since
// authn.Authenticator forbids returning an identity-less Caller
// alongside a nil error, so it is treated as the accident it is.
func (acl ACL) RoleOf(c purser.Caller) Role {
	if c.IsZero() {
		return RoleNone
	}
	if c.Admin {
		return RoleAdmin
	}
	if c.Identity == acl.Owner {
		return RoleOwner
	}
	if contains(acl.Contributors, c.Identity) {
		return RoleContributor
	}
	if contains(acl.Viewers, c.Identity) {
		return RoleViewer
	}
	return RoleNone
}

// Allows reports whether role may take action:
//
//	| Action     | Admin | Owner | Contributor | Viewer | None |
//	|------------|-------|-------|-------------|--------|------|
//	| List       |   ✓   |   ✓   |      ✓      |    ✓   |   ✓  |
//	| Read       |   ✓   |   ✓   |      ✓      |    ✓   |      |
//	| Write      |   ✓   |   ✓   |      ✓      |        |      |
//	| Admin      |   ✓   |   ✓   |             |        |      |
//	| ScopeAdmin |   ✓   |       |             |        |      |
//
// It is exported for the service that resolves roles some other way —
// from a group membership service, or a role already recorded on the
// resource — and wants the same matrix applied to the result. That is
// also why the range check below is not redundant: a Role reaching this
// function need not have come from RoleOf. A service persisting roles
// as integers and reading one back from a newer peer, a corrupted row,
// or an off-by-one in its own mapping table would otherwise find that
// any value above RoleAdmin satisfies every >= comparison here and
// authorizes everything short of the scope.
func Allows(role Role, action Action) bool {
	if role < RoleNone || role > RoleAdmin {
		return false
	}
	if role == RoleAdmin {
		return true
	}
	switch action {
	case ActionList:
		return true
	case ActionRead:
		return role >= RoleViewer
	case ActionWrite:
		return role >= RoleContributor
	case ActionAdmin:
		return role >= RoleOwner
	case ActionScopeAdmin:
		// Only RoleAdmin, which returned above. An ACL describes one
		// resource and cannot speak for the whole scope.
		return false
	}
	// An Action this build does not know — a value read from an older
	// or newer peer, or an uninitialized variable that happens not to
	// be zero. Deny.
	return false
}

// Authorize reports whether c may perform action against the resource
// guarded by acl. It is Allows(acl.RoleOf(c), action), which is the
// whole of the decision for a service that keeps its ACLs in this
// shape.
func Authorize(c purser.Caller, action Action, acl ACL) bool {
	return Allows(acl.RoleOf(c), action)
}

// contains reports whether want appears in xs. The empty string is
// never found: an ACL entry that was never filled in must not match a
// caller whose identity was never filled in either.
func contains(xs []string, want string) bool {
	if want == "" {
		return false
	}
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
