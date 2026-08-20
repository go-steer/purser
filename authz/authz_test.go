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

package authz_test

import (
	"testing"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authz"
)

// acl is the ACL every matrix case runs against: one owner, one viewer,
// one contributor, and by omission a stranger.
func acl() authz.ACL {
	return authz.ACL{
		Owner:        "owner@example.com",
		Viewers:      []string{"viewer@example.com"},
		Contributors: []string{"contrib@example.com"},
	}
}

// TestAuthorizeMatrix is core-agent's pkg/auth authorization table,
// ported cell for cell with its role names mapped onto purser's
// resource-generic ones (session.* becomes the bare verb,
// daemon.admin becomes scope.admin). Passing it unchanged is the
// evidence the lift preserved behavior, which is what phase 2 of the
// migration depends on: operators read this grid in the design doc and
// assume the code enforces it.
func TestAuthorizeMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		caller purser.Caller
		action authz.Action
		want   bool
	}{
		// Admin passes everything.
		{"admin/list", purser.Caller{Identity: "ops@example.com", Admin: true}, authz.ActionList, true},
		{"admin/read", purser.Caller{Identity: "ops@example.com", Admin: true}, authz.ActionRead, true},
		{"admin/write", purser.Caller{Identity: "ops@example.com", Admin: true}, authz.ActionWrite, true},
		{"admin/admin", purser.Caller{Identity: "ops@example.com", Admin: true}, authz.ActionAdmin, true},
		{"admin/scope", purser.Caller{Identity: "ops@example.com", Admin: true}, authz.ActionScopeAdmin, true},

		// Owner can do everything to its own resource except the
		// scope-wide action, which no ACL can grant.
		{"owner/list", purser.Caller{Identity: "owner@example.com"}, authz.ActionList, true},
		{"owner/read", purser.Caller{Identity: "owner@example.com"}, authz.ActionRead, true},
		{"owner/write", purser.Caller{Identity: "owner@example.com"}, authz.ActionWrite, true},
		{"owner/admin", purser.Caller{Identity: "owner@example.com"}, authz.ActionAdmin, true},
		{"owner/scope", purser.Caller{Identity: "owner@example.com"}, authz.ActionScopeAdmin, false},

		// Contributor: read + write, NOT admin.
		{"contrib/list", purser.Caller{Identity: "contrib@example.com"}, authz.ActionList, true},
		{"contrib/read", purser.Caller{Identity: "contrib@example.com"}, authz.ActionRead, true},
		{"contrib/write", purser.Caller{Identity: "contrib@example.com"}, authz.ActionWrite, true},
		{"contrib/admin", purser.Caller{Identity: "contrib@example.com"}, authz.ActionAdmin, false},
		{"contrib/scope", purser.Caller{Identity: "contrib@example.com"}, authz.ActionScopeAdmin, false},

		// Viewer: read only.
		{"viewer/list", purser.Caller{Identity: "viewer@example.com"}, authz.ActionList, true},
		{"viewer/read", purser.Caller{Identity: "viewer@example.com"}, authz.ActionRead, true},
		{"viewer/write", purser.Caller{Identity: "viewer@example.com"}, authz.ActionWrite, false},
		{"viewer/admin", purser.Caller{Identity: "viewer@example.com"}, authz.ActionAdmin, false},
		{"viewer/scope", purser.Caller{Identity: "viewer@example.com"}, authz.ActionScopeAdmin, false},

		// Stranger: list only (the handler filters the results).
		{"stranger/list", purser.Caller{Identity: "stranger@example.com"}, authz.ActionList, true},
		{"stranger/read", purser.Caller{Identity: "stranger@example.com"}, authz.ActionRead, false},
		{"stranger/write", purser.Caller{Identity: "stranger@example.com"}, authz.ActionWrite, false},
		{"stranger/admin", purser.Caller{Identity: "stranger@example.com"}, authz.ActionAdmin, false},
		{"stranger/scope", purser.Caller{Identity: "stranger@example.com"}, authz.ActionScopeAdmin, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := authz.Authorize(tt.caller, tt.action, acl()); got != tt.want {
				t.Errorf("Authorize(%q, %s, acl) = %v, want %v", tt.caller.Identity, tt.action, got, tt.want)
			}
		})
	}
}

// TestRoleOf pins the resolution half of the decision on its own, so a
// consumer that reads a role for an audit record — "alice acted as
// contributor" — gets the same answer Authorize acted on.
func TestRoleOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		caller purser.Caller
		want   authz.Role
	}{
		{"admin bit outranks the ACL", purser.Caller{Identity: "stranger@example.com", Admin: true}, authz.RoleAdmin},
		{"owner", purser.Caller{Identity: "owner@example.com"}, authz.RoleOwner},
		{"contributor", purser.Caller{Identity: "contrib@example.com"}, authz.RoleContributor},
		{"viewer", purser.Caller{Identity: "viewer@example.com"}, authz.RoleViewer},
		{"stranger", purser.Caller{Identity: "stranger@example.com"}, authz.RoleNone},
		{"no identity", purser.Caller{}, authz.RoleNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := acl().RoleOf(tt.caller); got != tt.want {
				t.Errorf("RoleOf(%+v) = %s, want %s", tt.caller, got, tt.want)
			}
		})
	}
}

// TestRoleOfTakesTheMostCapableRole pins that listing an identity in
// more than one place cannot cost it access. An operator who promotes a
// viewer to contributor by adding a line, and forgets to remove the
// old one, has widened the grant and not narrowed it.
func TestRoleOfTakesTheMostCapableRole(t *testing.T) {
	t.Parallel()

	both := authz.ACL{
		Owner:        "owner@example.com",
		Viewers:      []string{"alice@example.com"},
		Contributors: []string{"alice@example.com"},
	}
	if got := both.RoleOf(purser.Caller{Identity: "alice@example.com"}); got != authz.RoleContributor {
		t.Errorf("RoleOf(alice) = %s, want %s", got, authz.RoleContributor)
	}

	owning := authz.ACL{
		Owner:   "alice@example.com",
		Viewers: []string{"alice@example.com"},
	}
	if got := owning.RoleOf(purser.Caller{Identity: "alice@example.com"}); got != authz.RoleOwner {
		t.Errorf("RoleOf(alice) = %s, want %s", got, authz.RoleOwner)
	}
}

// TestEmptyIdentityIsNobody is the defense-in-depth case: a zero Caller
// must not slip through by matching the empty Owner of an ACL nobody
// populated. Both halves of that comparison are empty strings, and
// string equality would say yes.
func TestEmptyIdentityIsNobody(t *testing.T) {
	t.Parallel()

	empty := authz.ACL{}
	zero := purser.Caller{}

	for _, action := range []authz.Action{authz.ActionRead, authz.ActionWrite, authz.ActionAdmin, authz.ActionScopeAdmin} {
		if authz.Authorize(zero, action, empty) {
			t.Errorf("Authorize(zero Caller, %s, zero ACL) = true; the safe default must reject it", action)
		}
	}
	// Listing stays permitted, as it is for any caller: the handler
	// filters the result, and refusing here would tell an anonymous
	// client that the collection exists.
	if !authz.Authorize(zero, authz.ActionList, empty) {
		t.Error("Authorize(zero Caller, list, zero ACL) = false; listing is filtered by the handler, not refused here")
	}
	// Every list entry is empty-string too, and none of them may match.
	populated := authz.ACL{Owner: "", Viewers: []string{""}, Contributors: []string{""}}
	if authz.Authorize(zero, authz.ActionRead, populated) {
		t.Error("an empty-string ACL entry matched a Caller with no identity")
	}
}

// TestAdminWithoutAnIdentityIsNobody is purser's one deviation from the
// ported matrix. core-agent answers c.Admin before it looks at the
// identity, so a hand-built Caller{Admin: true} with no identity is
// authorized for everything. No authenticator can produce one —
// authn.Authenticator forbids returning an identity-less Caller with a
// nil error — so such a value is a struct literal somebody wrote, and
// it is treated as the accident it is.
func TestAdminWithoutAnIdentityIsNobody(t *testing.T) {
	t.Parallel()

	c := purser.Caller{Admin: true}
	if got := acl().RoleOf(c); got != authz.RoleNone {
		t.Errorf("RoleOf(Caller{Admin: true}) = %s, want %s", got, authz.RoleNone)
	}
	if authz.Authorize(c, authz.ActionScopeAdmin, acl()) {
		t.Error("a Caller carrying Admin with no identity was authorized for the scope-wide action")
	}
}

// TestAllowsUnknownActionIsDenied covers the value that arrives from a
// binary built against a different version of this enum, and the
// uninitialized variable that happens not to be zero.
func TestAllowsUnknownActionIsDenied(t *testing.T) {
	t.Parallel()

	for _, role := range []authz.Role{authz.RoleNone, authz.RoleViewer, authz.RoleContributor, authz.RoleOwner} {
		if authz.Allows(role, authz.Action(99)) {
			t.Errorf("Allows(%s, Action(99)) = true; an unrecognised action must deny", role)
		}
	}
	// Admin is the documented exception: it is not a per-action grant
	// but a "sees everything" role, so it does not depend on the action
	// being one this build knows about.
	if !authz.Allows(authz.RoleAdmin, authz.Action(99)) {
		t.Error("Allows(admin, Action(99)) = false; Admin is not scoped to the known actions")
	}
	if authz.Authorize(purser.Caller{Identity: "owner@example.com"}, authz.Action(99), acl()) {
		t.Error("Authorize with an unrecognised action = true; must deny")
	}
}

// TestAllowsUnknownRoleIsDenied is the same defense from the other
// side. The values above RoleAdmin are the ones that matter: every
// grant here is a >= comparison, so an out-of-range role satisfies all
// of them unless the range is checked. Allows is exported for services
// that resolve a role their own way, and an integer read back from a
// row or a mapping table is exactly where such a value comes from.
func TestAllowsUnknownRoleIsDenied(t *testing.T) {
	t.Parallel()

	actions := []authz.Action{authz.ActionRead, authz.ActionWrite, authz.ActionAdmin, authz.ActionScopeAdmin}
	for _, unknown := range []authz.Role{authz.Role(-1), authz.RoleAdmin + 1, authz.Role(99)} {
		for _, action := range actions {
			if authz.Allows(unknown, action) {
				t.Errorf("Allows(Role(%d), %s) = true; an unrecognised role must deny", unknown, action)
			}
		}
		// ActionList is permitted to every *recognised* role, including
		// RoleNone, but an unrecognised one is not a role at all.
		if authz.Allows(unknown, authz.ActionList) {
			t.Errorf("Allows(Role(%d), list) = true; an unrecognised role must deny", unknown)
		}
	}
}

// TestRoleOrderingIsPartOfTheAPI pins the constants' relative order.
// Allows compares roles with >=, the doc comment invites consumers to
// do the same, and reordering the block would silently reassign
// capabilities rather than fail to compile.
func TestRoleOrderingIsPartOfTheAPI(t *testing.T) {
	t.Parallel()

	ordered := []authz.Role{authz.RoleNone, authz.RoleViewer, authz.RoleContributor, authz.RoleOwner, authz.RoleAdmin}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1] >= ordered[i] {
			t.Errorf("%s (%d) is not below %s (%d)", ordered[i-1], ordered[i-1], ordered[i], ordered[i])
		}
	}
}

func TestActionString(t *testing.T) {
	t.Parallel()

	tests := map[authz.Action]string{
		authz.ActionList:       "list",
		authz.ActionRead:       "read",
		authz.ActionWrite:      "write",
		authz.ActionAdmin:      "admin",
		authz.ActionScopeAdmin: "scope.admin",
		authz.Action(42):       "unknown",
	}
	for a, want := range tests {
		if got := a.String(); got != want {
			t.Errorf("Action(%d).String() = %q, want %q", int(a), got, want)
		}
	}
}

func TestRoleString(t *testing.T) {
	t.Parallel()

	tests := map[authz.Role]string{
		authz.RoleNone:        "none",
		authz.RoleViewer:      "viewer",
		authz.RoleContributor: "contributor",
		authz.RoleOwner:       "owner",
		authz.RoleAdmin:       "admin",
		authz.Role(42):        "unknown",
	}
	for r, want := range tests {
		if got := r.String(); got != want {
			t.Errorf("Role(%d).String() = %q, want %q", int(r), got, want)
		}
	}
}
