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

package bearer

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// UsersFileSchemaVersion is the schema version this loader understands.
// Bump it when the on-disk shape changes in a way that breaks older
// loaders; LoadUsersFile rejects unknown versions so operators do not
// silently lose new fields to a binary that predates them.
const UsersFileSchemaVersion = 1

// UsersFile is the on-disk shape of a bearer token table.
//
// It is the format core-agent reads today at
// attach.multi_session.auth.table_file, preserved byte-for-byte so that
// adopting purser is a no-op for an existing deployment's config.
type UsersFile struct {
	Version int    `json:"version"`
	Users   []User `json:"users"`
}

// User is one row of the table. Identity is the stable opaque ID that
// lands on the resolved purser.Caller and on audit records; Token is the
// secret the client presents. Labels are free-form metadata carried
// through to authorization and audit.
//
// Identity and Token are both required. A row missing either is rejected
// at load time rather than skipped: skipping would leave an operator
// believing they had provisioned a caller who cannot in fact
// authenticate, or — worse for an empty token — one who can be
// impersonated by a request presenting no credential at all.
type User struct {
	Identity string            `json:"identity"`
	Token    string            `json:"token"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// LoadUsersFile reads and validates a users file from disk.
//
// Validation:
//   - On POSIX the file mode must be 0600 or stricter (group and other
//     bits unset). The file holds bearer secrets in cleartext; a
//     world-readable one is a misconfiguration to fail on, not a
//     laxity to tolerate. Skipped on Windows, where Unix mode bits do
//     not map cleanly.
//   - Unknown JSON fields are rejected, so a typoed key is an error
//     rather than a silently ignored setting.
//   - The schema version must equal UsersFileSchemaVersion.
//   - Every row must carry both an identity and a token, and both must
//     be unique across rows. See validateUsers.
//
// A file holding zero rows loads successfully: "authenticate nobody" is
// a legitimate state for a table that another authenticator supplements.
// NewFromFile is the one that treats it as a truncated file.
func LoadUsersFile(path string) (*UsersFile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("purser/bearer: stat users file %q: %w", path, err)
	}
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			return nil, fmt.Errorf(
				"purser/bearer: users file %q has mode %#o; must be 0600 or stricter (group/other bits must be unset)",
				path, mode)
		}
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied config, not request input
	if err != nil {
		return nil, fmt.Errorf("purser/bearer: read users file %q: %w", path, err)
	}

	var uf UsersFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&uf); err != nil {
		return nil, fmt.Errorf("purser/bearer: parse users file %q: %w", path, err)
	}
	if uf.Version != UsersFileSchemaVersion {
		return nil, fmt.Errorf("purser/bearer: users file %q has unsupported schema version %d (expected %d)",
			path, uf.Version, UsersFileSchemaVersion)
	}
	if err := validateUsers(fmt.Sprintf("users file %q", path), uf.Users); err != nil {
		return nil, err
	}
	return &uf, nil
}

// validateUsers enforces the row-level invariants shared by LoadUsersFile
// and New. where names the source of the rows ("users file %q", or
// "options" for a table assembled in code) so the message points at
// whichever one the operator can actually edit.
//
// Both callers run it because both are reachable independently: a
// consumer may build Options.Users programmatically and never touch a
// file, and New is the last place a bad row can be caught before it
// becomes a live credential.
func validateUsers(where string, users []User) error {
	// Tokens are deduplicated by digest so the checker does not build a
	// second map keyed by the cleartext secrets.
	seenToken := make(map[[sha256.Size]byte]string, len(users))
	seenIdentity := make(map[string]struct{}, len(users))
	for i, u := range users {
		if u.Identity == "" {
			return fmt.Errorf("purser/bearer: %s: row %d: identity is required", where, i)
		}
		if u.Token == "" {
			return fmt.Errorf("purser/bearer: %s: row %d (identity %q): token is required", where, i, u.Identity)
		}
		// A token that is not equal to its own trimmed form — padded, or
		// nothing but whitespace — can never be presented: extractToken
		// trims what it reads out of the header, so the digest of what
		// arrives never equals the digest of what was provisioned. The
		// row would fail closed, which is safe but silent: the operator
		// sees a user who simply cannot log in, with nothing in the logs
		// to say why.
		if strings.TrimSpace(u.Token) != u.Token {
			return fmt.Errorf(
				"purser/bearer: %s: row %d (identity %q): token has leading or trailing whitespace, "+
					"which the header parser strips; it could never be presented", where, i, u.Identity)
		}
		digest := sha256.Sum256([]byte(u.Token))
		if other, ok := seenToken[digest]; ok {
			// Reported without either token: the message reaches logs.
			return fmt.Errorf("purser/bearer: %s: row %d (identity %q): token collides with the row for identity %q",
				where, i, u.Identity, other)
		}
		if _, ok := seenIdentity[u.Identity]; ok {
			return fmt.Errorf("purser/bearer: %s: row %d: duplicate identity %q", where, i, u.Identity)
		}
		seenToken[digest] = u.Identity
		seenIdentity[u.Identity] = struct{}{}
	}
	return nil
}
