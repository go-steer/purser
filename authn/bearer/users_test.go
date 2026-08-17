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

package bearer_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-steer/purser/authn/bearer"
)

// writeUsersFile writes body to a file in a fresh temp dir with mode
// 0600 and returns its path.
func writeUsersFile(tb testing.TB, body string) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "users.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		tb.Fatalf("write users file: %v", err)
	}
	// os.WriteFile's mode is masked by the process umask, so pin it.
	if err := os.Chmod(path, 0o600); err != nil {
		tb.Fatalf("chmod users file: %v", err)
	}
	return path
}

const validUsersJSON = `{
  "version": 1,
  "users": [
    {"identity": "alice@example.com", "token": "alice-token-3f9c", "labels": {"team": "platform"}},
    {"identity": "sa:slack-bot", "token": "bot-token-71ad"}
  ]
}`

func TestLoadUsersFile(t *testing.T) {
	t.Parallel()

	uf, err := bearer.LoadUsersFile(writeUsersFile(t, validUsersJSON))
	if err != nil {
		t.Fatalf("LoadUsersFile() = %v, want success", err)
	}
	if uf.Version != bearer.UsersFileSchemaVersion {
		t.Errorf("Version = %d, want %d", uf.Version, bearer.UsersFileSchemaVersion)
	}
	if len(uf.Users) != 2 {
		t.Fatalf("len(Users) = %d, want 2", len(uf.Users))
	}
	if got := uf.Users[0].Identity; got != "alice@example.com" {
		t.Errorf("Users[0].Identity = %q, want %q", got, "alice@example.com")
	}
	if got := uf.Users[0].Labels["team"]; got != "platform" {
		t.Errorf("Users[0].Labels[team] = %q, want %q", got, "platform")
	}
	if uf.Users[1].Labels != nil {
		t.Errorf("Users[1].Labels = %v, want nil for a row with no labels", uf.Users[1].Labels)
	}
}

func TestLoadUsersFileAcceptsAnEmptyTable(t *testing.T) {
	t.Parallel()

	uf, err := bearer.LoadUsersFile(writeUsersFile(t, `{"version": 1, "users": []}`))
	if err != nil {
		t.Fatalf("LoadUsersFile() = %v, want success", err)
	}
	if len(uf.Users) != 0 {
		t.Errorf("len(Users) = %d, want 0", len(uf.Users))
	}
}

func TestLoadUsersFileRejectsLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode bits do not map cleanly on Windows")
	}
	t.Parallel()

	// The file holds cleartext bearer secrets. A group- or
	// world-readable one is the single most likely way a token leaks,
	// and it is silent unless the loader refuses to start.
	for _, mode := range []fs.FileMode{0o644, 0o640, 0o604, 0o666} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			path := writeUsersFile(t, validUsersJSON)
			if err := os.Chmod(path, mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			_, err := bearer.LoadUsersFile(path)
			if err == nil {
				t.Fatalf("LoadUsersFile() on a %v file = nil error, want rejection", mode)
			}
			if !strings.Contains(err.Error(), "0600 or stricter") {
				t.Errorf("LoadUsersFile() error = %v, want it to name the required mode", err)
			}
		})
	}
}

func TestLoadUsersFileAcceptsStricterPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode bits do not map cleanly on Windows")
	}
	t.Parallel()

	// 0400 is stricter, not looser: a read-only secrets mount must load.
	path := writeUsersFile(t, validUsersJSON)
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := bearer.LoadUsersFile(path); err != nil {
		t.Errorf("LoadUsersFile() on a 0400 file = %v, want success", err)
	}
}

func TestLoadUsersFileRejectsBadContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"not json", `not json at all`, "parse"},
		{
			// Version 0 is what an operator gets by omitting the field,
			// so the message has to say which version was expected.
			name:    "missing version",
			body:    `{"users": []}`,
			wantErr: "unsupported schema version 0",
		},
		{"future version", `{"version": 99, "users": []}`, "unsupported schema version 99"},
		{
			// A typoed key that parsed as "absent" would silently drop
			// whatever the operator meant to configure.
			name:    "unknown top-level field",
			body:    `{"version": 1, "users": [], "adminIdentities": ["alice@example.com"]}`,
			wantErr: "parse",
		},
		{
			name:    "unknown row field",
			body:    `{"version": 1, "users": [{"identity": "a", "token": "t", "admin": true}]}`,
			wantErr: "parse",
		},
		{
			name:    "missing identity",
			body:    `{"version": 1, "users": [{"token": "t"}]}`,
			wantErr: "identity is required",
		},
		{
			name:    "missing token",
			body:    `{"version": 1, "users": [{"identity": "a"}]}`,
			wantErr: "token is required",
		},
		{
			// The likeliest way this reaches a real file: a token
			// pasted out of a terminal with the newline attached.
			name:    "padded token",
			body:    `{"version": 1, "users": [{"identity": "a", "token": " t\n"}]}`,
			wantErr: "leading or trailing whitespace",
		},
		{
			name:    "duplicate token",
			body:    `{"version": 1, "users": [{"identity": "a", "token": "t"}, {"identity": "b", "token": "t"}]}`,
			wantErr: "collides",
		},
		{
			name:    "duplicate identity",
			body:    `{"version": 1, "users": [{"identity": "a", "token": "t"}, {"identity": "a", "token": "u"}]}`,
			wantErr: "duplicate identity",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeUsersFile(t, tt.body)
			uf, err := bearer.LoadUsersFile(path)
			if err == nil {
				t.Fatalf("LoadUsersFile() = %+v, want an error mentioning %q", uf, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("LoadUsersFile() error = %v, want it to mention %q", err, tt.wantErr)
			}
			// Every load error names the file: an operator running
			// several daemons needs to know which one to edit.
			if !strings.Contains(err.Error(), path) {
				t.Errorf("LoadUsersFile() error = %v, want it to name %q", err, path)
			}
		})
	}
}

func TestLoadUsersFileMissing(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	_, err := bearer.LoadUsersFile(path)
	if err == nil {
		t.Fatal("LoadUsersFile() = nil error, want a stat failure")
	}
	// Wrapped rather than replaced, so a consumer can distinguish "no
	// table configured yet" from "the table is malformed".
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("LoadUsersFile() error = %v, want it to wrap fs.ErrNotExist", err)
	}
}

func TestLoadUsersFileOnADirectory(t *testing.T) {
	t.Parallel()

	// An operator pointing the config at a directory gets a read error,
	// not a panic and not an empty table. Chmod 0700 first so the
	// permission check passes and the read is what fails — t.TempDir
	// hands back a 0755 directory, which would otherwise be rejected
	// one step earlier and leave this path untested.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err := bearer.LoadUsersFile(dir)
	if err == nil {
		t.Fatal("LoadUsersFile(<a directory>) = nil error, want a read failure")
	}
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("LoadUsersFile() error = %v, want it to name %q", err, dir)
	}
}

func TestNewFromFile(t *testing.T) {
	t.Parallel()

	path := writeUsersFile(t, validUsersJSON)
	a, err := bearer.NewFromFile(path, bearer.Options{
		AdminIdentities: []string{"alice@example.com"},
		ProxyIdentities: []string{"sa:slack-bot"},
	})
	if err != nil {
		t.Fatalf("NewFromFile() = %v, want success", err)
	}
	if got := a.Len(); got != 2 {
		t.Errorf("Len() = %d, want 2", got)
	}
	c, err := a.Authenticate(authorized("alice-token-3f9c"))
	if err != nil {
		t.Fatalf("Authenticate() = %v, want success", err)
	}
	if !c.Admin || c.Label("team") != "platform" {
		t.Errorf("Authenticate() = %+v, want an admin on team platform", c)
	}
}

func TestNewFromFileIgnoresOptionsUsers(t *testing.T) {
	t.Parallel()

	// The file is the source of truth; a row passed in Options must not
	// quietly join the table alongside it.
	path := writeUsersFile(t, validUsersJSON)
	a, err := bearer.NewFromFile(path, bearer.Options{
		Users: []bearer.User{{Identity: "mallory@example.com", Token: "mallory-token"}},
	})
	if err != nil {
		t.Fatalf("NewFromFile() = %v, want success", err)
	}
	if _, ok := a.LookupIdentity("mallory@example.com"); ok {
		t.Error("NewFromFile merged Options.Users into the table, want the file's rows only")
	}
}

func TestNewFromFileRejectsAnEmptyTable(t *testing.T) {
	t.Parallel()

	path := writeUsersFile(t, `{"version": 1, "users": []}`)
	_, err := bearer.NewFromFile(path, bearer.Options{})
	if !errors.Is(err, bearer.ErrNoUsers) {
		t.Errorf("NewFromFile() error = %v, want bearer.ErrNoUsers", err)
	}
	if err != nil && !strings.Contains(err.Error(), path) {
		t.Errorf("NewFromFile() error = %v, want it to name %q", err, path)
	}
}

func TestNewFromFilePropagatesLoadErrors(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	if _, err := bearer.NewFromFile(path, bearer.Options{}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("NewFromFile() error = %v, want it to wrap fs.ErrNotExist", err)
	}
}
