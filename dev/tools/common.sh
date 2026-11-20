#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Shared helpers for dev/tools/* scripts.
#
# Source this from each tool with:
#   . "$(dirname "$0")/common.sh"
#
# Provides:
#   repo_root          — absolute path to the git working tree root
#   resolve_toolchain  — the Go version go.mod pins us to (e.g. 1.26.11)
#   ensure_tool        — go install <pkg>@<ver> if the binary isn't on PATH
#   run_step           — run a command + print a "▸ name" header (for ci aggregator)
#
# Sourcing this also exports GOTOOLCHAIN, pinning every go command these
# scripts run to the toolchain go.mod names.

set -euo pipefail

_COMMON_SH_DIR="$(CDPATH="" cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

repo_root() {
  git -C "$_COMMON_SH_DIR" rev-parse --show-toplevel
}

# resolve_toolchain — print the Go toolchain version go.mod pins us to,
# without the `go` prefix (e.g. 1.26.11). Prefers `toolchain goX.Y.Z` over
# the `go X.Y.Z` compatibility floor so stdlib CVE fixes take effect without
# forcing downstream importers onto a higher minimum `go` directive.
resolve_toolchain() {
  local gomod="${1:-}" root version
  if [[ -z "$gomod" ]]; then
    root="$(repo_root)" || return 1
    gomod="${root}/go.mod"
  fi
  if [[ ! -f "$gomod" ]]; then
    echo "resolve_toolchain: no such file: ${gomod}" >&2
    return 1
  fi
  version=$(grep -oE '^toolchain go[0-9]+\.[0-9]+(\.[0-9]+)?$' "$gomod" \
            | sed -n '1p' | sed 's/^toolchain go//' || true)
  if [[ -z "$version" ]]; then
    version=$(grep -oE '^go [0-9]+\.[0-9]+(\.[0-9]+)?$' "$gomod" \
              | sed -n '1p' | awk '{print $2}' || true)
  fi
  if [[ -z "$version" ]]; then
    echo "resolve_toolchain: no toolchain or go directive in ${gomod}" >&2
    return 1
  fi
  echo "$version"
}

# pin_toolchain — export GOTOOLCHAIN=go<pinned> unless the caller has
# already chosen one. GOTOOLCHAIN=auto treats go.mod's toolchain directive
# as a minimum, which causes source-mode govulncheck to scan a newer host
# stdlib and breaks tools compiled against Go 1.26 when the host has 1.27+.
pin_toolchain() {
  if [[ -n "${GOTOOLCHAIN:-}" ]]; then
    return 0
  fi
  local version goroot
  version=$(resolve_toolchain) || return 1
  export GOTOOLCHAIN="go${version}"
  goroot="$(go env GOROOT 2>/dev/null || true)"
  if [[ -n "$goroot" && -x "${goroot}/bin/go" ]]; then
    export PATH="${goroot}/bin:${PATH}"
  fi
}

pin_toolchain

# ensure_tool <bin-name> <go-install-target>
#
# Checks for <bin-name> on PATH; if missing, installs the pinned version
# via `go install`. Honors GOBIN, falls back to $(go env GOPATH)/bin.
# After install, prepends GOBIN to PATH for the calling shell.
ensure_tool() {
  local name="$1"
  local target="$2"
  if command -v "$name" >/dev/null 2>&1; then
    return 0
  fi
  local gobin
  gobin="${GOBIN:-$(go env GOPATH)/bin}"
  # Already installed at GOBIN but not on PATH? Just expose it.
  if [[ -x "$gobin/$name" ]]; then
    export PATH="$gobin:$PATH"
    return 0
  fi
  echo "▸ $name not found — installing $target into $gobin" >&2
  GOBIN="$gobin" go install "$target"
  export PATH="$gobin:$PATH"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "ensure_tool: $name still missing after install" >&2
    return 1
  fi
}

# run_step <label> <command...>
#
# Runs the command and prints a tidy header. Used by the ci aggregator
# so each check has a visible boundary in the output. Exit code is
# propagated.
run_step() {
  local label="$1"; shift
  printf '\n\033[1m▸ %s\033[0m\n' "$label"
  "$@"
}
