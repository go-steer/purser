# AGENTS.md — purser

Instructions for AI agents working in this repository.

## Start here

[`README.md`](./README.md) for what purser is, and
[`docs/DESIGN.md`](./docs/DESIGN.md) for the design this module implements —
the two mTLS profiles, the separation of connection admission from identity
extraction, and the phase plan. Read the design before adding to the exported
surface, and keep it current in the same PR as the API change it describes.

## What this project is

A Go **library**, `github.com/go-steer/purser`, consumed as a module by every
go-steer service that terminates or dials an authenticated HTTP/SSE connection.
It ships no binary and no image. Its product is the exported API.

## Hard rules (violations are bugs)

- **Identity extraction is unconditional.** Whatever a connection-layer
  authorizer decides about *admitting* a peer, the caller's identity is always
  extracted and passed on. Admission and identity are separate concerns; do not
  collapse them.
- **SPIFFE is the goal, never the requirement.** Certificates issued by a
  standard CA must remain a first-class path. Any API that only makes sense for
  a SPIFFE deployment goes behind its own constructor, not into the common one.
- **No caller-supplied `*tls.Config` for the mTLS profiles.** The PKI and
  SPIFFE profiles verify with opposite `crypto/tls` idioms (`VerifiedChains` is
  populated under one and empty under the other), so the config and the
  authenticator that reads it are constructed as a matched pair. A caller who
  can substitute the config can silently pair a SPIFFE authenticator with a PKI
  listener.
- **No identity from spoofable headers.** An asserted or proxied caller is only
  trusted when the authenticator that verified the connection says it may
  proxy; the resulting auth source must never be re-derived from request
  headers.
- **No service-specific policy.** Session ACLs, role names, and admin lists
  belong to the consuming service. purser supplies the mechanism (identity,
  matchers, rules) and stays out of the vocabulary.

## Build & test

```bash
dev/tools/ci                # full local presubmit sweep, fast-fail order
dev/ci/presubmits/build     # go build ./...
dev/ci/presubmits/test-unit # go test -race ./...
dev/ci/presubmits/vet       # go vet ./...
dev/ci/presubmits/lint-go   # golangci-lint (auto-installs the pinned version)
dev/ci/presubmits/verify-go-format  # gofmt + goimports (fix: dev/tools/fix-go-format)
dev/ci/presubmits/verify-mod-tidy   # go.mod/go.sum are tidy
dev/ci/presubmits/verify-apidiff    # exported-API diff vs the last release tag
dev/ci/presubmits/verify-coverage   # per-package floors (dev/coverage-floors.txt)
dev/ci/presubmits/verify-vuln       # govulncheck
```

The default test run needs no network and no credentials. Certificates that
tests need are minted in-process — do not check fixture keys into the repo.

## Conventions

- Mirror `core-agent` / `core-tui` / `switchboard` conventions (package layout,
  `dev/` tooling); a maintainer of one repo should recognize the others. Fixes
  should be one-line ports.
- **License headers everywhere.** The Apache 2.0 boilerplate attributed to
  Google LLC sits atop every Go / shell / YAML source file. Markdown carries no
  header. `goheader` enforces it on `.go`; run `dev/tools/add-license-headers`
  for the rest.
- **Conventional Commits**, small self-contained commits, bodies explaining
  *why* + the verification done. **DCO sign-off** (`git commit -s`).
- **No `Co-Authored-By` trailer and no assistant attribution** — in commits, PR
  titles/bodies, or any committed/published artifact. Author under your own name.
  See [`CONTRIBUTING.md`](./CONTRIBUTING.md).
- **Tests before merging.** Every new package ships unit tests; a bug fix ships a
  regression test. A new package also needs a floor in `dev/coverage-floors.txt`
  — `verify-coverage` fails on a package that has none, rather than letting it
  in unmeasured. Lowering an existing floor is allowed and belongs in the same
  PR as the code that made it necessary, with a comment saying why.

## How we develop

Single long-lived branch `main`; short-lived `feat/…` `fix/…` `chore/…`
`docs/…` branches → PR → merge once the required CI checks are green. Rebase,
don't merge; `--force-with-lease` on your own branch is fine, never force-push
`main`. Full contributor flow + DCO in [`CONTRIBUTING.md`](./CONTRIBUTING.md).

Conventions worth knowing at agent prompt time:

- **Run presubmits before every push.** `dev/tools/ci` runs the same scripts CI
  runs (`dev/ci/presubmits/*`). A green local run is the green remote run —
  skipping them ships preventable red builds.
- **Adversarial-review gate before every PR.** Before `gh pr create` on any
  change touching Go code: run a skeptic subagent over the staged diff
  (correctness, races, API misuse — verified against real dependency source, not
  memory), fix or pin every finding, and record the outcome in the PR body under
  an `## Adversarial review` heading. For bug fixes, additionally **verify the
  new regression test FAILS on the pre-fix code** (run it against the parent
  commit) — a test that passes on the buggy code is documentation, not a gate.
  Enforced by this convention plus the `review-gate` **required** CI check
  (Go-touching PRs fail without the section; docs-only and bot PRs exempt).
  Optionally copy `dev/claude/settings-review-gate.json` into your local,
  untracked `.claude/settings.json` for a Claude Code hook that blocks
  `gh pr create` at the terminal before CI ever sees it.
- **Admin merge protocol.** `gh pr merge <N> --admin --squash --delete-branch`
  is the maintainer path once CI is green. It is **not** a way to skip review —
  the adversarial gate + green CI *are* the review on this single-maintainer
  repo. Never merge unverified CI.
- **The exported API is the product.** Changing it is a reviewable act:
  `dev/tools/verify-apidiff` reports every change since the last release tag and
  fails on incompatible ones that `dev/api-breaks.txt` does not acknowledge. See
  "Changing the exported API" in [`CONTRIBUTING.md`](./CONTRIBUTING.md).
- **`[Unreleased]` grows on every merged PR.** Any user-visible change adds a
  bullet under `## [Unreleased]` in `CHANGELOG.md` as part of the PR.
- **Harness settings are not committed.** `.claude/` (and a personal `CLAUDE.md`)
  are git-ignored; the repo-native enforcement is this file + the required CI
  check. The only checked-in Claude Code config is the opt-in sample under
  `dev/claude/`.

## Current state

**Phase 1a complete.** The identity contract, `authtest` and its conformance
suite, the bearer-token table, both mTLS profiles, `client`, `httpmw`,
`authn/oidc`, and `authz` are all in, with a worked example under `examples/`
and per-package coverage floors over the lot. Nothing is tagged, so the
exported API is still free to move — but it is what phase 2 will migrate
`core-agent` and `mast` onto, so changing it is a design conversation, not a
refactor. Phase 1b (service-mesh / sidecar-terminated TLS) is optional and
unstarted; see the phase table in [`docs/DESIGN.md`](./docs/DESIGN.md).
