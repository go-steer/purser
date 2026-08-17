# Contributing to purser

Thanks for contributing. purser follows the same contributor flow as
[core-agent](https://github.com/go-steer/core-agent) — a maintainer of one repo
should recognize the other.

## Workflow

- Single long-lived branch: `main`. Work on short-lived feature branches
  (`feat/…`, `fix/…`, `chore/…`, `docs/…`) → PR against `main` → merge
  once CI's required checks are green.
- **Rebase, don't merge.** Keep feature branches rebased on `main`;
  `git push --force-with-lease` on your own branch is normal. Never
  force-push `main`.

## Commits

- **Conventional Commits** subject lines: `feat:`, `fix:`, `docs:`,
  `chore:`, `refactor:`, `test:`, `ci:`, `build:`. Bodies explain *why*
  and call out the verification done.
- **DCO sign-off** on every commit: `git commit -s` (adds a
  `Signed-off-by:` trailer certifying the [Developer Certificate of
  Origin](https://developercertificate.org/)).
- **No `Co-Authored-By` trailer, and no assistant attribution anywhere.**
  Maintainer preference: author the work under your own name. Do not add
  `Co-Authored-By:` lines, "Generated with …" footers, or any
  tool/assistant credit to commits, PR titles/bodies, or other committed
  or published artifacts.

## Before you push

- Run `dev/tools/ci` — the full presubmit sweep, the same scripts CI
  runs (`dev/ci/presubmits/*`). A green local run is the green remote
  run.
- **Adversarial-review gate** on any PR touching Go code — see
  [`AGENTS.md`](./AGENTS.md) "How we develop". Record the outcome under an
  `## Adversarial review` heading in the PR body; the `review-gate`
  required CI check enforces it.

## Changing the exported API

purser is consumed as a Go module, so the exported surface *is* the
product: a removed field or a changed signature breaks a consumer's build
at `go get`. `dev/tools/verify-apidiff` compares the module's exported API
against the last release tag and fails on incompatible changes that
[`dev/api-breaks.txt`](./dev/api-breaks.txt) does not acknowledge.

Pre-1.0 the project reserves the right to break the surface at a minor
version — but "you may break it" is not "you may break it silently".
To make a deliberate break:

1. Run `dev/tools/verify-apidiff` locally. Copy the lines it prints under
   *Incompatible changes* into `dev/api-breaks.txt`, minus the leading `- `.
2. Add a `#` comment above them naming the PR or issue and the reason.
3. Commit both in the PR that makes the change, and record it under
   *Changed* or *Removed* in `CHANGELOG.md`.

Cutting a release empties the file: once the tag moves, those breaks sit
behind the new baseline, and a leftover entry would silently permit a
second, unrelated removal.

Prefer not to need the escape hatch. Add an option to a struct rather than
a parameter to a function; deprecate with an alias before removing.

## Tests

Every new package ships with unit tests. A new feature without a test
is not done; a bug fix without a regression test lets the bug come back.

Auth code has a particular failure mode: a test that only asserts the
happy path passes just as well against a check that never runs. Every
verification path needs its negative case — the wrong CA, the expired
SVID, the peer whose identity the authorizer rejects — and an assertion
that the call *failed*, not merely that it returned something.

Mint certificates in-process from a test CA. No private keys in the repo,
not even expired ones.

## License

By contributing you agree your contributions are licensed under the
project's [Apache 2.0](./LICENSE) license. Every Go / shell / YAML source
file carries the Apache 2.0 header attributed to Google LLC.
