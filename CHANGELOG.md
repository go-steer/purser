# Changelog

All notable changes to purser are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because purser is consumed as a Go module, entries under **Changed** and
**Removed** are the release notes a consumer reads before upgrading. An
incompatible change to the exported API is recorded here *and* acknowledged in
[`dev/api-breaks.txt`](./dev/api-breaks.txt) — see "Changing the exported API"
in [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## [Unreleased]

### Added (scaffold)
- Initial scaffold: empty `github.com/go-steer/purser` module, Apache 2.0
  license, and `doc.go`.
- Contributor / agent guardrails ported from core-agent, core-tui and
  switchboard: `AGENTS.md` "How we develop", `CONTRIBUTING.md` (DCO,
  Conventional Commits, no attribution, the apidiff flow), `dev/tools/*` +
  `dev/ci/presubmits/*` + `dev/tools/ci`, the `review-gate` required CI check,
  and the opt-in `dev/claude/settings-review-gate.json` hook sample.
- `dev/tools/verify-apidiff` + `dev/api-breaks.txt`: the exported surface is
  the product, so every change to it is reported against the last release tag
  and incompatible ones fail unless acknowledged in the same PR.
- `docs/DESIGN.md`: the design of record — motivation, the two mTLS profiles
  and why they verify with opposite `crypto/tls` idioms, the admission /
  identity split, the phase plan, and the verification each phase owes.
