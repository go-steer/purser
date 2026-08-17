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

### Added
- `purser.Caller`, the identity every consumer reads: an `Identity` string,
  free-form `Labels`, and an `Admin` bit set by policy rather than by a
  credential's own claim. `Caller.Clone` is the antidote to handing every
  request a map into an authenticator's own table.
- `purser.AuthSource`: the typed verdict for *how* a request was
  authenticated. `mtls` and `spiffe` are deliberately distinct values, and the
  wire strings match what core-agent's `/whoami` already reports so phase 2 is
  a no-op for existing clients. It rides on a private context key, so it can
  only be written by the code that performed the verification.
- Sentinel errors — `ErrUnauthenticated`, `ErrAssertedCallerForbidden`,
  `ErrAssertedCallerUnknown` — plus the `Caller` and proxy-identity context
  plumbing.
- `authn`: the `Authenticator` contract, with `Source()` on the base interface
  so a new implementation cannot fall into a middleware type switch's default
  arm and mis-report itself. `AuthenticatorWithProxy`, `IdentityLookup`, and
  `CredentialGate` are the optional extensions; `authn.Anonymous` is the first
  implementation.
- `authtest`: an in-memory CA (`NewCA`, `Issue`, `IssueClient`, `IssueServer`,
  including URI SANs for SVID-shaped certificates) and
  `RunAuthenticatorSuite`, the conformance suite every authenticator in this
  module and in consuming repositories is expected to pass. The suite's own
  tests run each check against a deliberately broken authenticator and assert
  the failure is reported.

- `authn/bearer`: the static token table, ported from core-agent's `pkg/auth`
  so phase 2 is a no-op for deployments running one today. Same `users.json`
  schema (version 1) and the same 0600-or-stricter permission requirement, with
  three corrections: the table is keyed by a SHA-256 digest rather than
  compared token by token, `LookupIdentity` clones the Caller it hands out
  (core-agent's returns the table's own `Labels` map), and the `Authorization`
  scheme is matched case-insensitively per RFC 7235 §2.1. Loading also rejects
  a token carrying leading or trailing whitespace — the header parser strips
  it, so such a row could never be presented and the operator would see a user
  who silently cannot log in. `NewFromFile` fails
  on a file holding zero rows (`ErrNoUsers`); `New` tolerates an empty table,
  which is legitimate when a second authenticator supplements it.

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
