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

- `authn/mtls`: the PKI profile — `NewPKI` returns a server `*tls.Config`
  requiring a verified client certificate *and* the `*PKIAuth` that reads an
  identity from it, as a matched pair. It is one decision: the config's
  `ClientAuth` mode determines where the verified certificate can be found, and
  the authenticator reads exactly that place, never `PeerCertificates`, which
  holds whatever the peer sent. The identity field is configured explicitly
  (`san_email`, `san_uri`, `san_dns`, `subject_cn`, `subject_dn`) with no
  fallback chain, and a field carrying zero or several values is rejected
  rather than guessed at. `Caller.Labels` carry `cert.issuer_dn`,
  `cert.serial`, and `cert.not_after` for audit. The TLS floor defaults to
  **1.3** — core-agent's server sets 1.2, and a deployment that needs 1.2 now
  asks for it explicitly.
- `authn/mtls`: `CertMatcher` and its combinators, the connection-admission
  (Layer A) check applied to the verified leaf during the handshake:
  `MatchCertIssuerDN`, `MatchCertOrganization`, `MatchCertOrganizationalUnit`,
  `MatchCertEmailSAN`, `MatchCertEmailDomain`, `MatchCertDNSSAN`,
  `MatchCertDNSSuffix`, `MatchCertFunc`, composed with `MatchCertAll` /
  `MatchCertAnyOf`. The domain matchers are anchored — on the last `@` and on a
  label boundary respectively — because a plain suffix test admits
  `alice@notexample.com` and `evil-svc.cluster.local`. Admission is enforced in
  `tls.Config.VerifyConnection` rather than the more obvious
  `VerifyPeerCertificate`, which crypto/tls skips on a resumed session — a
  matcher installed there would stop applying as soon as a client reconnected
  with a ticket.

- `authn/mtls`: the SPIFFE profile — `NewSPIFFE` returns the same matched pair
  for X.509-SVIDs, taking an `x509svid.Source` for the server's own SVID and an
  `x509bundle.Source` for the trust anchors, both read per handshake so SVID
  rotation and bundle withdrawal need no restart. `Caller.Identity` is the full
  `spiffe://…` ID and `Caller.Labels` add `spiffe.trust_domain` and
  `spiffe.path` alongside the same `cert.*` audit trio the PKI profile sets.
  It deliberately does **not** use go-spiffe's `MTLSServerConfig`: that helper
  verifies in `VerifyPeerCertificate`, which crypto/tls skips on a resumed
  session, and under `RequireAnyClientCert` there is no `ClientCAs` re-check to
  fall back on — so an expired SVID or a withdrawn authority would keep working
  for the life of a session ticket. purser verifies in `VerifyConnection`
  instead, with go-spiffe's own `x509svid.Verify` doing the work. A test pins
  the upstream gap so this can be revisited if it closes.
- `authn/mtls`: `SPIFFEAuth.Authenticate` re-verifies the peer's certificates
  against the trust bundle on every request rather than trusting the handshake.
  The SPIFFE profile leaves `VerifiedChains` empty by design, so unlike the PKI
  profile there is no verified-state flag to read; re-verifying is what makes a
  mispaired config fail closed, and it lets bundle rotation and SVID expiry take
  effect on the next request rather than the next handshake — which on a
  long-lived streaming connection may be hours away.
- `authn/mtls`: SPIFFE admission matchers — `MatchPathSegments`,
  `MatchPathPrefix`, `MatchGKEWorkload`, composed with `MatchAll` /
  `MatchAnyOf`. They are `spiffeid.Matcher` values, so they compose with
  go-spiffe's `MatchID`, `MatchOneOf`, and `MatchMemberOf` rather than
  re-exporting them. Path segments are passed variadically and validated
  individually, so a segment interpolated from configuration cannot smuggle a
  separator in and widen the rule, and the prefix matcher is anchored on a
  segment boundary — `MatchPathPrefix("ns", "prod")` does not admit
  `/ns/production`. An empty or invalid segment list, or an unset
  `MatchGKEWorkload` argument, admits nobody.

- `client`: the dialling half of `authn/mtls`. `client.NewPKI` and
  `client.NewSPIFFE` return a `*tls.Config` that pairs with a listener from the
  matching server constructor, and `client.Transport` wraps one in an
  `http.Transport` — the helper exists because `net/http` upgrades to HTTP/2
  automatically only while `TLSClientConfig` is nil, so setting one, as mTLS
  requires, silently drops the connection to HTTP/1.1 unless
  `ForceAttemptHTTP2` is also set. Both profiles verify the server from
  `VerifyConnection`, mirroring the server side: `NewSPIFFE` deliberately does
  **not** return go-spiffe's `tlsconfig.MTLSClientConfig`, which sets
  `InsecureSkipVerify` and verifies in `VerifyPeerCertificate` — skipped on a
  resumed session, leaving a session ticket as the entire proof of the server's
  identity for that ticket's lifetime. A test dials, empties the trust bundle,
  and asserts purser rejects the resumed connection; a sibling test pins that
  the upstream helper accepts it. `SPIFFEOptions.Authorize` is required where
  the server's `Admit` is optional — a server admits a population, a client
  dials one known service — and a caller who means "any SVID" passes
  `spiffeid.MatchAny()` in the source. `PKIOptions.RootCAs` is likewise
  required: nil is not read as the system pool, which for an internal service
  would trust every CA a browser does. Neither constructor installs
  `EncryptedClientHelloRejectionVerify`, although `crypto/tls` skips
  `VerifyConnection` on the ECH-rejected path too: that path cannot complete a
  handshake — the TLS 1.3 client returns `*tls.ECHRejectionError` regardless of
  what the hook decides, and crypto/tls will not offer ECH below TLS 1.3, which
  both constructors' `MinVersion` rules out — and the hook is called before
  `PeerCertificates` is populated, so it could not verify anything if it were
  reachable. Installing one only replaces a clean `ECHRejectionError`, carrying
  the retry configs a client needs, with a misleading certificate error. Tests
  pin both facts against real handshakes so a change in Go is caught.
  `Transport` clones the config it installs as well as the transport it starts
  from, and clips its `NextProtos` — net/http's HTTP/2 setup appends to that
  slice in place and `tls.Config.Clone` shares its backing array, so a shared
  config would acquire ALPN protocols its owner never asked for. It panics on a
  nil config rather than dial with the system roots and no client certificate.
- `authn/mtls`: `SPIFFEFileSource`, an `x509svid.Source` and `x509bundle.Source`
  backed by files on disk and reloaded on an interval. GKE Managed Workload
  Identity exposes no SPIFFE Workload API socket — its CSI driver mounts
  `certificates.pem`, `private_key.pem`, and `ca_certificates.pem` read-only
  under `/var/run/secrets/workload-spiffe-credentials` and rewrites them in
  place on rotation — so `workloadapi.X509Source` cannot be used there.
  `GKEFileOptions` fills in that layout. A failed reload keeps the last good
  credential and reports through `OnError`, so a half-written file cannot take a
  healthy workload offline. Torn reads are *not* self-detecting — go-spiffe's
  PEM reader discards a trailing partial block without error, so a half-written
  chain or bundle parses cleanly as a shorter valid one, and the sharp case is a
  CA rotation where the bundle grows from one anchor to two and a torn read
  lands on new-anchor-only, rejecting every existing peer with nothing logged.
  So each generation is read twice and the bytes compared, and an empty bundle
  is rejected outright. Retention is bounded by expiry on the SVID half:
  `GetX509SVID` refuses to serve a leaf that has actually expired rather than
  collect a TLS alert from the peer. The bundle half has no such bound and
  cannot get one — withdrawing a trust anchor is an edit to a file, not an
  expiry — so a revoked authority stays honoured for as long as the mount is
  unreadable, and `OnError` is the only signal; deployments that pair this
  bundle source with a `workloadapi.X509Source` for the SVID should alert on it.
  The bundle is cloned per call, because `x509bundle.Bundle` looks immutable and
  is not. `OnError` runs on one goroutine of the source's own, serialised and
  with panics recovered, so a callback that blocks cannot freeze rotation or
  accumulate a goroutine per failed reload, one that calls `Close` cannot
  deadlock, and one that panics cannot take the process down; errors raised
  while a callback is blocked are dropped once a short queue fills. Reads after
  `Close` fail, matching `workloadapi.X509Source`. `Close` waits for the reload
  goroutine and that wait is unbounded — a mount wedged inside `os.ReadFile`
  blocks it. `TrustDomain` is required and checked against the loaded SVID,
  because PEM on disk says nothing about which trust domain it belongs to and
  the symptom of getting it wrong is a remote peer's rejection.

- `examples/`: a hello-world REST/JSON server and client — service to service,
  no human anywhere — deployed four ways over both mTLS profiles: locally, on
  Kubernetes with cert-manager, on Kubernetes with SPIRE, and on GKE with
  managed workload identity. Every cell deploys *two* clients, and the second
  one holds a current certificate from the same CA and is refused during the
  handshake: chaining to the shared internal CA, or membership in a trust
  domain, is not an authorization decision, and a deployment that treats it as
  one admits every workload that CA serves. `examples/local/demo` mints
  throwaway credentials, runs both clients against a loopback listener, and
  asserts that the authorized one got in and the other did not; it needs no
  root, no network and no infrastructure, and it runs on every build as the new
  `smoke` presubmit — the seam the unit suite cannot reach, two processes
  talking over a real socket. The SPIRE and GKE cells share one code path
  because both read credentials from files: a spiffe-helper sidecar writes the
  three GKE file names into a memory-backed volume, so the GKE manifest is the
  SPIRE one with the sidecar deleted. `workloadapi.X509Source` is deliberately
  not used — GKE managed workload identity publishes no Workload API socket to
  dial, and it would pull gRPC and protobuf into the module graph of a library
  many services depend on.

### Changed
- `authtest.CA` is now a thin wrapper over an internal, error-returning CA core
  (`internal/ca`), so example binaries and local development commands can mint
  credentials without linking `testing`. The exported `authtest` surface is
  unchanged.
- The TLS version floor moved to `internal/tlsfloor`, shared by the client and
  server constructors so the two cannot drift apart on what they accept.

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
