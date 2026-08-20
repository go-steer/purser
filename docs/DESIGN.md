# purser: a shared authn/authz library for go-steer agents

Design doc for extracting core-agent's caller-identity layer into this
module, and for replacing the static bearer-token table with identity
derived from credentials the infrastructure already issues — SPIFFE
X509-SVIDs, ordinary CA-issued client certificates, and OIDC tokens.

**Status:** accepted (2026-08-17); phase 1a in progress. This document is
purser's design of record; the implementation lands as separate PRs
across the phases below, and any deviation is recorded here in the same
PR that makes it.

References into core-agent are permalinks pinned to
[`core-agent@09b6cd1`](https://github.com/go-steer/core-agent/tree/09b6cd1d9c97fa1e2673bac2e664d97579c68b24)
(2026-08-17), so the line numbers stay meaningful as that repo moves on.
Related core-agent design docs:
[`multi-session-design.md`](https://github.com/go-steer/core-agent/blob/main/docs/multi-session-design.md)
is the current source of truth for `pkg/auth` and what shipped in v2.4;
[`attach-mode-design.md`](https://github.com/go-steer/core-agent/blob/main/docs/attach-mode-design.md)
covers the transport that this sits behind.

## Motivation

Authentication on core-agent's attach (HTTP/SSE) endpoint has two
layers, and the wrong one is load-bearing for identity.

The **transport gate** — `AuthConfig` in
[`pkg/attach/auth.go`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/auth.go)
— already treats the bearer token as optional.
[`AuthConfig.Middleware`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/auth.go#L119)
only checks a token when one is configured, and
[`listenerAuthenticated`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/server.go#L212)
accepts a configured `ClientCAFile` as a sufficient credential gate on
its own:

```go
func listenerAuthenticated(opts Options) bool {
	if opts.Auth.BearerToken != "" {
		return true
	}
	if opts.Auth.ClientCAFile != "" {
		return true
	}
	return opts.MultiSessionEnabled && !opts.AllowAnonymous
}
```

So mTLS-without-a-bearer-token already works at the transport layer.
That part of the goal is done.

The **identity layer** —
[`pkg/auth`](https://github.com/go-steer/core-agent/tree/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/auth)
plus `attach.multi_session` — is the problem. It ships exactly one
authenticator: `bearer_table`, a static token→identity map loaded from
`users.json`. [`Config.Validate` hard-rejects every other
kind](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/config/config.go#L1424):

> `attach.multi_session.auth.kind=%q is not shipped in this version
> (only %q is supported; oidc/mtls/k8s_sa are designed but deferred)`

The consequence: **mTLS today authenticates without identifying.** The
handshake verifies the client certificate and
[`pkg/attach/caller_middleware.go:143`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/caller_middleware.go#L143)
stamps `source: "mtls"` on `/whoami`, but the resolved `Caller` is still
`auth.Anonymous`. Every mTLS client collapses into one principal, which
collapses session ACLs, audit attribution, and per-caller rate limiting
along with it.

**A per-user token table is not viable in production.** It is a fine
testing affordance and a bad production identity source: it must be
provisioned, distributed, rotated, and revoked by hand, and it scales
with headcount. The same objection applies to the two exact-match
identity lists next to it —
[`AdminIdentities`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/config/config.go#L1095)
and
[`ProxyIdentities`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/config/config.go#L1113).

### Why a shared library rather than a core-agent change

Two findings turn this from a core-agent change into an extraction.

**mast has already forked it, and hasn't drifted yet.**
[`mast/pkg/auth/*`](https://github.com/go-steer/mast/tree/main/pkg/auth)
carries the line
`// Originally derived from go-steer/core-agent@25d8531cf8d1d69459471009a9e7e2e9b0dff1e2`
(fork point 2026-07-29) on `authenticator.go`, `authorize.go`, and
`users.go`; the auth slice of `mast/pkg/attach/` came across with it.
`git log 25d8531..HEAD -- pkg/auth` in core-agent is empty — the files
are still byte-identical apart from that provenance line. Extracting now
is a mechanical import rewrite. Extracting after the two copies diverge
means reconciling real behavioral drift in security-sensitive code,
which is the expensive version of this task.

**k8s-lookout is auth-blocked and dependency-thin.** Its MCP server
(`internal/mcpserver/serve.go:46`) has no authentication at all and is
pinned behind a loopback check as its entire security model. It depends
on core-agent only for `pkg/telemetry`; pulling in all of core-agent
(ADK, genai, bubbletea) to obtain a `Caller` type is a bad trade it will
reasonably refuse to make.

There are two more prospective consumers — core-agent-tui and
switchboard — that need the *client* half rather than the server half.

A shared module also buys the thing no single consumer would fund on its
own: a reusable conformance suite and an in-memory CA, so every
authenticator in every repo is tested against the same adversarial cases
over real TLS handshakes.

## Decisions

| Decision | Choice |
|---|---|
| Module | New repo, `github.com/go-steer/purser` |
| v0.1 scope | Server substrate + HTTP middleware + outbound client credentials |
| Phase 1a | Build the library; daemon-terminated TLS (required) |
| Phase 1b | Service-mesh / sidecar-terminated TLS (optional) |
| Phase 2 | core-agent and mast migrate onto it |
| mTLS profiles | SPIFFE **and** standard-CA PKI, both first-class |
| SPIFFE library | `github.com/spiffe/go-spiffe/v2` v2.6.0 |
| Populations | Services (mTLS, either profile) and humans (OIDC) |
| Cert identity | SPIFFE URI SAN; configurable subject field for PKI |
| `bearer_table` | Ported into purser, marked deprecated / dev-and-test |

On the last row: the bearer table moves rather than being left behind,
because phase 2 needs existing `multi_session` deployments to migrate
with zero behavior change, because mast's fork already contains it, and
because it remains genuinely useful for testing. It ships with a
deprecation notice and is not the recommended production path. This is
reversible if it turns out to be the wrong call — nothing else depends
on where it lives.

## Two mTLS profiles, one identity contract

SPIFFE is the target. Nothing may *require* it: certificates issued by
an ordinary internal CA must work equally well. The two profiles verify
differently, and encapsulating that difference correctly is the single
most important thing in this design.

| | **PKI profile** (standard CA) | **SPIFFE profile** (go-spiffe) |
|---|---|---|
| `tls.Config` from | stdlib, `ClientCAs` pool | stdlib + `tlsconfig.GetCertificate(svid)`, see below |
| `ClientAuth` | `RequireAndVerifyClientCert` | `RequireAnyClientCert` |
| Who verifies | Go's TLS stack | `x509svid.Verify` against the bundle, from `VerifyConnection` |
| `r.TLS.VerifiedChains` | **populated** | **empty** |
| Read identity from | `VerifiedChains[0][0]` | `PeerCertificates`, re-verified |
| Identity field | configured: SAN email / URI / DNS / CN / DN | URI SAN via `x509svid.IDFromCert` |
| Trust refresh | static CA file (+ optional CRL) | `workloadapi.X509Source`, auto-rotating |
| Revocation | CRL / OCSP (Go does neither automatically) | short-lived, rotating SVIDs |

The asymmetry is not incidental.
[`tlsconfig.HookMTLSServerConfig`](https://github.com/spiffe/go-spiffe/blob/v2.6.0/spiffetls/tlsconfig/config.go#L123)
sets `config.ClientAuth = tls.RequireAnyClientCert` — deliberately *not*
`RequireAndVerifyClientCert` — and installs a `VerifyPeerCertificate`
that discards Go's computed chains entirely and calls
`x509svid.ParseAndVerify` against the SPIFFE bundle instead. That is why
`VerifiedChains` is empty on an accepted SPIFFE connection, and why
reading `PeerCertificates[0]` is the *correct* move there while being an
authentication bypass anywhere else.

**purser does not use that hook.** `NewSPIFFE` builds the config itself —
`RequireAnyClientCert`, `tlsconfig.GetCertificate(svid)` to present the
server's own SVID, and `x509svid.Verify` plus the authorizer inside
`VerifyConnection` — because `VerifyPeerCertificate` is not called on a
resumed session (see "admission runs in `VerifyConnection`" below), and
under `RequireAnyClientCert` there is no `ClientCAs` pool for crypto/tls
to fall back on either. A server built on the upstream helper therefore
verifies the peer's SVID on the first handshake and on no handshake
after it, for the lifetime of the ticket. Verification is go-spiffe's
code either way; only the hook it hangs from is purser's, and there is
exactly one of them.
`authn/mtls/spiffe_test.go` pins the gap against go-spiffe itself, so if
upstream closes it the test fails and the deviation can be revisited.

### The API consequence: config and authenticator are a matched pair

Because "where does the verified identity live" differs per profile,
**no code may infer verification from the shape of `r.TLS`.** The
library constructs both halves together and binds them:

```go
// The Authenticator knows which profile its tls.Config enforces,
// so it reads the correct field. You cannot obtain one without
// the other.
tlsCfg, auth, err := mtls.NewPKI(mtls.PKIOptions{...})
tlsCfg, auth, err := mtls.NewSPIFFE(mtls.SPIFFEOptions{...})
```

**One constructor per profile, not one with a `Profile` switch.** The
options are disjoint — `ClientCAs` and `Subject` mean nothing to SPIFFE,
an `x509svid.Source` means nothing to PKI — and a single struct holding
both makes "set the wrong profile's field" a compile-clean way to end up
with a listener verifying something other than what the operator
configured. Separate constructors turn that into an unused field the
reader can see, and let each one reject its own options completely.

This makes the dangerous case structurally unreachable. Reading
`PeerCertificates[0]` is safe *only* because the paired config
guarantees the handshake verified it; under `RequireAnyClientCert` with
no verify callback, `PeerCertificates[0]` is attacker-chosen. purser
therefore refuses a caller-supplied `tls.Config` on either profile. The
middleware still defends in depth: no peer certificate means anonymous,
never a guess.

The two profiles fail differently when that pairing is broken anyway,
and only one of them can detect it. A `PKIAuth` on a config that does
not verify finds `VerifiedChains` empty and 401s. A `SPIFFEAuth` has no
such signal — `VerifiedChains` is empty on a *good* SPIFFE connection —
so it re-runs `x509svid.Verify` against its own bundle on every request
rather than infer that the handshake did. That costs a chain
verification per request and buys a Layer B that is safe on its own
terms; it also means a withdrawn trust anchor or an expired SVID takes
effect on the next request rather than the next handshake, which on a
long-lived SSE stream may be hours away. `SPIFFEOptions.Admit` is *not*
re-applied there: admission is a decision about a connection, and
per-request policy is `authz`'s.

### Layer A and Layer B must not be conflated

**Layer A — connection admission.** Decides whether the TLS handshake
completes at all. A rejected peer never reaches HTTP. This is coarse,
per-listener policy: which trust domains, which namespaces, which
issuers.

**Layer B — identity extraction.** Runs unconditionally on every
admitted connection, produces the `Caller`, and feeds ACLs, audit, and
rate limiting.

Layer B is **never conditional on Layer A's configuration**. Even a
wide-open admission policy yields a fully populated `Caller`. Layer B is
the invariant; Layer A is policy. Conflating them is how systems end up
with "we allow everyone from this trust domain, so we stopped recording
who."

### What this means for core-agent

These are **not bugs today.**
[`pkg/attach/auth.go:88`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/auth.go#L88)
sets `RequireAndVerifyClientCert`, so the current PKI-only code is
correct, and its comment says exactly why:

> `VerifiedChains` is populated only when OUR listener verified the
> client cert against its configured CA (`ClientAuth =
> RequireAndVerifyClientCert`). A merely PRESENTED-but-unverified
> certificate never sets it […]

They are latent incompatibilities that bite the moment a SPIFFE listener
exists alongside:

- [`pkg/attach/caller_middleware.go:143`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/caller_middleware.go#L143)
  infers `source = "mtls"` from `len(r.TLS.VerifiedChains) > 0`. Correct
  for PKI; silently reports `anonymous` for SPIFFE.
- [`listenerAuthenticated`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/server.go#L212)
  gates on `ClientCAFile != ""`. There is no CA file in the SPIFFE case,
  so a non-loopback bind with working SPIFFE mTLS would be refused as
  unauthenticated.

Both are fixed in phase 2 by asking the authenticator what it enforces
instead of sniffing config fields.

## Phase 1a — the library (required)

### Layout

```
purser/
  go.mod                     module github.com/go-steer/purser
  caller.go                  Caller, context helpers, sentinel errors
  source.go                  AuthSource enum
  authn/
    authn.go                 Authenticator, AuthenticatorWithProxy, CredentialGate
    bearer/                  BearerTokenAuth + users.json loader (DEPRECATED)
    mtls/
      mtls.go                shared labels, TLS floor, connection state
      pkix.go                NewPKI() -> (*tls.Config, *PKIAuth) (stdlib only)
      spiffe.go              NewSPIFFE() -> (*tls.Config, *SPIFFEAuth)
      spiffefiles.go         SPIFFEFileSource: file-backed, reloading SVID + bundle
      match.go               admission matchers, both profiles
    oidc/
      oidc.go                Options, New() -> *Auth, token extraction + JWS verify
      discovery.go           the well-known document; issuer check
      keyset.go              JWKS cache: demand + age refetch, floor, single flight
      claims.go              claim validation, identity resolution, labels
  authz/
    authz.go                 Action, Role, ACL, RoleOf, Allows, Authorize
    rules.go                 Matcher, Rule, Rules: service-wide grants
    authenticator.go         WithRules: a rule set applied to an Authenticator
  httpmw/
    caller.go                caller middleware + auth-source verdict
    csrf.go                  browser write guard
    transport.go             transport gate + bind policy
  client/
    creds.go                 Credentials interface, BearerCreds
    google.go                GoogleOAuthCreds, GoogleIDTokenCreds
    mtls.go                  client-cert transport, both profiles (new)
  authtest/
    conformance.go           suite every Authenticator must pass
    ca.go                    in-memory CA: PKI certs and SPIFFE SVIDs
    issuer.go                fake OIDC issuer (httptest + JWKS)
  internal/
    ca/                      the CA core, error-returning; authtest wraps it
    tlsfloor/                the TLS version floor, shared by client and server
```

**Two internal packages exist to stop a policy from being stated
twice.** `internal/tlsfloor` holds the minimum-version rule, because a
client and a server that disagree about the floor is a defect nobody
notices until the weaker one is the one that matters. `internal/ca`
holds the certificate-minting logic that `authtest` exposes, split out
because `authtest.CA` takes a `testing.TB` and fails a test on error —
correct for tests, useless for an example binary or a local development
command, neither of which should link `testing`. `authtest.CA` is now a
thin wrapper over it and its public surface is unchanged.

### Lifted as-is from core-agent

Ported preserving behavior, so phase 2 is a no-op for existing
deployments:

| From (core-agent@09b6cd1) | To |
|---|---|
| [`pkg/auth/auth.go`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/auth/auth.go) | `purser/caller.go` |
| [`pkg/auth/authenticator.go`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/auth/authenticator.go) | `authn/authn.go` + `authn/bearer/` |
| [`pkg/auth/authorize.go`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/auth/authorize.go) | `authz/authz.go` (matrix preserved, nouns dropped — see [below](#authzauthzgo--the-matrix-without-the-nouns)) |
| [`pkg/auth/users.go`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/auth/users.go) | `authn/bearer/users.go` (keep the 0600 mode check) |
| [`pkg/attach/caller_middleware.go`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/caller_middleware.go) | `httpmw/caller.go` |
| [`pkg/attach/csrf.go`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/csrf.go) | `httpmw/csrf.go` |
| [`pkg/attach/auth.go`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/auth.go) | `httpmw/transport.go`; its [`AuthConfig.LoadTLSConfig`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/auth.go#L61) becomes the PKI profile |
| [`pkg/attach/server.go:212-237`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/server.go#L212-L237) | `httpmw` (`listenerAuthenticated`, `isLoopbackAddr`) |
| [`internal/attachclient/credentials.go`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/internal/attachclient/credentials.go) | `client/` |

Stale framing gets stripped in the move.
[`pkg/auth/auth.go:19`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/auth/auth.go#L19)
still describes the package as "intentionally substrate-only" with
enforcement "layered on in later phases (see issue #162)", and the
`Action` doc says handlers don't enforce these "in α.1". Both are wrong:
the ACL layer is fully wired. The `v2.4`-era version stamps go too.

### `authn/mtls` — PKI profile

Essentially
[`AuthConfig.LoadTLSConfig`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/auth.go#L61)
plus the identity mapping it never had.

Subject extraction is **explicitly configured, with no silent fallback
chain.** A chain like "email SAN, else CN" is an impersonation surface:
if any issuer in the pool can mint a certificate lacking the preferred
field, an attacker picks which field their identity comes from. One
configured source; a certificate that doesn't carry it is rejected.

- `san_email` (rfc822Name) — the natural fit for human operator certs
- `san_uri` — non-SPIFFE URI identities
- `san_dns` — service certs
- `subject_cn` — legacy; supported, documented as discouraged
- `subject_dn` — full RFC 2253 string, when the whole DN is the identity

A field carrying **more than one** value is rejected too, not resolved
by taking the first: two email SANs are two identities, and which one a
request is attributed to must not depend on the order the CA encoded
them in. A multi-name service certificate — the usual Kubernetes shape —
wants `san_uri` or the SPIFFE profile, where the identity is singular by
construction.

`Caller.Labels` carry the issuer DN, serial, and `NotAfter` for audit
(`cert.issuer_dn`, `cert.serial`, `cert.not_after`). Issuer plus serial
is what a revocation list is keyed by, and the pair an audit record
needs to trace a request back to an issued credential.

**The TLS floor defaults to 1.3, not 1.2.** core-agent's
[`LoadTLSConfig`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/auth.go#L61)
sets 1.2; purser raises the default because every first-party client
speaks 1.3, and a deployment that genuinely needs 1.2 can ask for it
through `MinVersion`. That is the direction the mistake should point: an
operator who says nothing gets the stronger setting. Anything below 1.2
is refused outright.

### `authn/mtls` — SPIFFE profile

**Identity extraction** is a side effect of verification:
`x509svid.Verify(certs, bundle)` returns the `spiffeid.ID` along with
the chains it built, so purser never parses a URI SAN itself and never
reads an ID off a certificate it has not verified. go-spiffe already
enforces exactly-one-URI-SAN, valid SPIFFE syntax, and a non-CA leaf —
the cases a hand-rolled parser gets wrong. The leaf whose issuer and
serial land in the audit labels is `chains[0][0]`, the verified one,
not whatever the peer happened to send first.

**`Caller` mapping:** `Identity` is the full `spiffe://…` string;
`Labels` carry `spiffe.trust_domain` (`id.TrustDomain()`) and
`spiffe.path` (`id.Path()`), plus the same `cert.issuer_dn` /
`cert.serial` / `cert.not_after` audit trio the PKI profile sets, so one
audit consumer reads both profiles.

**A zero `SPIFFEAuth` rejects everything.** The bundle source it holds
is also the marker that it came from `NewSPIFFE`; a value built any
other way has no trust anchors and no business resolving an identity.

**SVID and bundle sources**, both satisfying `x509svid.Source` and
`x509bundle.Source`:

- `workloadapi.NewX509Source(ctx)` — SPIRE agent socket, auto-rotating.
  This is the real answer to revocation: short-lived SVIDs rotated
  in-process.
- `mtls.NewSPIFFEFileSource(opts)` — credentials delivered as files,
  reloaded on a ticker. Satisfies both source interfaces from one
  object. See below.
- Static PEM via `x509bundle.FromX509Authorities(td, certs)` — for
  development and no-SPIRE deployments.

All are read on every handshake and every request rather than
snapshotted at construction, which is what makes rotation and
withdrawal take effect without a restart.

**`SPIFFEFileSource`, and why the Workload API is not enough.** GKE
Managed Workload Identity does not expose a SPIFFE Workload API socket.
Its CSI driver (`podcertificate.gke.io`) mounts credentials read-only as
*files* under `/var/run/secrets/workload-spiffe-credentials` —
`certificates.pem`, `private_key.pem`, `ca_certificates.pem`,
`trust_bundles.json` — and rewrites them in place on rotation. So
`workloadapi.X509Source`, the source every SPIFFE tutorial reaches for,
cannot be used on the platform purser most needs to run on.

`SPIFFEFileSource` closes that: it loads the triple, serves it from an
`atomic.Pointer`, and re-reads on an interval (30s by default, against
GKE's roughly five-minute trust-anchor propagation window). Design
notes:

- **Polling, not `fsnotify`.** The mount is rewritten rather than
  renamed, inotify semantics across a CSI mount are not something to
  bet admission on, and the propagation delay this races against is
  measured in minutes. A ticker has no failure mode to reason about.
- **A failed reload keeps the last good credential** and reports through
  `OnError`. A truncated or half-written file must not take a healthy
  workload offline.
- **Torn reads are *not* self-detecting, so each generation is read
  twice.** A mismatched cert and key is caught — `x509svid.Parse` checks
  the key against the leaf's public key — but a truncated file is not:
  go-spiffe's PEM reader discards a trailing partial block without
  error, so a half-written three-certificate chain parses cleanly as a
  two-certificate one. The sharp case is a CA rotation, where the bundle
  grows from one anchor to two and a torn read lands on new-anchor-only:
  every existing peer is rejected, with nothing logged. So `load` reads
  all three files twice and compares the bytes, accepting a generation
  only if the files held still across both reads. Two identical reads is
  not a proof — a writer could finish in between — but it turns "a write
  is in progress right now" from a silent wrong answer into a retry on
  the next tick. An empty bundle is rejected outright for the same
  reason.
- **Retention is bounded by expiry on the SVID half only.** Keeping the
  last good credential is unbounded on its own: if the mount becomes
  permanently unreadable there is no next good tick. `GetX509SVID`
  refuses to serve a leaf that has actually expired, so the process
  fails locally and legibly instead of presenting a dead certificate and
  collecting a TLS alert from the peer. The *bundle* has no equivalent
  bound and cannot get one from here: a trust anchor is a long-lived CA
  certificate, withdrawing one is an edit to the file rather than an
  expiry, and a source that can no longer read the file cannot tell a
  withdrawal from a mount glitch — so a revoked authority stays honoured
  for as long as the mount stays broken. Where both halves come from one
  source the SVID's expiry bounds this in practice, but that is a side
  effect and it disappears when the halves are split: a
  `workloadapi.X509Source` for the SVID beside this for the bundle keeps
  presenting a fresh SVID while trusting a withdrawn authority
  indefinitely. `OnError` is the only signal, so a deployment that
  splits them should alert on it.
- **`OnError` runs on one goroutine of the source's own, serialised.**
  Calling it inline would put caller-supplied code on the reload loop's
  critical path, where three ordinary things become severe: a callback
  that blocks stops all future reloads, so the SVID quietly ages out
  even after the files recover; a callback that calls `Close` — the
  natural reaction to a credential failure — deadlocks, since `Close`
  waits for the loop that is waiting for the callback; and a panic takes
  down the process from a goroutine the caller never started and cannot
  recover on. A panic in the callback is recovered and discarded.
  Delivery is *one* long-lived goroutine draining a short queue rather
  than a goroutine per failure, because the latter is unbounded: a
  callback blocked on a wedged log sink would accumulate one goroutine
  per tick, thousands a day, for as long as the mount stayed broken.
  Once the queue fills, further errors are dropped — every one of them a
  duplicate of the "reload is still failing" the first call already
  delivered.
- **`Close` waits for the reload goroutine, and that wait is not
  bounded.** The loop notices `Close` only between ticks, so if it is
  blocked inside `os.ReadFile` on a wedged mount, `Close` blocks with
  it. Reads already fail by then — they check the closed flag, not the
  goroutine — so what is lost is the caller's shutdown path rather than
  any safety property. A timeout was considered and rejected: it trades
  a visible hang for a silently leaked goroutine still writing to the
  source, and a process whose credential mount has wedged is not going
  to shut down cleanly regardless.
- **The bundle is cloned per call.** `x509bundle.Bundle` looks immutable
  and is not — `AddX509Authority` and `SetX509Authorities` are exported,
  and x509bundle's own `GetX509BundleForTrustDomain` returns the
  receiver rather than a copy. Handing out the live bundle would let any
  holder promote an untrusted issuer for every concurrent handshake in
  the process.
- **Reads after `Close` fail**, matching `workloadapi.X509Source`. A
  caller who wrote `defer src.Close()` in a function that returns the
  `tls.Config` should find out at the next handshake, not at expiry.
- **`TrustDomain` is a required option**, and the loaded SVID's own
  domain is checked against it at construction. PEM on disk says nothing
  about which trust domain it belongs to, and the symptom of getting it
  wrong is a remote peer rejecting the connection.
- **`ca_certificates.pem`, not `trust_bundles.json`.** The JSON form
  carries federated bundles for other trust domains; federation is a
  [deliberate gap](#deliberate-gaps) and reading it would imply support
  purser does not have.

The same type serves local development, where a test CA writes the same
three files to a temp directory — one component covering both cells
rather than a real one and a mock.

go-spiffe v2.6.0 is already a transitive dependency of k8s-lookout, so
it adds no new supply-chain surface there. Within purser it adds none at
all beyond itself: the four packages used (`spiffeid`, `x509bundle`,
`svid/x509svid`, `spiffetls/tlsconfig`) need only the standard library,
so `go.mod` gains one direct requirement and no indirect ones. The gRPC
and go-jose dependencies live in `workloadapi`, which purser does not
import — a consumer that wants the SPIRE agent socket takes them on
knowingly.

### `authn/mtls` — admission matchers

Two files, one per profile: `match.go` for the PKI profile's
`CertMatcher`, `spiffematch.go` for the SPIFFE profile's
`spiffeid.Matcher`.

**SPIFFE.** go-spiffe's `Authorizer` is a **function type** —
[`type Authorizer func(id spiffeid.ID, verifiedChains [][]*x509.Certificate) error`](https://github.com/spiffe/go-spiffe/blob/v2.6.0/spiffetls/tlsconfig/authorizer.go#L12)
— not an interface. There is **no `tlsconfig.AuthorizerFunc`**. The
idiomatic extension point is `spiffeid.Matcher` (`func(ID) error`),
adapted via `tlsconfig.AdaptMatcher`.

The built-in matchers are only `MatchAny`, `MatchID`, `MatchOneOf`, and
`MatchMemberOf`
([`spiffeid/match.go`](https://github.com/spiffe/go-spiffe/blob/v2.6.0/spiffeid/match.go)).
**There is no path or prefix matcher.** That gap is purser's to fill,
and it is precisely why leaving each consumer to hand-roll it is
dangerous:

```go
// The trap. Substring matching on an untrusted path:
strings.Contains(id.Path(), "/ns/prod/")
// also matches spiffe://td/ns/attacker/x/ns/prod/sa/y
```

purser ships structured matchers that cannot be fooled this way:

| Matcher | Use |
|---|---|
| `MatchPathSegments("ns", ns, "sa", sa)` | Structured segment equality — no substring escape |
| `MatchPathPrefix(segments...)` | Anchored, segment-aligned prefix |
| `MatchAll(matchers...)` | Conjunction; empty adds no constraint |
| `MatchAnyOf(matchers...)` | Disjunction; empty admits nobody |

They *are* `spiffeid.Matcher` values rather than a parallel type, so
go-spiffe's four built-ins need no re-export: `MatchAll(
spiffeid.MatchMemberOf(td), MatchPathSegments("ns", ns, "sa", sa))`
composes across both packages, and anything that takes a
`spiffeid.Matcher` takes purser's.

Segments are variadic arguments rather than one `"/ns/prod/sa/api"`
string, which is what makes the anchoring hold when a segment comes from
configuration: a value carrying a slash is rejected by
`spiffeid.ValidatePathSegment` instead of silently widening the rule.
An empty or invalid segment list yields a matcher that admits nobody, so
a rule assembled from unset configuration closes the door.

There is deliberately **no glob matcher**. A pattern language is the
same anchoring hazard one layer up — `/ns/*/sa/deployer` invites
`/ns/*` — and nothing in the target deployments needs it that
`MatchAnyOf` over explicit alternatives does not cover. It can be added
if a real consumer wants it; it cannot be removed once shipped.

Plus a GCP-shaped wrapper, since the target topology is Google:

- **GKE workload identity** —
  `spiffe://{project}.svc.id.goog/ns/{ns}/sa/{sa}`:
  `MatchGKEWorkload(project, ns, sa)`. An empty or malformed argument
  admits nobody; there is no `""`-means-any wildcard, because the
  argument most likely to be accidentally empty is the one read from
  configuration. `MatchAll(spiffeid.MatchMemberOf(td),
  MatchPathPrefix("ns", ns))` is the way to say "any workload in this
  namespace".

The helper exists because the trust domain is the *project*, not the
cluster — a shape that is easy to assemble wrongly by hand, and a subtly
wrong trust domain is a silent authorization bypass.

A **Vertex Agent Engine** wrapper is deferred. Its trust domain and
resource path
(`agents.global.org-{org}` versus `agents.global.proj-{proj}`, and the
`/resources/aiplatform/projects/…/reasoningEngines/…` path) could not be
confirmed against a real issued SVID, and a matcher pinned to a guessed
shape is worse than no matcher: it fails closed in testing and stays
wrong in production. `MatchPathSegments` expresses it in the meantime.

**PKI.** The standard library has no `Authorizer` equivalent, so purser
supplies the same Layer-A concept over the parsed peer certificate as
`CertMatcher` (`func(*x509.Certificate) error`). Same composition
vocabulary as the SPIFFE side, so operators learn one model.

It is enforced inside **`VerifyConnection`, not `VerifyPeerCertificate`**
— the hook that looks right and is wrong. `VerifyPeerCertificate` is
skipped entirely when a session resumes from a ticket: crypto/tls
re-checks the carried chain against `ClientCAs`, rejects an expired leaf
([`handshake_server_tls13.go`](https://github.com/golang/go/blob/go1.26.6/src/crypto/tls/handshake_server_tls13.go#L370-L381)),
restores `VerifiedChains`, and proceeds. An admission matcher hung there
stops applying the moment a client reconnects with a ticket, so a peer
admitted under an older policy keeps its access for the ticket's
lifetime. `VerifyConnection` runs on both the full and resumed paths, on
TLS 1.2 and 1.3, with the same verified state.

| Matcher | Use |
|---|---|
| `MatchCertIssuerDN(dn)` | Which authority in a multi-CA pool vouched |
| `MatchCertOrganization(o)` / `MatchCertOrganizationalUnit(ou)` | Subject RDN membership |
| `MatchCertEmailSAN(email)` / `MatchCertDNSSAN(name)` | Exact SAN pin |
| `MatchCertEmailDomain(domain)` | Anchored on the last `@` |
| `MatchCertDNSSuffix(domain)` | Anchored on a label boundary |
| `MatchCertFunc(fn)` | Anything else |

The two domain matchers are anchored for the same reason the SPIFFE path
matchers are: `strings.HasSuffix(email, "example.com")` also admits
`alice@notexample.com`, and `HasSuffix(name, "svc.cluster.local")` also
admits `evil-svc.cluster.local`. Both are a domain registration away
from being an authorization bypass.

`MatchCertAll` and `MatchCertAnyOf` compose them, and their empty cases
are deliberate opposites: an empty conjunction adds no constraint, while
an empty disjunction admits nobody. That is what keeps "unconstrained"
from being spelled the same way as "the allowlist came back empty".

### `authn/oidc`

Issuer discovery, JWKS fetch with caching and key rotation, audience and
expiry validation, configurable claim→identity mapping (default `email`,
falling back to `sub`), and remaining claims copied into `Caller.Labels`.
This is the human-operator path: it removes the need to issue client
certificates to laptops.

It verifies a token the client already holds. The OAuth 2.0
authorization code flow is not implemented and is not planned here:
obtaining a token is the client's problem (`gcloud auth
print-identity-token`, an IdP device flow, an oauth2 library), and the
server half is the part every consuming service needs.

**go-jose, not go-oidc.** `github.com/go-jose/go-jose/v4` supplies JWS
parsing, signature verification, and JWK decoding; the layer above it —
discovery, the key cache, claim validation, identity resolution — is
purser's. go-oidc was the alternative and would have been fewer lines,
but it depends on go-jose anyway, so the choice was never about
dependency count. It was about which policies this repository owns.
Three of go-oidc's are wrong here: its `RemoteKeySet` single-flights
concurrent refetches but applies **no rate limit** to a token whose key
ID it has not cached, its verifier checks one `ClientID` rather than a
set of audiences, and it carries a hardcoded schemeless-issuer exemption
for `accounts.google.com`. Vendoring the parsing and owning the policy
costs a few hundred lines and makes each of those a decision recorded
here.

**Construction does no network I/O.** `New` validates options and
returns; discovery and the first key fetch happen on the first request
that presents a token. A service must start with its IdP briefly
unreachable, and — more to the point — must not come up holding an
authenticator that rejects everything because a fetch at construction
failed.

**Two knobs bound the key cache, and they bound opposite hazards.**

| Option | Default | Bounds |
|---|---|---|
| `KeyRefresh` | 15m | How long a key the issuer **withdrew** keeps verifying tokens here |
| `KeyRefreshFloor` | 30s | How often an unauthenticated caller can make this service **fetch** from its IdP |

The floor is the one that is easy to miss. A token's key ID is read from
its *unverified* header, so anyone who can reach the surface can name a
key ID that is not cached; without a floor, each such request becomes a
fetch, and the service is an amplifier pointed at its own IdP. With one,
a rotation this process has not yet seen costs its callers at most that
long. `KeyRefresh` covers what the demand-driven path cannot: a
withdrawn key ID is one the cache has *seen*, so nothing about it looks
unknown, and only age forces the refetch that drops it.

When a fetch fails and a matching key is already cached, the cached key
is served. An IdP that is briefly down must not log every operator out
of every service, and the request still has to present a token signed by
that key and inside its validity window.

**The discovery document must name the issuer it was fetched from.**
This is the check that makes following discovery safe: without it,
anything that can answer at the issuer's well-known path redirects the
key fetch to a JWK Set of its own and signs tokens for any identity.
RFC 8414 §3.3 requires it. The `jwks_uri` need only be https — the key
endpoint legitimately lives on another host, as Google's does.

**Refusals, and why each one is not configurable:**

- **Symmetric algorithms and `none`.** The permitted set is an
  allowlist (`RS*`, `PS*`, `ES*`, `EdDSA`) rather than a denylist, so an
  algorithm added to go-jose in a future release cannot become
  acceptable here without somebody deciding it should be. A verifier
  that accepts `HS256` can be handed a token signed with the issuer's
  *public* key, which is published.
- **The JWS JSON serialization.** `jose.ParseSignedCompact`, not
  `jose.ParseSigned`: the latter also accepts a form that can carry
  several signatures with per-signature headers, and "the first
  signature verified" is the shape of several real CVEs. An ID token is
  always compact.
- **An empty `Audiences`.** The audience is the only thing
  distinguishing a token minted for this service from one minted for any
  other service of the same issuer.
- **A missing `exp`.** RFC 7519 makes it optional; this package does
  not. A token with no expiry is a bearer credential valid forever.
- **An unverified `email` as the identity.** On most providers the
  address is a self-service profile field, so a user who can type one
  could otherwise authenticate as its owner.
  `Options.AllowUnverifiedEmail` exists for the corporate IdP whose only
  source of addresses is the HR system.
- **A key published for another algorithm.** A provider's RSA key
  published as `PS256` must not verify an `RS256` signature: different
  padding, same key, and the issuer said which one it signs with.

**`Caller.Admin` is never read from a claim.** A token that could assert
its own admin bit would be a privilege escalation the moment an operator
gained write access to their own IdP profile. Claims reach policy as
labels — `oidc.issuer`, `oidc.sub`, `oidc.email`, `oidc.expires_at`, and
everything else scalar under `oidc.claim/` — and `authz.Rules` decides.
Arrays and objects are dropped rather than flattened: joining a `groups`
array with commas produces a value that matches no policy anyone would
write and looks like it should, so a group matcher gets added
deliberately when a real consumer needs one.

**No `authn.IdentityLookup`.** There is no table of provisioned
identities behind a claim-based authenticator, so an identity asserted
through the proxy path is taken at face value and
`Options.ProxyIdentities` is the whole control. Implementing the
interface with anything other than a real table would either invent
`Caller`s or reject every assertion.

### `authz/authz.go` — the matrix without the nouns

This design originally said `authz.go` would export `Action`,
`SessionACL` and `Authorize`. It exports `Action`, `Role`, `ACL`,
`RoleOf`, `Allows` and `Authorize`: the matrix is core-agent's, cell for
cell, but the vocabulary is not. `SessionACL` became `ACL` and the
actions lost their resource prefix, because a *session* is core-agent's
noun and [`AGENTS.md`](../AGENTS.md) makes shipping it here a hard rule
— "session ACLs, role names, and admin lists belong to the consuming
service." A library that names one consumer's resource type invites the
second consumer to authorize its jobs against a struct called
`SessionACL`, and by then the name is API.

Core-agent keeps its own `SessionACL` and its own `session.read` /
`daemon.admin` spellings in a phase-2 wrapper that is four lines and one
`switch`, and keeps them in its audit records where they belong.
`Action.String` deliberately renders `"read"`, not `"session.read"`, so
that wrapper prefixes rather than translates.

`Allows` is exported alongside `Authorize` for the service that resolves
a role some other way — from a group-membership service, or from a role
already recorded on the resource — and still wants one matrix.

Three behaviors worth stating, all stricter than the code they came
from. A `Caller` with an empty `Identity` is `RoleNone` **before** the
`Admin` bit is consulted, so a half-initialized struct cannot own a
resource whose `ACL.Owner` was never populated either. An `Action` this
build does not know denies rather than falling through to a permissive
default — with the single documented exception that `RoleAdmin` still
passes, since admin is defined as "everything", including verbs added
after this binary was built. And `Allows` range-checks the `Role` it is
given: every grant below `RoleAdmin` is a `>=` comparison, so a value
above `RoleAdmin` would satisfy all of them. That is not hypothetical
precisely because `Allows` is exported for services resolving roles
their own way — an integer read back from a row written by a newer peer,
or an off-by-one in a service's mapping table, is exactly where such a
value comes from.

### `authz/rules.go` — rules, not rows

The actual fix for the scale objection.
[`AdminIdentities`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/config/config.go#L1095)
and
[`ProxyIdentities`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/config/config.go#L1113)
are exact-match `[]string` today, and scale no better than `users.json`
does. They are replaced by a rule list matching on identity, email
domain, SPIFFE path segments, certificate fields or OIDC claims — any of
which are `Caller` labels by the time `authz` sees them — and granting
`Admin` or proxy capability. `MatchIdentity` is the degenerate rule, so
existing configs keep working.

**Not ordered, and no deny.** This design said "ordered rule list"; the
shipped `Rules` is a union. Order is what makes a policy engine hard to
reason about — whether a grant survives depends on what precedes it —
and the ordering only buys anything once there are deny rules. There are
none: every rule grants, `Rules.Apply` never clears a bit somebody else
set, and an exception is written inside the matcher that grants it,
`MatchAll(MatchPathPrefix(…), MatchNot(MatchIdentity(…)))`. A rule set
therefore means the same thing however it is sorted, and a deployment
running both a legacy `ProxyIdentities` list and a rule set during a
migration loses nobody.

**Matchers fail closed on their own configuration.** `Matcher` is
`func(purser.Caller) bool` rather than the error-returning shape
`mtls.CertMatcher` uses, because a rule set is assembled once at startup
and consulted per request: there is no per-request error to report, only
a configuration that never got set. `MatchEmailDomain("")`,
`MatchLabel("group")` with no values, `MatchLabel("group", "")`,
`MatchPathPrefix(key)` with no segments, `MatchAll()` with no matchers
and `MatchNot(nil)` all match *nobody*. The `MatchLabel` case is the
sharp one — `Caller.Label` returns `""` for an absent label, so an unset
config value that matched `""` would grant to every caller that does not
carry the label at all.

`MatchAll()`'s empty case is the **opposite of `mtls.MatchCertAll`'s**,
and the asymmetry is the point. An admission matcher is an additional
restriction on a peer the TLS stack already verified, so an empty
conjunction there removes a constraint. Here the conjunction is the
entire predicate of a grant, so an empty one *is* the grant:
`MatchAll(cfg.Matchers...)` over a config section nobody filled in would
hand `Admin` to every caller. The consequence is that this package
supplies no spelling for "everyone" — a deployment that means it writes
`func(purser.Caller) bool { return true }` in its own source, where it
is visible in review, the same move `client.NewSPIFFE` forces with
`spiffeid.MatchAny()`. `MatchNot(nil)` denies for the same reason,
against the logically pure reading that `not(nobody)` is everyone: an
exception that was never configured must not inflate into a blanket
grant. Only a `nil` is recognisable that way — `MatchNot(MatchAll())` is
a closure that matches nobody, indistinguishable from a deliberate one,
and does mean everyone.

Path matching is **segment-anchored**, for the reason the SPIFFE
admission matchers are: `strings.Contains(path, "/ns/prod")` admits
`/ns/attacker/x/ns/prod/sa/y`, and `strings.HasPrefix` admits
`/ns/production`. `MatchEmailDomain` anchors on the last `@` for the
same reason `HasSuffix(email, "example.com")` cannot be used —
`alice@notexample.com` is one registration away — and folds the domain's
case over **ASCII only**. `strings.EqualFold` applies Unicode simple
folding, under which `ſlack.com` (U+017F) and `slacK.com` (U+212A, the
Kelvin sign) both equal `slack.com`: separately registrable IDN domains
satisfying a rule that names neither.

**An exception is only as wide as the comparison it is written in.**
`MatchEmailDomain` folds case; `MatchIdentity` and `ACL` membership are
byte-exact, because an identity is an opaque string and canonicalizing
it belongs to the authenticator that minted it, where the credential's
own rules are known. So `MatchAll(MatchEmailDomain("example.com"),
MatchNot(MatchIdentity("mallory@example.com")))` grants
`Mallory@example.com`, and whether that is reachable depends on whether
the identity's spelling is pinned upstream. `MatchNot`'s doc says to
except on the property the grant is written in; a test pins the
behaviour so the edge cannot be discovered in production.

**No grant reaches a caller nothing authenticated**, and two mechanisms
say so because one is not enough. `Rules` refuses the zero `Caller` *and*
`purser.AnonymousIdentity` — the identity an unauthenticated request
resolves to wherever anonymous access is allowed, which is not zero and
would otherwise be matched like any other. `WithRules` additionally
refuses at construction an authenticator reporting
`purser.AuthSourceAnonymous`, which covers a deployment that configured
some other fallback identity: applying policy to an authenticator that
verifies nothing is granting on the strength of a request that presented
nothing.

**Label keys are arguments, not constants declared here.** A rule reads
`MatchPathPrefix(mtls.LabelPath, "ns", "prod")`. `authz` is stdlib-only
and cannot import `authn/mtls`; re-declaring `"spiffe.path"` in a second
package is how two spellings of one key drift apart, so the key is
passed in and a test in `authz` pins the agreement by using the real
constant.

**Every rule is named, and the name is required and unique.**
`Rules.Matching(c)` returns the names that fired, which is what makes
"why is this caller an admin" answerable from an audit record rather
than by re-deriving policy by hand.

### `authz/authenticator.go` — connecting rules to a surface

`Rules` is data nothing consults until `WithRules(auth, rules)` wraps an
`authn.Authenticator` in it: every `Caller` the wrapped authenticator
resolves passes through `Rules.Apply`, `CanProxyAs` becomes the union of
the rules and whatever allowlist the authenticator already had, and an
identity reached through `authn.IdentityLookup` gets the same grants it
would have had authenticating directly.

It is a decorator in `authz` rather than a `Rules` field on
`httpmw.CallerOptions` so that policy stays out of the middleware and
the composition is reusable by a surface that is not HTTP.

The awkward part is real and worth recording: `authn`'s optional
extensions are discovered by type assertion, so the wrapper must
implement *exactly* the ones the wrapped authenticator implements —
hence four unexported variants and a type switch. Dropping
`authn.IdentityLookup` would make `httpmw` take every asserted identity
at face value; adding it to an authenticator with no table would make
`httpmw` reject every assertion as unprovisioned; and implementing
`authn.CredentialGate` unconditionally means inventing an answer for an
authenticator that gave none — claim `true` and `httpmw.NewCaller`
accepts `Enforce` over an authenticator that admits every request, with
`CheckBind` then reporting the surface as safe to expose.
`authn.AuthenticatorWithProxy` is the one exception, always implemented,
because rules may grant proxying on their own — and it reads the same as
not implementing it when neither the rules nor the wrapped authenticator
permit anyone.

### `client/mtls.go`

No first-party client can do mTLS today.
[`internal/attachclient/client.go:120`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/internal/attachclient/client.go#L120)
clones `http.DefaultTransport` and never sets `TLSClientConfig`, and
[`cmd/core-agent/attach.go:51`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/cmd/core-agent/attach.go#L51)
says so outright: *"mTLS is not yet wired in the client (TODO
follow-on)."*

Both profiles: a stdlib `tls.Config` with a keypair plus `RootCAs` for
PKI, and an SVID plus a bundle source for SPIFFE. Without this, phase 2
ships a server that nothing can talk to.

**The client verifies where the server verifies.** This design
originally said to return `tlsconfig.MTLSClientConfig(svid, bundle,
authorizer)` for the SPIFFE profile. It does not, and the reason is the
one from ["Layer A and Layer B must not be
conflated"](#layer-a-and-layer-b-must-not-be-conflated) applied to the
other end of the connection: that helper sets `InsecureSkipVerify` and
hangs go-spiffe's verification off `VerifyPeerCertificate`, which
`crypto/tls` **skips on a resumed session** — Go's own comment in
`handshake_client.go` reads *"Resumptions currently don't reverify
certificates so they don't call verifyServerCertificate. See Issue
31641."* With stdlib checking disabled and its only replacement skipped,
a session ticket becomes the entire proof of the server's identity for
that ticket's lifetime: an authority since withdrawn from the bundle
keeps being accepted, and so does a server that a narrowed `Authorize`
would now reject. Expiry of the server's leaf is the one thing
`crypto/tls` still catches on its own — `loadSession` drops a cached
session past `NotAfter` (`handshake_client.go:403`) and that check sits
*above* the `!InsecureSkipVerify` guard, so it applies even to a config
like go-spiffe's. Everything else on that path is the helper's to do and
it does not do it. This is the same trap the SPIFFE
*server* profile avoids by not using `MTLSServerConfig`, and the client
avoids it the same way — go-spiffe's verification logic, moved onto
`VerifyConnection`, which `crypto/tls` calls on both paths.
`client.NewPKI` puts its optional `Admit` matcher there too, for
symmetry and for the same reason.

`client/mtls_test.go` pins both halves: purser rejects a resumed
connection whose trust bundle has been emptied, and — in a sibling
subtest that will fail if upstream ever closes the gap —
`tlsconfig.MTLSClientConfig` accepts it.

**`Authorize` is required on the client and `Admit` is optional on the
server.** The asymmetry is deliberate. A server admits a *population*;
every workload its authority issues to may legitimately connect. A
client dials *one known service*, so "any SVID in the trust domain"
includes every compromised peer that can win a race for the address.
A caller who genuinely means it passes `spiffeid.MatchAny()` and says so
in the source.

**The ECH-rejection path looks like a second hole and is not one.** It
is recorded here because the resemblance is strong enough that an
earlier revision of this package acted on it, and the fix was wrong
twice over.

The setup is real: when a caller sets `EncryptedClientHelloConfigList`
and the server rejects ECH, `crypto/tls` guards *both*
`VerifyPeerCertificate` and `VerifyConnection` with `&& !echRejected`
(`handshake_client.go:1127`) and verifies through
`EncryptedClientHelloRejectionVerify` instead — falling back, if that
hook is unset, to a chain build against `RootCAs` that does not consult
`InsecureSkipVerify`. Read on its own, that says an ECH-rejected SPIFFE
connection would be verified against the system roots with no SPIFFE
check at all.

It never gets that far. On rejection the TLS 1.3 client sends
`alertECHRequired` and returns `*tls.ECHRejectionError` before setting
`isHandshakeComplete` (`handshake_client_tls13.go:151-154`), whatever
the hook decided. The only route around that abort is TLS 1.2, and
`crypto/tls` refuses to offer ECH at all unless `MinVersion` is 1.3 or
unset (`handshake_client.go:175-180`) — both client constructors always
set `MinVersion`, so a purser config takes one error or the other. There
is no reachable state in which an ECH-rejected connection carries
traffic.

And the hook could not verify anything if there were. `crypto/tls` calls
it with the `ConnectionState` built at `handshake_client.go:1130`,
fifty-nine lines *before* `c.peerCertificates = certs` at `:1189`, so
`PeerCertificates` is empty and any honest hook fails unconditionally.
Installing one is therefore not neutral: it converts a clean
`ECHRejectionError` — which carries the `RetryConfigs` a client needs to
recover from a stale ECH config — into a `bad_certificate` alert and a
misleading complaint about the server's chain.

So neither constructor sets the hook, and `TestECHRejectionNeedsNoHook`
pins both reasons with real handshakes rather than by calling the hook
directly: one subtest drives an actual ECH rejection with the most
permissive hook possible and requires the handshake to fail anyway, and
another records what the hook was passed and requires it to be empty. If
a future Go moves that assignment, the second fails — and the first is
the one to re-read, because it is what makes the path unreachable.

**Mispairing a client and server profile is a configuration error, not
a security boundary.** The package comment says so explicitly, because
the stronger claim is false and a test proves it: a SPIFFE client
dialling a PKI listener succeeds whenever that listener's certificate
happens to be SVID-shaped and issued by an authority in the client's
bundle — a live state during a migration to SPIFFE. The PKI direction
does fail, but incidentally: an X509-SVID carries a URI SAN and no DNS
name, so the standard hostname check has nothing to match. The real
protection against mispairing is that the constructors return the config
and its authenticator together.

**`Transport(cfg)`** exists because `net/http` upgrades a transport to
HTTP/2 automatically only while `TLSClientConfig` is nil. Setting one —
which mTLS requires — silently drops back to HTTP/1.1 unless
`ForceAttemptHTTP2` is also set. It clones both the transport it starts
from and the config it installs. Cloning `http.DefaultTransport` is
obvious — every other client in the process is using it. Cloning the
*config* is less so: `net/http`'s HTTP/2 setup appends to
`TLSClientConfig.NextProtos` **in place** (`h2_bundle.go:7539`), so a
caller who kept the config to dial with directly, or handed it to a
second transport, would find ALPN protocols in it that it never asked
for. Cloning is not quite enough on its own — `tls.Config.Clone` copies
the slice header and shares the backing array (`common.go:1014`), so the
installed `NextProtos` is clipped to force the append to reallocate.

Two smaller decisions there. `Transport(nil)` **panics**: `net/http`
reads a nil config as the system roots and no client certificate, so the
alternative is a transport built for mTLS that quietly cannot
authenticate and trusts every CA a browser does — and neither
constructor returns a nil config with a nil error, so reaching it means
an unchecked error above. And the fallback branch, taken when
`http.DefaultTransport` has been replaced by something that is not an
`*http.Transport`, sets its own `DialContext`: without one `net/http`
dials through a zero `net.Dialer` with no connect timeout at all, which
would make that branch strictly more dangerous than the `Clone` branch
it stands in for, and only on the machines where the type assertion
happens to fail.

### `AuthSource` as a typed value

Today the auth-source verdict is a private string context key in
[`pkg/attach/caller_middleware.go`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/caller_middleware.go)
plus a set of `whoAmISource*` constants in
[`handlers_whoami.go`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/handlers_whoami.go#L76)
— including
[`whoAmISourceIAP`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/handlers_whoami.go#L87),
which is reserved and currently `//nolint:unused`.

purser owns the enum. `mtls` and `spiffe` are **distinct values**, so
`/whoami` tells an operator which profile admitted them.
`credentialSource()` becomes a method on the `Authenticator` rather than
a type switch at the middleware, so a new authenticator cannot silently
report the wrong source. The
[core-agent#385](https://github.com/go-steer/core-agent/issues/385) hardening
property is preserved: the verdict is stamped by the code that performed
the authentication and is never re-derived from spoofable headers.

### `authtest` — the component-testing payoff

The stated motivation for extraction, and the piece no single consumer
would build alone.

- **`authtest.RunAuthenticatorSuite(t, factory)`** — conformance every
  implementation must pass: missing credential returns
  `ErrUnauthenticated`; a malformed credential never panics; a success
  never returns an empty-identity `Caller`; non-proxy callers are
  rejected on `X-Asserted-Caller`; an unknown asserted identity is
  rejected; the reported `AuthSource` matches.
- **`authtest.NewCA(t)`** — in-memory CA issuing **both** plain PKI
  client certs (with chosen SAN/CN shapes) and SPIFFE SVIDs, exposing
  `x509svid.Source` / `x509bundle.Source`. Drives real handshakes on
  both profiles: no disk, no SPIRE, no expiry rot.
- **`authtest.NewIssuer(t)`** — `httptest` OIDC issuer serving discovery
  and JWKS and minting signed tokens, including rotation and
  wrong-audience cases. It runs over TLS, because the authenticator
  refuses a plaintext issuer. `AddKey` is the gradual rotation and
  `Rotate` the abrupt one; `JWKSRequests` / `DiscoveryRequests` are what
  a test asserts a key cache against; `Close` is the IdP outage. A nil
  value in `TokenOptions.Claims` **removes** the claim, which is how a
  test reaches the payloads a well-behaved provider never emits and an
  attacker will (`{"exp": nil}` — no expiry at all).
- **Golden matrix test** for `Authorize`, pinning the
  Admin / Owner / Viewer / Contributor table. It lives in
  `authz/authz_test.go` rather than in `authtest`: core-agent's grid is
  ported cell for cell with the nouns mapped onto the generic actions,
  and it tests this package's own matrix rather than anything a consumer
  implements. `WithRules` is held to `RunAuthenticatorSuite` like any
  other authenticator — a decorator is one.

### Repo setup

Mirror go-steer conventions rather than inventing new ones. Shipped with
the scaffold (2026-08-17): Apache 2.0 headers attributed to Google LLC,
[`AGENTS.md`](../AGENTS.md) carrying the adversarial-review gate,
`dev/ci/presubmits/*` delegating to `dev/tools/*` so a green local
`dev/tools/ci` is the green remote run, a REQUIRED `review-gate` check,
branch protection on `main` (`ci` + `review-gate`, strict, linear
history), and `CHANGELOG.md`.

Two library-specific additions over the service repos:
`dev/tools/verify-apidiff` + `dev/api-breaks.txt`, because the exported
surface is the product; and no `Dockerfile` / `deploy/` /
`verify-go-toolchain`, because purser ships no binary and no image.
`dev/tools/verify-coverage` is deferred to phase 1a, when there is code
for a floor to mean anything.

Keep the root package, `authz`, `httpmw`, and the PKI half of
`authn/mtls` **stdlib-only**. go-spiffe, the JWT/JWKS library, and
oauth2 + idtoken are confined to `authn/mtls/spiffe.go` +
`authn/mtls/spiffematch.go`, `authn/oidc`, and `client/google.go`
respectively. If import-graph isolation turns out
to matter more than ergonomics, those can become nested modules — a
decision to make on a real consumer complaint, not upfront.

### Verification

Phase 1a is a library with no consumers, so verification is
self-contained.

1. `go test ./... -race` — the conformance suite runs against every
   authenticator.
2. **Real handshake tests, both profiles.** Bind a loopback listener
   from `mtls.New(...)` fed by `authtest.NewCA`, connect via
   `client/mtls.go`, and assert the resolved `Caller` identity, labels,
   and `AuthSource`. Negatives per profile: untrusted issuer, expired
   cert, admission-matcher rejection. SPIFFE-specific: non-SVID cert (no
   URI SAN) and two-URI-SAN cert. PKI-specific: cert missing the
   configured subject field.
3. **Profile-invariant test.** The same table of identity assertions
   runs against both profiles, proving `Caller` construction does not
   depend on which profile admitted the connection.
4. **`VerifiedChains` regression test.** Assert it is empty on an
   accepted SPIFFE connection and populated on an accepted PKI
   connection, and that identity resolves correctly in both. This is the
   property that breaks naive middleware, so it gets pinned.
5. **Session-resumption regression test, both ends.** Connect once so a
   ticket is cached, withdraw the peer's authority from the trust
   bundle, connect again, and assert the *resumed* handshake is
   rejected. Assert `DidResume`, so the test cannot pass by quietly
   doing a full handshake. Run it against `mtls.NewSPIFFE` and
   `client.NewSPIFFE`, and pin the upstream gap alongside: the same
   scenario through `tlsconfig.MTLSClientConfig` / `MTLSServerConfig`
   succeeds, and the day it stops doing so the test fails and the
   deviation gets revisited.
6. **ECH-rejection unreachability test.** The sibling of the resumption
   test, for the hole that turns out not to be one. Configure ECH on a
   purser client config, dial a server that has never heard of it, and
   assert the handshake fails with `*tls.ECHRejectionError` even with
   the most permissive `EncryptedClientHelloRejectionVerify` installed —
   and, separately, that `crypto/tls` passes that hook a
   `ConnectionState` with no peer certificates. Both are statements
   about the standard library, so both are written to fail loudly if a
   future Go changes them.
7. **`SPIFFEFileSource` rotation and hostile-caller tests.** Rewrite the
   mounted files and assert the new SVID is served without a restart;
   write a torn pair and assert the last good credential survives and
   `OnError` fires. Rewrite the bundle continuously between one anchor
   and two and assert a torn generation is *reported*, not accepted —
   the double read is the only thing standing between a CA rotation and
   a silent new-anchor-only bundle. Assert the source refuses an expired
   SVID once the mount is gone, that a returned bundle cannot be mutated
   into the source's own, and that an `OnError` which blocks, calls
   `Close`, or panics neither freezes rotation nor takes the process
   down. Assert too that `OnError` calls never overlap: serialised
   delivery is what keeps a blocked callback from costing a goroutine
   per failed reload.
8. **Matcher adversarial suite.** The substring escape is a named test:
   `MatchPathSegments("ns", "prod")` must reject
   `spiffe://td/ns/attacker/x/ns/prod/sa/y`, which `strings.Contains`
   accepts. Table-test the GCP helpers against real-shaped GKE and Agent
   Engine IDs, with wrong-trust-domain negatives.
9. **Layer separation test.** With a permissive admission policy, assert
   the `Caller` is still fully populated — pinning that admission policy
   never degrades identity extraction.
10. **OIDC end-to-end** via `authtest.NewIssuer(t)`: a valid token
   resolves; wrong audience, expired, and rotated-key-not-yet-cached are
   all rejected. Alongside those, the negatives that only a hand-rolled
   JWS reaches — `alg: none`, an `HS256` signature over otherwise valid
   claims, the JWS JSON serialization, and an `RS256` header naming a
   key the issuer published for `PS256`. The key cache gets its own
   assertions on fetch *counts*, because "correct" here is a number: 20
   verifications cost one fetch, 50 unknown key IDs under an hour-long
   floor cost one fetch, 20 concurrent cold-cache requests cost one
   fetch, and a withdrawn key stops verifying on the first request past
   `KeyRefresh`. A token asserting `"admin": true` resolves to a
   non-admin `Caller` with the claim visible as a label.
11. **Differential test against the source of truth.** Table-drive the
   ported `Authorize`, browser write guard, and transport-gate cases
   from core-agent's existing `pkg/auth/*_test.go` and
   `pkg/attach/{csrf,auth,caller_middleware}_test.go`. Passing them
   unchanged is the evidence the lift preserved behavior.
12. `examples/` server and client exercising both mTLS profiles end to
   end, wired into a `dev/ci/presubmits` smoke script.
13. `dev/tools/ci` green — including `lint-go` and `verify-apidiff`.

## Phase 1b — service mesh (optional)

Deferred behind 1a because it is a *different trust model*, not more of
the same one. Behind an Istio or Linkerd sidecar, TLS terminates at the
proxy: `r.TLS` is **nil**, so every phase-1a mechanism is inapplicable.
Identity arrives as a header.

- **`authn/meshheader`** — `Caller` from `X-Forwarded-Client-Cert`
  (Istio XFCC, whose `By=` and `URI=` fields carry SPIFFE IDs parseable
  with `spiffeid.FromString`) or Linkerd's `l5d-client-id`.
- **The trust anchor is the whole problem.** A header is forgeable by
  anything that can reach the port. This requires an explicit, mandatory
  anchor: bind loopback-only so only the sidecar can connect, and/or an
  allowlist of peer addresses. The library must **refuse to construct**
  this authenticator without one. A defaulted-open trusted-header
  authenticator is worse than no authenticator, because it looks like
  security.
- **Same shape as
  [core-agent#142](https://github.com/go-steer/core-agent/issues/142)**
  (gateway identity propagation: Cloud Run IAM, IAP, Cloudflare Access).
  One authenticator with pluggable header dialects should serve both
  mesh and gateway, and closes that issue — including finally emitting
  the reserved `iap` auth source.

## Phase 2 — core-agent and mast migrate

Recorded here so phase 1a does not paint us into a corner.

- core-agent's `pkg/auth` becomes type aliases
  (`type Caller = purser.Caller`) for one release so k8s-lookout pinned
  at core-agent v2.7.0 does not break, then is removed.
- [`BuildMultiSessionAuthn`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/compose/multi_session.go#L58)
  gains `mtls` (both profiles) and `oidc` cases; [`Config.Validate`
  stops rejecting
  them](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/config/config.go#L1424).
- The `VerifiedChains` and `ClientCAFile` inferences are replaced by the
  authenticator-owned profile and a `CredentialGate` query, as described
  above.
- The attach client learns mTLS, closing the
  [`cmd/core-agent/attach.go:51`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/cmd/core-agent/attach.go#L51)
  TODO.
- mast deletes `pkg/auth/` and the auth slice of `pkg/attach/`.
- **Backward-compat oracle:** core-agent's existing auth tests must pass
  unchanged after the swap. Any diff is a porting bug, not an expected
  consequence.

Operator-facing documentation under core-agent's
`docs/site/src/content/docs/` changes in this phase, not before — phase
1a ships no user-visible core-agent behavior.

## Deliberate gaps

- **PKI revocation.** Go performs neither CRL nor OCSP checking
  automatically. The PKI profile supports an optional CRL file and
  documents the gap honestly. Operators who want real automatic
  revocation want short-lived certificates — the SPIFFE profile's model
  — rather than long-lived certificates plus revocation infrastructure.
- **`X-Attach-Token` precedence.** The side-channel header wins over
  `Authorization` even when the token is wrong
  ([`pkg/attach/auth.go:140-145`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/auth.go#L140-L145)).
  This is deliberate and documented; it ports as-is and is revisited
  separately if at all.
- **Per-caller rate limiting**
  ([`pkg/attach/rate_limit.go`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/attach/rate_limit.go))
  is keyed on caller identity and arguably belongs here, but its
  endpoint classification is core-agent-specific. Left behind in phase
  1a; revisit when a second consumer wants it.
- **K8s ServiceAccount TokenReview**, listed as a future authenticator
  in
  [`pkg/auth/authenticator.go:33`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/auth/authenticator.go#L33),
  is not in the phase-1a scope. On GKE it is largely subsumed by the
  SPIFFE profile's workload-identity path.
- **SPIFFE federation.** `SPIFFEFileSource` reads
  `ca_certificates.pem` — the anchors for its own trust domain — and
  ignores GKE's `trust_bundles.json`, which carries federated bundles
  for others. A cross-trust-domain deployment needs a multi-domain
  bundle source; nothing in the design precludes one, and no consumer
  has asked.
- **GKE self-managed workload identity pools.** `MatchGKEWorkload`
  builds the fleet trust domain, `PROJECT_ID.svc.id.goog`, which is what
  Managed Workload Identity issues by default and what GKE's own guide
  walks an operator through. A self-managed pool in `TRUST_DOMAIN` mode
  issues under
  `POOL_ID.global.POOL_HOST_PROJECT_NUMBER.workload.id.goog` instead.
  That is a missing matcher rather than a wrong one — such a deployment
  can compose `spiffeid.MatchMemberOf` today — and it lands when someone
  runs that configuration.
