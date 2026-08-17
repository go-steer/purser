# purser: a shared authn/authz library for go-steer agents

Design doc for extracting core-agent's caller-identity layer into this
module, and for replacing the static bearer-token table with identity
derived from credentials the infrastructure already issues — SPIFFE
X509-SVIDs, ordinary CA-issued client certificates, and OIDC tokens.

**Status:** proposed (2026-08-17). No code yet beyond the scaffold. This
document is purser's design of record; the implementation lands as
separate PRs across the phases below.

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
      match.go               admission matchers, both profiles
    oidc/                    issuer + JWKS + claim mapping -> Caller
  authz/
    authz.go                 Action, SessionACL, Authorize
    rules.go                 pattern-based role rules
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
```

### Lifted as-is from core-agent

Ported preserving behavior, so phase 2 is a no-op for existing
deployments:

| From (core-agent@09b6cd1) | To |
|---|---|
| [`pkg/auth/auth.go`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/auth/auth.go) | `purser/caller.go` |
| [`pkg/auth/authenticator.go`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/auth/authenticator.go) | `authn/authn.go` + `authn/bearer/` |
| [`pkg/auth/authorize.go`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/auth/authorize.go) | `authz/authz.go` |
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
- Static PEM via `x509bundle.FromX509Authorities(td, certs)` — for
  development and no-SPIRE deployments.

Both are read on every handshake and every request rather than
snapshotted at construction, which is what makes rotation and
withdrawal take effect without a restart.

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

### `authz/rules.go` — rules, not rows

The actual fix for the scale objection.
[`AdminIdentities`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/config/config.go#L1095)
and
[`ProxyIdentities`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/pkg/config/config.go#L1113)
are exact-match `[]string` today, and scale no better than `users.json`
does. They are replaced by an ordered rule list matching on identity
pattern, SPIFFE path segment, certificate subject field, or OIDC claim,
and granting `Admin` or proxy capability. Exact-match strings remain
valid as the degenerate rule, so existing configs keep working.

### `client/mtls.go`

No first-party client can do mTLS today.
[`internal/attachclient/client.go:120`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/internal/attachclient/client.go#L120)
clones `http.DefaultTransport` and never sets `TLSClientConfig`, and
[`cmd/core-agent/attach.go:51`](https://github.com/go-steer/core-agent/blob/09b6cd1d9c97fa1e2673bac2e664d97579c68b24/cmd/core-agent/attach.go#L51)
says so outright: *"mTLS is not yet wired in the client (TODO
follow-on)."*

Both profiles: a stdlib `tls.Config` with a keypair plus `RootCAs` for
PKI, and `tlsconfig.MTLSClientConfig(svid, bundle, authorizer)` for
SPIFFE. Without this, phase 2 ships a server that nothing can talk to.

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
- **`authtest.NewIssuer()`** — `httptest` OIDC issuer serving discovery
  and JWKS and minting signed tokens, including rotation and
  wrong-audience cases.
- **Golden matrix test** for `Authorize`, pinning the
  Admin / Owner / Viewer / Contributor table.

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
5. **Matcher adversarial suite.** The substring escape is a named test:
   `MatchPathSegments("ns", "prod")` must reject
   `spiffe://td/ns/attacker/x/ns/prod/sa/y`, which `strings.Contains`
   accepts. Table-test the GCP helpers against real-shaped GKE and Agent
   Engine IDs, with wrong-trust-domain negatives.
6. **Layer separation test.** With a permissive admission policy, assert
   the `Caller` is still fully populated — pinning that admission policy
   never degrades identity extraction.
7. **OIDC end-to-end** via `authtest.NewIssuer()`: a valid token
   resolves; wrong audience, expired, and rotated-key-not-yet-cached are
   all rejected.
8. **Differential test against the source of truth.** Table-drive the
   ported `Authorize`, browser write guard, and transport-gate cases
   from core-agent's existing `pkg/auth/*_test.go` and
   `pkg/attach/{csrf,auth,caller_middleware}_test.go`. Passing them
   unchanged is the evidence the lift preserved behavior.
9. `examples/` server and client exercising both mTLS profiles end to
   end, wired into a `dev/ci/presubmits` smoke script.
10. `dev/tools/ci` green — including `lint-go` and `verify-apidiff`.

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
