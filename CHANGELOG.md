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

Nothing yet.

## [0.1.0] - 2026-08-30

Phase 1a: the whole of the authentication and authorization layer, with no
consumers on it yet.

**What v0.1.0 is for.** Until now there was no tag, so the only way to depend
on purser was a commit SHA — and `dev/tools/verify-apidiff` had no baseline to
measure against, which meant the guard on the thing this module calls its
product had never actually run. This tag exists to give consumers something to
pin and that check something to compare to.

**Expect the surface to move.** Pre-1.0, an incompatible change may land at any
minor version — see "Changing the exported API" in
[`CONTRIBUTING.md`](./CONTRIBUTING.md). `core-agent` and `mast` migrate onto
this in phase 2, and that first real integration is the one thing most likely
to change the API. It will not change silently: from here on every break is
reported by apidiff, acknowledged in
[`dev/api-breaks.txt`](./dev/api-breaks.txt), and written down under
**Changed** or **Removed** below.

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
  three GKE file names into a memory-backed volume, so the Go code is identical
  and only the plumbing around it moves. `workloadapi.X509Source` is
  deliberately not used — GKE managed workload identity publishes no Workload
  API socket to dial, and it would pull gRPC and protobuf into the module graph
  of a library many services depend on. The PKI cells re-read their leaf
  through `PKIOptions.GetCertificate` on a `-pki-reload` interval rather than
  loading it once: cert-manager renews 30 days before a 90-day expiry and
  nothing rolls the pod, so a pinned certificate looks healthy for two months
  and then stops.

- `httpmw`: the HTTP layer, stdlib-only, lifted from core-agent's `pkg/attach`
  with core-agent's own tests ported as the evidence the behavior survived.
  `NewCaller` returns a `*CallerMiddleware` that resolves the Caller onto the
  request context and stamps the auth-source verdict from the authenticator's
  `Source()` — never from `tls.ConnectionState.VerifiedChains`, which is
  populated under the PKI profile and empty under a perfectly good SPIFFE
  connection, so the check it replaces reported `anonymous` for a caller whose
  SVID had just been verified. A proxy assertion is refused rather than ignored
  when the request did not authenticate, the authenticator cannot proxy, will
  not proxy for this caller, or has no such identity provisioned; silently
  dropping it leaves an operator whose allowlist change did nothing believing
  it took effect. The unauthenticated case is the middleware's to catch and not
  the authenticator's: on the non-enforcing path the Caller handed to
  `CanProxyAs` is the *fallback*, an ordinary non-zero Caller, so
  `AuthenticatorWithProxy`'s "must return false for the zero Caller" guard
  never fires. `Enforce` alongside a fallback, a nil authenticator, or an
  authenticator reporting `GatesCredentials() == false` is refused at
  construction, because at runtime each is indistinguishable from a working
  enforced surface.
- `httpmw.NewBrowserWriteGuard`: the browser cross-site request forgery guard —
  an Origin check and a `Content-Type: application/json` requirement on every
  state-changing method. A page the operator visits can fire a CORS simple
  request at a listener it cannot otherwise reach; the response stays
  unreadable, which does not help, because the side effect has already landed.
  `AllowedOrigins` is an exact-match allowlist with no wildcard and no suffix
  match: `*.example.com` is one subdomain takeover away from being an open
  door. An `Origin` or allowlist entry carrying userinfo is refused, because
  `https://evil.example.com@app.example.com` parses with a host of
  `app.example.com` and would otherwise register as — or match — a host nobody
  meant to name. What the guard does *not* stop is DNS rebinding, which the
  doc comment now says plainly: the self-origin rule compares against the
  request's own Host, and closing that needs a Host allowlist belonging to the
  service that knows its own names.
- `httpmw.NewTokenGate` and `httpmw.ReadOnly`: the shared transport token and
  the listener-wide write switch. A request the gate admits carries
  `AuthSourceBearer` on its context, so a caller middleware further in whose
  authenticator verified nothing itself still reports how the request got in —
  inheritance from the code that did the work, replacing core-agent's
  `transportBearerConfigured` config sniff.
- `httpmw.CheckBind`, `httpmw.Gate` and `httpmw.IsLoopback`: the bind policy,
  which asks a gate whether credentials are enforced instead of inspecting a
  config field. The check it replaces keyed off `ClientCAFile != ""`, and no CA
  file exists under SPIFFE — so a working mutually authenticated listener was
  refused as unauthenticated. The gate to hand it is the `*CallerMiddleware`,
  not the authenticator: a bearer table reports `GatesCredentials() == true`
  and is telling the truth about itself, while the surface in front of it
  admits every anonymous request unless `Enforce` is set. Enforcement is
  therefore the middleware's own property, which also means an authenticator
  that does not implement `authn.CredentialGate` — a future OIDC one — yields a
  surface the policy can still approve.
- `authn.HeaderAttachToken`, the side-channel token header, defined in the one
  package both `authn/bearer` and `httpmw` must import so the two cannot drift
  onto different spellings of the same credential.
  `bearer.HeaderAttachToken` is unchanged and now an alias for it.
- `authn.IdentityLookup` now carries the same no-aliasing clause as
  `Authenticate`: the Caller it returns is handed to a handler, so its `Labels`
  must not alias the authenticator's table. `httpmw` clones it regardless — the
  cost of one implementation getting it wrong is a request's mutation
  rewriting a provisioned identity for every request after it.

- `authz`: the per-resource authorization matrix, ported from core-agent's
  `pkg/auth/authorize.go` cell for cell — `ACL`, `Role`, `ACL.RoleOf`, `Allows`
  and `Authorize`, with `ActionList` always permitted so a listing filters
  rather than 403s. The nouns are gone: core-agent's `SessionACL` and its
  `session.read` / `daemon.admin` spellings stay in core-agent, behind a
  wrapper, because a library that names one consumer's resource type invites
  the next consumer to authorize its jobs against a struct called `SessionACL`.
  Three behaviors are stricter than the code they came from: a `Caller` with an
  empty `Identity` is `RoleNone` before the `Admin` bit is consulted, so a
  half-initialized struct cannot own a resource whose `ACL.Owner` was never
  populated either; an unknown `Action` denies, except to `RoleAdmin`, which is
  defined as everything; and `Allows` range-checks its `Role`, since every
  grant below `RoleAdmin` is a `>=` comparison and `Allows` is exported for
  services that resolve a role their own way — an integer read back from a row
  or a mapping table is where an out-of-range value comes from.
- `authz.Rules`: named matchers over identity, email domain, `Caller` labels
  and structured label paths, granting the `Admin` bit and the right to proxy
  — the replacement for core-agent's exact-match `AdminIdentities` and
  `ProxyIdentities`, which scale no better than the token table.
  `MatchPathSegments` and `MatchPathPrefix` are segment-anchored and
  `MatchEmailDomain` anchors on the last `@`, so a rule naming `/ns/prod`
  cannot be satisfied by `/ns/production` or by `/ns/attacker/x/ns/prod/sa/y`,
  and one naming `example.com` cannot be satisfied by `notexample.com`. The
  domain's case is folded over ASCII only, not with `strings.EqualFold`, whose
  Unicode simple folding makes `ſlack.com` and `slacK.com` (U+017F, U+212A)
  equal to `slack.com` — separately registrable IDN domains. A matcher
  assembled from configuration that never got set matches nobody, including
  `MatchAll()` with no matchers and `MatchNot(nil)`; the consequence is that
  the package supplies no way to spell "everyone", which a deployment that
  means it writes in its own source. No rule grants anything to the zero
  `Caller` or to `purser.AnonymousIdentity`, the identity an unauthenticated
  request resolves to where anonymous access is allowed. The rule set is a
  union with no deny rules, so its meaning does not depend on its order and
  `Rules.Apply` never clears a grant somebody else set; exceptions are written
  with `MatchNot`, which is only ever as wide as the comparison it is written
  in — identities are matched byte for byte, so an exception naming one does
  not cover a case-varied spelling of it. `Rules.Matching` reports which named
  rules fired, which is what makes a grant answerable from an audit record.
  Label keys are arguments rather than constants re-declared here — a rule
  reads `MatchPathPrefix(mtls.LabelPath, "ns", "prod")` — because `authz` is
  stdlib-only and two spellings of one key would drift.
- `authz.WithRules`: applies a rule set to any `authn.Authenticator`. Every
  resolved `Caller` passes through `Rules.Apply`, `CanProxyAs` is the union of
  the rules and the authenticator's own allowlist so a migration loses nobody,
  and an identity reached through `authn.IdentityLookup` gets the grants it
  would have had authenticating directly. It refuses at construction an
  authenticator reporting `purser.AuthSourceAnonymous`: applying policy to an
  authenticator that verifies nothing would put the `Admin` bit on requests
  that presented no credential. The returned authenticator implements exactly
  the optional `authn` extensions the wrapped one does, plus
  `authn.AuthenticatorWithProxy`, which rules may grant on their own and which
  reads the same as absence when nothing permits proxying — implementing too
  few makes `httpmw` take asserted identities at face value, and too many
  makes it reject every assertion as unprovisioned, or accept `Enforce` over
  an authenticator that admits everything.
- `authn/oidc`: caller identity from an OpenID Connect ID token — the
  human-operator path, so an engineer's morning sign-in authenticates them to a
  service without anyone issuing, distributing, or revoking a certificate for
  their laptop. `oidc.New` validates options and returns without touching the
  network; discovery and the first key fetch happen on the first request that
  presents a token, so a service starts with a briefly unreachable IdP rather
  than coming up with an authenticator that rejects everything. Only the server
  half is here: obtaining a token is the client's problem.
  It builds on `github.com/go-jose/go-jose/v4` for JWS verification and JWK
  decoding, and owns the layer above it. go-oidc was the alternative, and since
  it depends on go-jose anyway the choice was about policy rather than
  dependency count: its key set applies no rate limit to a token naming an
  uncached key, its verifier checks a single client ID rather than a set of
  audiences, and it carries a hardcoded schemeless-issuer exemption for
  `accounts.google.com`.
- `authn/oidc`: the key cache has two knobs, bounding opposite hazards.
  `KeyRefresh` (15m) is how long a key the issuer *withdrew* keeps verifying
  tokens here — the demand-driven refetch cannot notice a withdrawal, because
  the key ID is one the cache has seen. `KeyRefreshFloor` (30s) is the minimum
  interval between fetches: a token's key ID is read from its *unverified*
  header, so without a floor anyone who can reach the surface can name an
  uncached key ID and turn this service into an amplifier pointed at its own
  IdP. Concurrent refetches are single-flighted and detached from the request
  that triggered them, so the first client to hang up does not cancel the fetch
  for everyone waiting behind it; when a fetch fails and a matching key is
  already cached, the cached key is served, because an IdP that is briefly down
  must not log every operator out of every service. That last point is the
  documented cost of `KeyRefresh`: it bounds a withdrawn key's life only while
  fetches succeed. A panic anywhere inside a fetch — a caller-supplied
  `Transport`, a dependency decoding hostile JWKS bytes — publishes an error to
  the waiters and clears the single-flight slot before it propagates, since
  `net/http` recovers per connection and a slot left occupied would park every
  later request until its own context ended.
- `authn/oidc`: a discovery document is followed only if it declares the issuer
  it was fetched from (RFC 8414 §3.3). Without that check, anything that can
  answer at the issuer's well-known path can point the key fetch at a JWK Set
  of its own and sign tokens for any identity. The `jwks_uri` need only be
  https — a provider's keys legitimately live on another host, as Google's do.
  The scheme checks are backed by a redirect policy on purser's copy of the
  HTTP client that refuses any hop to a non-https URL: `http.Client` follows up
  to ten redirects and crosses from https to http on the way, so without it
  those checks cover only the first URL in the chain and a `302 Location:
  http://...` on the key endpoint gets the key set read in cleartext. A
  `CheckRedirect` of the caller's own still runs, after that one.
- `authn/oidc`: the refusals. Signature algorithms are an allowlist (`RS*`,
  `PS*`, `ES*`, `EdDSA`), so symmetric algorithms and `none` cannot be
  configured back in and a future go-jose addition cannot become acceptable by
  default — a verifier that accepts `HS256` can be handed a token signed with
  the issuer's *public* key. Tokens are parsed with `ParseSignedCompact`, not
  `ParseSigned`, which also accepts the multi-signature JSON serialization. A
  key published for one algorithm does not verify another. `Audiences` may not
  be empty, since the audience is the only thing distinguishing a token minted
  for this service from one minted for any other service of the same issuer. A
  token with no `exp` is refused, RFC 7519 making it optional
  notwithstanding: such a token is a bearer credential valid forever. A payload
  that is not a JSON object is refused rather than read as an empty one, an
  `exp`/`nbf`/`iat` outside the range of an `int64` second is refused rather
  than converted (`int64` of an out-of-range float is implementation-defined:
  amd64 returns `math.MinInt64` whatever the sign, so `"nbf": 1e300` reads as
  long past and passes the not-before check, while arm64 saturates toward the
  sign, so there `"exp": 1e300` reads as the far future and never expires), and
  an identity resolving to whitespace is refused rather than carried, since
  `" "` satisfies every non-empty check in the module and then sits in an ACL
  as something no operator can see.
- `authn/oidc`: every registered claim is looked up by its exact key rather
  than unmarshalled into a tagged struct. `encoding/json` falls back to a
  case-insensitive field match when no exact match exists, and of two keys that
  fold-equal the *last* one in the payload wins — so on a decoder that reads
  the struct, an added claim named `AUD`, `EXP`, `SUB`, `ISS` or
  `Email_Verified` overrides the real one, while the separate exact-keyed
  decode that produces the labels reports the true value. The registered names
  are reserved by every IdP; their case variants are reserved by none, and
  several providers let an application append claims of its own, so the variant
  arrives on a genuinely issuer-signed token.
- `authn/oidc`: `Caller.Identity` is the `email` claim, falling back to `sub`,
  or whichever claim `IdentityClaim` names — with no fallback in that case,
  because a deployment that asked for one claim and silently got another would
  have two shapes of identity in its ACLs. An email-derived identity requires
  `email_verified`, since on most providers the address is a self-service
  profile field. Claims reach policy as labels: `oidc.issuer`, `oidc.sub`,
  `oidc.email`, `oidc.expires_at`, and every other scalar claim under
  `oidc.claim/`. Arrays and objects are dropped rather than flattened.
  `Caller.Admin` is never read from a claim, and `authn.IdentityLookup` is
  deliberately not implemented — there is no table of provisioned identities
  behind a claim-based authenticator, so `ProxyIdentities` is the whole control
  on the proxy path.
- `authtest.NewIssuer`: an in-process OpenID Connect provider, serving
  discovery and a JWK Set over TLS and minting signed tokens. `AddKey` is the
  gradual rotation and `Rotate` the abrupt one; `JWKSRequests` and
  `DiscoveryRequests` are what a test asserts a key cache against; `Close` is
  the IdP outage, after which it still mints. A nil value in
  `TokenOptions.Claims` removes the claim rather than setting it to null, which
  is how a test reaches the payloads a well-behaved provider never emits and an
  attacker will.
- `authtest.Issuer.RawToken` and `RawTokenOptions`: a token assembled
  header-first. `Mint` covers the token that should be accepted and the one
  malformed in its *claims*; this covers the one malformed in its *header* —
  an `alg` the key was not published for, a `kid` naming a key that did not
  sign it, no `kid` at all, `alg: none`, an HS256 MAC keyed by the issuer's own
  public key, or a payload that is not JSON. Those are exactly the shapes a
  verifier has to refuse, and without this they have to be built by splicing
  base64 segments by hand — a test that does that tends to end up asserting
  something other than what it names. `Claims` returns the payload `Mint` would
  have signed, so a test can put its own header or its own extra key over it;
  `KeyID` and `PublicKey` name and export the current signing key. `JWKS`
  returns the served document's bytes and `DefaultSubject` is exported
  alongside `DefaultAudience`.
- `dev/tools/verify-coverage` + `dev/coverage-floors.txt`, the last item
  deferred out of the scaffold: every package is held to its own statement
  floor, not the module to one number, because a repo-wide average lets a
  large easily-covered package fund the gaps in a small dangerous one. A
  package with no floor fails the check rather than arriving unmeasured, and
  lowering a floor costs one reviewable diff hunk in the PR that lowers it —
  the bargain `dev/api-breaks.txt` already makes for the exported API. It
  runs in `dev/tools/ci` right after `test`, on the profile that step wrote,
  and regenerates a profile that is missing or older than a `.go` file rather
  than passing on a stale one. No change to the exported API.

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

[Unreleased]: https://github.com/go-steer/purser/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/go-steer/purser/releases/tag/v0.1.0
