# purser

Shared authentication and authorization for [go-steer](https://github.com/go-steer)
services: caller identity from SPIFFE X.509-SVIDs, standard-CA client
certificates, and OIDC tokens.

A purser is the officer who checks who is aboard. That is the whole job here —
turn a TLS connection or an HTTP request into a `Caller`, and answer whether
that caller may perform an action.

> **Status: phase 1a complete.** The identity contract, the test harness, the
> bearer-token table, both mTLS profiles — standard-CA and SPIFFE — the
> dialling half in `client`, the HTTP middleware, OIDC, and the authorization
> layer are in place, with a worked example under [`examples/`](./examples/)
> and a per-package coverage floor holding them there. The API is not tagged
> yet, so treat it as unstable until there is a release: phase 2 migrates
> `core-agent` and `mast` onto it, and what that first real consumer runs into
> is what the tag will reflect.

## Why it exists

Every go-steer service that exposes an HTTP/SSE surface needs the same two
layers, and today they each solve them differently or not at all:

- **Connection admission** — should this TLS peer be allowed to connect?
- **Caller identity** — *who* is on the other end, so the request can be
  attributed, authorized, and audited?

`core-agent` ships the second layer as a static bearer-token → identity table,
which does not scale past a handful of operators. `mast` carries an undrifted
fork of that code. `k8s-lookout` has no answer at all. Extracting the layer once,
with real identity sources behind it, is cheaper than four divergent copies —
and a standalone module is far easier to test at the component level than a
package buried in a daemon.

## Consumers

| Repo | Role |
|---|---|
| [`core-agent`](https://github.com/go-steer/core-agent) | server (attach endpoint), client |
| [`mast`](https://github.com/go-steer/mast) | server — replaces its `pkg/auth` fork |
| [`core-tui`](https://github.com/go-steer/core-tui) | client |
| [`switchboard`](https://github.com/go-steer/switchboard) | client |
| [`k8s-lookout`](https://github.com/go-steer/k8s-lookout) | server |

## Packages

| Package | Contents |
|---|---|
| `purser` | `Caller`, `AuthSource`, the sentinel errors, and the context plumbing. Stdlib-only and depends on no other purser package, so a client that merely reads an identity off a context links nothing else. |
| `authn` | The `Authenticator` contract and its implementations. Each credential type lands in its own subpackage. |
| `authn/bearer` | The static token table, kept for compatibility with deployments running one today. It is the thing purser exists to replace, not the thing to reach for in a new deployment. |
| `authn/mtls` | Caller identity from a client certificate, in two profiles: `NewPKI` for certificates from a standard CA, `NewSPIFFE` for X.509-SVIDs. Each constructor returns a `*tls.Config` and the `Authenticator` that understands the connections it admits, together — the two are one decision, and the profiles verify with opposite `crypto/tls` idioms. Also the connection-admission matchers for both, anchored so that a rule naming one namespace cannot be widened into one naming several. |
| `authn/oidc` | Caller identity from an OpenID Connect ID token — the human-operator path, so an engineer's morning sign-in authenticates them without anyone issuing a certificate for their laptop. `New` does no network I/O; discovery and the key fetch happen on the first token. The key cache refetches both on an unseen key ID and on age, under a floor that keeps an unauthenticated caller from turning this service into an amplifier pointed at its own IdP. `Caller.Admin` is never read from a claim. |
| `httpmw` | The serving half: `NewCaller` puts the `Caller` and the auth-source verdict on the request context, `NewBrowserWriteGuard` closes the browser CSRF vectors against a JSON API, `NewTokenGate` is the shared transport token, and `CheckBind` refuses to bind a network address unless something in that chain reports that it enforces credentials. Stdlib-only; it learns everything about a credential through the `authn` interfaces. |
| `authz` | The deciding half: an `ACL` and the Admin / Owner / Contributor / Viewer matrix for one resource, plus `Rules` — named matchers over identity, email domain, SPIFFE path segments and labels that grant the `Admin` bit and the right to proxy, replacing the exact-match identity lists that scale no better than the token table. `WithRules` applies a rule set to any `Authenticator`. Stdlib-only, and it names no resource type: the vocabulary is the consuming service's. |
| `client` | The dialling half of `authn/mtls`: `NewPKI` and `NewSPIFFE` return a `*tls.Config` that pairs with a listener from the matching server constructor, and `Transport` wraps one in an `http.Transport` that keeps HTTP/2. |
| `authtest` | An in-memory CA, an in-process OIDC issuer, and `RunAuthenticatorSuite`, the conformance suite every `Authenticator` — here and in consuming repos — is expected to pass. |

## Example

[`examples/`](./examples/) is a hello-world REST/JSON server and client
deployed four ways — locally, on Kubernetes with cert-manager, on Kubernetes
with SPIRE, and on GKE with managed workload identity — over both mTLS
profiles. Every cell deploys two clients, one that is served and one holding an
equally valid certificate that is refused during the handshake.

```bash
examples/local/demo    # no root, no network, no infrastructure
```

That script is also the `smoke` step of `dev/tools/ci`. purser itself ships no
binary and no image; the examples are a demonstration and a test, not a
product.

## Design

[`docs/DESIGN.md`](./docs/DESIGN.md) is the design of record — the phase plan,
the decisions and why they went that way, and the properties the tests exist to
pin. Read it before adding to the API surface. In short:

- Two mTLS profiles — standard PKI and SPIFFE — verified with opposite
  `crypto/tls` idioms, behind one matched-pair constructor that returns a
  `*tls.Config` and the authenticator that understands it.
- Connection-layer authorization and identity extraction are separate concerns.
  Identity is *always* extracted and passed on, whatever the connection
  authorizer decided.
- SPIFFE is the goal, but nothing may require it: certificates from a standard
  CA are a first-class path.

## Development

```bash
dev/tools/ci    # every check CI runs, in fast-fail order
```

See [`dev/README.md`](./dev/README.md) for the tooling layout and
[`AGENTS.md`](./AGENTS.md) for the conventions this repo is developed under.

## License

Apache 2.0 — see [LICENSE](./LICENSE).
