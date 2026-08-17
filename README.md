# purser

Shared authentication and authorization for [go-steer](https://github.com/go-steer)
services: caller identity from SPIFFE X.509-SVIDs, standard-CA client
certificates, and OIDC tokens.

A purser is the officer who checks who is aboard. That is the whole job here —
turn a TLS connection or an HTTP request into a `Caller`, and answer whether
that caller may perform an action.

> **Status: scaffold.** No API yet. This repo currently holds the module,
> the license, and the CI guardrails; the library lands in phase 1a.

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

## Design

The design lives with the service that motivated it:
[`core-agent/docs/purser-auth-design.md`](https://github.com/go-steer/core-agent/blob/main/docs/purser-auth-design.md).
Read it before adding to the API surface. In short:

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
