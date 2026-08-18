# purser by example

A hello-world REST/JSON service and the client that calls it, wired up
four ways. One binary pair, one library, four deployments:

| Cell | Credentials from | Run it |
| --- | --- | --- |
| [`local/`](local/) | files minted by `mint-credentials` | `examples/local/demo` |
| [`k8s/pki/`](k8s/) | cert-manager, in a Secret | `kubectl apply -f` on any cluster |
| [`k8s/spiffe/`](k8s/) | SPIRE, via a spiffe-helper sidecar | needs SPIRE |
| [`gke-mwid/`](gke-mwid/) | GKE managed workload identity | needs a GKE fleet |

Everything under `examples/` is a demonstration. purser itself ships no
binary and no image; its product is the exported API, and these programs
exist to show what calling it looks like and to keep it honest — the
local cell runs on every CI build as the `smoke` step.

## The point of the thing

Two workloads, no human. The server answers `GET /hello` with who it
thinks called:

```json
{
  "greeting": "hello, spiffe://example.org/ns/default/sa/hello-client",
  "caller": "spiffe://example.org/ns/default/sa/hello-client",
  "auth_source": "spiffe",
  "labels": {
    "cert.issuer_dn": "CN=purser examples",
    "cert.not_after": "2026-08-18T19:57:18Z",
    "cert.serial": "8c52796f0e3519fc54a3644d12feb61",
    "spiffe.path": "/ns/default/sa/hello-client",
    "spiffe.trust_domain": "example.org"
  },
  "served_by": "hello-server-7d4f8c9b5-x2klm"
}
```

The labels are the authenticator's, not the application's — purser attaches
them to every `Caller` for audit.

Every cell deploys *two* clients: one that is served and one that is
refused. The refused one is the half that matters. Its certificate is
valid, current, and issued by the same CA — it is refused because the
server admits one named peer and this is not it. A demo where every
credential works only demonstrates that TLS is switched on.

The refusal happens at the handshake, and *which* layer it happens at
is the library's central distinction:

- **Admission** (layer A) happens during the handshake. A refused peer
  never reaches `net/http`, so no handler runs and nothing is logged at
  the application layer. This is `-pki-admit-ou` / `-spiffe-admit-id`,
  and it is what turns the second client away in every cell.
- **Identity** (layer B) is extracted from every admitted connection,
  unconditionally, and is what the handler reads off the context. It
  never rejects anything; an unrecognized-but-admitted peer still gets
  a `Caller`, and deciding what that caller may *do* is the consuming
  service's job, not purser's.

## The programs

```
cmd/hello-server       serves GET /hello over mTLS
cmd/hello-client       calls it, once or forever
cmd/mint-credentials   writes a throwaway CA and three identities to a directory
internal/hello         the wire contract and both halves of the exchange
internal/profile       flags -> (*tls.Config, authn.Authenticator)
internal/credentials   the minting, shared by the command and the tests
```

`internal/profile` is the file to read first. It is the only place in
the examples that mentions purser's constructors, and it is about a
page of real code:

```go
// server, PKI profile
tlsCfg, auth, err := mtls.NewPKI(mtls.PKIOptions{ ... })

// server, SPIFFE profile
tlsCfg, auth, err := mtls.NewSPIFFE(mtls.SPIFFEOptions{ ... })
```

Both return a `*tls.Config` and the authenticator that reads it, as a
matched pair, because the two profiles verify with opposite
`crypto/tls` idioms — PKI populates `VerifiedChains`, SPIFFE leaves it
empty and puts the peer in `PeerCertificates`. Pairing a SPIFFE
authenticator with a PKI listener would be a silent hole, so the API
does not let you.

The client side is the same shape, minus the authenticator:

```go
tlsCfg, err := client.NewSPIFFE(client.SPIFFEOptions{ ... })
httpClient := &http.Client{Transport: client.Transport(tlsCfg)}
```

## Running it locally

```
examples/local/demo            # both profiles
examples/local/demo pki
examples/local/demo spiffe
```

No root, no network, no infrastructure. The script mints credentials
into a temporary directory, starts the server on an ephemeral loopback
port, runs both clients, and asserts that the authorized one got in and
the unauthorized one did not. `dev/tools/smoke` and the `smoke`
presubmit are both this script.

To drive the pieces by hand:

```
go run ./examples/cmd/mint-credentials -dir /tmp/creds -profile spiffe

go run ./examples/cmd/hello-server \
  -profile spiffe \
  -spiffe-dir /tmp/creds/server \
  -spiffe-trust-domain example.org \
  -spiffe-admit-id spiffe://example.org/ns/default/sa/hello-client

go run ./examples/cmd/hello-client \
  -profile spiffe \
  -spiffe-dir /tmp/creds/client \
  -spiffe-trust-domain example.org \
  -spiffe-authorize-id spiffe://example.org/ns/default/sa/hello-server
```

Swap `client` for `unauthorized` in the last command to watch the
refusal. The minted keys never leave the directory you name and are not
checked in; regenerate them whenever.

### Flags

Shared, from `internal/profile`:

| Flag | Meaning |
| --- | --- |
| `-profile` | `pki` or `spiffe` |
| `-pki-cert`, `-pki-key` | this workload's certificate and key |
| `-pki-peer-ca` | anchors the peer's certificate must chain to |
| `-pki-subject` | where the caller's name comes from: `san_dns`, `san_uri`, `san_email`, `subject_cn`, `subject_dn` |
| `-pki-admit-ou` | *server*: admit only peers with this OU |
| `-pki-reload` | how often to re-read the certificate and key; `0` means 30s, negative pins them |
| `-spiffe-dir` | directory holding `certificates.pem`, `private_key.pem`, `ca_certificates.pem` |
| `-spiffe-trust-domain` | e.g. `example.org` |
| `-spiffe-reload` | how often to re-read those files; `0` means 30s, negative disables reloading |
| `-spiffe-admit-id` | *server*: admit this SPIFFE ID (repeatable) |
| `-spiffe-admit-gke` | *server*: admit `PROJECT/NAMESPACE/SERVICEACCOUNT` (repeatable) |
| `-spiffe-authorize-id` | *client*: the server ID to accept (repeatable) |
| `-spiffe-authorize-gke` | *client*: the same, as `PROJECT/NAMESPACE/SERVICEACCOUNT` |

`hello-server` adds `-addr`, `-admin-addr`, `-addr-file`, `-name`,
`-shutdown-grace`. `hello-client` adds `-url`, `-count` (`0` = forever),
`-interval`, `-timeout`, `-retries`, `-retry-delay`.

The `-spiffe-dir` file names are not arbitrary: they are the three GKE
managed workload identity writes, so the local cell, the SPIRE cell and
the GKE cell all point at the same layout and differ only in who fills
it.

## Why files and not the Workload API

The SPIRE cell runs a [spiffe-helper](https://github.com/spiffe/spiffe-helper)
sidecar that subscribes to the Workload API and writes PEM files, which
purser's `mtls.SPIFFEFileSource` reads and re-reads. The obvious
alternative — `workloadapi.X509Source`, talking to the agent socket
directly — is deliberately not used here, for two reasons:

1. **It does not generalize.** GKE managed workload identity publishes
   no Workload API socket. It mounts files. A code path built on the
   socket would work in the SPIRE cell and have to be rewritten for the
   GKE one.
2. **It costs the module graph.** `workloadapi` pulls in gRPC and
   protobuf. purser is a library that many services will depend on, and
   dragging that in for one deployment shape is not a trade worth
   making.

`mtls.SPIFFEFileSource` costs one sidecar in the SPIRE cell and nothing
at all on GKE, and it is the same three lines of Go in both. Nothing
stops a consuming service from using `workloadapi.X509Source` — it
satisfies the same `x509svid.Source` / `x509bundle.Source` interfaces
purser accepts.

## Building the image

The manifests need an image; purser publishes none.

```
docker build -f examples/Dockerfile -t purser-examples:latest .
```

Both binaries land in the image (`/hello-server`, `/hello-client`) and
the manifests pick one with `command:`. See [`k8s/README.md`](k8s/) for
loading it into kind or minikube, and [`gke-mwid/README.md`](gke-mwid/)
for pushing it to Artifact Registry.
