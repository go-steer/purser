# The example on Kubernetes

Two independent cells. They deploy the same two binaries into separate
namespaces and differ only in where the credentials come from:

- **[`pki/`](pki/)** — `purser-example-pki`. cert-manager issues an
  internal CA and three leaf certificates into Secrets. Runs on any
  cluster with cert-manager installed.
- **[`spiffe/`](spiffe/)** — `purser-example-spiffe`. SPIRE issues
  X.509-SVIDs, and a [spiffe-helper](https://github.com/spiffe/spiffe-helper)
  sidecar writes them to a memory-backed volume. Needs SPIRE and the
  SPIFFE CSI driver.

Each cell runs one server and two clients — `hello-client`, which is
served, and `hello-intruder`, which is refused during the handshake with
a certificate that is entirely valid. See [`../README.md`](../) for why
the second one is the interesting one.

## Build and load the image

purser ships no image, so build the examples' one:

```
docker build -f examples/Dockerfile -t purser-examples:latest .
```

The manifests use `imagePullPolicy: IfNotPresent` and an unqualified
tag, so on a local cluster you load it rather than push it:

```
kind load docker-image purser-examples:latest            # kind
minikube image load purser-examples:latest               # minikube
k3d image import purser-examples:latest -c CLUSTER       # k3d
```

On a real cluster, retag to your registry, push, and update `image:` in
the Deployments.

## The PKI cell

Needs [cert-manager](https://cert-manager.io/docs/installation/):

```
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
kubectl -n cert-manager rollout status deploy/cert-manager-webhook
```

Then:

```
kubectl apply -f examples/k8s/pki/
kubectl -n purser-example-pki rollout status deploy/hello-server
```

cert-manager takes a few seconds to fill in the Secrets; until it does,
the pods sit in `ContainerCreating`. Watch the result:

```
kubectl -n purser-example-pki logs -f deploy/hello-client
kubectl -n purser-example-pki logs -f deploy/hello-intruder
```

The client prints a greeting naming itself
`hello-client.purser-example-pki.svc` — its DNS SAN, because the server
runs with `-pki-subject san_dns`. The intruder prints a TLS error. Both
certificates were signed by the same CA; only the OU differs, and the
server admits `-pki-admit-ou platform`.

Clean up with `kubectl delete -f examples/k8s/pki/` (or delete the
namespace; the cluster-scoped objects in this cell are none).

## The SPIFFE cell

Needs a SPIRE server and agent, the
[SPIFFE CSI driver](https://github.com/spiffe/spiffe-csi), and
[spire-controller-manager](https://github.com/spiffe/spire-controller-manager)
for the `ClusterSPIFFEID` CRD. The
[SPIRE Helm charts](https://artifacthub.io/packages/helm/spiffe/spire)
install all three:

```
helm upgrade --install -n spire-mgmt --create-namespace \
  spire-crds spire-crds --repo https://spiffe.github.io/helm-charts-hardened/

helm upgrade --install -n spire-mgmt \
  spire spire --repo https://spiffe.github.io/helm-charts-hardened/ \
  --set global.spire.trustDomain=example.org
```

The trust domain must match `trust_domain` in
[`spiffe/00-namespace.yaml`](spiffe/00-namespace.yaml), which is
`example.org` — change one and change the other.

Then:

```
kubectl apply -f examples/k8s/spiffe/
kubectl -n purser-example-spiffe rollout status deploy/hello-server
kubectl -n purser-example-spiffe logs -f deploy/hello-client
```

The greeting names the caller
`spiffe://example.org/ns/purser-example-spiffe/sa/hello-client` with
`auth_source: spiffe`. The identity comes from the service account, via
the `ClusterSPIFFEID` in
[`spiffe/10-clusterspiffeid.yaml`](spiffe/10-clusterspiffeid.yaml):

```
spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}
```

That resource is cluster-scoped, so `kubectl delete -f` the directory
rather than only deleting the namespace.

### The sidecar

Each pod runs spiffe-helper as a **native sidecar** — an entry in
`initContainers` with `restartPolicy: Always`. It subscribes to the
SPIRE agent's Workload API over the CSI-delivered socket and writes
three files into a `medium: Memory` emptyDir:

```
/var/run/secrets/workload-spiffe-credentials/certificates.pem
/var/run/secrets/workload-spiffe-credentials/private_key.pem
/var/run/secrets/workload-spiffe-credentials/ca_certificates.pem
```

which `mtls.SPIFFEFileSource` reads and re-reads as they rotate. Those
paths and names are GKE managed workload identity's, which is why
[`../gke-mwid/`](../gke-mwid/) is the same manifest with the sidecar
deleted.

It is a native sidecar because of ordering: `hello-server` reads its
SVID at startup and exits if it is not there. The `startupProbe` on
spiffe-helper's `/ready` — which reports ready only once the files are
on disk — is what holds the main container back until it is.

The SVID never touches a Secret and never reaches etcd.
`fsGroup: 65532` is what lets the app container read the `0600` key the
sidecar writes; both run as uid 65532.

### If nothing gets an SVID

- `kubectl -n purser-example-spiffe logs deploy/hello-server -c spiffe-helper`
  is the first place to look. A stuck pod is almost always a pod whose
  `startupProbe` never passed.
- Check the trust domains agree: `helm ... --set global.spire.trustDomain`
  against the ConfigMap in `00-namespace.yaml`.
- `kubectl get clusterspiffeids.spire.spiffe.io purser-example -o yaml`
  shows how many entries the controller matched. Zero means the
  `namespaceSelector` did not match — the namespace must carry the
  `kubernetes.io/metadata.name` label, which Kubernetes sets
  automatically on 1.21+.
- The agent must be running on the node the pod landed on.

## Both cells

Namespaces enforce `restricted` pod security; every container runs as
uid 65532 with a read-only root filesystem and no capabilities. The
Services publish only port 8443. The plaintext `-admin-addr` port
carries `/healthz` for the kubelet probes and is deliberately not in any
Service.
