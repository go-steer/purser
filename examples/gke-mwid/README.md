# The example on GKE, with managed workload identity

The same hello-world server and clients as
[`../k8s/spiffe/`](../k8s/spiffe/). GKE's managed workload identity
(MWID) issues each pod an X.509-SVID from a Google-managed CA and mounts
it — certificate, key and trust anchors — under the same three file
names spiffe-helper was configured to write, so the Go code is
byte-for-byte the same and only the deployment moves:

- the spiffe-helper sidecar and the SPIRE agent socket are gone, and the
  emptyDir they filled is replaced by a `podcertificate.gke.io` CSI
  volume that GKE fills itself;
- the trust domain is the fleet's, `PROJECT_ID.svc.id.goog`;
- peers are named with `-spiffe-admit-gke` / `-spiffe-authorize-gke`
  instead of `-spiffe-admit-id` / `-spiffe-authorize-id`, which is a
  convenience over the same matcher, not a different check;
- Standard clusters need a `nodeSelector` for the metadata server.

That is the argument for reading credentials from files rather than from
an agent socket, made concrete: MWID publishes no SPIFFE Workload API to
dial. See [`../README.md`](../) for the longer version.

## What you need first

MWID is a fleet-level feature. The setup below is Google's, not
purser's; [what it
is](https://cloud.google.com/iam/docs/managed-workload-identity) and
[how to turn it
on](https://cloud.google.com/iam/docs/create-managed-workload-identities-gke)
are authoritative and this is a summary of the shape of it.

1. **A fleet.** The cluster must be registered to a fleet, and the trust
   domain is the *fleet host project's* workload identity pool —
   `PROJECT_ID.svc.id.goog`. Not the cluster. Two clusters in one fleet
   issue indistinguishable identities for the same namespace and service
   account name.

2. **A CA pool** in Certificate Authority Service, with a subordinate CA
   and a **certificate issuance config** (CIC) referencing it, in each
   region your nodes run in.

3. **IAM on that pool** for the GKE service agent:
   `roles/privateca.poolReader` and
   `roles/privateca.workloadCertificateRequester`.

4. **The cluster enabled** for managed workload identity, pointed at the
   CIC and the trust domain.

5. **A recent GKE version.** MWID needs the `podcertificate.gke.io` CSI
   driver present on the nodes; older clusters do not have it.

Confirm the pieces are live before deploying anything: a pod whose
credential cannot be issued sits in `ContainerCreating`, because the
volume mount is what blocks.

## Build and push the image

purser ships no image.

```
REGION=us-central1
PROJECT_ID=your-fleet-project

gcloud artifacts repositories create purser-examples \
  --repository-format=docker --location="$REGION"

docker build -f examples/Dockerfile \
  -t "$REGION-docker.pkg.dev/$PROJECT_ID/purser-examples/hello:latest" .
docker push "$REGION-docker.pkg.dev/$PROJECT_ID/purser-examples/hello:latest"
```

## Deploy

Two placeholders to replace: `PROJECT_ID` in
[`00-namespace.yaml`](00-namespace.yaml), and the `image:` in the two
Deployments.

```
sed -i "s/project_id: PROJECT_ID/project_id: $PROJECT_ID/" \
  examples/gke-mwid/00-namespace.yaml
sed -i "s|REGION-docker.pkg.dev/PROJECT_ID|$REGION-docker.pkg.dev/$PROJECT_ID|" \
  examples/gke-mwid/*.yaml

kubectl apply -f examples/gke-mwid/
kubectl -n purser-example-gke rollout status deploy/hello-server
kubectl -n purser-example-gke logs -f deploy/hello-client
```

Do not touch `trustDomain: fleet-project/svc.id.goog` in the CSI volume.
Despite appearances it is not a placeholder — it is a fixed nickname
meaning "this fleet's SVID pool". (A self-managed pool uses
`fleet-project/tenancy-scope`.)

On a Standard cluster the pods carry
`nodeSelector: iam.gke.io/gke-metadata-server-enabled: "true"`. Delete
those three lines on Autopilot, which has no unlabelled nodes to keep
the pod away from.

## What you should see

`hello-client` is served:

```json
{
  "greeting": "hello, spiffe://PROJECT_ID.svc.id.goog/ns/purser-example-gke/sa/hello-client",
  "caller": "spiffe://PROJECT_ID.svc.id.goog/ns/purser-example-gke/sa/hello-client",
  "auth_source": "spiffe",
  "labels": {
    "spiffe.trust_domain": "PROJECT_ID.svc.id.goog",
    "spiffe.path": "/ns/purser-example-gke/sa/hello-client",
    "cert.issuer_dn": "...",
    "cert.serial": "...",
    "cert.not_after": "..."
  },
  "served_by": "hello-server-..."
}
```

`hello-intruder` is refused during the handshake, holding a credential
from the same Google-managed CA that is valid in every respect. That is
the whole lesson of this cell. Under MWID every workload in the fleet
holds a certificate that chains to the same anchors, so "the trust
bundle verifies it" narrows a caller down to *someone in the fleet*. The
server admits one named ID:

```
-spiffe-admit-gke=$(PROJECT_ID)/purser-example-gke/hello-client
```

`-spiffe-admit-gke` and `-spiffe-admit-id` reach the same decision;
`mtls.MatchGKEWorkload` assembles the ID from the three parts that
actually vary rather than from a `spiffe://` string that is easy to
paste slightly wrong.

The clients name the server too, with `-spiffe-authorize-gke`. A SPIFFE
client verifies with `InsecureSkipVerify` set and go-spiffe checking the
peer ID, so no hostname is checked anywhere: a client that does not name
its server accepts any workload in the fleet that answers the address.

## Troubleshooting

**Pods stuck in `ContainerCreating`.** Almost always credential
issuance, since the mount blocks until the certificate exists. On a cold
pod the legitimate wait can run to several minutes; longer than that,
check the events:

```
kubectl -n purser-example-gke describe pod -l app=hello-server
```

CSI errors there generally point back at the CA pool IAM grants or a
missing certificate issuance config in the node's region.

**`permission denied` reading the mount.** The manifests run as uid
65532 with `fsGroup: 65532`, which is what a `restricted`-profile
namespace wants. Google's documentation does not specify the ownership
or mode the driver applies to the mounted files, and it has changed
before. Look at what is actually on disk rather than relaxing the pod:

```
kubectl -n purser-example-gke debug -it deploy/hello-server \
  --image=busybox --target=hello-server \
  -- ls -ln /var/run/secrets/workload-spiffe-credentials
```

Then set `fsGroup` to the gid that shows, or `runAsUser` to the uid.
Dropping `runAsNonRoot` or the namespace's `restricted` label would also
make the read succeed, and is the wrong fix: it trades a file-mode
problem for a privileged pod.

**Wrong trust domain.** `-spiffe-trust-domain` must be the fleet
project's pool, `PROJECT_ID.svc.id.goog`, not the cluster name and not a
domain you own. A mismatch fails the handshake with a trust-domain
error, not a certificate error.

## What this cell does not cover

- **Self-managed pools.** `mtls.MatchGKEWorkload` builds fleet IDs
  (`PROJECT_ID.svc.id.goog`). A self-managed pool has a different trust
  domain shape and no matcher of its own yet; use `-spiffe-admit-id`
  with the literal ID.
- **The PKI profile on GKE.** Nothing about `mtls.NewPKI` changes on
  GKE — mount the certificate from a Secret exactly as
  [`../k8s/pki/`](../k8s/pki/) does. There is no separate cell because
  there would be nothing in it.
