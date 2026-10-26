# Fresh Grant + Exposure only (isolated IED development)

Target context: `gke_patch2-the-new-era_asia-northeast3_ied-cluster`.
Target namespace: `grant-exposure-v020`. Ownership label:
`deployment.exposure.io/owner=grant-exposure-v020`.

This is a **new, non-HA development stack**, not a migration or replacement.
Do not touch `patch-data-grant-exposure-go-v1`, `operable`, or their databases,
PVCs, identities, objects, policies or workload templates. No old state is copied.
There is no Patch Data, PocketBase, Compos, Litestream, extra auth container,
operator, or remote object-store service in this deployment.

## Topology and preservation

One `StatefulSet/grant-exposure`, one replica/Pod, contains only Grant and
Exposure as two containers, **not independent workloads**. Replacing either
container image by replacing that Pod restarts both processes. This is non-HA;
the dedicated PVC protects Grant state, not availability.
Grant runs the supported `GRANT_RHIZA_CONFIG_JSON={"Local":true}` mode with new
unique cluster/node IDs and `/data/rhiza` on `PVC/grant-state` (5 GiB,
`standard-rwo`). Backups remain under `/data/backups` on the same PVC; these are
not off-cluster disaster recovery. No native membership, peer credentials,
remote transport, object prefix, learner or operator is configured. Exposure is
stateless and calls the colocated Grant directly for both PDP and native APIs.
`GRANT_PEER_ADDR` is explicitly empty: omission defaults to a listener and Rhiza
rejects local mode with any peer listener, including `127.0.0.1:0`.

The explicit PVC is not owned by the StatefulSet and survives deleting/stopping
that workload. Never delete the namespace/PVC as a rollback. `OnDelete` prevents
an unnoticed pod replacement when the template changes. Readiness requires
Grant strong read/write checks plus a verified active Exposure catalog. Health
probes are process-only; an unavailable catalog does not cause restart loops.

`Service/grant` is private/headless (8080, including unready addresses for initial
bootstrap); `Service/exposure` is private ClusterIP (8080 to 8082). Admin 8083 has
no Service. Namespace-only ingress policy and no public Ingress, HTTPRoute,
NodePort or LoadBalancer are created. Egress allows TCP 8443 only to the separate
temporary auth namespace plus TCP/UDP 53 for managed/node-local DNS. The auth
owner must permit inbound 8443 from `grant-exposure-v020`; no broad old-stack
access is required. Grant mounts the fixture's **public CA only** at
`/etc/grant-goauthy/ca.pem` and sets `SSL_CERT_FILE`; TLS trust and the stable
issuer hostname are verified, never bypassed.
ServiceAccount token automount is disabled. Images are AMD64 digest pins;
containers are nonroot, read-only root filesystem, capabilities dropped, with
bounded CPU/memory and private temporary volumes.

## Inputs and image gate

Copy `config.example.json` **outside Git** and fill the official Grant release
image digest, tag and source revision. Never deploy a local build or the old
release. Exposure is fixed at v0.2.0:
`ghcr.io/mrchypark/exposure@sha256:268d5ded6ec941af266306cf63f09c32a0ec38057b95f6c5ceb140afb04cce62`.
The example deliberately fails rendering until Grant release fields are filled.
Verify the supplied Grant digest/tag/revision against the official release and
successful GHCR Actions result before apply; syntax validation is not provenance.

Generate generation 1 catalog and action definitions from **the matching released
Grant source**, using its supported `cmd/grant-management-catalog` CLI:

```sh
# This verifies a clean source checkout, published tag and exact source SHA:
./deploy/grant-exposure/prepare-catalog.sh "$CONFIG" "$GRANT_SOURCE" "$PRIVATE_DIR/generated"
# In this repository (render only):
./deploy/grant-exposure/render.sh "$CONFIG" "$PRIVATE_DIR/generated/catalog.json" > "$PRIVATE_DIR/runtime.json"
```

No producer payload is patched by hand and no catalog is synthesized by shell.
Review method/path/action/resource policies and the pin before staging. There is
no old management orgless fallback in Exposure; explicit catalog policy applies.

## Credentials (private files, no values in logs/Git)

Generate distinct fresh `master`, `app`, and `limiter` files with `umask 077` in
an operator-owned temporary directory. For each file use
`openssl rand -hex 32 | tr -d '\n' > "$PRIVATE_DIR/KEY"` without tracing.
Never reuse development defaults, source master/app keys or voter identities.
Create only `Secret/runtime-credentials` in the new namespace, containing keys
`master`, `app`, `limiter`, and `goauthy-introspection` through Kubernetes
`--from-file` arguments; do not print a Secret manifest.

The standalone real-Goauthy owner manages only `test-goauthy/` and temporary
namespace `grant-exposure-auth-test-v020`. The stable issuer is
`https://goauthy.grant-exposure-auth-test-v020.svc.cluster.local:8443`.
Consume that owner's private-file contract: `issuer`, `clientID`, `audience`, and
`requiredScopes` must match the new config's issuer, introspection/expected
client ID, resource and scopes. Context and namespace must identify this IED
fixture. `clientSecretFile` and `caFile` are absolute paths to
0600 files in its 0700 task directory. No private CA key is copied. An optional
`accessTokenFile` belongs to native bootstrap/live smoke only and contains the
real user's token; provisioning does not read it. No old Goauthy Secret/client/user
is reused. Confirmed fresh client is `grant-exposure-v020-test`, audience
`https://grant-exposure-v020.test/management`, scopes `openid goauthy.read`.

`provision.sh` verifies the actual fixture client-configuration endpoint over
TLS using the supplied CA, its response-byte ETag, bootstrap/confidential/enabled
metadata, expected client/issuer/resource, code+refresh grants and required
scopes. Grant's identity-binding API remains the authoritative second check,
including the exact registered redirect manifest. The separate fixture performs
genuine authorization-code/PKCE/state login; no made-up token is accepted.

`Secret/ghcr-pull` must contain **only** a `ghcr.io` Docker auth entry. Extract
only that entry from the approved `mrchypark` login; never copy other registry
credentials or perform global Docker login. The refreshed CLI's `read:packages`
credential passed the exact released Exposure digest check; the earlier Docker
entry did not. Recheck with `check-pull.sh` for **both official digests** before
any provision phase. Do not make packages public or substitute another image.

## Fresh deployment and supported bootstrap order

After the parent integration checkpoint, use the explicit provision phases.
Every phase checks the official Grant release/source and both pinned manifests.
`check`, `secrets`, and `runtime` also verify the fixture contract/client/CA.
`infra` needs no user token or running auth fixture, but still requires the
official images/pull access and reviewed public runtime configuration.

```sh
# Read-only preflight; paths supplied by the deployment and auth owners:
./deploy/grant-exposure/provision.sh check "$CONFIG" "$CATALOG" "$GHCR_CONFIG" "$AUTH_CONTRACT" "$OWNERSHIP"
# Future writes after parent integration, not commands executed during prep:
./deploy/grant-exposure/provision.sh infra "$CONFIG" "$CATALOG" "$GHCR_CONFIG" "$AUTH_CONTRACT" "$OWNERSHIP"
./deploy/grant-exposure/provision.sh secrets "$CONFIG" "$CATALOG" "$GHCR_CONFIG" "$AUTH_CONTRACT" "$OWNERSHIP"
./deploy/grant-exposure/provision.sh runtime "$CONFIG" "$CATALOG" "$GHCR_CONFIG" "$AUTH_CONTRACT" "$OWNERSHIP"
```

The initial `infra` phase requires the namespace to be absent and a nonexistent
receipt path. It **creates**, never applies/adopts: a fresh namespace cannot have
an existing `grant-state` PVC. Its receipt records the namespace UID immediately
and PVC UID after creation. Any partial failure retains the receipt/resources;
an incomplete receipt fails closed and requires inspection, not silent adoption.
Retries verify the exact original namespace/PVC UIDs, owner labels, nondeletion
and expected storage. A same-name recreated/foreign PVC is rejected. Secrets and
runtime are create-only; existing credentials are never rotated or adopted.
Their UIDs and the CA ConfigMap/StatefulSet UIDs are appended to the receipt.
Record the later PVC/PV binding, image pins and config hashes as nonsecret evidence.

The secret phase generates fresh distinct master/app/limiter values only into
private temporary files, injects Secrets without printing their JSON, and removes
its temporary files on success/failure. Only the public CA is copied to the new
`goauthy-trust` ConfigMap. Private input files remain the supplying owner's
responsibility until successful injection, then are cleaned up as coordinated.

For local fixture preflight, use its owned TLS port-forward and optionally set
`GOAUTHY_CONNECT_TO=goauthy.grant-exposure-auth-test-v020.svc.cluster.local:8443:127.0.0.1:18443`.
This changes only the socket destination; certificate verification still uses
the configured issuer name and CA. No `-k` or insecure verification is allowed.

The initial Pod is expected to be unready because Exposure has no catalog yet.
**Do not wait for full Pod/StatefulSet readiness before bootstrap**. Use
an owned, loopback-only port-forward to that **Pod**, not a ready-only Service:

```sh
kubectl --context gke_patch2-the-new-era_asia-northeast3_ied-cluster -n grant-exposure-v020 port-forward --address 127.0.0.1 pod/grant-exposure-0 18080:8080 18082:8082 18083:8083
```

1. Run `stage-readiness.sh grant "$OWNERSHIP"` to check the exact StatefulSet/Pod
   owner and **Grant container** readiness only (Exposure may remain unready).
   Verify Grant `/healthz` and strong `/readyz` through the Pod forward before
   writes. The headless Service publishes unready addresses for private bootstrap;
   it is not evidence that the entire stack is traffic-ready. Seed bootstrap
   creates only the reserved user, same-ID organization and owner membership;
   it does not provision an external auth identity or application.
2. With the new master key **and a real Goauthy user bearer**, call private
   `POST /api/v1/admin/bootstrap/owner` with `X-Organization-ID` set to the new
   organization. This validates the external identity and atomically links the
   user/organization/owner through supported APIs.
3. Register the new local management application separately through its native
   organization application API. Bind it through the supported master-protected
   identity-binding API; require actual Goauthy client-configuration verification
   and `ready` provisioning. Never edit SQL/provisioning_status directly.
4. Through supported APIs register/update the generated `grant-management`
   provider/actions, configure application action admission/trust, and create the
   active PEP binding with private
   `PUT /ops/providers/grant-management/enforcers/{freshPepID}`. Do not infer user
   permission from application admission. Give the synthetic owner only the
   intended organization management role, not platform-admin privileges.
5. Stage the unmodified generation-1 catalog through
   `POST /api/v1/admin/providers/grant-management/http-capability-generations`.
   Activate with null expected generation/digest and the exact target generation
   and digest, through the supported `/http-capability-active` endpoint. If a
   generation already exists, stop and inspect; do not overwrite/reuse a pin.
6. Activation lets Exposure fetch and verify its exact configured catalog pin.
   Require Exposure admin `/readyz`, then `stage-readiness.sh complete "$OWNERSHIP"`
   (both containers and full Pod Ready). Only now use the ready-gated Exposure
   Service and run `smoke.sh`. Its optional authenticated
   checks use `USER_CURL_CONFIG` (a private curl config containing only the actual
   user Authorization header) and `ORGANIZATION_ID`. No bearer appears in argv,
   URL queries, output or traces. Do not claim counters from HTTP status alone.

`bootstrap.sh` implements that sequence against only the new owned Pod's private
Grant forward. It checks readiness and exact release/catalog template pins,
reads only the recorded new Secret UID, and validates the fixture contract.
It registers the provider/actions, bootstraps the real owner, registers the app
with the actual client's exact redirect manifest, then verifies identity binding
through Goauthy before trusting the app. It uses supported APIs and conditional
ETags, never SQL or a provisioning-status override. It admits only organization
detail, groups read and admin-users read to the app; the user role gets only the
two organization actions bound to this organization. The admitted platform
action deliberately has no user grant and must be denied. Finally it registers
the PEP and stages/activates generation 1 with null previous state. A previously
active catalog or unexpected existing provider/app stops the helper; it does
not replay blindly over partially configured state.

```sh
GOAUTHY_CONNECT_TO=goauthy.grant-exposure-auth-test-v020.svc.cluster.local:8443:127.0.0.1:18443 \
  ./deploy/grant-exposure/bootstrap.sh "$CONFIG" "$CATALOG" "$ACTIONS" "$AUTH_CONTRACT" "$OWNERSHIP"
# Exposure refresh and Pod probes are asynchronous; check again until complete:
./deploy/grant-exposure/stage-readiness.sh complete "$OWNERSHIP"
```

Only the helper's private temporary curl configs contain credentials; they and
response bodies are removed on exit. A failure prints bounded method/path/status
and retains existing cluster state for inspection, never a Secret/token/body.
The intended reader role/binding, identity, app, PEP and catalog are desired new
stack configuration, not temporary policy fixtures to remove after testing.

API operations use a protected curl config for master/bearer headers; errors
must report bounded status, not tokens or sensitive response bodies. `/ops` and
master bootstrap always go to the private Grant port, never Exposure.

## Live user login and evidence limits

The standalone fixture owner supplies a new test user/client and genuine
authorization-code login with state, S256 PKCE, the registered redirect and code
exchange, plus private access/refresh-token files. Do not research or reuse old
interactive-login apps, tokens or Secret values. Do not use client_credentials
as a user identity. The returned token must match expected client/resource/scope.

Without a real user bearer, do not fabricate a JWT or grant allow. Infrastructure,
runtime health and negative transport checks can be prepared independently, but
owner/app identity binding and live authenticated allow/deny remain pending.
Catalog publication itself does not prove user permission or live Goauthy E2E.
After live tests, the fixture owner stops/removes only its temporary Goauthy
resources. The permanent Grant/Exposure stack remains; once that IdP is down,
new authentications/refreshes may fail closed (and cached identities expire).
Persisted Grant state/catalog and process health are not continuing IdP availability.

## Ownership, cleanup and stop/removal

Leave the desired new deployment running after verification. Stop only owned
port-forward PIDs and remove private temporary credential/token/config files
after injection, checking removal. Preserve non-secret test results and ownership
records. Smoke is read-only and creates no test policies or users. Intended
bootstrap identities and catalog are desired configuration, not disposable tests.

Offline guard coverage: `./deploy/grant-exposure/test-ownership.sh` uses a
rejecting mock kubectl, testing absence, matching retry UIDs, recreated/foreign
namespace/PVC, deleting resources, storage mismatch, API failure and incomplete
receipts. No cluster writes are part of these tests. `test-goauthy/` has a
separate owner and is never modified or cleaned up by these permanent scripts.

To stop this stack while preserving state (do not run against another namespace):

```sh
kubectl --context gke_patch2-the-new-era_asia-northeast3_ied-cluster -n grant-exposure-v020 scale statefulset/grant-exposure --replicas=0
```

Deletion of `namespace/grant-exposure-v020` destroys its PVC and may delete the
backing disk. It is **not** a rollback command and requires an explicit decision
about the new data. Verify namespace ownership/UID and preserve any valuable
state before a separately authorized permanent removal. No cleanup command here
selects existing production namespaces or shared resources.
