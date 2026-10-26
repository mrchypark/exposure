# Stage A development template

Authorized target annotation: `gke_patch2-the-new-era_asia-northeast3_ied-cluster`.
The single Pod is in `grant-compos-exposure-v1`; Exposure is the only `ClusterIP`
Service. The bundle owns one `HTTPRoute` attachment for
`exposure-stage-a.dev.conalog.com` and can also be inspected with an ephemeral
`kubectl port-forward`. Do not apply this template without a separate explicit
START authorization.

The immutable artifact collection contains only the legacy Compos
`customer-profile` projection. Its ConfigMap is versioned as
`exposure-read-artifacts-compos-v2`; the Pod references that exact name so an
existing immutable artifact collection is never updated in place. There is no
service-specific data adapter or data-service token in this template. Other
upstreams, including authentication services, use separate generic capability
proxy instances; see the repository README.

## Controlled replacement

This development manifest deliberately uses one naked Pod and one RWO Compos
PVC. Its Pod volume and environment fields are immutable, and a second
versioned Pod cannot safely mount the same RWO volume while the old Pod is
running. An existing Stage A installation therefore requires a reviewed,
explicitly authorized delete-and-recreate; plain `kubectl apply` over the live
Pod is forbidden.

The deployment owner must verify the exact context, namespace, Pod UID, route,
Service, PVC, and rollback render before mutation. It must derive and hash two
documents from the same reviewed full render: phase 1 contains every document
except the final `HTTPRoute`; phase 2 contains only that exact `HTTPRoute`.

Phase 1 removes only the existing `exposure-stage-a` HTTPRoute, waits for the
public route to be absent, deletes only Pod `grant-compos-exposure-stage-a`
normally with bounded wait (no force or finalizer edit), and applies only the
reviewed phase-1 render. Readiness, exact image IDs, artifact bytes, source
connectivity, and the full user scenario must pass through a bounded
port-forward while the public route remains absent. Only after that PASS may
phase 2 apply the reviewed route document and verify `Accepted=True`,
`ResolvedRefs=True`, and the public smoke.

On a phase-1 failure, keep the route absent and restore the prior workload from
the prior render with its route omitted. Restore the prior route only after the
prior workload is healthy and its bounded port-forward scenario passes. On a
phase-2 or public-smoke failure, remove the route first, then follow the same
prior-workload validation and prior-route restoration sequence. Secret values
and the existing PVC are never read, copied, deleted, or recreated by this
replacement. The manifest annotation
`stage-a.conalog.io/replacement-policy: delete-recreate` records this
operational invariant; it is not permission to perform the mutation without a
fresh START.

Grant is pinned and uses its image entrypoint, empty ephemeral Hiqlite storage, and
the `grant-stage-a-secrets` bundle. Grant HTTP/HQL (`8080`, `8110`, `8210`),
Compos HTTP/HQL (`7878`, `8100`, `8200`), Rauthy HTTP/HQL (`8081`, `8120`,
`8220`), and Exposure internal HTTP (`8082`) use distinct ports.

The `rauthy-config` Secret is deliberately not defined by this apply bundle. Before
applying it, an external operator must create that Opaque Secret in
`grant-compos-exposure-v1` with exactly the keys `config.toml`, `clients.json`, and
`api_keys.json`. Provision and rotate it through a secret-safe external creation
path that neither renders credential-bearing YAML nor uses client-side apply or
`--save-config`; the Secret must never retain a
`kubectl.kubernetes.io/last-applied-configuration` annotation. Do not add values to
this repository or validator output.

Remaining render-time placeholders are `__REQUIRED_GRANT_RAUTHY_CONFIG_MOUNT_PATH__`,
the Compos/Exposure application-secret key and PVC values, and the Exposure image
digest. The verified Grant-source bootstrap renderer uses a pinned BusyBox init
container, the external `rauthy-config` Secret templates, and
`grant-stage-a-secrets` to atomically render read-only bootstrap files; no
credential is embedded or mounted into a long-running container. Compos fixture
initialization remains external operator input only: `stage-a-user-credential` key
`CONALOG_TOKEN`; no fixture initializer is defined here.

Grant startup/liveness probes use the pinned image's verified `/usr/bin/curl -fsS`.
Its readiness probe uses verified `--fail-early -fsS` against Grant and Rauthy so
an earlier failed URL cannot be masked by a later success. The exact Rauthy base
image has no verified curl/wget/busybox health client, so Rauthy has no Kubernetes
probe; the launcher retains `RAUTHY_LAUNCHER_HEALTH_URL` for child health handling.

`./test-stage-a.sh` fails while Grant and Exposure release contracts are unresolved.
`./test-stage-a.sh --fixture` only substitutes non-routable values and performs
offline fixture render/static validation; it is not deployable and does not claim
Kubernetes server schema or admission validation. Target-cluster server validation
remains a pre-START step. Deployment acceptance separately checks
`quorum_available` and `writes_enabled`.

Build the Exposure image with `docker build --platform=linux/amd64 -t exposure:stage-a .`.

Exposure serves plain internal HTTP on port `8082`; its Service exposes port `80`.
Direct Exposure TLS compatibility is intentionally broken and no active Exposure
certificate/key contract remains. The bundle owns only the `HTTPRoute` attachment
to the pre-existing Gateway `haproxy-gateway-system/dev-gateway`, listener section
`https-exposure-stage-a-dev-conalog-com`. That external Gateway owns the public
HTTPS hostname and certificate and forwards accepted traffic through the Exposure
Service on port `80` to Exposure HTTP on port `8082`. No Ingress alternative is
part of this contract. The bundle does not own a Gateway, certificate, Secret,
mTLS policy, or NetworkPolicy, and Exposure does not trust `Forwarded` or
`X-Forwarded-*` headers.

After an authorized apply, external validation must prove the HTTPRoute parent
status conditions `Accepted=True` and `ResolvedRefs=True`. Offline fixture and
client-side YAML validation cannot establish listener attachment or reference
resolution.

## Authorization-code scenario contract

The scenario runner provides exactly one bounded local authorization-code callback as an optional `redirectUri`.
One-shot Rauthy create/read verifies the stored `redirectUri` byte-for-byte and reads the generated `rauthyClientId`.
Public flows are exactly `authorization_code` and `refresh_token`, with PKCE `S256`.
ROPC/password, a long-lived provisioner/controller, users.json, and DB seed are forbidden.
Fixed `GRANT_RAUTHY_CLIENT_ID` is distinct from the per-application generated ID.
The least-privilege Clients create/read/update key expires in at most 10 minutes, use stops immediately after verification, and post-expiry denial is proved.
Organization ID is derived through supported bootstrap/query, `organization.application.manage` is proved before application creation, and no ID is hardcoded.
No delete controller is invented.
This template documents the contract only; it does not validate external live IaC.

## Image publication

`.github/workflows/ci.yml` verifies every pull request and runs CI followed by
publication for a push to `main` or `feature/**` in `mrchypark/exposure`.
The publish job explicitly maps repository secrets `GCP_SA_KEY`,
`GCP_REGISTRY_HOST`, `GCP_PROJECT_ID`, and `GCP_REPOSITORY` to the unchanged
reusable publisher. Its callee-owned build/push limitations are accepted here;
this repository does not duplicate or modify callee logic.
It does not deploy, apply a manifest, or authorize START; the manifest keeps the
Exposure image digest unresolved until a later reviewed render.
