# Exposure

The current HTTP capability mode forwards only routes in a pinned Grant catalog.
The Grant management fixture contains 69 capabilities, including organization
and application lifecycle management and authenticated self-onboarding. See
[Grant management](docs/grant-management.md) for the registration, permission
and rollout contract. Four exact onboarding routes can omit the organization
header while still requiring Bearer authentication and Grant authorization;
ordinary organization routes cannot. This source update does not establish a
live IED rollout.

## Legacy simple-read mode

The following describes the separate legacy artifact-based read mode, not the
capability mode used by management Exposure.

Exposure is a stateless, fail-closed HTTP policy-enforcement point for one
immutable, server-owned read projection. This release exposes exactly:

- `GET /healthz`
- `GET /readyz`
- `GET /v1/exposures/{exposureId}/resources/{resourceId}`

The protected read requires exactly one `Authorization: Bearer …` header and
one `X-Organization-ID` header. Callers cannot supply selectors, projection
pointers, or the server-owned Grant application key. Exposure creates a fresh
request binding, obtains a tuple-bound unexpired Grant decision, reads the fixed
object from either private Compos or the fixed internal Patch Data plant record
operation, and returns only scalar leaves named by the startup artifact. The
user bearer is sent only to Grant. After Grant allows the exact tuple, Exposure
authenticates the fixed PocketBase request with a separate server-owned Patch
Data service token; the user bearer can never reach the Patch Data client API.
Dependency responses and public responses
are bounded; redirects and environment proxies are disabled. Exposure does not
interpret `Forwarded` or `X-Forwarded-*` headers.

In this legacy mode, operations, pages, management, metrics, actions, arbitrary selectors, write APIs,
field masks/ACLs, receipts, and hot reload are unsupported. Their routes are not
registered and return `404`.

## Authentication and dependency errors

Missing or malformed bearer authentication returns the bounded public `401`
error envelope before any dependency call. Every public `401`, including a
Grant-originated `401`, contains exactly the generic challenge
`WWW-Authenticate: Bearer`; it never includes `error`, `error_description`, or
upstream detail. The scheme is case-insensitive and accepts one or more ASCII
spaces before an RFC 6750 `b64token`, while tabs, control characters, combined
credentials, empty/padding-only tokens, and misplaced padding are rejected.
Grant non-success bodies are not a
public or stable schema: Exposure closes them without parsing or echoing and
maps only the bounded HTTP status (`401` to public `401`, `403` to public `403`, `503` and
other upstream failures to public `503`; Grant `400`/`422` remain public `422`).
No Grant error text is echoed. A successful Grant `200` must still satisfy the
complete strict decision schema, while the normal policy decision
`200 {"allowed":false,...}` remains a public `403`. This preserves useful,
fail-closed status semantics for invalid/expired identities, organization or
application denial, and Patch Data authentication dependency failure without
coupling Exposure to Grant's legacy `{ "error": ... }` body.

The strict Grant decision wire follows Grant's canonical formats:
`artifactDigest` is `sha256:` plus 64 lowercase hexadecimal characters, while
`principalDigest` is exactly 64 lowercase hexadecimal characters with no
prefix. The two fields are distinct contracts; Exposure rejects prefixed,
uppercase, non-hexadecimal, or wrong-length principal digests.

## Configuration

Required environment variables:

- `EXPOSURE_GRANT_LEARNER_URL`: canonical internal Grant HTTP origin.
- `EXPOSURE_PATCH_DATA_URL`: canonical internal Patch Data HTTP origin.
- `EXPOSURE_READ_ARTIFACTS_FILE`: immutable startup JSON artifact collection.
- `EXPOSURE_GRANT_APP_AUTH_KEY`: server-owned Grant credential.

The two dependency origins are always required and fail startup unless they are
exactly `http://grant.<namespace>.svc.cluster.local:8080` and
`http://patch-data.<namespace>.svc.cluster.local:8090`, where `namespace` is one
canonical lowercase DNS label. Literal loopback IP origins with those exact
ports are accepted only to support local tests. HTTPS, public or bare hosts,
other Service names, private or metadata IPs, alternate ports, credentials,
paths (including encoded paths), queries, fragments, wildcards, and
noncanonical DNS/case are rejected. The configured Patch Data origin is passed
unchanged to its fixed-operation client; no alternate or hardcoded backend is
used.

`EXPOSURE_PATCH_DATA_SERVICE_TOKEN` is also required for those artifacts. It is
the raw token of a dedicated least-privilege Patch Data service identity and
must be injected from a Secret; do not include the `Bearer` prefix. Exposure
uses it only as the backend `Authorization` bearer and never logs it, returns
it, or substitutes the caller's user bearer. An invalid or absent token fails
startup, while Patch Data `401`/`403` responses fail closed.

This repository does not create that Patch Data principal or authorize generic
PocketBase collections. Patch Data owns the enabled service-principal identity
and permits it only on the private fixed-operation route. A superuser or other
ACL-bypass token is not an acceptable substitute.
Loopback origins exist only behind the package-private test helper. The Patch
Data source is a closed operation: `patch-data-plant-profile`, `plant.get`,
private route `GET /api/internal/exposure/v1/plants/{plantId}`, and projection
`/id`, `/name`, `/updated` are fixed in code. Callers cannot
select a host, path, collection, query, schema, field list, or projection. The
backend request has no body or query and cannot name a PocketBase collection.

Compos artifacts retain their original untagged source shape and exact public
`resourceVersion` response. Patch Data responses instead carry the PocketBase
`updated` value as opaque `sourceRevision`; they do not invent an integer
resource version. Missing records become a read conflict, PocketBase ACL denial
remains forbidden, and timeout, redirect, malformed, oversized, or upstream
failures are fail-closed dependency failures. No PocketBase metadata,
organization relation, permission relation, collection metadata, or other
unapproved field is returned.

The `plant.get` descriptor fixes Grant's policy tuple to provider `patch-data`,
action `patch-data.plant.read`, resource type `plant`, and the exact plant ID.
The caller supplies none of those policy selectors. Grant echoes the registered
operation and exact policy tuple, and Exposure validates them with the artifact
and replay binding before executing the fixed backend request.

See [Patch Data fixed-operation boundary](docs/patch-data-operations.md) for
the initial operation and explicitly deferred list/search families.
See [internal provider scope](docs/internal-provider-scope.md) for current
internal K8s provider support and deferred external integration.

Exact DNS does not by itself prevent a Kubernetes owner from replacing the
Service with an `ExternalName`. The Deploy acceptance contract must therefore
verify that `patch/patch-data` is the intended non-ExternalName Service with the
expected selector/endpoints before exposing traffic. Exposure never accepts an
alternate origin as a workaround.

The Compos origin is intentionally fixed at `http://127.0.0.1:7878`. The Patch
Data private operation path is likewise fixed in the dedicated client. Optional
timeout and size/concurrency settings retain fail-closed defaults in
`internal/config`.

### HTTP capability proxy mode

When `EXPOSURE_PROXY_ENABLED=true`, Exposure instead serves the active Grant
HTTP capability catalog for one configured provider and fixed internal origin.
For PocketBase authentication and a separately protected Patch Data upstream,
see the [local patch-auth integration runbook](docs/local-patch-auth.md).
`EXPOSURE_PUBLIC_AUTHN_GLOBAL_*` and `EXPOSURE_PUBLIC_AUTHN_PEER_*` are
**per-process-instance** token buckets. They bound one Exposure process only;
the effective deployment total scales with replicas. This mode intentionally
does not add a shared limiter or claim a cluster-wide quota. A deployment that
needs a global quota must supply and review that separate boundary.
Peer entries are pruned after one hour of inactivity and the bounded 4,096-entry
map evicts its deterministic least-recently-used entry before admitting a new
peer.

## HTTP migration boundary

Exposure now serves plain internal HTTP only. Direct Exposure TLS compatibility
is intentionally broken: the former Exposure-held certificate/key configuration
has been removed and is no longer an active runtime or deployment contract.

The pre-existing Gateway `haproxy-gateway-system/dev-gateway`, listener section
`https-exposure-stage-a-dev-conalog-com`, owns the public HTTPS hostname and TLS
material and forwards accepted traffic to Exposure's internal HTTP Service. This
repository manages no Gateway resource or TLS material; the Stage A bundle owns
only an `HTTPRoute` attachment to that listener. No Ingress is part of this
contract, and Exposure does not trust forwarding headers as authorization or
routing input.

## Verification

```sh
gofmt -w ./cmd ./internal ./deploy/stage-a-dev
git diff --check
go test -count=1 ./...
go test -count=1 -race ./...
go vet ./...
go build ./...
./deploy/stage-a-dev/test-stage-a.sh --fixture
docker build --check .
```

The Stage A template is render-only and deliberately contains unresolved
`__REQUIRED_*__` inputs. It keeps Grant, Compos, Rauthy, and Exposure in one Pod;
only Exposure receives a ClusterIP Service, and the bundle adds one HTTPRoute to
the pre-existing `haproxy-gateway-system/dev-gateway` listener section
`https-exposure-stage-a-dev-conalog-com`.

See [Stage A deployment notes](deploy/stage-a-dev/README.md) and
[selective-reuse provenance](docs/release-provenance.md).
