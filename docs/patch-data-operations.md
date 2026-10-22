# Patch Data fixed-operation boundary

Exposure is the execution boundary between a Grant decision and Patch Data.
The public caller selects only an immutable exposure ID and resource ID. It
cannot select a PocketBase host, collection, path, query, filter, sort, expand,
field list, or projection.

## Initial operation

`patch-data-plant-profile` is bound at startup to:

- source kind `patch-data.plant.v1`;
- operation `plant.get`;
- exact private route `GET /api/internal/exposure/v1/plants/{resourceId}`;
- no backend query or request body;
- exact public scalar projection `/id`, `/name`, `/updated`;
- a 15-character lowercase alphanumeric plant ID;
- Grant provider `patch-data`, action `patch-data.plant.read`, and resource type
  `plant`.

This is descriptor version 1. Its operation-to-policy meaning is immutable;
future incompatible semantics require a new operation ID rather than changing
the mapping behind `plant.get`.

## Wave 0 typed registry boundary

The compiled descriptor also binds operation version, contract digest and one
fixed executor kind. `Resolve` accepts only those typed fields plus the
canonical resource tuple. It has no backend URL/path/method, PocketBase
`filter`, `fields`, `expand`, projection, or schema selector. The only callable
entry remains `plant.get`; the migration inventory does not register future
operation IDs. Operation-backed traffic uses Grant's closed V2 decision wire.
Exposure derives version, contract digest and resource type from this registry
and validates every echoed field before fixed execution. Grant's V1 P0 endpoint
remains available for rollback compatibility; callers cannot select either wire.

Wave 0 verification is implementation-only. It does not insert live or
development authority data, import a production snapshot, deploy a runtime, or
change existing P0 records. After review, commit, and CI, a separate isolated
fixture-based use-validation phase must exercise the complete sequence: Patch
Data export, Grant import, then Exposure decision and fixed execution.

The published runtime images carry the reviewed offline tools without changing
either server entrypoint: Grant provides
`/usr/local/bin/grant-patch-data-authority-snapshot`, and Exposure provides
`/usr/local/bin/exposure-validate-run`. A use-validation manifest binds the
exact Patch Data, Grant, and Exposure commits and immutable image digests. It
also binds each tool to its owning image and fixed path; a missing field,
different image, or different path is rejected before evidence is accepted.

Exposure authorizes this operation only through the closed Grant endpoint
`POST /api/v2/exposure-authz/decide`. Exposure sends only its compiled operation
ID/version/contract digest, exact resource ID and fresh request binding; callers
cannot submit provider, action, resource type, or backend selectors. Grant's
decision must echo the exact operation and provider/action/resource tuple before
Exposure can execute the private Patch Data request. Legacy Compos reads retain
their existing `/api/v1/exposure-authz/read` wire.

The caller's Patch Data login bearer is used to authenticate the Grant request.
It is not a backend credential. The Patch Data client owns a separate service
bearer loaded from `EXPOSURE_PATCH_DATA_SERVICE_TOKEN`, and its interface does
not accept the caller bearer. Deployment must provision that service identity
with only the backend access required by the registered fixed operations.
Its backend origin is the startup-validated `EXPOSURE_PATCH_DATA_URL`; only the
canonical `patch-data` Kubernetes Service on port 8090 (or exact-port literal
loopback for local tests) is accepted. The client appends only the fixed private
operation path shown above and never forwards the user bearer.

Patch Data owns the enabled service principal and authenticates it only for the
fixed private route. The route performs no end-user authorization; Grant is the
authority for the fixed `patch-data/patch-data.plant.read/plant/{plantId}`
tuple. Acceptance must prove an allowed read and denial for a disabled or
unrelated principal. Neither a PocketBase superuser token nor a generic rule
bypass satisfies this contract.

The immutable artifact digest, exposure version, resource ID, and fresh request
binding are validated against the Grant response before the backend call. The
same artifact mapping is executed after allow. Redirects, environment proxies,
unbounded response bodies, malformed JSON, duplicate fields, mismatched record
IDs, missing revisions, and upstream failures all fail closed.

## Deferred operation families

Lists do not fit the current singular resource endpoint or decision tuple. They
remain unregistered until a coordinated Grant+Exposure contract defines exact
query templates, bounded pagination, response shape, and resource semantics:

- `plant.ids-and-names.list` for alert and Gatus consumers;
- `plant.ids-and-names.by-organization` for the sb-inverter consumer;
- `plant.search.v1` for Backoffice, with closed filter and sort enums;
- a general bounded `plant.list` operation.

No list may be implemented as an arbitrary PocketBase query proxy or by
post-filtering a broader result after authorization. Writes likewise remain
unregistered until Patch Data defines a fixed command contract and Grant owns
the corresponding action, resource, idempotency, and failure semantics.
