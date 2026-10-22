# Grant Management Catalog

Builds the grant-management HTTP capability catalog fixture for Exposure testing.

## Usage

```sh
# Legacy 3-route groups fixture (default)
scripts/build-management-catalog.sh

# Full 69-capability catalog from Grant source tree
export GRANT_SOURCE_DIR=/path/to/grant
scripts/build-management-catalog.sh --full

# Full catalog with custom generation
scripts/build-management-catalog.sh --full -generation 2 -previous-generation 1
```

## Flags

| Flag | Description |
|------|-------------|
| `--full` | Build the complete 69-capability catalog. Requires `GRANT_SOURCE_DIR`. |
| `-generation N` | Override the catalog generation number (forwarded to Grant CLI). |
| `-previous-generation P` | Expected previous generation; required when advancing to `P+1`. |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GRANT_SOURCE_DIR` | With `--full` | Path to the Grant source tree containing `cmd/grant-management-catalog`. |

## Legacy Output

Without `--full`, the script generates a deterministic 3-route fixture covering
`GET`, `POST`, and `DELETE` on `/api/v1/orgs/{organizationId}/groups`. The
output is a self-contained JSON catalog with pre-computed contract and catalog
digests. It requires `jq` and `openssl`; full generation additionally requires Go.

## Full Catalog Output

With `--full`, the script delegates to Grant's `cmd/grant-management-catalog`
Go CLI. The output is a complete JSON catalog containing all 69 management
capabilities with real contract digests computed by Grant's canonicalization.

The output is written to stdout and can be redirected to the testdata fixture:

```sh
scripts/build-management-catalog.sh --full \
  > internal/capability/testdata/grant-management-full.json
```

## Test Coverage

The full catalog fixture is validated by table-driven tests in
`internal/capability/management_full_test.go`:

- All 69 capabilities pass `validateCapability` and contract digest binding.
- Catalog digest matches the computed `catalogDigest` over all capabilities.
- Proxy routes match actual capability method/path templates.
- `X-Grant-Master-Key` and `X-Grant-App-Auth-Key` are stripped before upstream.
- Token and a supplied `X-Organization-ID` are forwarded unchanged; the exact
  onboarding contracts below can omit the organization header.
- PDP denial returns 403 with zero upstream calls.
- Unknown paths return 404.
- All required PDP request binding fields are echoed.
- Rauthy uses JWT `sub` and `client_id` as untrusted hints. Goauthy mode accepts
  only compact JWT-shaped credentials and sends the canonical subject hint
  `goauthy:<EXPOSURE_GOAUTHY_ISSUER>/<JWT sub>` (for example,
  `goauthy:https://gw-auth.dev.conalog.com/user-1`) with the configured
  `EXPOSURE_GOAUTHY_APPLICATION_ID` as the capability audience. The JWT `sub`
  remains untrusted evidence; JWT `aud`, `azp`, issuer, and signature are not
  local authorization evidence. Grant validates the bearer online.
- The fixture permits responses up to 4 MiB.
- Organization IDs are validated as ASCII tokens (alphanumeric, `.`, `-`, `_`, `:`; max 256 bytes).
- GET routes accept an optional `consistency=strong` query parameter.

The current full catalog publishes 69 business endpoints. Bootstrap uses the
provider-neutral private `POST /api/v1/admin/bootstrap/owner`; `/ops/backups`,
`/ops/migrations/patch-data-authority` and `/ops/providers/{providerId}/enforcers/{pepClientId}`
are also private and never forwarded by management Exposure.

Action-set GETs expose Grant's `ETag`. Full replacement PUTs forward `If-Match`,
and initial consent creation forwards `If-None-Match: *`. Grant's 412 and 428
responses pass through unchanged. Use per-action link PUT/DELETE or provider
action metadata PATCH for small edits. These contracts live in registered
catalog data; the proxy does not hard-code permission decisions for them.

Regenerate the fixture from the same Grant source used to deploy the backend:

```sh
(cd "$GRANT_SOURCE_DIR" && go run ./cmd/grant-management-catalog) \
  > internal/capability/testdata/grant-management-full.json
```

The local seed creates data and management Applications explicitly after owner
bootstrap. Its full action-set replacements fetch an ETag and fail when one is
missing. Deployment-owned enforcer bindings use the private `/ops` endpoint.

## Lifecycle API boundary

The 69-capability fixture adds organization creation/list/profile, Provider
metadata PATCH, group/agreement PATCH, app metadata/status/deletion, role
metadata/deletion, membership listing/removal, and administrator consent
revocation. It replaces POST `.../provisioning/verify` with platform-authorized
PUT `/api/v1/admin/orgs/{organizationId}/apps/{applicationId}/identity-binding`.
The payload identifies an existing IdP client with `clientId`; Grant's configured
read-only Rauthy adapter verifies the link and does not create IdP clients or
credentials. PocketBase retains its existing ready-without-client-ID behavior;
Goauthy verification is not implemented.

Grant's `/auth`, `/auth/v1` and wildcard IdP proxy are removed. Gateway routes
IdP traffic directly. These paths and the old provisioning route are absent
from this catalog, so management Exposure returns 404 without contacting either
Grant's decision endpoint or the upstream service. Bootstrap and `/ops` remain
private. The lifecycle APIs are Grant's business endpoints. Exposure retains
Grant as the authority and adds only the narrowly matched orgless transport
exception described below; it does not decide user permissions locally.

Generate the management catalog from the deployed Grant revision, review and
register its new Action definitions, explicitly assign the required permissions
to management roles and applications, then activate a new catalog generation
with matching Exposure digest configuration. Registration is not permission
granted, and a fixture update is not a live rollout. Existing action-set
conditional PUT and single-link PUT semantics remain; metadata PATCH preserves
omitted fields. Provider POST now creates only and returns 409 on duplicates.
The local seed is for a fresh environment, not an upsert reconciler.

`management_full_test.go` checks real Exposure forwarding against local mocked
PDP/upstream HTTP servers, including the 16 lifecycle routes. The denial test
supplies a mocked deny response and verifies zero upstream calls; it does not
prove Grant's evaluator denied a real user. The retired-route regression in
`management_lifecycle_test.go` tests local catalog rejection without any PDP
response and checks zero dependency calls. Separate Grant integration and live
deployment tests are required to prove actual policy and persistence behavior.

## Authenticated onboarding without an organization

Only these exact authenticated management contracts may omit `X-Organization-ID`:

| Method | Path | Action |
|---|---|---|
| POST | `/api/v1/me/ensure` | `grant-management.user.materialize` |
| GET | `/api/v1/me` | `grant-management.user.read` |
| GET | `/api/v1/orgs` | `grant-management.organization.list` |
| POST | `/api/v1/orgs` | `grant-management.organization.create` |

Exposure requires a Bearer token and an active pinned catalog even for these
routes. The exception also matches Provider, method, path, Action, service/grant
resource, forward-user policy and exact body kind; record scope, batch and
response-authorization extensions cannot use it. The omitted organization
header stays absent on the PDP request and upstream request; it is not sent as
an empty header. Other organization routes retain their organization requirement.

Grant authenticates the external identity, requires the configured enforcer app
to match the token client, and checks that app is active, ready, trusted and
explicitly admitted to the requested Action. Provider, enforcer and the app's
own organization must remain active. An existing inactive user is denied.
A first-time external identity can pass this narrow PDP check without a local
identity write; the ensure endpoint provisions it. This is not public-authn
access and does not permit arbitrary organization enrollment.

Self-service organization creation accepts only `id` and `name`; the verified
caller becomes owner. It atomically creates the organization, owner membership,
coarse owner binding and an organization-scoped binding to the protected
`role-system-management-owner` role. Its fine Actions are limited to registered
organization management routes, excluding platform and service-wide rights.
Missing Action registrations fail creation rather than leaving a partial tenant.
Reserved system role IDs cannot be claimed by tenant role creation.

For subsequent organization management, Grant permits that same configured
trusted management app across organizations only on exact registered tenant
management contracts. The user must be an active member of the target
organization and hold its requested fine Action. The narrowly matched
reactivation operation retains its separate inactive-organization handling.
This does not broaden data-provider or general application-authz behavior.

Owner GET/PUT uses `/api/v1/orgs/{organizationId}/owner`. GET exposes an ETag;
PUT forwards the required `If-Match`. Transfer moves the existing management
owner binding while preserving its restrictions and removes the former owner's
ownership bindings. Unrelated explicit grants are not implicitly deleted.

`onboarding_test.go` exercises the real Exposure proxy against an HTTP PDP stub,
checking that absent organization headers remain absent and that malformed
credentials/headers and ordinary orgless requests never reach dependencies.
Grant's separate real service/API tests cover identity, organization creation,
management, ownership transfer and revocation. These are complementary local
checks, not a claim that one test exercised the entire deployed chain or that
IED has been updated. Rollout still requires a new catalog generation calculated
from the actual active generation; do not assume the successor is generation 5.
