# Exposure

Exposure is a fail-closed HTTP policy-enforcement point. In capability mode it
proxies one configured upstream origin using a pinned, versioned Grant catalog.
Business data, authentication services, and management APIs use the same catalog
plumbing; no service-specific data adapter or compiled plant operation exists.

## Authentication and authorization

| Capability | Request flow |
|---|---|
| `public_authn` | Credential-free, rate-limited request to the configured auth upstream; no per-request Grant decision. The upstream authenticates the user and issues its native response/token. |
| `authorized`, `forward-user` | Grant validates the identity and authorizes the bound request; Exposure forwards the user's bearer to the configured upstream. |
| `authorized`, `service-token` | Grant validates the user's identity and authorizes the bound request; Exposure replaces the upstream Authorization value with its server-owned credential. |

Authentication is not exclusively obtained from Grant. `CredentialMode`
(`rauthy`, `pocketbase`, `goauthy`) describes how Exposure extracts untrusted
identity hints for Grant; parsing a JWT is not signature verification. Grant
remains the authorization authority and validates the supplied identity before
allowing protected requests.

Auth upstreams are ordinary providers. Their `public_authn` routes are explicitly
registered method/path contracts with bounded query/body/response policies and
allowlisted headers/statuses. Bodies and admitted native statuses are preserved.
These routes reject Authorization, Cookie, alternate credentials and token query
parameters; this is not a general OAuth/browser-session proxy. All login and
protected responses are `Cache-Control: no-store`, including native errors.

Login skips `/decide`, **not the catalog control plane**: Exposure must fetch and
verify a pinned, unexpired catalog from Grant before serving any capability.
An expired or missing catalog fails closed. Each instance has one fixed origin;
clients and JWT issuer claims cannot choose it.

A `service-token` instance cannot enable `public_authn`. Use separate instances
for an auth service and a privileged data service, each with its own origin,
provider/PEP identity, catalog digest, listeners and deployment credentials. A
`forward-user` provider may expose both credential-free login and protected APIs
when its reviewed catalog permits them. Do not change upstream auth collections
or add private business endpoints to satisfy Exposure.

### Organization context

Protected capabilities require a Bearer credential and, by default, one nonempty
`X-Organization-ID`. A capability can explicitly set
`organizationContext: "optional"` to allow an absent organization header while
still requiring the full bound Grant decision. This is provider-independent:
Exposure has no provider/action/path whitelist. A supplied organization is never
silently stripped; it goes to the PDP and is forwarded upstream only when the
catalog header allowlist permits it. Empty or duplicate headers are rejected.

Omitting the policy means `required` and preserves old digests. Explicit policies
are digest-bound and valid only for `authorized` capabilities. Management fixture
onboarding routes now opt in as catalog data. Existing publishers must implement
the [organization-context producer contract](docs/organization-context.md)
before those new catalogs can be deployed; old catalogs no longer receive a
hidden management exception.

## Capability configuration

### Goauthy user authorization (candidate wire version 2)

An explicitly configured Grant user PEP publishes both `authorizationMode:"user"`
and a positive int64 `pepPolicyRevision` in its catalog envelope. Exposure sends
`wireVersion:2` and that revision on every decision and requires the exact echo.
These envelope fields do not change catalog or capability digests: they rely on
the authenticated private Grant transport and decision binding. Never infer the
mode from a token or retry an executed request with a refreshed policy.

This user integration supports only the existing compact JWT-shaped Goauthy
tokens. By default, `sub` and exactly one `aud` (a string or one-element string
array) are untrusted hints. Grant introspection/UserInfo, actual client/audience/scope
validation, local membership and RBAC remain authoritative. No local signature
verification, opaque-token support, or client hint is added. User mode does not
require a Grant managed application. Set `EXPOSURE_CREDENTIAL_MODE=goauthy` and
`EXPOSURE_GOAUTHY_ISSUER`; `EXPOSURE_GOAUTHY_APPLICATION_ID` may be omitted for a
user catalog. Application catalogs still require it and retain their original
audience and admission semantics. Missing mode/revision means legacy application;
the legacy wire omits all new fields. Explicit policy rollback is a Grant private
CAS operation with a new revision, never automatic token-based fallback.

For Goauthy user tokens whose JWT audience contains both the OAuth client and
resource, operations may explicitly set both `EXPOSURE_GOAUTHY_USER_CLIENT_ID`
and `EXPOSURE_GOAUTHY_USER_RESOURCE_AUDIENCE`. They must be distinct, nonempty
values; a partial or invalid pair fails startup. This user-only profile requires
an array containing exactly those two audiences in either order, without
duplicates or extras, plus exact `azp` equal to the configured client and `iss`
equal to `EXPOSURE_GOAUTHY_ISSUER`. Missing, aliased or mismatched claims fail
closed with no fallback to the default profile. The PDP audience hint is the
configured resource; the original bearer and existing decision digests are
unchanged. These are local consistency hints, not signature or identity proof:
Grant independently validates online client/resource/scope evidence and UserInfo.
Operators must confirm that both configured values match that online contract.
The pair creates no OAuth client or managed application and does not change
legacy application audience/admission behavior. Leave both values unset to keep
the strict-single-audience profile, including existing same-value singleton cases.

The CI candidate artifact `exposure-linux-amd64-<source SHA>` contains `exposure`
and `exposure.sha256`. Run the binary without arguments (container entrypoint
`/exposure`) with the existing capability configuration below. Candidate unit
tests use a stub PDP and do not prove real Grant authorization or Goauthy login.
Real Grant/Exposure tests must separately establish applications=0 allow,
revocation denial without another upstream call, forged credential denial and
legacy behavior. Existing 5-second decisions do not promise cancellation of
already-running operations.

Set `EXPOSURE_PROXY_ENABLED=true` and supply:

- `EXPOSURE_GRANT_LEARNER_URL`: fixed Grant protocol HTTP(S) origin.
- `EXPOSURE_PROVIDER_ID`, `EXPOSURE_PEP_CLIENT_ID`: registered identities.
- `EXPOSURE_PROVIDER_ORIGIN`: fixed provider HTTP(S) origin.
- `EXPOSURE_EXPECTED_CATALOG_DIGEST`: reviewed active catalog digest.
- `EXPOSURE_GRANT_APP_AUTH_KEY`, `EXPOSURE_AUTHN_LIMITER_KEY`: server secrets.
- `EXPOSURE_PROVIDER_AUTHORIZATION_MODE`: `forward-user` or `service-token`.
- `EXPOSURE_PROVIDER_TOKEN_FILE`: private file containing the complete raw
  upstream Authorization value, required only for `service-token` mode.

Both origins use the same neutral validator. Operations configuration selects
their complete address, scheme and port at startup; no service name, Kubernetes
suffix, network range or service-specific port is required. Canonical lowercase
DNS names (including single-label Docker service names), IPv4 and bracketed IPv6
are accepted. Ports may be omitted or explicitly set to decimal 1–65535 without
leading zeroes. Credentials, paths (even `/`), queries, fragments and noncanonical
host spellings are rejected. Request headers, paths and catalog entries cannot
override either configured origin.

`https://` retains normal certificate trust and DNS/IP identity verification.
`http://` explicitly opts into plaintext transport; no additional flag is needed.
Deployment owners control endpoint ownership, trust roots and network access.
DNS alone does not establish endpoint ownership. Runtime clients ignore proxy
environment variables and never follow redirects, including cross-origin or
HTTPS-to-HTTP redirects. Forwarding headers are not trusted identity or routing
input. Exposure's own listener remains plain HTTP; outbound HTTPS does not change
that separate ingress contract.

Exposure intentionally depends on Grant's catalog and PDP protocol. Grant is the
authority for business allow/deny decisions; Exposure validates the transport,
catalog, request and decision bindings and enforces the result. This dependency
does not create service, provider, path or action exceptions: every `authorized`
capability uses the same Grant checks. `public_authn` is an explicit catalog
protocol mode, not a service-name exception. See the
[organization-context contract](docs/organization-context.md) for optional context
and deployment compatibility requirements.

See [generic auth configuration](deploy/generic-auth.env.example),
[internal provider scope](docs/internal-provider-scope.md), and the
[local integration fixture](docs/local-patch-auth.md). The latter uses named
services as test data, not built-in routing or production prerequisites.

`EXPOSURE_DATA_ADDR` and `EXPOSURE_ADMIN_ADDR` must differ. Size, timeout and
concurrency limits have fail-closed defaults in `internal/config`.
`EXPOSURE_PUBLIC_AUTHN_GLOBAL_*` and `EXPOSURE_PUBLIC_AUTHN_PEER_*` token buckets
are per-process, not cluster-wide quotas. Peer entries expire after one hour;
the bounded 4,096-entry map evicts its deterministic least-recently-used entry.

## Legacy simple-read mode

With capability mode disabled, the separate legacy mode serves only:

- `GET /healthz`
- `GET /readyz`
- `GET /v1/exposures/{exposureId}/resources/{resourceId}`

It reads Compos at fixed `http://127.0.0.1:7878` after a bound Grant decision,
and returns only scalar leaves from the immutable startup projection. It
requires `EXPOSURE_GRANT_LEARNER_URL`, `EXPOSURE_READ_ARTIFACTS_FILE`, and
`EXPOSURE_GRANT_APP_AUTH_KEY`. Its user bearer goes to Grant, not Compos. This
legacy behavior is not a rule for generic upstream authentication.

The service-specific plant artifact, operation registry, data client, URL/token
configuration and authority-snapshot run-validator have been removed. Old
service-specific artifacts are rejected at startup; migrate them to reviewed
generic HTTP catalogs, not renamed artifacts. The Stage A legacy template now
contains only its Compos projection and a new immutable ConfigMap name.

Legacy missing/malformed bearer errors return `401` before dependencies. The
legacy parser accepts case-insensitive Bearer and ASCII spaces with RFC 6750
token syntax; the capability parser retains its stricter JWT transport contract.
Legacy Grant errors map only bounded status, never upstream error text. Successful
decisions must match the strict artifact/resource/request binding and expiry.
`artifactDigest` is `sha256:` plus 64 lowercase hex characters;
`principalDigest` is 64 lowercase hex characters without a prefix.

## Deployment and verification

Exposure serves internal plain HTTP. The pre-existing Gateway owns public TLS;
the Stage A bundle attaches only an HTTPRoute and manages no Gateway, Ingress,
certificate or key. Templates are render-only with unresolved required inputs.
No live deployment is established by local tests. See
[Stage A notes](deploy/stage-a-dev/README.md) and
[reuse provenance](docs/release-provenance.md).

The coordinated real-Grant `TestExposureOrganizationContextE2E` run passed all
15 cases under `-race` with `EXPOSURE_SOURCE_DIR` set to this checkout. It uses a
PocketBase auth-refresh HTTP fixture, not live Goauthy or IED. See the
[integration evidence and coordinated rollout requirements](docs/organization-context.md#verified-integration-evidence-and-limits).

```sh
git diff --check
sh ./deploy/verify-runtime-tools.sh
go test -count=1 ./...
go test -count=1 -race ./...
go vet ./...
go build ./...
./deploy/stage-a-dev/test-stage-a.sh --fixture
docker build --check .
```
