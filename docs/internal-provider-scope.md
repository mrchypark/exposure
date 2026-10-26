# Internal provider scope

Each capability proxy instance has one deployment-owned upstream HTTP(S) origin.
Provider names, routes, actions and resources are catalog data, not compiled
business-service adapters. Authentication services use the same provider/PEP,
catalog-fetch, digest-binding and transport path as data or management services.

`public_authn` handles bounded credential-free login and skips the per-request
Grant decision. The upstream authenticates the user and returns its native
response. The catalog still comes from Grant and must be pinned and unexpired.
Cookies, caller Authorization, alternate credentials and token query parameters
are not accepted on public login routes. Token responses cannot be cached.

Protected requests use `authorized` capabilities and a fresh bound Grant
decision. `forward-user` sends the same bearer to the fixed upstream;
`service-token` substitutes the server-owned upstream credential. A service-token
instance rejects active public-authn capabilities; use a separate auth instance.
Credential modes select identity-hint parsing, not routing or local trust.

The digest-bound `organizationContext` capability field defaults to `required`;
an explicit `optional` permits authenticated orgless requests for any provider,
still subject to the full Grant decision. There is no management-specific
whitelist. See the [producer contract](organization-context.md) for the required
Grant publisher/verifier upgrade and rollout boundary.

## Supported boundaries

- Grant and provider addresses use the same fixed-origin validator: explicit
  HTTP(S), lowercase DNS names or canonical IPv4/bracketed IPv6, and optional
  canonical decimal ports 1–65535. Names, addresses and ports are operations
  configuration, not service exceptions. Credentials, paths, queries and
  fragments are rejected; no request or catalog can select another origin.
- Outbound HTTPS validates certificate trust and the configured DNS/IP identity.
  Explicit HTTP selects plaintext without an additional enable flag. Both runtime
  clients ignore environment proxies and reject redirects. Endpoint ownership,
  network access and system trust roots remain deployment responsibilities.
- Catalog method/path/query/body/response policies, header allowlists, limits,
  resource extraction, request/decision bindings, and fail-closed expiry.
- PocketBase native atomic batch transport with child authorization and
  response-reference authorization for supported relation expansion.
- A separate legacy Compos-only immutable projection mode.

## Not implemented

mTLS provider transport and realtime/SSE are not implemented. Public DNS/IP
origins are accepted as fixed operations configuration; this does not implement
caller-directed routing or a general external-provider onboarding workflow.
The new organization policy passed the coordinated real-Grant
`TestExposureOrganizationContextE2E` run with `EXPOSURE_SOURCE_DIR` under `-race`
(15 cases, final PASS). Its PocketBase auth-refresh dependency is an HTTP fixture,
not live Goauthy or an IED deployment. See the
[evidence and rollout limits](organization-context.md#verified-integration-evidence-and-limits).
Runtime versions, catalog generations and pins still require coordinated rollout;
local integration is not proof of a live deployment or production-cloud parity.

See the [README](../README.md), [Grant management](grant-management.md), and
[local fixture runbook](local-patch-auth.md).
