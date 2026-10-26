# Organization-context catalog contract

Exposure intentionally implements Grant's PDP/catalog protocol. Grant owns
business authorization; Exposure validates protocol and transport constraints
and enforces bound Grant decisions. The operator fixes the Grant endpoint through
`EXPOSURE_GRANT_LEARNER_URL`; hostname and port are deployment choices, never
request input. This protocol dependence creates no provider, service-path or
action exceptions. See the README for endpoint transport and network controls.

`organizationContext` is an optional **capability-level** field, not a request
parameter or deployment switch:

```json
"organizationContext": "optional"
```

| Wire value | Protected request behavior |
|---|---|
| Omitted | `required`: one nonempty `X-Organization-ID` is required. |
| `"required"` | Same enforcement, but explicit and included in digests. |
| `"optional"` | Header may be absent; a supplied header must remain single and nonempty. |

Only `authorized` capabilities may specify this field. `public_authn` must omit
it and retains its credential-free login contract. Null, empty strings, unknown
values/types, duplicate policy keys and case-insensitive aliases of the field
are rejected rather than treated as absence. Disabled capabilities are validated
too. No `none` mode, client opt-in or provider/path/action inference exists.

Optional context never disables Bearer authentication, identity-hint checks,
resource extraction or the full unexpired Grant decision and binding checks.
Grant still decides whether the authenticated principal can perform the action
with the supplied context (or without one). Denial never reaches upstream.
Absent organization stays absent on the PDP request. When supplied, the same
value goes to Grant and, if `x-organization-id` is allowlisted by the capability,
to upstream. Header allowlists are not widened by this policy. Configure that
allowlist when the upstream consumes organization context. Existing transport
header validation and stripping remain unchanged.

The decision request/response DTO is **unchanged**: organization is conveyed by
the PDP HTTP header, not a newly echoed JSON field. Policy is bound through the
existing contract digest, catalog digest/generation and request/decision binding.
This change does not claim a new organization-specific decision echo.

## Composite boundaries

An optional batch parent may reference only children that explicitly opt into
optional organization context, including both branches of upsert recipes. A
required parent may reference either policy: its own header requirement remains.

`optional` combined with `recordScope` or `responseAuthorization` is currently
rejected at catalog validation. These scoped/second-decision features retain
their existing required-org behavior. Supporting optional context there requires
separate end-to-end policy/second-decision validation; it is not silently enabled.

## Producer, verifier and hashing upgrade

This is an additive extension to local catalog schema version 1. Older Exposure
versions reject the new field. The checked-in management fixture now explicitly
opts four self-service capabilities in; the runtime has no management whitelist.
An unchanged old catalog still has its old digest but now requires organization,
even for those same old management tuples. Do not deploy this runtime against
an old orgless-onboarding catalog and expect a compatibility fallback.

Before live use, the external Grant implementation must:

1. Admit and strictly validate this exact optional field in capability staging,
   persistence, publication and decision-verification models; do not drop or
   normalize it before computing contract/generation digests.
2. Keep omitted fields omitted. Serialize an explicit field **last** in the
   typed capability object, after `responseAuthorization` when present. Existing
   field ordering remains unchanged. Exposure's generation digest hashes typed
   objects in order, not globally sorted JSON.
3. Include the explicit field in `contractDigest`: remove `contractDigest`,
   recursively sort object keys and hash compact JSON using the existing
   contract algorithm. Omission and explicit `required` have different digests.
   Recompute `catalogDigest` over the typed generation with the updated
   capability digests. Optional extensions retain their established positions.
4. Apply `required` when omitted, and admit orgless identity/authorization only
   for explicitly optional capabilities. Continue validating identities,
   application/PEP/provider state, resources, actions and request binding.
   Recognizing the field must not itself grant the action.
5. Maintain shared digest coverage and real publisher/PDP/Exposure tests
   for absent/supplied organization, allow/deny, and policy tampering. The local
   jq/OpenSSL vector and HTTP PDP stubs alone are not interoperability proof;
   the real-Grant evidence below covers the local integrated path.

Upgrade producer/verifier support first, generate and review new capabilities
(with version changes as required by Grant), stage a new catalog generation using
actual generation preconditions, and deploy the matching Exposure version and
reviewed digest pin together before routing traffic. Existing capability pins
cannot authorize a policy change. Keep a compatible runtime/catalog pair for
rollback; do not patch only a live digest or rely on transient old-catalog fallback.

`scripts/build-management-catalog.sh --full` delegates to the external producer.
It does not retrofit policy or rewrite that producer's digests. An old producer
therefore emits required-org contracts. This Exposure change does not modify the
Grant repository; the coordinated Grant changes must be delivered separately.

## Verified integration evidence and limits

The coordinated local Grant test
`internal/api/exposure_organization_context_e2e_test.go`,
`TestExposureOrganizationContextE2E`, ran with `EXPOSURE_SOURCE_DIR` pointing to
this Exposure checkout and completed with a final PASS under `-race` across
15 cases. It uses real Grant catalog staging/publication and PDP handling with
the real Exposure binary, rather than an echo-only PDP stub. This establishes
local cross-repository catalog/digest and authorization interoperability.

The authentication dependency in that test is a PocketBase auth-refresh HTTP
fixture, not a live PocketBase or Goauthy deployment. It does not establish live
Goauthy verification, production IdP integration or an IED rollout. Matching
Grant/Exposure runtime versions, reviewed catalog generations and digest pins
must still be coordinated before traffic or rollback. The evidence is from the
completed coordinated run, not a new E2E run performed during PR preparation.
