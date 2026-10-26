# Temporary real Goauthy fixture

Owned namespace: `grant-exposure-auth-test-v020`. This fixture must never adopt
an existing namespace, join a production cluster, or use production credentials.
It is local-only standalone Goauthy on a dedicated disposable PVC, not HA/DR.

Official feature image source: `e3532862f9347dd340ae1ed7979893a87074156b`
([reviewed PR #168](https://github.com/mrchypark/goauthy/pull/168)).
Main CI: https://github.com/mrchypark/goauthy/actions/runs/40307263698 .
Publisher: https://github.com/mrchypark/goauthy/actions/runs/40315331978 .
The immutable manifest digest is pinned in runtime.yaml and was checked using
fresh authenticated GHCR access. No application binary is locally built.

**Compatibility boundary:** the previous v0.3.8 image lacked
`GET /oidc/client-configuration` and returned 404. Login/introspection alone did
not establish Grant identity-binding compatibility. PR #168 supplies the route
and metadata-only scope deduplication without storage schema changes. Its image
was published only after normal PR and main CI. Registry bytes, Linux/amd64 and
OCI source/revision labels were independently verified; no attached BuildKit
provenance attestation is present. Never bypass Grant's binding check.

Issuer: `https://goauthy.grant-exposure-auth-test-v020.svc.cluster.local:8443`.
Client: `grant-exposure-v020-test`. Audience:
`https://grant-exposure-v020.test/management`. Scopes: `openid goauthy.read`.
The configured bootstrap client is the real native client; no stub JWTs exist.

`scripts/fixture -dir PRIVATE_DIR prepare` generates an owned CA and DNS-valid
TLS key/certificate. CA key remains only in process memory. Bootstrap secret
files are generated with the existing Operable goauthy-bootstrap helper, without
its apply flag. All private files live outside the repository with mode 0600.

Grant must mount the fixture CA using normal system trust. No insecure TLS,
public ingress, or production hostname override is used. Kubernetes HTTPS
health probes do not establish TLS trust; the auth helper independently verifies
the CA and configured hostname through its owned loopback port-forward.

`scripts/fixture -dir PRIVATE_DIR -address 127.0.0.1:18443 auth` runs real
the mandatory client-configuration check first, then real password interaction,
state validation, S256 PKCE authorization-code exchange,
and active-token introspection. It also requires invalid client rejection and
unknown-token inactivity. It writes token files and prints only evidence/path
metadata. The HTTP client never follows callback redirects, proxies or other
origins. Password grant and client-credentials user impersonation are not used.

`scripts/fixture -dir PRIVATE_DIR -address 127.0.0.1:18443 configuration` checks
only that required real endpoint over normal TLS, without a new login or token
file writes. HTTP 404/401, wrong version/client/issuer/resource/redirect/grants/
scopes, missing/null/duplicate fields, wrong byte-derived ETag or missing
`Cache-Control: no-store` fail closed. `auth` cannot print its complete pass
unless this gate succeeds. Focused offline tests exercise the valid contract,
malformed metadata, and the observed 404 failure; they are not a substitute for
the actual official-image endpoint check.

Retain owned resources until the parent confirms Grant/Exposure tests complete.
Cleanup must verify recorded namespace UID, stop only the recorded port-forward,
delete the owned namespace/PVC/Secrets, verify deletion, then remove the private
task directory (including registry auth). No production resources are touched.
