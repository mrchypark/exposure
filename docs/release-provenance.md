# Simple-read release provenance

This branch starts from `origin/main` at `7e3f0e48`. It does not merge,
cherry-pick, or rewrite the earlier feature branches.

The release selectively reuses reviewed simple-read evidence from these Git
objects: `2ef591f`, `1c643f4`, `be67913`, `2a9f225`, `d90e30e`, `fd0d027`,
`6eb690f`, `2977a77`, `140c562`, `d9fdd58`, and `90a47f67`. Reuse is limited to
the immutable artifact/JCS behavior, Grant and private Compos read wires,
closed HTTP surface and bounds, container packaging, thin reusable workflow
caller, and the corrected Stage A bundle.

The release later removed Exposure-held TLS termination. This intentionally
breaks direct TLS compatibility: the pre-existing Gateway
`haproxy-gateway-system/dev-gateway`, listener section
`https-exposure-stage-a-dev-conalog-com`, owns the public HTTPS hostname and TLS
material and forwards to internal HTTP. No Gateway resource or TLS material is
managed here, and no Ingress alternative is part of the contract. Stage A owns
only a closed HTTPRoute attachment to that exact listener.

The earlier engine-neutral operation service, management proxy/catalog,
field-rendering and field-ACL machinery, receipts, operation/page routes,
metrics, and related dormant contracts/tests are intentionally not present.
The runtime helpers in this branch are concrete to the single read path.
