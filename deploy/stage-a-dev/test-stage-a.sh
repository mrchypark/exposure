#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
manifest=$root/deploy/stage-a-dev/stage-a.yaml
readme=$root/deploy/stage-a-dev/README.md
workflow=$root/.github/workflows/ci.yml
fail() { printf '%s\n' "stage-a validation: $*" >&2; exit 1; }

# grep compatibility shim for the small ripgrep option subset used below. CI runners
# provide grep but not necessarily ripgrep; all matching is delegated to grep/awk.
rg() {
  fixed=0 ignore=0 numbered= counted= only=0
  while [ $# -gt 0 ]; do
    case $1 in
      -F) fixed=1 ;;
      -i) ignore=1 ;;
      -n) numbered=-n ;;
      -c) counted=-c ;;
      -o) only=1 ;;
      *) break ;;
    esac
    shift
  done
  pattern=$1
  shift
  if [ "$only" = 1 ]; then
    awk '{ while (match($0, /__REQUIRED_[A-Z0-9_]*__/)) { print substr($0, RSTART, RLENGTH); $0=substr($0, RSTART+RLENGTH) } }' "$@"
    return
  fi
  if [ "$fixed" = 1 ]; then
    if [ "$ignore" = 1 ]; then grep -F -i $numbered $counted -- "$pattern" "$@"; else grep -F $numbered $counted -- "$pattern" "$@"; fi
  else
    grep -E $numbered $counted -- "$pattern" "$@"
  fi
}

case ${1:-} in
  --fixture) fixture=1 ;;
  '') fixture=0 ;;
  *) fail "usage: $0 [--fixture]" ;;
esac

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/exposure-stage-a.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

test -f "$manifest" || fail "missing manifest"
test -f "$readme" || fail "missing README"
target='gke_patch2-the-new-era_asia-northeast3_ied-cluster'
test "$(awk -v target="$target" '
  /^kind: Namespace$/ { in_namespace=1; next }
  in_namespace && /^---$/ { exit }
  in_namespace && /^metadata:$/ { in_metadata=1; next }
  in_namespace && in_metadata && /^  annotations:$/ { in_annotations=1; next }
  in_namespace && in_annotations && /^  [^ ]/ { in_annotations=0 }
  in_namespace && in_annotations && $0 == "    stage-a.conalog.io/authorized-target: " target { found++ }
  END { print found+0 }
' "$manifest")" = 1 || fail "Namespace authorized IED target annotation mismatch"
test "$(grep -Fxc "Authorized target annotation: \`$target\`." "$readme")" = 1 || fail "README authorized IED target line mismatch"
! rg -F 'tg900' "$manifest" "$readme" >/dev/null || fail "obsolete tg900 target remains"
for line in \
  'The `rauthy-config` Secret is deliberately not defined by this apply bundle. Before' \
  '`grant-compos-exposure-v1` with exactly the keys `config.toml`, `clients.json`, and' \
  'path that neither renders credential-bearing YAML nor uses client-side apply or' \
  '`kubectl.kubernetes.io/last-applied-configuration` annotation. Do not add values to'; do
  grep -Fqx "$line" "$readme" || fail "README external Rauthy Secret safety contract missing: $line"
done
for line in \
  'Exposure serves plain internal HTTP on port `8082`; its Service exposes port `80`.' \
  'Direct Exposure TLS compatibility is intentionally broken and no active Exposure' \
  'certificate/key contract remains. The bundle owns only the `HTTPRoute` attachment' \
  'to the pre-existing Gateway `haproxy-gateway-system/dev-gateway`, listener section' \
  '`https-exposure-stage-a-dev-conalog-com`. That external Gateway owns the public' \
  'Service on port `80` to Exposure HTTP on port `8082`. No Ingress alternative is' \
  'part of this contract. The bundle does not own a Gateway, certificate, Secret,' \
  'status conditions `Accepted=True` and `ResolvedRefs=True`. Offline fixture and'; do
  grep -Fqx "$line" "$readme" || fail "README HTTP migration boundary missing: $line"
done
for line in \
  'The scenario runner provides exactly one bounded local authorization-code callback as an optional `redirectUri`.' \
  'One-shot Rauthy create/read verifies the stored `redirectUri` byte-for-byte and reads the generated `rauthyClientId`.' \
  'Public flows are exactly `authorization_code` and `refresh_token`, with PKCE `S256`.' \
  'ROPC/password, a long-lived provisioner/controller, users.json, and DB seed are forbidden.' \
  'Fixed `GRANT_RAUTHY_CLIENT_ID` is distinct from the per-application generated ID.' \
  'The least-privilege Clients create/read/update key expires in at most 10 minutes, use stops immediately after verification, and post-expiry denial is proved.' \
  'Organization ID is derived through supported bootstrap/query, `organization.application.manage` is proved before application creation, and no ID is hardcoded.' \
  'No delete controller is invented.' \
  'This template documents the contract only; it does not validate external live IaC.'; do
  grep -Fqx "$line" "$readme" || fail "README authorization-code contract missing: $line"
done
test "$(rg -c '^kind: Pod$' "$manifest")" = 1 || fail "exactly one Pod required"
test "$(rg -c '^kind: Service$' "$manifest")" = 1 || fail "exactly one Service required"
test "$(rg -c '^kind: HTTPRoute$' "$manifest")" = 1 || fail "exactly one HTTPRoute required"
test "$(rg -c '^kind: Secret$' "$manifest")" = 0 || fail "apply bundle must not define a Secret"
! rg -F 'stringData:' "$manifest" >/dev/null || fail "apply bundle must not contain Secret stringData"
! rg -F 'kubectl.kubernetes.io/last-applied-configuration' "$manifest" >/dev/null || fail "apply bundle must not contain a last-applied credential annotation"
test "$(rg -c '^    - name: (compos|grant|rauthy|exposure)$' "$manifest")" = 4 || fail "exactly four containers required"
rg -F 'type: ClusterIP' "$manifest" >/dev/null || fail "Exposure ClusterIP missing"
rg -F 'app.kubernetes.io/name: exposure' "$manifest" >/dev/null || fail "fixed Service selector missing"
! rg -n '^kind: (Gateway|Ingress|ReferenceGrant|Certificate|Secret)$|^kind: (Deployment|StatefulSet)$|hostPort:|hostNetwork:|field.?acl|(^|[^[:alnum:]_])masks?([^[:alnum:]_]|$)|client.?pointer|stage.?b' "$manifest" >/dev/null || fail "out-of-scope configuration found"
route=$tmpdir/httproute.yaml
awk '/^apiVersion: gateway\.networking\.k8s\.io\/v1$/{on=1} on{print}' "$manifest" > "$route"
expected_route=$tmpdir/expected-httproute.yaml
printf '%s\n' \
  'apiVersion: gateway.networking.k8s.io/v1' \
  'kind: HTTPRoute' \
  'metadata:' \
  '  name: exposure-stage-a' \
  '  namespace: grant-compos-exposure-v1' \
  'spec:' \
  '  parentRefs:' \
  '    - name: dev-gateway' \
  '      namespace: haproxy-gateway-system' \
  '      port: 443' \
  '      sectionName: https-exposure-stage-a-dev-conalog-com' \
  '  hostnames:' \
  '    - exposure-stage-a.dev.conalog.com' \
  '  rules:' \
  '    - matches:' \
  '        - path:' \
  '            type: PathPrefix' \
  '            value: /' \
  '      backendRefs:' \
  '        - name: exposure' \
  '          port: 80' > "$expected_route"
cmp -s "$expected_route" "$route" || fail "HTTPRoute must match the exact closed attachment contract"
test "$(rg -c 'containerPort:' "$manifest")" = 1 || fail "only Exposure may have a containerPort"
test "$(grep -Fxc '      image: asia-northeast3-docker.pkg.dev/patch2-the-new-era/mrchypark/grant@sha256:0ff2803c26f61206a0becbf531a0fbaa908e5512bccc5ffacf4f16e7c4a3e1ca' "$manifest")" = 1 || fail "Grant image digest mismatch"
test "$(grep -Fxc '      image: asia-northeast3-docker.pkg.dev/patch2-the-new-era/mrchypark/grant-rauthy-launcher@sha256:03bf98c29f7189c51ddb90c66425578eff324d32ab2f4ba526b5d8cd1a587202' "$manifest")" = 1 || fail "Rauthy image digest mismatch"
for forbidden in 'asia-northeast3-docker.pkg.dev/patch2-the-new-era/mrchypark/grant@sha256:1cbd805cc2af0520a194661d35342456fbdc066829bb6a608ee99d67aaa2ca93' 'ghcr.io/' 'rauthy-launcher-pull'; do
  ! rg -F "$forbidden" "$manifest" >/dev/null || fail "forbidden image pull configuration remains: $forbidden"
done
! grep -E '^[[:blank:]]*imagePullSecrets[[:blank:]]*:' "$manifest" >/dev/null || fail "forbidden image pull configuration remains: imagePullSecrets"
! rg -F '__REQUIRED_GRANT_COMMAND' "$manifest" >/dev/null || fail "Grant must use its verified image entrypoint"
! rg -F 'grant-preflight' "$manifest" >/dev/null || fail "Grant preflight placeholder remains"
rg -F 'emptyDir: {}' "$manifest" >/dev/null || fail "Grant fresh hiqlite storage missing"
rg -F 'mountPath: /var/lib/grant/hiqlite' "$manifest" >/dev/null || fail "Grant hiqlite mount missing"
rg -F 'name: grant-stage-a-secrets' "$manifest" >/dev/null || fail "Grant secret bundle missing"
for name in GRANT_RUNTIME_MODE GRANT_LOCAL_NODE_ROLE GRANT_READ_CONSISTENCY GRANT_BIND_ADDR GRANT_RAUTHY_BASE_URL HQL_NODE_ID HQL_NODES HQL_LISTEN_ADDR_RAFT HQL_LISTEN_ADDR_API GRANT_MASTER_KEY GRANT_APP_AUTH_KEY GRANT_RAUTHY_CLIENT_ID GRANT_RAUTHY_CLIENT_SECRET GRANT_RAUTHY_CLIENT_READ_API_KEY HQL_SECRET_RAFT HQL_SECRET_API ENC_KEYS ENC_KEY_ACTIVE; do
  rg -F "$name" "$manifest" >/dev/null || fail "Grant contract field missing: $name"
done
for value in '127.0.0.1:8080' 'http://127.0.0.1:8081' '1 127.0.0.1:8110 127.0.0.1:8210' '1 127.0.0.1:8120 127.0.0.1:8220' 'http://127.0.0.1:8220/ready'; do
  rg -F "$value" "$manifest" >/dev/null || fail "missing exact loopback value: $value"
done
test "$(rg -c '\["/usr/bin/curl", "-fsS", "http://127.0.0.1:8080/healthz"\]' "$manifest")" = 2 || fail "Grant startup/liveness exec probes missing"
rg -F '["/usr/bin/curl", "--fail-early", "-fsS", "http://127.0.0.1:8080/readyz", "http://127.0.0.1:8081/auth/v1/health"]' "$manifest" >/dev/null || fail "Grant readiness dependency probe missing"
for key in config.toml clients.json api_keys.json; do
  rg -F "$key" "$manifest" >/dev/null || fail "Rauthy config key missing: $key"
done
test "$(rg -c 'secretName: rauthy-config' "$manifest")" = 2 || fail "Pod must reference the external Rauthy Secret in exactly two volumes"
rg -F 'name: rauthy-bootstrap-renderer' "$manifest" >/dev/null || fail "Rauthy bootstrap renderer missing"
rg -F 'busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662' "$manifest" >/dev/null || fail "bootstrap renderer image mismatch"
rg -F 'command: ["/bin/sh", "/renderer/render-rauthy-bootstrap.sh", "/bootstrap-template", "/bootstrap"]' "$manifest" >/dev/null || fail "bootstrap renderer command missing"
rg -F 'defaultMode: 0555' "$manifest" >/dev/null || fail "bootstrap renderer permissions missing"
for value in '/bootstrap-template' '/bootstrap' 'GRANT_RAUTHY_CLIENT_SECRET' 'GRANT_RAUTHY_CLIENT_READ_API_KEY' 'chmod 0400' 'mv -f'; do
  rg -F "$value" "$manifest" >/dev/null || fail "bootstrap renderer invariant missing: $value"
done
rg -F 'command: ["/usr/local/bin/rauthy-launcher"]' "$manifest" >/dev/null || fail "Rauthy launcher command missing"
rg -F 'args: ["/app/rauthy", "serve"]' "$manifest" >/dev/null || fail "Rauthy launcher arguments missing"
! awk '/^    - name: rauthy$/{on=1} /^    - name: exposure$/{on=0} on && /(startupProbe:|readinessProbe:|livenessProbe:)/{found=1} END{exit found ? 0 : 1}' "$manifest" || fail "Rauthy probes require an unproven in-container HTTP client"
! rg -F 'PUB_URL' "$manifest" >/dev/null || fail "external PUB_URL must not be used as a bind knob"
for value in \
  '{name: EXPOSURE_ADDR, value: ":8082"}' \
  '{name: http, containerPort: 8082, protocol: TCP}' \
  'httpGet: {path: /healthz, port: http, scheme: HTTP}' \
  'httpGet: {path: /readyz, port: http, scheme: HTTP}' \
  '{name: http, port: 80, targetPort: http, protocol: TCP}'; do
  rg -F "$value" "$manifest" >/dev/null || fail "Exposure internal HTTP contract missing: $value"
done
for forbidden in exposure-tls EXPOSURE_SERVER_CERT EXPOSURE_SERVER_KEY; do
  ! rg -F "$forbidden" "$manifest" >/dev/null || fail "removed Exposure TLS contract remains: $forbidden"
done
exposure_container=$(awk '/^    - name: exposure$/{on=1} on && /^---$/{exit} on{print}' "$manifest")
exposure_service=$(awk '/^kind: Service$/{on=1} on && /^---$/{exit} on{print}' "$manifest")
for forbidden in 'name: https' 'scheme: HTTPS' 'containerPort: 8443' 'port: 443'; do
  ! printf '%s\n%s\n' "$exposure_container" "$exposure_service" | grep -F "$forbidden" >/dev/null || fail "removed Exposure TLS contract remains: $forbidden"
done
for value in '127.0.0.1:7878' '127.0.0.1:8100' '127.0.0.1:8200' '127.0.0.1:8080' 'http://127.0.0.1:8080' ':8082'; do
  rg -F "$value" "$manifest" >/dev/null || fail "missing loopback value: $value"
done
pod_listener_ports=$(sed -n \
  -e 's/.*{name: COMPOS_BIND, value: "127\.0\.0\.1:\([0-9][0-9]*\)"}.*/\1/p' \
  -e 's/.*{name: GRANT_BIND_ADDR, value: "127\.0\.0\.1:\([0-9][0-9]*\)"}.*/\1/p' \
  -e 's/.*{name: LISTEN_PORT_HTTP, value: "\([0-9][0-9]*\)"}.*/\1/p' \
  -e 's/.*{name: EXPOSURE_ADDR, value: ":\([0-9][0-9]*\)"}.*/\1/p' \
  -e 's/^[[:space:]]*1 127\.0\.0\.1:\([0-9][0-9]*\) 127\.0\.0\.1:[0-9][0-9]*[[:space:]]*$/\1/p' "$manifest"
sed -n -e 's/^[[:space:]]*1 127\.0\.0\.1:[0-9][0-9]* 127\.0\.0\.1:\([0-9][0-9]*\)[[:space:]]*$/\1/p' "$manifest")
test "$(printf '%s\n' "$pod_listener_ports" | sed '/^$/d' | wc -l | tr -d ' ')" = 10 || fail "expected ten same-Pod listeners"
test "$(printf '%s\n' "$pod_listener_ports" | sed '/^$/d' | sort -u | wc -l | tr -d ' ')" = 10 || fail "same-Pod listener port collision"
runtime=$root/cmd/exposure/main.go
config=$root/internal/config/config.go
test ! -d "$root/internal/tlsconfig" || fail "removed internal/tlsconfig package remains"
for forbidden in '"crypto/tls"' 'internal/tlsconfig' 'TLSConfig' 'tls.Listen' 'ListenAndServeTLS' EXPOSURE_SERVER_CERT EXPOSURE_SERVER_KEY; do
  ! rg -F "$forbidden" "$runtime" "$config" >/dev/null || fail "removed runtime TLS contract remains: $forbidden"
done
! grep -E 'EXPOSURE_SERVER_(CERT|KEY)' "$root/README.md" "$root/docs/release-provenance.md" "$readme" >/dev/null || fail "active docs still name removed Exposure certificate/key variables"
test "$(rg -c 'allowPrivilegeEscalation: false' "$manifest")" = 5 || fail "container security contexts missing"
rg -F 'runAsNonRoot: true' "$manifest" >/dev/null || fail "non-root Pod context missing"
rg -F 'GOOS=$TARGETOS GOARCH=$TARGETARCH' "$root/Dockerfile" >/dev/null || fail "Dockerfile must honor target platform"
rg -F 'USER nonroot:nonroot' "$root/Dockerfile" >/dev/null || fail "Dockerfile must run non-root"
artifact='[{"artifactType":"exposure.read.v1","exposureId":"customer-profile","exposureVersion":1,"artifactDigest":"sha256:f03f2684ba9cf86c0fb5c3aa915eddd5f3f2523f2df4ea43014205634f854585","source":{"namespace":"wks_default","objectType":"otp_builtin_company_wks_default","schemaDigest":"sha256:ff37152682230e96eee7376ef415e7357d88846ea34bf78bb3555a2630371cf7"},"projectionPointers":["/domain","/employee_count"]},{"artifactType":"exposure.read.v1","exposureId":"patch-data-plant-profile","exposureVersion":1,"artifactDigest":"sha256:2782d8f92dca0b7a3e507ebad602cb95461c344230511e9cd22b5b39a8cf4ee7","source":{"kind":"patch-data.plant.v1","operation":"plant.get"},"projectionPointers":["/id","/name","/updated"]}]'
artifact_payload=$tmpdir/read-artifacts.json
: > "$artifact_payload"
awk -v output="$artifact_payload" '
  function finish_document() {
    if (target) target_count++
    if (target && key_count != 1) invalid=1
    is_config=0; in_metadata=0; target=0; in_data=0; in_payload=0; key_count=0
  }
  $0 == "---" { finish_document(); next }
  $0 == "kind: ConfigMap" { is_config=1; next }
  is_config && $0 == "metadata:" { in_metadata=1; next }
  in_metadata && $0 == "  name: exposure-read-artifacts-patch-data-v1" { target=1; next }
  in_metadata && /^  [^ ]/ { in_metadata=0 }
  target && $0 == "data:" { in_data=1; next }
  in_data && /^[^[:space:]]/ { in_data=0 }
  in_payload && substr($0, 1, 4) == "    " { print substr($0, 5) > output; next }
  in_payload { in_payload=0 }
  target && in_data && $0 == "  read-artifacts.json: |" { key_count++; in_payload=1; next }
  END {
    finish_document()
    exit target_count == 1 && invalid == 0 ? 0 : 1
  }
' "$manifest" || fail "exactly one versioned exposure-read-artifacts ConfigMap with read-artifacts.json is required"
printf '%s\n' "$artifact" | cmp -s - "$artifact_payload" || fail "artifact payload bytes mismatch"
! grep -F '"exposureId":"stage-a-company"' "$artifact_payload" >/dev/null || fail "obsolete deployment artifact ID remains"
! grep -F '"composSource"' "$artifact_payload" >/dev/null || fail "obsolete artifact source field remains"
! rg -F '"secret":' "$artifact_payload" >/dev/null || fail "secret field committed in artifact"

compos_container=$(awk '/^    - name: compos$/{in_compos=1; next} /^    - name: grant$/{in_compos=0} in_compos{print}' "$manifest")
compos_env=$(printf '%s\n' "$compos_container" | awk '/^      env:/{in_env=1; next} in_env && /^      volumeMounts:/{exit} in_env{print}')
compos_env_names=$(printf '%s\n' "$compos_env" | sed -n -e 's/^[[:space:]]*- {[[:space:]]*name:[[:space:]]*\([A-Z0-9_]*\).*/\1/p' -e 's/^[[:space:]]*- name:[[:space:]]*\([A-Z0-9_]*\).*/\1/p')
for name in COMPOS_BIND COMPOS_STORAGE COMPOS_BOOTSTRAP_DEFAULT_WORKSPACE COMPOS_CONALOG_AUTO_WORKSPACE_ID COMPOS_CONALOG_AUTO_WORKSPACE_ROLE COMPOS_QUORUM_CLUSTER_ID COMPOS_QUORUM_GENERATION COMPOS_QUORUM_CONTROL_MODE HQL_NODE_ID HQL_NODES HQL_LISTEN_ADDR_RAFT HQL_LISTEN_ADDR_API HQL_SECRET_RAFT HQL_SECRET_API HQL_DATA_DIR HQL_FILENAME_DB HQL_LEARNER_ONLY ENC_KEY_ACTIVE ENC_KEYS COMPOS_PROJECTION_SIGNING_KEY_ID COMPOS_PROJECTION_SIGNING_SEED_B64; do
  test "$(printf '%s\n' "$compos_env_names" | grep -Fxc "$name")" = 1 || fail "Compos env key must occur exactly once: $name"
done
test "$(printf '%s\n' "$compos_env_names" | sed '/^$/d' | wc -l | tr -d ' ')" = 21 || fail "Compos env must contain exactly the approved keys"
for value in \
  '{name: COMPOS_BIND, value: "127.0.0.1:7878"}' \
  '{name: COMPOS_STORAGE, value: hiqlite}' \
  '{name: COMPOS_BOOTSTRAP_DEFAULT_WORKSPACE, value: "1"}' \
  '{name: COMPOS_CONALOG_AUTO_WORKSPACE_ID, value: wks_default}' \
  '{name: COMPOS_CONALOG_AUTO_WORKSPACE_ROLE, value: member}' \
  '{name: COMPOS_QUORUM_CLUSTER_ID, value: grant-compos-exposure-v1}' \
  '{name: COMPOS_QUORUM_GENERATION, value: "1"}' \
  '{name: COMPOS_QUORUM_CONTROL_MODE, value: active}' \
  '{name: HQL_NODE_ID, value: "1"}' \
  '{name: HQL_LISTEN_ADDR_RAFT, value: "127.0.0.1"}' \
  '{name: HQL_LISTEN_ADDR_API, value: "127.0.0.1"}' \
  '{name: HQL_DATA_DIR, value: /data/hiqlite}' \
  '{name: HQL_FILENAME_DB, value: hiqlite.db}' \
  '{name: HQL_LEARNER_ONLY, value: "false"}'; do
  printf '%s\n' "$compos_env" | grep -Fx "        - $value" >/dev/null || fail "Compos env value mismatch: $value"
done
printf '%s\n' "$compos_env" | grep -Fx '        - name: HQL_NODES' >/dev/null || fail "Compos HQL_NODES missing"
printf '%s\n' "$compos_env" | grep -Fx '          value: |-' >/dev/null || fail "Compos HQL_NODES must be a literal line"
printf '%s\n' "$compos_env" | grep -Fx '            1 127.0.0.1:8100 127.0.0.1:8200' >/dev/null || fail "Compos HQL_NODES mismatch"
compos_secret_ref_is_adjacent() {
  name=$1 key=$2
  printf '%s\n' "$compos_env" | awk -v name="$name" -v key="$key" '
    $0 == "        - name: " name {
      matches++
      if (getline next_line && next_line == "          valueFrom: {secretKeyRef: {name: compos-stage-a-secrets, key: " key "}}") matched++
    }
    END { exit matches == 1 && matched == 1 ? 0 : 1 }
  '
}
for pair in \
  'HQL_SECRET_RAFT HQL_SECRET_RAFT' \
  'HQL_SECRET_API HQL_SECRET_API' \
  'ENC_KEY_ACTIVE ENC_KEY_ACTIVE' \
  'ENC_KEYS ENC_KEYS' \
  'COMPOS_PROJECTION_SIGNING_KEY_ID __REQUIRED_COMPOS_PROJECTION_SIGNING_KEY_ID_SECRET_KEY__' \
  'COMPOS_PROJECTION_SIGNING_SEED_B64 __REQUIRED_COMPOS_PROJECTION_SIGNING_SEED_B64_SECRET_KEY__'; do
  set -- $pair
  compos_secret_ref_is_adjacent "$1" "$2" || fail "Compos secret selector must immediately follow its env name: $1"
done
for forbidden in HQL_BIND_RAFT HQL_BIND_API COMPOS_PROJECTION_SIGNING_SEED COMPOS_QUORUM_MODE; do
  ! printf '%s\n' "$compos_env_names" | grep -Fx "$forbidden" >/dev/null || fail "forbidden Compos env key remains: $forbidden"
done
printf '%s\n' "$compos_container" | awk '
  $0 == "      readinessProbe:" {
    probes++
    if (getline next_line && next_line == "        exec: {command: [\"/usr/bin/curl\", \"-fsS\", \"http://127.0.0.1:7878/api/v1/health\"]}") matched++
  }
  END { exit probes == 1 && matched == 1 ? 0 : 1 }
' || fail "Compos readiness probe must immediately run the exact health exec"
test -f "$workflow" || fail "required CI workflow missing"
for forbidden in 'cloud build' 'buildx' 'github.event.inputs.destination' 'ghp_' 'github_pat_' 'ya29.'; do
  if rg -F -i "$forbidden" "$workflow" "$manifest" >/dev/null; then
    fail "forbidden publication pattern: $forbidden"
  else
    grep_status=$?
    test "$grep_status" -eq 1 || fail "forbidden-pattern scan error: $forbidden"
  fi
done
test ! -e "$root/.github/workflows/publish-stage-a-image.yml" || fail "obsolete dispatch publisher remains"
rg -F 'branches: [main, "feature/**"]' "$workflow" >/dev/null || fail "CI must trigger on main and feature branches"
rg -F 'needs: verify' "$workflow" >/dev/null || fail "publish must require CI"
rg -F "github.event_name == 'push' && github.ref == 'refs/heads/main' && github.repository == 'mrchypark/exposure'" "$workflow" >/dev/null || fail "publish must use merged main in the canonical repository"
rg -F "github.repository == 'mrchypark/exposure'" "$workflow" >/dev/null || fail "publish must require canonical repository"
rg -F 'uses: ./.github/workflows/buildandpush-versioned.yaml' "$workflow" >/dev/null || fail "pinned reusable publisher missing"
for value in 'application-name: exposure' 'version: sha-${{ github.sha }}' 'dockerfile: ./Dockerfile' 'context: ./' 'ref: ${{ github.sha }}' 'arch: linux/amd64' 'latest: false' 'push: true' 'output-types: type=registry' 'GCP_SA_KEY: ${{ secrets.GCP_SA_KEY }}' 'GCP_REGISTRY_HOST: ${{ secrets.GCP_REGISTRY_HOST }}' 'GCP_PROJECT_ID: ${{ secrets.GCP_PROJECT_ID }}' 'GCP_REPOSITORY: ${{ secrets.GCP_REPOSITORY }}'; do
  rg -F "$value" "$workflow" >/dev/null || fail "publisher contract missing: $value"
done
! rg -F 'secrets: inherit' "$workflow" >/dev/null || fail "publisher secrets must be explicit"
test "$(grep -Ec '^      GCP_(SA_KEY|REGISTRY_HOST|PROJECT_ID|REPOSITORY):' "$workflow")" = 4 || fail "publisher must map exactly four GCP secrets"
! grep -E 'id-token: write|google-github-actions/|gcloud auth|gcloud builds|cloud build|docker push|docker buildx|buildx|docker/build-push-action' "$workflow" >/dev/null || fail "alternate publisher or WIF remains"
! rg -F 'workflow_dispatch:' "$workflow" >/dev/null || fail "manual publish dispatch is prohibited"
! rg -F 'actions: read' "$workflow" >/dev/null || fail "workflow API query permission is obsolete"

if [ "$fixture" = 0 ]; then
  approved='__REQUIRED_COMPOS_HIQLITE_STORAGE_SIZE__ __REQUIRED_COMPOS_PROJECTION_SIGNING_KEY_ID_SECRET_KEY__ __REQUIRED_COMPOS_PROJECTION_SIGNING_SEED_B64_SECRET_KEY__ __REQUIRED_GRANT_RAUTHY_CONFIG_MOUNT_PATH__ __REQUIRED_EXPOSURE_IMAGE_DIGEST__ __REQUIRED_EXPOSURE_GRANT_APP_AUTH_KEY_SECRET_KEY__ __REQUIRED_EXPOSURE_PATCH_DATA_SERVICE_TOKEN_SECRET_KEY__'
  for placeholder in $(rg -o '__REQUIRED_[A-Z0-9_]*__' "$manifest" | sort -u); do
    case " $approved " in *" $placeholder "*) ;; *) fail "unapproved render placeholder: $placeholder" ;; esac
  done
  fail "approved render placeholders remain; use --fixture only for offline render/static validation"
fi

rendered=$tmpdir/stage-a.yaml
sed -e 's|__REQUIRED_COMPOS_HIQLITE_STORAGE_SIZE__|1Gi|g' -e 's|__REQUIRED_GRANT_RAUTHY_CONFIG_MOUNT_PATH__|/etc/grant/rauthy|g' -e 's|__REQUIRED_EXPOSURE_IMAGE_DIGEST__|example.invalid/exposure@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc|g' -e 's|__REQUIRED_[A-Z0-9_]*__|fixture-value|g' "$manifest" > "$rendered"
! rg -n '__REQUIRED_[A-Z0-9_]*__' "$rendered" >/dev/null || fail "fixture left unresolved placeholder"
test "$(rg -c '^apiVersion:' "$rendered")" = 7 || fail "fixture document count mismatch"
test "$(rg -c '^kind: Namespace$' "$rendered")" = 1 || fail "fixture Namespace missing"
test "$(rg -c '^kind: PersistentVolumeClaim$' "$rendered")" = 1 || fail "fixture PVC missing"
test "$(rg -c '^kind: ConfigMap$' "$rendered")" = 2 || fail "fixture ConfigMap count mismatch"
test "$(rg -c '^kind: Secret$' "$rendered")" = 0 || fail "fixture must not define a Secret"
test "$(rg -c '^kind: Pod$' "$rendered")" = 1 || fail "fixture Pod missing"
test "$(rg -c '^kind: Service$' "$rendered")" = 1 || fail "fixture Service missing"
test "$(rg -c '^kind: HTTPRoute$' "$rendered")" = 1 || fail "fixture HTTPRoute missing"
printf '%s\n' 'stage-a offline fixture render/static validation passed'
