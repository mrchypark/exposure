#!/bin/sh
# Offline tests: kubectl is a rejecting mock; no live credentials or cluster calls.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/grant-exposure-ownership-test.XXXXXX")
cleanup() { find "$scratch" -type f -exec unlink {} \;; rmdir "$scratch/bin"; rmdir "$scratch"; }
trap cleanup EXIT HUP INT TERM
mkdir "$scratch/bin"
cat > "$scratch/bin/kubectl" <<'MOCK'
#!/bin/sh
set -eu
[ "$1" = --context ] && [ "$2" = gke_patch2-the-new-era_asia-northeast3_ied-cluster ] || exit 99
case "$*" in
  *'get namespace grant-exposure-v020 --ignore-not-found -o name')
    case "$MOCK_CASE" in absent) exit 0 ;; api-error) exit 7 ;; *) echo namespace/grant-exposure-v020 ;; esac ;;
  *'get namespace grant-exposure-v020 -o json')
    case "$MOCK_CASE" in
      namespace-recreated) jq '.metadata.uid="foreign-namespace"' "$MOCK_DATA/ns.json" ;;
      foreign-label) jq '.metadata.labels["deployment.exposure.io/owner"]="other"' "$MOCK_DATA/ns.json" ;;
      terminating) jq '.metadata.deletionTimestamp="2026-10-26T00:00:00Z"' "$MOCK_DATA/ns.json" ;;
      api-error) exit 7 ;;
      *) cat "$MOCK_DATA/ns.json" ;;
    esac ;;
  *'-n grant-exposure-v020 get pvc grant-state -o json')
    case "$MOCK_CASE" in
      pvc-recreated) jq '.metadata.uid="foreign-pvc"' "$MOCK_DATA/pvc.json" ;;
      foreign-pvc-label) jq '.metadata.labels["deployment.exposure.io/owner"]="other"' "$MOCK_DATA/pvc.json" ;;
      wrong-storage) jq '.spec.storageClassName="other"' "$MOCK_DATA/pvc.json" ;;
      api-error) exit 7 ;;
      *) cat "$MOCK_DATA/pvc.json" ;;
    esac ;;
  *'-n grant-exposure-v020 get statefulset grant-exposure -o json')
    if [ "$MOCK_CASE" = wrong-sts ]; then
      jq '.metadata.uid="foreign-sts"' "$MOCK_DATA/sts.json"
    else cat "$MOCK_DATA/sts.json"; fi ;;
  *'-n grant-exposure-v020 get pod grant-exposure-0 -o json')
    case "$MOCK_CASE" in
      grant-only) jq '.status.containerStatuses[0].ready=false | .status.conditions[0].status="False"' "$MOCK_DATA/pod.json" ;;
      grant-unready) jq '.status.containerStatuses[1].ready=false' "$MOCK_DATA/pod.json" ;;
      wrong-pod-owner) jq '.metadata.ownerReferences[0].uid="foreign-sts"' "$MOCK_DATA/pod.json" ;;
      extra-container) jq '.status.containerStatuses += [{name:"extra",ready:true}]' "$MOCK_DATA/pod.json" ;;
      *) cat "$MOCK_DATA/pod.json" ;;
    esac ;;
  *) echo 'Unexpected/mutating kubectl invocation rejected' >&2; exit 99 ;;
esac
MOCK
chmod +x "$scratch/bin/kubectl"
export MOCK_DATA="$scratch"
export PATH="$scratch/bin:$PATH"
printf '%s\n' '{"metadata":{"uid":"new-namespace-uid","labels":{"deployment.exposure.io/owner":"grant-exposure-v020"}}}' > "$scratch/ns.json"
printf '%s\n' '{"metadata":{"uid":"new-pvc-uid","labels":{"deployment.exposure.io/owner":"grant-exposure-v020"}},"spec":{"storageClassName":"standard-rwo","accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"5Gi"}}}}' > "$scratch/pvc.json"
printf '%s\n' '{"context":"gke_patch2-the-new-era_asia-northeast3_ied-cluster","namespace":"grant-exposure-v020","namespaceUID":"new-namespace-uid","pvcUID":"new-pvc-uid","statefulSetUID":"new-sts-uid"}' > "$scratch/receipt.json"
printf '%s\n' '{"metadata":{"uid":"new-sts-uid","labels":{"deployment.exposure.io/owner":"grant-exposure-v020"}}}' > "$scratch/sts.json"
printf '%s\n' '{"metadata":{"ownerReferences":[{"kind":"StatefulSet","uid":"new-sts-uid","controller":true}]},"status":{"phase":"Running","containerStatuses":[{"name":"exposure","ready":true},{"name":"grant","ready":true}],"conditions":[{"type":"Ready","status":"True"}]}}' > "$scratch/pod.json"
MOCK_CASE=absent "$root/ownership.sh" absent >/dev/null
MOCK_CASE=matching "$root/ownership.sh" owned "$scratch/receipt.json" >/dev/null
for condition in matching api-error; do
  if MOCK_CASE="$condition" "$root/ownership.sh" absent >/dev/null 2>&1; then echo "accepted existing namespace/API failure: $condition" >&2; exit 1; fi
done
for condition in namespace-recreated pvc-recreated foreign-label foreign-pvc-label terminating wrong-storage api-error; do
  if MOCK_CASE="$condition" "$root/ownership.sh" owned "$scratch/receipt.json" >/dev/null 2>&1; then echo "accepted foreign/invalid state: $condition" >&2; exit 1; fi
done
jq '.pvcUID=null' "$scratch/receipt.json" > "$scratch/incomplete.json"
if MOCK_CASE=matching "$root/ownership.sh" owned "$scratch/incomplete.json" >/dev/null 2>&1; then echo 'accepted incomplete creation receipt' >&2; exit 1; fi
jq '.namespace="operable"' "$scratch/receipt.json" > "$scratch/wrong-namespace.json"
if MOCK_CASE=matching "$root/ownership.sh" owned "$scratch/wrong-namespace.json" >/dev/null 2>&1; then echo 'accepted wrong namespace receipt' >&2; exit 1; fi
MOCK_CASE=grant-only "$root/stage-readiness.sh" grant "$scratch/receipt.json" >/dev/null
if MOCK_CASE=grant-only "$root/stage-readiness.sh" complete "$scratch/receipt.json" >/dev/null 2>&1; then echo 'accepted incomplete Exposure/catalog activation' >&2; exit 1; fi
MOCK_CASE=matching "$root/stage-readiness.sh" complete "$scratch/receipt.json" >/dev/null
for condition in wrong-sts wrong-pod-owner grant-unready extra-container; do
  if MOCK_CASE="$condition" "$root/stage-readiness.sh" grant "$scratch/receipt.json" >/dev/null 2>&1; then echo "accepted wrong/unready Pod: $condition" >&2; exit 1; fi
done
# Local Rhiza rejects even an ephemeral listener. An explicitly empty env value
# is necessary because Grant defaults an omitted GRANT_PEER_ADDR to loopback.
jq '.grantImage="ghcr.io/mrchypark/grant@sha256:0000000000000000000000000000000000000000000000000000000000000000" | .grantRelease="v0.2.0" | .grantRevision="0000000000000000000000000000000000000000"' "$root/config.example.json" > "$scratch/config.json"
printf '%s\n' '{"schemaVersion":1,"generation":1,"expectedLatestGeneration":null,"catalogDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","capabilities":[{}]}' > "$scratch/catalog.json"
"$root/render.sh" "$scratch/config.json" "$scratch/catalog.json" | jq -e '.items[0].data | has("GRANT_PEER_ADDR") and .GRANT_PEER_ADDR=="" and (.GRANT_RHIZA_CONFIG_JSON|fromjson|.Local==true)' >/dev/null
cleanup
trap - EXIT HUP INT TERM
test ! -e "$scratch"
printf '%s\n' 'PASS: absent/matching/foreign UID guards, deletion/storage/API/receipt rejection, Grant-only vs complete readiness, exact Pod owner/containers; no cluster calls'
