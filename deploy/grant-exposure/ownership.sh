#!/bin/sh
# Read-only guard. A label is not ownership evidence: retries require exact UIDs.
set -eu
context=gke_patch2-the-new-era_asia-northeast3_ied-cluster
namespace=grant-exposure-v020
owner=grant-exposure-v020
kube() { kubectl --context "$context" "$@"; }
case "${1:-}" in
  absent)
    [ "$#" -eq 1 ] || exit 2
    existing=$(kube get namespace "$namespace" --ignore-not-found -o name)
    [ -z "$existing" ] || { echo 'Refusing existing namespace; use owned with its original UID receipt.' >&2; exit 1; }
    # A namespace that does not exist cannot contain a preexisting grant-state PVC.
    ;;
  owned)
    [ "$#" -eq 2 ] || { echo 'usage: ownership.sh owned original-receipt.json' >&2; exit 2; }
    jq -e --arg c "$context" --arg n "$namespace" '
      .context==$c and .namespace==$n and
      (.namespaceUID|type=="string" and length>0) and
      (.pvcUID|type=="string" and length>0)
    ' "$2" >/dev/null
    nsuid=$(jq -r .namespaceUID "$2")
    pvcuid=$(jq -r .pvcUID "$2")
    kube get namespace "$namespace" -o json | jq -e --arg uid "$nsuid" --arg owner "$owner" '
      .metadata.uid==$uid and .metadata.labels["deployment.exposure.io/owner"]==$owner and .metadata.deletionTimestamp==null
    ' >/dev/null
    kube -n "$namespace" get pvc grant-state -o json | jq -e --arg uid "$pvcuid" --arg owner "$owner" '
      .metadata.uid==$uid and .metadata.labels["deployment.exposure.io/owner"]==$owner and
      .metadata.deletionTimestamp==null and .spec.storageClassName=="standard-rwo" and
      .spec.accessModes==["ReadWriteOnce"] and .spec.resources.requests.storage=="5Gi"
    ' >/dev/null
    ;;
  *) echo 'usage: ownership.sh absent | owned original-receipt.json' >&2; exit 2 ;;
esac
printf '%s\n' "PASS: namespace/PVC ownership guard ($1)"
