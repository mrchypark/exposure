#!/bin/sh
# Read-only, single snapshot. No implicit wait/restart/bootstrap/apply.
set -eu
[ "$#" -eq 2 ] || { echo 'usage: stage-readiness.sh grant|complete ownership.json' >&2; exit 2; }
case "$1" in grant|complete) ;; *) exit 2 ;; esac
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$root/ownership.sh" owned "$2" >/dev/null
uid=$(jq -er '.statefulSetUID|select(type=="string" and length>0)' "$2")
context=gke_patch2-the-new-era_asia-northeast3_ied-cluster
namespace=grant-exposure-v020
kubectl --context "$context" -n "$namespace" get statefulset grant-exposure -o json |
  jq -e --arg uid "$uid" '.metadata.uid==$uid and .metadata.labels["deployment.exposure.io/owner"]=="grant-exposure-v020"' >/dev/null
kubectl --context "$context" -n "$namespace" get pod grant-exposure-0 -o json |
  jq -e --arg uid "$uid" --arg stage "$1" '
    (.metadata.ownerReferences|any(.kind=="StatefulSet" and .uid==$uid and .controller==true)) and
    .metadata.deletionTimestamp==null and .status.phase=="Running" and
    (.status.containerStatuses|map(.name)|sort)==["exposure","grant"] and
    (if $stage=="grant" then (.status.containerStatuses|any(.name=="grant" and .ready==true))
     else (.status.containerStatuses|all(.ready==true)) and (.status.conditions|any(.type=="Ready" and .status=="True")) end)
  ' >/dev/null
printf '%s\n' "PASS: owned deployment readiness stage $1"
