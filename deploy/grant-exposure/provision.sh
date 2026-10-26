#!/bin/sh
# Explicit phases only. No phase deletes, patches, adopts, rotates or rolls pods.
# check is read-only; infra/secrets/runtime are future authorized write phases.
set -eu
[ "$#" -eq 6 ] || { echo 'usage: provision.sh check|infra|secrets|runtime config.json catalog.json ghcr-only.json fixture-contract.json ownership.json' >&2; exit 2; }
mode=$1; config=$2; catalog=$3; registry=$4; fixture=$5; receipt=$6
case "$mode" in check|infra|secrets|runtime) ;; *) exit 2 ;; esac
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
context=gke_patch2-the-new-era_asia-northeast3_ied-cluster
namespace=grant-exposure-v020
owner=grant-exposure-v020
kube() { kubectl --context "$context" "$@"; }
umask 077
scratch=$(mktemp -d "${TMPDIR:-/tmp}/grant-exposure-provision.XXXXXX")
cleanup() { for file in "$scratch"/*; do test ! -f "$file" || unlink "$file"; done; rmdir "$scratch"; }
trap cleanup EXIT HUP INT TERM
"$root/render.sh" "$config" "$catalog" > "$scratch/runtime.json"
image=$(jq -r .grantImage "$config")
tag=$(jq -r .grantRelease "$config")
revision=$(jq -r .grantRevision "$config")
gh release view "$tag" --repo mrchypark/grant --json isDraft,isPrerelease,tagName | jq -e --arg tag "$tag" '.tagName==$tag and .isDraft==false and .isPrerelease==false' >/dev/null
[ "$(gh api "repos/mrchypark/grant/commits/$tag" --jq .sha)" = "$revision" ] || { echo 'Grant release/source revision mismatch' >&2; exit 1; }
"$root/check-pull.sh" "$registry" "$image" ghcr.io/mrchypark/exposure@sha256:268d5ded6ec941af266306cf63f09c32a0ec38057b95f6c5ceb140afb04cce62
printf '%s\n' 'PASS: release/source and both pinned manifests'
if [ "$mode" != infra ]; then
# The standalone Goauthy owner supplies this private-file contract. No old
# namespace, Secret or database is read by this script.
jq -e --slurpfile config "$config" '
  . as $f | $config[0] as $c |
  .context=="gke_patch2-the-new-era_asia-northeast3_ied-cluster" and .namespace=="grant-exposure-auth-test-v020" and
  .issuer==$c.issuer and .clientID==$c.introspectionClientID and .clientID==$c.expectedClientID and
  .audience==$c.resource and .requiredScopes==$c.requiredScopes and
  (.clientSecretFile|type=="string" and startswith("/")) and
  (.caFile|type=="string" and startswith("/"))
' "$fixture" >/dev/null
secretfile=$(jq -r .clientSecretFile "$fixture")
cafile=$(jq -r .caFile "$fixture")
[ -s "$secretfile" ] || { echo 'fixture introspection secret file missing/empty' >&2; exit 1; }
[ -s "$cafile" ] || { echo 'fixture public CA file missing/empty' >&2; exit 1; }
openssl x509 -in "$cafile" -noout >/dev/null
issuer=$(jq -r .issuer "$config")
client=$(jq -r .introspectionClientID "$config")
# Keep Basic auth out of argv and stdout. jq -r emits a curl-config header only
# to a private file; credentials are never returned as provisioning output.
{
  printf 'header = "Authorization: Basic '
  { printf '%s:' "$client"; cat "$secretfile"; } | openssl base64 -A
  printf '"\n'
} > "$scratch/goauthy.conf"
# In-cluster service DNS is resolved through an already-owned local fixture
# port-forward when supplied. TLS still verifies the configured issuer name.
connect_to=${GOAUTHY_CONNECT_TO:-}
if [ -n "$connect_to" ]; then
  printf '%s\n' "$connect_to" | grep -Eq '^goauthy\.grant-exposure-auth-test-v020\.svc\.cluster\.local:8443:127\.0\.0\.1:[0-9]{1,5}$' || { echo 'fixture connection override must target owned loopback port-forward' >&2; exit 2; }
  code=$(curl --noproxy '*' --proto '=https' --max-time 20 -sS --cacert "$cafile" --connect-to "$connect_to" --config "$scratch/goauthy.conf" -H 'Accept-Encoding: identity' -D "$scratch/client.headers" -o "$scratch/client.json" -w '%{http_code}' "$issuer/oidc/client-configuration")
else
  code=$(curl --noproxy '*' --proto '=https' --max-time 20 -sS --cacert "$cafile" --config "$scratch/goauthy.conf" -H 'Accept-Encoding: identity' -D "$scratch/client.headers" -o "$scratch/client.json" -w '%{http_code}' "$issuer/oidc/client-configuration")
fi
[ "$code" = 200 ] || { echo "fixture client configuration unavailable: HTTP $code" >&2; exit 1; }
expected_etag="\"sha256:$(openssl dgst -sha256 -r "$scratch/client.json" | cut -d ' ' -f1)\""
actual_etag=$(awk 'tolower($1)=="etag:" {gsub("\r","",$2);print $2}' "$scratch/client.headers")
[ "$actual_etag" = "$expected_etag" ] || { echo 'Goauthy client configuration ETag mismatch' >&2; exit 1; }
jq -e --slurpfile config "$config" '
  . as $m | $config[0] as $c |
  .version=="goauthy.client-configuration.v1" and .issuer==$c.issuer and
  .client_id==$c.introspectionClientID and .client_id==$c.expectedClientID and
  .client_kind=="bootstrap" and .enabled==true and .confidential==true and
  ((.grant_types|index("authorization_code"))!=null) and ((.grant_types|index("refresh_token"))!=null) and
  ((.audience|index($c.resource))!=null) and .default_aud==[$c.resource] and
  ((($c.requiredScopes|split(" ")) - $m.scopes)|length==0)
' "$scratch/client.json" >/dev/null
printf '%s\n' 'PASS: release/source, pinned manifest access, fixture metadata and real client compatibility'
fi
[ "$mode" != check ] || exit 0
if [ "$mode" = infra ]; then
  [ ! -e "$receipt" ] || { echo 'refusing to overwrite an ownership receipt' >&2; exit 1; }
  "$root/ownership.sh" absent
  kube create --dry-run=client --validate=true -f "$root/infra.yaml" -o json > "$scratch/infra-stream.json"
  # kubectl prints one JSON object per YAML document, not necessarily a List.
  jq -s '{apiVersion:"v1",kind:"List",items:[.[]|if .kind=="List" then .items[] else . end]}' "$scratch/infra-stream.json" > "$scratch/infra.json"
  jq '.items[]|select(.kind=="Namespace")' "$scratch/infra.json" > "$scratch/namespace.json"
  kube create -f "$scratch/namespace.json" -o json > "$scratch/namespace-created.json"
  nsuid=$(jq -er .metadata.uid "$scratch/namespace-created.json")
  jq -n --arg c "$context" --arg n "$namespace" --arg uid "$nsuid" '{context:$c,namespace:$n,namespaceUID:$uid,pvcUID:null}' > "$receipt"
  # Keep this partial receipt if any later creation fails. Never auto-adopt a
  # same-name PVC on retry; incomplete receipts require explicit inspection.
  jq '.items |= map(select(.kind!="Namespace"))' "$scratch/infra.json" > "$scratch/namespaced.json"
  kube -n "$namespace" create -f "$scratch/namespaced.json" -o json > "$scratch/created-stream.json"
  jq -s '{items:[.[]|if .kind=="List" then .items[] else . end]}' "$scratch/created-stream.json" > "$scratch/created.json"
  pvcuid=$(jq -er '.items[]|select(.kind=="PersistentVolumeClaim" and .metadata.name=="grant-state")|.metadata.uid' "$scratch/created.json")
  jq --arg uid "$pvcuid" '.pvcUID=$uid' "$receipt" > "$scratch/receipt.json"
  mv "$scratch/receipt.json" "$receipt"
  "$root/ownership.sh" owned "$receipt"
  exit 0
fi
"$root/ownership.sh" owned "$receipt"
if [ "$mode" = secrets ]; then
  existing=$(kube -n "$namespace" get secret runtime-credentials ghcr-pull --ignore-not-found -o name)
  [ -z "$existing" ] || { echo 'Secrets already exist: refusing rotation/adoption; inspect original receipts.' >&2; exit 1; }
  existing=$(kube -n "$namespace" get configmap goauthy-trust --ignore-not-found -o name)
  [ -z "$existing" ] || { echo 'trust config already exists; refusing implicit CA rotation/adoption' >&2; exit 1; }
  for key in master app limiter; do openssl rand -hex 32 | tr -d '\n' > "$scratch/$key"; done
  if cmp -s "$scratch/master" "$scratch/app" || cmp -s "$scratch/master" "$scratch/limiter" || cmp -s "$scratch/app" "$scratch/limiter"; then
    echo 'generated credentials must differ' >&2; exit 1
  fi
  kube -n "$namespace" create secret generic runtime-credentials \
    --from-file="master=$scratch/master" --from-file="app=$scratch/app" --from-file="limiter=$scratch/limiter" \
    --from-file="goauthy-introspection=$secretfile" --dry-run=client -o json |
    jq --arg owner "$owner" '.metadata.labels={"deployment.exposure.io/owner":$owner}' > "$scratch/secret.json"
  kube -n "$namespace" create -f "$scratch/secret.json" -o json > "$scratch/secret-created.json"
  uid=$(jq -er .metadata.uid "$scratch/secret-created.json")
  jq --arg uid "$uid" '.runtimeSecretUID=$uid' "$receipt" > "$scratch/receipt.json"
  mv "$scratch/receipt.json" "$receipt"
  kube -n "$namespace" create secret generic ghcr-pull --type=kubernetes.io/dockerconfigjson \
    --from-file=".dockerconfigjson=$registry" --dry-run=client -o json |
    jq --arg owner "$owner" '.metadata.labels={"deployment.exposure.io/owner":$owner}' > "$scratch/pull-secret.json"
  kube -n "$namespace" create -f "$scratch/pull-secret.json" -o json > "$scratch/pull-created.json"
  uid=$(jq -er .metadata.uid "$scratch/pull-created.json")
  jq --arg uid "$uid" '.pullSecretUID=$uid' "$receipt" > "$scratch/receipt.json"
  mv "$scratch/receipt.json" "$receipt"
  kube -n "$namespace" create configmap goauthy-trust --from-file="ca.pem=$cafile" --dry-run=client -o json |
    jq --arg owner "$owner" '.metadata.labels={"deployment.exposure.io/owner":$owner}' > "$scratch/trust.json"
  kube -n "$namespace" create -f "$scratch/trust.json" -o json > "$scratch/trust-created.json"
  uid=$(jq -er .metadata.uid "$scratch/trust-created.json")
  jq --arg uid "$uid" '.trustConfigUID=$uid' "$receipt" > "$scratch/receipt.json"
  mv "$scratch/receipt.json" "$receipt"
  printf '%s\n' 'Created only new namespace-local Secrets; values not displayed; UIDs recorded'
  exit 0
fi
for pair in runtime-credentials:runtimeSecretUID ghcr-pull:pullSecretUID; do
  name=${pair%:*}; field=${pair#*:}
  uid=$(jq -er --arg field "$field" '.[$field]|select(type=="string" and length>0)' "$receipt")
  kube -n "$namespace" get secret "$name" -o json | jq -e --arg uid "$uid" --arg owner "$owner" '.metadata.uid==$uid and .metadata.labels["deployment.exposure.io/owner"]==$owner' >/dev/null
 done
uid=$(jq -er '.trustConfigUID|select(type=="string" and length>0)' "$receipt")
kube -n "$namespace" get configmap goauthy-trust -o json | jq -e --arg uid "$uid" --arg owner "$owner" '.metadata.uid==$uid and .metadata.labels["deployment.exposure.io/owner"]==$owner' >/dev/null
existing=$(kube -n "$namespace" get statefulset grant-exposure --ignore-not-found -o name)
[ -z "$existing" ] || { echo 'runtime exists; no implicit apply/restart permitted' >&2; exit 1; }
kube -n "$namespace" create -f "$scratch/runtime.json" -o json > "$scratch/runtime-stream.json"
jq -s '{items:[.[]|if .kind=="List" then .items[] else . end]}' "$scratch/runtime-stream.json" > "$scratch/runtime-created.json"
uid=$(jq -er '.items[]|select(.kind=="StatefulSet")|.metadata.uid' "$scratch/runtime-created.json")
jq --arg uid "$uid" '.statefulSetUID=$uid' "$receipt" > "$scratch/receipt.json"
mv "$scratch/receipt.json" "$receipt"
printf '%s\n' 'Runtime created. Wait for Grant container readiness only; use Pod port-forward for authenticated bootstrap/catalog activation before full Pod readiness.'
