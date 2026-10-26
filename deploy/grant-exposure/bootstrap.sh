#!/bin/sh
# Explicit fresh-stack API writes. Never SQL, old namespaces, or fabricated JWTs.
set -eu
[ "$#" -eq 5 ] || { echo 'usage: bootstrap.sh config.json catalog.json actions.json fixture-contract.json ownership.json' >&2; exit 2; }
config=$1; catalog=$2; actions=$3; fixture=$4; receipt=$5
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
context=gke_patch2-the-new-era_asia-northeast3_ied-cluster
namespace=grant-exposure-v020
GRANT_URL=${GRANT_URL:-http://127.0.0.1:18080}
printf '%s\n' "$GRANT_URL" | grep -Eq '^http://127\.0\.0\.1:[0-9]{1,5}$' || exit 2
"$root/stage-readiness.sh" grant "$receipt" >/dev/null
umask 077
scratch=$(mktemp -d "${TMPDIR:-/tmp}/grant-exposure-bootstrap.XXXXXX")
cleanup() { for file in "$scratch"/*; do test ! -f "$file" || unlink "$file"; done; rmdir "$scratch"; }
trap cleanup EXIT HUP INT TERM
"$root/render.sh" "$config" "$catalog" > "$scratch/runtime.json"
kubectl --context "$context" -n "$namespace" get statefulset grant-exposure -o json |
  jq -e --slurpfile c "$config" --slurpfile catalog "$catalog" '
    (.spec.template.spec.containers|any(.name=="grant" and .image==$c[0].grantImage)) and
    .spec.template.metadata.annotations["deployment.exposure.io/grant-revision"]==$c[0].grantRevision and
    .spec.template.metadata.annotations["deployment.exposure.io/catalog-digest"]==$catalog[0].catalogDigest
  ' >/dev/null
org=$(jq -r .organizationID "$config"); app=$(jq -r .applicationID "$config"); pep=$(jq -r .pepClientID "$config")
jq -e --slurpfile c "$config" '.context=="gke_patch2-the-new-era_asia-northeast3_ied-cluster" and .namespace=="grant-exposure-auth-test-v020" and .issuer==$c[0].issuer and .clientID==$c[0].expectedClientID and .audience==$c[0].resource and .requiredScopes==$c[0].requiredScopes and (.accessTokenFile|startswith("/"))' "$fixture" >/dev/null
tokenfile=$(jq -r .accessTokenFile "$fixture"); cafile=$(jq -r .caFile "$fixture"); clientsecret=$(jq -r .clientSecretFile "$fixture")
[ -s "$tokenfile" ] && [ -s "$cafile" ] && [ -s "$clientsecret" ]
# Read only this fresh namespace's recorded Secret, and retain no credential.
uid=$(jq -er .runtimeSecretUID "$receipt")
kubectl --context "$context" -n "$namespace" get secret runtime-credentials -o json > "$scratch/secret.json"
jq -e --arg uid "$uid" '.metadata.uid==$uid and .metadata.labels["deployment.exposure.io/owner"]=="grant-exposure-v020"' "$scratch/secret.json" >/dev/null
jq -r '.data.master' "$scratch/secret.json" | openssl base64 -d -A > "$scratch/master"
jq -nr --rawfile key "$scratch/master" --arg org "$org" '"header = "+("X-Grant-Master-Key: "+$key|@json), "header = "+("X-Organization-ID: "+$org|@json)' > "$scratch/master.conf"
jq -nr --rawfile token "$tokenfile" --arg org "$org" '$token|rtrimstr("\n")|rtrimstr("\r")|select(test("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$"))|"header = "+("Authorization: Bearer "+.|@json), "header = "+("X-Organization-ID: "+$org|@json)' > "$scratch/user.conf"
[ -s "$scratch/user.conf" ] || { echo 'real user token is absent/malformed' >&2; exit 1; }
cat "$scratch/master.conf" "$scratch/user.conf" > "$scratch/both.conf"
# request expected-status method path config body-file [If-Match]. Bodies and
# response details stay private; only method/path/status are reported on failure.
request() {
  want=$1; method=$2; path=$3; auth=$4; body=$5; match=${6:-}
  : > "$scratch/match.conf"
  if [ -n "$match" ]; then jq -nr --arg h "If-Match: $match" '"header = "+($h|@json)' > "$scratch/match.conf"; fi
  if [ "$method" = GET ]; then
    code=$(curl --noproxy '*' --max-time 20 -sS --config "$auth" --config "$scratch/match.conf" -D "$scratch/headers" -o "$scratch/response.json" -w '%{http_code}' "$GRANT_URL$path")
  else
    code=$(curl --noproxy '*' --max-time 20 -sS --config "$auth" --config "$scratch/match.conf" -X "$method" -H 'Content-Type: application/json' --data-binary "@$body" -D "$scratch/headers" -o "$scratch/response.json" -w '%{http_code}' "$GRANT_URL$path")
  fi
  [ "$code" = "$want" ] || { echo "bootstrap stopped: $method $path HTTP $code (expected $want); private response not printed" >&2; exit 1; }
}
etag() { awk 'tolower($1)=="etag:" {gsub("\r","",$2);print $2}' "$scratch/headers"; }
request 200 GET /readyz "$scratch/master.conf" /dev/null
jq -e '.readReady==true and .writeReady==true' "$scratch/response.json" >/dev/null
# No replay over an already activated catalog, or a different pre-existing app.
request 404 GET /api/v1/admin/providers/grant-management/http-capability-active "$scratch/master.conf" /dev/null
printf '%s\n' '{"id":"grant-management","name":"Grant management","active":true}' > "$scratch/provider.json"
case "${BOOTSTRAP_EXISTING_PROVIDER:-0}" in
  0) request 201 POST /api/v1/admin/providers "$scratch/master.conf" "$scratch/provider.json" ;;
  1) ;; # Explicit resume after this owned fresh stack's provider creation.
  *) echo 'invalid BOOTSTRAP_EXISTING_PROVIDER' >&2; exit 2 ;;
esac
request 200 GET /api/v1/admin/providers/grant-management/actions "$scratch/master.conf" /dev/null
match=$(etag); [ -n "$match" ]
jq '{actions:map({id,code,name,description,riskLevel,visibilityGranting,grantableToApplications,consentLabel,consentDescription})}' "$actions" > "$scratch/actions.json"
request 200 PUT /api/v1/admin/providers/grant-management/actions "$scratch/master.conf" "$scratch/actions.json" "$match"
request 201 POST /api/v1/admin/bootstrap/owner "$scratch/both.conf" /dev/null
user=$(jq -er --arg org "$org" 'select(.organizationId==$org)|.userId' "$scratch/response.json")
# Fetch the real client's exact redirect manifest over TLS, not a guessed URI.
client=$(jq -r .clientID "$fixture"); issuer=$(jq -r .issuer "$fixture")
{ printf 'header = "Authorization: Basic '; { printf '%s:' "$client"; cat "$clientsecret"; } | openssl base64 -A; printf '"\n'; } > "$scratch/client.conf"
connect=${GOAUTHY_CONNECT_TO:-goauthy.grant-exposure-auth-test-v020.svc.cluster.local:8443:127.0.0.1:18443}
printf '%s\n' "$connect" | grep -Eq '^goauthy\.grant-exposure-auth-test-v020\.svc\.cluster\.local:8443:127\.0\.0\.1:[0-9]{1,5}$' || exit 2
curl --noproxy '*' --proto '=https' --max-time 20 -fsS --cacert "$cafile" --connect-to "$connect" --config "$scratch/client.conf" -o "$scratch/client.json" "$issuer/oidc/client-configuration"
jq -e --arg client "$client" --arg issuer "$issuer" '.client_id==$client and .issuer==$issuer and .enabled==true and .confidential==true and (.redirect_uris|type=="array" and length<=1)' "$scratch/client.json" >/dev/null
jq -n --arg app "$app" --slurpfile client "$scratch/client.json" '{id:$app,slug:$app,name:"Grant Exposure isolated management",applicationType:"confidential",appType:"server",active:true,redirectUri:($client[0].redirect_uris[0]//null)}' > "$scratch/app.json"
request 201 POST "/api/v1/orgs/$org/apps" "$scratch/user.conf" "$scratch/app.json"
jq -n --arg client "$client" '{clientId:$client}' > "$scratch/binding.json"
request 200 PUT "/api/v1/admin/orgs/$org/apps/$app/identity-binding" "$scratch/master.conf" "$scratch/binding.json"
jq -e '.provisioningStatus=="ready"' "$scratch/response.json" >/dev/null
printf '%s\n' '{"trusted":true}' > "$scratch/trust.json"
request 200 PUT "/api/v1/admin/orgs/$org/apps/$app/trust" "$scratch/master.conf" "$scratch/trust.json"
# Admit exactly the read/list and denial-test actions. Admission is not a user grant.
for action in grant-management.organization.detail grant-management.groups.read grant-management.admin.users.read; do
  request 204 PUT "/api/v1/admin/orgs/$org/apps/$app/actions/$action" "$scratch/master.conf" /dev/null
done
role=grant-exposure-v020-reader
jq -n --arg role "$role" '{id:$role,code:$role,name:"Isolated organization reader"}' > "$scratch/role.json"
request 201 POST "/api/v1/orgs/$org/roles" "$scratch/user.conf" "$scratch/role.json"
request 200 GET "/api/v1/orgs/$org/roles/$role/actions" "$scratch/user.conf" /dev/null
match=$(etag); [ -n "$match" ]
printf '%s\n' '{"actionIds":["grant-management.organization.detail","grant-management.groups.read"]}' > "$scratch/role-actions.json"
request 200 PUT "/api/v1/orgs/$org/roles/$role/actions" "$scratch/user.conf" "$scratch/role-actions.json" "$match"
jq -n --arg user "$user" --arg org "$org" --arg role "$role" '{id:"grant-exposure-v020-reader-binding",subjectType:"user",subjectId:$user,subjectOrganizationId:$org,providerId:"grant-management",resourceType:"organization",resourceId:$org,roleId:$role,agreementId:null,state:"active"}' > "$scratch/role-binding.json"
request 201 POST "/api/v1/orgs/$org/bindings" "$scratch/user.conf" "$scratch/role-binding.json"
printf '%s\n' '{"lifecycle":"active","validUntil":null}' > "$scratch/pep.json"
request 200 PUT "/ops/providers/grant-management/enforcers/$pep" "$scratch/master.conf" "$scratch/pep.json"
request 201 POST /api/v1/admin/providers/grant-management/http-capability-generations "$scratch/master.conf" "$catalog"
jq '{expectedGeneration:null,expectedCatalogDigest:null,targetGeneration:.generation,targetCatalogDigest:.catalogDigest}' "$catalog" > "$scratch/activation.json"
request 200 POST /api/v1/admin/providers/grant-management/http-capability-active "$scratch/master.conf" "$scratch/activation.json"
printf '%s\n' 'PASS: supported native APIs provisioned the fresh real-user/app/role/PEP/catalog; no platform user grant'
# Grant API writes are finished. Exposure refresh/readiness is asynchronous.
# The caller performs stage-readiness complete then smoke with a separately
# protected config constructed from the same real fixture accessTokenFile.
