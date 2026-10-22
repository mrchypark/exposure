#!/bin/sh
# Seed only a fresh, independently started loopback Grant fixture through public APIs.
set -eu
umask 077
ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
: "${PATCH_AUTH_FIXTURE:?set to patch-auth verify-local integration.json}"
: "${GRANT_URL:?set to the owned loopback Grant server origin}"
: "${GRANT_MASTER_KEY_FILE:?set private fixture key file}"
: "${GRANT_APP_KEY_FILE:?set private fixture key file}"
for tool in curl jq mktemp; do command -v "$tool" >/dev/null; done
loopback() { printf '%s\n' "$1" | grep -Eq '^http://127\.0\.0\.1:[0-9]+$'; }
loopback "$GRANT_URL" || { echo 'Grant fixture requires a loopback origin' >&2; exit 2; }
auth_origin=$(jq -er .authOrigin "$PATCH_AUTH_FIXTURE")
data_origin=$(jq -er .patchDataOrigin "$PATCH_AUTH_FIXTURE")
if ! loopback "$auth_origin" || ! loopback "$data_origin"; then echo 'PocketBase fixtures require loopback origins' >&2; exit 2; fi
jq -e '.collection=="users" and .collectionId=="_pb_users_auth_" and .resourcePath=="/api/collections/plants/records/fixtureplant01a"' "$PATCH_AUTH_FIXTURE" >/dev/null
out=$(mktemp -d "${TMPDIR:-/tmp}/grant-auth-seed.XXXXXX")
master=$(cat "$GRANT_MASTER_KEY_FILE")
app=$(cat "$GRANT_APP_KEY_FILE")
[ -n "$master" ] && [ -n "$app" ]
jq '{identity:.allowIdentity,password:.password}' "$PATCH_AUTH_FIXTURE" >"$out/login-input.json"
curl --max-time 5 -fsS -H 'Content-Type: application/json' --data-binary "@$out/login-input.json" "$auth_origin/api/collections/users/auth-with-password" >"$out/login.json"
bearer=$(jq -er .token "$out/login.json")
printf 'Content-Type: application/json\nX-Grant-Master-Key: %s\nX-Grant-App-Auth-Key: %s\nAuthorization: Bearer %s\nX-Organization-ID: synthetic-org\n' "$master" "$app" "$bearer" >"$out/headers"
unset master app bearer
req() {
 target=''
 method=''
 previous=''
 for arg do
   if [ "$previous" = '-X' ]; then method=$arg; fi
   previous=$arg
   target=$arg
 done
 case "$method:$target" in
   "PUT:$GRANT_URL/"*/actions)
     curl --max-time 5 -fsS -D "$out/etag-headers" -o /dev/null --header "@$out/headers" "$target?consistency=strong"
     etag=$(awk 'tolower($1)=="etag:" {sub(/\r$/, ""); print $2}' "$out/etag-headers")
     [ -n "$etag" ] || { echo 'Missing Grant action-set ETag' >&2; return 1; }
     curl --max-time 5 -fsS -H "If-Match: $etag" --header "@$out/headers" "$@"
     return
     ;;
 esac
 curl --max-time 5 -fsS --header "@$out/headers" "$@" || { printf 'Fixture seed failed: %s\n' "$target" >&2; return 1; }
}
req -X POST -d '{"organizationId":"synthetic-org"}' "$GRANT_URL/api/v1/admin/bootstrap/owner" >"$out/bootstrap.json"
req -d '{"id":"synthetic-app","slug":"synthetic-app","name":"Local data PEP","description":null,"applicationType":"confidential","appType":"internal","active":true,"redirectUri":null}' "$GRANT_URL/api/v1/orgs/synthetic-org/apps" >/dev/null
req -d '{"id":"patch-data","name":"Patch Data","active":true}' "$GRANT_URL/api/v1/admin/providers" >/dev/null
req -X PUT -d '{"actions":[{"id":"plant.read","code":"plant.read","name":"Read plant","riskLevel":"low","visibilityGranting":false,"grantableToApplications":true}]}' "$GRANT_URL/api/v1/admin/providers/patch-data/actions" >/dev/null
req -X PUT -d '{"trusted":false}' "$GRANT_URL/api/v1/admin/orgs/synthetic-org/apps/synthetic-app/trust" >/dev/null
req -X PUT -d '{"actionIds":["patch-data.plant.read"]}' "$GRANT_URL/api/v1/orgs/synthetic-org/apps/synthetic-app/actions" >/dev/null
req -X PUT -d '{"trusted":true}' "$GRANT_URL/api/v1/admin/orgs/synthetic-org/apps/synthetic-app/trust" >/dev/null
req -d '{"id":"fixture-reader","code":"fixture-reader","name":"Fixture reader"}' "$GRANT_URL/api/v1/orgs/synthetic-org/roles" >/dev/null
req -X PUT -d '{"actionIds":["patch-data.plant.read"]}' "$GRANT_URL/api/v1/orgs/synthetic-org/roles/fixture-reader/actions" >/dev/null
jq '{id:"fixture-binding",subjectType:"user",subjectId:.userId,subjectOrganizationId:"synthetic-org",providerId:"patch-data",resourceType:"plant",resourceId:"fixtureplant01a",roleId:"fixture-reader",agreementId:null,state:"active"}' "$out/bootstrap.json" >"$out/binding.json"
req -d "@$out/binding.json" "$GRANT_URL/api/v1/orgs/synthetic-org/bindings" >/dev/null
req -X PUT -d '{"applicationId":"synthetic-app","lifecycle":"active","validUntil":null}' "$GRANT_URL/ops/providers/patch-data/enforcers/synthetic-pep" >/dev/null
req -d "@$ROOT/scripts/testdata/patch-auth-capability.json" "$GRANT_URL/api/v1/admin/providers/patch-data/http-capability-generations" >/dev/null
jq '{expectedGeneration:null,expectedCatalogDigest:null,targetGeneration:1,targetCatalogDigest:.catalogDigest}' "$ROOT/scripts/testdata/patch-auth-capability.json" >"$out/activation.json"
req -d "@$out/activation.json" "$GRANT_URL/api/v1/admin/providers/patch-data/http-capability-active" >/dev/null
req -d '{"id":"grant-management","name":"Grant management","active":true}' "$GRANT_URL/api/v1/admin/providers" >/dev/null
req -X PUT -d '{"actions":[{"id":"manage","code":"manage","name":"Manage Grant groups","riskLevel":"high","visibilityGranting":false,"grantableToApplications":true}]}' "$GRANT_URL/api/v1/admin/providers/grant-management/actions" >/dev/null
req -d '{"id":"synthetic-management-app","slug":"synthetic-management-app","name":"Grant management app","description":null,"applicationType":"confidential","appType":"internal","active":true,"redirectUri":null}' "$GRANT_URL/api/v1/orgs/synthetic-org/apps" >/dev/null
req -X PUT -d '{"trusted":false}' "$GRANT_URL/api/v1/admin/orgs/synthetic-org/apps/synthetic-management-app/trust" >/dev/null
req -X PUT -d '{"actionIds":["grant-management.manage"]}' "$GRANT_URL/api/v1/orgs/synthetic-org/apps/synthetic-management-app/actions" >/dev/null
req -X PUT -d '{"trusted":true}' "$GRANT_URL/api/v1/admin/orgs/synthetic-org/apps/synthetic-management-app/trust" >/dev/null
req -d '{"id":"fixture-management","code":"fixture-management","name":"Manage local Grant fixture"}' "$GRANT_URL/api/v1/orgs/synthetic-org/roles" >/dev/null
req -X PUT -d '{"actionIds":["grant-management.manage"]}' "$GRANT_URL/api/v1/orgs/synthetic-org/roles/fixture-management/actions" >/dev/null
jq '{id:"fixture-management-binding",subjectType:"user",subjectId:.userId,subjectOrganizationId:"synthetic-org",providerId:"grant-management",resourceType:"organization",resourceId:"synthetic-org",roleId:"fixture-management",agreementId:null,state:"active"}' "$out/bootstrap.json" >"$out/management-binding.json"
req -d "@$out/management-binding.json" "$GRANT_URL/api/v1/orgs/synthetic-org/bindings" >/dev/null
req -X PUT -d '{"applicationId":"synthetic-management-app","lifecycle":"active","validUntil":null}' "$GRANT_URL/ops/providers/grant-management/enforcers/synthetic-management-pep" >/dev/null
req -d "@$ROOT/scripts/testdata/grant-management-capability.json" "$GRANT_URL/api/v1/admin/providers/grant-management/http-capability-generations" >/dev/null
jq '{expectedGeneration:null,expectedCatalogDigest:null,targetGeneration:1,targetCatalogDigest:.catalogDigest}' "$ROOT/scripts/testdata/grant-management-capability.json" >"$out/management-activation.json"
req -d "@$out/management-activation.json" "$GRANT_URL/api/v1/admin/providers/grant-management/http-capability-active" >/dev/null
jq --arg grantURL "$GRANT_URL" --rawfile key "$GRANT_APP_KEY_FILE" --slurpfile catalog "$ROOT/scripts/testdata/patch-auth-capability.json" '{AuthOrigin:.authOrigin,Collection:.collection,CollectionID:.collectionId,ApplicationID:"synthetic-app",AllowIdentity:.allowIdentity,AllowPassword:.password,DenyIdentity:.denyIdentity,DenyPassword:.password,GrantURL:$grantURL,GrantAppKey:($key|rtrimstr("\n")),ProviderID:"patch-data",PEPClientID:"synthetic-pep",CatalogDigest:$catalog[0].catalogDigest,DataOrigin:.patchDataOrigin,ResourcePath:.resourcePath,OrganizationID:"synthetic-org",DisabledLoginPath:"/api/collections/users/auth-with-password",UpstreamToken:.upstreamToken}' "$PATCH_AUTH_FIXTURE" >"$out/exposure-integration.json"
printf '%s\n' "$out/exposure-integration.json"
