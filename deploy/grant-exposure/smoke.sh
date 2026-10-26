#!/bin/sh
# Read-only HTTP smoke through an operator-owned loopback port-forward.
set -eu
GRANT_URL=${GRANT_URL:-http://127.0.0.1:18080}
EXPOSURE_URL=${EXPOSURE_URL:-http://127.0.0.1:18082}
EXPOSURE_ADMIN_URL=${EXPOSURE_ADMIN_URL:-http://127.0.0.1:18083}
for url in "$GRANT_URL" "$EXPOSURE_URL" "$EXPOSURE_ADMIN_URL"; do
  printf '%s\n' "$url" | grep -Eq '^http://127\.0\.0\.1:[0-9]{1,5}$' || { echo 'smoke requires explicit loopback origins' >&2; exit 2; }
done
curl --noproxy '*' --max-time 10 -fsS "$GRANT_URL/healthz" | jq -e '.status=="ok"' >/dev/null
curl --noproxy '*' --max-time 10 -fsS "$GRANT_URL/readyz" | jq -e '.writeReady==true and .readReady==true' >/dev/null
curl --noproxy '*' --max-time 10 -fsS "$EXPOSURE_ADMIN_URL/readyz" | jq -e '.ready==true' >/dev/null
expect() {
  want=$1; shift
  got=$(curl --noproxy '*' --max-time 15 -sS -o /dev/null -w '%{http_code}' "$@")
  [ "$got" = "$want" ] || { echo "HTTP smoke failed: expected $want, received $got" >&2; exit 1; }
}
expect 401 "$EXPOSURE_URL/api/v1/orgs"
expect 401 -H 'Authorization: Bearer not-a-jwt' "$EXPOSURE_URL/api/v1/orgs"
expect 404 "$EXPOSURE_URL/ops/backups"
printf '%s\n' 'PASS: Grant strong readiness, pinned Exposure readiness, missing/malformed bearer, private-route exclusion'
if [ -n "${USER_CURL_CONFIG:-}" ]; then
  : "${ORGANIZATION_ID:?set fresh organization ID for the authenticated smoke}"
  printf '%s\n' "$ORGANIZATION_ID" | grep -Eq '^grant-exposure-v020[-a-z0-9]*$' || exit 2
  [ -f "$USER_CURL_CONFIG" ] || exit 2
  # The private curl config supplies only the real user Authorization header.
  # Never pass a token through argv, stdout, trace output or a URL query.
  expect 200 --config "$USER_CURL_CONFIG" -H "X-Organization-ID: $ORGANIZATION_ID" "$EXPOSURE_URL/api/v1/orgs/$ORGANIZATION_ID"
  expect 200 --config "$USER_CURL_CONFIG" -H "X-Organization-ID: $ORGANIZATION_ID" "$EXPOSURE_URL/api/v1/orgs/$ORGANIZATION_ID/groups"
  expect 403 --config "$USER_CURL_CONFIG" -H "X-Organization-ID: $ORGANIZATION_ID" "$EXPOSURE_URL/api/v1/admin/users"
  printf '%s\n' 'PASS: native organization read/list allowed, platform users denied for non-platform owner'
else
  printf '%s\n' 'SKIP: live Goauthy user allow/deny (USER_CURL_CONFIG not provided)'
fi
# HTTP status alone is not a counter of upstream or PDP calls. Do not claim
# zero-upstream-hit evidence unless a separately observed counter establishes it.
