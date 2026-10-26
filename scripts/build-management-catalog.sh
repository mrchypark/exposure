#!/bin/sh
# Deterministic fixture only; output contains no credentials.
#
# Usage:
#   scripts/build-management-catalog.sh                    # legacy 3-route groups fixture
#   scripts/build-management-catalog.sh --full             # full catalog (requires GRANT_SOURCE_DIR)
#   GRANT_SOURCE_DIR=../grant-management-exposure \
#     scripts/build-management-catalog.sh --full -generation 2 -previous-generation 1
#
# --full delegates to Grant's cmd/grant-management-catalog. The source tree
# must already exist and contain the CLI entry point.
# The producer must implement docs/organization-context.md to emit optional
# organization policies. This wrapper never adds policy or rewrites digests
# behind the producer's back; older producers emit required-org catalogs.
set -eu

# ---------- legacy group-only fixture (default) ----------
build_group_fixture() {
  capabilities='[]'
  for method in GET POST DELETE; do
    path='/api/v1/orgs/{organizationId}/groups'
    body=none
    max=0
    if [ "$method" = POST ]; then body=json; max=65536; fi
    if [ "$method" = DELETE ]; then path="$path/{groupId}"; fi
    cap=$(jq -cn --arg method "$method" --arg path "$path" --arg body "$body" --argjson max "$max" '{capabilityId:("fixture-groups-"+($method|ascii_downcase)),version:1,enabled:true,accessMode:"authorized",method:$method,pathTemplate:$path,actionId:"grant-management.manage",resource:{type:"organization",id:{kind:"pathSegment",name:"organizationId",format:"slug"}},query:{mode:"none"},request:{body:$body,maxBytes:$max,forwardHeaders:["content-type","x-organization-id"],authorization:"forward-user"},response:{maxBytes:65536,forwardHeaders:["content-type"],redirects:"deny",errorStatuses:[400,401,403,404,409,422,500,503]}}')
    canonical=$(printf '%s' "$cap" | jq -cS .)
    digest=$(printf '%s' "$canonical" | openssl dgst -sha256 -r | cut -d ' ' -f1)
    cap=$(printf '%s' "$cap" | jq -c --arg digest "sha256:$digest" '.+{contractDigest:$digest}')
    capabilities=$(printf '%s' "$capabilities" | jq -c --argjson cap "$cap" '.+[$cap]')
  done
  canonical=$(jq -cn --argjson caps "$capabilities" '{schemaVersion:1,providerId:"grant-management",generation:1,capabilities:$caps}')
  digest=$(printf '%s' "$canonical" | openssl dgst -sha256 -r | cut -d ' ' -f1)
  jq -cn --argjson caps "$capabilities" --arg digest "sha256:$digest" '{schemaVersion:1,generation:1,expectedLatestGeneration:null,capabilities:$caps,catalogDigest:$digest}'
}

# ---------- full catalog from Grant CLI ----------
build_full_catalog() {
  if [ -z "${GRANT_SOURCE_DIR:-}" ]; then
    echo "error: --full requires GRANT_SOURCE_DIR to point to the Grant source tree" >&2
    echo "       export GRANT_SOURCE_DIR=/path/to/grant-management-exposure" >&2
    exit 1
  fi
  if [ ! -d "$GRANT_SOURCE_DIR/cmd/grant-management-catalog" ]; then
    echo "error: GRANT_SOURCE_DIR ($GRANT_SOURCE_DIR) does not contain cmd/grant-management-catalog" >&2
    exit 1
  fi
  shift
  cd "$GRANT_SOURCE_DIR"
  exec go run ./cmd/grant-management-catalog "$@"
}

# ---------- main ----------
case "${1:-}" in
  --full)
    build_full_catalog "$@"
    ;;
  --help|-h)
    printf 'usage: %s [--full]\n' "$(basename "$0")" >&2
    exit 1
    ;;
  *)
    build_group_fixture
    ;;
esac
