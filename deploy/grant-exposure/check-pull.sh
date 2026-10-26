#!/bin/sh
# Registry-only verification, no Docker login/config mutation and no K8s writes.
# All registry credentials and bearer replies stay in private temporary files.
set -eu
[ "$#" -ge 2 ] || { echo 'usage: check-pull.sh ghcr-only-dockerconfig.json pinned-image ...' >&2; exit 2; }
umask 077
scratch=$(mktemp -d "${TMPDIR:-/tmp}/grant-exposure-pull.XXXXXX")
cleanup() { for file in "$scratch"/*; do test ! -f "$file" || unlink "$file"; done; rmdir "$scratch"; }
trap cleanup EXIT HUP INT TERM
jq -e '(.auths|keys)==["ghcr.io"] and (.auths["ghcr.io"]|keys)==["auth"] and (.auths["ghcr.io"].auth|type=="string" and test("^[A-Za-z0-9+/]+={0,2}$"))' "$1" >/dev/null
jq -r '.auths["ghcr.io"].auth | "header = \"Authorization: Basic " + . + "\""' "$1" > "$scratch/basic.conf"
shift
for image in "$@"; do
  printf '%s\n' "$image" | grep -Eq '^ghcr.io/mrchypark/(grant|exposure)@sha256:[0-9a-f]{64}$' || exit 2
  package=${image#ghcr.io/mrchypark/}; package=${package%@*}
  digest=${image#*@}
  code=$(curl --noproxy '*' --proto '=https' --max-time 20 -sS --config "$scratch/basic.conf" -o "$scratch/token.json" -w '%{http_code}' "https://ghcr.io/token?service=ghcr.io&scope=repository:mrchypark/$package:pull")
  [ "$code" = 200 ] || { echo "$package registry pull authentication failed: HTTP $code" >&2; exit 1; }
  jq -er '(.token // .access_token) | select(type=="string" and test("^[A-Za-z0-9._~+/=-]+$")) | "header = \"Authorization: Bearer " + . + "\""' "$scratch/token.json" > "$scratch/bearer.conf"
  code=$(curl --noproxy '*' --proto '=https' --max-time 20 -sS --config "$scratch/bearer.conf" -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json' -D "$scratch/headers" -o "$scratch/manifest.json" -w '%{http_code}' "https://ghcr.io/v2/mrchypark/$package/manifests/$digest")
  [ "$code" = 200 ] || { echo "$package pinned manifest read failed: HTTP $code (refresh an approved read:packages credential; do not change scopes silently)" >&2; exit 1; }
  actual=$(awk 'tolower($1)=="docker-content-digest:" {gsub("\r","",$2); print $2}' "$scratch/headers")
  [ "$actual" = "$digest" ] || { echo "$package registry digest mismatch" >&2; exit 1; }
  printf '%s\n' "PASS: $image registry authentication and pinned manifest"
done
