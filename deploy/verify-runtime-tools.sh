#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dockerfile=${1:-"$root/Dockerfile"}

verify() {
  file=$1
  grep -F -- './cmd/exposure-validate-run' "$file" >/dev/null &&
  grep -F -- '/out/exposure-validate-run' "$file" >/dev/null &&
  grep -F -- '/usr/local/bin/exposure-validate-run' "$file" >/dev/null &&
  grep -F -- 'ENTRYPOINT ["/exposure"]' "$file" >/dev/null
}

verify "$dockerfile"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/exposure-runtime-tools.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

sed '/exposure-validate-run/d' "$dockerfile" >"$tmp/missing-tool.Dockerfile"
if verify "$tmp/missing-tool.Dockerfile" 2>/dev/null; then
  echo 'runtime tool verifier accepted a missing validator' >&2
  exit 1
fi

sed 's|ENTRYPOINT \["/exposure"\]|ENTRYPOINT ["/usr/local/bin/exposure-validate-run"]|' \
  "$dockerfile" >"$tmp/changed-entrypoint.Dockerfile"
if verify "$tmp/changed-entrypoint.Dockerfile" 2>/dev/null; then
  echo 'runtime tool verifier accepted a changed server entrypoint' >&2
  exit 1
fi

printf '%s\n' 'Exposure runtime tool packaging contract verified'
