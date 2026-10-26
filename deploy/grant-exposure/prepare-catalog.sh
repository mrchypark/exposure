#!/bin/sh
# Run the maintained CLI from an already clean, exact released Grant checkout.
# No checkout, build/push of a runtime image, database or cluster operation.
set -eu
[ "$#" -eq 3 ] || { echo 'usage: prepare-catalog.sh config.json released-grant-source new-output-dir' >&2; exit 2; }
config=$1; source=$2; output=$3
revision=$(jq -er '.grantRevision|select(test("^[0-9a-f]{40}$"))' "$config")
tag=$(jq -er '.grantRelease|select(test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))' "$config")
[ "$(git -C "$source" rev-parse HEAD)" = "$revision" ] || { echo 'Grant source is not the release revision' >&2; exit 1; }
[ -z "$(git -C "$source" status --porcelain=v1)" ] || { echo 'Grant generator source must be clean' >&2; exit 1; }
gh release view "$tag" --repo mrchypark/grant --json isDraft,isPrerelease | jq -e '.isDraft==false and .isPrerelease==false' >/dev/null
[ "$(gh api "repos/mrchypark/grant/commits/$tag" --jq .sha)" = "$revision" ] || exit 1
[ ! -e "$output" ] || { echo 'refusing existing output path' >&2; exit 1; }
umask 077
mkdir "$output"
output=$(CDPATH= cd -- "$output" && pwd)
(cd "$source" && go run ./cmd/grant-management-catalog -generation 1) > "$output/catalog.json"
(cd "$source" && go run ./cmd/grant-management-catalog -generation 1 -actions) > "$output/actions.json"
jq -e '.schemaVersion==1 and .generation==1 and .expectedLatestGeneration==null and (.capabilities|length>0)' "$output/catalog.json" >/dev/null
jq -e 'type=="array" and length>0' "$output/actions.json" >/dev/null
printf '%s\n' "PASS: catalog/actions generated from exact released source $revision"
