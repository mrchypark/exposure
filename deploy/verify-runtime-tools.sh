#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dockerfile=${1:-"$root/Dockerfile"}
verify() {
  file=$1
  grep -Fx 'RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='"'"'-s -w'"'"' -o /out/exposure ./cmd/exposure' "$file" >/dev/null &&
  grep -Fx 'COPY --from=build /out/exposure /exposure' "$file" >/dev/null &&
  grep -Fx 'ENTRYPOINT ["/exposure"]' "$file" >/dev/null &&
  ! grep -F 'exposure-validate-run' "$file" >/dev/null
}
verify "$dockerfile"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/exposure-runtime-tools.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
for pattern in '^RUN CGO_ENABLED=' '^COPY --from=build /out/exposure ' '^ENTRYPOINT '; do
  sed "\|$pattern|d" "$dockerfile" > "$tmp/missing.Dockerfile"
  if verify "$tmp/missing.Dockerfile"; then
    echo "packaging check accepted missing server contract: $pattern" >&2
    exit 1
  fi
done
printf '%s\n' 'Exposure server packaging contract verified'
