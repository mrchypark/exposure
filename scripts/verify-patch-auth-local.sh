#!/bin/sh
# Fresh loopback-only servers; never uses existing data or a Kubernetes context.
set -eu
umask 077
ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
WORK=$(dirname "$ROOT")
PATCH_AUTH_DIR=${PATCH_AUTH_DIR:-$WORK/patch-auth}
PATCH_DATA_DIR=${PATCH_DATA_DIR:-$WORK/patch-data-auth-extraction}
GRANT_DIR=${GRANT_DIR:-$WORK/grant-porting-go}
: "${POCKETBASE_BIN:?set PocketBase 0.40.3 executable}"
case "$("$POCKETBASE_BIN" --version)" in
 'pocketbase version 0.40.3') ;;
 *) echo 'This fixture requires PocketBase 0.40.3; no resources started' >&2; exit 2 ;;
esac
AUTH_PORT=${AUTH_PORT:-18201}
DATA_PORT=${DATA_PORT:-18202}
GRANT_PORT=${GRANT_PORT:-18204}
FENCE_PORT=$((GRANT_PORT+1)); DATA_PDP_PORT=$((GRANT_PORT+2)); PEER_PORT=$((GRANT_PORT+6))
for tool in go curl jq openssl lsof; do command -v "$tool" >/dev/null; done
for port in "$AUTH_PORT" "$DATA_PORT" "$GRANT_PORT" "$FENCE_PORT" "$DATA_PDP_PORT" "$PEER_PORT" "$((AUTH_PORT+100))"; do
 case "$port" in ''|*[!0-9]*) echo 'invalid local port' >&2; exit 2;; esac
 if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 || lsof -nP -iUDP:"$port" >/dev/null 2>&1; then echo "local port $port occupied; nothing stopped" >&2; exit 2; fi
done
trial=$(mktemp -d "${TMPDIR:-/tmp}/patch-auth-e2e.XXXXXX")
auth_pid=; grant_pid=; data_pdp_pid=;
cleanup() {
 trap - EXIT HUP INT TERM
 for pid in "$data_pdp_pid" "$grant_pid" "$auth_pid"; do
  if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
 done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
printf 'Local verification output: %s\n' "$trial"
PATCH_DATA_DIR="$PATCH_DATA_DIR" AUTH_PORT="$AUTH_PORT" DATA_PORT="$DATA_PORT" KEEP_RUNNING=1 POCKETBASE_BIN="$POCKETBASE_BIN" sh "$PATCH_AUTH_DIR/scripts/verify-local.sh" >"$trial/pocketbase.log" 2>&1 & auth_pid=$!
attempt=0
while :; do
 kill -0 "$auth_pid" 2>/dev/null || { echo "PocketBase fixture failed; inspect $trial/pocketbase.log" >&2; exit 1; }
 pb_dir=$(sed -n 's/^PASS:.*Fixture: //p' "$trial/pocketbase.log" | tail -1)
 if [ -n "$pb_dir" ] && [ -r "$pb_dir/integration.json" ]; then break; fi
 attempt=$((attempt+1)); [ "$attempt" -lt 90 ] || { echo 'PocketBase fixture timed out' >&2; exit 1; }; sleep 1
done
echo 'PocketBase auth and data fixtures verified; building local servers.'
(cd "$GRANT_DIR" && CGO_ENABLED=0 go build -o "$trial/grant" ./cmd/grant)
for name in master app voter sync fence runtime; do openssl rand -hex 24 >"$trial/$name.key"; done
jq -cn --arg peer "quic://127.0.0.1:$PEER_PORT" --rawfile token "$trial/voter.key" '[{node_id:"single",peer_url:$peer,token:($token|rtrimstr("\n"))}]' >"$trial/members.json"
jq -c '{ClusterID:"patch-auth-local-fixture",Members:.}' "$trial/members.json" | sh "$GRANT_DIR/scripts/replica-members" >"$trial/replica-members.json"
jq -cn --rawfile admin "$trial/sync.key" '{AdminToken:($admin|rtrimstr("\n"))}' >"$trial/voter-config.json"
jq -cn --rawfile admin "$trial/sync.key" --slurpfile members "$trial/replica-members.json" '{AdminToken:($admin|rtrimstr("\n")),Members:$members[0]}' >"$trial/replica-config.json"
# The script execs the binary, so captured PIDs are the actual server PIDs.
cat >"$trial/start-grant.sh" <<'LAUNCH'
#!/bin/sh
set -eu
trial=$1; auth_port=$2; fence_port=$3; peer_port=$4; node=$5; port=$6; app=$7; role=$8
export GRANT_BIND_ADDR="127.0.0.1:$port" GRANT_DATA_DIR="$trial/$node" GRANT_BACKUP_DIR="$trial/backups"
export GRANT_MASTER_KEY="$(cat "$trial/master.key")" GRANT_APP_AUTH_KEY="$(cat "$trial/app.key")"
export GRANT_AUTH_PROVIDER=pocketbase GRANT_POCKETBASE_BASE_URL="http://127.0.0.1:$auth_port" GRANT_POCKETBASE_COLLECTION=users GRANT_POCKETBASE_APPLICATION_ID="$app" GRANT_HTTP_CAPABILITY_PEP_APPLICATION_ID="$app"
export GRANT_CLUSTER_ID=patch-auth-local-fixture GRANT_NODE_ID="$node" GRANT_READ_CONSISTENCY=strong GRANT_RUNTIME_MODE=embedded GRANT_LOCAL_NODE_ROLE="$role"
export RHIZA_OBJSTORE_PROVIDER=filesystem RHIZA_OBJSTORE_DIR="$trial/objects" GRANT_READ_FENCE_KEY="$(cat "$trial/fence.key")"
if [ "$role" = voter ]; then
 export GRANT_PEER_ADDR="127.0.0.1:$peer_port" GRANT_CLUSTER_MEMBERS="$(cat "$trial/members.json")" GRANT_RHIZA_CONFIG_JSON="$(cat "$trial/voter-config.json")"
 export GRANT_RUNTIME_BIND_ADDR="127.0.0.1:$fence_port" GRANT_REMOTE_API_SECRET="$(cat "$trial/runtime.key")"
else
 export GRANT_RHIZA_REPLICA_CONFIG_JSON="$(cat "$trial/replica-config.json")" GRANT_REMOTE_NODES="http://127.0.0.1:$fence_port"
fi
exec "$trial/grant"
LAUNCH
ready() {
 pid=$1; origin=$2; path=$3; attempt=0
 while :; do
  kill -0 "$pid" 2>/dev/null || { echo "Owned server exited: $origin; logs in $trial" >&2; exit 1; }
  if curl --max-time 5 -fsS "$origin$path" >/dev/null 2>&1; then break; fi
  attempt=$((attempt+1)); [ "$attempt" -lt 40 ] || { echo "Readiness timed out: $origin" >&2; exit 1; }; sleep 1
 done
}
env -i PATH="$PATH" HOME="$HOME" sh "$trial/start-grant.sh" "$trial" "$AUTH_PORT" "$FENCE_PORT" "$PEER_PORT" single "$GRANT_PORT" synthetic-management-app voter >"$trial/grant.log" 2>&1 & grant_pid=$!
ready "$grant_pid" "http://127.0.0.1:$GRANT_PORT" /readyz
export PATCH_AUTH_FIXTURE="$pb_dir/integration.json" GRANT_URL="http://127.0.0.1:$GRANT_PORT" GRANT_MASTER_KEY_FILE="$trial/master.key" GRANT_APP_KEY_FILE="$trial/app.key"
seed_config=$(sh "$ROOT/scripts/seed-grant-local.sh")
echo 'Grant public API seed completed; starting one authority replica.'
env -i PATH="$PATH" HOME="$HOME" sh "$trial/start-grant.sh" "$trial" "$AUTH_PORT" "$FENCE_PORT" "$PEER_PORT" data-pdp "$DATA_PDP_PORT" synthetic-app learner >"$trial/data-pdp.log" 2>&1 & data_pdp_pid=$!
ready "$data_pdp_pid" "http://127.0.0.1:$DATA_PDP_PORT" /readyz
echo 'The data-colocated authority replica is ready.'
echo 'Stock PocketBase is ready; running two-Exposure end-to-end checks.'
jq --arg masterFile "$trial/master.key" --arg voter "$GRANT_URL" --arg pdp "http://127.0.0.1:$DATA_PDP_PORT" --arg management "$GRANT_URL" --slurpfile catalog "$ROOT/scripts/testdata/grant-management-capability.json" '.+{GrantMasterKeyFile:$masterFile,PrivateDataOrigin:.DataOrigin,VoterURL:$voter,GrantURL:$pdp,ManagementPDPURL:$management,ManagementApplicationID:"synthetic-management-app",ManagementPEPClientID:"synthetic-management-pep",ManagementCatalogDigest:$catalog[0].catalogDigest}' "$seed_config" >"$trial/exposure-integration.json"
export PATCH_AUTH_E2E_CONFIG="$trial/exposure-integration.json"
printf '%s\n' "$PATCH_AUTH_E2E_CONFIG" >"$trial/e2e-config-path"
(cd "$ROOT" && go test ./internal/capability -run '^(TestPocketBaseLocalEndToEnd|TestPocketBaseGrantScopedList|TestPocketBaseCatalogNativeTransport)$' -count=1 -v)
(cd "$GRANT_DIR" && go run ./cmd/patch-data-catalog -read-only) >"$trial/patch-data-read-catalog.json"
(cd "$GRANT_DIR" && go run ./cmd/patch-data-catalog -read-only -actions) >"$trial/patch-data-read-actions.json"
export PATCH_DATA_READ_CATALOG="$trial/patch-data-read-catalog.json"
export PATCH_DATA_READ_ACTIONS="$trial/patch-data-read-actions.json"
(cd "$ROOT" && go test ./internal/capability -run '^TestPocketBaseRemainingCollections$' -count=1 -v)
(cd "$GRANT_DIR" && go run ./cmd/patch-data-catalog) >"$trial/patch-data-native-catalog.json"
(cd "$GRANT_DIR" && go run ./cmd/patch-data-catalog -actions) >"$trial/patch-data-native-actions.json"
export PATCH_DATA_NATIVE_CATALOG="$trial/patch-data-native-catalog.json"
export PATCH_DATA_NATIVE_ACTIONS="$trial/patch-data-native-actions.json"
(cd "$ROOT" && go test ./internal/capability -run '^TestPocketBaseMutations$' -count=1 -v)

# No writer credential exists on learners. The fence key cannot execute SQL.
printf 'Authorization: Bearer %s\nContent-Type: application/json\n' "$(cat "$trial/fence.key")" >"$trial/fence-headers"
status=$(curl --max-time 5 -sS -o "$trial/fence-write-response" -w '%{http_code}' --header "@$trial/fence-headers" -d '{"SQL":"SELECT 1"}' "http://127.0.0.1:$FENCE_PORT/sql/execute")
[ "$status" = 401 ] || { echo 'Read-fence credential gained runtime write access' >&2; exit 1; }
if [ "${KEEP_RUNNING:-0}" = 1 ]; then
 echo 'Keeping fixture servers until Ctrl-C; Exposure test listeners have closed.'
 wait
else
 kill "$grant_pid"; wait "$grant_pid" || :; grant_pid=
 status=$(curl --max-time 5 -sS -o "$trial/fence-down.json" -w '%{http_code}' "http://127.0.0.1:$DATA_PDP_PORT/readyz")
 [ "$status" = 503 ] || { echo "Data learner did not fail closed after voter stop: status$status" >&2; exit 1; }
 status=$(curl --max-time 5 -s -o "$trial/management-down.json" -w '%{http_code}' "$GRANT_URL/readyz" || :)
 [ "$status" = 000 ] || { echo 'Stopped management voter is unexpectedly reachable' >&2; exit 1; }
 echo 'PASS: one authority replica fails closed without voter fence; fence credentials cannot write.'
fi
printf 'PASS: fresh auth/data, one authority replica, two Exposure instances, management CRUD. Evidence: %s\n' "$trial"
