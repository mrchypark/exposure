#!/bin/sh
# Render only; input files contain no credentials. Does not contact Kubernetes.
set -eu
[ "$#" -eq 2 ] || { echo 'usage: render.sh config.json released-grant-catalog.json' >&2; exit 2; }
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
jq -e '
  (.grantImage | test("^ghcr.io/mrchypark/grant@sha256:[0-9a-f]{64}$")) and
  (.grantRelease | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$")) and
  (.grantRevision | test("^[0-9a-f]{40}$")) and
  ([.clusterID,.nodeID,.organizationID,.applicationID,.pepClientID] | all(test("^grant-exposure-v020[-a-z0-9]*$"))) and
  ([.issuer,.resource] | all(test("^https://[^[:space:]]+$"))) and
  ([.introspectionClientID,.expectedClientID,.requiredScopes] | all(type=="string" and length>0))
' "$1" >/dev/null
jq -e '.schemaVersion==1 and .generation==1 and .expectedLatestGeneration==null and (.catalogDigest|test("^sha256:[0-9a-f]{64}$")) and (.capabilities|length>0)' "$2" >/dev/null
jq --slurpfile conf "$1" --slurpfile catalog "$2" '
  $conf[0] as $c | $catalog[0] as $cat |
  .items[0].data={
    GRANT_BIND_ADDR:"0.0.0.0:8080",GRANT_AUTH_PROVIDER:"goauthy",SSL_CERT_FILE:"/etc/grant-goauthy/ca.pem",
    GRANT_RUNTIME_MODE:"embedded",GRANT_LOCAL_NODE_ROLE:"voter",GRANT_READ_CONSISTENCY:"strong",
    GRANT_DATA_DIR:"/data/rhiza",GRANT_BACKUP_DIR:"/data/backups",
    GRANT_NODE_ID:$c.nodeID,GRANT_CLUSTER_ID:$c.clusterID,GRANT_PEER_ADDR:"",
    GRANT_RHIZA_CONFIG_JSON:"{\"Local\":true}",
    GRANT_BOOTSTRAP_USER_ID:$c.organizationID,GRANT_BOOTSTRAP_USER_NAME:"Grant Exposure isolated development",
    GRANT_MANAGEMENT_ORGANIZATION_ID:$c.organizationID,GRANT_MANAGEMENT_APPLICATION_ID:$c.applicationID,
    GRANT_HTTP_CAPABILITY_PEP_CLIENT_ID:$c.pepClientID,
    GRANT_GOAUTHY_ISSUER:$c.issuer,GRANT_GOAUTHY_INTROSPECTION_CLIENT_ID:$c.introspectionClientID,
    GRANT_GOAUTHY_EXPECTED_CLIENT_ID:$c.expectedClientID,GRANT_GOAUTHY_RESOURCE:$c.resource,
    GRANT_GOAUTHY_APPLICATION_ID:$c.applicationID,GRANT_GOAUTHY_REQUIRED_SCOPES:$c.requiredScopes
  } |
  .items[1].data={
    EXPOSURE_PROXY_ENABLED:"true",EXPOSURE_DATA_ADDR:":8082",EXPOSURE_ADMIN_ADDR:":8083",
    EXPOSURE_PROVIDER_ID:"grant-management",EXPOSURE_PEP_CLIENT_ID:$c.pepClientID,
    EXPOSURE_PROVIDER_ORIGIN:"http://127.0.0.1:8080",EXPOSURE_GRANT_LEARNER_URL:"http://127.0.0.1:8080",
    EXPOSURE_PROVIDER_AUTHORIZATION_MODE:"forward-user",EXPOSURE_CREDENTIAL_MODE:"goauthy",
    EXPOSURE_GOAUTHY_ISSUER:$c.issuer,EXPOSURE_GOAUTHY_APPLICATION_ID:$c.applicationID,
    EXPOSURE_EXPECTED_CATALOG_DIGEST:$cat.catalogDigest
  } |
  .items[2].spec.template.metadata.annotations={"deployment.exposure.io/grant-release":$c.grantRelease,"deployment.exposure.io/grant-revision":$c.grantRevision,"deployment.exposure.io/catalog-digest":$cat.catalogDigest} |
  .items[2].spec.template.spec.containers[0].image=$c.grantImage
' "$root/runtime.template.json"
