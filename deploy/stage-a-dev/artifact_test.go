package stageadeploy

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/mrchypark/exposure/internal/readartifact"
)

const stageAArtifact = `{"artifactType":"exposure.read.v1","exposureId":"customer-profile","exposureVersion":1,"artifactDigest":"sha256:f03f2684ba9cf86c0fb5c3aa915eddd5f3f2523f2df4ea43014205634f854585","source":{"namespace":"wks_default","objectType":"otp_builtin_company_wks_default","schemaDigest":"sha256:ff37152682230e96eee7376ef415e7357d88846ea34bf78bb3555a2630371cf7"},"projectionPointers":["/domain","/employee_count"]}`
const stageAArtifactPayloadJSON = "[" + stageAArtifact + "]\n"
const stageAHTTPRoute = `apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: exposure-stage-a
  namespace: grant-compos-exposure-v1
spec:
  parentRefs:
    - name: dev-gateway
      namespace: haproxy-gateway-system
      port: 443
      sectionName: https-exposure-stage-a-dev-conalog-com
  hostnames:
    - exposure-stage-a.dev.conalog.com
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: exposure
          port: 80`

func TestStageAArtifactIsImmutableAndProjectsOnlyApprovedFields(t *testing.T) {
	b, err := os.ReadFile("stage-a.yaml")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := stageAArtifactPayload(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != stageAArtifactPayloadJSON {
		t.Fatalf("stage-a artifact payload=%q want=%q", payload, stageAArtifactPayloadJSON)
	}
	a, err := readartifact.Parse([]byte(stageAArtifact))
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.Project(map[string]any{"domain": "stage-a.example", "employee_count": float64(7), "secret": "must-not-appear"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"domain": "stage-a.example", "employee_count": float64(7)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projected=%#v want=%#v", got, want)
	}
}

func TestStageAArtifactPayloadRejectsStructuralAndDecoyVariants(t *testing.T) {
	b, err := os.ReadFile("stage-a.yaml")
	if err != nil {
		t.Fatal(err)
	}
	wrong := strings.Replace(stageAArtifact, "customer-profile", "wrong-profile", 1)
	decoy := []byte(strings.Replace(string(b), stageAArtifact, wrong, 1) + "\n# " + stageAArtifact)
	payload, err := stageAArtifactPayload(decoy)
	if err != nil || string(payload) == stageAArtifactPayloadJSON {
		t.Fatalf("decoy payload=%q err=%v", payload, err)
	}
	for _, mutated := range [][]byte{
		[]byte(strings.Replace(string(b), "  name: exposure-read-artifacts-compos-v2", "  name: other-artifacts", 1)),
		[]byte(strings.Replace(string(b), "  name: rauthy-bootstrap-renderer", "  name: exposure-read-artifacts-compos-v2", 1)),
		[]byte(strings.Replace(string(b), "  read-artifacts.json: |", "  read-artifacts.json: |\n  read-artifacts.json: |", 1)),
		[]byte(strings.Replace(string(b), "  read-artifacts.json: |", "  unrelated: value\nmisplaced:\n  read-artifacts.json: |", 1)),
	} {
		if _, err := stageAArtifactPayload(mutated); err == nil {
			t.Fatal("structural artifact mutation was accepted")
		}
	}
}

func TestStageAUsesVersionedImmutableArtifactConfigMap(t *testing.T) {
	b, err := os.ReadFile("stage-a.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(b, []byte("exposure-read-artifacts-compos-v2")) != 2 || !bytes.Contains(b, []byte("immutable: true")) || bytes.Contains(b, []byte("name: exposure-read-artifacts\n")) || bytes.Contains(b, []byte("configMap: {name: exposure-read-artifacts}")) {
		t.Fatal("artifact ConfigMap name is not versioned consistently")
	}
}

func TestStageAPodRequiresControlledDeleteRecreate(t *testing.T) {
	b, err := os.ReadFile("stage-a.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(b, []byte("stage-a.conalog.io/replacement-policy: delete-recreate")) != 1 {
		t.Fatal("exact Pod replacement policy annotation missing")
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"plain `kubectl apply` over the live", "phase 1 contains every document", "phase 2 contains only that exact `HTTPRoute`", "while the public route remains absent", "Only after that PASS", "remove the route first", "Restore the prior route only after", "only Pod `grant-compos-exposure-stage-a`", "no force", "fresh START"} {
		if !bytes.Contains(readme, []byte(required)) {
			t.Fatalf("controlled replacement contract missing: %s", required)
		}
	}
}

func TestStageAManifestContainsNoCredentialBearingSecretBody(t *testing.T) {
	b, err := os.ReadFile("stage-a.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"kind: Secret", "stringData:", "kubectl.kubernetes.io/last-applied-configuration"} {
		if bytes.Contains(b, []byte(forbidden)) {
			t.Fatalf("credential-bearing manifest content present: %s", forbidden)
		}
	}
	for _, required := range []string{"secretName: rauthy-config", "key: config.toml", "key: clients.json", "key: api_keys.json"} {
		if !bytes.Contains(b, []byte(required)) {
			t.Fatalf("external Rauthy Secret reference missing: %s", required)
		}
	}
}

func TestStageAExposureUsesOnlyInternalPlainHTTP(t *testing.T) {
	b, err := os.ReadFile("stage-a.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"exposure-tls", "EXPOSURE_SERVER_CERT", "EXPOSURE_SERVER_KEY"} {
		if bytes.Contains(b, []byte(forbidden)) {
			t.Fatalf("removed Exposure TLS contract present: %s", forbidden)
		}
	}
	exposureStart := bytes.Index(b, []byte("    - name: exposure\n"))
	serviceStart := bytes.LastIndex(b, []byte("kind: Service\n"))
	if exposureStart < 0 || serviceStart < 0 || serviceStart <= exposureStart {
		t.Fatal("Exposure container or Service missing")
	}
	exposureEnd := bytes.Index(b[exposureStart:], []byte("\n---\n"))
	serviceEnd := bytes.Index(b[serviceStart:], []byte("\n---\n"))
	if exposureEnd < 0 || serviceEnd < 0 {
		t.Fatal("Exposure container or Service document boundary missing")
	}
	exposureContract := append(append([]byte(nil), b[exposureStart:exposureStart+exposureEnd]...), b[serviceStart:serviceStart+serviceEnd]...)
	for _, forbidden := range []string{"port: https", "scheme: HTTPS", "containerPort: 8443", "port: 443"} {
		if bytes.Contains(exposureContract, []byte(forbidden)) {
			t.Fatalf("removed Exposure TLS contract present: %s", forbidden)
		}
	}
	for _, required := range []string{
		`{name: EXPOSURE_ADDR, value: ":8082"}`,
		`{name: http, containerPort: 8082, protocol: TCP}`,
		`httpGet: {path: /healthz, port: http, scheme: HTTP}`,
		`httpGet: {path: /readyz, port: http, scheme: HTTP}`,
		`{name: http, port: 80, targetPort: http, protocol: TCP}`,
	} {
		if !bytes.Contains(b, []byte(required)) {
			t.Fatalf("internal HTTP contract missing: %s", required)
		}
	}
}

func TestStageAHTTPRouteHasExactClosedShape(t *testing.T) {
	b, err := os.ReadFile("stage-a.yaml")
	if err != nil {
		t.Fatal(err)
	}
	documents := bytes.Split(bytes.TrimSpace(b), []byte("\n---\n"))
	if len(documents) != 7 {
		t.Fatalf("document count=%d want=7", len(documents))
	}
	if got := string(documents[6]); got != stageAHTTPRoute {
		t.Fatalf("HTTPRoute document mismatch:\n%s", got)
	}
	for _, forbiddenKind := range []string{"Gateway", "Ingress", "ReferenceGrant", "Certificate", "Secret"} {
		if bytes.Contains(b, []byte("kind: "+forbiddenKind+"\n")) {
			t.Fatalf("forbidden resource kind present: %s", forbiddenKind)
		}
	}
}

func stageAArtifactPayload(manifest []byte) ([]byte, error) {
	var payload []byte
	targets, keys := 0, 0
	isConfig, inMetadata, target, inData, inPayload := false, false, false, false, false

	finishDocument := func() {
		if target {
			targets++
		}
		isConfig, inMetadata, target, inData, inPayload = false, false, false, false, false
	}
	for _, raw := range bytes.SplitAfter(manifest, []byte("\n")) {
		line := bytes.TrimSuffix(raw, []byte("\n"))
		if bytes.Equal(line, []byte("---")) {
			finishDocument()
			continue
		}
		if bytes.Equal(line, []byte("kind: ConfigMap")) {
			isConfig = true
			continue
		}
		if isConfig && bytes.Equal(line, []byte("metadata:")) {
			inMetadata = true
			continue
		}
		if inMetadata && bytes.Equal(line, []byte("  name: exposure-read-artifacts-compos-v2")) {
			target = true
			continue
		}
		if inMetadata && bytes.HasPrefix(line, []byte("  ")) && !bytes.HasPrefix(line, []byte("    ")) {
			inMetadata = false
		}
		if target && bytes.Equal(line, []byte("data:")) {
			inData = true
			continue
		}
		if inData && len(line) > 0 && line[0] != ' ' {
			inData = false
		}
		if inPayload && bytes.HasPrefix(line, []byte("    ")) {
			payload = append(payload, line[4:]...)
			payload = append(payload, '\n')
			continue
		}
		inPayload = false
		if target && inData && bytes.Equal(line, []byte("  read-artifacts.json: |")) {
			keys++
			inPayload = true
		}
	}
	finishDocument()
	if targets != 1 || keys != 1 {
		return nil, fmt.Errorf("versioned exposure-read-artifacts ConfigMap/key count: configs=%d keys=%d", targets, keys)
	}
	return payload, nil
}
