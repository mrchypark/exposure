package readartifact

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mrchypark/exposure/internal/contracts"
)

func artifactJSON(t *testing.T, pointers []string) []byte {
	t.Helper()
	sourceValue := composSource{Namespace: "n", ObjectType: "object", SchemaDigest: digest(t, map[string]any{"schema": 1})}
	input := struct {
		ArtifactType       string       `json:"artifactType"`
		ExposureID         string       `json:"exposureId"`
		ExposureVersion    int64        `json:"exposureVersion"`
		Source             composSource `json:"source"`
		ProjectionPointers []string     `json:"projectionPointers"`
	}{artifactType, "exposure", 1, sourceValue, pointers}
	d := digest(t, input)
	sourceJSON, err := json.Marshal(sourceValue)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(artifactWire{artifactType, "exposure", 1, d, sourceJSON, pointers})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func patchDataArtifactJSON(t *testing.T, exposureID, operation string, pointers []string) []byte {
	t.Helper()
	sourceValue := patchDataSource{Kind: SourcePatchDataPlant, Operation: operation}
	input := struct {
		ArtifactType       string          `json:"artifactType"`
		ExposureID         string          `json:"exposureId"`
		ExposureVersion    int64           `json:"exposureVersion"`
		Source             patchDataSource `json:"source"`
		ProjectionPointers []string        `json:"projectionPointers"`
	}{artifactType, exposureID, 1, sourceValue, pointers}
	d := digest(t, input)
	sourceJSON, err := json.Marshal(sourceValue)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(artifactWire{artifactType, exposureID, 1, d, sourceJSON, pointers})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPatchDataPlantArtifactIsClosed(t *testing.T) {
	valid := patchDataArtifactJSON(t, patchDataExposureID, patchDataOperation, []string{"/id", "/name", "/updated"})
	a, err := Parse(valid)
	if err != nil || a.SourceKind() != SourcePatchDataPlant || !a.ValidResourceID("4n5mdid6ccx1bh6") {
		t.Fatalf("artifact=%#v err=%v", a, err)
	}
	if a.ValidResourceID("4n5mdid6ccx1bh") || a.ValidResourceID("4N5MDID6CCX1BH6") || a.ValidResourceID("../../plants") {
		t.Fatal("invalid Patch Data resource ID accepted")
	}
	descriptor, ok := a.Operation()
	if !ok || descriptor.ID != "plant.get" || descriptor.Version != 1 || descriptor.ProviderID != "patch-data" || descriptor.ActionID != "patch-data.plant.read" || descriptor.ResourceType != "plant" {
		t.Fatalf("operation=%#v ok=%v", descriptor, ok)
	}
	for _, body := range [][]byte{
		patchDataArtifactJSON(t, "other", patchDataOperation, []string{"/id", "/name", "/updated"}),
		patchDataArtifactJSON(t, patchDataExposureID, "records.get", []string{"/id", "/name", "/updated"}),
		patchDataArtifactJSON(t, patchDataExposureID, patchDataOperation, []string{"/id", "/metadata", "/name", "/updated"}),
	} {
		if _, err := Parse(body); err == nil {
			t.Fatalf("unsafe Patch Data artifact accepted: %s", body)
		}
	}
}

func TestPatchDataArtifactRejectsLegacyOrBackendSelectorsEvenWithMatchingDigest(t *testing.T) {
	for _, selector := range []string{"providerId", "actionId", "resourceType", "method", "path", "query", "fields", "filter", "sort", "expand", "view", "mask"} {
		source := map[string]any{"kind": SourcePatchDataPlant, "operation": patchDataOperation, selector: "attacker-selected"}
		input := map[string]any{
			"artifactType": artifactType, "exposureId": patchDataExposureID, "exposureVersion": 1,
			"source": source, "projectionPointers": []string{"/id", "/name", "/updated"},
		}
		input["artifactDigest"] = digest(t, input)
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(body); err == nil {
			t.Fatalf("selector %q accepted: %s", selector, body)
		}
	}
}
func digest(t *testing.T, value any) string {
	t.Helper()
	d, err := contracts.Digest(value)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestParseDigestStabilityAndTamper(t *testing.T) {
	b := artifactJSON(t, []string{"/name", "/profile/email"})
	a, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(); err != nil || a.ExposureID() != "exposure" {
		t.Fatalf("artifact=%#v err=%v", a, err)
	}
	tampered := strings.Replace(string(b), `"exposureVersion":1`, `"exposureVersion":2`, 1)
	if _, err := Parse([]byte(tampered)); err == nil {
		t.Fatal("tampered artifact accepted")
	}
}

func TestParseRejectsClosedAndDuplicateJSON(t *testing.T) {
	valid := string(artifactJSON(t, []string{"/name"}))
	for _, body := range []string{
		strings.Replace(valid, `"artifactType"`, `"unknown":true,"artifactType"`, 1),
		strings.Replace(valid, `"namespace":"n"`, `"namespace":"n","namespace":"other"`, 1),
		valid + ` {}`,
	} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}

func TestPointerValidation(t *testing.T) {
	for _, pointers := range [][]string{
		nil, {""}, {"name"}, {"/bad~2"}, {"/z", "/a"}, {"/a", "/a"}, {"/a", "/a/b"},
	} {
		if _, err := Parse(artifactJSON(t, pointers)); err == nil {
			t.Fatalf("accepted pointers %#v", pointers)
		}
	}
}

func TestProjectFixedProjection(t *testing.T) {
	a, err := Parse(artifactJSON(t, []string{"/a~1b", "/profile/email"}))
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{"a/b": "escaped", "profile": map[string]any{"email": "a@example.test", "secret": "hidden"}, "secret": "hidden"}
	got, err := a.Project(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got["a/b"] != "escaped" || got["profile"].(map[string]any)["email"] != "a@example.test" {
		t.Fatalf("projection=%#v", got)
	}
	if _, ok := got["secret"]; ok {
		t.Fatal("secret leaked")
	}
	if _, ok := got["profile"].(map[string]any)["secret"]; ok {
		t.Fatal("nested secret leaked")
	}
	for _, raw := range []map[string]any{{"profile": map[string]any{}}, {"a/b": "x", "profile": []any{map[string]any{"email": "x"}}}} {
		if got, err := a.Project(raw); err == nil || got != nil {
			t.Fatalf("partial output=%#v err=%v", got, err)
		}
	}
}

func TestProjectRejectsContainerLeaves(t *testing.T) {
	for _, tc := range []struct {
		pointer string
		raw     map[string]any
	}{
		{"/profile", map[string]any{"profile": map[string]any{"email": "a@example.test", "secret": "hidden"}}},
		{"/tags", map[string]any{"tags": []any{"internal", "secret"}}},
	} {
		a, err := Parse(artifactJSON(t, []string{tc.pointer}))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := a.Project(tc.raw); err == nil || got != nil {
			t.Fatalf("pointer %s output=%#v err=%v", tc.pointer, got, err)
		}
	}
}
