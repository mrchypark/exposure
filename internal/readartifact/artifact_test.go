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

func TestRemovedServiceSpecificArtifactsFailClosed(t *testing.T) {
	input := map[string]any{"artifactType": artifactType, "exposureId": "patch-data-plant-profile", "exposureVersion": 1, "source": map[string]any{"kind": "patch-data.plant.v1", "operation": "plant.get"}, "projectionPointers": []string{"/id", "/name", "/updated"}}
	input["artifactDigest"] = digest(t, input)
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(body); err == nil {
		t.Fatal("removed service-specific artifact accepted")
	}
}
