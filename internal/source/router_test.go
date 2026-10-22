package source

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/readartifact"
)

type composFake struct{ request contracts.SourceReadRequest }

func (f *composFake) ReadObject(_ context.Context, request contracts.SourceReadRequest) (contracts.SourceReadResponse, error) {
	f.request = request
	return contracts.SourceReadResponse{Namespace: request.Namespace, ObjectType: request.ObjectType, SchemaDigest: request.SchemaDigest, ResourceID: request.ResourceID, ResourceVersion: 2, RawResource: map[string]any{"x": "y"}}, nil
}

type patchFake struct{ calls int }

func (f *patchFake) ReadPlant(_ context.Context, resourceID string) (contracts.SourceObject, error) {
	f.calls++
	return contracts.SourceObject{Kind: readartifact.SourcePatchDataPlant, ResourceID: resourceID, SourceRevision: "revision", RawResource: map[string]any{"id": resourceID}}, nil
}

func TestRouterDoesNotForwardBearerToCompos(t *testing.T) {
	artifact := parseArtifact(t, composArtifact(t))
	compos, patch := &composFake{}, &patchFake{}
	out, err := New(compos, patch).ReadObject(context.Background(), artifact, "resource")
	if err != nil || compos.request.ResourceID != "resource" || patch.calls != 0 || out.ResourceVersion == nil || *out.ResourceVersion != 2 {
		t.Fatalf("out=%#v compos=%#v patch=%#v err=%v", out, compos, patch, err)
	}
}

func TestRouterNeverForwardsUserBearerToPatchData(t *testing.T) {
	artifact := parseArtifact(t, patchArtifact(t))
	compos, patch := &composFake{}, &patchFake{}
	out, err := New(compos, patch).ReadObject(context.Background(), artifact, "4n5mdid6ccx1bh6")
	if err != nil || patch.calls != 1 || compos.request.ResourceID != "" || out.SourceRevision != "revision" {
		t.Fatalf("out=%#v compos=%#v patch=%#v err=%v", out, compos, patch, err)
	}
}

func parseArtifact(t *testing.T, body []byte) readartifact.Artifact {
	t.Helper()
	a, err := readartifact.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func composArtifact(t *testing.T) []byte {
	source := map[string]any{"namespace": "n", "objectType": "o", "schemaDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	return artifactJSON(t, "exp", source, []string{"/x"})
}

func patchArtifact(t *testing.T) []byte {
	source := map[string]any{"kind": readartifact.SourcePatchDataPlant, "operation": "plant.get"}
	return artifactJSON(t, "patch-data-plant-profile", source, []string{"/id", "/name", "/updated"})
}

func artifactJSON(t *testing.T, exposureID string, source map[string]any, pointers []string) []byte {
	t.Helper()
	input := map[string]any{"artifactType": "exposure.read.v1", "exposureId": exposureID, "exposureVersion": 1, "source": source, "projectionPointers": pointers}
	digest, err := contracts.Digest(input)
	if err != nil {
		t.Fatal(err)
	}
	input["artifactDigest"] = digest
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
