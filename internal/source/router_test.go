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

func TestRouterDoesNotForwardBearerToCompos(t *testing.T) {
	artifact := parseArtifact(t, composArtifact(t))
	compos := &composFake{}
	out, err := New(compos).ReadObject(context.Background(), artifact, "resource")
	if err != nil || compos.request.ResourceID != "resource" || out.ResourceVersion == nil || *out.ResourceVersion != 2 {
		t.Fatalf("out=%#v compos=%#v err=%v", out, compos, err)
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
