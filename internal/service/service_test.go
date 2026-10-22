package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/dependency"
	"github.com/mrchypark/exposure/internal/operation"
	"github.com/mrchypark/exposure/internal/readartifact"
)

type fakeGrant struct {
	mutate func(*contracts.ReadGrantResponse)
	calls  int
	last   contracts.ReadGrantRequest
}

func (g *fakeGrant) Read(_ context.Context, request contracts.ReadGrantRequest, _, _, _ string) (contracts.ReadGrantResponse, error) {
	g.calls++
	g.last = request
	response := contracts.ReadGrantResponse{
		Allowed: true, Reason: "ok", ExposureID: request.ExposureID,
		ExposureVersion: request.ExposureVersion, ArtifactDigest: request.ArtifactDigest,
		ResourceID: request.ResourceID, RequestBinding: request.RequestBinding,
		PrincipalDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		IssuedAt:        nowForTest.Add(-time.Minute), ExpiresAt: nowForTest.Add(time.Minute),
	}
	if descriptor, ok := operation.Lookup(request.OperationID); ok {
		response.OperationID = descriptor.ID
		response.ProviderID = descriptor.ProviderID
		response.ActionID = descriptor.ActionID
		response.ResourceType = descriptor.ResourceType
	}
	if g.mutate != nil {
		g.mutate(&response)
	}
	return response, nil
}

type fakeSource struct {
	calls         int
	kind          string
	patchDataMode bool
	err           error
}

func (s *fakeSource) ReadObject(_ context.Context, artifact readartifact.Artifact, resourceID string) (contracts.SourceObject, error) {
	s.calls++
	if s.err != nil {
		return contracts.SourceObject{}, s.err
	}
	version := int64(7)
	kind := s.kind
	if kind == "" {
		kind = artifact.SourceKind()
	}
	if s.patchDataMode {
		return contracts.SourceObject{
			Kind: kind, ResourceID: resourceID, SourceRevision: "2026-08-11 01:02:03.456Z",
			RawResource: map[string]any{"id": resourceID, "name": "Gwangdeok", "updated": "2026-08-11 01:02:03.456Z", "permission": "never-return"},
		}, nil
	}
	return contracts.SourceObject{
		Kind: kind, ResourceID: resourceID, ResourceVersion: &version,
		RawResource: map[string]any{"domain": "example.test", "employee_count": json.Number("12"), "secret": "never-return"},
	}, nil
}

func TestPatchDataDependencyErrorSemantics(t *testing.T) {
	for _, tc := range []struct {
		code string
		want error
	}{
		{"unauthenticated", ErrUnauthenticated},
		{"access_denied", ErrDenied},
		{"not_found", ErrConflict},
		{"upstream_failure", ErrUnavailable},
		{"malformed_response", ErrUnavailable},
	} {
		t.Run(tc.code, func(t *testing.T) {
			grant := &fakeGrant{}
			source := &fakeSource{patchDataMode: true, err: &dependency.RemoteError{Code: tc.code}}
			svc, err := New([]readartifact.Artifact{patchDataArtifactForTest(t)}, grant, source, "server-owned-key")
			if err != nil {
				t.Fatal(err)
			}
			svc.now = func() time.Time { return nowForTest }
			_, err = svc.Read(context.Background(), ReadRequest{ExposureID: "patch-data-plant-profile", ResourceID: "4n5mdid6ccx1bh6", Authorization: "Bearer user", OrganizationID: "org-1"})
			if !errors.Is(err, tc.want) || grant.calls != 1 || source.calls != 1 {
				t.Fatalf("err=%v grant=%d source=%d", err, grant.calls, source.calls)
			}
		})
	}
}

func patchDataArtifactForTest(t *testing.T) readartifact.Artifact {
	t.Helper()
	digestInput := map[string]any{
		"artifactType": "exposure.read.v1", "exposureId": "patch-data-plant-profile", "exposureVersion": 1,
		"source":             map[string]any{"kind": "patch-data.plant.v1", "operation": "plant.get"},
		"projectionPointers": []string{"/id", "/name", "/updated"},
	}
	digest, err := contracts.Digest(digestInput)
	if err != nil {
		t.Fatal(err)
	}
	digestInput["artifactDigest"] = digest
	data, err := json.Marshal(digestInput)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := readartifact.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

var nowForTest = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func artifactForTest(t *testing.T) readartifact.Artifact {
	t.Helper()
	schema := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestInput := map[string]any{
		"artifactType": "exposure.read.v1", "exposureId": "customer-profile", "exposureVersion": 1,
		"source":             map[string]any{"namespace": "wks_default", "objectType": "otp_builtin_company_wks_default", "schemaDigest": schema},
		"projectionPointers": []string{"/domain", "/employee_count"},
	}
	digest, err := contracts.Digest(digestInput)
	if err != nil {
		t.Fatal(err)
	}
	digestInput["artifactDigest"] = digest
	data, err := json.Marshal(digestInput)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := readartifact.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func serviceForTest(t *testing.T, grant *fakeGrant, source *fakeSource) *Service {
	t.Helper()
	service, err := New([]readartifact.Artifact{artifactForTest(t)}, grant, source, "server-owned-key")
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return nowForTest }
	return service
}

func TestReadProjectsOnlyArtifactScalars(t *testing.T) {
	grant, source := &fakeGrant{}, &fakeSource{}
	service := serviceForTest(t, grant, source)
	response, err := service.Read(context.Background(), ReadRequest{
		ExposureID: "customer-profile", ResourceID: "company-1", Authorization: "Bearer user", OrganizationID: "org-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if grant.calls != 1 || source.calls != 1 || response.ResourceVersion == nil || *response.ResourceVersion != 7 || len(response.Data) != 2 || response.Data["domain"] != "example.test" {
		t.Fatalf("response=%#v grant=%d source=%d", response, grant.calls, source.calls)
	}
	if _, leaked := response.Data["secret"]; leaked {
		t.Fatal("secret leaked")
	}
}

func TestPatchDataReadAuthorizesBeforeSourceAndUsesOpaqueRevision(t *testing.T) {
	grant := &fakeGrant{}
	source := &fakeSource{patchDataMode: true}
	svc, err := New([]readartifact.Artifact{patchDataArtifactForTest(t)}, grant, source, "server-owned-key")
	if err != nil {
		t.Fatal(err)
	}
	svc.now = func() time.Time { return nowForTest }
	response, err := svc.Read(context.Background(), ReadRequest{
		ExposureID: "patch-data-plant-profile", ResourceID: "4n5mdid6ccx1bh6", Authorization: "Bearer user", OrganizationID: "org-1",
	})
	if err != nil || grant.calls != 1 || grant.last.OperationID != "plant.get" || source.calls != 1 || response.ResourceVersion != nil || response.SourceRevision != "2026-08-11 01:02:03.456Z" || len(response.Data) != 3 || response.Data["name"] != "Gwangdeok" {
		t.Fatalf("response=%#v grant=%d source=%d err=%v", response, grant.calls, source.calls, err)
	}
	if _, leaked := response.Data["permission"]; leaked {
		t.Fatal("Patch Data ACL metadata leaked")
	}
}

func TestPatchDataReadRejectsOperationPolicyTamperBeforeExecution(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*contracts.ReadGrantResponse)
	}{
		{"operation", func(r *contracts.ReadGrantResponse) { r.OperationID = "plant.list" }},
		{"provider", func(r *contracts.ReadGrantResponse) { r.ProviderID = "exposure" }},
		{"action", func(r *contracts.ReadGrantResponse) { r.ActionID = "exposure.read" }},
		{"resource type", func(r *contracts.ReadGrantResponse) { r.ResourceType = "patch-data-plant-profile" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			grant := &fakeGrant{mutate: test.mutate}
			source := &fakeSource{patchDataMode: true}
			svc, err := New([]readartifact.Artifact{patchDataArtifactForTest(t)}, grant, source, "server-owned-key")
			if err != nil {
				t.Fatal(err)
			}
			svc.now = func() time.Time { return nowForTest }
			_, err = svc.Read(context.Background(), ReadRequest{ExposureID: "patch-data-plant-profile", ResourceID: "4n5mdid6ccx1bh6", Authorization: "Bearer user", OrganizationID: "org-1"})
			if !errors.Is(err, contracts.ErrContract) || source.calls != 0 {
				t.Fatalf("error=%v source calls=%d", err, source.calls)
			}
		})
	}
}

func TestPatchDataResourceIDRejectedBeforeGrant(t *testing.T) {
	grant := &fakeGrant{}
	source := &fakeSource{patchDataMode: true}
	svc, err := New([]readartifact.Artifact{patchDataArtifactForTest(t)}, grant, source, "server-owned-key")
	if err != nil {
		t.Fatal(err)
	}
	for _, resourceID := range []string{"short", "4N5MDID6CCX1BH6", "../../etc/passwd"} {
		if _, err := svc.Read(context.Background(), ReadRequest{ExposureID: "patch-data-plant-profile", ResourceID: resourceID, Authorization: "Bearer user", OrganizationID: "org-1"}); !errors.Is(err, contracts.ErrContract) || grant.calls != 0 || source.calls != 0 {
			t.Fatalf("resource=%q err=%v grant=%d source=%d", resourceID, err, grant.calls, source.calls)
		}
	}
}

func TestReadRejectsReplayedOrExpiredGrantBeforeSource(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*contracts.ReadGrantResponse)
		want   error
	}{
		{"binding", func(r *contracts.ReadGrantResponse) { r.RequestBinding = "old-binding" }, contracts.ErrContract},
		{"resource", func(r *contracts.ReadGrantResponse) { r.ResourceID = "other" }, contracts.ErrContract},
		{"artifact", func(r *contracts.ReadGrantResponse) {
			r.ArtifactDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		}, contracts.ErrContract},
		{"future issue", func(r *contracts.ReadGrantResponse) { r.IssuedAt = nowForTest.Add(time.Second) }, contracts.ErrContract},
		{"expired", func(r *contracts.ReadGrantResponse) { r.ExpiresAt = nowForTest }, ErrConflict},
		{"denied", func(r *contracts.ReadGrantResponse) { r.Allowed = false }, ErrDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			grant, source := &fakeGrant{mutate: test.mutate}, &fakeSource{}
			service := serviceForTest(t, grant, source)
			_, err := service.Read(context.Background(), ReadRequest{ExposureID: "customer-profile", ResourceID: "company-1", Authorization: "Bearer user", OrganizationID: "org-1"})
			if !errors.Is(err, test.want) || source.calls != 0 {
				t.Fatalf("error=%v source calls=%d", err, source.calls)
			}
		})
	}
}
