package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/dependency"
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
	if g.mutate != nil {
		g.mutate(&response)
	}
	return response, nil
}

type fakeSource struct {
	calls int
	kind  string
	err   error
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
	return contracts.SourceObject{
		Kind: kind, ResourceID: resourceID, ResourceVersion: &version,
		RawResource: map[string]any{"domain": "example.test", "employee_count": json.Number("12"), "secret": "never-return"},
	}, nil
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

func TestDependencyErrorSemantics(t *testing.T) {
	for _, tc := range []struct {
		code string
		want error
	}{
		{"unauthenticated", ErrUnauthenticated}, {"access_denied", ErrDenied}, {"not_found", ErrConflict}, {"upstream_failure", ErrUnavailable}, {"malformed_response", ErrUnavailable},
	} {
		t.Run(tc.code, func(t *testing.T) {
			grant, source := &fakeGrant{}, &fakeSource{err: &dependency.RemoteError{Code: tc.code}}
			svc := serviceForTest(t, grant, source)
			_, err := svc.Read(context.Background(), ReadRequest{ExposureID: "customer-profile", ResourceID: "company-1", Authorization: "Bearer user", OrganizationID: "org-1"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
		})
	}
}
