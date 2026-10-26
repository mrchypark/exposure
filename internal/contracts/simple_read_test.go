package contracts

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSimpleReadResponseClosedAndPresent(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	grant := `{"allowed":true,"reason":"ok","exposureId":"e","exposureVersion":1,"artifactDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resourceId":"r","requestBinding":"b","principalDigest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","issuedAt":"2025-12-31T23:59:00Z","expiresAt":"2026-01-01T00:01:00Z"}`
	for _, body := range []string{grant, `{"allowed":true}`, grant[:len(grant)-1] + `,"extra":true}`, `{"allowed":null,"reason":"ok","exposureId":"e","exposureVersion":1,"artifactDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resourceId":"r","requestBinding":"b","principalDigest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","issuedAt":"2025-12-31T23:59:00Z","expiresAt":"2026-01-01T00:01:00Z"}`, grant[:len(grant)-1] + `,"allowed":false`} {
		var r ReadGrantResponse
		err := json.Unmarshal([]byte(body), &r)
		if body == grant {
			if err != nil || r.ValidateAgainst(ReadGrantRequest{ExposureID: "e", ExposureVersion: 1, ArtifactDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ResourceID: "r", RequestBinding: "b"}, now) != nil {
				t.Fatal(err)
			}
		} else if err == nil {
			t.Fatal("accepted", body)
		}
	}
	source := `{"namespace":"n","objectType":"o","schemaDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resourceId":"r","resourceVersion":0,"rawResource":{"x":"y"}}`
	for _, body := range []string{source, `{"namespace":"n"}`, source[:len(source)-1] + `,"extra":true}`, `{"namespace":"n","objectType":"o","schemaDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resourceId":"r","resourceVersion":null,"rawResource":{}}`, source[:len(source)-1] + `,"resourceVersion":3}`} {
		var r SourceReadResponse
		err := json.Unmarshal([]byte(body), &r)
		if body == source {
			if err != nil || r.ValidateAgainst(SourceReadRequest{Namespace: "n", ObjectType: "o", SchemaDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ResourceID: "r"}) != nil {
				t.Fatal(err)
			}
		} else if err == nil {
			t.Fatal("accepted", body)
		}
	}
}

func TestReadGrantResponseRequiresCanonicalRawPrincipalDigest(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	request := ReadGrantRequest{ExposureID: "e", ExposureVersion: 1, ArtifactDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ResourceID: "r", RequestBinding: "b"}
	base := ReadGrantResponse{Allowed: false, Reason: "no_matching_binding", ExposureID: "e", ExposureVersion: 1, ArtifactDigest: request.ArtifactDigest, ResourceID: "r", RequestBinding: "b", IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Second)}
	base.PrincipalDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := base.ValidateAgainst(request, now); err != nil {
		t.Fatalf("Grant canonical principal digest rejected: %v", err)
	}
	for _, invalid := range []string{
		"sha256:" + base.PrincipalDigest,
		"0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
		"g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		base.PrincipalDigest[:63],
	} {
		response := base
		response.PrincipalDigest = invalid
		if err := response.ValidateAgainst(request, now); err == nil {
			t.Fatalf("invalid principal digest accepted: %q", invalid)
		}
	}
}
