package usevalidation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrchypark/exposure/internal/operation"
)

func TestManifestAcceptsOnlyFrozenInputsAndCompiledContract(t *testing.T) {
	dir := t.TempDir()
	snapshot := []byte(`{"schemaVersion":2,"sourceId":"patch-data","generation":1,"sourceRevision":"9a27580e7fd7e4bb0df63c1e2e8876e3a24c717d","sourceLedgerDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sourceWatermark":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","producedAt":"2026-08-26T00:00:00Z","principals":[],"organizations":[],"memberships":[],"applications":[],"effectiveBindings":[],"snapshotDigest":"sha256:868dff9d46dcb754ac82aa760837227bc4d0489505bd0063587122f26bc3ee30"}`)
	files := map[string]string{"snapshot": string(snapshot), "run": "run", "cleanup": "cleanup"}
	paths := map[string]string{}
	digests := map[string]string{}
	for name, body := range files {
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(body))
		paths[name] = path
		digests[name] = "sha256:" + hex.EncodeToString(sum[:])
	}
	descriptor, _ := operation.Lookup(operation.PlantGetID)
	manifest := Manifest{
		SchemaVersion: 2,
		Implementation: Implementation{
			PatchDataCommit: string(make([]byte, 40)),
			PatchDataImage:  "registry/patch-data@" + digests["snapshot"],
			GrantCommit:     string(make([]byte, 40)),
			GrantImage:      "registry/grant@" + digests["run"],
			ExposureCommit:  string(make([]byte, 40)),
			ExposureImage:   "registry/exposure@" + digests["cleanup"],
		},
		Artifacts: Artifacts{
			AuthoritySnapshotExporter: RuntimeArtifact{
				Image: "registry/grant@" + digests["run"],
				Path:  "/usr/local/bin/grant-patch-data-authority-snapshot",
			},
			RunValidator: RuntimeArtifact{
				Image: "registry/exposure@" + digests["cleanup"],
				Path:  "/usr/local/bin/exposure-validate-run",
			},
		},
		AuthoritySnapshot: AuthoritySnapshot{SourceID: "patch-data", Generation: 1, SnapshotDigest: "sha256:868dff9d46dcb754ac82aa760837227bc4d0489505bd0063587122f26bc3ee30", ArtifactSHA256: digests["snapshot"], Path: paths["snapshot"]},
		Contract:          Contract{OperationID: descriptor.ID, Version: descriptor.Version, Digest: descriptor.ContractDigest},
		Run:               Evidence{ID: "run-1", Path: paths["run"], Digest: digests["run"]},
		Cleanup:           Evidence{ID: "cleanup-1", Path: paths["cleanup"], Digest: digests["cleanup"]},
	}
	manifest.Implementation.PatchDataCommit = "cccccccccccccccccccccccccccccccccccccccc"
	manifest.Implementation.GrantCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	manifest.Implementation.ExposureCommit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if digests["snapshot"] != "sha256:adc00e004802ab049d403a7f2b2949836468e87092f99f0c4d6241f62e74baab" {
		t.Fatalf("Grant exporter fixture artifact digest drifted: %s", digests["snapshot"])
	}
	body, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(dir, "manifest.json")
	_ = os.WriteFile(manifestPath, body, 0600)
	if receipt, err := LoadAndValidate(manifestPath); err != nil || !receipt.Valid {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	manifest.Implementation.PatchDataCommit = strings.Repeat("0", 40)
	body, _ = json.Marshal(manifest)
	_ = os.WriteFile(manifestPath, body, 0600)
	if _, err := LoadAndValidate(manifestPath); err == nil {
		t.Fatal("placeholder Patch Data commit accepted")
	}
	manifest.Implementation.PatchDataCommit = "cccccccccccccccccccccccccccccccccccccccc"
	manifest.Implementation.PatchDataImage += "@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	body, _ = json.Marshal(manifest)
	_ = os.WriteFile(manifestPath, body, 0600)
	if _, err := LoadAndValidate(manifestPath); err == nil {
		t.Fatal("non-exact Patch Data image reference accepted")
	}
	manifest.Implementation.PatchDataImage = "registry/patch-data@" + digests["snapshot"]
	manifest.Artifacts.AuthoritySnapshotExporter.Image = manifest.Implementation.ExposureImage
	body, _ = json.Marshal(manifest)
	_ = os.WriteFile(manifestPath, body, 0600)
	if _, err := LoadAndValidate(manifestPath); err == nil {
		t.Fatal("exporter image mismatch accepted")
	}
	manifest.Artifacts.AuthoritySnapshotExporter.Image = manifest.Implementation.GrantImage
	manifest.Artifacts.RunValidator.Path = "/exposure-validate-run"
	body, _ = json.Marshal(manifest)
	_ = os.WriteFile(manifestPath, body, 0600)
	if _, err := LoadAndValidate(manifestPath); err == nil {
		t.Fatal("validator path mismatch accepted")
	}
	manifest.Artifacts.RunValidator.Path = "/usr/local/bin/exposure-validate-run"
	tampered := bytes.Replace(snapshot, []byte("2026-08-26T00:00:00Z"), []byte("2026-08-26T00:00:01Z"), 1)
	if err := os.WriteFile(paths["snapshot"], tampered, 0600); err != nil {
		t.Fatal(err)
	}
	tamperedSum := sha256.Sum256(tampered)
	manifest.AuthoritySnapshot.ArtifactSHA256 = "sha256:" + hex.EncodeToString(tamperedSum[:])
	body, _ = json.Marshal(manifest)
	_ = os.WriteFile(manifestPath, body, 0600)
	if _, err := LoadAndValidate(manifestPath); err == nil {
		t.Fatal("semantically tampered snapshot accepted after artifact digest was updated")
	}
	_ = os.WriteFile(paths["snapshot"], snapshot, 0600)
	manifest.AuthoritySnapshot.ArtifactSHA256 = digests["snapshot"]
	manifest.AuthoritySnapshot.SnapshotDigest = manifest.AuthoritySnapshot.ArtifactSHA256
	body, _ = json.Marshal(manifest)
	_ = os.WriteFile(manifestPath, body, 0600)
	if _, err := LoadAndValidate(manifestPath); err == nil {
		t.Fatal("artifact byte digest accepted as logical snapshot digest")
	}
	manifest.AuthoritySnapshot.SnapshotDigest = "sha256:868dff9d46dcb754ac82aa760837227bc4d0489505bd0063587122f26bc3ee30"
	manifest.Contract.OperationID = "unregistered.operation"
	body, _ = json.Marshal(manifest)
	_ = os.WriteFile(manifestPath, body, 0600)
	if _, err := LoadAndValidate(manifestPath); err == nil {
		t.Fatal("unregistered operation accepted")
	}
	manifest.Contract.OperationID = descriptor.ID
	manifest.Run.Digest = digests["cleanup"]
	body, _ = json.Marshal(manifest)
	_ = os.WriteFile(manifestPath, body, 0600)
	if _, err := LoadAndValidate(manifestPath); err == nil {
		t.Fatal("mismatched evidence digest accepted")
	}
}
