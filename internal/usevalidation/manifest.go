package usevalidation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/operation"
)

type Manifest struct {
	SchemaVersion     int               `json:"schemaVersion"`
	Implementation    Implementation    `json:"implementation"`
	Artifacts         Artifacts         `json:"artifacts"`
	AuthoritySnapshot AuthoritySnapshot `json:"authoritySnapshot"`
	Contract          Contract          `json:"contract"`
	Run               Evidence          `json:"run"`
	Cleanup           Evidence          `json:"cleanup"`
}
type Implementation struct {
	PatchDataCommit string `json:"patchDataCommit"`
	PatchDataImage  string `json:"patchDataImage"`
	GrantCommit     string `json:"grantCommit"`
	GrantImage      string `json:"grantImage"`
	ExposureCommit  string `json:"exposureCommit"`
	ExposureImage   string `json:"exposureImage"`
}
type Artifacts struct {
	AuthoritySnapshotExporter RuntimeArtifact `json:"authoritySnapshotExporter"`
	RunValidator              RuntimeArtifact `json:"runValidator"`
}
type RuntimeArtifact struct {
	Image string `json:"image"`
	Path  string `json:"path"`
}
type AuthoritySnapshot struct {
	SourceID       string `json:"sourceId"`
	Generation     uint64 `json:"generation"`
	SnapshotDigest string `json:"snapshotDigest"`
	ArtifactSHA256 string `json:"artifactSha256"`
	Path           string `json:"path"`
}
type Contract struct {
	OperationID string `json:"operationId"`
	Version     int64  `json:"version"`
	Digest      string `json:"digest"`
}
type Evidence struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	Digest string `json:"digest"`
}
type Receipt struct {
	Valid          bool   `json:"valid"`
	RunID          string `json:"runId"`
	OperationID    string `json:"operationId"`
	SnapshotDigest string `json:"snapshotDigest"`
	ArtifactSHA256 string `json:"artifactSha256"`
}

func LoadAndValidate(path string) (Receipt, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Receipt{}, err
	}
	var manifest Manifest
	if err := contracts.StrictDecode(body, &manifest); err != nil {
		return Receipt{}, err
	}
	if manifest.SchemaVersion != 2 || manifest.AuthoritySnapshot.SourceID == "" || manifest.AuthoritySnapshot.Generation == 0 || manifest.Run.ID == "" || manifest.Cleanup.ID == "" {
		return Receipt{}, fmt.Errorf("invalid usage-validation manifest")
	}
	for name, value := range map[string]string{"patchDataCommit": manifest.Implementation.PatchDataCommit, "grantCommit": manifest.Implementation.GrantCommit, "exposureCommit": manifest.Implementation.ExposureCommit} {
		if !isCommit(value) {
			return Receipt{}, fmt.Errorf("invalid %s", name)
		}
	}
	for name, value := range map[string]string{"patchDataImage": manifest.Implementation.PatchDataImage, "grantImage": manifest.Implementation.GrantImage, "exposureImage": manifest.Implementation.ExposureImage} {
		if !isImage(value) {
			return Receipt{}, fmt.Errorf("invalid %s", name)
		}
	}
	if err := validateRuntimeArtifact(
		manifest.Artifacts.AuthoritySnapshotExporter,
		manifest.Implementation.GrantImage,
		"/usr/local/bin/grant-patch-data-authority-snapshot",
	); err != nil {
		return Receipt{}, fmt.Errorf("authority snapshot exporter: %w", err)
	}
	if err := validateRuntimeArtifact(
		manifest.Artifacts.RunValidator,
		manifest.Implementation.ExposureImage,
		"/usr/local/bin/exposure-validate-run",
	); err != nil {
		return Receipt{}, fmt.Errorf("run validator: %w", err)
	}
	descriptor, ok := operation.Lookup(manifest.Contract.OperationID)
	if !ok || descriptor.Version != manifest.Contract.Version || descriptor.ContractDigest != manifest.Contract.Digest {
		return Receipt{}, fmt.Errorf("uncompiled operation contract")
	}
	if !isDigest(manifest.AuthoritySnapshot.SnapshotDigest) || !isDigest(manifest.AuthoritySnapshot.ArtifactSHA256) {
		return Receipt{}, fmt.Errorf("invalid snapshot digest")
	}
	for name, evidence := range map[string]Evidence{"run": manifest.Run, "cleanup": manifest.Cleanup, "snapshot": {ID: manifest.AuthoritySnapshot.SourceID, Path: manifest.AuthoritySnapshot.Path, Digest: manifest.AuthoritySnapshot.ArtifactSHA256}} {
		if err := validateEvidence(evidence); err != nil {
			return Receipt{}, fmt.Errorf("%s evidence: %w", name, err)
		}
	}
	if err := validateAuthoritySnapshot(manifest.AuthoritySnapshot); err != nil {
		return Receipt{}, err
	}
	return Receipt{Valid: true, RunID: manifest.Run.ID, OperationID: descriptor.ID, SnapshotDigest: manifest.AuthoritySnapshot.SnapshotDigest, ArtifactSHA256: manifest.AuthoritySnapshot.ArtifactSHA256}, nil
}

func validateRuntimeArtifact(artifact RuntimeArtifact, image, path string) error {
	if artifact.Image != image {
		return fmt.Errorf("image mismatch")
	}
	if artifact.Path != path {
		return fmt.Errorf("path mismatch")
	}
	return nil
}

func validateAuthoritySnapshot(expected AuthoritySnapshot) error {
	body, err := os.ReadFile(expected.Path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var snapshot map[string]any
	if err := decoder.Decode(&snapshot); err != nil {
		return fmt.Errorf("decode authority snapshot: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("decode authority snapshot: trailing JSON")
	}
	if snapshot["schemaVersion"] != json.Number("2") || snapshot["sourceId"] != expected.SourceID || snapshot["generation"] != json.Number(fmt.Sprint(expected.Generation)) {
		return fmt.Errorf("authority snapshot identity mismatch")
	}
	embedded, ok := snapshot["snapshotDigest"].(string)
	if !ok || embedded != expected.SnapshotDigest {
		return fmt.Errorf("authority snapshot logical digest mismatch")
	}
	delete(snapshot, "snapshotDigest")
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(snapshot); err != nil {
		return err
	}
	sum := sha256.Sum256(bytes.TrimSuffix(canonical.Bytes(), []byte("\n")))
	if "sha256:"+hex.EncodeToString(sum[:]) != expected.SnapshotDigest {
		return fmt.Errorf("authority snapshot canonical digest mismatch")
	}
	return nil
}

func validateEvidence(e Evidence) error {
	if e.ID == "" || !filepath.IsAbs(e.Path) || !isDigest(e.Digest) {
		return fmt.Errorf("invalid immutable input")
	}
	body, err := os.ReadFile(e.Path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	if "sha256:"+hex.EncodeToString(sum[:]) != e.Digest {
		return fmt.Errorf("digest mismatch")
	}
	return nil
}
func isDigest(v string) bool {
	return len(v) == 71 && strings.HasPrefix(v, "sha256:") && v[7:] != strings.Repeat("0", 64) && strings.ToLower(v) == v && strings.IndexFunc(v[7:], func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') }) < 0
}
func isImage(v string) bool {
	prefix, digest, ok := strings.Cut(v, "@")
	return ok && prefix != "" && strings.TrimSpace(prefix) == prefix && !strings.Contains(digest, "@") && isDigest(digest)
}
func isCommit(v string) bool {
	return len(v) == 40 && v != strings.Repeat("0", 40) && strings.ToLower(v) == v && strings.IndexFunc(v, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') }) < 0
}

func EncodeReceipt(receipt Receipt) ([]byte, error) { return json.Marshal(receipt) }
