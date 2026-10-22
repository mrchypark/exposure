// Package readartifact defines the fixed, server-owned projection artifact used for reads.
package readartifact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/operation"
)

const (
	artifactType         = "exposure.read.v1"
	SourceComposObject   = "compos.object.v1"
	SourcePatchDataPlant = "patch-data.plant.v1"
	patchDataExposureID  = "patch-data-plant-profile"
	patchDataOperation   = operation.PlantGetID
)

var patchDataResourceID = regexp.MustCompile(`^[a-z0-9]{15}$`)

// Artifact is an immutable, closed V1 read projection artifact.
type Artifact struct {
	artifactType       string
	exposureID         string
	exposureVersion    int64
	artifactDigest     string
	sourceKind         string
	composSource       composSource
	patchDataSource    patchDataSource
	projectionPointers []string
}

type composSource struct {
	Namespace    string `json:"namespace"`
	ObjectType   string `json:"objectType"`
	SchemaDigest string `json:"schemaDigest"`
}

type patchDataSource struct {
	Kind      string `json:"kind"`
	Operation string `json:"operation"`
}

type artifactWire struct {
	ArtifactType       string          `json:"artifactType"`
	ExposureID         string          `json:"exposureId"`
	ExposureVersion    int64           `json:"exposureVersion"`
	ArtifactDigest     string          `json:"artifactDigest"`
	Source             json.RawMessage `json:"source"`
	ProjectionPointers []string        `json:"projectionPointers"`
}

// Parse decodes a closed artifact, rejecting duplicate keys at every JSON-object depth.
func Parse(data []byte) (Artifact, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return Artifact{}, err
	}
	var wire artifactWire
	if err := contracts.StrictDecode(data, &wire); err != nil {
		return Artifact{}, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return Artifact{}, fmt.Errorf("%w: artifact object", contracts.ErrContract)
	}
	for _, name := range []string{"artifactType", "exposureId", "exposureVersion", "artifactDigest", "source", "projectionPointers"} {
		if _, ok := fields[name]; !ok {
			return Artifact{}, fmt.Errorf("%w: missing artifact %s", contracts.ErrContract, name)
		}
	}
	var sourceFields map[string]json.RawMessage
	if err := json.Unmarshal(fields["source"], &sourceFields); err != nil {
		return Artifact{}, fmt.Errorf("%w: source", contracts.ErrContract)
	}
	a := Artifact{
		artifactType: wire.ArtifactType, exposureID: wire.ExposureID,
		exposureVersion: wire.ExposureVersion, artifactDigest: wire.ArtifactDigest,
		projectionPointers: append([]string(nil), wire.ProjectionPointers...),
	}
	if _, tagged := sourceFields["kind"]; tagged {
		if err := contracts.StrictDecode(wire.Source, &a.patchDataSource); err != nil {
			return Artifact{}, err
		}
		for _, name := range []string{"kind", "operation"} {
			if _, ok := sourceFields[name]; !ok {
				return Artifact{}, fmt.Errorf("%w: missing source %s", contracts.ErrContract, name)
			}
		}
		a.sourceKind = a.patchDataSource.Kind
	} else {
		if err := contracts.StrictDecode(wire.Source, &a.composSource); err != nil {
			return Artifact{}, err
		}
		for _, name := range []string{"namespace", "objectType", "schemaDigest"} {
			if _, ok := sourceFields[name]; !ok {
				return Artifact{}, fmt.Errorf("%w: missing source %s", contracts.ErrContract, name)
			}
		}
		a.sourceKind = SourceComposObject
	}
	if err := a.Validate(); err != nil {
		return Artifact{}, err
	}
	return a, nil
}

func (a Artifact) Validate() error {
	if a.artifactType != artifactType || a.exposureID == "" || a.exposureVersion <= 0 || !contracts.IsDigest(a.artifactDigest) {
		return fmt.Errorf("%w: invalid read artifact identity", contracts.ErrContract)
	}
	switch a.sourceKind {
	case SourceComposObject:
		if a.composSource.Namespace == "" || a.composSource.ObjectType == "" || !contracts.IsDigest(a.composSource.SchemaDigest) {
			return fmt.Errorf("%w: invalid Compos source", contracts.ErrContract)
		}
	case SourcePatchDataPlant:
		if a.exposureID != patchDataExposureID || a.patchDataSource.Kind != SourcePatchDataPlant || a.patchDataSource.Operation != patchDataOperation || !reflect.DeepEqual(a.projectionPointers, []string{"/id", "/name", "/updated"}) {
			return fmt.Errorf("%w: invalid Patch Data plant source", contracts.ErrContract)
		}
	default:
		return fmt.Errorf("%w: unsupported read source", contracts.ErrContract)
	}
	if err := validatePointers(a.projectionPointers); err != nil {
		return err
	}
	digest, err := contracts.Digest(a.digestInput())
	if err != nil || digest != a.artifactDigest {
		return fmt.Errorf("%w: artifact digest mismatch", contracts.ErrContract)
	}
	return nil
}

func (a Artifact) digestInput() any {
	var source any = a.composSource
	if a.sourceKind == SourcePatchDataPlant {
		source = a.patchDataSource
	}
	return struct {
		ArtifactType       string   `json:"artifactType"`
		ExposureID         string   `json:"exposureId"`
		ExposureVersion    int64    `json:"exposureVersion"`
		Source             any      `json:"source"`
		ProjectionPointers []string `json:"projectionPointers"`
	}{a.artifactType, a.exposureID, a.exposureVersion, source, a.projectionPointers}
}

func (a Artifact) ExposureID() string     { return a.exposureID }
func (a Artifact) ExposureVersion() int64 { return a.exposureVersion }
func (a Artifact) ArtifactDigest() string { return a.artifactDigest }
func (a Artifact) SourceKind() string     { return a.sourceKind }
func (a Artifact) Namespace() string      { return a.composSource.Namespace }
func (a Artifact) ObjectType() string     { return a.composSource.ObjectType }
func (a Artifact) SchemaDigest() string   { return a.composSource.SchemaDigest }

// Operation returns the immutable server-owned operation descriptor for
// operation-backed artifacts. Legacy Compos reads have no operation descriptor.
func (a Artifact) Operation() (operation.Descriptor, bool) {
	if a.sourceKind != SourcePatchDataPlant {
		return operation.Descriptor{}, false
	}
	return operation.Lookup(a.patchDataSource.Operation)
}

func (a Artifact) ValidResourceID(resourceID string) bool {
	if a.sourceKind == SourcePatchDataPlant {
		return ValidPatchDataResourceID(resourceID)
	}
	return resourceID != "" && !strings.ContainsAny(resourceID, "/\\?#")
}

func ValidPatchDataResourceID(resourceID string) bool {
	return patchDataResourceID.MatchString(resourceID)
}

func (a Artifact) ValidateSourceObject(object contracts.SourceObject) error {
	if object.Kind != a.sourceKind || !a.ValidResourceID(object.ResourceID) || object.RawResource == nil {
		return fmt.Errorf("%w: invalid source response", contracts.ErrContract)
	}
	switch a.sourceKind {
	case SourceComposObject:
		if object.ResourceVersion == nil || *object.ResourceVersion < 0 || object.SourceRevision != "" {
			return fmt.Errorf("%w: invalid Compos revision", contracts.ErrContract)
		}
	case SourcePatchDataPlant:
		if object.ResourceVersion != nil || object.SourceRevision == "" {
			return fmt.Errorf("%w: invalid Patch Data revision", contracts.ErrContract)
		}
	}
	return nil
}

// Project returns exactly the artifact's fixed projection. It never returns partial output.
func (a Artifact) Project(raw map[string]any) (map[string]any, error) {
	if err := a.Validate(); err != nil || raw == nil {
		return nil, fmt.Errorf("%w: invalid projection input", contracts.ErrContract)
	}
	out := make(map[string]any)
	for _, pointer := range a.projectionPointers {
		tokens, _ := pointerTokens(pointer)
		value, err := lookupObject(raw, tokens)
		if err != nil {
			return nil, fmt.Errorf("%w: projection %s", contracts.ErrContract, pointer)
		}
		if containerValue(value) {
			return nil, fmt.Errorf("%w: projection %s must select a scalar leaf", contracts.ErrContract, pointer)
		}
		if err := setObject(out, tokens, clone(value)); err != nil {
			return nil, fmt.Errorf("%w: projection %s", contracts.ErrContract, pointer)
		}
	}
	return out, nil
}

func containerValue(value any) bool {
	if value == nil {
		return false
	}
	switch reflect.ValueOf(value).Kind() {
	case reflect.Map, reflect.Slice, reflect.Array:
		return true
	default:
		return false
	}
}

func validatePointers(pointers []string) error {
	if len(pointers) == 0 {
		return fmt.Errorf("%w: empty projection", contracts.ErrContract)
	}
	decoded := make([][]string, len(pointers))
	for i, p := range pointers {
		if i > 0 && bytes.Compare([]byte(pointers[i-1]), []byte(p)) >= 0 {
			return fmt.Errorf("%w: projection pointers not byte sorted and unique", contracts.ErrContract)
		}
		var err error
		if decoded[i], err = pointerTokens(p); err != nil {
			return fmt.Errorf("%w: invalid projection pointer", contracts.ErrContract)
		}
	}
	for i := range decoded {
		for j := range decoded {
			if i != j && tokenPrefix(decoded[i], decoded[j]) {
				return fmt.Errorf("%w: overlapping projection pointers", contracts.ErrContract)
			}
		}
	}
	return nil
}

func pointerTokens(pointer string) ([]string, error) {
	if pointer == "" || !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("root or malformed pointer")
	}
	parts := strings.Split(pointer[1:], "/")
	for i, p := range parts {
		var b strings.Builder
		for j := 0; j < len(p); j++ {
			if p[j] != '~' {
				b.WriteByte(p[j])
				continue
			}
			if j+1 >= len(p) || (p[j+1] != '0' && p[j+1] != '1') {
				return nil, fmt.Errorf("bad escape")
			}
			if p[j+1] == '0' {
				b.WriteByte('~')
			} else {
				b.WriteByte('/')
			}
			j++
		}
		parts[i] = b.String()
	}
	return parts, nil
}

func tokenPrefix(a, b []string) bool {
	if len(a) >= len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func lookupObject(value any, tokens []string) (any, error) {
	for _, token := range tokens {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("not object")
		}
		var exists bool
		value, exists = object[token]
		if !exists {
			return nil, fmt.Errorf("missing")
		}
	}
	return value, nil
}

func setObject(out map[string]any, tokens []string, value any) error {
	for _, token := range tokens[:len(tokens)-1] {
		next, ok := out[token]
		if !ok {
			child := make(map[string]any)
			out[token] = child
			out = child
			continue
		}
		var isObject bool
		out, isObject = next.(map[string]any)
		if !isObject {
			return fmt.Errorf("conflict")
		}
	}
	out[tokens[len(tokens)-1]] = value
	return nil
}

func clone(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = clone(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = clone(item)
		}
		return out
	default:
		return v
	}
}

func rejectDuplicateKeys(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := scanValue(d); err != nil {
		return fmt.Errorf("%w: malformed artifact JSON: %v", contracts.ErrContract, err)
	}
	if _, err := d.Token(); !errorsEOF(err) {
		return fmt.Errorf("%w: trailing JSON value", contracts.ErrContract)
	}
	return nil
}
func errorsEOF(err error) bool { return err == io.EOF }
func scanValue(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return fmt.Errorf("object key")
				}
				if seen[name] {
					return fmt.Errorf("duplicate key %q", name)
				}
				seen[name] = true
				if err := scanValue(d); err != nil {
					return err
				}
			}
			_, err := d.Token()
			return err
		case '[':
			for d.More() {
				if err := scanValue(d); err != nil {
					return err
				}
			}
			_, err := d.Token()
			return err
		default:
			return fmt.Errorf("unexpected delimiter")
		}
	}
	return nil
}
