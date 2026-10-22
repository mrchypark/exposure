package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/mrchypark/exposure/internal/operation"
)

type ReadGrantRequest struct {
	ExposureID      string `json:"exposureId"`
	ExposureVersion int64  `json:"exposureVersion"`
	ArtifactDigest  string `json:"artifactDigest"`
	ResourceID      string `json:"resourceId"`
	RequestBinding  string `json:"requestBinding"`
	OperationID     string `json:"operationId,omitempty"`
}

func (r ReadGrantRequest) Validate() error {
	if r.ExposureID == "" || r.ExposureVersion <= 0 || !IsDigest(r.ArtifactDigest) || r.ResourceID == "" || r.RequestBinding == "" {
		return fmt.Errorf("%w: invalid read grant request", ErrContract)
	}
	if r.OperationID != "" {
		descriptor, ok := operation.Lookup(r.OperationID)
		if !ok || descriptor.Semantics != operation.Read {
			return fmt.Errorf("%w: unsupported read operation", ErrContract)
		}
	}
	return nil
}

type ReadGrantResponse struct {
	Allowed         bool      `json:"allowed"`
	Reason          string    `json:"reason"`
	ExposureID      string    `json:"exposureId"`
	ExposureVersion int64     `json:"exposureVersion"`
	ArtifactDigest  string    `json:"artifactDigest"`
	ResourceID      string    `json:"resourceId"`
	RequestBinding  string    `json:"requestBinding"`
	OperationID     string    `json:"operationId,omitempty"`
	ProviderID      string    `json:"providerId,omitempty"`
	ActionID        string    `json:"actionId,omitempty"`
	ResourceType    string    `json:"resourceType,omitempty"`
	PrincipalDigest string    `json:"principalDigest"`
	IssuedAt        time.Time `json:"issuedAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

type OperationDecisionRequestV2 struct {
	OperationID      string              `json:"operationId"`
	OperationVersion int64               `json:"operationVersion"`
	ContractDigest   string              `json:"contractDigest"`
	Resource         OperationResourceV2 `json:"resource"`
	RequestBinding   string              `json:"requestBinding"`
}

type OperationResourceV2 struct {
	Type string `json:"type,omitempty"`
	ID   string `json:"id"`
}

type OperationDecisionResponseV2 struct {
	Allowed          bool                `json:"allowed"`
	Reason           string              `json:"reason"`
	OperationID      string              `json:"operationId"`
	OperationVersion int64               `json:"operationVersion"`
	ContractDigest   string              `json:"contractDigest"`
	ProviderID       string              `json:"providerId"`
	ActionID         string              `json:"actionId"`
	Resource         OperationResourceV2 `json:"resource"`
	RequestBinding   string              `json:"requestBinding"`
	PrincipalDigest  string              `json:"principalDigest"`
	IssuedAt         time.Time           `json:"issuedAt"`
	ExpiresAt        time.Time           `json:"expiresAt"`
}

func (r *OperationDecisionResponseV2) UnmarshalJSON(data []byte) error {
	type plain OperationDecisionResponseV2
	var out plain
	if err := StrictDecode(data, &out); err != nil {
		return err
	}
	if err := readRequiredFields(data, []string{"allowed", "reason", "operationId", "operationVersion", "contractDigest", "providerId", "actionId", "resource", "requestBinding", "principalDigest", "issuedAt", "expiresAt"}); err != nil {
		return err
	}
	*r = OperationDecisionResponseV2(out)
	return nil
}

func (r OperationDecisionResponseV2) ValidateAgainst(q OperationDecisionRequestV2, descriptor operation.Descriptor, now time.Time) error {
	if r.Reason == "" || r.OperationID != descriptor.ID || r.OperationID != q.OperationID ||
		r.OperationVersion != descriptor.Version || r.OperationVersion != q.OperationVersion ||
		r.ContractDigest != descriptor.ContractDigest || r.ContractDigest != q.ContractDigest ||
		r.ProviderID != descriptor.ProviderID || r.ActionID != descriptor.ActionID ||
		r.Resource.Type != descriptor.ResourceType || r.Resource.ID != q.Resource.ID ||
		r.RequestBinding != q.RequestBinding || !IsPrincipalDigest(r.PrincipalDigest) ||
		r.IssuedAt.IsZero() || r.IssuedAt.After(now) || r.ExpiresAt.IsZero() ||
		!r.ExpiresAt.After(r.IssuedAt) || !r.ExpiresAt.After(now) {
		return fmt.Errorf("%w: invalid operation decision", ErrContract)
	}
	return nil
}

func (r *ReadGrantResponse) UnmarshalJSON(data []byte) error {
	type plain ReadGrantResponse
	var out plain
	if err := StrictDecode(data, &out); err != nil {
		return err
	}
	required := []string{"allowed", "reason", "exposureId", "exposureVersion", "artifactDigest", "resourceId", "requestBinding", "principalDigest", "issuedAt", "expiresAt"}
	if out.OperationID != "" {
		required = append(required, "operationId", "providerId", "actionId", "resourceType")
	}
	if err := readRequiredFields(data, required); err != nil {
		return err
	}
	*r = ReadGrantResponse(out)
	return nil
}

func (r ReadGrantResponse) ValidateAgainst(q ReadGrantRequest, now time.Time) error {
	if r.Reason == "" || r.ExposureID != q.ExposureID || r.ExposureVersion != q.ExposureVersion || r.ArtifactDigest != q.ArtifactDigest || r.ResourceID != q.ResourceID || r.RequestBinding != q.RequestBinding || !IsPrincipalDigest(r.PrincipalDigest) || r.IssuedAt.IsZero() || r.IssuedAt.After(now) || r.ExpiresAt.IsZero() || !r.ExpiresAt.After(r.IssuedAt) || !r.ExpiresAt.After(now) {
		return fmt.Errorf("%w: invalid read grant response", ErrContract)
	}
	if q.OperationID == "" {
		if r.OperationID != "" || r.ProviderID != "" || r.ActionID != "" || r.ResourceType != "" {
			return fmt.Errorf("%w: unexpected operation decision", ErrContract)
		}
		return nil
	}
	descriptor, ok := operation.Lookup(q.OperationID)
	if !ok || r.OperationID != descriptor.ID || r.ProviderID != descriptor.ProviderID || r.ActionID != descriptor.ActionID || r.ResourceType != descriptor.ResourceType {
		return fmt.Errorf("%w: operation decision mismatch", ErrContract)
	}
	return nil
}

type SourceReadRequest struct {
	Namespace    string `json:"namespace"`
	ObjectType   string `json:"objectType"`
	SchemaDigest string `json:"schemaDigest"`
	ResourceID   string `json:"resourceId"`
}

func (r SourceReadRequest) Validate() error {
	if r.Namespace == "" || r.ObjectType == "" || !IsDigest(r.SchemaDigest) || r.ResourceID == "" {
		return fmt.Errorf("%w: invalid source read request", ErrContract)
	}
	return nil
}

type SourceReadResponse struct {
	Namespace       string         `json:"namespace"`
	ObjectType      string         `json:"objectType"`
	SchemaDigest    string         `json:"schemaDigest"`
	ResourceID      string         `json:"resourceId"`
	ResourceVersion int64          `json:"resourceVersion"`
	RawResource     map[string]any `json:"rawResource"`
}

// SourceObject is the normalized result of one fixed, server-owned source
// operation. Compos supplies ResourceVersion; Patch Data supplies
// SourceRevision. Exactly one revision form is valid for a source kind.
type SourceObject struct {
	Kind            string
	ResourceID      string
	ResourceVersion *int64
	SourceRevision  string
	RawResource     map[string]any
}

func (r *SourceReadResponse) UnmarshalJSON(data []byte) error {
	type plain SourceReadResponse
	var out plain
	if err := StrictDecode(data, &out); err != nil {
		return err
	}
	if err := readRequiredFields(data, []string{"namespace", "objectType", "schemaDigest", "resourceId", "resourceVersion", "rawResource"}); err != nil {
		return err
	}
	*r = SourceReadResponse(out)
	return nil
}

func readRequiredFields(data []byte, required []string) error {
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("%w: response object", ErrContract)
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return fmt.Errorf("%w: response key", ErrContract)
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return fmt.Errorf("%w: duplicate response field", ErrContract)
		}
		seen[name] = true
		var raw json.RawMessage
		if err = d.Decode(&raw); err != nil || bytes.Equal(raw, []byte("null")) {
			return fmt.Errorf("%w: null response field", ErrContract)
		}
	}
	if _, err = d.Token(); err != nil {
		return fmt.Errorf("%w: response close", ErrContract)
	}
	if err = d.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("%w: response trailing", ErrContract)
	}
	for _, name := range required {
		if !seen[name] {
			return fmt.Errorf("%w: missing response field", ErrContract)
		}
	}
	return nil
}

func (r SourceReadResponse) ValidateAgainst(q SourceReadRequest) error {
	if r.Namespace != q.Namespace || r.ObjectType != q.ObjectType || r.SchemaDigest != q.SchemaDigest || r.ResourceID != q.ResourceID || r.ResourceVersion < 0 || r.RawResource == nil {
		return fmt.Errorf("%w: invalid source read response", ErrContract)
	}
	return nil
}
