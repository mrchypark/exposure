package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type ReadGrantRequest struct {
	ExposureID      string `json:"exposureId"`
	ExposureVersion int64  `json:"exposureVersion"`
	ArtifactDigest  string `json:"artifactDigest"`
	ResourceID      string `json:"resourceId"`
	RequestBinding  string `json:"requestBinding"`
}

func (r ReadGrantRequest) Validate() error {
	if r.ExposureID == "" || r.ExposureVersion <= 0 || !IsDigest(r.ArtifactDigest) || r.ResourceID == "" || r.RequestBinding == "" {
		return fmt.Errorf("%w: invalid read grant request", ErrContract)
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
	PrincipalDigest string    `json:"principalDigest"`
	IssuedAt        time.Time `json:"issuedAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

func (r *ReadGrantResponse) UnmarshalJSON(data []byte) error {
	type plain ReadGrantResponse
	var out plain
	if err := StrictDecode(data, &out); err != nil {
		return err
	}
	required := []string{"allowed", "reason", "exposureId", "exposureVersion", "artifactDigest", "resourceId", "requestBinding", "principalDigest", "issuedAt", "expiresAt"}
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

type SourceObject struct {
	Kind            string
	ResourceID      string
	ResourceVersion *int64
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
