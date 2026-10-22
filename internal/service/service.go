// Package service performs one authorized, immutable, fixed-projection read.
package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/dependency"
	"github.com/mrchypark/exposure/internal/readartifact"
)

var (
	ErrUnauthenticated = errors.New("authentication required")
	ErrDenied          = errors.New("authorization denied")
	ErrConflict        = errors.New("read conflict")
	ErrUnavailable     = errors.New("dependency unavailable")
)

type ReadGrant interface {
	Read(context.Context, contracts.ReadGrantRequest, string, string, string) (contracts.ReadGrantResponse, error)
}

type ReadSource interface {
	ReadObject(context.Context, readartifact.Artifact, string) (contracts.SourceObject, error)
}

type ReadRequest struct {
	ExposureID, ResourceID, Authorization, OrganizationID string
}

type ReadResponse struct {
	ExposureID      string         `json:"exposureId"`
	ExposureVersion int64          `json:"exposureVersion"`
	ArtifactDigest  string         `json:"artifactDigest"`
	ResourceID      string         `json:"resourceId"`
	ResourceVersion *int64         `json:"resourceVersion,omitempty"`
	SourceRevision  string         `json:"sourceRevision,omitempty"`
	Data            map[string]any `json:"data"`
}

type Service struct {
	artifacts map[string]readartifact.Artifact
	grant     ReadGrant
	source    ReadSource
	appKey    string
	now       func() time.Time
}

func New(artifacts []readartifact.Artifact, grant ReadGrant, source ReadSource, appKey string) (*Service, error) {
	if len(artifacts) == 0 || grant == nil || source == nil || appKey == "" {
		return nil, fmt.Errorf("invalid read configuration")
	}
	indexed := make(map[string]readartifact.Artifact, len(artifacts))
	for _, artifact := range artifacts {
		if err := artifact.Validate(); err != nil {
			return nil, err
		}
		if _, exists := indexed[artifact.ExposureID()]; exists {
			return nil, fmt.Errorf("duplicate read artifact")
		}
		indexed[artifact.ExposureID()] = artifact
	}
	return &Service{artifacts: indexed, grant: grant, source: source, appKey: appKey, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (s *Service) Read(ctx context.Context, input ReadRequest) (ReadResponse, error) {
	artifact, ok := s.artifacts[input.ExposureID]
	if !ok {
		return ReadResponse{}, ErrConflict
	}
	if !artifact.ValidResourceID(input.ResourceID) || input.Authorization == "" || input.OrganizationID == "" {
		return ReadResponse{}, fmt.Errorf("%w: read input", contracts.ErrContract)
	}
	binding, err := newBinding()
	if err != nil {
		return ReadResponse{}, ErrUnavailable
	}
	request := contracts.ReadGrantRequest{
		ExposureID: artifact.ExposureID(), ExposureVersion: artifact.ExposureVersion(),
		ArtifactDigest: artifact.ArtifactDigest(), ResourceID: input.ResourceID, RequestBinding: binding,
	}
	if descriptor, ok := artifact.Operation(); ok {
		request.OperationID = descriptor.ID
	}
	decision, err := s.grant.Read(ctx, request, input.Authorization, input.OrganizationID, s.appKey)
	if err != nil {
		return ReadResponse{}, mapDependencyError(err)
	}
	now := s.now()
	if !decision.ExpiresAt.After(now) {
		return ReadResponse{}, ErrConflict
	}
	if err := decision.ValidateAgainst(request, now); err != nil {
		return ReadResponse{}, err
	}
	if !decision.Allowed {
		return ReadResponse{}, ErrDenied
	}
	object, err := s.source.ReadObject(ctx, artifact, input.ResourceID)
	if err != nil {
		return ReadResponse{}, mapDependencyError(err)
	}
	if object.ResourceID != input.ResourceID {
		return ReadResponse{}, fmt.Errorf("%w: source resource mismatch", contracts.ErrContract)
	}
	if err := artifact.ValidateSourceObject(object); err != nil {
		return ReadResponse{}, err
	}
	data, err := artifact.Project(object.RawResource)
	if err != nil {
		return ReadResponse{}, err
	}
	if !decision.ExpiresAt.After(s.now()) {
		return ReadResponse{}, ErrConflict
	}
	return ReadResponse{
		ExposureID: artifact.ExposureID(), ExposureVersion: artifact.ExposureVersion(),
		ArtifactDigest: artifact.ArtifactDigest(), ResourceID: object.ResourceID,
		ResourceVersion: object.ResourceVersion, SourceRevision: object.SourceRevision, Data: data,
	}, nil
}

func newBinding() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes[:]), nil
}

func mapDependencyError(err error) error {
	if code, ok := dependency.ErrorCode(err); ok {
		switch code {
		case "unauthenticated":
			return ErrUnauthenticated
		case "access_denied":
			return ErrDenied
		case "not_found", "precondition_failed", "digest_mismatch", "contract_mismatch":
			return ErrConflict
		case "upstream_failure", "malformed_response":
			return ErrUnavailable
		case "invalid_request", "invalid_remote_error":
			return fmt.Errorf("%w: dependency response", contracts.ErrContract)
		}
	}
	return ErrUnavailable
}
