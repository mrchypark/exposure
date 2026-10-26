// Package source routes immutable artifact source kinds to fixed clients.
package source

import (
	"context"
	"fmt"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/readartifact"
)

type Compos interface {
	ReadObject(context.Context, contracts.SourceReadRequest) (contracts.SourceReadResponse, error)
}

type Router struct {
	compos Compos
}

func New(compos Compos) *Router {
	return &Router{compos: compos}
}

func (r *Router) ReadObject(ctx context.Context, artifact readartifact.Artifact, resourceID string) (contracts.SourceObject, error) {
	switch artifact.SourceKind() {
	case readartifact.SourceComposObject:
		if r.compos == nil {
			return contracts.SourceObject{}, fmt.Errorf("Compos source is not configured")
		}
		request := contracts.SourceReadRequest{
			Namespace: artifact.Namespace(), ObjectType: artifact.ObjectType(),
			SchemaDigest: artifact.SchemaDigest(), ResourceID: resourceID,
		}
		object, err := r.compos.ReadObject(ctx, request)
		if err != nil {
			return contracts.SourceObject{}, err
		}
		version := object.ResourceVersion
		return contracts.SourceObject{
			Kind: readartifact.SourceComposObject, ResourceID: object.ResourceID,
			ResourceVersion: &version, RawResource: object.RawResource,
		}, nil
	default:
		return contracts.SourceObject{}, fmt.Errorf("unsupported source kind")
	}
}
