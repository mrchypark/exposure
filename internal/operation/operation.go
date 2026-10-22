// Package operation defines the closed, server-owned operation mappings that
// Exposure may authorize and execute. Callers never supply these policy keys.
package operation

import (
	"fmt"
	"strings"
)

type Semantics string

const Read Semantics = "read"

// ExecutorToken is an opaque, compiled capability. It cannot encode a caller
// selected backend host, path, method, or query.
type ExecutorToken struct{ id uint8 }

// Descriptor binds one public data operation to its exact Grant policy tuple.
// It intentionally contains no backend URL, path, method, or query.
type Descriptor struct {
	ID             string
	Version        int64
	ContractDigest string
	Semantics      Semantics
	ProviderID     string
	ActionID       string
	ResourceType   string
	Executor       ExecutorToken
}

// Request is the complete caller-independent operation tuple that is frozen
// before Grant authorization. It deliberately has no backend URL, path,
// method, query, filter, fields, expand, projection, or schema selector.
type Request struct {
	OperationID      string
	OperationVersion int64
	ContractDigest   string
	ResourceType     string
	ResourceID       string
}

type Registry struct{ descriptors map[string]Descriptor }

func NewRegistry(descriptors ...Descriptor) (Registry, error) {
	indexed := make(map[string]Descriptor, len(descriptors))
	for _, descriptor := range descriptors {
		if descriptor.ID == "" || descriptor.Version <= 0 || descriptor.ContractDigest == "" ||
			descriptor.ProviderID == "" || descriptor.ActionID == "" || descriptor.ResourceType == "" ||
			descriptor.Executor.id == 0 {
			return Registry{}, fmt.Errorf("invalid operation descriptor")
		}
		if _, exists := indexed[descriptor.ID]; exists {
			return Registry{}, fmt.Errorf("duplicate operation descriptor")
		}
		indexed[descriptor.ID] = descriptor
	}
	return Registry{descriptors: indexed}, nil
}

func (r Registry) Lookup(id string) (Descriptor, bool) {
	descriptor, ok := r.descriptors[id]
	return descriptor, ok
}

var compiledRegistry = mustRegistry(patchDataPlantGetDescriptor())

func mustRegistry(descriptors ...Descriptor) Registry {
	registry, err := NewRegistry(descriptors...)
	if err != nil {
		panic(err)
	}
	return registry
}

// Lookup resolves only operations implemented by this binary. Returning the
// descriptor by value prevents a caller from mutating the registered mapping.
func Lookup(id string) (Descriptor, bool) { return compiledRegistry.Lookup(id) }

// Resolve fails closed unless every caller-bound contract field matches the
// one compiled descriptor. The returned value is a copy and cannot mutate the
// registry.
func Resolve(request Request) (Descriptor, error) {
	descriptor, ok := Lookup(request.OperationID)
	if !ok {
		return Descriptor{}, fmt.Errorf("unknown operation")
	}
	if request.OperationVersion != descriptor.Version ||
		request.ContractDigest != descriptor.ContractDigest ||
		request.ResourceType != descriptor.ResourceType ||
		request.ResourceID == "" ||
		strings.TrimSpace(request.ResourceID) != request.ResourceID {
		return Descriptor{}, fmt.Errorf("operation contract mismatch")
	}
	return descriptor, nil
}
