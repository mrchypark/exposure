// Package grantclient calls the fixed Grant simple-read authorization endpoint.
package grantclient

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/dependency"
	"github.com/mrchypark/exposure/internal/operation"
)

type Client struct {
	dependency *dependency.Client
	timeout    time.Duration
}

func New(base string, httpClient *http.Client, timeout time.Duration, maxResponseBytes int64) *Client {
	return &Client{dependency: dependency.New(base, httpClient, maxResponseBytes), timeout: timeout}
}

func (c *Client) Read(ctx context.Context, request contracts.ReadGrantRequest, authorization, organizationID, appKey string) (contracts.ReadGrantResponse, error) {
	var response contracts.ReadGrantResponse
	if err := request.Validate(); err != nil || authorization == "" || organizationID == "" || appKey == "" {
		return response, fmt.Errorf("read: %w", contracts.ErrContract)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	path := "/api/v1/exposure-authz/read"
	if request.OperationID != "" {
		descriptor, ok := operation.Lookup(request.OperationID)
		if !ok {
			return response, fmt.Errorf("read: %w", contracts.ErrContract)
		}
		wire := contracts.OperationDecisionRequestV2{
			OperationID: descriptor.ID, OperationVersion: descriptor.Version,
			ContractDigest: descriptor.ContractDigest,
			Resource:       contracts.OperationResourceV2{ID: request.ResourceID}, RequestBinding: request.RequestBinding,
		}
		var decision contracts.OperationDecisionResponseV2
		_, err := c.dependency.DoGrantRead(ctx, "/api/v2/exposure-authz/decide", authorization, organizationID, appKey, wire, &decision)
		if err != nil {
			return response, fmt.Errorf("read: %w", err)
		}
		if err := decision.ValidateAgainst(wire, descriptor, time.Now().UTC()); err != nil {
			return response, fmt.Errorf("read: %w", err)
		}
		return contracts.ReadGrantResponse{
			Allowed: decision.Allowed, Reason: decision.Reason,
			ExposureID: request.ExposureID, ExposureVersion: request.ExposureVersion,
			ArtifactDigest: request.ArtifactDigest, ResourceID: request.ResourceID,
			RequestBinding: request.RequestBinding, OperationID: descriptor.ID,
			ProviderID: descriptor.ProviderID, ActionID: descriptor.ActionID, ResourceType: descriptor.ResourceType,
			PrincipalDigest: decision.PrincipalDigest, IssuedAt: decision.IssuedAt, ExpiresAt: decision.ExpiresAt,
		}, nil
	}
	_, err := c.dependency.DoGrantRead(ctx, path, authorization, organizationID, appKey, request, &response)
	if err != nil {
		return response, fmt.Errorf("read: %w", err)
	}
	return response, nil
}
