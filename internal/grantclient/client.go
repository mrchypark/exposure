// Package grantclient calls the fixed Grant simple-read authorization endpoint.
package grantclient

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/dependency"
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
	_, err := c.dependency.DoGrantRead(ctx, path, authorization, organizationID, appKey, request, &response)
	if err != nil {
		return response, fmt.Errorf("read: %w", err)
	}
	return response, nil
}
