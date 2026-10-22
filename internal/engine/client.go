// Package engine reads private Compos objects over the same-Pod loopback channel.
package engine

import (
	"context"
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

func (c *Client) ReadObject(ctx context.Context, request contracts.SourceReadRequest) (contracts.SourceReadResponse, error) {
	var response contracts.SourceReadResponse
	if err := request.Validate(); err != nil {
		return response, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	_, err := c.dependency.Do(ctx, http.MethodPost, "/internal/v1/objects:read", request, &response)
	if err == nil {
		err = response.ValidateAgainst(request)
	}
	return response, err
}
