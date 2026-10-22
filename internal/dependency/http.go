package dependency

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/mrchypark/exposure/internal/contracts"
)

type Client struct {
	base string
	http *http.Client
	max  int64
}

type RemoteError struct {
	Status int
	Code   string
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("dependency status %d: %s", e.Status, e.Code)
}
func ErrorCode(err error) (string, bool) {
	var e *RemoteError
	if !errors.As(err, &e) {
		return "", false
	}
	return e.Code, true
}

func New(base string, h *http.Client, max int64) *Client {
	return &Client{strings.TrimRight(base, "/"), h, max}
}
func (c *Client) Do(ctx context.Context, method, path string, in, out any) (int, error) {
	return c.do(ctx, method, path, nil, in, out, false)
}
func (c *Client) DoGrantRead(ctx context.Context, path, authorization, organizationID, appKey string, in, out any) (int, error) {
	return c.do(ctx, http.MethodPost, path, http.Header{"Authorization": {authorization}, "X-Organization-ID": {organizationID}, "X-Grant-App-Auth-Key": {appKey}}, in, out, true)
}
func (c *Client) do(ctx context.Context, method, path string, headers http.Header, in, out any, grantStatusErrors bool) (int, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, fmt.Errorf("marshal request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("dependency request: %w", err)
	}
	if grantStatusErrors && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		_ = resp.Body.Close()
		return resp.StatusCode, grantStatusError(resp.StatusCode)
	}
	defer func() { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)); _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, c.max+1))
	if err != nil {
		return resp.StatusCode, err
	}
	if int64(len(b)) > c.max {
		return resp.StatusCode, fmt.Errorf("dependency response exceeds limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, decodeRemoteError(resp.StatusCode, b)
	}
	if out != nil {
		mediaType, _, parseErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if parseErr != nil || mediaType != "application/json" {
			return resp.StatusCode, fmt.Errorf("dependency content type")
		}
		if err = contracts.StrictDecode(b, out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func grantStatusError(status int) error {
	code := "upstream_failure"
	switch status {
	case http.StatusUnauthorized:
		code = "unauthenticated"
	case http.StatusForbidden:
		code = "access_denied"
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		code = "invalid_request"
	}
	return &RemoteError{Status: status, Code: code}
}

func decodeRemoteError(status int, b []byte) error {
	type wire struct {
		SchemaVersion int    `json:"schemaVersion"`
		ErrorCode     string `json:"errorCode"`
		Message       string `json:"message,omitempty"`
		CorrelationID string `json:"correlationId,omitempty"`
	}
	var w wire
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return &RemoteError{Status: status, Code: "invalid_remote_error"}
	}
	if err := contracts.StrictDecode(b, &w); err != nil || w.SchemaVersion != 1 || w.ErrorCode == "" {
		return &RemoteError{Status: status, Code: "invalid_remote_error"}
	}
	_, messagePresent := raw["message"]
	if !messagePresent || w.Message == "" {
		return &RemoteError{Status: status, Code: "invalid_remote_error"}
	}
	if !oneOf(w.ErrorCode, "invalid_request", "digest_mismatch", "precondition_failed", "not_found", "contract_mismatch", "internal_error") {
		return &RemoteError{Status: status, Code: "invalid_remote_error"}
	}
	return &RemoteError{Status: status, Code: w.ErrorCode}
}
func oneOf(v string, allowed ...string) bool {
	for _, x := range allowed {
		if v == x {
			return true
		}
	}
	return false
}
func NewHTTPClient(timeout time.Duration, transport *http.Transport) *http.Client {
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
