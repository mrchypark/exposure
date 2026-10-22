// Package patchdata reads one fixed PocketBase plants record after Grant allows it.
package patchdata

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/dependency"
	"github.com/mrchypark/exposure/internal/readartifact"
)

var bearerToken = regexp.MustCompile(`^[A-Za-z0-9._~+/\-]+=*$`)

const (
	plantPath = "/api/internal/exposure/v1/plants/"
)

type Client struct {
	base                 string
	http                 *http.Client
	timeout              time.Duration
	max                  int64
	serviceAuthorization string
}

type plantRecord struct {
	ID      *string `json:"id"`
	Name    *string `json:"name"`
	Updated *string `json:"updated"`
}

func New(base string, client *http.Client, timeout time.Duration, maxResponseBytes int64, serviceToken string) (*Client, error) {
	return newClient(base, client, timeout, maxResponseBytes, serviceToken)
}

func newClient(base string, client *http.Client, timeout time.Duration, maxResponseBytes int64, serviceToken string) (*Client, error) {
	if !bearerToken.MatchString(serviceToken) || strings.Trim(serviceToken, "=") == "" {
		return nil, fmt.Errorf("invalid Patch Data service token")
	}
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{base: strings.TrimRight(base, "/"), http: &clone, timeout: timeout, max: maxResponseBytes, serviceAuthorization: "Bearer " + serviceToken}, nil
}

func (c *Client) ReadPlant(ctx context.Context, resourceID string) (contracts.SourceObject, error) {
	if !readartifact.ValidPatchDataResourceID(resourceID) {
		return contracts.SourceObject{}, fmt.Errorf("%w: invalid Patch Data read", contracts.ErrContract)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+plantPath+resourceID, nil)
	if err != nil {
		return contracts.SourceObject{}, fmt.Errorf("create Patch Data request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.serviceAuthorization)
	resp, err := c.http.Do(req)
	if err != nil {
		return contracts.SourceObject{}, &dependency.RemoteError{Code: "upstream_failure"}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return contracts.SourceObject{}, &dependency.RemoteError{Status: resp.StatusCode, Code: "access_denied"}
	case http.StatusNotFound:
		return contracts.SourceObject{}, &dependency.RemoteError{Status: resp.StatusCode, Code: "not_found"}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return contracts.SourceObject{}, &dependency.RemoteError{Status: resp.StatusCode, Code: "upstream_failure"}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.max+1))
	if err != nil || int64(len(body)) > c.max {
		return contracts.SourceObject{}, &dependency.RemoteError{Status: resp.StatusCode, Code: "malformed_response"}
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || rejectDuplicateKeys(body) != nil {
		return contracts.SourceObject{}, &dependency.RemoteError{Status: resp.StatusCode, Code: "malformed_response"}
	}
	var record plantRecord
	if err := contracts.StrictDecode(body, &record); err != nil {
		return contracts.SourceObject{}, &dependency.RemoteError{Status: resp.StatusCode, Code: "malformed_response"}
	}
	if record.ID == nil || record.Name == nil || record.Updated == nil || *record.ID != resourceID || *record.Updated == "" {
		return contracts.SourceObject{}, &dependency.RemoteError{Status: resp.StatusCode, Code: "malformed_response"}
	}
	return contracts.SourceObject{
		Kind: readartifact.SourcePatchDataPlant, ResourceID: *record.ID, SourceRevision: *record.Updated,
		RawResource: map[string]any{"id": *record.ID, "name": *record.Name, "updated": *record.Updated},
	}, nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func scanValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			name, keyOK := key.(string)
			if err != nil || !keyOK || seen[name] {
				return fmt.Errorf("duplicate or invalid object key")
			}
			seen[name] = true
			if err := scanValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("invalid delimiter")
	}
}
