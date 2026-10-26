package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func configurationBody(t *testing.T, mutate func(map[string]any)) ([]byte, http.Header) {
	t.Helper()
	v := map[string]any{"version": "goauthy.client-configuration.v1", "issuer": issuer, "client_id": clientID, "client_kind": "bootstrap", "enabled": true, "confidential": true, "redirect_uris": []string{callback}, "grant_types": []string{"authorization_code", "refresh_token"}, "scopes": []string{"openid", "goauthy.read"}, "default_scopes": []string{}, "audience": []string{audience}, "default_aud": []string{audience}}
	if mutate != nil {
		mutate(v)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b, configurationHeaders(b)
}
func configurationHeaders(b []byte) http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("ETag", fmt.Sprintf(`"sha256:%x"`, sha256.Sum256(b)))
	return h
}
func TestGrantCompatibilityRequiresConfigurationContract(t *testing.T) {
	b, h := configurationBody(t, nil)
	if err := validateConfiguration(b, h); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"old version":            func(v map[string]any) { v["version"] = "v0" },
		"wrong issuer":           func(v map[string]any) { v["issuer"] = "https://other.invalid" },
		"wrong client":           func(v map[string]any) { v["client_id"] = "other-client" },
		"wrong kind":             func(v map[string]any) { v["client_kind"] = "managed" },
		"disabled":               func(v map[string]any) { v["enabled"] = false },
		"public":                 func(v map[string]any) { v["confidential"] = false },
		"DNS loopback redirect":  func(v map[string]any) { v["redirect_uris"] = []string{"http://localhost:5555/callback"} },
		"wrong resource":         func(v map[string]any) { v["audience"] = []string{"https://other.invalid"} },
		"wrong default resource": func(v map[string]any) { v["default_aud"] = []string{"https://other.invalid"} },
		"missing code grant":     func(v map[string]any) { v["grant_types"] = []string{"refresh_token"} },
		"missing refresh grant":  func(v map[string]any) { v["grant_types"] = []string{"authorization_code"} },
		"missing scope":          func(v map[string]any) { v["scopes"] = []string{"openid"} },
		"duplicate scope":        func(v map[string]any) { v["scopes"] = []string{"openid", "goauthy.read", "openid"} },
		"bad default scope":      func(v map[string]any) { v["default_scopes"] = []string{"unadmitted"} },
		"null array":             func(v map[string]any) { v["default_scopes"] = nil },
		"missing field":          func(v map[string]any) { delete(v, "default_scopes") },
		"secret field":           func(v map[string]any) { v["client_secret"] = "must-not-be-reported" },
	} {
		t.Run(name, func(t *testing.T) {
			b, h := configurationBody(t, mutate)
			err := validateConfiguration(b, h)
			if err == nil || strings.Contains(err.Error(), "must-not-be-reported") {
				t.Fatal("unsafe metadata accepted or response body exposed")
			}
		})
	}
	duplicate := append(append([]byte(nil), b[:len(b)-1]...), []byte(`,"enabled":true}`)...)
	if validateConfiguration(duplicate, configurationHeaders(duplicate)) == nil {
		t.Fatal("duplicate field accepted")
	}
	for _, change := range []func(http.Header){
		func(h http.Header) { h.Set("ETag", `"sha256:wrong"`) },
		func(h http.Header) { h.Del("ETag") },
		func(h http.Header) { h.Add("ETag", h.Get("ETag")) },
		func(h http.Header) { h.Set("Cache-Control", "public") },
		func(h http.Header) { h.Set("Content-Type", "text/plain") },
	} {
		bad := h.Clone()
		change(bad)
		if validateConfiguration(b, bad) == nil {
			t.Fatal("bad ETag/cache/media accepted")
		}
	}
}

type fixtureRoundTrip func(*http.Request) (*http.Response, error)

func (f fixtureRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestMissingRealRouteCannotDeclareGrantCompatible(t *testing.T) {
	f := &fixture{secret: "synthetic-unit-test-secret", client: &http.Client{Transport: fixtureRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Path != "/oidc/client-configuration" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("incorrect client configuration request")
		}
		return &http.Response{StatusCode: 404, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("route absent"))}, nil
	})}}
	if err := f.configuration(); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatal("missing route did not fail compatibility gate")
	}
}
