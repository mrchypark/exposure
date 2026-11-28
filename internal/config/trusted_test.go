package config

import "testing"

func TestTrustedCredentialMode(t *testing.T) {
	valid := ProxyConfig{CredentialMode: "trusted", TrustedGatewayKey: "gateway-secret"}
	if err := valid.ValidateCredentialMode(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid.TrustedSubjectHeaderName() != "X-Operable-Subject" {
		t.Fatalf("unexpected default subject header: %q", valid.TrustedSubjectHeaderName())
	}
	if valid.TrustedAudienceName() != "gateway" {
		t.Fatalf("unexpected default audience: %q", valid.TrustedAudienceName())
	}

	custom := ProxyConfig{
		CredentialMode:       "trusted",
		TrustedGatewayKey:    "gateway-secret",
		TrustedSubjectHeader: "x-grant-subject",
		TrustedAudience:      "operable-gateway",
	}
	if err := custom.ValidateCredentialMode(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if custom.TrustedSubjectHeaderName() != "X-Grant-Subject" {
		t.Fatalf("unexpected canonical subject header: %q", custom.TrustedSubjectHeaderName())
	}

	for _, mutate := range []func(*ProxyConfig){
		func(c *ProxyConfig) { c.TrustedGatewayKey = "" },
		func(c *ProxyConfig) { c.TrustedGatewayKey = "bad key" },
		func(c *ProxyConfig) { c.TrustedGatewayKey = "bad\nkey" },
		func(c *ProxyConfig) { c.TrustedSubjectHeader = "Authorization" },
		func(c *ProxyConfig) { c.TrustedSubjectHeader = "X-Grant-Gateway-Key" },
		func(c *ProxyConfig) { c.TrustedSubjectHeader = "Bad Header" },
		func(c *ProxyConfig) { c.TrustedAudience = "bad audience" },
		func(c *ProxyConfig) { c.GoauthyIssuer = "https://auth.example" },
		func(c *ProxyConfig) { c.PocketBaseIssuer = "http://127.0.0.1:8090" },
	} {
		cfg := valid
		mutate(&cfg)
		if cfg.ValidateCredentialMode() == nil {
			t.Fatalf("expected invalid trusted config to fail: %+v", cfg)
		}
	}

	for _, other := range []ProxyConfig{
		{CredentialMode: "rauthy", TrustedGatewayKey: "gateway-secret"},
		{CredentialMode: "goauthy", GoauthyIssuer: "https://auth.example", TrustedSubjectHeader: "X-Operable-Subject"},
		{CredentialMode: "pocketbase", PocketBaseIssuer: "http://127.0.0.1:8090", PocketBaseCollectionID: "_pb_users_auth_", PocketBaseApplicationID: "app", TrustedAudience: "trusted"},
	} {
		if other.ValidateCredentialMode() == nil {
			t.Fatalf("expected non-trusted mode with trusted fields to fail: %+v", other)
		}
	}
}

func TestLoadTrustedCredentialMode(t *testing.T) {
	t.Setenv("EXPOSURE_GRANT_LEARNER_URL", "http://127.0.0.1:9000")
	t.Setenv("EXPOSURE_PROXY_ENABLED", "true")
	t.Setenv("EXPOSURE_PROVIDER_AUTHORIZATION_MODE", "forward-user")
	t.Setenv("EXPOSURE_PROVIDER_ID", "provider")
	t.Setenv("EXPOSURE_PEP_CLIENT_ID", "pep")
	t.Setenv("EXPOSURE_PROVIDER_ORIGIN", "http://127.0.0.1:9001")
	t.Setenv("EXPOSURE_EXPECTED_CATALOG_DIGEST", "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	t.Setenv("EXPOSURE_GRANT_APP_AUTH_KEY", "app-key")
	t.Setenv("EXPOSURE_AUTHN_LIMITER_KEY", "limiter-key")
	t.Setenv("EXPOSURE_CREDENTIAL_MODE", "trusted")
	t.Setenv("EXPOSURE_TRUSTED_GATEWAY_KEY", "gateway-key")
	t.Setenv("EXPOSURE_TRUSTED_SUBJECT_HEADER", "X-Operable-Subject")
	t.Setenv("EXPOSURE_TRUSTED_AUDIENCE", "operable-gateway")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Proxy.CredentialMode != "trusted" || cfg.Proxy.TrustedGatewayKey != "gateway-key" || cfg.Proxy.TrustedSubjectHeaderName() != "X-Operable-Subject" || cfg.Proxy.TrustedAudienceName() != "operable-gateway" {
		t.Fatalf("unexpected loaded trusted config: %+v", cfg.Proxy)
	}
}
