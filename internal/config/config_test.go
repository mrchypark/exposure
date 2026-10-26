package config

import (
	"strings"
	"testing"
)

func setRequiredOrigins(t *testing.T) {
	t.Helper()
	t.Setenv("EXPOSURE_GRANT_LEARNER_URL", "http://127.0.0.1:8080")
}

func setProxyOrigins(t *testing.T) {
	t.Helper()
	setRequiredOrigins(t)
	t.Setenv("EXPOSURE_PROXY_ENABLED", "true")
	t.Setenv("EXPOSURE_PROVIDER_AUTHORIZATION_MODE", "forward-user")
	t.Setenv("EXPOSURE_DATA_ADDR", ":8082")
	t.Setenv("EXPOSURE_ADMIN_ADDR", ":8080")
	t.Setenv("EXPOSURE_PROVIDER_ID", "example-data")
	t.Setenv("EXPOSURE_PEP_CLIENT_ID", "pep-example-data")
	t.Setenv("EXPOSURE_PROVIDER_ORIGIN", "https://independent-api.example:9449")
	t.Setenv("EXPOSURE_EXPECTED_CATALOG_DIGEST", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("EXPOSURE_GRANT_APP_AUTH_KEY", "opaque")
	t.Setenv("EXPOSURE_AUTHN_LIMITER_KEY", "opaque-limiter-key")
}

func TestLoadAcceptsConfiguredOrigins(t *testing.T) {
	for _, target := range []string{"EXPOSURE_GRANT_LEARNER_URL", "EXPOSURE_PROVIDER_ORIGIN"} {
		t.Run(target, func(t *testing.T) {
			for _, valid := range []string{
				"http://127.0.0.1:8080", "http://127.0.0.1:49152", "http://127.0.0.1",
				"http://policy.default.svc.cluster.local:9097", "https://api.example.com:9443",
				"https://api.example.com", "https://10.20.30.40:9443", "https://203.0.113.10",
				"https://[2001:db8::1]:9443", "http://10.0.0.1:8080", "http://127.0.0.2:8080",
				"http://169.254.169.254:8080", "http://policy-engine:1", "https://data-store:65535",
				"http://grant.default:8080", "http://policy.example.com:8080",
				"http://grant.a.b.svc.cluster.local:8080", "http://[::1]:8080", "https://[::1]",
				"http://grant.grant-compos-exposure-v1.svc.cluster.local:8080",
				"http://grant.a.svc.cluster.local:8080", "http://grant." + strings.Repeat("a", 63) + ".svc.cluster.local:8080",
				"http://api.example:80", "https://api.example:443",
			} {
				t.Run("valid_"+valid, func(t *testing.T) {
					setProxyOrigins(t)
					t.Setenv(target, valid)
					cfg, err := Load()
					got := cfg.LearnerURL
					if target == "EXPOSURE_PROVIDER_ORIGIN" {
						got = cfg.Proxy.Origin
					}
					if err != nil || got != valid {
						t.Fatalf("origin=%q err=%v", got, err)
					}
				})
			}
			for _, invalid := range []string{
				"", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:08080",
				"https://api.example:", "https://api.example:+443", "http://api.example:abc",
				"http://grant.Default.svc.cluster.local:8080", "http://grant.-bad.svc.cluster.local:8080",
				"http://grant.bad-.svc.cluster.local:8080", "http://grant.a_b.svc.cluster.local:8080",
				"https://[2001:0db8::1]:9443", "http://grant..svc.cluster.local:8080",
				"http://grant." + strings.Repeat("a", 64) + ".svc.cluster.local:8080",
				"http://" + strings.Repeat("a.", 127) + "com", "https://Policy.example.com",
				"http://api.example/", "http://api.example/%2e", "http://api.example?x=1",
				"http://api.example?", "http://api.example#x", "http://api.example#",
				"http://user@api.example", "https://user:password@api.example", "http:api.example",
				"HTTP://api.example", "ftp://api.example", "//api.example", "api.example",
				"http://api.example.", "http://gr%C3%A1nt.example:8080",
				"http://[::ffff:127.0.0.1]:8080", "http://[::1%25lo0]:8080",
				"http://2001:db8::1", "http://[127.0.0.1]:8080", " https://api.example",
			} {
				t.Run("invalid_"+invalid, func(t *testing.T) {
					setProxyOrigins(t)
					t.Setenv(target, invalid)
					if _, err := Load(); err == nil {
						t.Fatal("noncanonical origin accepted")
					}
				})
			}
		})
	}
}

func TestLoadProxyModeUsesConfiguredProvider(t *testing.T) {
	setProxyOrigins(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// An operations-configured endpoint is captured at startup, not selected by
	// subsequent environment changes or catalog/request contents.
	t.Setenv("EXPOSURE_PROVIDER_ORIGIN", "https://other.example:9448")
	t.Setenv("EXPOSURE_GRANT_LEARNER_URL", "https://other-policy.example:8448")
	if cfg.Proxy.Origin != "https://independent-api.example:9449" || cfg.LearnerURL != "http://127.0.0.1:8080" {
		t.Fatal("startup origins changed")
	}
}
