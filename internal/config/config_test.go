package config

import (
	"strings"
	"testing"
)

func setRequiredOrigins(t *testing.T) {
	t.Helper()
	t.Setenv("EXPOSURE_GRANT_LEARNER_URL", "http://127.0.0.1:8080")
	t.Setenv("EXPOSURE_PATCH_DATA_URL", "http://127.0.0.1:8090")
}

func TestLoadAcceptsOnlyExactGrantInternalOrigins(t *testing.T) {
	setRequiredOrigins(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Fatalf("default listen address=%q", cfg.ListenAddr)
	}
	for _, valid := range []string{
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
		"http://grant.grant-compos-exposure-v1.svc.cluster.local:8080",
		"http://grant.a.svc.cluster.local:8080",
		"http://grant." + strings.Repeat("a", 63) + ".svc.cluster.local:8080",
	} {
		t.Run("valid_"+valid, func(t *testing.T) {
			setRequiredOrigins(t)
			t.Setenv("EXPOSURE_GRANT_LEARNER_URL", valid)
			cfg, err := Load()
			if err != nil || cfg.LearnerURL != valid {
				t.Fatalf("learner=%q err=%v", cfg.LearnerURL, err)
			}
		})
	}
	for _, invalid := range []string{
		"", "http://127.0.0.1", "http://127.0.0.1:8081", "http://10.0.0.1:8080",
		"http://127.0.0.2:8080", "http://169.254.169.254:8080", "http://grant:8080", "http://grant.default:8080",
		"http://other.default.svc.cluster.local:8080", "http://grant.Default.svc.cluster.local:8080",
		"http://grant.-bad.svc.cluster.local:8080", "http://grant.bad-.svc.cluster.local:8080",
		"http://grant.a_b.svc.cluster.local:8080", "http://grant.a.b.svc.cluster.local:8080",
		"http://grant..svc.cluster.local:8080", "http://grant." + strings.Repeat("a", 64) + ".svc.cluster.local:8080",
		"https://grant.default.svc.cluster.local:8080", "http://grant.default.svc.cluster.local:8080/",
		"http://grant.default.svc.cluster.local:8080/%2e", "http://grant.default.svc.cluster.local:8080?x=1",
		"http://grant.default.svc.cluster.local:8080#x", "http://user@grant.default.svc.cluster.local:8080",
		"http:grant.default.svc.cluster.local:8080", "HTTP://grant.default.svc.cluster.local:8080",
		"http://grant.default.svc.cluster.local.:8080", "http://gr%C3%A1nt.default.svc.cluster.local:8080",
		"http://[::ffff:127.0.0.1]:8080", "http://[::1%25lo0]:8080",
	} {
		t.Run("invalid_"+invalid, func(t *testing.T) {
			setRequiredOrigins(t)
			t.Setenv("EXPOSURE_GRANT_LEARNER_URL", invalid)
			if _, err := Load(); err == nil {
				t.Fatal("unsafe Grant origin accepted")
			}
		})
	}
}

func TestLoadAcceptsOnlyExactPatchDataInternalOrigins(t *testing.T) {
	for _, valid := range []string{
		"http://127.0.0.1:8090",
		"http://[::1]:8090",
		"http://patch-data.patch.svc.cluster.local:8090",
		"http://patch-data.grant-compos-exposure-v1.svc.cluster.local:8090",
		"http://patch-data." + strings.Repeat("a", 63) + ".svc.cluster.local:8090",
	} {
		t.Run("valid_"+valid, func(t *testing.T) {
			setRequiredOrigins(t)
			t.Setenv("EXPOSURE_PATCH_DATA_URL", valid)
			cfg, err := Load()
			if err != nil || cfg.PatchDataURL != valid {
				t.Fatalf("patchData=%q err=%v", cfg.PatchDataURL, err)
			}
		})
	}
	for _, invalid := range []string{
		"",
		"http://127.0.0.1:8091",
		"http://127.0.0.2:8090",
		"http://patch-data.patch.svc.cluster.local:8091",
		"http://other.patch.svc.cluster.local:8090",
		"http://patch-data.patch.svc.cluster.local:8090/",
		"http://patch-data.patch.svc.cluster.local:8090/%2f",
		"https://patch-data.patch.svc.cluster.local:8090",
		"http://patch-data.patch.svc.cluster.local:8090/api",
		"http://patch-data.patch.svc.cluster.local:8090?x=1",
		"http://patch-data.patch.svc.cluster.local:8090#x",
		"http://user@patch-data.patch.svc.cluster.local:8090",
		"http://patch-data.example.com:8090",
		"http://10.0.0.1:8090",
		"http://169.254.169.254:8090",
		"http://patch-data.Patch.svc.cluster.local:8090",
		"http://patch-data.*.svc.cluster.local:8090",
		"http://patch-data." + strings.Repeat("a", 64) + ".svc.cluster.local:8090",
		"http://patch-data.patch.svc.cluster.local.:8090",
		"http://[::ffff:127.0.0.1]:8090",
	} {
		t.Run(invalid, func(t *testing.T) {
			setRequiredOrigins(t)
			t.Setenv("EXPOSURE_PATCH_DATA_URL", invalid)
			if _, err := Load(); err == nil {
				t.Fatal("unsafe Patch Data origin accepted")
			}
		})
	}
}

func TestLoadCarriesPatchDataServiceTokenWithoutLoggingOrParsingIt(t *testing.T) {
	setRequiredOrigins(t)
	t.Setenv("EXPOSURE_PATCH_DATA_SERVICE_TOKEN", "opaque.service-token")
	cfg, err := Load()
	if err != nil || cfg.PatchDataServiceToken != "opaque.service-token" {
		t.Fatalf("token loaded=%t err=%v", cfg.PatchDataServiceToken != "", err)
	}
}

func TestLoadProxyModeDoesNotRequireLegacyPatchDataAdapter(t *testing.T) {
	t.Setenv("EXPOSURE_GRANT_LEARNER_URL", "http://127.0.0.1:8080")
	t.Setenv("EXPOSURE_PATCH_DATA_URL", "")
	t.Setenv("EXPOSURE_PROXY_ENABLED", "true")
	t.Setenv("EXPOSURE_PROVIDER_AUTHORIZATION_MODE", "forward-user")
	t.Setenv("EXPOSURE_DATA_ADDR", ":8082")
	t.Setenv("EXPOSURE_ADMIN_ADDR", ":8080")
	t.Setenv("EXPOSURE_PROVIDER_ID", "patch-data")
	t.Setenv("EXPOSURE_PEP_CLIENT_ID", "pep-patch-data")
	t.Setenv("EXPOSURE_PROVIDER_ORIGIN", "http://patch-data.example.svc.cluster.local:8090")
	t.Setenv("EXPOSURE_EXPECTED_CATALOG_DIGEST", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("EXPOSURE_GRANT_APP_AUTH_KEY", "opaque")
	t.Setenv("EXPOSURE_AUTHN_LIMITER_KEY", "opaque-limiter-key")
	if _, err := Load(); err != nil {
		t.Fatalf("proxy config: %v", err)
	}
}
