package config

import "testing"

func TestLearnerGRPCConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, target, ca, server string
		proxy, ok                bool
	}{
		{"loopback", "127.0.0.1:8081", "", "", true, true},
		{"ipv6 loopback", "[::1]:8081", "", "", true, true},
		{"tls", "learner.example:443", "/ca.pem", "learner.example", true, true},
		{"plaintext hostname", "localhost:8081", "", "", true, false},
		{"plaintext remote", "10.0.0.1:8081", "", "", true, false},
		{"partial tls", "127.0.0.1:8081", "/ca.pem", "", true, false},
		{"simple read", "127.0.0.1:8081", "", "", false, false},
		{"target injection", "dns:///learner:443", "/ca.pem", "learner", true, false},
		{"orphan tls", "", "/ca.pem", "learner", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.proxy {
				setProxyOrigins(t)
			} else {
				setRequiredOrigins(t)
				t.Setenv("EXPOSURE_PROXY_ENABLED", "false")
			}
			t.Setenv("EXPOSURE_GRANT_GRPC_TARGET", tc.target)
			t.Setenv("EXPOSURE_GRANT_GRPC_CA_FILE", tc.ca)
			t.Setenv("EXPOSURE_GRANT_GRPC_SERVER_NAME", tc.server)
			_, err := Load()
			if (err == nil) != tc.ok {
				t.Fatalf("Load() error = %v, want success %v", err, tc.ok)
			}
		})
	}
}

func TestBusinessGRPCRequiresExplicitProfile(t *testing.T) {
	for _, tc := range []struct {
		name, file, target, mode, client, audience string
		want                                       bool
	}{
		{"off", "", "", "rauthy", "", "", true},
		{"no learner", "fixture", "", "goauthy", "client", "resource", false},
		{"no user profile", "fixture", "127.0.0.1:8081", "goauthy", "", "", false},
		{"configured", "fixture", "127.0.0.1:8081", "goauthy", "client", "resource", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setProxyOrigins(t)
			t.Setenv("EXPOSURE_BUSINESS_GRPC_FILE", tc.file)
			t.Setenv("EXPOSURE_GRANT_GRPC_TARGET", tc.target)
			t.Setenv("EXPOSURE_CREDENTIAL_MODE", tc.mode)
			t.Setenv("EXPOSURE_GOAUTHY_USER_CLIENT_ID", tc.client)
			t.Setenv("EXPOSURE_GOAUTHY_USER_RESOURCE_AUDIENCE", tc.audience)
			if tc.mode == "goauthy" {
				t.Setenv("EXPOSURE_GOAUTHY_ISSUER", "https://issuer.example")
			}
			_, err := Load()
			if (err == nil) != tc.want {
				t.Fatalf("Load()=%v want success=%v", err, tc.want)
			}
		})
	}
}
