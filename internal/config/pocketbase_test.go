package config

import "testing"

func TestPocketBaseCredentialConfig(t *testing.T) {
	valid := ProxyConfig{CredentialMode: "pocketbase", PocketBaseIssuer: "http://127.0.0.1:8091", PocketBaseCollectionID: "_pb_users_auth_", PocketBaseApplicationID: "app-patch-auth"}
	if err := valid.ValidateCredentialMode(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ProxyConfig){
		func(c *ProxyConfig) { c.CredentialMode = "guessed" },
		func(c *ProxyConfig) { c.CredentialMode = "rauthy" },
		func(c *ProxyConfig) { c.PocketBaseCollectionID = "" },
		func(c *ProxyConfig) { c.PocketBaseCollectionID = "a/b" },
		func(c *ProxyConfig) { c.PocketBaseApplicationID = "" },
		func(c *ProxyConfig) { c.PocketBaseIssuer = "https://auth.example:443" },
		func(c *ProxyConfig) { c.PocketBaseIssuer = "http://auth.example/" },
		func(c *ProxyConfig) { c.PocketBaseIssuer = "http://AUTH.example" },
		func(c *ProxyConfig) { c.PocketBaseIssuer = "http://auth.example?route=other" },
	} {
		c := valid
		mutate(&c)
		if c.ValidateCredentialMode() == nil {
			t.Fatalf("invalid accepted: %+v", c)
		}
	}
}

func TestUpstreamCredentialMode(t *testing.T) {
	for _, c := range []ProxyConfig{
		{AuthorizationMode: "service-token"},
		{AuthorizationMode: "service-token", UpstreamToken: "Bearer token"},
		{AuthorizationMode: "forward-user", UpstreamToken: "secret"},
		{AuthorizationMode: "unknown"},
	} {
		if c.ValidateUpstreamAuthorization() == nil {
			t.Fatal("invalid service credential configuration accepted")
		}
	}
	if err := (ProxyConfig{AuthorizationMode: "service-token", UpstreamToken: "synthetic-token"}).ValidateUpstreamAuthorization(); err != nil {
		t.Fatal(err)
	}
}
