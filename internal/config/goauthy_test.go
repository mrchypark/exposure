package config

import (
	"strings"
	"testing"
)

func TestGoauthyCredentialConfigIsPinned(t *testing.T) {
	for _, applicationID := range []string{"", "ied-management", "ied-data"} {
		valid := ProxyConfig{CredentialMode: "goauthy", GoauthyIssuer: "https://gw-auth.dev.conalog.com", GoauthyApplicationID: applicationID}
		if err := valid.ValidateCredentialMode(); err != nil {
			t.Fatalf("application=%q: %v", applicationID, err)
		}
	}
	valid := ProxyConfig{CredentialMode: "goauthy", GoauthyIssuer: "https://gw-auth.dev.conalog.com", GoauthyApplicationID: "ied-management"}
	for _, mutate := range []func(*ProxyConfig){
		func(c *ProxyConfig) { c.GoauthyIssuer = "" },
		func(c *ProxyConfig) { c.GoauthyIssuer = "http://gw-auth.dev.conalog.com" },
		func(c *ProxyConfig) { c.GoauthyIssuer = "https://gw-auth.dev.conalog.com/" },
		func(c *ProxyConfig) { c.GoauthyIssuer = "https://gw-auth.dev.conalog.com:443" },
		func(c *ProxyConfig) { c.GoauthyIssuer = "https://GW-auth.dev.conalog.com" },
		func(c *ProxyConfig) { c.GoauthyIssuer = "https://gw-auth.dev.conalog.com?x=1" },
		func(c *ProxyConfig) { c.GoauthyApplicationID = "ied data" },
		func(c *ProxyConfig) { c.PocketBaseIssuer = "https://other.example" },
		func(c *ProxyConfig) { c.CredentialMode = "rauthy" },
	} {
		c := valid
		mutate(&c)
		if c.ValidateCredentialMode() == nil {
			t.Fatalf("invalid Goauthy configuration accepted: %+v", c)
		}
	}
}

func TestGoauthyUserProfileConfigIsExplicitAndDistinct(t *testing.T) {
	valid := ProxyConfig{CredentialMode: "goauthy", GoauthyIssuer: "https://issuer.example", GoauthyUserClientID: "fixture-client", GoauthyUserResourceAudience: "https://resource.example"}
	if valid.ValidateCredentialMode() != nil {
		t.Fatal("valid user profile rejected")
	}
	for _, mutate := range []func(*ProxyConfig){
		func(c *ProxyConfig) { c.GoauthyUserClientID = "" },
		func(c *ProxyConfig) { c.GoauthyUserResourceAudience = "" },
		func(c *ProxyConfig) { c.GoauthyUserResourceAudience = c.GoauthyUserClientID },
		func(c *ProxyConfig) { c.GoauthyUserClientID = " fixture-client" },
		func(c *ProxyConfig) { c.GoauthyUserResourceAudience = "resource\n" },
		func(c *ProxyConfig) { c.GoauthyUserClientID = strings.Repeat("a", 513) },
		func(c *ProxyConfig) { c.GoauthyUserResourceAudience = string([]byte{0xff}) },
		func(c *ProxyConfig) { c.CredentialMode = "rauthy" },
		func(c *ProxyConfig) { c.CredentialMode = "pocketbase" },
	} {
		c := valid
		mutate(&c)
		if c.ValidateCredentialMode() == nil {
			t.Fatal("invalid user profile accepted")
		}
	}
}
