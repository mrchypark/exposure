package config

import "testing"

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
