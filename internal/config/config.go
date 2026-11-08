package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type Config struct {
	ListenAddr, LearnerURL                                                                        string
	LearnerGRPCTarget, LearnerGRPCCAFile, LearnerGRPCServerName                                   string
	BusinessGRPCFile                                                                              string
	StreamGRPCFile                                                                                string
	ReadHeaderTimeout, ReadTimeout, WriteTimeout, IdleTimeout, DependencyTimeout, ShutdownTimeout time.Duration
	MaxHeaderBytes, MaxResponseBytes, MaxConcurrent                                               int
	Proxy                                                                                         ProxyConfig
}

// ProxyConfig is deliberately deployment-local. In particular, Origin is not
// part of Grant's capability catalog and can never be selected by a caller.
// Public-authn quotas are per Exposure process instance; deployment-wide
// enforcement needs an explicitly selected shared limiter and is not implied.
type ProxyConfig struct {
	AuthorizationMode, UpstreamToken                                   string
	Enabled                                                            bool
	DataAddr, AdminAddr                                                string
	ProviderID, PepClientID, Origin, ExpectedCatalogDigest, AppAuthKey string
	AuthnLimiterKey                                                    string
	CredentialMode, PocketBaseCollectionID                             string
	PocketBaseIssuer, PocketBaseApplicationID                          string
	GoauthyIssuer, GoauthyApplicationID                                string
	GoauthyUserClientID, GoauthyUserResourceAudience                   string
	MaxRequestBytes, MaxResponseBytes                                  int64
	PublicAuthnGlobalCapacity, PublicAuthnPeerCapacity                 int
	PublicAuthnGlobalRefill, PublicAuthnPeerRefill                     time.Duration
}

func Load() (Config, error) {
	c := Config{ListenAddr: env("EXPOSURE_ADDR", ":8080"), LearnerURL: os.Getenv("EXPOSURE_GRANT_LEARNER_URL"), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, DependencyTimeout: 5 * time.Second, ShutdownTimeout: 15 * time.Second, MaxHeaderBytes: 32 << 10, MaxResponseBytes: 4 << 20, MaxConcurrent: 128}
	c.LearnerGRPCTarget = os.Getenv("EXPOSURE_GRANT_GRPC_TARGET")
	c.LearnerGRPCCAFile = os.Getenv("EXPOSURE_GRANT_GRPC_CA_FILE")
	c.LearnerGRPCServerName = os.Getenv("EXPOSURE_GRANT_GRPC_SERVER_NAME")
	c.BusinessGRPCFile = os.Getenv("EXPOSURE_BUSINESS_GRPC_FILE")
	c.StreamGRPCFile = os.Getenv("EXPOSURE_STREAM_GRPC_FILE")
	var err error
	for _, x := range []struct {
		name string
		dst  *time.Duration
	}{{"EXPOSURE_READ_HEADER_TIMEOUT", &c.ReadHeaderTimeout}, {"EXPOSURE_READ_TIMEOUT", &c.ReadTimeout}, {"EXPOSURE_WRITE_TIMEOUT", &c.WriteTimeout}, {"EXPOSURE_IDLE_TIMEOUT", &c.IdleTimeout}, {"EXPOSURE_DEPENDENCY_TIMEOUT", &c.DependencyTimeout}, {"EXPOSURE_SHUTDOWN_TIMEOUT", &c.ShutdownTimeout}} {
		if v := os.Getenv(x.name); v != "" {
			*x.dst, err = time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf("%s: %w", x.name, err)
			}
		}
	}
	for _, x := range []struct {
		name string
		dst  *int
	}{{"EXPOSURE_MAX_HEADER_BYTES", &c.MaxHeaderBytes}, {"EXPOSURE_MAX_RESPONSE_BYTES", &c.MaxResponseBytes}, {"EXPOSURE_MAX_CONCURRENT", &c.MaxConcurrent}} {
		if v := os.Getenv(x.name); v != "" {
			*x.dst, err = strconv.Atoi(v)
			if err != nil || *x.dst <= 0 {
				return Config{}, fmt.Errorf("%s must be positive", x.name)
			}
		}
	}
	c.Proxy = ProxyConfig{
		AuthorizationMode: os.Getenv("EXPOSURE_PROVIDER_AUTHORIZATION_MODE"),
		Enabled:           os.Getenv("EXPOSURE_PROXY_ENABLED") == "true",
		DataAddr:          env("EXPOSURE_DATA_ADDR", ":8082"), AdminAddr: env("EXPOSURE_ADMIN_ADDR", c.ListenAddr),
		ProviderID: os.Getenv("EXPOSURE_PROVIDER_ID"), PepClientID: os.Getenv("EXPOSURE_PEP_CLIENT_ID"),
		Origin: os.Getenv("EXPOSURE_PROVIDER_ORIGIN"), ExpectedCatalogDigest: os.Getenv("EXPOSURE_EXPECTED_CATALOG_DIGEST"),
		AppAuthKey: os.Getenv("EXPOSURE_GRANT_APP_AUTH_KEY"), AuthnLimiterKey: os.Getenv("EXPOSURE_AUTHN_LIMITER_KEY"),
		CredentialMode: env("EXPOSURE_CREDENTIAL_MODE", "rauthy"), PocketBaseCollectionID: os.Getenv("EXPOSURE_POCKETBASE_COLLECTION_ID"),
		PocketBaseIssuer: os.Getenv("EXPOSURE_POCKETBASE_ISSUER"), PocketBaseApplicationID: os.Getenv("EXPOSURE_POCKETBASE_APPLICATION_ID"),
		GoauthyIssuer: os.Getenv("EXPOSURE_GOAUTHY_ISSUER"), GoauthyApplicationID: os.Getenv("EXPOSURE_GOAUTHY_APPLICATION_ID"),
		GoauthyUserClientID: os.Getenv("EXPOSURE_GOAUTHY_USER_CLIENT_ID"), GoauthyUserResourceAudience: os.Getenv("EXPOSURE_GOAUTHY_USER_RESOURCE_AUDIENCE"),
		MaxRequestBytes: int64(c.MaxResponseBytes), MaxResponseBytes: int64(c.MaxResponseBytes),
		PublicAuthnGlobalCapacity: 64, PublicAuthnPeerCapacity: 8, PublicAuthnGlobalRefill: time.Second, PublicAuthnPeerRefill: time.Second,
	}
	if v := os.Getenv("EXPOSURE_MAX_REQUEST_BYTES"); v != "" {
		n, parseErr := strconv.ParseInt(v, 10, 64)
		if parseErr != nil || n <= 0 || n > int64(c.MaxResponseBytes) {
			return Config{}, fmt.Errorf("EXPOSURE_MAX_REQUEST_BYTES must be positive and at most response limit")
		}
		c.Proxy.MaxRequestBytes = n
	}
	for _, item := range []struct {
		name   string
		target *int
	}{{"EXPOSURE_PUBLIC_AUTHN_GLOBAL_CAPACITY", &c.Proxy.PublicAuthnGlobalCapacity}, {"EXPOSURE_PUBLIC_AUTHN_PEER_CAPACITY", &c.Proxy.PublicAuthnPeerCapacity}} {
		if v := os.Getenv(item.name); v != "" {
			n, parseErr := strconv.Atoi(v)
			if parseErr != nil || n <= 0 || n > 4096 {
				return Config{}, fmt.Errorf("%s must be between 1 and 4096", item.name)
			}
			*item.target = n
		}
	}
	for _, item := range []struct {
		name   string
		target *time.Duration
	}{{"EXPOSURE_PUBLIC_AUTHN_GLOBAL_REFILL", &c.Proxy.PublicAuthnGlobalRefill}, {"EXPOSURE_PUBLIC_AUTHN_PEER_REFILL", &c.Proxy.PublicAuthnPeerRefill}} {
		if v := os.Getenv(item.name); v != "" {
			d, parseErr := time.ParseDuration(v)
			if parseErr != nil || d <= 0 || d > time.Hour {
				return Config{}, fmt.Errorf("%s must be positive and at most one hour", item.name)
			}
			*item.target = d
		}
	}
	if c.LearnerGRPCTarget == "" {
		if c.LearnerGRPCCAFile != "" || c.LearnerGRPCServerName != "" {
			return Config{}, fmt.Errorf("gRPC TLS settings require a target")
		}
		if err = validateFixedOrigin(c.LearnerURL); err != nil {
			return Config{}, fmt.Errorf("learner URL: %w", err)
		}
	} else {
		if !c.Proxy.Enabled {
			return Config{}, fmt.Errorf("gRPC learner requires capability proxy mode")
		}
		host, port, splitErr := net.SplitHostPort(c.LearnerGRPCTarget)
		n, portErr := strconv.Atoi(port)
		if splitErr != nil || host == "" || portErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || strings.ContainsAny(host, "/% \t\r\n") {
			return Config{}, fmt.Errorf("invalid gRPC learner target")
		}
		ip := net.ParseIP(host)
		if c.LearnerGRPCCAFile == "" && c.LearnerGRPCServerName == "" {
			if ip == nil || !ip.IsLoopback() {
				return Config{}, fmt.Errorf("plaintext gRPC requires literal loopback")
			}
		} else if c.LearnerGRPCCAFile == "" || c.LearnerGRPCServerName == "" || strings.ContainsAny(c.LearnerGRPCServerName, "/ \t\r\n") {
			return Config{}, fmt.Errorf("gRPC TLS requires CA file and server name")
		}
		if c.LearnerURL != "" {
			if err = validateFixedOrigin(c.LearnerURL); err != nil {
				return Config{}, fmt.Errorf("learner URL: %w", err)
			}
		}
	}
	if c.BusinessGRPCFile != "" && (!c.Proxy.Enabled || c.LearnerGRPCTarget == "" || c.Proxy.CredentialMode != "goauthy" || c.Proxy.GoauthyUserClientID == "" || c.Proxy.GoauthyUserResourceAudience == "") {
		return Config{}, fmt.Errorf("business gRPC requires capability mode, gRPC learner and Goauthy USER profile")
	}
	if c.StreamGRPCFile != "" && (!c.Proxy.Enabled || c.LearnerGRPCTarget == "" || c.Proxy.CredentialMode != "goauthy" || c.Proxy.GoauthyUserClientID == "" || c.Proxy.GoauthyUserResourceAudience == "") {
		return Config{}, fmt.Errorf("stream gRPC requires capability mode, gRPC learner and Goauthy USER profile")
	}
	if c.DependencyTimeout >= c.WriteTimeout {
		return Config{}, fmt.Errorf("dependency timeout must be below write timeout")
	}
	if c.Proxy.Enabled {
		if tokenFile := os.Getenv("EXPOSURE_PROVIDER_TOKEN_FILE"); tokenFile != "" {
			b, err := os.ReadFile(tokenFile)
			if err != nil {
				return Config{}, fmt.Errorf("cannot read provider token file")
			}
			c.Proxy.UpstreamToken = strings.TrimSpace(string(b))
		}
		if err := c.Proxy.ValidateUpstreamAuthorization(); err != nil {
			return Config{}, err
		}
		if err := c.Proxy.ValidateCredentialMode(); err != nil {
			return Config{}, err
		}
		if c.Proxy.ProviderID == "" || c.Proxy.PepClientID == "" || c.Proxy.AppAuthKey == "" || c.Proxy.AuthnLimiterKey == "" || !isDigest(c.Proxy.ExpectedCatalogDigest) {
			return Config{}, fmt.Errorf("proxy provider ID, PEP client ID, app auth key, limiter key, and expected catalog digest are required")
		}
		if c.Proxy.AuthorizationMode != "forward-user" && c.Proxy.AuthorizationMode != "service-token" {
			return Config{}, fmt.Errorf("proxy requires an explicit provider authorization mode")
		}
		if c.Proxy.DataAddr == c.Proxy.AdminAddr {
			return Config{}, fmt.Errorf("proxy data and admin listeners must differ")
		}
		if err := validateFixedOrigin(c.Proxy.Origin); err != nil {
			return Config{}, fmt.Errorf("provider origin: %w", err)
		}
	}
	return c, nil
}

func (c ProxyConfig) ValidateUpstreamAuthorization() error {
	if c.AuthorizationMode == "service-token" {
		if c.UpstreamToken == "" || strings.ContainsAny(c.UpstreamToken, " \t\r\n") {
			return fmt.Errorf("service-token mode requires a raw provider token")
		}
	} else if (c.AuthorizationMode != "" && c.AuthorizationMode != "forward-user") || c.UpstreamToken != "" {
		return fmt.Errorf("invalid provider authorization configuration")
	}
	return nil
}

func (c ProxyConfig) ValidateCredentialMode() error {
	if c.GoauthyUserClientID != "" || c.GoauthyUserResourceAudience != "" {
		if c.CredentialMode != "goauthy" {
			return fmt.Errorf("Goauthy user profile requires goauthy credential mode")
		}
		if c.GoauthyUserClientID == c.GoauthyUserResourceAudience {
			return fmt.Errorf("Goauthy user profile requires distinct client and resource metadata")
		}
		for _, value := range []string{c.GoauthyUserClientID, c.GoauthyUserResourceAudience} {
			if value == "" || len(value) > 512 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.IndexFunc(value, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
				return fmt.Errorf("Goauthy user profile requires valid client and resource metadata")
			}
		}
	}
	switch c.CredentialMode {
	case "", "rauthy":
		if c.PocketBaseCollectionID != "" || c.PocketBaseIssuer != "" || c.PocketBaseApplicationID != "" || c.GoauthyIssuer != "" || c.GoauthyApplicationID != "" {
			return fmt.Errorf("credential mode has provider-specific configuration")
		}
	case "pocketbase":
		if c.GoauthyIssuer != "" || c.GoauthyApplicationID != "" {
			return fmt.Errorf("Goauthy configuration requires goauthy credential mode")
		}
		if !PocketBaseID(c.PocketBaseCollectionID) || c.PocketBaseApplicationID == "" || strings.ContainsAny(c.PocketBaseApplicationID, " \t\r\n") {
			return fmt.Errorf("pocketbase credential mode requires fixed collection and application IDs")
		}
		u, err := url.Parse(c.PocketBaseIssuer)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.Host != strings.ToLower(u.Host) || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.HasSuffix(u.Host, ":") || (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
			return fmt.Errorf("pocketbase issuer must be a canonical origin without a path or default port")
		}
	case "goauthy":
		if c.PocketBaseCollectionID != "" || c.PocketBaseIssuer != "" || c.PocketBaseApplicationID != "" || strings.ContainsAny(c.GoauthyApplicationID, " \t\r\n") {
			return fmt.Errorf("invalid goauthy credential configuration")
		}
		u, err := url.Parse(c.GoauthyIssuer)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Host != strings.ToLower(u.Host) || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.HasSuffix(u.Host, ":") || u.Port() == "443" {
			return fmt.Errorf("goauthy issuer must be a canonical HTTPS origin without a path or default port")
		}
	default:
		return fmt.Errorf("unsupported credential mode")
	}
	return nil
}

func PocketBaseID(v string) bool {
	if v == "" {
		return false
	}
	for _, c := range v {
		if c != '_' && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func isDigest(v string) bool {
	if len(v) != 71 || !strings.HasPrefix(v, "sha256:") || v != strings.ToLower(v) {
		return false
	}
	for _, r := range v[7:] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func validateFixedOrigin(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || raw == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" || u.RawPath != "" || u.Hostname() == "" || strings.HasSuffix(u.Host, ":") {
		return fmt.Errorf("must be a canonical fixed HTTP(S) origin without credentials, path, query, or fragment")
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return fmt.Errorf("must use a canonical port between 1 and 65535")
		}
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if host != ip.String() {
			return fmt.Errorf("must use canonical IP spelling")
		}
	} else {
		labels := strings.Split(host, ".")
		if len(host) > 253 {
			return fmt.Errorf("hostname is too long")
		}
		for _, label := range labels {
			if !dnsLabel.MatchString(label) {
				return fmt.Errorf("must use a canonical lowercase DNS hostname")
			}
		}
	}
	canonicalHost := host
	if strings.Contains(host, ":") {
		canonicalHost = "[" + host + "]"
	}
	if port != "" {
		canonicalHost = net.JoinHostPort(host, port)
	}
	if raw != u.Scheme+"://"+canonicalHost {
		return fmt.Errorf("must use a canonical fixed origin")
	}
	return nil
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
