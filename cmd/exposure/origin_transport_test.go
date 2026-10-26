package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
)

func TestRuntimeClientsVerifyConfiguredTLSOrigin(t *testing.T) {
	var proxyCalls, upstreamCalls atomic.Int64
	envProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer envProxy.Close()
	t.Setenv("HTTP_PROXY", envProxy.URL)
	t.Setenv("HTTPS_PROXY", envProxy.URL)
	t.Setenv("ALL_PROXY", envProxy.URL)
	t.Setenv("NO_PROXY", "")
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.WriteString(w, "verified HTTPS")
	}))
	// Expected handshake failures should not pollute the test output.
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.StartTLS()
	defer origin.Close()
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	base, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Use a certificate-covered DNS name so success cannot be attributed to
	// net/http's special loopback handling of environment proxies.
	if len(origin.Certificate().DNSNames) == 0 {
		t.Fatal("TLS fixture has no DNS identity")
	}
	trustedName := origin.Certificate().DNSNames[0]
	for name, newClient := range map[string]func(config.Config) *http.Client{
		"read": internalHTTPClient, "capability": proxyHTTPClient,
	} {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name, host string
				trust      bool
				want       string
			}{
				{"trusted", trustedName, true, "success"},
				{"untrusted", trustedName, false, "authority"},
				{"name mismatch", "unrelated.invalid", true, "hostname"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					client := newClient(config.Config{DependencyTimeout: 2 * time.Second})
					defer client.CloseIdleConnections()
					transport := client.Transport.(*http.Transport)
					if transport.Proxy != nil {
						t.Fatal("runtime honored environment proxy")
					}
					if tc.trust {
						// Test-only private trust roots; normal verification remains enabled.
						// Production still uses standard system trust, with no insecure option.
						transport.TLSClientConfig = &tls.Config{RootCAs: roots}
					}
					transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, network, origin.Listener.Addr().String())
					}
					endpoint := *base
					endpoint.Host = net.JoinHostPort(tc.host, base.Port())
					response, err := client.Get(endpoint.String())
					switch tc.want {
					case "success":
						if err != nil {
							t.Fatal(err)
						}
						defer response.Body.Close()
						body, readErr := io.ReadAll(response.Body)
						if readErr != nil || response.StatusCode != 200 || string(body) != "verified HTTPS" {
							t.Fatalf("HTTPS response status=%d read=%v", response.StatusCode, readErr)
						}
					case "authority":
						if response != nil {
							response.Body.Close()
						}
						var untrusted x509.UnknownAuthorityError
						if !errors.As(err, &untrusted) {
							t.Fatalf("want certificate trust failure, got %v", err)
						}
					case "hostname":
						if response != nil {
							response.Body.Close()
						}
						var mismatch x509.HostnameError
						if !errors.As(err, &mismatch) {
							t.Fatalf("want hostname failure, got %v", err)
						}
					}
				})
			}
		})
	}
	if proxyCalls.Load() != 0 || upstreamCalls.Load() != 2 {
		t.Fatalf("proxy=%d upstream=%d", proxyCalls.Load(), upstreamCalls.Load())
	}
}
