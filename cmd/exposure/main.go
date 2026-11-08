package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mrchypark/exposure/internal/capability"
	"github.com/mrchypark/exposure/internal/config"
	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/dependency"
	"github.com/mrchypark/exposure/internal/engine"
	"github.com/mrchypark/exposure/internal/grantclient"
	"github.com/mrchypark/exposure/internal/httpapi"
	"github.com/mrchypark/exposure/internal/readartifact"
	"github.com/mrchypark/exposure/internal/readiness"
	"github.com/mrchypark/exposure/internal/service"
	"github.com/mrchypark/exposure/internal/source"
)

func main() {
	if err := run(); err != nil {
		slog.Error("exposure stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if cfg.Proxy.Enabled {
		return runCapabilityProxy(cfg)
	}

	grant := grantclient.New(cfg.LearnerURL, internalHTTPClient(cfg), cfg.DependencyTimeout, int64(cfg.MaxResponseBytes))
	artifactPath, appKey := os.Getenv("EXPOSURE_READ_ARTIFACTS_FILE"), os.Getenv("EXPOSURE_GRANT_APP_AUTH_KEY")
	if artifactPath == "" || appKey == "" {
		return fmt.Errorf("EXPOSURE_READ_ARTIFACTS_FILE and EXPOSURE_GRANT_APP_AUTH_KEY are required")
	}
	artifacts, err := loadReadArtifacts(artifactPath)
	if err != nil {
		return err
	}

	compos := engine.New("http://127.0.0.1:7878", internalHTTPClient(cfg), cfg.DependencyTimeout, int64(cfg.MaxResponseBytes))
	svc, err := service.New(artifacts, grant, source.New(compos), appKey)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           httpapi.New(svc, readiness.New(), int64(cfg.MaxResponseBytes), cfg.MaxConcurrent).Handler(),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errch := make(chan error, 1)
	go func() {
		ln, listenErr := net.Listen("tcp", srv.Addr)
		if listenErr != nil {
			errch <- listenErr
			return
		}
		errch <- srv.Serve(ln)
	}()

	var serveErr error
	select {
	case serveErr = <-errch:
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil {
		return err
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}

// runCapabilityProxy serves only the configured provider's pinned catalog.
func runCapabilityProxy(cfg config.Config) error {
	p, err := capability.New(cfg.Proxy, cfg.LearnerURL, proxyHTTPClient(cfg), cfg.MaxConcurrent)
	if err != nil {
		return err
	}
	if cfg.LearnerGRPCTarget != "" {
		if err := p.ConfigureGRPCLearner(cfg.LearnerGRPCTarget, cfg.LearnerGRPCCAFile, cfg.LearnerGRPCServerName, cfg.DependencyTimeout); err != nil {
			return err
		}
		defer p.CloseGRPCLearner()
	}
	var business *capability.BusinessServer
	if cfg.BusinessGRPCFile != "" {
		business, err = p.NewBusinessServer(cfg.BusinessGRPCFile)
		if err != nil {
			return err
		}
		defer business.Close()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	refresh := func() {
		if err := p.Refresh(ctx); err != nil {
			slog.Warn("capability catalog unavailable", "error", err)
		}
	}
	refresh()
	go func() {
		ticker := time.NewTicker(minDuration(cfg.DependencyTimeout, time.Second*30))
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()
	data := &http.Server{Addr: cfg.Proxy.DataAddr, Handler: p.Handler(), ReadHeaderTimeout: cfg.ReadHeaderTimeout, ReadTimeout: cfg.ReadTimeout, WriteTimeout: cfg.WriteTimeout, IdleTimeout: cfg.IdleTimeout, MaxHeaderBytes: cfg.MaxHeaderBytes}
	admin := &http.Server{Addr: cfg.Proxy.AdminAddr, Handler: proxyAdmin(p, business), ReadHeaderTimeout: cfg.ReadHeaderTimeout, ReadTimeout: cfg.ReadTimeout, WriteTimeout: cfg.WriteTimeout, IdleTimeout: cfg.IdleTimeout, MaxHeaderBytes: cfg.MaxHeaderBytes}
	errs := make(chan error, 3)
	serve := func(s *http.Server) {
		ln, e := net.Listen("tcp", s.Addr)
		if e != nil {
			errs <- e
			return
		}
		errs <- s.Serve(ln)
	}
	go serve(data)
	go serve(admin)
	if business != nil {
		go func() { errs <- business.Serve() }()
	}
	select {
	case err = <-errs:
	case <-ctx.Done():
	}
	if business != nil {
		business.Close()
	}
	shutdown, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	dataErr := data.Shutdown(shutdown)
	adminErr := admin.Shutdown(shutdown)
	if dataErr != nil {
		return dataErr
	}
	if adminErr != nil {
		return adminErr
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func proxyAdmin(p *capability.Proxy, business *capability.BusinessServer) http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !p.Ready() || (business != nil && !business.Ready(r.Context())) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"ready":false}`))
			return
		}
		_, _ = w.Write([]byte(`{"ready":true}`))
	})
	return m
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func loadReadArtifacts(path string) ([]readartifact.Artifact, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var raw []json.RawMessage
	if err := contracts.StrictDecode(b, &raw); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("read artifacts empty")
	}
	out := make([]readartifact.Artifact, 0, len(raw))
	seen := map[string]bool{}
	for _, item := range raw {
		artifact, err := readartifact.Parse(item)
		if err != nil {
			return nil, err
		}
		if seen[artifact.ExposureID()] {
			return nil, fmt.Errorf("duplicate read artifact")
		}
		seen[artifact.ExposureID()] = true
		out = append(out, artifact)
	}
	return out, nil
}

func internalHTTPClient(cfg config.Config) *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: cfg.DependencyTimeout,
	}
	return dependency.NewHTTPClient(cfg.DependencyTimeout, transport)
}

// The wildcard PEP has a transport separate from legacy dependencies: it never
// honors proxy environment variables, never decompresses, never redirects and
// disables keep-alive retry opportunities.  Each provider request is one send.
func proxyHTTPClient(cfg config.Config) *http.Client {
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: false, DisableCompression: true, DisableKeepAlives: true, ResponseHeaderTimeout: cfg.DependencyTimeout}
	return &http.Client{Timeout: cfg.DependencyTimeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
