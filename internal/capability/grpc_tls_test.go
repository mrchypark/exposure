package capability

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/pdppb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestGRPCLearnerTLSVerification(t *testing.T) {
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := fixture.TLS.Certificates[0]
	fixture.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	otherDER, err := x509.CreateCertificate(rand.Reader, other, other, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	goodCA := filepath.Join(dir, "ca.pem")
	badCA := filepath.Join(dir, "other.pem")
	if err := os.WriteFile(goodCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherDER}), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	pdppb.RegisterPolicyDecisionPointServer(server, &testPDP{t: t})
	go server.Serve(listener)
	defer server.Stop()
	for _, tc := range []struct {
		name, ca, server string
		ok               bool
	}{
		{"trusted", goodCA, "example.com", true},
		{"wrong name", goodCA, "wrong.invalid", false},
		{"wrong ca", badCA, "example.com", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{}
			if err := p.ConfigureGRPCLearner(listener.Addr().String(), tc.ca, tc.server, time.Second); err != nil {
				t.Fatal(err)
			}
			defer p.CloseGRPCLearner()
			_, err := p.learner.catalog(context.Background(), "provider", "key")
			if (err == nil) != tc.ok {
				t.Fatalf("catalog error=%v; want success %v", err, tc.ok)
			}
		})
	}
}
