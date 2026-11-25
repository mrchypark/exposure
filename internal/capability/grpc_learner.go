package capability

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/mrchypark/exposure/internal/pdppb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const grpcPayloadLimit = 2 << 20

type grpcLearner struct {
	conn    *grpc.ClientConn
	client  pdppb.PolicyDecisionPointClient
	timeout time.Duration
}

// ConfigureGRPCLearner is called only with the validated startup configuration.
func (p *Proxy) ConfigureGRPCLearner(target, caFile, serverName string, timeout time.Duration) error {
	var creds credentials.TransportCredentials
	if caFile == "" {
		creds = insecure.NewCredentials()
	} else {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return fmt.Errorf("read learner CA: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return fmt.Errorf("invalid learner CA")
		}
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName})
	}
	conn, err := grpc.NewClient("passthrough:///"+target, grpc.WithTransportCredentials(creds), grpc.WithNoProxy(), grpc.WithDisableRetry(), grpc.WithDisableServiceConfig(), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(grpcPayloadLimit+1024), grpc.MaxCallSendMsgSize(grpcPayloadLimit+1024)))
	if err != nil {
		return err
	}
	p.learner = &grpcLearner{conn: conn, client: pdppb.NewPolicyDecisionPointClient(conn), timeout: timeout}
	return nil
}

func (p *Proxy) CloseGRPCLearner() error {
	if p.learner != nil {
		return p.learner.conn.Close()
	}
	return nil
}

func (g *grpcLearner) catalog(ctx context.Context, provider, appKey string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("x-grant-app-auth-key", appKey))
	r, err := g.client.GetHttpCatalog(ctx, &pdppb.CatalogRequest{ProviderId: provider})
	if err != nil {
		return nil, err
	}
	if len(r.GetCatalogJson()) > grpcPayloadLimit {
		return nil, fmt.Errorf("catalog exceeds limit")
	}
	return r.GetCatalogJson(), nil
}

func (g *grpcLearner) decide(ctx context.Context, evidence []byte, authorization, org, appKey string) ([]byte, int, error) {
	if len(evidence) > grpcPayloadLimit {
		return nil, 0, fmt.Errorf("evidence exceeds limit")
	}
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	md := metadata.Pairs("x-grant-app-auth-key", appKey, "authorization", authorization)
	if org != "" {
		md.Set("x-organization-id", org)
	}
	ctx = metadata.NewOutgoingContext(ctx, md)
	r, err := g.client.DecideHttp(ctx, &pdppb.DecisionRequest{EvidenceJson: evidence})
	if err != nil {
		switch status.Code(err) {
		case codes.Unauthenticated:
			return nil, 401, err
		case codes.PermissionDenied:
			return nil, 403, err
		default:
			return nil, 0, err
		}
	}
	if len(r.GetDecisionJson()) > 64<<10 {
		return nil, 0, fmt.Errorf("decision exceeds limit")
	}
	return r.GetDecisionJson(), 0, nil
}
