package capability

// This draft is restricted to an explicitly configured loopback test listener.
import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/pdppb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

// rawRPCCodec preserves the protobuf message bytes rather than re-marshalling.
type rawRPCCodec struct{}

func (rawRPCCodec) Name() string { return "proto" }
func (rawRPCCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.(*[]byte)
	if !ok {
		return nil, errors.New("raw message required")
	}
	return *b, nil
}
func (rawRPCCodec) Unmarshal(b []byte, v any) error {
	p, ok := v.(*[]byte)
	if !ok {
		return errors.New("raw message required")
	}
	*p = append((*p)[:0], b...)
	return nil
}

// businessDraft supports isolated tests only. Upstream authentication is not
// implemented and it must not be used across a production trust boundary.
type businessDraft struct {
	proxy       *Proxy
	upstream    *grpc.ClientConn
	descriptors map[string][]byte
	// Explicitly reviewed full-call resource assignments, not caller input.
	allowed    map[string]businessCapability
	catalogPin string
	maxBytes   int
	sem        chan struct{}
}

// Only an isolated literal-loopback test upstream is supported. The draft
// owns its connection so callers cannot install retry or hedging policies.
func newBusinessDraft(p *Proxy, target string, desc map[string][]byte, allowed map[string]businessCapability, pin string, max int) (*businessDraft, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || port == "" || max <= 0 || max > grpcPayloadLimit {
		return nil, errors.New("isolated loopback target required")
	}
	conn, err := grpc.NewClient("passthrough:///"+target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithNoProxy(), grpc.WithDisableRetry(), grpc.WithDisableServiceConfig())
	if err != nil {
		return nil, err
	}
	return &businessDraft{proxy: p, upstream: conn, descriptors: desc, allowed: allowed, catalogPin: pin, maxBytes: max, sem: make(chan struct{}, 32)}, nil
}

// A single constructor keeps size, concurrency and compression controls in
// place for every isolated draft server.
func (d *businessDraft) newServer() (*grpc.Server, error) {
	if d == nil || d.maxBytes <= 0 || d.sem == nil {
		return nil, errors.New("invalid draft")
	}
	return grpc.NewServer(grpc.StatsHandler(rejectCompressedStats{}), grpc.ForceServerCodec(rawRPCCodec{}), grpc.UnknownServiceHandler(d.handler), grpc.MaxRecvMsgSize(d.maxBytes), grpc.MaxSendMsgSize(d.maxBytes), grpc.MaxConcurrentStreams(32)), nil
}

type compressionKey struct{}
type compressionState struct{ state atomic.Uint32 }
type rejectCompressedStats struct{}

func (rejectCompressedStats) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return context.WithValue(ctx, compressionKey{}, &compressionState{})
}
func (rejectCompressedStats) HandleRPC(ctx context.Context, event stats.RPCStats) {
	if header, ok := event.(*stats.InHeader); ok {
		if s, ok := ctx.Value(compressionKey{}).(*compressionState); ok {
			if header.Compression == "" || header.Compression == "identity" {
				s.state.Store(1)
			} else {
				s.state.Store(2)
			}
		}
	}
}
func (rejectCompressedStats) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}
func (rejectCompressedStats) HandleConn(context.Context, stats.ConnStats) {}

func (d *businessDraft) handler(_ any, stream grpc.ServerStream) error {
	if d.proxy == nil || d.proxy.learner == nil || d.upstream == nil || d.maxBytes <= 0 || d.sem == nil {
		return status.Error(codes.Unavailable, "unavailable")
	}
	// The native transport cancels both RecvMsg calls on deadline; do not
	// spawn a reader goroutine that could outlive the request.
	deadline, ok := stream.Context().Deadline()
	now := time.Now()
	if !ok || !deadline.After(now) || deadline.Sub(now) > d.proxy.learner.timeout {
		return status.Error(codes.DeadlineExceeded, "bounded deadline required")
	}
	select {
	case d.sem <- struct{}{}:
		defer func() { <-d.sem }()
	default:
		return status.Error(codes.ResourceExhausted, "busy")
	}
	compression, ok := stream.Context().Value(compressionKey{}).(*compressionState)
	if !ok || compression.state.Load() != 1 {
		return status.Error(codes.InvalidArgument, "compression unsupported")
	}
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "unauthorized")
	}
	for k, values := range md {
		switch k {
		// grpc-go exposes the client's response-compression advertisement as
		// metadata. It is untrusted, ignored and never forwarded upstream.
		case ":authority", "content-type", "user-agent", "grpc-accept-encoding":
		case "authorization", "x-organization-id":
			if len(values) != 1 {
				return status.Error(codes.Unauthenticated, "unauthorized")
			}
		default:
			return status.Error(codes.InvalidArgument, "unsupported metadata")
		}
	}
	if len(md.Get("authorization")) != 1 || len(md.Get("x-organization-id")) != 1 {
		return status.Error(codes.Unauthenticated, "unauthorized")
	}
	request := &http.Request{Header: http.Header{}, URL: &url.URL{}}
	request.Header.Set("Authorization", strings.TrimSpace(md.Get("authorization")[0]))
	request.Header.Set("X-Organization-ID", md.Get("x-organization-id")[0])
	// Identity claims are hints; the learner independently verifies the bearer.
	auth, org, subject, audience, err := userBearerIdentity(request, d.proxy.cfg, false)
	if err != nil {
		return status.Error(codes.Unauthenticated, "unauthorized")
	}
	method, ok := grpc.MethodFromServerStream(stream)
	if !ok {
		return status.Error(codes.InvalidArgument, "invalid method")
	}
	ctx, cancel := context.WithTimeout(stream.Context(), d.proxy.learner.timeout)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("x-grant-app-auth-key", d.proxy.cfg.AppAuthKey))
	catalogResponse, err := d.proxy.learner.client.GetGrpcCatalog(ctx, &pdppb.CatalogRequest{ProviderId: d.proxy.cfg.ProviderID})
	if err != nil {
		return status.Error(codes.Unavailable, "unavailable")
	}
	now = time.Now().UTC()
	catalog, err := parseBusinessCatalog(catalogResponse.GetCatalogJson(), d.proxy.cfg.ProviderID, d.proxy.cfg.PepClientID, d.catalogPin, now)
	if err != nil {
		return status.Error(codes.Unavailable, "unavailable")
	}
	var selected *businessCapability
	for i := range catalog.Capabilities {
		cap := &catalog.Capabilities[i]
		if cap.Enabled && cap.FullMethod == method {
			selected = cap
			break
		}
	}
	approved, present := d.allowed[method]
	if selected == nil || !present || *selected != approved || selected.MaxMessageBytes > uint64(d.maxBytes) || validateBusinessMethod(d.descriptors[selected.DescriptorDigest], selected.DescriptorDigest, method) != nil {
		return status.Error(codes.PermissionDenied, "denied")
	}
	var body []byte
	if err := stream.RecvMsg(&body); err != nil || uint64(len(body)) > selected.MaxMessageBytes || len(body) > d.maxBytes {
		return status.Error(codes.InvalidArgument, "invalid request")
	}
	var extra []byte
	if err := stream.RecvMsg(&extra); err != io.EOF {
		return status.Error(codes.InvalidArgument, "unary request required")
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return status.Error(codes.Unavailable, "unavailable")
	}
	binding := base64.RawURLEncoding.EncodeToString(nonce[:])
	evidence := map[string]any{"wireVersion": 1, "providerId": catalog.ProviderID, "pepClientId": catalog.PepClientID, "pepPolicyRevision": catalog.PepPolicyRevision, "catalogGeneration": catalog.Generation, "catalogDigest": catalog.CatalogDigest, "capabilityId": selected.CapabilityID, "capabilityVersion": selected.Version, "contractDigest": selected.ContractDigest, "fullMethod": method, "descriptorDigest": selected.DescriptorDigest, "rpcKind": "unary", "resourceType": selected.ResourceType, "resourceId": selected.ResourceID, "messageDigest": shaBytes(body), "messageLength": len(body), "forwardedMetadataDigest": shaBytes(nil), "providerCredentialDigest": credentialDigest(auth), "providerCredential": map[string]string{"subject": subject, "audience": audience}, "requestBinding": binding}
	wire, err := json.Marshal(evidence)
	if err != nil || len(wire) > grpcPayloadLimit {
		return status.Error(codes.Unavailable, "unavailable")
	}
	decisionCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("x-grant-app-auth-key", d.proxy.cfg.AppAuthKey, "authorization", auth, "x-organization-id", org))
	decision, err := d.proxy.learner.client.DecideGrpc(decisionCtx, &pdppb.DecisionRequest{EvidenceJson: wire})
	if err != nil || len(decision.GetDecisionJson()) > 64<<10 {
		return status.Error(codes.Unavailable, "unavailable")
	}
	if !verifyBusinessReceipt(decision.GetDecisionJson(), evidence, selected.ActionID, org, catalog.ExpiresAt, time.Now().UTC()) {
		return status.Error(codes.PermissionDenied, "denied")
	}
	var receipt struct {
		ExpiresAt string `json:"expiresAt"`
	}
	if json.Unmarshal(decision.GetDecisionJson(), &receipt) != nil {
		return status.Error(codes.Unavailable, "unavailable")
	}
	expiry, err := time.Parse(time.RFC3339Nano, receipt.ExpiresAt)
	if err != nil || !expiry.After(time.Now().UTC()) {
		return status.Error(codes.PermissionDenied, "denied")
	}
	upstreamCtx, stop := context.WithDeadline(metadata.NewOutgoingContext(stream.Context(), metadata.MD{}), expiry)
	defer stop()
	// The request was authorized as raw bytes. Never forward caller metadata or
	// learner credentials, and never retry an uncertain upstream invocation.
	var response []byte
	if err := d.upstream.Invoke(upstreamCtx, method, &body, &response, grpc.ForceCodec(rawRPCCodec{}), grpc.MaxCallRecvMsgSize(d.maxBytes), grpc.MaxCallSendMsgSize(d.maxBytes)); err != nil {
		return status.Error(codes.Unavailable, "upstream unavailable")
	}
	if len(response) > d.maxBytes {
		return status.Error(codes.ResourceExhausted, "response too large")
	}
	return stream.SendMsg(&response)
}

func verifyBusinessReceipt(raw []byte, evidence map[string]any, action, org, catalogExpiry string, now time.Time) bool {
	if len(raw) == 0 || rejectDuplicateJSONKeys(raw) != nil {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	keys := make([]string, 0, len(evidence)+6)
	for k := range evidence {
		keys = append(keys, k)
	}
	keys = append(keys, "allowed", "reason", "actionId", "organizationId", "principalDigest", "issuedAt", "expiresAt")
	if !exactKeys(fields, keys...) {
		return false
	}
	for key, expected := range evidence {
		var got any
		dec := json.NewDecoder(strings.NewReader(string(fields[key])))
		dec.UseNumber()
		if dec.Decode(&got) != nil {
			return false
		}
		a, err1 := grpcCanonical(expected)
		b, err2 := grpcCanonical(got)
		if err1 != nil || err2 != nil || string(a) != string(b) {
			return false
		}
	}
	var allowed bool
	var reason, actualAction, actualOrg, principal, issuedText, expiryText string
	if json.Unmarshal(fields["allowed"], &allowed) != nil || !allowed || json.Unmarshal(fields["reason"], &reason) != nil || reason == "" || json.Unmarshal(fields["actionId"], &actualAction) != nil || actualAction != action || json.Unmarshal(fields["organizationId"], &actualOrg) != nil || actualOrg != org || json.Unmarshal(fields["principalDigest"], &principal) != nil || !contracts.IsPrincipalDigest(principal) || json.Unmarshal(fields["issuedAt"], &issuedText) != nil || json.Unmarshal(fields["expiresAt"], &expiryText) != nil {
		return false
	}
	issued, e1 := time.Parse(time.RFC3339Nano, issuedText)
	expiry, e2 := time.Parse(time.RFC3339Nano, expiryText)
	catExpiry, e3 := time.Parse(time.RFC3339Nano, catalogExpiry)
	return e1 == nil && e2 == nil && e3 == nil && !issued.After(now) && expiry.After(now) && expiry.After(issued) && expiry.Sub(issued) <= 5*time.Second && !expiry.After(catExpiry)
}
