package capability

// This isolated pilot assumes every process sharing its network namespace is
// trusted. It must not be exposed to an untrusted network or another Pod.
import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mrchypark/exposure/internal/pdppb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

const (
	streamRequestMax      = 4 << 10
	streamFrameWireMax    = (64 << 10) + 1024
	streamResponseWireMax = (256 << 10) + (16 << 10)
	streamMaxFrames       = 4096
)

// streamPilot is intentionally not connected to production startup. Selectors
// are accepted solely from a trusted colocated caller; they are not identity.
type streamPilot struct {
	proxy       *Proxy
	upstream    *grpc.ClientConn
	method      string
	provider    string
	org         string
	action      string
	resource    string
	resourceKey string
	selectors   []string
	fixed       map[string]string
	limit       int
	sem         chan struct{}
}

func newStreamPilot(p *Proxy, target, method string, descriptor []byte, digest, provider, org, action, resource, resourceKey string, selectors []string, fixed map[string]string, limit int) (*streamPilot, error) {
	if !loopbackAddress(target, false) ||
		p == nil || p.learner == nil || p.learner.timeout <= 0 || provider == "" || provider != p.cfg.ProviderID || p.cfg.AppAuthKey == "" ||
		p.cfg.CredentialMode != "goauthy" || p.cfg.GoauthyUserClientID == "" || p.cfg.GoauthyUserResourceAudience == "" ||
		org == "" || action == "" || resource == "" ||
		limit <= 0 || limit > streamResponseWireMax || len(selectors) == 0 || len(selectors) > 8 || len(fixed) == 0 {
		return nil, errors.New("invalid isolated stream configuration")
	}
	if shaBytes(descriptor) != digest || !serverStreamMethod(descriptor, method) {
		return nil, errors.New("invalid stream descriptor")
	}
	seen := make(map[string]bool)
	for _, key := range selectors {
		if key == "" || key != strings.ToLower(key) || seen[key] ||
			key == "authorization" || key == "x-organization-id" || key == "x-grant-app-auth-key" ||
			strings.HasPrefix(key, "grpc-") || !strings.HasPrefix(key, "x-") {
			return nil, errors.New("invalid selector key")
		}
		for _, c := range key {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return nil, errors.New("invalid selector key")
			}
		}
		seen[key] = true
	}
	if !seen[resourceKey] || fixed[resourceKey] != "" {
		return nil, errors.New("invalid resource selector")
	}
	fixedCopy := make(map[string]string, len(fixed))
	for key, value := range fixed {
		if !seen[key] || !streamSelectorValue(value) {
			return nil, errors.New("invalid fixed selector")
		}
		fixedCopy[key] = value
	}
	conn, err := grpc.NewClient("passthrough:///"+target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithNoProxy(), grpc.WithDisableRetry(), grpc.WithDisableServiceConfig())
	if err != nil {
		return nil, err
	}
	return &streamPilot{proxy: p, upstream: conn, method: method, provider: provider, org: org, action: action, resource: resource, resourceKey: resourceKey, selectors: append([]string(nil), selectors...), fixed: fixedCopy, limit: limit, sem: make(chan struct{}, 16)}, nil
}

func serverStreamMethod(raw []byte, method string) bool {
	var set descriptorpb.FileDescriptorSet
	if len(raw) == 0 || proto.Unmarshal(raw, &set) != nil {
		return false
	}
	files, err := protodesc.NewFiles(&set)
	parts := strings.Split(strings.TrimPrefix(method, "/"), "/")
	if err != nil || !strings.HasPrefix(method, "/") || len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	found, err := files.FindDescriptorByName(protoreflect.FullName(parts[0]))
	if err != nil {
		return false
	}
	svc, ok := found.(protoreflect.ServiceDescriptor)
	if !ok {
		return false
	}
	m := svc.Methods().ByName(protoreflect.Name(parts[1]))
	return m != nil && !m.IsStreamingClient() && m.IsStreamingServer()
}

func streamSelectorValue(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (s *streamPilot) server() *grpc.Server {
	return grpc.NewServer(grpc.StatsHandler(rejectCompressedStats{}), grpc.ForceServerCodec(rawRPCCodec{}), grpc.UnknownServiceHandler(s.handler), grpc.MaxRecvMsgSize(streamRequestMax), grpc.MaxSendMsgSize(streamFrameWireMax), grpc.MaxConcurrentStreams(16))
}

func (s *streamPilot) handler(_ any, stream grpc.ServerStream) error {
	deadline, ok := stream.Context().Deadline()
	now := time.Now()
	if !ok || !deadline.After(now) || deadline.Sub(now) > 3*time.Second {
		return status.Error(codes.DeadlineExceeded, "bounded deadline required")
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		return status.Error(codes.ResourceExhausted, "busy")
	}
	compression, ok := stream.Context().Value(compressionKey{}).(*compressionState)
	if !ok || compression.state.Load() != 1 {
		return status.Error(codes.InvalidArgument, "compression unsupported")
	}
	method, ok := grpc.MethodFromServerStream(stream)
	if !ok || method != s.method {
		return status.Error(codes.PermissionDenied, "denied")
	}
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok || len(md.Get("authorization")) != 1 || len(md.Get("x-organization-id")) != 1 || md.Get("x-organization-id")[0] != s.org {
		return status.Error(codes.Unauthenticated, "unauthorized")
	}
	for k, values := range md {
		switch k {
		case ":authority", "content-type", "user-agent", "grpc-accept-encoding":
		case "authorization", "x-organization-id":
			if len(values) != 1 {
				return status.Error(codes.Unauthenticated, "unauthorized")
			}
		default:
			allowed := false
			for _, key := range s.selectors {
				if k == key {
					allowed = true
					break
				}
			}
			if !allowed || len(values) != 1 || !streamSelectorValue(values[0]) {
				return status.Error(codes.InvalidArgument, "invalid metadata")
			}
		}
	}
	out := metadata.MD{}
	for _, key := range s.selectors {
		values := md.Get(key)
		if len(values) != 1 || !streamSelectorValue(values[0]) {
			return status.Error(codes.InvalidArgument, "missing selector")
		}
		if expected, fixed := s.fixed[key]; fixed && expected != values[0] {
			return status.Error(codes.PermissionDenied, "denied")
		}
		out.Set(key, values[0])
	}
	request := &http.Request{Header: http.Header{}, URL: &url.URL{}}
	request.Header.Set("Authorization", strings.TrimSpace(md.Get("authorization")[0]))
	request.Header.Set("X-Organization-ID", s.org)
	auth, org, _, _, err := userBearerIdentity(request, s.proxy.cfg, false)
	if err != nil || org != s.org {
		return status.Error(codes.Unauthenticated, "unauthorized")
	}
	var body, extra []byte
	if err := stream.RecvMsg(&body); err != nil || len(body) > streamRequestMax {
		return status.Error(codes.InvalidArgument, "invalid request")
	}
	if err := stream.RecvMsg(&extra); err != io.EOF {
		return status.Error(codes.InvalidArgument, "one request required")
	}
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	revision := int64(0)
	if err := s.check(ctx, auth, org, out.Get(s.resourceKey)[0], &revision); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return status.Error(codes.Canceled, "canceled")
	}
	upstreamCtx := metadata.NewOutgoingContext(ctx, out)
	up, err := s.upstream.NewStream(upstreamCtx, &grpc.StreamDesc{ServerStreams: true}, s.method, grpc.ForceCodec(rawRPCCodec{}), grpc.MaxCallRecvMsgSize(streamFrameWireMax), grpc.MaxCallSendMsgSize(streamRequestMax))
	if err != nil {
		return status.Error(codes.Unavailable, "upstream unavailable")
	}
	if up.SendMsg(&body) != nil || up.CloseSend() != nil {
		return status.Error(codes.Unavailable, "upstream unavailable")
	}
	total, frames := 0, 0
	for {
		var frame []byte
		err := up.RecvMsg(&frame)
		if err == io.EOF {
			if frames == 0 {
				return status.Error(codes.Unavailable, "empty upstream response")
			}
			return nil
		}
		if err != nil {
			return status.Error(codes.Unavailable, "upstream unavailable")
		}
		frames++
		if frames > streamMaxFrames || len(frame) > streamFrameWireMax || len(frame) > s.limit-total {
			return status.Error(codes.ResourceExhausted, "response too large")
		}
		total += len(frame)
		if err := s.check(ctx, auth, org, out.Get(s.resourceKey)[0], &revision); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return status.Error(codes.Canceled, "canceled")
		}
		if err := stream.SendMsg(&frame); err != nil {
			return err
		}
	}
}

func (s *streamPilot) check(ctx context.Context, auth, org, resourceID string, revision *int64) error {
	body, err := json.Marshal(map[string]any{"checks": []any{map[string]any{"action": s.action, "resource": map[string]string{"provider": s.provider, "type": s.resource, "id": resourceID}}}})
	if err != nil {
		return status.Error(codes.Unavailable, "unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, s.proxy.learner.timeout)
	defer cancel()
	callCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("x-grant-app-auth-key", s.proxy.cfg.AppAuthKey, "authorization", auth, "x-organization-id", org))
	resp, err := s.proxy.learner.client.BatchCheckProviderUser(callCtx, &pdppb.ProviderUserBatchRequest{ProviderId: s.provider, ChecksJson: body})
	if err != nil || len(resp.GetDecisionJson()) > 64<<10 || rejectDuplicateJSONKeys(resp.GetDecisionJson()) != nil {
		return status.Error(codes.Unavailable, "authorization unavailable")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(resp.GetDecisionJson(), &fields) != nil || !exactKeys(fields, "results", "pepPolicyRevision") {
		return status.Error(codes.Unavailable, "authorization unavailable")
	}
	var checks []map[string]json.RawMessage
	if json.Unmarshal(fields["results"], &checks) != nil || len(checks) != 1 || !exactKeys(checks[0], "allowed", "reason") {
		return status.Error(codes.Unavailable, "authorization unavailable")
	}
	var result struct {
		Results []struct {
			Allowed bool   `json:"allowed"`
			Reason  string `json:"reason"`
		} `json:"results"`
		PepPolicyRevision int64 `json:"pepPolicyRevision"`
	}
	if strictJSON(resp.GetDecisionJson(), &result) != nil || len(result.Results) != 1 || result.PepPolicyRevision <= 0 || result.Results[0].Reason == "" || (*revision != 0 && *revision != result.PepPolicyRevision) {
		return status.Error(codes.Unavailable, "authorization unavailable")
	}
	*revision = result.PepPolicyRevision
	if !result.Results[0].Allowed {
		return status.Error(codes.PermissionDenied, "denied")
	}
	return nil
}
