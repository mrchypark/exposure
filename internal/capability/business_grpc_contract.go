package capability

// Business gRPC authorization is deliberately separate from HTTP capability
// authorization: an HTTP decision must never authorize an RPC.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mrchypark/exposure/internal/contracts"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

type businessCapability struct {
	CapabilityID     string `json:"capabilityId"`
	Version          uint64 `json:"version"`
	Enabled          bool   `json:"enabled"`
	FullMethod       string `json:"fullMethod"`
	DescriptorDigest string `json:"descriptorDigest"`
	ActionID         string `json:"actionId"`
	ResourceType     string `json:"resourceType"`
	ResourceID       string `json:"resourceId"`
	MaxMessageBytes  uint64 `json:"maxMessageBytes"`
	ContractDigest   string `json:"contractDigest"`
}

type businessCatalog struct {
	SchemaVersion     uint64               `json:"schemaVersion"`
	ProviderID        string               `json:"providerId"`
	Generation        uint64               `json:"generation"`
	CatalogDigest     string               `json:"catalogDigest"`
	Capabilities      []businessCapability `json:"capabilities"`
	PepClientID       string               `json:"pepClientId"`
	AuthorizationMode string               `json:"authorizationMode"`
	PepPolicyRevision int64                `json:"pepPolicyRevision"`
	IssuedAt          string               `json:"issuedAt"`
	ExpiresAt         string               `json:"expiresAt"`
}

// grpcCanonical encodes the small JSON subset in Grant's contract without
// float conversion, HTML escaping, or U+2028/U+2029 escaping.
func grpcCanonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var x any
	if err = d.Decode(&x); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err = appendCanonical(&out, x); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func appendCanonical(out *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(x))
	case json.Number:
		if _, err := strconv.ParseUint(string(x), 10, 64); err != nil {
			return err
		}
		out.WriteString(string(x))
	case string:
		if !utf8.ValidString(x) {
			return errors.New("invalid UTF-8")
		}
		out.WriteByte('"')
		for _, r := range x {
			switch r {
			case '"', '\\':
				out.WriteByte('\\')
				out.WriteRune(r)
			case '\b':
				out.WriteString(`\b`)
			case '\f':
				out.WriteString(`\f`)
			case '\n':
				out.WriteString(`\n`)
			case '\r':
				out.WriteString(`\r`)
			case '\t':
				out.WriteString(`\t`)
			default:
				if r < 0x20 {
					fmt.Fprintf(out, `\u%04x`, r)
				} else {
					out.WriteRune(r)
				}
			}
		}
		out.WriteByte('"')
	case []any:
		out.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := appendCanonical(out, e); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := appendCanonical(out, k); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := appendCanonical(out, x[k]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return errors.New("unsupported canonical JSON")
	}
	return nil
}

func businessCapabilityDigest(c businessCapability) (string, error) {
	b, err := grpcCanonical(map[string]any{"capabilityId": c.CapabilityID, "version": c.Version, "enabled": c.Enabled, "fullMethod": c.FullMethod, "descriptorDigest": c.DescriptorDigest, "actionId": c.ActionID, "resourceType": c.ResourceType, "resourceId": c.ResourceID, "maxMessageBytes": c.MaxMessageBytes})
	if err != nil {
		return "", err
	}
	return shaBytes(b), nil
}

func businessCatalogDigest(c businessCatalog) (string, error) {
	b, err := grpcCanonical(map[string]any{"schemaVersion": c.SchemaVersion, "providerId": c.ProviderID, "generation": c.Generation, "capabilities": c.Capabilities})
	if err != nil {
		return "", err
	}
	return shaBytes(b), nil
}

// parseBusinessCatalog rejects unsupported shapes before any caller can use a
// capability. The caller must also verify its pinned descriptor at dispatch.
func parseBusinessCatalog(raw []byte, provider, pep, pin string, now time.Time) (*businessCatalog, error) {
	if len(raw) == 0 || len(raw) > 2<<20 || !utf8.Valid(raw) || rejectDuplicateJSONKeys(raw) != nil {
		return nil, errors.New("invalid catalog encoding")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || !exactKeys(fields, "schemaVersion", "providerId", "generation", "catalogDigest", "capabilities", "pepClientId", "authorizationMode", "pepPolicyRevision", "issuedAt", "expiresAt") {
		return nil, errors.New("invalid catalog fields")
	}
	var capFields []map[string]json.RawMessage
	if json.Unmarshal(fields["capabilities"], &capFields) != nil || len(capFields) == 0 {
		return nil, errors.New("invalid capabilities")
	}
	for _, f := range capFields {
		if !exactKeys(f, "capabilityId", "version", "enabled", "fullMethod", "descriptorDigest", "actionId", "resourceType", "resourceId", "maxMessageBytes", "contractDigest") {
			return nil, errors.New("invalid capability fields")
		}
	}
	var c businessCatalog
	if strictJSON(raw, &c) != nil || c.SchemaVersion != 1 || c.ProviderID != provider || c.PepClientID != pep || c.Generation == 0 || c.PepPolicyRevision <= 0 || c.AuthorizationMode != "user" || c.CatalogDigest != pin || !contracts.IsDigest(pin) {
		return nil, errors.New("catalog binding mismatch")
	}
	issued, e1 := time.Parse(time.RFC3339Nano, c.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if e1 != nil || e2 != nil || issued.After(now) || !expires.After(now) || !expires.After(issued) || expires.Sub(issued) > 30*time.Second {
		return nil, errors.New("invalid catalog lease")
	}
	seen := make(map[string]bool)
	for _, cap := range c.Capabilities {
		digest, err := businessCapabilityDigest(cap)
		if err != nil || cap.CapabilityID == "" || cap.Version == 0 || cap.FullMethod == "" || cap.ActionID == "" || cap.ResourceType == "" || cap.ResourceID == "" || cap.MaxMessageBytes == 0 || !contracts.IsDigest(cap.DescriptorDigest) || digest != cap.ContractDigest || seen[cap.FullMethod] {
			return nil, errors.New("invalid capability")
		}
		seen[cap.FullMethod] = true
	}
	digest, err := businessCatalogDigest(c)
	if err != nil || digest != c.CatalogDigest {
		return nil, errors.New("catalog digest mismatch")
	}
	return &c, nil
}

func exactKeys(fields map[string]json.RawMessage, keys ...string) bool {
	if len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		v, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return false
		}
	}
	return true
}

func validateBusinessMethod(raw []byte, expectedDigest, fullMethod string) error {
	if len(raw) == 0 || shaBytes(raw) != expectedDigest {
		return errors.New("descriptor digest mismatch")
	}
	var set descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(raw, &set); err != nil {
		return err
	}
	files, err := protodesc.NewFiles(&set)
	if err != nil {
		return err
	}
	parts := strings.Split(strings.TrimPrefix(fullMethod, "/"), "/")
	if !strings.HasPrefix(fullMethod, "/") || len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return errors.New("invalid full method")
	}
	service, err := files.FindDescriptorByName(protoreflect.FullName(parts[0]))
	if err != nil {
		return err
	}
	svc, ok := service.(protoreflect.ServiceDescriptor)
	if !ok {
		return errors.New("not a service")
	}
	method := svc.Methods().ByName(protoreflect.Name(parts[1]))
	if method == nil || method.IsStreamingClient() || method.IsStreamingServer() {
		return errors.New("method is not unary")
	}
	return nil
}
