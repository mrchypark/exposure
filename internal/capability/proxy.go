// Package capability implements Exposure's provider-neutral HTTP PEP.  It has
// no collection, operation, or provider-specific knowledge: Grant's active
// immutable catalog is the only route contract.
package capability

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mrchypark/exposure/internal/config"
	"github.com/mrchypark/exposure/internal/contracts"
)

const credentialDomain = "grant.http-capability.provider-credential.v1"

const (
	maxAuthnPeers = 4096
	authnPeerTTL  = time.Hour
)

type catalog struct {
	SchemaVersion     uint64             `json:"schemaVersion"`
	ProviderID        string             `json:"providerId"`
	PepClientID       string             `json:"pepClientId"`
	Generation        uint64             `json:"generation"`
	CatalogDigest     string             `json:"catalogDigest"`
	Capabilities      []capability       `json:"capabilities"`
	ResponseResources []responseResource `json:"responseResources,omitempty"`
	IssuedAt          string             `json:"issuedAt"`
	ExpiresAt         string             `json:"expiresAt"`
}
type capability struct {
	CapabilityID          string                       `json:"capabilityId"`
	Version               uint64                       `json:"version"`
	Enabled               bool                         `json:"enabled"`
	AccessMode            string                       `json:"accessMode"`
	Method                string                       `json:"method"`
	PathTemplate          string                       `json:"pathTemplate"`
	ActionID              *string                      `json:"actionId"`
	Resource              *resource                    `json:"resource"`
	Query                 queryPolicy                  `json:"query"`
	Request               requestPolicy                `json:"request"`
	Response              responsePolicy               `json:"response"`
	ContractDigest        string                       `json:"contractDigest"`
	PathParameters        []pathParameter              `json:"pathParameters,omitempty"`
	RecordScope           *recordScopePolicy           `json:"recordScope,omitempty"`
	Batch                 *batchPolicy                 `json:"batch,omitempty"`
	ResponseAuthorization *responseAuthorizationPolicy `json:"responseAuthorization,omitempty"`
	OrganizationContext   string                       `json:"organizationContext,omitempty"`
}

// Omission retains the original required-organization contract and digest.
// Explicit policy must have exactly this spelling and a supported string value;
// encoding/json otherwise accepts case aliases and null for a string field.
func (c *capability) UnmarshalJSON(b []byte) error {
	if err := rejectDuplicateJSONKeys(b); err != nil {
		return err
	}
	type wire capability
	var out wire
	if err := strictJSON(b, &out); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return err
	}
	for key := range fields {
		if strings.EqualFold(key, "organizationContext") {
			if key != "organizationContext" || (out.OrganizationContext != "required" && out.OrganizationContext != "optional") {
				return errors.New("invalid organization context policy")
			}
		}
	}
	*c = capability(out)
	return nil
}

type pathParameter struct {
	Name     string `json:"name"`
	Format   string `json:"format"`
	MaxBytes uint64 `json:"maxBytes"`
}
type resource struct {
	Type string    `json:"type"`
	ID   extractor `json:"id"`
}
type extractor struct {
	Kind    string `json:"kind"`
	Name    string `json:"name,omitempty"`
	Pointer string `json:"pointer,omitempty"`
	Format  string `json:"format,omitempty"`
	Value   string `json:"value,omitempty"`
}
type queryPolicy struct {
	Mode       string       `json:"mode"`
	Parameters []queryParam `json:"parameters,omitempty"`
}
type queryParam struct {
	Name     string `json:"name"`
	Format   string `json:"format"`
	Required bool   `json:"required"`
	MaxBytes uint64 `json:"maxBytes,omitempty"`
	Repeated bool   `json:"repeated,omitempty"`
}
type requestPolicy struct {
	Body           string   `json:"body"`
	MaxBytes       uint64   `json:"maxBytes"`
	ForwardHeaders []string `json:"forwardHeaders"`
	Authorization  string   `json:"authorization,omitempty"`
	ContentTypes   []string `json:"contentTypes,omitempty"`
}
type responsePolicy struct {
	MaxBytes       uint64   `json:"maxBytes"`
	ForwardHeaders []string `json:"forwardHeaders"`
	Redirects      string   `json:"redirects"`
	ErrorStatuses  []int    `json:"errorStatuses,omitempty"`
}

type Proxy struct {
	cfg     config.ProxyConfig
	grant   string
	origin  *url.URL
	http    *http.Client
	sem     chan struct{}
	mu      sync.RWMutex
	active  *catalog
	limiter *authnLimiter
}

type tokenBucket struct {
	tokens  float64
	updated time.Time
}
type authnLimiter struct {
	mu                           sync.Mutex
	key                          []byte
	global                       tokenBucket
	peers                        map[string]tokenBucket
	globalCapacity, peerCapacity float64
	globalRefill, peerRefill     time.Duration
}

func New(cfg config.ProxyConfig, grant string, h *http.Client, maxConcurrent int) (*Proxy, error) {
	if err := cfg.ValidateUpstreamAuthorization(); err != nil {
		return nil, err
	}
	if err := cfg.ValidateCredentialMode(); err != nil {
		return nil, err
	}
	origin, err := url.Parse(cfg.Origin)
	if err != nil {
		return nil, err
	}
	return &Proxy{cfg: cfg, grant: strings.TrimRight(grant, "/"), origin: origin, http: h, sem: make(chan struct{}, maxConcurrent), limiter: &authnLimiter{key: []byte(cfg.AuthnLimiterKey), peers: map[string]tokenBucket{}, globalCapacity: float64(cfg.PublicAuthnGlobalCapacity), peerCapacity: float64(cfg.PublicAuthnPeerCapacity), globalRefill: cfg.PublicAuthnGlobalRefill, peerRefill: cfg.PublicAuthnPeerRefill}}, nil
}

// Refresh only replaces a catalog after all immutable bindings were checked.
func (p *Proxy) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.grant+"/api/v2/http-capabilities/catalog/"+url.PathEscape(p.cfg.ProviderID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Grant-App-Auth-Key", p.cfg.AppAuthKey)
	resp, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("catalog status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	var c catalog
	if err := strictJSON(b, &c); err != nil {
		return err
	}
	if err := p.validateCatalog(&c); err != nil {
		return err
	}
	p.mu.Lock()
	p.active = &c
	p.mu.Unlock()
	return nil
}
func (p *Proxy) validateCatalog(c *catalog) error {
	if c.SchemaVersion != 1 || c.ProviderID != p.cfg.ProviderID || c.PepClientID != p.cfg.PepClientID || c.CatalogDigest != p.cfg.ExpectedCatalogDigest || !contracts.IsDigest(c.CatalogDigest) {
		return errors.New("catalog binding mismatch")
	}
	exp, err := time.Parse(time.RFC3339, c.ExpiresAt)
	if err != nil || !exp.After(time.Now().UTC()) {
		return errors.New("catalog expired")
	}
	seen := map[string]bool{}
	for _, cap := range c.Capabilities {
		if cap.Enabled {
			service := p.cfg.AuthorizationMode == "service-token"
			if service && (cap.AccessMode != "authorized" || cap.Request.Authorization != "service-token") || !service && cap.Request.Authorization == "service-token" {
				return errors.New("catalog upstream authorization mode mismatch")
			}
		}
		if err := validateCapability(cap); err != nil || cap.Response.MaxBytes > uint64(p.cfg.MaxResponseBytes) {
			if err == nil {
				err = errors.New("capability response exceeds configured bound")
			}
			return err
		}
		if cap.ContractDigest != capabilityDigest(cap) {
			return errors.New("capability contract digest mismatch")
		}
		if cap.Enabled {
			k := cap.Method + "\x00" + cap.PathTemplate
			if seen[k] {
				return errors.New("duplicate capability template")
			}
			seen[k] = true
		}
	}
	if c.CatalogDigest != catalogDigest(c) {
		return errors.New("catalog digest mismatch")
	}
	if err := validateBatchCatalog(c); err != nil {
		return err
	}
	if err := validateResponseAuthorization(c); err != nil {
		return err
	}
	return nil
}
func validateCapability(c capability) error {
	if c.OrganizationContext != "" && (c.AccessMode != "authorized" || (c.OrganizationContext != "required" && c.OrganizationContext != "optional")) {
		return errors.New("unsupported organization context policy")
	}
	if c.OrganizationContext == "optional" && (c.RecordScope != nil || c.ResponseAuthorization != nil) {
		return errors.New("scoped and response-reference authorization require organization context")
	}
	if c.Request.Authorization != "" && c.Request.Authorization != "forward-user" && c.Request.Authorization != "service-token" {
		return errors.New("unsupported upstream authorization mode")
	}
	if c.AccessMode == "public_authn" && c.Request.Authorization == "service-token" {
		return errors.New("public authentication cannot carry a service credential")
	}
	if c.CapabilityID == "" || c.Version == 0 || c.Method == "" || !strings.HasPrefix(c.PathTemplate, "/") || !contracts.IsDigest(c.ContractDigest) {
		return errors.New("invalid capability")
	}
	if path.Clean(c.PathTemplate) != c.PathTemplate || strings.Contains(c.PathTemplate, "//") || strings.ContainsAny(c.PathTemplate, "\\\x00") {
		return errors.New("noncanonical capability path")
	}
	if c.AccessMode != "public_authn" && c.AccessMode != "authorized" {
		return errors.New("unsupported access mode")
	}
	if c.AccessMode == "authorized" && (c.ActionID == nil || c.Resource == nil) {
		return errors.New("authorized capability missing policy")
	}
	if c.Request.Body != "none" && c.Request.Body != "json" && c.Request.Body != "opaque" && c.Request.Body != "multipart" {
		return errors.New("unsupported body policy")
	}
	if err := validateRecordScope(c); err != nil {
		return err
	}
	if err := validateTransportPolicy(c); err != nil {
		return err
	}
	if c.Response.Redirects != "deny" || c.Response.MaxBytes == 0 {
		return errors.New("unsupported response policy")
	}
	previous := 0
	for _, status := range c.Response.ErrorStatuses {
		if (status != 304 && (status < 400 || status > 599)) || status <= previous {
			return errors.New("error statuses must be sorted unique HTTP errors")
		}
		previous = status
	}
	return nil
}

// Grant uses serde_json over these exact structs, not JCS.  Go's struct field
// order matches CanonicalGeneration/HttpCapability and is deliberately kept
// explicit so a catalog altered in transit cannot be accepted on its pin alone.
func catalogDigest(c *catalog) string {
	v := struct {
		SchemaVersion     uint64             `json:"schemaVersion"`
		ProviderID        string             `json:"providerId"`
		Generation        uint64             `json:"generation"`
		Capabilities      []capability       `json:"capabilities"`
		ResponseResources []responseResource `json:"responseResources,omitempty"`
	}{c.SchemaVersion, c.ProviderID, c.Generation, c.Capabilities, c.ResponseResources}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return shaBytes(b)
}
func capabilityDigest(c capability) string {
	// Grant serializes HttpCapability into serde_json::Value, removes
	// contractDigest, then serializes that Value. serde_json's default Value
	// map is lexicographically ordered. encoding/json has the same map-key
	// ordering, including nested maps, while preserving the null fields that
	// the typed capability serialization emitted.
	b, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&raw); err != nil {
		return ""
	}
	delete(raw, "contractDigest")
	v := make(map[string]any, len(raw))
	for key, value := range raw {
		// UseNumber preserves uint64 fields above JavaScript's 2^53 range
		// while converting nested objects to lexicographically sorted maps.
		part := json.NewDecoder(bytes.NewReader(value))
		part.UseNumber()
		var decoded any
		if err := part.Decode(&decoded); err != nil {
			return ""
		}
		v[key] = decoded
	}
	b, err = json.Marshal(v)
	if err != nil {
		return ""
	}
	return shaBytes(b)
}
func (p *Proxy) Ready() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.active == nil {
		return false
	}
	t, e := time.Parse(time.RFC3339, p.active.ExpiresAt)
	return e == nil && t.After(time.Now().UTC())
}
func (p *Proxy) Handler() http.Handler { return http.HandlerFunc(p.serveHTTP) }

func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect || !p.Ready() {
		errorJSON(w, http.StatusServiceUnavailable, "not_ready")
		return
	}
	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	default:
		errorJSON(w, http.StatusServiceUnavailable, "overloaded")
		return
	}
	if err := validateIncomingPath(r); err != nil {
		errorJSON(w, 422, "invalid_request")
		return
	}
	p.mu.RLock()
	c := p.active
	p.mu.RUnlock()
	cap, captures := findCapability(c.Capabilities, r.Method, r.URL.EscapedPath())
	if cap == nil {
		errorJSON(w, 404, "not_found")
		return
	}
	if connectionNominatedAny(r.Header) || hasAlternateCredential(r) {
		errorJSON(w, 422, "invalid_request")
		return
	}
	if cap.AccessMode == "public_authn" {
		if retryAfter, ok := p.limiter.allow(r.RemoteAddr, cap.CapabilityID, time.Now()); !ok {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			errorJSON(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
	}
	query, err := canonicalQuery(r.URL.RawQuery, cap.Query)
	if err != nil {
		errorJSON(w, 422, "invalid_request")
		return
	}
	expansions, err := requestedExpansion(r.URL.RawQuery, c, *cap)
	if err != nil {
		errorJSON(w, 422, "invalid_request")
		return
	}
	if err := validateScopeRequest(r.URL.RawQuery, cap.RecordScope); err != nil {
		errorJSON(w, 422, "invalid_request")
		return
	}
	upstreamQuery := r.URL.RawQuery
	body, err := readBody(r, cap.Request, p.cfg.MaxRequestBytes)
	if err != nil {
		errorJSON(w, 422, "invalid_request")
		return
	}
	defer body.close()
	headers, err := forwardHeaders(r.Header, cap.Request.ForwardHeaders)
	if err != nil {
		errorJSON(w, 422, "invalid_request")
		return
	}
	resourceValue, evidence, err := extract(cap.Resource, captures, query, body.data())
	if err != nil {
		errorJSON(w, 422, "invalid_request")
		return
	}
	children, err := prepareBatch(c, *cap, r.Header.Get("Content-Type"), body)
	if err != nil {
		errorJSON(w, 422, "invalid_request")
		return
	}
	var authorizedUntil time.Time
	var proof *responseProof
	if expansions != nil {
		proof = &responseProof{requestBinding: randomBinding()}
	}
	if cap.AccessMode == "authorized" {
		if err := p.authorize(r.Context(), r, c, *cap, query, headers, body, resourceValue, evidence, &upstreamQuery, children, &authorizedUntil, proof); err != nil {
			p.writeDecisionError(w, err)
			return
		}
	} else if hasCredential(r) {
		errorJSON(w, 422, "invalid_request")
		return
	}
	if !authorizedUntil.IsZero() {
		if !authorizedUntil.After(time.Now()) {
			errorJSON(w, 502, "dependency_unavailable")
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), authorizationExpiryKey{}, authorizedUntil))
	}
	// Policy evaluates decoded canonical values, but the service receives the
	// exact original query spelling and order from this same checked request.
	var responseChecks []func([]byte, http.Header, int) error
	if proof != nil {
		responseChecks = append(responseChecks, func(data []byte, responseHeaders http.Header, status int) error {
			if status >= 400 {
				return nil
			}
			if status != 200 {
				return decisionError{502, "dependency_unavailable"}
			}
			media, _, err := mime.ParseMediaType(responseHeaders.Get("Content-Type"))
			if err != nil || media != "application/json" {
				return decisionError{502, "dependency_unavailable"}
			}
			refs, err := collectResponseReferences(c, *cap, expansions, data, resourceValue)
			if err != nil {
				return decisionError{502, "dependency_unavailable"}
			}
			proof.digest = shaBytes(data)
			proof.length = uint64(len(data))
			proof.references = refs
			if err = p.authorize(r.Context(), r, c, *cap, query, headers, body, resourceValue, evidence, &upstreamQuery, nil, &authorizedUntil, proof); err != nil {
				return err
			}
			if !authorizedUntil.After(time.Now()) {
				return decisionError{502, "dependency_unavailable"}
			}
			return nil
		})
	}
	p.forward(w, r, *cap, upstreamQuery, headers, body, responseChecks...)
}

func validateIncomingPath(r *http.Request) error {
	if r.URL.IsAbs() || r.URL.Opaque != "" || strings.ContainsAny(r.URL.Path, "\\\x00") || path.Clean(r.URL.Path) != r.URL.Path || strings.Contains(r.URL.Path, "//") {
		return errors.New("noncanonical path")
	}
	for _, s := range strings.Split(r.URL.Path, "/") {
		if s == "." || s == ".." {
			return errors.New("dot path")
		}
	}
	return nil
}
func findCapability(cs []capability, method, p string) (*capability, map[string]string) {
	var found *capability
	var captures map[string]string
	for i := range cs {
		c := &cs[i]
		if !c.Enabled || c.Method != method {
			continue
		}
		m, ok := matchTemplateParameters(c.PathTemplate, p, c.PathParameters)
		if !ok {
			continue
		}
		if found != nil {
			return nil, nil
		}
		found, captures = c, m
	}
	return found, captures
}
func matchTemplate(t, p string) (map[string]string, bool) {
	return matchTemplateParameters(t, p, nil)
}
func matchTemplateParameters(t, p string, parameters []pathParameter) (map[string]string, bool) {
	ts, ps := strings.Split(strings.TrimPrefix(t, "/"), "/"), strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(ts) != len(ps) {
		return nil, false
	}
	out := map[string]string{}
	for i := range ts {
		if strings.HasPrefix(ts[i], "{") && strings.HasSuffix(ts[i], "}") {
			n := strings.TrimSuffix(strings.TrimPrefix(ts[i], "{"), "}")
			_, duplicate := out[n]
			value := ps[i]
			valid := validPathToken(value)
			for _, parameter := range parameters {
				if parameter.Name == n && parameter.Format == "utf8Segment" {
					decoded, err := url.PathUnescape(value)
					valid = err == nil && decoded != "" && validText(decoded, parameter.MaxBytes) && decoded != "." && decoded != ".." && !strings.ContainsAny(decoded, "/\\%")
					value = decoded
				}
			}
			if n == "" || duplicate || !valid {
				return nil, false
			}
			out[n] = value
		} else if ts[i] != ps[i] {
			return nil, false
		}
	}
	return out, true
}

func validPathToken(v string) bool {
	return v != "" && len(v) <= 256 && v != "." && v != ".." && strings.Trim(v, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:") == ""
}
func canonicalQuery(raw string, policy queryPolicy) (string, error) {
	if strings.Contains(raw, ";") {
		return "", errors.New("semicolon")
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "", err
	}
	if policy.Mode == "none" {
		if len(values) > 0 {
			return "", errors.New("unexpected query")
		}
		return "", nil
	}
	if policy.Mode != "exact" {
		return "", errors.New("unsupported query")
	}
	allowed := map[string]queryParam{}
	for _, p := range policy.Parameters {
		allowed[p.Name] = p
	}
	for name, vs := range values {
		p, ok := allowed[name]
		if !ok || (!p.Repeated && len(vs) != 1) {
			return "", errors.New("query")
		}
		for _, value := range vs {
			valid := validScalar(p.Format, value)
			if p.Format == "text" {
				valid = validText(value, p.MaxBytes)
			}
			if !valid {
				return "", errors.New("query value")
			}
		}
	}
	for _, p := range policy.Parameters {
		if p.Required && len(values[p.Name]) == 0 {
			return "", errors.New("missing query")
		}
	}
	return strings.ReplaceAll(values.Encode(), "+", "%20"), nil
}
func readJSONBody(r *http.Request, policy requestPolicy, max int64) ([]byte, error) {
	if policy.Body == "none" {
		if r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
			return nil, errors.New("body")
		}
		return nil, nil
	}
	if policy.Body != "json" || policy.MaxBytes > uint64(max) {
		return nil, errors.New("body policy")
	}
	if mediaType := strings.Split(r.Header.Get("Content-Type"), ";")[0]; mediaType != "application/json" {
		return nil, errors.New("JSON content type required")
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, int64(policy.MaxBytes)+1))
	if err != nil || uint64(len(b)) > policy.MaxBytes {
		return nil, errors.New("body size")
	}
	if !utf8.Valid(b) {
		return nil, errors.New("invalid UTF-8 JSON")
	}
	if err := rejectDuplicateJSONKeys(b); err != nil {
		return nil, errors.New("duplicate JSON key")
	}
	var v any
	if strictJSON(b, &v) != nil {
		return nil, errors.New("json")
	}
	return b, nil
}
func forwardHeaders(h http.Header, allowed []string) (http.Header, error) {
	out := http.Header{}
	allow := map[string]bool{}
	for _, n := range allowed {
		n = http.CanonicalHeaderKey(n)
		if forbiddenHeader(n) {
			return nil, errors.New("forbidden policy")
		}
		allow[n] = true
	}
	for n, vs := range h {
		cn := http.CanonicalHeaderKey(n)
		if forbiddenHeader(cn) || strings.HasPrefix(strings.ToLower(cn), "x-forwarded-") || strings.HasPrefix(strings.ToLower(cn), "x-grant-") {
			continue
		}
		if allow[cn] {
			if len(vs) != 1 {
				return nil, errors.New("header duplicate")
			}
			out[cn] = append([]string(nil), vs...)
		}
	}
	if connectionNominatedAny(h) {
		return nil, errors.New("connection auth")
	}
	return out, nil
}
func connectionNominatedAny(h http.Header) bool {
	for _, v := range h.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			if strings.TrimSpace(token) != "" {
				return true
			}
		}
	}
	return false
}
func hasAlternateCredential(r *http.Request) bool {
	for n := range r.Header {
		lower := strings.ToLower(n)
		if lower == "authorization" {
			continue
		}
		if strings.Contains(lower, "authorization") || strings.Contains(lower, "token") || strings.Contains(lower, "api-key") || strings.Contains(lower, "apikey") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "session") || lower == "cookie" {
			return true
		}
	}
	return r.URL.Query().Get("access_token") != "" || r.URL.Query().Get("token") != ""
}
func forbiddenHeader(n string) bool {
	switch strings.ToLower(n) {
	case "authorization", "proxy-authorization", "host", "connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "forwarded", "content-length", "cookie", "set-cookie":
		return true
	}
	return false
}
func extract(res *resource, captures map[string]string, query string, body []byte) (string, map[string]string, error) {
	if res == nil {
		return "", map[string]string{"kind": "constant", "canonicalValue": ""}, nil
	}
	e := res.ID
	var v string
	ev := map[string]string{"kind": e.Kind}
	switch e.Kind {
	case "pathSegment":
		v = captures[e.Name]
		ev["name"] = e.Name
	case "queryScalar":
		q, _ := url.ParseQuery(query)
		v = q.Get(e.Name)
		ev["name"] = e.Name
	case "constant":
		v = e.Value
	case "jsonPointer":
		var x any
		if strictJSON(body, &x) != nil {
			return "", nil, errors.New("json")
		}
		var ok bool
		v, ok = jsonPointerScalar(x, e.Pointer)
		if !ok {
			return "", nil, errors.New("pointer")
		}
		ev["name"] = e.Pointer
	default:
		return "", nil, errors.New("extractor")
	}
	if !validScalar(e.Format, v) {
		return "", nil, errors.New("scalar")
	}
	ev["canonicalValue"] = v
	return v, ev, nil
}
func jsonPointerScalar(v any, pointer string) (string, bool) {
	if !strings.HasPrefix(pointer, "/") {
		return "", false
	}
	cur := v
	for _, s := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = m[strings.ReplaceAll(strings.ReplaceAll(s, "~1", "/"), "~0", "~")]
		if !ok {
			return "", false
		}
	}
	switch x := cur.(type) {
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	default:
		return "", false
	}
}
func validScalar(format, v string) bool {
	if format == "bool" {
		return v == "true" || v == "false"
	}
	if format == "uint" {
		if v == "" || len(v) > 10 || len(v) > 1 && v[0] == '0' {
			return false
		}
		for _, c := range []byte(v) {
			if c < '0' || c > '9' {
				return false
			}
		}
		_, err := strconv.ParseUint(v, 10, 32)
		return err == nil
	}
	if format == "asciiToken" {
		return validPathToken(v)
	}
	if v == "" || len(v) > 512 {
		return false
	}
	switch format {
	case "pocketbaseId":
		if len(v) != 15 {
			return false
		}
	case "uuid":
		if len(v) != 36 {
			return false
		}
	case "xid":
		if len(v) != 20 {
			return false
		}
	case "slug", "":
	default:
		return false
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func (p *Proxy) authorize(ctx context.Context, r *http.Request, c *catalog, cap capability, query string, headers http.Header, body *preparedBody, resourceID string, evidence map[string]string, upstreamQuery *string, children []batchChild, authorizedUntil *time.Time, proof *responseProof) error {
	auth, org, subject, audience, err := bearerIdentityWithOrganization(r, p.cfg, cap.OrganizationContext == "optional")
	if err != nil {
		return decisionError{http.StatusUnauthorized, "unauthorized"}
	}
	requestBinding := randomBinding()
	if proof != nil {
		requestBinding = proof.requestBinding
	}
	queryDigest := shaText(query)
	headerDigest := shaText(canonicalHeaders(headers))
	bodyDigest := body.digest()
	credentialDigest := credentialDigest(auth)
	wire := map[string]any{"providerId": p.cfg.ProviderID, "pepClientId": p.cfg.PepClientID, "catalogGeneration": c.Generation, "catalogDigest": c.CatalogDigest, "capabilityId": cap.CapabilityID, "capabilityVersion": cap.Version, "contractDigest": cap.ContractDigest, "method": cap.Method, "canonicalPath": r.URL.EscapedPath(), "canonicalQuery": query, "canonicalQueryDigest": queryDigest, "forwardedHeaderDigest": headerDigest, "bodyDigest": bodyDigest, "bodyLength": body.length(), "providerCredentialDigest": credentialDigest, "providerCredential": map[string]string{"subject": subject, "audience": audience}, "resourceEvidence": evidence, "resourceType": cap.Resource.Type, "resourceId": resourceID, "requestBinding": requestBinding}
	batchDigest := ""
	if cap.Batch != nil {
		batchDigest = batchChildrenDigest(children)
		wire["batchChildren"] = children
		wire["batchDigest"] = batchDigest
	}
	responseDigest, refsDigest := "", ""
	var responseLength uint64
	if proof != nil && proof.digest != "" {
		responseDigest = proof.digest
		responseLength = proof.length
		refsDigest = responseReferencesDigest(proof.references)
		wire["responseDigest"] = responseDigest
		wire["responseLength"] = responseLength
		wire["responseReferencesDigest"] = refsDigest
		wire["responseReferences"] = proof.references
	}
	b, err := json.Marshal(wire)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.grant+"/api/v2/http-capabilities/decide", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	if org != "" {
		req.Header.Set("X-Organization-ID", org)
	}
	req.Header.Set("X-Grant-App-Auth-Key", p.cfg.AppAuthKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return decisionError{http.StatusBadGateway, "dependency_unavailable"}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return decisionError{401, "unauthorized"}
	}
	if resp.StatusCode == 403 {
		return decisionError{403, "forbidden"}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decisionError{502, "dependency_unavailable"}
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return decisionError{502, "dependency_unavailable"}
	}
	var d struct {
		Allowed                  bool         `json:"allowed"`
		Reason                   string       `json:"reason"`
		ProviderID               string       `json:"providerId"`
		PepClientID              string       `json:"pepClientId"`
		CatalogGeneration        uint64       `json:"catalogGeneration"`
		CatalogDigest            string       `json:"catalogDigest"`
		CapabilityID             string       `json:"capabilityId"`
		CapabilityVersion        uint64       `json:"capabilityVersion"`
		ContractDigest           string       `json:"contractDigest"`
		ActionID                 string       `json:"actionId"`
		ResourceType             string       `json:"resourceType"`
		ResourceID               string       `json:"resourceId"`
		Method                   string       `json:"method"`
		CanonicalPath            string       `json:"canonicalPath"`
		CanonicalQueryDigest     string       `json:"canonicalQueryDigest"`
		ForwardedHeaderDigest    string       `json:"forwardedHeaderDigest"`
		BodyDigest               string       `json:"bodyDigest"`
		BodyLength               int          `json:"bodyLength"`
		ProviderCredentialDigest string       `json:"providerCredentialDigest"`
		ProviderSubject          string       `json:"providerSubject"`
		ProviderAudience         string       `json:"providerAudience"`
		RequestBinding           string       `json:"requestBinding"`
		PrincipalDigest          string       `json:"principalDigest"`
		IssuedAt                 string       `json:"issuedAt"`
		ExpiresAt                string       `json:"expiresAt"`
		RecordScope              *recordScope `json:"recordScope,omitempty"`
		BatchDigest              string       `json:"batchDigest,omitempty"`
		ResponseDigest           string       `json:"responseDigest,omitempty"`
		ResponseLength           uint64       `json:"responseLength,omitempty"`
		ResponseReferencesDigest string       `json:"responseReferencesDigest,omitempty"`
	}
	if strictJSON(out, &d) != nil {
		return decisionError{502, "dependency_unavailable"}
	}
	if d.BatchDigest != batchDigest {
		return decisionError{502, "dependency_unavailable"}
	}
	if d.ResponseDigest != responseDigest || d.ResponseLength != responseLength || d.ResponseReferencesDigest != refsDigest {
		return decisionError{502, "dependency_unavailable"}
	}
	if d.Reason == "" || d.ActionID != *cap.ActionID || d.ResourceType != cap.Resource.Type || d.ResourceID != resourceID || !contracts.IsPrincipalDigest(d.PrincipalDigest) || d.ProviderID != p.cfg.ProviderID || d.PepClientID != p.cfg.PepClientID || d.CatalogGeneration != c.Generation || d.CatalogDigest != c.CatalogDigest || d.CapabilityID != cap.CapabilityID || d.CapabilityVersion != cap.Version || d.ContractDigest != cap.ContractDigest || d.Method != cap.Method || d.CanonicalPath != r.URL.EscapedPath() || d.CanonicalQueryDigest != queryDigest || d.ForwardedHeaderDigest != headerDigest || d.BodyDigest != bodyDigest || int64(d.BodyLength) != body.length() || d.ProviderCredentialDigest != credentialDigest || d.ProviderSubject != subject || d.ProviderAudience != audience || d.RequestBinding != requestBinding {
		return decisionError{502, "dependency_unavailable"}
	}
	issued, issuedErr := time.Parse(time.RFC3339, d.IssuedAt)
	expiry, expiryErr := time.Parse(time.RFC3339, d.ExpiresAt)
	now := time.Now().UTC()
	if issuedErr != nil || expiryErr != nil || issued.After(now) || now.After(expiry) || !expiry.After(issued) || expiry.Sub(issued) > 5*time.Second {
		return decisionError{502, "dependency_unavailable"}
	}
	if !d.Allowed {
		return decisionError{403, "forbidden"}
	}
	if responseDigest != "" {
		if d.RecordScope != nil {
			return decisionError{502, "dependency_unavailable"}
		}
		*authorizedUntil = expiry
		return nil
	}
	transformed, err := applyRecordScope(r.URL.RawQuery, cap.RecordScope, d.RecordScope)
	if err != nil {
		return decisionError{502, "dependency_unavailable"}
	}
	*upstreamQuery = transformed
	*authorizedUntil = expiry
	return nil
}

type authorizationExpiryKey struct{}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, cap capability, query string, headers http.Header, body *preparedBody, checks ...func([]byte, http.Header, int) error) {
	u := *p.origin
	u.Path = r.URL.Path
	u.RawPath = r.URL.RawPath
	u.RawQuery = query
	u.ForceQuery = r.URL.ForceQuery
	req, err := http.NewRequestWithContext(r.Context(), cap.Method, u.String(), body.reader())
	if err != nil {
		errorJSON(w, 502, "dependency_unavailable")
		return
	}
	req.Header = headers.Clone()
	req.ContentLength = body.length()
	if cap.AccessMode == "authorized" {
		if p.cfg.AuthorizationMode == "service-token" {
			req.Header.Set("Authorization", p.cfg.UpstreamToken)
		} else {
			req.Header.Set("Authorization", r.Header.Get("Authorization"))
		}
	}
	req.Header.Set("X-Correlation-ID", randomBinding())
	if expiry, ok := r.Context().Value(authorizationExpiryKey{}).(time.Time); ok && !expiry.After(time.Now()) {
		errorJSON(w, 502, "dependency_unavailable")
		return
	}
	resp, err := p.http.Do(req)
	if err != nil {
		if cap.Method != http.MethodGet && cap.Method != http.MethodHead && cap.Method != http.MethodOptions {
			// net/http cannot reliably tell a caller whether a buffered write made
			// it past the socket.  For mutations, preserve that ambiguity rather
			// than falsely claiming failure; Exposure never retries it.
			errorJSON(w, 502, "unknown_outcome")
			return
		}
		if errors.Is(err, context.DeadlineExceeded) {
			errorJSON(w, 504, "dependency_timeout")
		} else {
			errorJSON(w, 502, "dependency_unavailable")
		}
		return
	}
	defer resp.Body.Close()
	allowedStatus := resp.StatusCode >= 200 && resp.StatusCode < 300
	for _, status := range cap.Response.ErrorStatuses {
		allowedStatus = allowedStatus || resp.StatusCode == status
	}
	if !allowedStatus {
		errorJSON(w, http.StatusBadGateway, "upstream_rejected")
		return
	}
	if connectionNominatedAny(resp.Header) {
		errorJSON(w, http.StatusBadGateway, "dependency_unavailable")
		return
	}
	limit := int64(cap.Response.MaxBytes)
	if p.cfg.MaxResponseBytes < limit {
		limit = p.cfg.MaxResponseBytes
	}
	if limit <= 0 {
		errorJSON(w, 502, "dependency_unavailable")
		return
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(b)) > limit {
		errorJSON(w, 502, "dependency_unavailable")
		return
	}
	if value := resp.Header.Get("Content-Length"); value != "" {
		n, parseErr := strconv.ParseUint(value, 10, 63)
		if parseErr != nil || strings.Trim(value, "0123456789") != "" || (cap.Method != http.MethodHead && resp.StatusCode != http.StatusNotModified && n != uint64(len(b))) {
			errorJSON(w, 502, "dependency_unavailable")
			return
		}
	}
	for _, check := range checks {
		if err := check(b, resp.Header, resp.StatusCode); err != nil {
			p.writeDecisionError(w, err)
			return
		}
	}
	allowed := map[string]bool{}
	for _, n := range cap.Response.ForwardHeaders {
		allowed[http.CanonicalHeaderKey(n)] = true
	}
	for n, vs := range resp.Header {
		cn := http.CanonicalHeaderKey(n)
		if allowed[cn] && (cn == "Content-Length" || !forbiddenHeader(cn)) && !strings.HasPrefix(strings.ToLower(cn), "x-forwarded-") {
			for _, v := range vs {
				w.Header().Add(cn, v)
			}
		}
	}
	if cap.AccessMode == "authorized" || cap.AccessMode == "public_authn" {
		// Protected responses must not outlive their decision; login responses
		// can contain newly issued credentials even when upstream says cacheable.
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(b)
}

type decisionError struct {
	status int
	code   string
}

func (e decisionError) Error() string { return e.code }
func (p *Proxy) writeDecisionError(w http.ResponseWriter, e error) {
	var d decisionError
	if errors.As(e, &d) {
		errorJSON(w, d.status, d.code)
		return
	}
	errorJSON(w, 502, "dependency_unavailable")
}
func errorJSON(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if status == 401 {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"schemaVersion":1,"errorCode":"` + code + `"}`))
}
func strictJSON(b []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

// rejectDuplicateJSONKeys rejects duplicate member names at every object
// depth. encoding/json otherwise keeps the final occurrence, which could
// make the authorization extractor and upstream consumer disagree.
func rejectDuplicateJSONKeys(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := scanJSONValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON")
		}
		return err
	}
	return nil
}

func scanJSONValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate JSON key")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("object terminator")
		}
	case '[':
		for dec.More() {
			if err := scanJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("array terminator")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}
func canonicalHeaders(h http.Header) string {
	names := make([]string, 0, len(h))
	for n := range h {
		names = append(names, strings.ToLower(n))
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(h.Get(n))
		b.WriteByte('\n')
	}
	return b.String()
}
func shaText(v string) string  { return shaBytes([]byte(v)) }
func shaBytes(v []byte) string { s := sha256.Sum256(v); return "sha256:" + hex.EncodeToString(s[:]) }
func credentialDigest(v string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(credentialDomain))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(v)))
	_, _ = h.Write(n[:])
	_, _ = h.Write([]byte(v))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
func randomBinding() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func (l *authnLimiter) allow(remote, capabilityID string, now time.Time) (int, bool) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil || net.ParseIP(host) == nil {
		return 1, false
	}
	mac := hmac.New(sha256.New, l.key)
	_, _ = mac.Write([]byte(host))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(capabilityID))
	peer := hex.EncodeToString(mac.Sum(nil)[:8])
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneStale(now)
	l.global = refill(l.global, l.globalCapacity, l.globalRefill, now)
	bucket, knownPeer := l.peers[peer]
	if !knownPeer && len(l.peers) >= maxAuthnPeers {
		l.evictOldest()
	}
	b := refill(bucket, l.peerCapacity, l.peerRefill, now)
	if l.global.tokens < 1 || b.tokens < 1 {
		l.peers[peer] = b
		return retryAfter(l.global, b, l.globalRefill, l.peerRefill), false
	}
	l.global.tokens--
	b.tokens--
	l.peers[peer] = b
	return 0, true
}

func (l *authnLimiter) pruneStale(now time.Time) {
	for key, bucket := range l.peers {
		if now.Sub(bucket.updated) > authnPeerTTL {
			delete(l.peers, key)
		}
	}
}

func (l *authnLimiter) evictOldest() {
	var oldestKey string
	var oldest time.Time
	for key, bucket := range l.peers {
		if oldestKey == "" || bucket.updated.Before(oldest) || (bucket.updated.Equal(oldest) && key < oldestKey) {
			oldestKey, oldest = key, bucket.updated
		}
	}
	if oldestKey != "" {
		delete(l.peers, oldestKey)
	}
}
func refill(b tokenBucket, capacity float64, interval time.Duration, now time.Time) tokenBucket {
	if b.updated.IsZero() {
		return tokenBucket{tokens: capacity, updated: now}
	}
	b.tokens = minFloat(capacity, b.tokens+now.Sub(b.updated).Seconds()/interval.Seconds())
	b.updated = now
	return b
}
func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
func retryAfter(global, peer tokenBucket, globalEvery, peerEvery time.Duration) int {
	wait := globalEvery
	if peer.tokens < global.tokens {
		wait = peerEvery
	}
	seconds := int(wait.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	if seconds > 3600 {
		seconds = 3600
	}
	return seconds
}
func hasCredential(r *http.Request) bool {
	return r.Header.Get("Authorization") != "" || r.Header.Get("Proxy-Authorization") != "" || r.URL.Query().Get("access_token") != "" || r.Header.Get("Cookie") != ""
}
func bearerIdentity(r *http.Request, cfg config.ProxyConfig) (string, string, string, string, error) {
	return bearerIdentityWithOrganization(r, cfg, false)
}
func bearerIdentityWithOrganization(r *http.Request, cfg config.ProxyConfig, allowOrgless bool) (string, string, string, string, error) {
	if len(r.Header.Values("Authorization")) != 1 || r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Cookie") != "" || r.URL.Query().Get("access_token") != "" || connectionNominates(r.Header, "Authorization") {
		return "", "", "", "", errors.New("auth")
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || strings.Count(auth, " ") != 1 {
		return "", "", "", "", errors.New("auth")
	}
	org := r.Header.Get("X-Organization-ID")
	if (org == "" && (!allowOrgless || len(r.Header.Values("X-Organization-ID")) != 0)) || (org != "" && len(r.Header.Values("X-Organization-ID")) != 1) {
		return "", "", "", "", errors.New("org")
	}
	parts := strings.Split(strings.TrimPrefix(auth, "Bearer "), ".")
	if len(parts) != 3 {
		return "", "", "", "", errors.New("jwt")
	}
	if cfg.CredentialMode == "goauthy" {
		subject, err := goauthyJWTSubject(parts)
		if err != nil {
			return "", "", "", "", err
		}
		return auth, org, "goauthy:" + cfg.GoauthyIssuer + "/" + subject, cfg.GoauthyApplicationID, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", "", "", err
	}
	var claims struct {
		Sub          string `json:"sub"`
		ClientID     string `json:"client_id"`
		ID           string `json:"id"`
		CollectionID string `json:"collectionId"`
		Type         string `json:"type"`
	}
	// These claims are only an echo hint; Grant validates the token and compares
	// its authenticated identity before deciding.  JWTs routinely include extra
	// standard claims, so strict request DTO decoding must not be used here.
	if rejectDuplicateJSONKeys(b) != nil || json.Unmarshal(b, &claims) != nil {
		return "", "", "", "", errors.New("claims")
	}
	if cfg.CredentialMode == "pocketbase" {
		if !config.PocketBaseID(claims.ID) || claims.CollectionID != cfg.PocketBaseCollectionID || claims.Type != "auth" {
			return "", "", "", "", errors.New("PocketBase claims")
		}
		return auth, org, "pocketbase:" + cfg.PocketBaseIssuer + "/" + claims.CollectionID + "/" + claims.ID, cfg.PocketBaseApplicationID, nil
	}
	if claims.Sub == "" || claims.ClientID == "" {
		return "", "", "", "", errors.New("claims")
	}
	return auth, org, claims.Sub, claims.ClientID, nil
}

func goauthyJWTSubject(parts []string) (string, error) {
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", errors.New("jwt")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || rejectDuplicateJSONKeys(header) != nil {
		return "", errors.New("jwt")
	}
	var headerObject map[string]json.RawMessage
	if json.Unmarshal(header, &headerObject) != nil || headerObject == nil {
		return "", errors.New("jwt")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || rejectDuplicateJSONKeys(payload) != nil {
		return "", errors.New("jwt")
	}
	if _, err = base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
		return "", errors.New("jwt")
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Sub == "" || claims.Sub != strings.TrimSpace(claims.Sub) || len(claims.Sub) > 512 || !utf8.ValidString(claims.Sub) {
		return "", errors.New("claims")
	}
	for _, r := range claims.Sub {
		if r < 32 || r == 127 {
			return "", errors.New("claims")
		}
	}
	return claims.Sub, nil
}
func connectionNominates(h http.Header, name string) bool {
	for _, v := range h.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), name) {
				return true
			}
		}
	}
	return false
}
