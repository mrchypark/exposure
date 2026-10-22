package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strings"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/readiness"
	"github.com/mrchypark/exposure/internal/service"
)

type API struct {
	svc         *service.Service
	gate        *readiness.Gate
	maxResponse int64
	sem         chan struct{}
}

func New(s *service.Service, g *readiness.Gate, maxResponse int64, maxConcurrent int) *API {
	return &API{svc: s, gate: g, maxResponse: maxResponse, sem: make(chan struct{}, maxConcurrent)}
}
func (a *API) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", a.health)
	m.HandleFunc("GET /readyz", a.ready)
	m.HandleFunc("GET /v1/exposures/{exposureId}/resources/{resourceId}", a.read)
	return a.security(a.canonicalPath(a.limit(m)))
}
func (a *API) canonicalPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if path.Clean(r.URL.Path) != r.URL.Path {
			writeError(w, http.StatusUnprocessableEntity, "invalid_request", correlation(r))
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (a *API) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case a.sem <- struct{}{}:
			defer func() { <-a.sem }()
			next.ServeHTTP(w, r)
		default:
			writeError(w, 503, "overloaded", correlation(r))
		}
	})
}
func (a *API) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		next.ServeHTTP(w, r)
	})
}
func (a *API) read(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", correlation(r))
		return
	}
	if !a.protectedReady(w, r) {
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.ContentLength != 0 || r.TransferEncoding != nil {
		writeError(w, 422, "invalid_request", correlation(r))
		return
	}
	e, id := r.PathValue("exposureId"), r.PathValue("resourceId")
	if !readID(e) || !readID(id) {
		writeError(w, 422, "invalid_request", correlation(r))
		return
	}
	auth, org, ok, unauthenticated := readHeaders(r)
	if !ok {
		if unauthenticated {
			writeError(w, http.StatusUnauthorized, "unauthorized", correlation(r))
			return
		}
		writeError(w, 422, "invalid_request", correlation(r))
		return
	}
	out, err := a.svc.Read(r.Context(), service.ReadRequest{ExposureID: e, ResourceID: id, Authorization: auth, OrganizationID: org})
	if err != nil {
		a.handle(w, correlation(r), err)
		return
	}
	a.writeJSON(w, 200, out)
}
func readID(v string) bool { return v != "" && !strings.ContainsAny(v, "/\\?#") }
func readHeaders(r *http.Request) (string, string, bool, bool) {
	for _, n := range []string{"Authorization", "X-Organization-ID", "X-Grant-App-Auth-Key"} {
		if connectionNominates(r.Header, n) {
			return "", "", false, false
		}
	}
	if len(r.Header.Values("X-Grant-App-Auth-Key")) != 0 {
		return "", "", false, false
	}
	get := func(n string) (string, bool) {
		v := r.Header.Values(n)
		return func() string {
			if len(v) == 1 {
				return v[0]
			}
			return ""
		}(), len(v) == 1 && v[0] != ""
	}
	auth, ok := get("Authorization")
	if !ok || !validBearerAuthorization(auth) {
		return "", "", false, len(r.Header.Values("Authorization")) <= 1
	}
	org, ok := get("X-Organization-ID")
	return auth, org, ok, false
}

func validBearerAuthorization(value string) bool {
	separator := strings.IndexByte(value, ' ')
	if separator < 0 || !strings.EqualFold(value[:separator], "Bearer") {
		return false
	}
	tokenStart := separator
	for tokenStart < len(value) && value[tokenStart] == ' ' {
		tokenStart++
	}
	token := value[tokenStart:]
	if token == "" {
		return false
	}
	padding, seenTokenCharacter := false, false
	for _, char := range token {
		if char == '=' {
			if !seenTokenCharacter {
				return false
			}
			padding = true
			continue
		}
		if padding || !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("-._~+/", char)) {
			return false
		}
		seenTokenCharacter = true
	}
	return seenTokenCharacter
}
func connectionNominates(h http.Header, n string) bool {
	for _, v := range h.Values("Connection") {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), n) {
				return true
			}
		}
	}
	return false
}
func (a *API) writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil || int64(len(b)) > a.maxResponse {
		writeError(w, 503, "response_unavailable", "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
func (a *API) handle(w http.ResponseWriter, c string, err error) {
	switch {
	case errors.Is(err, service.ErrUnauthenticated):
		writeError(w, http.StatusUnauthorized, "unauthorized", c)
	case errors.Is(err, service.ErrDenied):
		writeError(w, 403, "forbidden", c)
	case errors.Is(err, service.ErrConflict):
		writeError(w, 409, "read_conflict", c)
	case errors.Is(err, service.ErrUnavailable):
		writeError(w, 503, "dependency_unavailable", c)
	case errors.Is(err, contracts.ErrContract):
		writeError(w, 422, "contract_invalid", c)
	default:
		writeError(w, 500, "internal_error", c)
	}
}
func (a *API) protectedReady(w http.ResponseWriter, r *http.Request) bool {
	ok, _ := a.gate.Ready()
	if !ok {
		writeError(w, 503, "not_ready", correlation(r))
		return false
	}
	return true
}
func (a *API) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
func (a *API) ready(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	ok, checks := a.gate.Ready()
	status := http.StatusOK
	if !ok {
		status = http.StatusServiceUnavailable
	}
	a.writeJSON(w, status, struct {
		Ready  bool              `json:"ready"`
		Checks map[string]string `json:"checks"`
	}{ok, checks})
}
func writeError(w http.ResponseWriter, status int, code, c string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		SchemaVersion int    `json:"schemaVersion"`
		ErrorCode     string `json:"errorCode"`
		CorrelationID string `json:"correlationId,omitempty"`
	}{1, code, c})
}
func correlation(r *http.Request) string {
	v := r.Header.Get("X-Correlation-ID")
	if len(v) > 128 {
		return ""
	}
	for _, c := range v {
		if !(c == '-' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return ""
		}
	}
	return v
}
