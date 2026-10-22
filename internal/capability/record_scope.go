package capability

import (
	"errors"
	"net/url"
	"sort"
	"strings"

	"github.com/ganigeorgiev/fexpr"
)

type recordScopePolicy struct {
	FilterParameter string            `json:"filterParameter"`
	RowKey          string            `json:"rowKey"`
	Grammar         string            `json:"grammar"`
	MaxIDs          uint64            `json:"maxIds"`
	MaxFilterBytes  uint64            `json:"maxFilterBytes"`
	AllowedFields   []string          `json:"allowedFields"`
	SortParameter   string            `json:"sortParameter,omitempty"`
	Pagination      *paginationPolicy `json:"pagination,omitempty"`
}
type paginationPolicy struct {
	PageParameter      string `json:"pageParameter,omitempty"`
	PageSizeParameter  string `json:"pageSizeParameter,omitempty"`
	SkipTotalParameter string `json:"skipTotalParameter,omitempty"`
}
type recordScope struct {
	IDs []string `json:"ids"`
}

// fexpr decodes quote/backslash and n/r/t escapes, but not Go's \u or \x
// escapes. Preserve Unicode literals while escaping only its native syntax.
var filterTextEscaper = strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r", "\t", "\\t")

func quoteFilterText(s string) string { return "\"" + filterTextEscaper.Replace(s) + "\"" }

func rootField(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func validateRecordScope(c capability) error {
	p := c.RecordScope
	if p == nil {
		return nil
	}
	if c.Request.Body != "none" || c.Method != "GET" || c.AccessMode != "authorized" || c.Resource == nil || c.Resource.ID.Kind != "constant" || p.Grammar != "fexpr" || p.MaxIDs == 0 || p.MaxIDs > 199 || p.MaxFilterBytes == 0 || p.MaxFilterBytes > 65536 || !rootField(p.RowKey) || !rootField(p.FilterParameter) {
		return errors.New("invalid record scope policy")
	}
	last := ""
	for _, field := range p.AllowedFields {
		if !rootField(field) || field <= last {
			return errors.New("invalid scope field allowlist")
		}
		last = field
	}
	if !sort.StringsAreSorted(p.AllowedFields) || !containsField(p.AllowedFields, p.RowKey) {
		return errors.New("scope row key missing from fields")
	}
	foundFilter, foundSort := false, p.SortParameter == ""
	for _, q := range c.Query.Parameters {
		if q.Name == p.FilterParameter {
			foundFilter = q.Format == "text" && !q.Required && !q.Repeated
		}
		if q.Name == p.SortParameter {
			foundSort = q.Format == "text" && !q.Repeated && !q.Required
		}
	}
	if !foundFilter || !foundSort || p.SortParameter == p.FilterParameter || p.SortParameter != "" && !rootField(p.SortParameter) {
		return errors.New("invalid scope query policy")
	}
	roles := map[string]string{p.FilterParameter: "text"}
	if p.SortParameter != "" {
		roles[p.SortParameter] = "text"
	}
	if p.Pagination != nil {
		for _, role := range []struct{ name, format string }{{p.Pagination.PageParameter, "uint"}, {p.Pagination.PageSizeParameter, "uint"}, {p.Pagination.SkipTotalParameter, "bool"}} {
			if role.name == "" {
				continue
			}
			if !rootField(role.name) || roles[role.name] != "" {
				return errors.New("invalid pagination role")
			}
			roles[role.name] = role.format
		}
	}
	if response := c.ResponseAuthorization; response != nil {
		if !rootField(response.QueryParameter) || roles[response.QueryParameter] != "" {
			return errors.New("invalid response expansion role")
		}
		roles[response.QueryParameter] = "text"
	}
	for _, q := range c.Query.Parameters {
		if roles[q.Name] == "" || roles[q.Name] != q.Format || q.Repeated {
			return errors.New("query parameter has no safe scope role")
		}
		delete(roles, q.Name)
	}
	if len(roles) != 0 {
		return errors.New("scope query role missing")
	}
	return nil
}
func containsField(fields []string, s string) bool {
	i := sort.SearchStrings(fields, s)
	return i < len(fields) && fields[i] == s
}

// Parse and re-render the complete expression: raw text (including comments or
// parentheses) can never escape the generated authorization conjunction.
func scopeClientFilter(raw string, p *recordScopePolicy) (string, int, error) {
	if raw == "" {
		return "", 0, nil
	}
	groups, err := fexpr.Parse(raw)
	if err != nil {
		return "", 0, err
	}
	count := 0
	var render func([]fexpr.ExprGroup) (string, error)
	token := func(t fexpr.Token) (string, error) {
		switch t.Type {
		case fexpr.TokenIdentifier:
			if t.Meta != nil || !(containsField(p.AllowedFields, t.Literal) || t.Literal == "true" || t.Literal == "false" || t.Literal == "null") {
				return "", errors.New("filter field is not allowed")
			}
			return t.Literal, nil
		case fexpr.TokenNumber:
			return t.Literal, nil
		case fexpr.TokenText:
			return quoteFilterText(t.Literal), nil
		default:
			return "", errors.New("filter functions and joins are not allowed")
		}
	}
	render = func(gs []fexpr.ExprGroup) (string, error) {
		var out strings.Builder
		for i, g := range gs {
			if i > 0 {
				if g.Join != fexpr.JoinAnd && g.Join != fexpr.JoinOr {
					return "", errors.New("invalid filter join")
				}
				out.WriteString(" " + string(g.Join) + " ")
			}
			switch e := g.Item.(type) {
			case []fexpr.ExprGroup:
				s, err := render(e)
				if err != nil {
					return "", err
				}
				out.WriteString("(" + s + ")")
			case fexpr.Expr:
				count++
				if count > 200 {
					return "", errors.New("too many filter expressions")
				}
				l, err := token(e.Left)
				if err != nil {
					return "", err
				}
				r, err := token(e.Right)
				if err != nil {
					return "", err
				}
				out.WriteString(l + " " + string(e.Op) + " " + r)
			default:
				return "", errors.New("invalid filter expression")
			}
		}
		return out.String(), nil
	}
	result, err := render(groups)
	return result, count, err
}
func validateScopeRequest(raw string, p *recordScopePolicy) error {
	if p == nil {
		return nil
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return err
	}
	if _, _, err = scopeClientFilter(values.Get(p.FilterParameter), p); err != nil {
		return err
	}
	if p.SortParameter != "" && values.Get(p.SortParameter) != "" {
		for _, field := range strings.Split(values.Get(p.SortParameter), ",") {
			if strings.HasPrefix(field, "+") || strings.HasPrefix(field, "-") {
				field = field[1:]
			}
			if !containsField(p.AllowedFields, field) {
				return errors.New("sort field is not allowed")
			}
		}
	}
	return nil
}
func applyRecordScope(raw string, p *recordScopePolicy, scope *recordScope) (string, error) {
	if p == nil {
		if scope != nil {
			return "", errors.New("unexpected record scope")
		}
		return raw, nil
	}
	if scope == nil || scope.IDs == nil || uint64(len(scope.IDs)) > p.MaxIDs {
		return "", errors.New("missing or oversized record scope")
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "", err
	}
	client, count, err := scopeClientFilter(values.Get(p.FilterParameter), p)
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(scope.IDs))
	last := ""
	for _, id := range scope.IDs {
		if !validText(id, 256) || id == "" || id <= last {
			return "", errors.New("invalid record scope IDs")
		}
		last = id
		parts = append(parts, p.RowKey+" = "+quoteFilterText(id))
	}
	scoped := "1 = 0"
	clauses := len(parts)
	if clauses == 0 {
		clauses = 1
	} else {
		scoped = strings.Join(parts, " || ")
	}
	if count+clauses > 200 {
		return "", errors.New("too many combined filter expressions")
	}
	combined := "(" + scoped + ")"
	if client != "" {
		combined = combined + " && (" + client + ")"
	}
	if uint64(len(combined)) > p.MaxFilterBytes {
		return "", errors.New("combined filter exceeds policy bound")
	}
	replacement := strings.ReplaceAll(url.QueryEscape(p.FilterParameter), "+", "%20") + "=" + strings.ReplaceAll(url.QueryEscape(combined), "+", "%20")
	// Only the declared filter value changes. Every other raw query pair keeps
	// its byte spelling and order, including percent escape case and plus signs.
	pieces := strings.Split(raw, "&")
	replaced := false
	for i, piece := range pieces {
		key, _, _ := strings.Cut(piece, "=")
		decoded, e := url.QueryUnescape(key)
		if e != nil {
			return "", e
		}
		if decoded == p.FilterParameter {
			if replaced {
				return "", errors.New("duplicate filter")
			}
			pieces[i] = replacement
			replaced = true
		}
	}
	if !replaced {
		if raw == "" {
			return replacement, nil
		}
		pieces = append(pieces, replacement)
	}
	return strings.Join(pieces, "&"), nil
}
