package capability

import (
	"net/url"
	"strings"
	"testing"

	"github.com/ganigeorgiev/fexpr"
)

func testScopePolicy() *recordScopePolicy {
	return &recordScopePolicy{FilterParameter: "filter", RowKey: "id", Grammar: "fexpr", MaxIDs: 199, MaxFilterBytes: 65536, AllowedFields: []string{"id", "name"}, SortParameter: "sort"}
}
func TestRecordScopeCompositionPreservesOtherRawQuery(t *testing.T) {
	p := testScopePolicy()
	raw := "page=1&filter=" + url.QueryEscape(`name = "a" || name = 'b' // comment`) + "&sort=-name&tag=a%2fb+z"
	result, err := applyRecordScope(raw, p, &recordScope{IDs: []string{"*", "a\"b", "z"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result, "page=1&filter=") || !strings.HasSuffix(result, "&sort=-name&tag=a%2fb+z") {
		t.Fatal(result)
	}
	q, _ := url.ParseQuery(result)
	filter := q.Get("filter")
	groups, err := fexpr.Parse(filter)
	if err != nil || len(groups) != 2 || groups[1].Join != fexpr.JoinAnd {
		t.Fatalf("unbound conjunction %q %v", filter, err)
	}
	if strings.Contains(filter, "//") || !strings.Contains(filter, `id = "*"`) {
		t.Fatal(filter)
	}
}
func TestRecordScopeRejectsUnsafeClientExpressions(t *testing.T) {
	p := testScopePolicy()
	for _, filter := range []string{`name='a') || true = true || (name='b'`, `@request.auth.id = 'x'`, `parent.name = 'x'`, `@collection.users.id = 'x'`, `lower(name) = 'x'`, `unknown = 'x'`, `name = 'x' &&`} {
		if err := validateScopeRequest("filter="+url.QueryEscape(filter), p); err == nil {
			t.Errorf("accepted %s", filter)
		}
	}
	for _, sort := range []string{"@random", "parent.name", "unknown", "+-name", "name,"} {
		if err := validateScopeRequest("sort="+url.QueryEscape(sort), p); err == nil {
			t.Errorf("accepted sort %s", sort)
		}
	}
}
func TestRecordScopeEmptyAndInvalidDecision(t *testing.T) {
	p := testScopePolicy()
	raw, err := applyRecordScope("page=2", p, &recordScope{IDs: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.ParseQuery(raw)
	if q.Get("filter") != "(1 = 0)" {
		t.Fatal(raw)
	}
	for _, s := range []*recordScope{nil, {}, {IDs: []string{"b", "a"}}, {IDs: []string{"a", "a"}}, {IDs: []string{""}}, {IDs: []string{"bad\n"}}} {
		if _, err := applyRecordScope("", p, s); err == nil {
			t.Fatalf("accepted invalid scope %#v", s)
		}
	}
	if _, err := applyRecordScope("", nil, &recordScope{IDs: []string{}}); err == nil {
		t.Fatal("unexpected scope accepted")
	}
	p.MaxFilterBytes = 3
	if _, err := applyRecordScope("", p, &recordScope{IDs: []string{"a"}}); err == nil {
		t.Fatal("oversized expression accepted")
	}
}
func TestRecordScopeExpressionBound(t *testing.T) {
	p := testScopePolicy()
	ids := make([]string, 199)
	for i := range ids {
		ids[i] = strings.Repeat("a", i+1)
	}
	raw := "filter=" + url.QueryEscape("name='a' || name='b'")
	if _, err := applyRecordScope(raw, p, &recordScope{IDs: ids}); err == nil {
		t.Fatal("201 expressions accepted")
	}
}

func TestScopedCatalogRejectsUnboundQueryMeaning(t *testing.T) {
	p := testScopePolicy()
	p.Pagination = &paginationPolicy{PageParameter: "page", PageSizeParameter: "perPage", SkipTotalParameter: "skipTotal"}
	c := capability{Method: "GET", AccessMode: "authorized", Resource: &resource{ID: extractor{Kind: "constant", Value: "records"}}, Request: requestPolicy{Body: "none"}, RecordScope: p, Query: queryPolicy{Mode: "exact", Parameters: []queryParam{{Name: "filter", Format: "text"}, {Name: "sort", Format: "text"}, {Name: "page", Format: "uint"}, {Name: "perPage", Format: "uint"}, {Name: "skipTotal", Format: "bool"}}}}
	if err := validateRecordScope(c); err != nil {
		t.Fatal(err)
	}
	for _, q := range []queryParam{{Name: "expand", Format: "text"}, {Name: "expand", Format: "asciiToken"}, {Name: "customJoin", Format: "bool"}} {
		bad := c
		bad.Query.Parameters = append(append([]queryParam{}, c.Query.Parameters...), q)
		if validateRecordScope(bad) == nil {
			t.Fatal("accepted unbound query", q)
		}
	}
	unbound := *p
	unbound.SortParameter = ""
	c.RecordScope = &unbound
	if validateRecordScope(c) == nil {
		t.Fatal("unbound sort accepted")
	}
	for _, v := range []string{"+1", "-1", "01", "4294967296", "1.0"} {
		if validScalar("uint", v) {
			t.Fatal("invalid uint", v)
		}
	}
	for _, v := range []string{"1", "True", "yes"} {
		if validScalar("bool", v) {
			t.Fatal("invalid bool", v)
		}
	}
}

func TestFilterLiteralRoundTrip(t *testing.T) {
	for _, literal := range []string{"한글", "a\u2028b", "a\"b\\c", "a\nb"} {
		rendered, _, err := scopeClientFilter("name = "+"\""+strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n").Replace(literal)+"\"", testScopePolicy())
		if err != nil {
			t.Fatal(err)
		}
		ast, err := fexpr.Parse(rendered)
		if err != nil {
			t.Fatal(err)
		}
		got := ast[0].Item.(fexpr.Expr).Right.Literal
		if got != literal {
			t.Fatalf("literal changed: %q != %q", got, literal)
		}
	}
}
