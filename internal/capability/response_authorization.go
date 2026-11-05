package capability

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type responseAuthorizationPolicy struct {
	RootKey        string `json:"rootKey"`
	RecordsPointer string `json:"recordsPointer"`
	ExpansionField string `json:"expansionField"`
	QueryParameter string `json:"queryParameter"`
	MaxDepth       uint64 `json:"maxDepth"`
	MaxRecords     uint64 `json:"maxRecords"`
}
type responseResource struct {
	Key           string             `json:"key"`
	ActionID      string             `json:"actionId"`
	ResourceType  string             `json:"resourceType"`
	IDField       string             `json:"idField"`
	IDFormat      string             `json:"idFormat"`
	IdentityField string             `json:"identityField"`
	IdentityValue string             `json:"identityValue"`
	Relations     []responseRelation `json:"relations"`
}
type responseRelation struct {
	Field     string `json:"field"`
	TargetKey string `json:"targetKey"`
}
type responseReference struct {
	ResourceKey   string  `json:"resourceKey"`
	ID            string  `json:"id"`
	ParentIndex   *uint64 `json:"parentIndex,omitempty"`
	RelationField string  `json:"relationField,omitempty"`
}
type responseProof struct {
	requestBinding  string
	principalDigest string
	digest          string
	length          uint64
	references      []responseReference
}
type expansionTree map[string]expansionTree

func responseReferencesDigest(refs []responseReference) string {
	if refs == nil {
		refs = []responseReference{}
	}
	b, e := json.Marshal(refs)
	if e != nil {
		return ""
	}
	var value any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if dec.Decode(&value) != nil {
		return ""
	}
	b, e = json.Marshal(value)
	if e != nil {
		return ""
	}
	return shaBytes(b)
}

func validateResponseAuthorization(c *catalog) error {
	if len(c.ResponseResources) > 256 {
		return errors.New("response resource graph too large")
	}
	nodes := map[string]responseResource{}
	previous := ""
	for _, node := range c.ResponseResources {
		if node.Key == "" || node.Key <= previous || node.ActionID == "" || node.ResourceType == "" || !rootField(node.IDField) || !slices.Contains([]string{"asciiToken", "pocketbaseId", "uuid", "xid", "slug", "uint", "bool"}, node.IDFormat) || !rootField(node.IdentityField) || node.IdentityValue == "" {
			return errors.New("invalid response resource")
		}
		nodes[node.Key] = node
		previous = node.Key
		last := ""
		for _, edge := range node.Relations {
			if !rootField(edge.Field) || edge.Field <= last || edge.TargetKey == "" {
				return errors.New("invalid response relation")
			}
			last = edge.Field
		}
	}
	for _, node := range c.ResponseResources {
		for _, edge := range node.Relations {
			if _, ok := nodes[edge.TargetKey]; !ok {
				return errors.New("missing response relation target")
			}
		}
	}
	for _, cap := range c.Capabilities {
		p := cap.ResponseAuthorization
		if p == nil {
			continue
		}
		root, ok := nodes[p.RootKey]
		if !ok || cap.Query.Mode != "exact" || cap.Method != "GET" || cap.AccessMode != "authorized" || cap.Batch != nil || cap.Request.Body != "none" || cap.Resource == nil || cap.ActionID == nil || *cap.ActionID != root.ActionID || cap.Resource.Type != root.ResourceType || !rootField(p.ExpansionField) || !rootField(p.QueryParameter) || p.MaxDepth == 0 || p.MaxDepth > 6 || p.MaxRecords == 0 || p.MaxRecords > 200 {
			return errors.New("invalid response authorization policy")
		}
		if p.RecordsPointer != "" && (!strings.HasPrefix(p.RecordsPointer, "/") || !rootField(strings.TrimPrefix(p.RecordsPointer, "/"))) {
			return errors.New("invalid response records pointer")
		}
		if p.RecordsPointer == "" {
			if cap.RecordScope != nil || cap.Resource.ID.Kind != "pathSegment" {
				return errors.New("response detail requires record resource")
			}
		} else if cap.RecordScope == nil {
			return errors.New("response list requires record scope")
		}
		found := false
		for _, q := range cap.Query.Parameters {
			if q.Name == p.QueryParameter {
				found = q.Format == "text" && !q.Required && !q.Repeated && q.MaxBytes > 0
			}
		}
		if !found {
			return errors.New("response expansion query missing")
		}
	}
	return nil
}
func requestedExpansion(raw string, c *catalog, cap capability) (expansionTree, error) {
	p := cap.ResponseAuthorization
	if p == nil {
		return nil, nil
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil, err
	}
	requested, exists := values[p.QueryParameter]
	if !exists {
		return nil, nil
	}
	if len(requested) != 1 || requested[0] == "" {
		return nil, errors.New("invalid expansion query")
	}
	nodes := map[string]responseResource{}
	for _, node := range c.ResponseResources {
		nodes[node.Key] = node
	}
	tree := expansionTree{}
	seen := map[string]bool{}
	paths := strings.Split(requested[0], ",")
	if uint64(len(paths)) > p.MaxRecords {
		return nil, errors.New("too many expansion paths")
	}
	for _, path := range paths {
		if seen[path] {
			return nil, errors.New("duplicate expansion path")
		}
		seen[path] = true
		fields := strings.Split(path, ".")
		if uint64(len(fields)) > p.MaxDepth {
			return nil, errors.New("expansion too deep")
		}
		node := nodes[p.RootKey]
		branch := tree
		for _, field := range fields {
			if !rootField(field) {
				return nil, errors.New("invalid expansion field")
			}
			target := ""
			for _, edge := range node.Relations {
				if edge.Field == field {
					target = edge.TargetKey
					break
				}
			}
			if target == "" {
				return nil, errors.New("undeclared expansion edge")
			}
			if branch[field] == nil {
				branch[field] = expansionTree{}
			}
			branch = branch[field]
			node = nodes[target]
		}
	}
	return tree, nil
}
func collectResponseReferences(c *catalog, cap capability, tree expansionTree, data []byte, rootID string) ([]responseReference, error) {
	p := cap.ResponseAuthorization
	fail := errors.New("invalid expanded response")
	if p == nil || tree == nil || rejectDuplicateJSONKeys(data) != nil {
		return nil, fail
	}
	var value any
	if strictJSON(data, &value) != nil {
		return nil, fail
	}
	nodes := map[string]responseResource{}
	for _, node := range c.ResponseResources {
		nodes[node.Key] = node
	}
	var roots []any
	if p.RecordsPointer == "" {
		roots = []any{value}
	} else {
		items, ok := batchPointer(value, p.RecordsPointer)
		if !ok {
			return nil, fail
		}
		roots, ok = items.([]any)
		if !ok {
			return nil, fail
		}
	}
	refs := make([]responseReference, 0)
	var visit func(any, string, expansionTree, uint64, *uint64, string) (string, error)
	visit = func(value any, key string, branch expansionTree, depth uint64, parent *uint64, field string) (string, error) {
		if depth > p.MaxDepth || uint64(len(refs)) >= p.MaxRecords {
			return "", fail
		}
		record, ok := value.(map[string]any)
		if !ok {
			return "", fail
		}
		node, ok := nodes[key]
		if !ok {
			return "", fail
		}
		id, ok := responseIDValue(record[node.IDField])
		if !ok || !validScalar(node.IDFormat, id) || record[node.IdentityField] != node.IdentityValue {
			return "", fail
		}
		if parent == nil && p.RecordsPointer == "" && id != rootID {
			return "", fail
		}
		index := uint64(len(refs))
		refs = append(refs, responseReference{ResourceKey: key, ID: id, ParentIndex: parent, RelationField: field})
		expanded, exists := record[p.ExpansionField]
		if !exists || expanded == nil {
			return id, nil
		}
		expansions, ok := expanded.(map[string]any)
		if !ok {
			return "", fail
		}
		fields := make([]string, 0, len(expansions))
		for field := range expansions {
			fields = append(fields, field)
		}
		sort.Strings(fields)
		for _, field := range fields {
			subtree, requested := branch[field]
			if !requested {
				return "", fail
			}
			target := ""
			for _, edge := range node.Relations {
				if edge.Field == field {
					target = edge.TargetKey
					break
				}
			}
			if target == "" {
				return "", fail
			}
			expanded := expansions[field]
			if expanded == nil {
				continue
			}
			var related []any
			if array, ok := expanded.([]any); ok {
				related = array
			} else {
				related = []any{expanded}
			}
			ids := map[string]bool{}
			switch relation := record[field].(type) {
			case string:
				if relation != "" {
					ids[relation] = true
				}
			case []any:
				for _, entry := range relation {
					s, ok := responseIDValue(entry)
					if !ok {
						return "", fail
					}
					ids[s] = true
				}
			case nil:
			default:
				return "", fail
			}
			for _, relatedRecord := range related {
				childID, e := visit(relatedRecord, target, subtree, depth+1, &index, field)
				if e != nil || !ids[childID] {
					return "", fail
				}
			}
		}
		return id, nil
	}
	for _, root := range roots {
		if _, err := visit(root, p.RootKey, tree, 0, nil, ""); err != nil {
			return nil, err
		}
	}
	return refs, nil
}

func responseIDValue(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	case bool:
		return strconv.FormatBool(v), true
	default:
		return "", false
	}
}
