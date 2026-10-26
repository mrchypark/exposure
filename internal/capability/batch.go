package capability

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type batchPolicy struct {
	Encoding             string          `json:"encoding"`
	RequestsPointer      string          `json:"requestsPointer"`
	MethodField          string          `json:"methodField"`
	URLField             string          `json:"urlField"`
	BodyField            string          `json:"bodyField"`
	HeadersField         string          `json:"headersField"`
	MaxOperations        uint64          `json:"maxOperations"`
	AllowedCapabilityIDs []string        `json:"allowedCapabilityIds"`
	Upserts              []batchUpsert   `json:"upserts,omitempty"`
	Multipart            *batchMultipart `json:"multipart,omitempty"`
}
type batchUpsert struct {
	Method             string `json:"method"`
	PathTemplate       string `json:"pathTemplate"`
	CreateCapabilityID string `json:"createCapabilityId"`
	UpdateCapabilityID string `json:"updateCapabilityId"`
	IDPointer          string `json:"idPointer"`
}
type batchMultipart struct {
	PayloadField      string   `json:"payloadField"`
	FileFieldPatterns []string `json:"fileFieldPatterns"`
}
type batchChild struct {
	Index                 uint64            `json:"index"`
	OriginalMethod        string            `json:"originalMethod"`
	OriginalPath          string            `json:"originalPath"`
	UpsertID              string            `json:"upsertId,omitempty"`
	CapabilityID          string            `json:"capabilityId"`
	CapabilityVersion     uint64            `json:"capabilityVersion"`
	ContractDigest        string            `json:"contractDigest"`
	Method                string            `json:"method"`
	CanonicalPath         string            `json:"canonicalPath"`
	CanonicalQuery        string            `json:"canonicalQuery"`
	CanonicalQueryDigest  string            `json:"canonicalQueryDigest"`
	ForwardedHeaderDigest string            `json:"forwardedHeaderDigest"`
	BodyDigest            string            `json:"bodyDigest"`
	BodyLength            uint64            `json:"bodyLength"`
	ResourceType          string            `json:"resourceType"`
	ResourceID            string            `json:"resourceId"`
	ResourceEvidence      map[string]string `json:"resourceEvidence"`
}

func batchChildrenDigest(children []batchChild) string {
	b, err := json.Marshal(children)
	if err != nil {
		return ""
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return ""
	}
	b, err = json.Marshal(value)
	if err != nil {
		return ""
	}
	return shaBytes(b)
}

func validateBatchCatalog(c *catalog) error {
	byID := map[string]capability{}
	ambiguous := map[string]bool{}
	for _, cap := range c.Capabilities {
		if !cap.Enabled {
			continue
		}
		if _, ok := byID[cap.CapabilityID]; ok {
			ambiguous[cap.CapabilityID] = true
		}
		byID[cap.CapabilityID] = cap
	}
	for _, cap := range c.Capabilities {
		p := cap.Batch
		if p == nil {
			continue
		}
		if cap.AccessMode != "authorized" || cap.Method != "POST" || cap.Query.Mode != "none" || cap.RecordScope != nil || cap.Request.Body != "opaque" || cap.Resource == nil || cap.Resource.ID.Kind != "constant" || p.Encoding != "request-array" || p.MaxOperations == 0 || p.MaxOperations > 20 || !strings.HasPrefix(p.RequestsPointer, "/") || !batchFieldIdentifier(strings.TrimPrefix(p.RequestsPointer, "/")) || len(p.AllowedCapabilityIDs) == 0 {
			return errors.New("invalid batch policy")
		}
		fields := []string{p.MethodField, p.URLField, p.BodyField, p.HeadersField}
		for i, f := range fields {
			if !batchFieldIdentifier(f) || slices.Contains(fields[:i], f) {
				return errors.New("ambiguous batch fields")
			}
		}
		previous := ""
		for _, id := range p.AllowedCapabilityIDs {
			child, ok := byID[id]
			if !ok || ambiguous[id] || id <= previous || !child.Enabled || child.Batch != nil || child.RecordScope != nil || child.Query.Mode != "none" || child.AccessMode != "authorized" || child.Resource == nil || !slices.Contains([]string{"constant", "pathSegment"}, child.Resource.ID.Kind) || !slices.Contains([]string{"POST", "PATCH", "DELETE"}, child.Method) {
				return errors.New("invalid batch child reference")
			}
			previous = id
			if cap.OrganizationContext == "optional" && child.OrganizationContext != "optional" {
				return errors.New("optional organization batch requires optional organization children")
			}
			if child.Request.Authorization != cap.Request.Authorization || (child.Method == "DELETE" && child.Request.Body != "none") || (child.Method != "DELETE" && child.Request.Body != "json" && child.Request.Body != "opaque") {
				return errors.New("incompatible batch child body or authorization")
			}
		}
		previous = ""
		for _, up := range p.Upserts {
			create, ok := byID[up.CreateCapabilityID]
			update, ok2 := byID[up.UpdateCapabilityID]
			if !ok || !ok2 || up.Method+" "+up.PathTemplate <= previous || strings.ContainsAny(up.PathTemplate, "{}") || !slices.Contains(p.AllowedCapabilityIDs, up.CreateCapabilityID) || !slices.Contains(p.AllowedCapabilityIDs, up.UpdateCapabilityID) || up.Method != "PUT" || up.PathTemplate != create.PathTemplate || create.Method != "POST" || create.Resource.ID.Kind != "constant" || update.Method != "PATCH" || update.Resource.ID.Kind != "pathSegment" || update.PathTemplate != up.PathTemplate+"/{"+update.Resource.ID.Name+"}" || !strings.HasPrefix(up.IDPointer, "/") || !batchFieldIdentifier(strings.TrimPrefix(up.IDPointer, "/")) {
				return errors.New("invalid batch upsert recipe")
			}
			previous = up.Method + " " + up.PathTemplate
		}
		if p.Multipart != nil {
			if cap.Request.Body != "opaque" || p.Multipart.PayloadField == "" || len(p.Multipart.PayloadField) > 64 || strings.ContainsAny(p.Multipart.PayloadField, "\r\n\x00") || len(p.Multipart.FileFieldPatterns) == 0 || len(p.Multipart.FileFieldPatterns) > 2 {
				return errors.New("invalid batch multipart policy")
			}
			previous = ""
			for _, pattern := range p.Multipart.FileFieldPatterns {
				if pattern <= previous {
					return errors.New("unordered indexed file patterns")
				}
				previous = pattern
				if _, err := batchFilePattern(pattern); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func batchFilePattern(pattern string) (*regexp.Regexp, error) {
	rest := strings.ReplaceAll(strings.ReplaceAll(pattern, "{index}", ""), "{field}", "")
	if len(pattern) > 128 || strings.ContainsAny(rest, "{}\r\n\x00/") || !strings.HasSuffix(pattern, "{field}") || strings.Count(pattern, "{index}") != 1 || strings.Count(pattern, "{field}") != 1 {
		return nil, errors.New("invalid indexed file pattern")
	}
	pattern = regexp.QuoteMeta(pattern)
	pattern = strings.ReplaceAll(pattern, regexp.QuoteMeta("{index}"), `(0|[1-9][0-9]*)`)
	pattern = strings.ReplaceAll(pattern, regexp.QuoteMeta("{field}"), `([A-Za-z_][A-Za-z0-9_+-]*)`)
	return regexp.Compile("^" + pattern + "$")
}
func batchFieldIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || (i > 0 && r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
func batchPointer(v any, pointer string) (any, bool) {
	for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		v, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return v, true
}

func prepareBatch(c *catalog, cap capability, contentType string, body *preparedBody) ([]batchChild, error) {
	if cap.Batch == nil {
		return nil, nil
	}
	p := cap.Batch
	fail := errors.New("invalid batch request")
	if body.file != nil {
		if _, err := body.file.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		defer body.file.Seek(0, io.SeekStart)
	}
	media, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fail
	}
	var payload []byte
	attachmentBytes := map[int]uint64{}
	attachmentFields := map[int][]string{}
	if media == "application/json" {
		payload, err = io.ReadAll(io.LimitReader(body.reader(), 1<<20+1))
		if err != nil || len(payload) > 1<<20 {
			return nil, fail
		}
	} else if media == "multipart/form-data" && p.Multipart != nil {
		if params["boundary"] == "" {
			return nil, fail
		}
		reader := multipart.NewReader(body.reader(), params["boundary"])
		seenPayload := false
		aliases := map[string]int{}
		parts := 0
		for {
			part, e := reader.NextPart()
			if e == io.EOF {
				break
			}
			if e != nil {
				return nil, fail
			}
			parts++
			if parts > 1024 {
				part.Close()
				return nil, fail
			}
			name := part.FormName()
			if name == p.Multipart.PayloadField && part.FileName() == "" {
				if seenPayload {
					part.Close()
					return nil, fail
				}
				seenPayload = true
				payload, e = io.ReadAll(io.LimitReader(part, 1<<20+1))
				part.Close()
				if e != nil || len(payload) > 1<<20 {
					return nil, fail
				}
				continue
			}
			if part.FileName() == "" {
				part.Close()
				return nil, fail
			}
			matched := false
			for patternIndex, pattern := range p.Multipart.FileFieldPatterns {
				re, e := batchFilePattern(pattern)
				if e != nil {
					return nil, e
				}
				m := re.FindStringSubmatch(name)
				if m == nil {
					continue
				}
				if matched {
					return nil, fail
				}
				matched = true
				index, e := strconv.Atoi(m[1])
				if e != nil || uint64(index) >= p.MaxOperations {
					part.Close()
					return nil, fail
				}
				field := m[2]
				key := strconv.Itoa(index) + "/" + field
				if old, ok := aliases[key]; ok && old != patternIndex {
					part.Close()
					return nil, fail
				}
				aliases[key] = patternIndex
				n, e := io.Copy(io.Discard, part)
				part.Close()
				if e != nil {
					return nil, fail
				}
				attachmentBytes[index] += uint64(n)
				attachmentFields[index] = append(attachmentFields[index], field)
			}
			if !matched {
				part.Close()
				return nil, fail
			}
		}
		if !seenPayload {
			return nil, fail
		}
	} else {
		return nil, fail
	}
	var root any
	if rejectDuplicateJSONKeys(payload) != nil || strictJSON(payload, &root) != nil {
		return nil, fail
	}
	rawItems, ok := batchPointer(root, p.RequestsPointer)
	if !ok {
		return nil, fail
	}
	items, ok := rawItems.([]any)
	if !ok || len(items) == 0 || uint64(len(items)) > p.MaxOperations {
		return nil, fail
	}
	for index := range attachmentBytes {
		if index >= len(items) {
			return nil, fail
		}
	}
	byID := map[string]capability{}
	for _, child := range c.Capabilities {
		if child.Enabled {
			byID[child.CapabilityID] = child
		}
	}
	result := make([]batchChild, 0, len(items))
	for index, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fail
		}
		for key := range m {
			if !slices.Contains([]string{p.MethodField, p.URLField, p.BodyField, p.HeadersField}, key) {
				return nil, fail
			}
		}
		method, ok := m[p.MethodField].(string)
		if !ok {
			return nil, fail
		}
		target, ok := m[p.URLField].(string)
		if !ok {
			return nil, fail
		}
		u, e := url.Parse(target)
		if e != nil || !strings.HasPrefix(target, "/") || strings.Contains(target, "#") || strings.HasPrefix(target, "//") || u.IsAbs() || u.Host != "" || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || validateIncomingPath(&http.Request{URL: u}) != nil {
			return nil, fail
		}
		if h, exists := m[p.HeadersField]; exists && h != nil {
			headers, ok := h.(map[string]any)
			if !ok || len(headers) != 0 {
				return nil, fail
			}
		}
		itemBody := map[string]any{}
		if v, exists := m[p.BodyField]; exists && v != nil {
			itemBody, ok = v.(map[string]any)
			if !ok {
				return nil, fail
			}
		}
		for _, field := range attachmentFields[index] {
			if _, collision := itemBody[field]; collision {
				return nil, fail
			}
			for _, up := range p.Upserts {
				if field == strings.TrimPrefix(up.IDPointer, "/") {
					return nil, fail
				}
			}
		}
		semanticBody, e := json.Marshal(itemBody)
		if e != nil {
			return nil, fail
		}
		type targetCap struct {
			cap  capability
			path string
		}
		targets := []targetCap{}
		upsertID := ""
		if method == "PUT" {
			found := false
			for _, up := range p.Upserts {
				if up.Method != method || up.PathTemplate != u.EscapedPath() {
					continue
				}
				if found {
					return nil, fail
				}
				found = true
				targets = append(targets, targetCap{byID[up.CreateCapabilityID], u.EscapedPath()})
				idValue, exists := batchPointer(itemBody, up.IDPointer)
				if exists && idValue != nil {
					id, ok := idValue.(string)
					if !ok {
						return nil, fail
					}
					upsertID = id
					if id != "" {
						update := byID[up.UpdateCapabilityID]
						if !validScalar(update.Resource.ID.Format, id) {
							return nil, fail
						}
						targets = append(targets, targetCap{update, strings.ReplaceAll(update.PathTemplate, "{"+update.Resource.ID.Name+"}", id)})
					}
				}
			}
			if !found {
				return nil, fail
			}
		} else {
			child, _ := findCapability(c.Capabilities, method, u.EscapedPath())
			if child == nil || !slices.Contains(p.AllowedCapabilityIDs, child.CapabilityID) {
				return nil, fail
			}
			targets = append(targets, targetCap{*child, u.EscapedPath()})
		}
		for _, target := range targets {
			child := target.cap
			if child.Batch != nil || child.RecordScope != nil || child.AccessMode != "authorized" {
				return nil, fail
			}
			childBody := semanticBody
			if child.Request.Body != "none" {
				requiredMedia := "application/json"
				if len(attachmentFields[index]) > 0 {
					requiredMedia = "multipart/form-data"
				}
				if len(child.Request.ContentTypes) > 0 && !slices.Contains(child.Request.ContentTypes, requiredMedia) {
					return nil, fail
				}
				if child.Request.Body == "json" && requiredMedia != "application/json" || child.Request.Body == "multipart" && requiredMedia != "multipart/form-data" {
					return nil, fail
				}
			}
			if child.Request.Body == "none" {
				if len(itemBody) != 0 || len(attachmentFields[index]) != 0 {
					return nil, fail
				}
				childBody = nil
			}
			if uint64(len(childBody))+attachmentBytes[index] > child.Request.MaxBytes {
				return nil, fail
			}
			captures, ok := matchTemplateParameters(child.PathTemplate, target.path, child.PathParameters)
			if !ok {
				return nil, fail
			}
			id, evidence, e := extract(child.Resource, captures, "", childBody)
			if e != nil {
				return nil, fail
			}
			result = append(result, batchChild{Index: uint64(index), OriginalMethod: method, OriginalPath: u.EscapedPath(), UpsertID: upsertID, CapabilityID: child.CapabilityID, CapabilityVersion: child.Version, ContractDigest: child.ContractDigest, Method: child.Method, CanonicalPath: target.path, CanonicalQuery: "", CanonicalQueryDigest: shaText(""), ForwardedHeaderDigest: shaText(""), BodyDigest: shaBytes(childBody), BodyLength: uint64(len(childBody)), ResourceType: child.Resource.Type, ResourceID: id, ResourceEvidence: evidence})
		}
	}
	return result, nil
}
