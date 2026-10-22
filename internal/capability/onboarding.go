package capability

// Only these exact authenticated self-service contracts may omit organization.
// This is not a public access mode and never bypasses the Grant decision.
func managementOnboardingCapability(provider string, cap capability) bool {
	if provider != "grant-management" || cap.AccessMode != "authorized" || cap.ActionID == nil || cap.Resource == nil || cap.Request.Authorization != "forward-user" || cap.Resource.Type != "service" || cap.Resource.ID.Kind != "constant" || cap.Resource.ID.Value != "grant" || cap.RecordScope != nil || cap.Batch != nil || cap.ResponseAuthorization != nil {
		return false
	}
	action, body := "", "none"
	switch cap.Method + " " + cap.PathTemplate {
	case "POST /api/v1/me/ensure":
		action = "user.materialize"
	case "GET /api/v1/me":
		action = "user.read"
	case "GET /api/v1/orgs":
		action = "organization.list"
	case "POST /api/v1/orgs":
		action, body = "organization.create", "json"
	default:
		return false
	}
	return *cap.ActionID == "grant-management."+action && cap.Request.Body == body
}
