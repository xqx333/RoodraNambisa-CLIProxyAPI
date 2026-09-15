package management

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	chatgptwebauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/chatgptweb"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/managementdiag"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/proxypool"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

type authFileRuntimeSummary struct {
	proxyBinding *proxypool.BindingStatus
	accountInfo  *chatgptwebauth.AccountInfoAuthRuntimeState
}

func (h *Handler) authFileRuntimeSummaries() map[string]authFileRuntimeSummary {
	if h == nil {
		return make(map[string]authFileRuntimeSummary)
	}
	h.mu.Lock()
	authManager := h.authManager
	h.mu.Unlock()
	return h.authFileRuntimeSummariesForManager(authManager)
}

func (h *Handler) authFileRuntimeSummariesForManager(authManager *coreauth.Manager) map[string]authFileRuntimeSummary {
	if authManager == nil {
		return h.authFileRuntimeSummariesForAuths(nil, nil)
	}
	return h.authFileRuntimeSummariesForAuths(authManager, authManager.AuthsForProviders(chatgptwebauth.Provider))
}

// authFileRuntimeSummariesForAuths collects account-info state only for the supplied
// auths while retaining proxy bindings for dependency resolution across the full pool.
func (h *Handler) authFileRuntimeSummariesForAuths(authManager *coreauth.Manager, auths []*coreauth.Auth) map[string]authFileRuntimeSummary {
	summaries := make(map[string]authFileRuntimeSummary)
	if h == nil {
		return summaries
	}
	h.mu.Lock()
	proxyManager := h.proxyPoolManager
	h.mu.Unlock()
	if proxyManager != nil {
		for _, status := range proxyManager.BindingStatuses() {
			statusCopy := status
			summary := summaries[status.AuthID]
			summary.proxyBinding = &statusCopy
			summaries[status.AuthID] = summary
		}
	}
	controller, ok := chatGPTWebAccountInfoControllerForManager(authManager)
	if !ok || authManager == nil {
		return summaries
	}
	for _, auth := range auths {
		if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), chatgptwebauth.Provider) {
			continue
		}
		state := controller.AccountInfoAuthState(auth.ID)
		stateCopy := state
		summary := summaries[auth.ID]
		summary.accountInfo = &stateCopy
		summaries[auth.ID] = summary
	}
	return summaries
}

func (h *Handler) authFileRuntimeSummary(authID string) authFileRuntimeSummary {
	return h.authFileRuntimeSummaries()[strings.TrimSpace(authID)]
}

func authFileRuntimeSummaryForAuth(auth *coreauth.Auth, graph *coreauth.ChatGPTWebDependencyGraph, summaries map[string]authFileRuntimeSummary) authFileRuntimeSummary {
	if auth == nil {
		return authFileRuntimeSummary{}
	}
	if sourceUID := coreauth.ChatGPTWebLinkedSourceUID(auth); sourceUID != "" {
		ownSummary := summaries[auth.ID]
		source, ambiguous := graph.SourceByUID(sourceUID)
		if ambiguous {
			return ownSummary
		}
		sourceID := coreauth.ChatGPTWebLinkedSourceID(auth)
		if source != nil && !coreauth.ChatGPTWebLinkedSourceMatches(auth, source) {
			return ownSummary
		}
		sourceSummary := summaries[sourceID]
		if sourceSummary.proxyBinding == nil || strings.TrimSpace(sourceSummary.proxyBinding.CredentialUID) != sourceUID {
			return ownSummary
		}
		ownSummary.proxyBinding = sourceSummary.proxyBinding
		return ownSummary
	}
	return summaries[auth.ID]
}

func applyChatGPTWebAuthFileSummary(entry gin.H, auth *coreauth.Auth, now time.Time, runtimeSummaries ...authFileRuntimeSummary) {
	applyChatGPTWebAuthFileSummaryWithDetail(entry, auth, now, managementdiag.DetailLevelSafe, runtimeSummaries...)
}

func applyChatGPTWebAuthFileSummaryWithDetail(entry gin.H, auth *coreauth.Auth, now time.Time, detailLevel string, runtimeSummaries ...authFileRuntimeSummary) {
	if entry == nil || auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), "chatgpt-web") {
		return
	}
	var runtimeSummary authFileRuntimeSummary
	if len(runtimeSummaries) > 0 {
		runtimeSummary = runtimeSummaries[0]
	}
	applyChatGPTWebMetadataSummary(entry, auth.Metadata, auth.LifecycleState(), now)
	entry["account_info_refreshable"] = !auth.Disabled &&
		auth.Status != coreauth.StatusDisabled &&
		auth.LifecycleRefreshable()
	entry["account_info_manual_recheckable"] = chatGPTWebAccountInfoManualRecheckable(auth)
	if runtimeSummary.accountInfo != nil {
		entry["quota_refreshing"] = runtimeSummary.accountInfo.Refreshing
		entry["account_info_recovery_state"] = runtimeSummary.accountInfo.RecoveryState
		entry["account_info_recovery_attempts"] = runtimeSummary.accountInfo.RecoveryAttempts
		entry["account_info_recovery_max_attempts"] = runtimeSummary.accountInfo.RecoveryMaxAttempts
		entry["account_info_consecutive_failures"] = runtimeSummary.accountInfo.ConsecutiveFailures
		if runtimeSummary.accountInfo.RecoveryStopReason != "" {
			entry["account_info_recovery_stop_reason"] = runtimeSummary.accountInfo.RecoveryStopReason
		}
		if !runtimeSummary.accountInfo.NextRefreshAt.IsZero() {
			entry["quota_next_refresh_at"] = runtimeSummary.accountInfo.NextRefreshAt
		}
		if runtimeSummary.accountInfo.LastError != "" {
			entry["quota_last_error"] = chatgptwebauth.SafeQuotaError(runtimeSummary.accountInfo.LastError)
		}
		if runtimeSummary.accountInfo.LastFailure != "" {
			entry["account_info_last_failure"] = chatgptwebauth.SafeQuotaError(runtimeSummary.accountInfo.LastFailure)
		}
		if !runtimeSummary.accountInfo.LastFailureAt.IsZero() {
			entry["account_info_last_failure_at"] = runtimeSummary.accountInfo.LastFailureAt
		}
		if !runtimeSummary.accountInfo.LastSuccessAt.IsZero() {
			entry["account_info_last_success_at"] = runtimeSummary.accountInfo.LastSuccessAt
		}
	}
	credential, _ := chatgptwebauth.ParseCredential(auth.Metadata)
	applyAuthCooldownStatus(entry, chatGPTWebQuotaCooldownStatus(auth, credential, runtimeSummary.accountInfo, now))
	if auth.LastError == nil {
		return
	}
	category := chatGPTWebRequestErrorCategory(auth.LastError)
	if auth.LastError.HTTPStatus == 429 {
		category = "rate_limited"
	} else if category == "authentication_failed" && summarizeAuthCooldown(auth, now).Active {
		category = "credential_cooldown"
	} else if category == "authentication_failed" {
		if reason, _ := entry["lifecycle_reason"].(string); reason != "" {
			category = reason
		}
	}
	safeDiagnostic := chatGPTWebManagementErrorDiagnostic(auth.LastError.Diagnostic, auth.EnsureIndex(), detailLevel)
	errorMessage := safeChatGPTWebErrorMessage(category)
	if managementdiag.NormalizeDetailLevel(detailLevel) == managementdiag.DetailLevelFull {
		if fullMessage, _ := managementdiag.ProcessText(auth.LastError.Message, detailLevel, 4096); strings.TrimSpace(fullMessage) != "" {
			errorMessage = fullMessage
		}
	}
	entry["last_error"] = &coreauth.Error{
		Code:       category,
		Message:    errorMessage,
		Retryable:  auth.LastError.Retryable,
		HTTPStatus: auth.LastError.HTTPStatus,
		Diagnostic: safeDiagnostic,
	}
	if reason, _ := entry["lifecycle_reason"].(string); reason == "" {
		entry["status_message"] = category
	}
	if safeDiagnostic != nil {
		entry["last_diagnostic"] = safeDiagnostic
	}
}

// Runtime failures are not evidence that authentication failed. Preserve known
// lifecycle reasons, otherwise describe only the observed HTTP/transport class.
func chatGPTWebRequestErrorCategory(err *coreauth.Error) string {
	if err == nil {
		return "request_failed"
	}
	if reason := chatgptwebauth.SafeLifecycleReason(strings.ToLower(strings.TrimSpace(err.Code))); reason != "" && reason != "authentication_failed" {
		return reason
	}
	if err.Diagnostic != nil {
		switch err.Diagnostic.Code {
		case "network_timeout", "request_canceled", "dns_error", "tls_error", "proxy_error", "network_error", "cloudflare_challenge":
			return err.Diagnostic.Code
		}
	}
	switch err.HTTPStatus {
	case 401:
		return "authentication_failed"
	case 403:
		return "permission_denied"
	case 404:
		return "not_found"
	case 429:
		return "rate_limited"
	case 451:
		return "access_restricted"
	}
	if err.HTTPStatus >= 500 {
		return "upstream_error"
	}
	if err.HTTPStatus >= 400 {
		return "request_rejected"
	}
	if err.Code == "authentication_failed" && err.Diagnostic == nil {
		return "authentication_failed"
	}
	return "request_failed"
}

func chatGPTWebAccountInfoManualRecheckable(auth *coreauth.Auth) bool {
	if auth == nil || auth.Disabled || auth.Status == coreauth.StatusDisabled {
		return false
	}
	switch auth.LifecycleState() {
	case "", coreauth.LifecycleStateActive, coreauth.LifecycleStateReauthRequired,
		coreauth.LifecycleStateInteractionRequired:
		return true
	default:
		return false
	}
}

func safeChatGPTWebErrorDiagnostic(diagnostic *coreauth.ErrorDiagnostic, authIndex string) *coreauth.ErrorDiagnostic {
	return chatGPTWebManagementErrorDiagnostic(diagnostic, authIndex, managementdiag.DetailLevelSafe)
}

func chatGPTWebManagementErrorDiagnostic(diagnostic *coreauth.ErrorDiagnostic, authIndex, detailLevel string) *coreauth.ErrorDiagnostic {
	if diagnostic == nil {
		return nil
	}
	detailLevel = managementdiag.NormalizeDetailLevel(detailLevel)
	responseBody, responseBodyTruncated := managementdiag.ProcessResponseBody(diagnostic.ResponseBody, detailLevel, 4096)
	safe := &coreauth.ErrorDiagnostic{
		Provider:              "chatgpt-web",
		AuthIndex:             safeChatGPTWebDiagnosticToken(authIndex, 64),
		Stage:                 safeChatGPTWebDiagnosticToken(diagnostic.Stage, 64),
		Code:                  chatgptwebauth.SafeDiagnosticCode(diagnostic.Code),
		ResponseType:          safeChatGPTWebDiagnosticToken(diagnostic.ResponseType, 32),
		ContentType:           safeChatGPTWebDiagnosticToken(diagnostic.ContentType, 128),
		CFRay:                 safeChatGPTWebDiagnosticToken(diagnostic.CFRay, 128),
		Persona:               safeChatGPTWebDiagnosticToken(diagnostic.Persona, 64),
		CatalogVersion:        safeChatGPTWebDiagnosticToken(diagnostic.CatalogVersion, 16),
		CatalogID:             safeChatGPTWebDiagnosticToken(diagnostic.CatalogID, 64),
		TransportPersonaID:    safeChatGPTWebDiagnosticToken(diagnostic.TransportPersonaID, 64),
		BrowserEnvironmentID:  safeChatGPTWebDiagnosticToken(diagnostic.BrowserEnvironmentID, 96),
		TLSProfile:            safeChatGPTWebDiagnosticToken(diagnostic.TLSProfile, 64),
		UAMajor:               safeChatGPTWebDiagnosticToken(diagnostic.UAMajor, 16),
		Platform:              safeChatGPTWebDiagnosticToken(diagnostic.Platform, 64),
		ResponseBytes:         diagnostic.ResponseBytes,
		ResponseBody:          responseBody,
		ResponseBodyTruncated: diagnostic.ResponseBodyTruncated || responseBodyTruncated,
		Attempts:              diagnostic.Attempts,
		HTTPStatus:            diagnostic.HTTPStatus,
		Cloudflare:            diagnostic.Cloudflare,
		Retryable:             diagnostic.Retryable,
	}
	if safe.Attempts < 0 || safe.Attempts > 100 {
		safe.Attempts = 0
	}
	if host := strings.ToLower(strings.TrimSpace(diagnostic.TargetHost)); safeChatGPTWebDiagnosticHost(host) {
		safe.TargetHost = host
	}
	if path := strings.TrimSpace(diagnostic.TargetPath); strings.HasPrefix(path, "/") {
		processed := managementdiag.ProcessURL("https://management.invalid"+path, detailLevel)
		path = strings.TrimPrefix(processed, "https://management.invalid")
		for _, character := range path {
			if character < 0x20 || character == 0x7f {
				path = ""
				break
			}
		}
		if len(path) > 128 {
			path = path[:128]
		}
		safe.TargetPath = path
	}
	if safe.Stage == "" && safe.Code == "" && safe.HTTPStatus == 0 {
		return nil
	}
	return safe
}

func safeChatGPTWebDiagnosticHost(host string) bool {
	if host == "external_asset" {
		return true
	}
	for _, suffix := range []string{"chatgpt.com", "openai.com", "oaiusercontent.com", "oaistatic.com", "blob.core.windows.net"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func safeChatGPTWebDiagnosticToken(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit > 0 && len(value) > limit {
		value = value[:limit]
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._-/ :()", character) {
			continue
		}
		return ""
	}
	return value
}

func applyChatGPTWebMetadataSummary(entry gin.H, metadata map[string]any, lifecycleState string, now time.Time) {
	if entry == nil {
		return
	}
	state := string(chatgptwebauth.SafeLifecycleState(lifecycleState))
	reason := chatgptwebauth.SafeLifecycleReason(stringValue(metadata, "lifecycle_reason"))
	entry["lifecycle_state"] = state
	entry["lifecycle_reason"] = reason
	entry["reason"] = reason
	entry["status_message"] = reason

	applyChatGPTWebSummaryTime(entry, metadata, "lifecycle_updated_at", "lifecycle_updated_at")
	applyChatGPTWebSummaryTime(entry, metadata, "last_login_at", "last_login_at")
	applyChatGPTWebSummaryTime(entry, metadata, "last_refresh_at", "last_refresh_at")
	applyChatGPTWebSummaryTime(entry, metadata, "last_relogin_at", "last_relogin_at")
	if expiresAt, ok := parseLastRefreshValue(metadata["expired"]); ok {
		entry["token_expires_at"] = expiresAt
		entry["token_expired"] = !now.Before(expiresAt)
	}
	strategy := strings.TrimSpace(stringValue(metadata, "refresh_strategy"))
	mode := strings.TrimSpace(stringValue(metadata, "credential_mode"))
	if credential, errParse := chatgptwebauth.ParseCredential(metadata); errParse == nil {
		strategy = string(credential.RefreshStrategy)
		mode = credential.CredentialMode
		applyChatGPTWebAdvancedSecuritySummary(entry, credential)
		planType := strings.TrimSpace(credential.PlanType)
		entry["plan_type"] = planType
		entry["quota_state"] = string(credential.QuotaState)
		entry["quota_stale"] = credential.QuotaStale
		if credential.ImageQuotaRemaining != nil {
			entry["image_quota_remaining"] = *credential.ImageQuotaRemaining
		}
		applyChatGPTWebSummaryTime(entry, metadata, "image_quota_reset_at", "image_quota_reset_at")
		applyChatGPTWebSummaryTime(entry, metadata, "quota_updated_at", "quota_updated_at")
		if credential.QuotaLastError != "" {
			entry["quota_last_error"] = chatgptwebauth.SafeQuotaError(credential.QuotaLastError)
		}
	}
	entry["credential_mode"] = mode
	entry["refresh_strategy"] = strategy
	entry["token_only"] = strategy == string(chatgptwebauth.RefreshStrategyTokenOnly)
	entry["token_refreshable"] = strategy != "" && strategy != string(chatgptwebauth.RefreshStrategyTokenOnly)
	entry["source_auth_id"] = strings.TrimSpace(stringValue(metadata, "source_auth_id"))
	entry["source_credential_uid"] = strings.TrimSpace(stringValue(metadata, "source_credential_uid"))
	if uid := strings.TrimSpace(stringValue(metadata, "credential_uid")); uid != "" {
		entry["credential_uid"] = uid
	}
}

func applyChatGPTWebAdvancedSecuritySummary(entry gin.H, credential *chatgptwebauth.Credential) {
	if entry == nil || credential == nil || credential.AdvancedAccountSecurity == nil {
		return
	}
	advanced := credential.AdvancedAccountSecurity
	entry["credential_schema_version"] = credential.CredentialSchemaVersion
	entry["advanced_account_security"] = gin.H{
		"enabled":            advanced.Enabled,
		"login_method":       strings.TrimSpace(advanced.LoginMethod),
		"passkey_count":      len(advanced.Passkeys),
		"recovery_key_count": len(advanced.RecoveryKeys),
	}
}

func chatGPTWebQuotaCooldownStatus(auth *coreauth.Auth, credential *chatgptwebauth.Credential, runtimeState *chatgptwebauth.AccountInfoAuthRuntimeState, now time.Time) authCooldownStatus {
	status := summarizeAuthCooldown(auth, now)
	if status.Active && status.Scope == "auth" {
		return status
	}
	if auth == nil || auth.Disabled || auth.Status == coreauth.StatusDisabled {
		return status
	}
	blocked, blockedUntil := coreauth.ChatGPTWebImageCapabilityUnavailable(auth, now)
	if !blocked {
		return status
	}
	status.Active = true
	status.Scope = "model"
	if !modelCooldownForAuth(auth, now, chatgptwebauth.ImageModel).Active {
		status.ModelCount++
	}
	if blockedUntil.After(status.Until) {
		status.Until = blockedUntil
	}
	if until := chatGPTWebQuotaRecheckAt(credential, runtimeState, now); until.After(status.Until) {
		status.Until = until
	}
	return status
}

func chatGPTWebImageModelCooldownStatus(auth *coreauth.Auth, credential *chatgptwebauth.Credential, runtimeState *chatgptwebauth.AccountInfoAuthRuntimeState, now time.Time, modelIDs ...string) authCooldownStatus {
	status := modelCooldownForAuth(auth, now, modelIDs...)
	if status.Active && status.Scope == "auth" {
		return status
	}
	if auth == nil || auth.Disabled || auth.Status == coreauth.StatusDisabled {
		return status
	}
	if !containsChatGPTWebImageModel(modelIDs) {
		return status
	}
	blocked, blockedUntil := coreauth.ChatGPTWebImageCapabilityUnavailable(auth, now)
	if !blocked {
		return status
	}
	status.Active = true
	status.Scope = "model"
	status.ModelCount = 1
	if blockedUntil.After(status.Until) {
		status.Until = blockedUntil
	}
	if until := chatGPTWebQuotaRecheckAt(credential, runtimeState, now); until.After(status.Until) {
		status.Until = until
	}
	return status
}

func chatGPTWebQuotaRecheckAt(credential *chatgptwebauth.Credential, runtimeState *chatgptwebauth.AccountInfoAuthRuntimeState, now time.Time) time.Time {
	if runtimeState != nil && runtimeState.NextRefreshAt.After(now) {
		return runtimeState.NextRefreshAt
	}
	if credential != nil {
		if resetAt, errParse := time.Parse(time.RFC3339Nano, strings.TrimSpace(credential.ImageQuotaResetAt)); errParse == nil && resetAt.After(now) {
			return resetAt
		}
	}
	return time.Time{}
}

func containsChatGPTWebImageModel(modelIDs []string) bool {
	for _, modelID := range modelIDs {
		if strings.EqualFold(strings.TrimSpace(modelID), chatgptwebauth.ImageModel) {
			return true
		}
	}
	return false
}

func trimModelsPrefix(modelID string) string {
	modelID = strings.TrimSpace(modelID)
	const prefix = "models/"
	if len(modelID) >= len(prefix) && strings.EqualFold(modelID[:len(prefix)], prefix) {
		return strings.TrimSpace(modelID[len(prefix):])
	}
	return modelID
}

func applyChatGPTWebDependencySummary(entry gin.H, auth *coreauth.Auth, graph *coreauth.ChatGPTWebDependencyGraph) {
	if entry == nil || auth == nil {
		return
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	switch provider {
	case "codex":
		uid := coreauth.ChatGPTWebCredentialUID(auth)
		entry["credential_uid"] = uid
		entry["deletion_state"] = strings.TrimSpace(stringValue(auth.Metadata, "deletion_state"))
		entry["retained_for_dependents"] = coreauth.ChatGPTWebAuthRetainedForDependents(auth)
		count, names, _ := retainedDependencySummary(auth, graph)
		entry["dependent_count"] = count
		entry["dependent_names"] = names
		if requestedAt := retainedDeletionRequestedAt(auth); requestedAt != "" {
			if parsed, errParse := time.Parse(time.RFC3339Nano, requestedAt); errParse == nil {
				entry["deletion_requested_at"] = parsed
			}
		}
	case "chatgpt-web":
		entry["source_missing"] = retainedSourceMissing(auth, graph)
	}
}

func applyChatGPTWebSummaryTime(entry gin.H, metadata map[string]any, responseKey, metadataKey string) {
	if timestamp, ok := parseLastRefreshValue(metadata[metadataKey]); ok {
		entry[responseKey] = timestamp
	}
}
