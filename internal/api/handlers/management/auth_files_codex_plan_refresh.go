package management

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	internalcodex "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/codex"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	codexPlanTypeRefreshStateIdle                = "idle"
	codexPlanTypeRefreshStateRunning             = "running"
	codexPlanTypeRefreshStateCompleted           = "completed"
	codexPlanTypeRefreshStateCompletedWithErrors = "completed_with_errors"
	codexPlanTypeRefreshStateFailed              = "failed"
	codexPlanTypeRefreshStatusUpdated            = "updated"
	codexPlanTypeRefreshStatusUnchanged          = "unchanged"
	codexPlanTypeRefreshStatusSkipped            = "skipped"
	codexPlanTypeRefreshStatusFailed             = "failed"
	codexPlanTypeRefreshUserAgent                = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
)

var codexPlanTypeRefreshUsageURL = "https://chatgpt.com/backend-api/wham/usage"

type codexPlanTypeRefreshSummary struct {
	Eligible  int `json:"eligible"`
	Processed int `json:"processed"`
	Updated   int `json:"updated"`
	Unchanged int `json:"unchanged"`
	Skipped   int `json:"skipped"`
	Failed    int `json:"failed"`
}

type codexPlanTypeRefreshResult struct {
	Name           string `json:"name"`
	AuthID         string `json:"auth_id"`
	Status         string `json:"status"`
	PlanTypeBefore string `json:"plan_type_before,omitempty"`
	PlanTypeAfter  string `json:"plan_type_after,omitempty"`
	HTTPStatus     int    `json:"http_status,omitempty"`
	Error          string `json:"error,omitempty"`
}

type codexPlanTypeRefreshTask struct {
	State       string                       `json:"state"`
	Running     bool                         `json:"running"`
	StartedAt   time.Time                    `json:"started_at,omitempty"`
	FinishedAt  time.Time                    `json:"finished_at,omitempty"`
	CurrentName string                       `json:"current_name,omitempty"`
	Summary     codexPlanTypeRefreshSummary  `json:"summary"`
	Results     []codexPlanTypeRefreshResult `json:"results"`
}

func (h *Handler) StartCodexPlanTypeRefresh(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}

	manager := h.authManager
	startedAt := time.Now().UTC()

	h.codexPlanRefreshMu.Lock()
	if h.codexPlanRefresh.Running {
		snapshot := h.codexPlanTypeRefreshSnapshotLocked()
		h.codexPlanRefreshMu.Unlock()
		c.JSON(http.StatusConflict, snapshot)
		return
	}
	h.codexPlanRefresh = codexPlanTypeRefreshTask{
		State:     codexPlanTypeRefreshStateRunning,
		Running:   true,
		StartedAt: startedAt,
		Results:   make([]codexPlanTypeRefreshResult, 0),
	}
	snapshot := h.codexPlanTypeRefreshSnapshotLocked()
	h.codexPlanRefreshMu.Unlock()

	go h.runCodexPlanTypeRefresh(manager)

	c.JSON(http.StatusAccepted, snapshot)
}

func (h *Handler) GetCodexPlanTypeRefreshStatus(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	c.JSON(http.StatusOK, h.codexPlanTypeRefreshSnapshot())
}

func (h *Handler) codexPlanTypeRefreshSnapshot() codexPlanTypeRefreshTask {
	h.codexPlanRefreshMu.Lock()
	defer h.codexPlanRefreshMu.Unlock()
	return h.codexPlanTypeRefreshSnapshotLocked()
}

func (h *Handler) codexPlanTypeRefreshSnapshotLocked() codexPlanTypeRefreshTask {
	snapshot := h.codexPlanRefresh
	if strings.TrimSpace(snapshot.State) == "" {
		snapshot.State = codexPlanTypeRefreshStateIdle
	}
	if len(snapshot.Results) == 0 {
		snapshot.Results = make([]codexPlanTypeRefreshResult, 0)
	} else {
		snapshot.Results = append([]codexPlanTypeRefreshResult(nil), snapshot.Results...)
	}
	return snapshot
}

func (h *Handler) runCodexPlanTypeRefresh(manager *coreauth.Manager) {
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Errorf("management codex plan type refresh panic: %v", recovered)
			h.finishCodexPlanTypeRefresh(codexPlanTypeRefreshStateFailed)
		}
	}()

	if manager == nil {
		h.finishCodexPlanTypeRefresh(codexPlanTypeRefreshStateFailed)
		return
	}

	for _, auth := range manager.List() {
		if !isCodexPlanTypeRefreshEligibleAuth(auth) {
			continue
		}
		name := codexPlanTypeRefreshName(auth)
		h.beginCodexPlanTypeRefreshAuth(name)
		result := h.refreshSingleCodexPlanType(manager, auth)
		h.recordCodexPlanTypeRefreshResult(result)
	}

	state := codexPlanTypeRefreshStateCompleted
	snapshot := h.codexPlanTypeRefreshSnapshot()
	if snapshot.Summary.Failed > 0 {
		state = codexPlanTypeRefreshStateCompletedWithErrors
	}
	h.finishCodexPlanTypeRefresh(state)
}

func isCodexPlanTypeRefreshEligibleAuth(auth *coreauth.Auth) bool {
	if auth == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return false
	}
	if isRuntimeOnlyAuth(auth) {
		return false
	}
	if auth.Metadata == nil {
		return false
	}
	if auth.Attributes != nil && strings.TrimSpace(auth.Attributes["api_key"]) != "" {
		return false
	}
	path := strings.TrimSpace(authAttribute(auth, "path"))
	if path == "" {
		return false
	}
	if _, err := os.Stat(path); err != nil {
		return false
	}
	return true
}

func codexPlanTypeRefreshName(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if name := strings.TrimSpace(auth.FileName); name != "" {
		return name
	}
	return strings.TrimSpace(auth.ID)
}

func (h *Handler) beginCodexPlanTypeRefreshAuth(name string) {
	h.codexPlanRefreshMu.Lock()
	defer h.codexPlanRefreshMu.Unlock()
	h.codexPlanRefresh.Summary.Eligible++
	h.codexPlanRefresh.CurrentName = strings.TrimSpace(name)
}

func (h *Handler) recordCodexPlanTypeRefreshResult(result codexPlanTypeRefreshResult) {
	h.codexPlanRefreshMu.Lock()
	defer h.codexPlanRefreshMu.Unlock()
	h.codexPlanRefresh.CurrentName = ""
	h.codexPlanRefresh.Summary.Processed++
	switch result.Status {
	case codexPlanTypeRefreshStatusUpdated:
		h.codexPlanRefresh.Summary.Updated++
	case codexPlanTypeRefreshStatusUnchanged:
		h.codexPlanRefresh.Summary.Unchanged++
	case codexPlanTypeRefreshStatusSkipped:
		h.codexPlanRefresh.Summary.Skipped++
	case codexPlanTypeRefreshStatusFailed:
		h.codexPlanRefresh.Summary.Failed++
	}
	h.codexPlanRefresh.Results = append(h.codexPlanRefresh.Results, result)
}

func (h *Handler) finishCodexPlanTypeRefresh(state string) {
	h.codexPlanRefreshMu.Lock()
	defer h.codexPlanRefreshMu.Unlock()
	if strings.TrimSpace(state) == "" {
		state = codexPlanTypeRefreshStateFailed
	}
	h.codexPlanRefresh.State = state
	h.codexPlanRefresh.Running = false
	h.codexPlanRefresh.FinishedAt = time.Now().UTC()
	h.codexPlanRefresh.CurrentName = ""
}

func (h *Handler) refreshSingleCodexPlanType(manager *coreauth.Manager, auth *coreauth.Auth) codexPlanTypeRefreshResult {
	result := codexPlanTypeRefreshResult{
		Name:           codexPlanTypeRefreshName(auth),
		AuthID:         strings.TrimSpace(auth.ID),
		PlanTypeBefore: effectiveCodexPlanType(auth),
	}

	accountID := internalcodex.EffectiveAccountID(auth.Metadata)
	if accountID == "" {
		result.Status = codexPlanTypeRefreshStatusSkipped
		result.Error = "account_id not found"
		return result
	}

	accessToken := codexAccessTokenFromMetadata(auth.Metadata)
	refreshToken := codexRefreshTokenFromMetadata(auth.Metadata)
	forcePersist := false

	if accessToken == "" && refreshToken != "" {
		var refreshErr error
		auth, refreshErr = refreshCodexPlanTypeAuth(manager, auth)
		if refreshErr != nil {
			result.Status = codexPlanTypeRefreshStatusSkipped
			result.Error = fmt.Sprintf("access token refresh failed: %v", refreshErr)
			return result
		}
		forcePersist = true
		accountID = firstNonEmptyValue(internalcodex.EffectiveAccountID(auth.Metadata), accountID)
		accessToken = codexAccessTokenFromMetadata(auth.Metadata)
	}
	if accessToken == "" {
		if forcePersist {
			if err := persistCodexPlanTypeRefreshAuth(context.Background(), manager, auth, "", accountID, true); err != nil {
				result.Status = codexPlanTypeRefreshStatusFailed
				result.Error = fmt.Sprintf("persist refreshed auth: %v", err)
				return result
			}
		}
		result.Status = codexPlanTypeRefreshStatusSkipped
		result.Error = "access_token not found"
		return result
	}

	planType, statusCode, err := h.fetchCodexUsagePlanType(context.Background(), auth, accessToken, accountID)
	if (statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden) && refreshToken != "" {
		auth, err = refreshCodexPlanTypeAuth(manager, auth)
		if err != nil {
			if forcePersist {
				if errPersist := persistCodexPlanTypeRefreshAuth(context.Background(), manager, auth, "", accountID, true); errPersist != nil {
					result.Status = codexPlanTypeRefreshStatusFailed
					result.HTTPStatus = statusCode
					result.Error = fmt.Sprintf("persist refreshed auth: %v", errPersist)
					return result
				}
			}
			result.Status = codexPlanTypeRefreshStatusFailed
			result.HTTPStatus = statusCode
			result.Error = fmt.Sprintf("usage request unauthorized and refresh failed: %v", err)
			return result
		}
		forcePersist = true
		accountID = firstNonEmptyValue(internalcodex.EffectiveAccountID(auth.Metadata), accountID)
		accessToken = codexAccessTokenFromMetadata(auth.Metadata)
		if accessToken == "" {
			if errPersist := persistCodexPlanTypeRefreshAuth(context.Background(), manager, auth, "", accountID, true); errPersist != nil {
				result.Status = codexPlanTypeRefreshStatusFailed
				result.HTTPStatus = statusCode
				result.Error = fmt.Sprintf("persist refreshed auth: %v", errPersist)
				return result
			}
			result.Status = codexPlanTypeRefreshStatusSkipped
			result.HTTPStatus = statusCode
			result.Error = "access_token not found after refresh"
			return result
		}
		planType, statusCode, err = h.fetchCodexUsagePlanType(context.Background(), auth, accessToken, accountID)
	}
	if err != nil {
		if forcePersist {
			if errPersist := persistCodexPlanTypeRefreshAuth(context.Background(), manager, auth, "", accountID, true); errPersist != nil {
				result.Status = codexPlanTypeRefreshStatusFailed
				result.HTTPStatus = statusCode
				result.Error = fmt.Sprintf("persist refreshed auth: %v", errPersist)
				return result
			}
		}
		result.Status = codexPlanTypeRefreshStatusFailed
		result.HTTPStatus = statusCode
		result.Error = err.Error()
		return result
	}

	result.HTTPStatus = statusCode
	result.PlanTypeAfter = planType
	if err = persistCodexPlanTypeRefreshAuth(context.Background(), manager, auth, planType, accountID, forcePersist); err != nil {
		result.Status = codexPlanTypeRefreshStatusFailed
		result.Error = fmt.Sprintf("persist auth: %v", err)
		return result
	}

	if strings.EqualFold(strings.TrimSpace(result.PlanTypeBefore), strings.TrimSpace(planType)) {
		result.Status = codexPlanTypeRefreshStatusUnchanged
		return result
	}
	result.Status = codexPlanTypeRefreshStatusUpdated
	return result
}

func refreshCodexPlanTypeAuth(manager *coreauth.Manager, auth *coreauth.Auth) (*coreauth.Auth, error) {
	if manager == nil {
		return auth, fmt.Errorf("core auth manager unavailable")
	}
	executor, ok := manager.Executor("codex")
	if !ok || executor == nil {
		return auth, fmt.Errorf("codex refresh executor unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultAPICallTimeout)
	defer cancel()
	refreshed, err := executor.Refresh(ctx, auth)
	if refreshed != nil {
		auth = refreshed
	}
	if err != nil {
		return auth, err
	}
	return auth, nil
}

func persistCodexPlanTypeRefreshAuth(ctx context.Context, manager *coreauth.Manager, auth *coreauth.Auth, planType string, accountID string, forcePersist bool) error {
	if manager == nil || auth == nil {
		return fmt.Errorf("core auth manager unavailable")
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}

	changed := forcePersist
	planType = strings.TrimSpace(planType)
	accountID = strings.TrimSpace(accountID)

	if planType != "" {
		if current := strings.TrimSpace(stringValue(auth.Metadata, "plan_type")); current != planType {
			auth.Metadata["plan_type"] = planType
			changed = true
		}
		if current := strings.TrimSpace(auth.Attributes["plan_type"]); current != planType {
			auth.Attributes["plan_type"] = planType
			changed = true
		}
	}
	if accountID != "" {
		if current := strings.TrimSpace(stringValue(auth.Metadata, "account_id")); current != accountID {
			auth.Metadata["account_id"] = accountID
			changed = true
		}
	}

	if !changed {
		return nil
	}

	auth.UpdatedAt = time.Now().UTC()
	_, err := manager.Update(ctx, auth)
	return err
}

func (h *Handler) fetchCodexUsagePlanType(ctx context.Context, auth *coreauth.Auth, accessToken string, accountID string) (string, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctxRequest, cancel := context.WithTimeout(ctx, defaultAPICallTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctxRequest, http.MethodGet, codexPlanTypeRefreshUsageURL, nil)
	if err != nil {
		return "", 0, fmt.Errorf("build usage request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", codexPlanTypeRefreshUserAgent)
	req.Header.Set("Chatgpt-Account-Id", strings.TrimSpace(accountID))

	httpClient := &http.Client{
		Timeout:   defaultAPICallTimeout,
		Transport: h.apiCallTransport(auth),
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("usage request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("codex usage response body close error: %v", errClose)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("read usage response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", resp.StatusCode, fmt.Errorf("usage request returned %d", resp.StatusCode)
	}

	var payload struct {
		PlanType  string `json:"plan_type"`
		PlanType2 string `json:"planType"`
	}
	if err = json.Unmarshal(body, &payload); err != nil {
		return "", resp.StatusCode, fmt.Errorf("decode usage response: %w", err)
	}

	planType := strings.TrimSpace(payload.PlanType)
	if planType == "" {
		planType = strings.TrimSpace(payload.PlanType2)
	}
	if planType == "" {
		return "", resp.StatusCode, fmt.Errorf("usage response missing plan_type")
	}
	return planType, resp.StatusCode, nil
}

func firstNonEmptyValue(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func codexAccessTokenFromMetadata(metadata map[string]any) string {
	if token := firstNonEmptyValue(stringValue(metadata, "access_token"), stringValue(metadata, "accessToken")); token != "" {
		return token
	}
	tokenRaw, ok := metadata["token"]
	if !ok || tokenRaw == nil {
		return ""
	}
	tokenMap, ok := tokenRaw.(map[string]any)
	if !ok {
		return ""
	}
	return firstNonEmptyValue(stringValue(tokenMap, "access_token"), stringValue(tokenMap, "accessToken"))
}

func codexRefreshTokenFromMetadata(metadata map[string]any) string {
	if token := firstNonEmptyValue(stringValue(metadata, "refresh_token"), stringValue(metadata, "refreshToken")); token != "" {
		return token
	}
	tokenRaw, ok := metadata["token"]
	if !ok || tokenRaw == nil {
		return ""
	}
	tokenMap, ok := tokenRaw.(map[string]any)
	if !ok {
		return ""
	}
	return firstNonEmptyValue(stringValue(tokenMap, "refresh_token"), stringValue(tokenMap, "refreshToken"))
}
