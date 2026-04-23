package management

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

func TestCodexPlanTypeRefreshUpdatesPlanTypeAndListAuthFiles(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer access-1" {
			t.Fatalf("authorization = %q, want %q", got, "Bearer access-1")
		}
		if got := r.Header.Get("Chatgpt-Account-Id"); got != "acct-1" {
			t.Fatalf("account header = %q, want %q", got, "acct-1")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"plan_type":"team"}`))
	}))
	defer server.Close()

	restoreUsageURL := codexPlanTypeRefreshUsageURL
	codexPlanTypeRefreshUsageURL = server.URL
	defer func() { codexPlanTypeRefreshUsageURL = restoreUsageURL }()

	h, manager, path, authID := newCodexPlanRefreshTestHandler(t, map[string]any{
		"type":         "codex",
		"email":        "codex@example.com",
		"access_token": "access-1",
		"id_token":     testManagementCodexJWT("acct-1", "pro"),
	})

	postRec := performManagementRequest(t, http.MethodPost, "/v0/management/auth-files/codex/plan-type-refresh", "", h.StartCodexPlanTypeRefresh)
	if postRec.Code != http.StatusAccepted {
		t.Fatalf("POST status = %d, want %d; body=%s", postRec.Code, http.StatusAccepted, postRec.Body.String())
	}

	snapshot := waitForCodexPlanTypeRefreshDone(t, h)
	if snapshot.State != codexPlanTypeRefreshStateCompleted {
		t.Fatalf("state = %q, want %q", snapshot.State, codexPlanTypeRefreshStateCompleted)
	}
	if snapshot.Summary.Updated != 1 {
		t.Fatalf("updated = %d, want 1", snapshot.Summary.Updated)
	}
	if len(snapshot.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(snapshot.Results))
	}
	if snapshot.Results[0].Status != codexPlanTypeRefreshStatusUpdated {
		t.Fatalf("result status = %q, want %q", snapshot.Results[0].Status, codexPlanTypeRefreshStatusUpdated)
	}
	if snapshot.Results[0].PlanTypeAfter != "team" {
		t.Fatalf("plan_type_after = %q, want %q", snapshot.Results[0].PlanTypeAfter, "team")
	}

	current, ok := manager.GetByID(authID)
	if !ok || current == nil {
		t.Fatal("expected auth to remain registered")
	}
	if got := current.Attributes["plan_type"]; got != "team" {
		t.Fatalf("runtime plan_type = %q, want %q", got, "team")
	}

	rawFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read auth file: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(rawFile, &payload); err != nil {
		t.Fatalf("unmarshal auth file: %v", err)
	}
	if got, _ := payload["plan_type"].(string); got != "team" {
		t.Fatalf("persisted plan_type = %q, want %q", got, "team")
	}

	listRec := performManagementRequest(t, http.MethodGet, "/v0/management/auth-files", "", h.ListAuthFiles)
	if listRec.Code != http.StatusOK {
		t.Fatalf("ListAuthFiles status = %d, want %d; body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var listPayload struct {
		Files []map[string]any `json:"files"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listPayload); err != nil {
		t.Fatalf("unmarshal list response: %v", err)
	}
	if len(listPayload.Files) != 1 {
		t.Fatalf("files = %d, want 1", len(listPayload.Files))
	}
	if got, _ := listPayload.Files[0]["plan_type"].(string); got != "team" {
		t.Fatalf("top-level plan_type = %q, want %q", got, "team")
	}
}

func TestCodexPlanTypeRefreshRejectsConcurrentRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)

	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"plan_type":"pro"}`))
	}))
	defer server.Close()

	restoreUsageURL := codexPlanTypeRefreshUsageURL
	codexPlanTypeRefreshUsageURL = server.URL
	defer func() { codexPlanTypeRefreshUsageURL = restoreUsageURL }()

	h, _, _, _ := newCodexPlanRefreshTestHandler(t, map[string]any{
		"type":         "codex",
		"email":        "codex@example.com",
		"access_token": "access-1",
		"id_token":     testManagementCodexJWT("acct-1", "pro"),
	})

	firstRec := performManagementRequest(t, http.MethodPost, "/v0/management/auth-files/codex/plan-type-refresh", "", h.StartCodexPlanTypeRefresh)
	if firstRec.Code != http.StatusAccepted {
		t.Fatalf("first POST status = %d, want %d; body=%s", firstRec.Code, http.StatusAccepted, firstRec.Body.String())
	}

	waitForCodexPlanTypeRefreshRunning(t, h)

	getRec := performManagementRequest(t, http.MethodGet, "/v0/management/auth-files/codex/plan-type-refresh", "", h.GetCodexPlanTypeRefreshStatus)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d; body=%s", getRec.Code, http.StatusOK, getRec.Body.String())
	}
	var statusPayload codexPlanTypeRefreshTask
	if err := json.Unmarshal(getRec.Body.Bytes(), &statusPayload); err != nil {
		t.Fatalf("unmarshal GET response: %v", err)
	}
	if !statusPayload.Running {
		t.Fatalf("running = %v, want true", statusPayload.Running)
	}

	secondRec := performManagementRequest(t, http.MethodPost, "/v0/management/auth-files/codex/plan-type-refresh", "", h.StartCodexPlanTypeRefresh)
	if secondRec.Code != http.StatusConflict {
		t.Fatalf("second POST status = %d, want %d; body=%s", secondRec.Code, http.StatusConflict, secondRec.Body.String())
	}

	close(release)
	waitForCodexPlanTypeRefreshDone(t, h)
}

func TestCodexPlanTypeRefreshRetriesAfterUnauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch got := r.Header.Get("Authorization"); got {
		case "Bearer access-old":
			atomic.AddInt32(&requests, 1)
			w.WriteHeader(http.StatusUnauthorized)
		case "Bearer access-new":
			atomic.AddInt32(&requests, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"plan_type":"team"}`))
		default:
			t.Fatalf("unexpected authorization header %q", got)
		}
	}))
	defer server.Close()

	restoreUsageURL := codexPlanTypeRefreshUsageURL
	codexPlanTypeRefreshUsageURL = server.URL
	defer func() { codexPlanTypeRefreshUsageURL = restoreUsageURL }()

	h, manager, path, authID := newCodexPlanRefreshTestHandler(t, map[string]any{
		"type":          "codex",
		"email":         "codex@example.com",
		"access_token":  "access-old",
		"refresh_token": "refresh-old",
		"id_token":      testManagementCodexJWT("acct-1", "pro"),
	})
	manager.RegisterExecutor(codexPlanRefreshTestExecutor{
		refreshFn: func(auth *coreauth.Auth) (*coreauth.Auth, error) {
			if auth.Metadata == nil {
				auth.Metadata = make(map[string]any)
			}
			auth.Metadata["access_token"] = "access-new"
			auth.Metadata["refresh_token"] = "refresh-new"
			auth.Metadata["account_id"] = "acct-1"
			return auth, nil
		},
	})

	postRec := performManagementRequest(t, http.MethodPost, "/v0/management/auth-files/codex/plan-type-refresh", "", h.StartCodexPlanTypeRefresh)
	if postRec.Code != http.StatusAccepted {
		t.Fatalf("POST status = %d, want %d; body=%s", postRec.Code, http.StatusAccepted, postRec.Body.String())
	}

	snapshot := waitForCodexPlanTypeRefreshDone(t, h)
	if snapshot.State != codexPlanTypeRefreshStateCompleted {
		t.Fatalf("state = %q, want %q", snapshot.State, codexPlanTypeRefreshStateCompleted)
	}
	if atomic.LoadInt32(&requests) != 2 {
		t.Fatalf("requests = %d, want 2", atomic.LoadInt32(&requests))
	}

	current, ok := manager.GetByID(authID)
	if !ok || current == nil {
		t.Fatal("expected auth to remain registered")
	}
	if got := current.Attributes["plan_type"]; got != "team" {
		t.Fatalf("runtime plan_type = %q, want %q", got, "team")
	}
	if got := strings.TrimSpace(stringValue(current.Metadata, "access_token")); got != "access-new" {
		t.Fatalf("persisted access_token = %q, want %q", got, "access-new")
	}
	if got := strings.TrimSpace(stringValue(current.Metadata, "refresh_token")); got != "refresh-new" {
		t.Fatalf("persisted refresh_token = %q, want %q", got, "refresh-new")
	}

	rawFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read auth file: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(rawFile, &payload); err != nil {
		t.Fatalf("unmarshal auth file: %v", err)
	}
	if got, _ := payload["plan_type"].(string); got != "team" {
		t.Fatalf("persisted plan_type = %q, want %q", got, "team")
	}
	if got, _ := payload["access_token"].(string); got != "access-new" {
		t.Fatalf("persisted access_token = %q, want %q", got, "access-new")
	}
}

func newCodexPlanRefreshTestHandler(t *testing.T, metadata map[string]any) (*Handler, *coreauth.Manager, string, string) {
	t.Helper()

	authDir := t.TempDir()
	path := filepath.Join(authDir, "codex-auth.json")
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("marshal auth metadata: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	store := sdkauth.NewFileTokenStore()
	store.SetBaseDir(authDir)
	manager := coreauth.NewManager(store, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	auth, err := h.buildAuthFromFileData(path, data)
	if err != nil {
		t.Fatalf("buildAuthFromFileData: %v", err)
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}
	return h, manager, path, auth.ID
}

func performManagementRequest(t *testing.T, method string, target string, body string, handler func(*gin.Context)) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	ctx.Request = req
	handler(ctx)
	return rec
}

func waitForCodexPlanTypeRefreshRunning(t *testing.T, h *Handler) codexPlanTypeRefreshTask {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := h.codexPlanTypeRefreshSnapshot()
		if snapshot.Running {
			return snapshot
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for refresh task to start")
	return codexPlanTypeRefreshTask{}
}

func waitForCodexPlanTypeRefreshDone(t *testing.T, h *Handler) codexPlanTypeRefreshTask {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := h.codexPlanTypeRefreshSnapshot()
		if !snapshot.Running {
			return snapshot
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for refresh task to finish")
	return codexPlanTypeRefreshTask{}
}

func testManagementCodexJWT(accountID string, planType string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": accountID,
			"chatgpt_plan_type":  planType,
		},
	})
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

type codexPlanRefreshTestExecutor struct {
	refreshFn func(auth *coreauth.Auth) (*coreauth.Auth, error)
}

func (e codexPlanRefreshTestExecutor) Identifier() string { return "codex" }

func (e codexPlanRefreshTestExecutor) Execute(_ context.Context, _ *coreauth.Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, fmt.Errorf("not implemented")
}

func (e codexPlanRefreshTestExecutor) ExecuteStream(_ context.Context, _ *coreauth.Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, fmt.Errorf("not implemented")
}

func (e codexPlanRefreshTestExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	if e.refreshFn == nil {
		return auth, nil
	}
	return e.refreshFn(auth)
}

func (e codexPlanRefreshTestExecutor) CountTokens(_ context.Context, _ *coreauth.Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, fmt.Errorf("not implemented")
}

func (e codexPlanRefreshTestExecutor) HttpRequest(_ context.Context, _ *coreauth.Auth, _ *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("not implemented")
}
