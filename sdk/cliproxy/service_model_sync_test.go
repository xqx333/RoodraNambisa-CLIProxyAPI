package cliproxy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/watcher"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

type serviceFailingDeleteStore struct{}

type serviceCountingDeleteStore struct {
	deleteCount atomic.Int32
}

type serviceToggleSaveStore struct {
	saveCount atomic.Int32
	failSave  atomic.Bool
}

type serviceDeleteSideEffectStore struct {
	deleteCount atomic.Int32
	onDelete    func(id string)
}

func (s *serviceFailingDeleteStore) List(context.Context) ([]*coreauth.Auth, error) { return nil, nil }

func (s *serviceFailingDeleteStore) Save(_ context.Context, auth *coreauth.Auth) (string, error) {
	if auth == nil {
		return "", nil
	}
	return "", nil
}

func (s *serviceFailingDeleteStore) Delete(context.Context, string) error {
	return errors.New("delete failed")
}

func (s *serviceCountingDeleteStore) List(context.Context) ([]*coreauth.Auth, error) { return nil, nil }

func (s *serviceCountingDeleteStore) Save(_ context.Context, auth *coreauth.Auth) (string, error) {
	if auth == nil {
		return "", nil
	}
	return "", nil
}

func (s *serviceCountingDeleteStore) Delete(context.Context, string) error {
	s.deleteCount.Add(1)
	return nil
}

func (s *serviceToggleSaveStore) List(context.Context) ([]*coreauth.Auth, error) { return nil, nil }

func (s *serviceToggleSaveStore) Save(_ context.Context, auth *coreauth.Auth) (string, error) {
	s.saveCount.Add(1)
	if auth == nil {
		return "", nil
	}
	if s.failSave.Load() {
		return "", errors.New("save failed")
	}
	return "", nil
}

func (s *serviceToggleSaveStore) Delete(context.Context, string) error { return nil }

func (s *serviceDeleteSideEffectStore) List(context.Context) ([]*coreauth.Auth, error) {
	return nil, nil
}

func (s *serviceDeleteSideEffectStore) Save(_ context.Context, auth *coreauth.Auth) (string, error) {
	if auth == nil {
		return "", nil
	}
	return "", nil
}

func (s *serviceDeleteSideEffectStore) Delete(_ context.Context, id string) error {
	s.deleteCount.Add(1)
	if s.onDelete != nil {
		s.onDelete(id)
	}
	return nil
}

func TestServiceApplyCoreAuthAddOrUpdate_ModelSyncWorkerEventuallyRegistersModels(t *testing.T) {
	service := &Service{
		cfg:         &config.Config{},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}
	service.startModelSyncLoop(context.Background())
	defer service.stopModelSyncLoop()

	authID := "service-async-model-sync-auth"
	t.Cleanup(func() {
		GlobalModelRegistry().UnregisterClient(authID)
	})

	service.applyCoreAuthAddOrUpdate(context.Background(), &coreauth.Auth{
		ID:       authID,
		Provider: "claude",
		Status:   coreauth.StatusActive,
	})

	deadline := time.Now().Add(2 * time.Second)
	for {
		if models := registry.GetGlobalRegistry().GetModelsForClient(authID); len(models) > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected async model sync to register models for %q", authID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServiceApplyCoreAuthAddOrUpdate_FallsBackToInlineSyncWhenQueueIsFull(t *testing.T) {
	service := &Service{
		cfg:         &config.Config{},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	service.modelSyncCancel = cancel
	service.modelSyncQueue = make(chan string, 1)
	service.modelSyncQueue <- "busy"
	service.modelSyncPending = make(map[string]modelSyncTaskState)

	authID := "service-inline-model-sync-auth"
	t.Cleanup(func() {
		GlobalModelRegistry().UnregisterClient(authID)
	})

	service.applyCoreAuthAddOrUpdate(ctx, &coreauth.Auth{
		ID:       authID,
		Provider: "claude",
		Status:   coreauth.StatusActive,
	})

	if models := registry.GetGlobalRegistry().GetModelsForClient(authID); len(models) == 0 {
		t.Fatalf("expected inline model sync to register models for %q", authID)
	}
	if _, exists := service.modelSyncPending[authID]; exists {
		t.Fatalf("expected inline fallback to clear pending state for %q", authID)
	}
}

func TestServiceHandleManagementAuthStatusChange_ReRegistersModelsForEnabledAuth(t *testing.T) {
	service := &Service{
		cfg:         &config.Config{},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}

	auth := &coreauth.Auth{
		ID:       "service-management-enable-auth",
		Provider: "claude",
		Status:   coreauth.StatusActive,
	}
	if _, errRegister := service.coreManager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	GlobalModelRegistry().UnregisterClient(auth.ID)
	t.Cleanup(func() {
		GlobalModelRegistry().UnregisterClient(auth.ID)
	})

	service.handleManagementAuthStatusChange(context.Background(), auth)

	if models := registry.GetGlobalRegistry().GetModelsForClient(auth.ID); len(models) == 0 {
		t.Fatalf("expected management status change hook to re-register models for %q", auth.ID)
	}
}

func TestServiceRefreshModelRegistrationForAuth_UpdatesCodexImageModelAfterConfigChange(t *testing.T) {
	service := &Service{
		cfg: &config.Config{
			SDKConfig: config.SDKConfig{
				Images: config.ImagesConfig{ImageModel: "gpt-image-2"},
			},
		},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}

	auth := &coreauth.Auth{
		ID:       "service-codex-image-refresh-auth",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"plan_type": "plus",
		},
	}
	if _, errRegister := service.coreManager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	reg := registry.GetGlobalRegistry()
	reg.UnregisterClient(auth.ID)
	t.Cleanup(func() {
		reg.UnregisterClient(auth.ID)
	})

	service.registerModelsForAuth(auth)
	if !containsRegisteredModel(reg.GetModelsForClient(auth.ID), "gpt-image-2") {
		t.Fatalf("expected initial image model registration")
	}

	service.cfg = &config.Config{
		SDKConfig: config.SDKConfig{
			Images: config.ImagesConfig{ImageModel: "gpt-image-custom"},
		},
	}
	if !service.refreshModelRegistrationForAuth(auth) {
		t.Fatal("expected refreshModelRegistrationForAuth to succeed")
	}

	models := reg.GetModelsForClient(auth.ID)
	if containsRegisteredModel(models, "gpt-image-2") {
		t.Fatalf("expected old image model to be removed")
	}
	if !containsRegisteredModel(models, "gpt-image-custom") {
		t.Fatalf("expected new image model to be registered")
	}
}

func TestShouldRefreshCodexRegistrations(t *testing.T) {
	testCases := []struct {
		name     string
		previous *config.Config
		next     *config.Config
		want     bool
	}{
		{
			name: "image model unchanged and free toggle unchanged",
			previous: &config.Config{SDKConfig: config.SDKConfig{
				Images: config.ImagesConfig{ImageModel: "gpt-image-2", EnableFreePlanImageModel: false},
			}},
			next: &config.Config{SDKConfig: config.SDKConfig{
				Images: config.ImagesConfig{ImageModel: "gpt-image-2", EnableFreePlanImageModel: false},
			}},
			want: false,
		},
		{
			name: "image model changed",
			previous: &config.Config{SDKConfig: config.SDKConfig{
				Images: config.ImagesConfig{ImageModel: "gpt-image-2", EnableFreePlanImageModel: false},
			}},
			next: &config.Config{SDKConfig: config.SDKConfig{
				Images: config.ImagesConfig{ImageModel: "gpt-image-custom", EnableFreePlanImageModel: false},
			}},
			want: true,
		},
		{
			name: "free toggle changed",
			previous: &config.Config{SDKConfig: config.SDKConfig{
				Images: config.ImagesConfig{ImageModel: "gpt-image-2", EnableFreePlanImageModel: false},
			}},
			next: &config.Config{SDKConfig: config.SDKConfig{
				Images: config.ImagesConfig{ImageModel: "gpt-image-2", EnableFreePlanImageModel: true},
			}},
			want: true,
		},
		{
			name: "custom models changed",
			previous: &config.Config{
				CodexCustomModels: []config.CodexCustomModel{
					{ID: "gpt-5.5-codex", DisplayName: "GPT 5.5 Codex", Groups: []string{"plus"}},
				},
			},
			next: &config.Config{
				CodexCustomModels: []config.CodexCustomModel{
					{ID: "gpt-5.5-codex", DisplayName: "GPT 5.5 Codex", Groups: []string{"plus", "pro"}},
				},
			},
			want: true,
		},
		{
			name: "custom models unchanged",
			previous: &config.Config{
				CodexCustomModels: []config.CodexCustomModel{
					{ID: "gpt-5.5-codex", DisplayName: "GPT 5.5 Codex", Groups: []string{"plus", "pro"}},
				},
			},
			next: &config.Config{
				CodexCustomModels: []config.CodexCustomModel{
					{ID: "gpt-5.5-codex", DisplayName: "GPT 5.5 Codex", Groups: []string{"plus", "pro"}},
				},
			},
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldRefreshCodexRegistrations(tc.previous, tc.next); got != tc.want {
				t.Fatalf("shouldRefreshCodexRegistrations() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestServiceDeleteCoreAuth_DeleteFailureKeepsRuntimeAndModels(t *testing.T) {
	service := &Service{
		cfg:         &config.Config{},
		coreManager: coreauth.NewManager(&serviceFailingDeleteStore{}, nil, nil),
	}

	auth := &coreauth.Auth{
		ID:       "service-delete-failure-auth",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{"type": "claude"},
	}
	if _, errRegister := service.coreManager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, "claude", []*registry.ModelInfo{{ID: "test-model"}})
	t.Cleanup(func() {
		registry.GetGlobalRegistry().UnregisterClient(auth.ID)
	})

	if err := service.deleteCoreAuth(context.Background(), auth.ID); err == nil {
		t.Fatal("expected deleteCoreAuth to report delete failure")
	}

	if _, ok := service.coreManager.GetByID(auth.ID); !ok {
		t.Fatal("expected auth to remain registered after delete failure")
	}
	if models := registry.GetGlobalRegistry().GetModelsForClient(auth.ID); len(models) == 0 {
		t.Fatalf("expected models to remain registered after delete failure for %q", auth.ID)
	}
}

func containsRegisteredModel(models []*registry.ModelInfo, modelID string) bool {
	for _, model := range models {
		if model != nil && strings.EqualFold(strings.TrimSpace(model.ID), modelID) {
			return true
		}
	}
	return false
}

func TestServiceDeleteAuthMaintenanceCandidate_PersistsDelete(t *testing.T) {
	authDir := t.TempDir()
	store := &serviceCountingDeleteStore{}
	service := &Service{
		cfg:         &config.Config{AuthDir: authDir},
		coreManager: coreauth.NewManager(store, nil, nil),
	}

	path := filepath.Join(authDir, "service-maintenance-persist-delete-auth.json")
	raw := []byte(`{"type":"claude","email":"persist@example.com"}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	auth := &coreauth.Auth{
		ID:       "service-maintenance-persist-delete-auth.json",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		FileName: path,
		Attributes: map[string]string{
			"path": path,
		},
		Metadata: map[string]any{"type": "claude", "email": "persist@example.com"},
	}
	if _, err := service.coreManager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	candidate, ok := service.authMaintenanceCandidateForAuth(auth, authDir, "quota_delete_6")
	if !ok {
		t.Fatal("expected auth maintenance candidate")
	}

	deleted, err := service.deleteAuthMaintenanceCandidate(context.Background(), candidate)
	if err != nil {
		t.Fatalf("deleteAuthMaintenanceCandidate returned error: %v", err)
	}
	if !deleted {
		t.Fatal("expected maintenance delete to complete")
	}
	if got := store.deleteCount.Load(); got != 1 {
		t.Fatalf("delete count = %d, want 1", got)
	}
	if _, ok := service.coreManager.GetByID(auth.ID); ok {
		t.Fatal("expected auth to be removed from runtime state")
	}
}

func TestServiceStartAuthMaintenance_QueuesDeleteOnlyAfterPendingDeletePersists(t *testing.T) {
	authDir := t.TempDir()
	store := &serviceToggleSaveStore{}
	service := &Service{
		cfg: &config.Config{
			AuthDir: authDir,
			AuthMaintenance: config.AuthMaintenanceConfig{
				Enable:                true,
				ScanIntervalSeconds:   1,
				DeleteIntervalSeconds: 1,
				DeleteQuotaExceeded:   true,
				QuotaStrikeThreshold:  1,
			},
		},
		coreManager: coreauth.NewManager(store, nil, nil),
	}

	path := filepath.Join(authDir, "service-maintenance-pending-delete-save-failure.json")
	raw := []byte(`{"type":"claude","email":"persist@example.com"}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	auth := &coreauth.Auth{
		ID:       "service-maintenance-pending-delete-save-failure.json",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		FileName: path,
		Attributes: map[string]string{
			"path": path,
		},
		Metadata: map[string]any{"type": "claude", "email": "persist@example.com"},
		Quota: coreauth.QuotaState{
			Exceeded:    true,
			StrikeCount: 1,
		},
	}
	if _, err := service.coreManager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	store.failSave.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service.startAuthMaintenance(ctx)
	defer service.stopAuthMaintenance()
	service.wakeAuthMaintenance()

	deadline := time.Now().Add(2 * time.Second)
	for store.saveCount.Load() <= 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := store.saveCount.Load(); got <= 1 {
		t.Fatalf("expected maintenance disable to attempt persistence, save count = %d", got)
	}

	service.maintenanceMu.Lock()
	queueLen := len(service.maintenanceQueue)
	_, pending := service.maintenancePending[path]
	service.maintenanceMu.Unlock()
	if queueLen != 0 {
		t.Fatalf("expected failed pending-delete save not to queue maintenance delete, got %d items", queueLen)
	}
	if pending {
		t.Fatal("expected failed pending-delete save not to leave a pending maintenance entry")
	}

	current, ok := service.coreManager.GetByID(auth.ID)
	if !ok || current == nil {
		t.Fatal("expected auth to remain registered after failed pending-delete update")
	}
	if authMaintenancePendingDelete(current) {
		t.Fatal("expected auth to remain unmarked when pending-delete persistence fails")
	}
	if got := strings.TrimSpace(current.StatusMessage); got == "disabled" || strings.Contains(got, "auth maintenance") {
		t.Fatalf("status message = %q, want active auth state after failed pending-delete update", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected auth file to remain after failed pending-delete update, stat err=%v", err)
	}
}

func TestServiceHandleAuthMaintenanceResult_QueuesDeleteOnlyAfterPendingDeletePersists(t *testing.T) {
	authDir := t.TempDir()
	store := &serviceToggleSaveStore{}
	service := &Service{
		cfg: &config.Config{
			AuthDir: authDir,
			AuthMaintenance: config.AuthMaintenanceConfig{
				Enable:                true,
				DeleteQuotaExceeded:   true,
				QuotaStrikeThreshold:  1,
				DeleteIntervalSeconds: 1,
			},
		},
		coreManager: coreauth.NewManager(store, nil, nil),
	}

	path := filepath.Join(authDir, "service-result-pending-delete-save-failure.json")
	raw := []byte(`{"type":"claude","email":"result@example.com"}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	auth := &coreauth.Auth{
		ID:       "service-result-pending-delete-save-failure.json",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		FileName: path,
		Attributes: map[string]string{
			"path": path,
		},
		Metadata: map[string]any{"type": "claude", "email": "result@example.com"},
		Quota: coreauth.QuotaState{
			Exceeded:    true,
			StrikeCount: 1,
		},
	}
	if _, err := service.coreManager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	store.failSave.Store(true)
	service.handleAuthMaintenanceResult(context.Background(), coreauth.Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Success:  false,
		Error:    &coreauth.Error{HTTPStatus: 429, Message: "quota exhausted"},
	})

	if got := store.saveCount.Load(); got <= 1 {
		t.Fatalf("expected result-driven pending-delete path to attempt persistence, save count = %d", got)
	}

	service.maintenanceMu.Lock()
	queueLen := len(service.maintenanceQueue)
	_, pending := service.maintenancePending[path]
	service.maintenanceMu.Unlock()
	if queueLen != 0 {
		t.Fatalf("expected failed pending-delete save not to queue result-driven maintenance delete, got %d items", queueLen)
	}
	if pending {
		t.Fatal("expected failed pending-delete save not to leave a pending maintenance entry")
	}

	current, ok := service.coreManager.GetByID(auth.ID)
	if !ok || current == nil {
		t.Fatal("expected auth to remain registered after failed result-driven pending-delete update")
	}
	if authMaintenancePendingDelete(current) {
		t.Fatal("expected auth to remain unmarked when result-driven pending-delete persistence fails")
	}
	if got := strings.TrimSpace(current.StatusMessage); got == "disabled" || strings.Contains(got, "auth maintenance") {
		t.Fatalf("status message = %q, want active auth state after failed result-driven pending-delete update", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected auth file to remain after failed result-driven pending-delete update, stat err=%v", err)
	}
}

func TestServiceDeleteAuthMaintenanceCandidate_DeleteFailureRestoresFile(t *testing.T) {
	authDir := t.TempDir()
	service := &Service{
		cfg:         &config.Config{AuthDir: authDir},
		coreManager: coreauth.NewManager(&serviceFailingDeleteStore{}, nil, nil),
	}

	path := filepath.Join(authDir, "service-maintenance-delete-failure-auth.json")
	raw := []byte(`{"type":"claude","email":"persist@example.com"}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	auth := &coreauth.Auth{
		ID:       "service-maintenance-delete-failure-auth.json",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		FileName: path,
		Attributes: map[string]string{
			"path": path,
		},
		Metadata: map[string]any{"type": "claude", "email": "persist@example.com"},
	}
	if _, err := service.coreManager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	candidate, ok := service.authMaintenanceCandidateForAuth(auth, authDir, "quota_delete_6")
	if !ok {
		t.Fatal("expected auth maintenance candidate")
	}

	deleted, err := service.deleteAuthMaintenanceCandidate(context.Background(), candidate)
	if err == nil {
		t.Fatal("expected maintenance delete to report delete failure")
	}
	if deleted {
		t.Fatal("expected failed maintenance delete not to report success")
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("expected auth file to be restored after delete failure, stat err=%v", statErr)
	}
	if _, ok := service.coreManager.GetByID(auth.ID); !ok {
		t.Fatal("expected auth to remain registered after delete failure")
	}
}

func TestServiceDeleteAuthMaintenanceCandidate_RechecksBetweenAuthDeletes(t *testing.T) {
	authDir := t.TempDir()
	path := filepath.Join(authDir, "service-maintenance-recheck-between-deletes.json")
	raw := []byte(`{"type":"claude","email":"persist@example.com"}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	var recreated atomic.Bool
	firstDeletedID := ""
	store := &serviceDeleteSideEffectStore{
		onDelete: func(id string) {
			if recreated.Swap(true) {
				return
			}
			firstDeletedID = id
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Errorf("recreate auth file: %v", err)
			}
		},
	}
	service := &Service{
		cfg:         &config.Config{AuthDir: authDir},
		coreManager: coreauth.NewManager(store, nil, nil),
	}

	authA := &coreauth.Auth{
		ID:       "auth-a",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		FileName: path,
		Attributes: map[string]string{
			"path": path,
		},
		Metadata: map[string]any{"type": "claude", "email": "a@example.com"},
	}
	authB := &coreauth.Auth{
		ID:       "auth-b",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		FileName: path,
		Attributes: map[string]string{
			"path": path,
		},
		Metadata: map[string]any{"type": "claude", "email": "b@example.com"},
	}
	if _, err := service.coreManager.Register(context.Background(), authA); err != nil {
		t.Fatalf("register authA: %v", err)
	}
	if _, err := service.coreManager.Register(context.Background(), authB); err != nil {
		t.Fatalf("register authB: %v", err)
	}

	candidate, ok := service.authMaintenanceCandidateForAuth(authA, authDir, "quota_delete_6")
	if !ok {
		t.Fatal("expected auth maintenance candidate")
	}

	deleted, err := service.deleteAuthMaintenanceCandidate(context.Background(), candidate)
	if err != nil {
		t.Fatalf("deleteAuthMaintenanceCandidate returned error: %v", err)
	}
	if deleted {
		t.Fatal("expected recreated auth file to stop stale maintenance delete")
	}
	if got := store.deleteCount.Load(); got != 1 {
		t.Fatalf("delete count = %d, want 1", got)
	}
	if firstDeletedID == "" {
		t.Fatal("expected one auth delete before file recreation")
	}
	if firstDeletedID == authA.ID {
		if _, ok := service.coreManager.GetByID(authA.ID); ok {
			t.Fatal("expected first deleted auth to be removed before file recreation")
		}
		if _, ok := service.coreManager.GetByID(authB.ID); !ok {
			t.Fatal("expected remaining auth to stay after file recreation")
		}
	} else if firstDeletedID == authB.ID {
		if _, ok := service.coreManager.GetByID(authB.ID); ok {
			t.Fatal("expected first deleted auth to be removed before file recreation")
		}
		if _, ok := service.coreManager.GetByID(authA.ID); !ok {
			t.Fatal("expected remaining auth to stay after file recreation")
		}
	} else {
		t.Fatalf("unexpected deleted auth id %q", firstDeletedID)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected recreated auth file to remain, stat err=%v", err)
	}
}

func TestServiceHandleManagementAuthStatusChange_CancelsMaintenanceDelete(t *testing.T) {
	authDir := t.TempDir()
	service := &Service{
		cfg:         &config.Config{AuthDir: authDir},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}

	auth := &coreauth.Auth{
		ID:       "service-maintenance-cancel-auth",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		FileName: filepath.Join(authDir, "service-maintenance-cancel-auth.json"),
		Metadata: map[string]any{"type": "claude"},
	}
	if _, errRegister := service.coreManager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	candidate, ok := service.authMaintenanceCandidateForAuth(auth, authDir, "quota_delete_6")
	if !ok {
		t.Fatal("expected auth maintenance candidate")
	}
	if !service.enqueueAuthMaintenanceCandidate(candidate) {
		t.Fatal("expected candidate to be enqueued")
	}
	dequeued, ok := service.dequeueAuthMaintenanceCandidate()
	if !ok {
		t.Fatal("expected candidate to be dequeued")
	}

	service.handleManagementAuthStatusChange(context.Background(), auth)

	if !service.authMaintenanceCandidateCanceled(dequeued) {
		t.Fatal("expected dequeued maintenance candidate to be canceled after manual re-enable")
	}

	queuedCandidate, ok := service.authMaintenanceCandidateForAuth(auth, authDir, "quota_delete_6")
	if !ok {
		t.Fatal("expected queued auth maintenance candidate")
	}
	if !service.enqueueAuthMaintenanceCandidate(queuedCandidate) {
		t.Fatal("expected queued candidate to be enqueued")
	}
	service.handleManagementAuthStatusChange(context.Background(), auth)

	service.maintenanceMu.Lock()
	defer service.maintenanceMu.Unlock()
	if len(service.maintenanceQueue) != 0 {
		t.Fatalf("expected maintenance queue to be empty, got %d items", len(service.maintenanceQueue))
	}
	if _, exists := service.maintenancePending[candidate.Key]; exists {
		t.Fatal("expected pending maintenance entry to be removed")
	}
	if service.maintenanceGeneration[candidate.Key] == 0 {
		t.Fatal("expected maintenance generation to advance after cancellation")
	}
}

func TestServiceHandleAuthUpdate_AddCancelsMaintenanceDelete(t *testing.T) {
	authDir := t.TempDir()
	service := &Service{
		cfg:         &config.Config{AuthDir: authDir},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}

	auth := &coreauth.Auth{
		ID:       "service-auth-update-cancel-auth",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		FileName: filepath.Join(authDir, "service-auth-update-cancel-auth.json"),
		Metadata: map[string]any{"type": "claude"},
	}
	if _, errRegister := service.coreManager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	candidate, ok := service.authMaintenanceCandidateForAuth(auth, authDir, "quota_delete_6")
	if !ok {
		t.Fatal("expected auth maintenance candidate")
	}
	if !service.enqueueAuthMaintenanceCandidate(candidate) {
		t.Fatal("expected candidate to be enqueued")
	}
	dequeued, ok := service.dequeueAuthMaintenanceCandidate()
	if !ok {
		t.Fatal("expected candidate to be dequeued")
	}

	reloaded := auth.Clone()
	reloaded.Metadata = map[string]any{"type": "claude", "note": "reloaded"}
	service.handleAuthUpdate(context.Background(), watcher.AuthUpdate{
		Action: watcher.AuthUpdateActionModify,
		ID:     reloaded.ID,
		Auth:   reloaded,
	})

	if !service.authMaintenanceCandidateCanceled(dequeued) {
		t.Fatal("expected dequeued maintenance candidate to be canceled after auth reload")
	}

	if !service.enqueueAuthMaintenanceCandidate(candidate) {
		t.Fatal("expected candidate to be enqueued again")
	}
	service.handleAuthUpdate(context.Background(), watcher.AuthUpdate{
		Action: watcher.AuthUpdateActionAdd,
		ID:     reloaded.ID,
		Auth:   reloaded,
	})

	service.maintenanceMu.Lock()
	defer service.maintenanceMu.Unlock()
	if len(service.maintenanceQueue) != 0 {
		t.Fatalf("expected maintenance queue to be empty, got %d items", len(service.maintenanceQueue))
	}
	if _, exists := service.maintenancePending[candidate.Key]; exists {
		t.Fatal("expected pending maintenance entry to be removed")
	}
	if service.maintenanceGeneration[candidate.Key] == 0 {
		t.Fatal("expected maintenance generation to advance after auth reload cancellation")
	}
}

func TestServiceHandleAuthUpdate_MaintenanceRewriteKeepsDeleteQueued(t *testing.T) {
	authDir := t.TempDir()
	service := &Service{
		cfg:         &config.Config{AuthDir: authDir},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}

	auth := &coreauth.Auth{
		ID:       "service-auth-update-pending-delete-auth",
		Provider: "claude",
		Status:   coreauth.StatusDisabled,
		FileName: filepath.Join(authDir, "service-auth-update-pending-delete-auth.json"),
		Metadata: map[string]any{
			"type":                                  "claude",
			authMaintenancePendingDeleteMetadataKey: true,
		},
	}
	if _, errRegister := service.coreManager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	candidate, ok := service.authMaintenanceCandidateForAuth(auth, authDir, "quota_delete_6")
	if !ok {
		t.Fatal("expected auth maintenance candidate")
	}
	if !service.enqueueAuthMaintenanceCandidate(candidate) {
		t.Fatal("expected candidate to be enqueued")
	}

	service.handleAuthUpdate(context.Background(), watcher.AuthUpdate{
		Action: watcher.AuthUpdateActionModify,
		ID:     auth.ID,
		Auth:   auth.Clone(),
	})

	service.maintenanceMu.Lock()
	defer service.maintenanceMu.Unlock()
	if len(service.maintenanceQueue) != 1 {
		t.Fatalf("expected maintenance queue to keep pending delete candidate, got %d items", len(service.maintenanceQueue))
	}
	if _, exists := service.maintenancePending[candidate.Key]; !exists {
		t.Fatal("expected pending maintenance entry to remain after maintenance rewrite")
	}
}

func TestServiceDeleteAuthMaintenanceCandidate_MissingPathDoesNotEmitDelete(t *testing.T) {
	authDir := t.TempDir()
	service := &Service{
		cfg:         &config.Config{AuthDir: authDir},
		coreManager: coreauth.NewManager(nil, nil, nil),
		authUpdates: make(chan watcher.AuthUpdate, 1),
	}

	auth := &coreauth.Auth{
		ID:       "service-missing-maintenance-path-auth",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		FileName: filepath.Join(authDir, "service-missing-maintenance-path-auth.json"),
		Metadata: map[string]any{"type": "claude"},
	}
	if _, errRegister := service.coreManager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	candidate := authMaintenanceCandidate{
		Key:    auth.FileName,
		Path:   auth.FileName,
		IDs:    []string{auth.ID},
		Reason: "quota_delete_6",
	}
	deleted, err := service.deleteAuthMaintenanceCandidate(context.Background(), candidate)
	if err != nil {
		t.Fatalf("deleteAuthMaintenanceCandidate returned error: %v", err)
	}
	if deleted {
		t.Fatal("expected missing maintenance path to be treated as stale, not deleted")
	}

	select {
	case update := <-service.authUpdates:
		t.Fatalf("expected no auth delete update for missing path, got action=%v id=%s", update.Action, update.ID)
	default:
	}
	if _, ok := service.coreManager.GetByID(auth.ID); !ok {
		t.Fatal("expected auth to remain registered when maintenance path is already missing")
	}
}

func TestServiceDeleteAuthMaintenanceCandidate_CanceledCandidateDoesNotDelete(t *testing.T) {
	authDir := t.TempDir()
	service := &Service{
		cfg:         &config.Config{AuthDir: authDir},
		coreManager: coreauth.NewManager(nil, nil, nil),
		authUpdates: make(chan watcher.AuthUpdate, 1),
	}

	path := filepath.Join(authDir, "service-canceled-maintenance-auth.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write auth file: %v", err)
	}
	auth := &coreauth.Auth{
		ID:       "service-canceled-maintenance-auth",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		FileName: path,
		Metadata: map[string]any{"type": "claude"},
	}
	if _, errRegister := service.coreManager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	candidate, ok := service.authMaintenanceCandidateForAuth(auth, authDir, "quota_delete_6")
	if !ok {
		t.Fatal("expected auth maintenance candidate")
	}
	if !service.enqueueAuthMaintenanceCandidate(candidate) {
		t.Fatal("expected candidate to be enqueued")
	}
	dequeued, ok := service.dequeueAuthMaintenanceCandidate()
	if !ok {
		t.Fatal("expected candidate to be dequeued")
	}
	service.cancelAuthMaintenanceCandidate(candidate)

	deleted, err := service.deleteAuthMaintenanceCandidate(context.Background(), dequeued)
	if err != nil {
		t.Fatalf("deleteAuthMaintenanceCandidate returned error: %v", err)
	}
	if deleted {
		t.Fatal("expected canceled maintenance candidate to skip deletion")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected auth file to remain after canceled maintenance delete, stat err=%v", err)
	}
	select {
	case update := <-service.authUpdates:
		t.Fatalf("expected no auth delete update for canceled candidate, got action=%v id=%s", update.Action, update.ID)
	default:
	}
}

func TestServiceDeleteAuthMaintenanceCandidate_CancelAfterStartRestoresFile(t *testing.T) {
	authDir := t.TempDir()
	service := &Service{
		cfg:         &config.Config{AuthDir: authDir},
		coreManager: coreauth.NewManager(nil, nil, nil),
		authUpdates: make(chan watcher.AuthUpdate, 1),
	}

	path := filepath.Join(authDir, "service-cancel-after-start-auth.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write auth file: %v", err)
	}
	auth := &coreauth.Auth{
		ID:       "service-cancel-after-start-auth",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		FileName: path,
		Metadata: map[string]any{"type": "claude"},
	}
	if _, errRegister := service.coreManager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	candidate, ok := service.authMaintenanceCandidateForAuth(auth, authDir, "quota_delete_6")
	if !ok {
		t.Fatal("expected auth maintenance candidate")
	}

	originalRemove := removeAuthMaintenanceFile
	t.Cleanup(func() {
		removeAuthMaintenanceFile = originalRemove
	})

	started := make(chan struct{})
	releaseRemove := make(chan struct{})
	var blocked atomic.Bool
	removeAuthMaintenanceFile = func(targetPath string) error {
		err := originalRemove(targetPath)
		if err == nil && blocked.CompareAndSwap(false, true) {
			close(started)
			<-releaseRemove
		}
		return err
	}

	type deleteResult struct {
		deleted bool
		err     error
	}
	done := make(chan deleteResult, 1)
	go func() {
		deleted, err := service.deleteAuthMaintenanceCandidate(context.Background(), candidate)
		done <- deleteResult{deleted: deleted, err: err}
	}()

	<-started
	service.cancelAuthMaintenanceCandidate(candidate)
	if !service.authMaintenanceCandidateCanceled(candidate) {
		t.Fatal("expected cancel to advance maintenance generation after delete started")
	}
	close(releaseRemove)

	result := <-done
	if result.err != nil {
		t.Fatalf("deleteAuthMaintenanceCandidate returned error: %v", result.err)
	}
	if result.deleted {
		t.Fatal("expected canceled maintenance delete to be treated as skipped")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected auth file to be restored after cancellation, stat err=%v", err)
	}
	select {
	case update := <-service.authUpdates:
		t.Fatalf("expected no auth delete update after canceled in-flight delete, got action=%v id=%s", update.Action, update.ID)
	default:
	}
}

func TestServiceDeleteAuthMaintenanceCandidate_CancelAfterStartRestoresCurrentRuntimeAuth(t *testing.T) {
	authDir := t.TempDir()
	store := sdkauth.NewFileTokenStore()
	store.SetBaseDir(authDir)
	service := &Service{
		cfg:         &config.Config{AuthDir: authDir},
		coreManager: coreauth.NewManager(store, nil, nil),
		authUpdates: make(chan watcher.AuthUpdate, 1),
	}

	path := filepath.Join(authDir, "service-cancel-after-start-runtime-restore-auth.json")
	originalContents := []byte(`{"type":"claude","broken":true}`)
	repairedContents := []byte(`{"type":"claude","broken":false}`)
	if err := os.WriteFile(path, originalContents, 0o644); err != nil {
		t.Fatalf("write auth file: %v", err)
	}
	auth := &coreauth.Auth{
		ID:       "service-cancel-after-start-runtime-restore-auth",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		FileName: path,
		Attributes: map[string]string{
			"path": path,
		},
		Metadata: map[string]any{"type": "claude", "broken": true},
	}
	if _, errRegister := service.coreManager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	candidate, ok := service.authMaintenanceCandidateForAuth(auth, authDir, "quota_delete_6")
	if !ok {
		t.Fatal("expected auth maintenance candidate")
	}

	originalRemove := removeAuthMaintenanceFile
	t.Cleanup(func() {
		removeAuthMaintenanceFile = originalRemove
	})

	started := make(chan struct{})
	releaseRemove := make(chan struct{})
	var blocked atomic.Bool
	removeAuthMaintenanceFile = func(targetPath string) error {
		err := originalRemove(targetPath)
		if err == nil && blocked.CompareAndSwap(false, true) {
			close(started)
			<-releaseRemove
		}
		return err
	}

	type deleteResult struct {
		deleted bool
		err     error
	}
	done := make(chan deleteResult, 1)
	go func() {
		deleted, err := service.deleteAuthMaintenanceCandidate(context.Background(), candidate)
		done <- deleteResult{deleted: deleted, err: err}
	}()

	<-started
	repaired := auth.Clone()
	repaired.Metadata = map[string]any{"type": "claude", "broken": false}
	coreauth.SetSourceHashAttribute(repaired, repairedContents)
	if _, errUpdate := service.coreManager.Update(coreauth.WithSkipPersist(context.Background()), repaired); errUpdate != nil {
		t.Fatalf("update runtime auth: %v", errUpdate)
	}
	service.cancelAuthMaintenanceCandidate(candidate)
	close(releaseRemove)

	result := <-done
	if result.err != nil {
		t.Fatalf("deleteAuthMaintenanceCandidate returned error: %v", result.err)
	}
	if result.deleted {
		t.Fatal("expected canceled maintenance delete to be treated as skipped")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read restored auth file: %v", err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(data, &metadata); err != nil {
		t.Fatalf("unmarshal restored auth file: %v", err)
	}
	if broken, _ := metadata["broken"].(bool); broken {
		t.Fatalf("restored auth file should keep repaired state, got %s", data)
	}
	if got, _ := metadata["type"].(string); got != "claude" {
		t.Fatalf("type = %q, want %q", got, "claude")
	}
}

func TestServiceDeleteAuthMaintenanceCandidate_RepairBeforeDeleteKeepsNewContents(t *testing.T) {
	authDir := t.TempDir()
	service := &Service{
		cfg:         &config.Config{AuthDir: authDir},
		coreManager: coreauth.NewManager(nil, nil, nil),
		authUpdates: make(chan watcher.AuthUpdate, 1),
	}

	path := filepath.Join(authDir, "service-repair-before-delete-auth.json")
	originalContents := []byte(`{"broken":true}`)
	repairedContents := []byte(`{"broken":false}`)
	if err := os.WriteFile(path, originalContents, 0o644); err != nil {
		t.Fatalf("write auth file: %v", err)
	}
	auth := &coreauth.Auth{
		ID:       "service-repair-before-delete-auth",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		FileName: path,
		Metadata: map[string]any{"type": "claude"},
	}
	if _, errRegister := service.coreManager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	candidate, ok := service.authMaintenanceCandidateForAuth(auth, authDir, "quota_delete_6")
	if !ok {
		t.Fatal("expected auth maintenance candidate")
	}

	originalRead := readAuthMaintenanceFile
	originalRemoveIfMatches := removeAuthMaintenanceFileIfSnapshotMatches
	t.Cleanup(func() {
		readAuthMaintenanceFile = originalRead
		removeAuthMaintenanceFileIfSnapshotMatches = originalRemoveIfMatches
	})

	var reads atomic.Int32
	readAuthMaintenanceFile = func(targetPath string) ([]byte, error) {
		if targetPath == path && reads.Add(1) == 3 {
			if err := os.WriteFile(path, repairedContents, 0o644); err != nil {
				return nil, err
			}
		}
		return originalRead(targetPath)
	}
	removeAuthMaintenanceFileIfSnapshotMatches = originalRemoveIfMatches

	deleted, err := service.deleteAuthMaintenanceCandidate(context.Background(), candidate)
	if err != nil {
		t.Fatalf("deleteAuthMaintenanceCandidate returned error: %v", err)
	}
	if deleted {
		t.Fatal("expected repaired auth file to skip maintenance delete")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read repaired auth file: %v", err)
	}
	if string(data) != string(repairedContents) {
		t.Fatalf("auth file contents = %s, want %s", data, repairedContents)
	}
	select {
	case update := <-service.authUpdates:
		t.Fatalf("expected no auth delete update for repaired file, got action=%v id=%s", update.Action, update.ID)
	default:
	}
}

func TestServiceApplyCoreAuthRemovalWithReason_PendingDeleteKeepsDeleteAction(t *testing.T) {
	service := &Service{
		cfg:         &config.Config{},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}
	auth := &coreauth.Auth{
		ID:       "service-pending-delete-action-auth",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{"type": "claude"},
	}
	if _, err := service.coreManager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	service.applyCoreAuthRemovalWithReason(context.Background(), auth.ID, "quota_delete_6", true)

	current, ok := service.coreManager.GetByID(auth.ID)
	if !ok || current == nil {
		t.Fatal("expected auth to remain registered")
	}
	if got, _ := current.Metadata[authMaintenanceActionMetadataKey].(string); got != authMaintenanceDeleteAction {
		t.Fatalf("maintenance action = %q, want %q", got, authMaintenanceDeleteAction)
	}
}

func TestServiceHandleAuthUpdate_MaintenanceDeleteSkipsRescuedAuthAtSamePath(t *testing.T) {
	authDir := t.TempDir()
	service := &Service{
		cfg:         &config.Config{AuthDir: authDir},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}

	path := filepath.Join(authDir, "service-maintenance-delete-same-path-auth.json")
	current := &coreauth.Auth{
		ID:       "service-maintenance-delete-same-path-auth",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		FileName: path,
		Metadata: map[string]any{"type": "claude"},
	}
	if _, errRegister := service.coreManager.Register(context.Background(), current); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	service.handleAuthUpdate(context.Background(), watcher.AuthUpdate{
		Action: watcher.AuthUpdateActionDelete,
		ID:     current.ID,
		Auth: &coreauth.Auth{
			ID:       current.ID,
			FileName: path,
			Attributes: map[string]string{
				"path": path,
			},
			Metadata: map[string]any{
				authMaintenanceActionMetadataKey:        authMaintenanceDeleteAction,
				authMaintenancePendingDeleteMetadataKey: true,
			},
		},
	})

	remaining, ok := service.coreManager.GetByID(current.ID)
	if !ok || remaining == nil {
		t.Fatal("expected rescued auth to remain after stale maintenance delete update")
	}
	if got := resolveAuthFilePath(remaining, authDir); got != path {
		t.Fatalf("remaining auth path = %q, want %q", got, path)
	}
}

func TestServiceHandleAuthUpdate_DeleteWithStalePathKeepsReplacementAuth(t *testing.T) {
	authDir := t.TempDir()
	service := &Service{
		cfg:         &config.Config{AuthDir: authDir},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}

	currentPath := filepath.Join(authDir, "replacement-auth.json")
	current := &coreauth.Auth{
		ID:       "service-stale-delete-replacement-auth",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		FileName: currentPath,
		Metadata: map[string]any{"type": "claude"},
	}
	if _, errRegister := service.coreManager.Register(context.Background(), current); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	stalePath := filepath.Join(authDir, "old-auth.json")
	service.handleAuthUpdate(context.Background(), watcher.AuthUpdate{
		Action: watcher.AuthUpdateActionDelete,
		ID:     current.ID,
		Auth: &coreauth.Auth{
			ID:       current.ID,
			FileName: stalePath,
			Attributes: map[string]string{
				"path": stalePath,
			},
		},
	})

	remaining, ok := service.coreManager.GetByID(current.ID)
	if !ok || remaining == nil {
		t.Fatal("expected replacement auth to remain registered after stale path delete")
	}
	if got := resolveAuthFilePath(remaining, authDir); got != currentPath {
		t.Fatalf("remaining auth path = %q, want %q", got, currentPath)
	}
}

func TestServiceAuthMaintenanceCandidateForAuth_ExcludesRuntimeOnlyChildrenFromFileGroup(t *testing.T) {
	authDir := t.TempDir()
	service := &Service{
		cfg:         &config.Config{AuthDir: authDir},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}

	path := filepath.Join(authDir, "gemini-multi.json")
	primary := &coreauth.Auth{
		ID:       "gemini-multi.json",
		Provider: "gemini-cli",
		Status:   coreauth.StatusDisabled,
		Disabled: true,
		FileName: path,
		Attributes: map[string]string{
			"path": path,
		},
		Metadata: map[string]any{
			authMaintenanceActionMetadataKey:        authMaintenanceDeleteAction,
			authMaintenancePendingDeleteMetadataKey: true,
			authMaintenanceReasonMetadataKey:        "pending_delete",
			"type":                                  "gemini",
		},
	}
	virtualA := &coreauth.Auth{
		ID:       "gemini-multi.json#project-a",
		Provider: "gemini-cli",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"path":                   path,
			"runtime_only":           "true",
			"gemini_virtual_parent":  primary.ID,
			"gemini_virtual_project": "project-a",
		},
		Metadata: map[string]any{
			authMaintenanceActionMetadataKey:        authMaintenanceDeleteAction,
			authMaintenancePendingDeleteMetadataKey: true,
			authMaintenanceReasonMetadataKey:        "pending_delete",
			"type":                                  "gemini",
		},
	}
	virtualB := &coreauth.Auth{
		ID:       "gemini-multi.json#project-b",
		Provider: "gemini-cli",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"path":                   path,
			"runtime_only":           "true",
			"gemini_virtual_parent":  primary.ID,
			"gemini_virtual_project": "project-b",
		},
		Metadata: map[string]any{
			authMaintenanceActionMetadataKey:        authMaintenanceDeleteAction,
			authMaintenancePendingDeleteMetadataKey: true,
			authMaintenanceReasonMetadataKey:        "pending_delete",
			"type":                                  "gemini",
		},
	}

	for _, auth := range []*coreauth.Auth{primary, virtualA, virtualB} {
		if _, err := service.coreManager.Register(context.Background(), auth); err != nil {
			t.Fatalf("register auth %s: %v", auth.ID, err)
		}
	}

	candidate, ok := service.authMaintenanceCandidateForAuth(primary, authDir, "pending_delete")
	if !ok {
		t.Fatal("expected auth maintenance candidate for primary auth")
	}
	if got := strings.TrimSpace(candidate.Path); got != path {
		t.Fatalf("candidate path = %q, want %q", got, path)
	}
	if len(candidate.IDs) != 1 || candidate.IDs[0] != primary.ID {
		t.Fatalf("candidate IDs = %v, want only %q", candidate.IDs, primary.ID)
	}

	scanned := service.scanAuthMaintenanceCandidates(config.AuthMaintenanceConfig{Enable: true}, authDir)
	if len(scanned) != 1 {
		t.Fatalf("scanAuthMaintenanceCandidates() returned %d candidates, want 1", len(scanned))
	}
	if got := strings.TrimSpace(scanned[0].Path); got != path {
		t.Fatalf("scanned candidate path = %q, want %q", got, path)
	}
	if len(scanned[0].IDs) != 1 || scanned[0].IDs[0] != primary.ID {
		t.Fatalf("scanned candidate IDs = %v, want only %q", scanned[0].IDs, primary.ID)
	}
}
