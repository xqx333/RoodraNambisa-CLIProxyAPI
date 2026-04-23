// Package cliproxy provides the core service implementation for the CLI Proxy API.
// It includes service lifecycle management, authentication handling, file watching,
// and integration with various AI service providers through a unified interface.
package cliproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/api"
	internalcodex "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor"
	internalusage "github.com/router-for-me/CLIProxyAPI/v6/internal/usage"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/watcher"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/wsrelay"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v6/sdk/access"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v6/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	sdkusage "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/usage"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
	log "github.com/sirupsen/logrus"
)

// Service wraps the proxy server lifecycle so external programs can embed the CLI proxy.
// It manages the complete lifecycle including authentication, file watching, HTTP server,
// and integration with various AI service providers.
type Service struct {
	// cfg holds the current application configuration.
	cfg *config.Config

	// cfgMu protects concurrent access to the configuration.
	cfgMu sync.RWMutex

	// configPath is the path to the configuration file.
	configPath string

	// tokenProvider handles loading token-based clients.
	tokenProvider TokenClientProvider

	// apiKeyProvider handles loading API key-based clients.
	apiKeyProvider APIKeyClientProvider

	// watcherFactory creates file watcher instances.
	watcherFactory WatcherFactory

	// hooks provides lifecycle callbacks.
	hooks Hooks

	// serverOptions contains additional server configuration options.
	serverOptions []api.ServerOption

	// server is the HTTP API server instance.
	server *api.Server

	// pprofServer manages the optional pprof HTTP debug server.
	pprofServer *pprofServer

	// serverErr channel for server startup/shutdown errors.
	serverErr chan error

	// watcher handles file system monitoring.
	watcher *WatcherWrapper

	// watcherCancel cancels the watcher context.
	watcherCancel context.CancelFunc

	// authUpdates channel for authentication updates.
	authUpdates chan watcher.AuthUpdate

	// authQueueStop cancels the auth update queue processing.
	authQueueStop context.CancelFunc

	// modelSyncMu protects the background model sync worker pool state.
	modelSyncMu sync.Mutex

	// modelSyncCancel stops the optional background model sync workers.
	modelSyncCancel context.CancelFunc

	// modelSyncDone is closed when the model sync workers exit.
	modelSyncDone chan struct{}

	// modelSyncQueue carries auth IDs that need registry and scheduler resync.
	modelSyncQueue chan string

	// modelSyncPending deduplicates queued or running auth sync tasks.
	modelSyncPending map[string]modelSyncTaskState

	// usagePersistenceMu protects the periodic persistence loop lifecycle.
	usagePersistenceMu sync.Mutex

	// usagePersistenceCancel stops the periodic usage persistence loop.
	usagePersistenceCancel context.CancelFunc

	// usagePersistenceDone is closed when the periodic usage persistence loop exits.
	usagePersistenceDone chan struct{}

	// usageStats optionally overrides the shared usage statistics store for tests.
	usageStats *internalusage.RequestStatistics

	// authManager handles legacy authentication operations.
	authManager *sdkAuth.Manager

	// accessManager handles request authentication providers.
	accessManager *sdkaccess.Manager

	// coreManager handles core authentication and execution.
	coreManager *coreauth.Manager

	// shutdownOnce ensures shutdown is called only once.
	shutdownOnce sync.Once

	// wsGateway manages websocket Gemini providers.
	wsGateway *wsrelay.Manager

	// maintenanceMu protects auth maintenance queue state.
	maintenanceMu sync.Mutex

	// maintenanceCancel stops the optional auth maintenance worker.
	maintenanceCancel context.CancelFunc

	// maintenanceDone is closed when the maintenance worker exits.
	maintenanceDone chan struct{}

	// maintenanceQueue stores pending auth file deletions.
	maintenanceQueue []authMaintenanceCandidate

	// maintenancePending deduplicates queued auth files by canonical path.
	maintenancePending map[string]struct{}

	// maintenanceGeneration tracks cancellation generations for auth maintenance keys.
	maintenanceGeneration map[string]uint64

	// maintenanceStaged tracks auth paths temporarily moved out of the way by maintenance.
	maintenanceStaged map[string]int

	// maintenanceWake nudges the maintenance worker to wake early.
	maintenanceWake chan struct{}
}

// RegisterUsagePlugin registers a usage plugin on the global usage manager.
// This allows external code to monitor API usage and token consumption.
//
// Parameters:
//   - plugin: The usage plugin to register
func (s *Service) RegisterUsagePlugin(plugin sdkusage.Plugin) {
	sdkusage.RegisterPlugin(plugin)
}

// newDefaultAuthManager creates a default authentication manager with all supported providers.
func newDefaultAuthManager() *sdkAuth.Manager {
	return sdkAuth.NewManager(
		sdkAuth.GetTokenStore(),
		sdkAuth.NewGeminiAuthenticator(),
		sdkAuth.NewCodexAuthenticator(),
		sdkAuth.NewClaudeAuthenticator(),
	)
}

const (
	usagePersistenceDisabledPollInterval    = 5 * time.Second
	authMaintenanceDisabledPollInterval     = 5 * time.Second
	defaultMaintenanceScanIntervalSeconds   = 30
	defaultMaintenanceDeleteIntervalSeconds = 5
	defaultMaintenanceQuotaStrikeThreshold  = 6
	authMaintenanceStagedIgnoreWindow       = 200 * time.Millisecond
	defaultModelSyncWorkers                 = 4
	defaultModelSyncQueueSize               = 256
	authMaintenanceMetadataPrefix           = "auth_maintenance_"
	authMaintenanceActionMetadataKey        = "auth_maintenance_action"
	authMaintenanceReasonMetadataKey        = "auth_maintenance_reason"
	authMaintenanceMarkedAtMetadataKey      = "auth_maintenance_marked_at"
	authMaintenancePendingDeleteMetadataKey = "auth_maintenance_pending_delete"
	authMaintenanceDeleteAction             = "delete"
	authMaintenanceDisableAction            = "disable"
)

var (
	readAuthMaintenanceFile                    = os.ReadFile
	statAuthMaintenanceFile                    = os.Stat
	removeAuthMaintenanceFile                  = os.Remove
	renameAuthMaintenanceFile                  = os.Rename
	removeAuthMaintenanceFileIfSnapshotMatches = stageAuthMaintenanceFileIfSnapshotMatches
)

type authMaintenanceCandidate struct {
	Key        string
	Path       string
	IDs        []string
	Reason     string
	Generation uint64
}

type modelSyncTaskState struct {
	dirty bool
}

type authMaintenanceHook struct {
	service *Service
}

func (h authMaintenanceHook) OnAuthRegistered(context.Context, *coreauth.Auth) {}

func (h authMaintenanceHook) OnAuthUpdated(context.Context, *coreauth.Auth) {}

func (h authMaintenanceHook) OnResult(ctx context.Context, result coreauth.Result) {
	if h.service != nil {
		h.service.handleAuthMaintenanceResult(ctx, result)
	}
}

func usagePersistenceIntervalForConfig(cfg *config.Config) time.Duration {
	if cfg == nil || cfg.UsageStatisticsPersistIntervalSeconds <= 0 {
		return 0
	}
	return time.Duration(cfg.UsageStatisticsPersistIntervalSeconds) * time.Second
}

func (s *Service) currentConfig() *config.Config {
	if s == nil {
		return nil
	}
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

func (s *Service) usageStatisticsEnabled() bool {
	cfg := s.currentConfig()
	return cfg != nil && cfg.UsageStatisticsEnabled
}

func (s *Service) usagePersistenceInterval() time.Duration {
	return usagePersistenceIntervalForConfig(s.currentConfig())
}

func (s *Service) usageStatisticsFilePath() string {
	cfg := s.currentConfig()
	if cfg == nil {
		return ""
	}
	return internalusage.StatisticsFilePath(cfg)
}

func (s *Service) usageStatisticsStore() *internalusage.RequestStatistics {
	if s != nil && s.usageStats != nil {
		return s.usageStats
	}
	return internalusage.GetRequestStatistics()
}

func (s *Service) restoreUsageStatistics() {
	if s == nil || !s.usageStatisticsEnabled() {
		return
	}
	path := s.usageStatisticsFilePath()
	if strings.TrimSpace(path) == "" {
		return
	}
	loaded, result, err := internalusage.RestoreRequestStatistics(path, s.usageStatisticsStore())
	if err != nil {
		log.WithError(err).Warnf("failed to restore usage statistics from %s", path)
		return
	}
	if loaded {
		log.Infof("usage statistics restored from %s (added=%d skipped=%d)", path, result.Added, result.Skipped)
	}
}

func (s *Service) persistUsageStatistics(reason string) {
	if s == nil {
		return
	}
	path := s.usageStatisticsFilePath()
	if strings.TrimSpace(path) == "" {
		return
	}
	if s.usagePersistenceInterval() <= 0 && reason != "disable" && reason != "shutdown" {
		return
	}
	saved, err := internalusage.PersistRequestStatistics(path, s.usageStatisticsStore())
	if err != nil {
		log.WithError(err).Warnf("failed to persist usage statistics during %s", reason)
		return
	}
	if !saved {
		return
	}
	if reason == "shutdown" {
		log.Infof("usage statistics persisted to %s during shutdown", path)
		return
	}
	log.Debugf("usage statistics persisted to %s (%s)", path, reason)
}

func (s *Service) nextUsagePersistenceWait() time.Duration {
	if !s.usageStatisticsEnabled() {
		return usagePersistenceDisabledPollInterval
	}
	interval := s.usagePersistenceInterval()
	if interval <= 0 {
		return usagePersistenceDisabledPollInterval
	}
	return interval
}

func (s *Service) startUsagePersistenceLoop() {
	if s == nil {
		return
	}
	s.usagePersistenceMu.Lock()
	defer s.usagePersistenceMu.Unlock()
	if s.usagePersistenceCancel != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.usagePersistenceCancel = cancel
	s.usagePersistenceDone = done

	go func() {
		defer close(done)
		for {
			wait := s.nextUsagePersistenceWait()
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			case <-timer.C:
			}

			if s.usageStatisticsEnabled() && s.usagePersistenceInterval() > 0 {
				s.reconcileUsageStatistics("periodic")
				s.persistUsageStatistics("periodic")
			}
		}
	}()
}

func (s *Service) stopUsagePersistenceLoop() {
	if s == nil {
		return
	}
	s.usagePersistenceMu.Lock()
	cancel := s.usagePersistenceCancel
	done := s.usagePersistenceDone
	s.usagePersistenceCancel = nil
	s.usagePersistenceDone = nil
	s.usagePersistenceMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (s *Service) restartUsagePersistenceLoop() {
	if s == nil {
		return
	}
	s.stopUsagePersistenceLoop()
	s.startUsagePersistenceLoop()
}

func (s *Service) applyUsagePersistenceConfigChange(previousEnabled bool, previousInterval time.Duration, newCfg *config.Config) {
	if s == nil || newCfg == nil {
		return
	}
	currentEnabled := newCfg.UsageStatisticsEnabled
	currentInterval := usagePersistenceIntervalForConfig(newCfg)

	if previousEnabled && !currentEnabled {
		s.persistUsageStatistics("disable")
	}
	if !previousEnabled && currentEnabled {
		s.restoreUsageStatistics()
		if s.reconcileUsageStatistics("enable") > 0 {
			s.persistUsageStatistics("enable-reconcile")
		}
	}
	if previousEnabled != currentEnabled || previousInterval != currentInterval {
		s.restartUsagePersistenceLoop()
	}
}

func resolveAuthFilePath(auth *coreauth.Auth, authDir string) string {
	if auth == nil {
		return ""
	}
	if auth.Attributes != nil && strings.EqualFold(strings.TrimSpace(auth.Attributes["runtime_only"]), "true") {
		return ""
	}
	path := ""
	if auth.Attributes != nil {
		path = strings.TrimSpace(auth.Attributes["path"])
	}
	if path == "" {
		path = strings.TrimSpace(auth.FileName)
	}
	if path == "" {
		return ""
	}
	if !filepath.IsAbs(path) {
		if strings.TrimSpace(authDir) == "" {
			return ""
		}
		path = filepath.Join(authDir, filepath.Base(path))
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return path
}

func authExistsForUsage(auth *coreauth.Auth, authDir string) bool {
	if auth == nil {
		return false
	}
	if auth.Attributes != nil && strings.EqualFold(strings.TrimSpace(auth.Attributes["runtime_only"]), "true") {
		return true
	}
	_ = authDir
	return true
}

func authUpdateDeletionPath(auth *coreauth.Auth, authDir string) string {
	if auth == nil {
		return ""
	}
	return resolveAuthFilePath(auth, authDir)
}

func authUpdateIsMaintenanceDelete(auth *coreauth.Auth) bool {
	if auth == nil {
		return false
	}
	if authMaintenancePendingDelete(auth) {
		return true
	}
	if auth.Metadata == nil {
		return false
	}
	action, _ := auth.Metadata[authMaintenanceActionMetadataKey].(string)
	return strings.EqualFold(strings.TrimSpace(action), authMaintenanceDeleteAction)
}

func (s *Service) buildValidUsageAuthIndexes() map[string]struct{} {
	if s == nil || s.coreManager == nil {
		return nil
	}
	cfg := s.currentConfig()
	authDir := ""
	if cfg != nil {
		authDir = strings.TrimSpace(cfg.AuthDir)
	}
	auths := s.coreManager.List()
	indexes := make(map[string]struct{}, len(auths))
	for _, auth := range auths {
		if auth == nil || !authExistsForUsage(auth, authDir) {
			continue
		}
		if index := strings.TrimSpace(auth.EnsureIndex()); index != "" {
			indexes[index] = struct{}{}
		}
	}
	return indexes
}

func (s *Service) reconcileUsageStatistics(reason string) int {
	if s == nil || !s.usageStatisticsEnabled() {
		return 0
	}
	valid := s.buildValidUsageAuthIndexes()
	removed := s.usageStatisticsStore().PruneAuthIndexes(valid)
	if removed > 0 {
		log.Infof("usage statistics reconciled (%s): removed %d stale records", reason, removed)
	}
	return removed
}

func (s *Service) usageAuthIndexesForIDs(ids []string) []string {
	if s == nil || !s.usageStatisticsEnabled() || len(ids) == 0 || s.coreManager == nil {
		return nil
	}
	indexSet := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		auth, ok := s.coreManager.GetByID(id)
		if !ok || auth == nil {
			continue
		}
		if index := strings.TrimSpace(auth.EnsureIndex()); index != "" {
			indexSet[index] = struct{}{}
		}
	}
	if len(indexSet) == 0 {
		return nil
	}
	indexes := make([]string, 0, len(indexSet))
	for index := range indexSet {
		indexes = append(indexes, index)
	}
	return indexes
}

func (s *Service) removeUsageStatisticsForAuthIndexes(indexes []string, reason string) int {
	if s == nil || !s.usageStatisticsEnabled() || len(indexes) == 0 {
		return 0
	}
	removed := s.usageStatisticsStore().RemoveAuthIndexes(indexes)
	if removed > 0 {
		log.Infof("usage statistics updated after %s: removed %d records for %d auth(s)", reason, removed, len(indexes))
		s.persistUsageStatistics("auth-delete")
	}
	return removed
}

func (s *Service) removeUsageStatisticsForAuthIDs(ids []string, reason string) int {
	return s.removeUsageStatisticsForAuthIndexes(s.usageAuthIndexesForIDs(ids), reason)
}

func (s *Service) snapshotAuthMaintenanceConfig() (config.AuthMaintenanceConfig, string) {
	if s == nil {
		return config.AuthMaintenanceConfig{
			ScanIntervalSeconds:         defaultMaintenanceScanIntervalSeconds,
			DeleteIntervalSeconds:       defaultMaintenanceDeleteIntervalSeconds,
			QuotaStrikeThreshold:        defaultMaintenanceQuotaStrikeThreshold,
			DisableQuotaStrikeThreshold: defaultMaintenanceQuotaStrikeThreshold,
		}, ""
	}
	cfg := s.currentConfig()
	if cfg == nil {
		return config.AuthMaintenanceConfig{
			ScanIntervalSeconds:         defaultMaintenanceScanIntervalSeconds,
			DeleteIntervalSeconds:       defaultMaintenanceDeleteIntervalSeconds,
			QuotaStrikeThreshold:        defaultMaintenanceQuotaStrikeThreshold,
			DisableQuotaStrikeThreshold: defaultMaintenanceQuotaStrikeThreshold,
		}, ""
	}
	maintenance := cfg.AuthMaintenance
	if maintenance.ScanIntervalSeconds <= 0 {
		maintenance.ScanIntervalSeconds = defaultMaintenanceScanIntervalSeconds
	}
	if maintenance.DeleteIntervalSeconds <= 0 {
		maintenance.DeleteIntervalSeconds = defaultMaintenanceDeleteIntervalSeconds
	}
	if maintenance.QuotaStrikeThreshold <= 0 {
		maintenance.QuotaStrikeThreshold = defaultMaintenanceQuotaStrikeThreshold
	}
	if maintenance.DisableQuotaStrikeThreshold <= 0 {
		maintenance.DisableQuotaStrikeThreshold = defaultMaintenanceQuotaStrikeThreshold
	}
	return maintenance, strings.TrimSpace(cfg.AuthDir)
}

func (s *Service) warnAuthMaintenanceConfig(cfg config.AuthMaintenanceConfig) {
	if !cfg.Enable {
		return
	}
	if cfg.DeleteQuotaExceeded && cfg.DisableQuotaExceeded {
		log.Warn("auth maintenance: delete-quota-exceeded and disable-quota-exceeded are both enabled; delete policy takes precedence and disable-only handling is skipped")
	}
}

func containsStatusCode(codes []int, want int) bool {
	if want == 0 {
		return false
	}
	for _, code := range codes {
		if code == want {
			return true
		}
	}
	return false
}

func authMaintenancePendingDelete(auth *coreauth.Auth) bool {
	if auth == nil || auth.Metadata == nil {
		return false
	}
	raw, ok := auth.Metadata[authMaintenancePendingDeleteMetadataKey]
	if !ok {
		return false
	}
	switch value := raw.(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(strings.TrimSpace(value), "true")
	default:
		return false
	}
}

func authMaintenanceReason(auth *coreauth.Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	value, _ := auth.Metadata[authMaintenanceReasonMetadataKey].(string)
	return strings.TrimSpace(value)
}

func authMaintenanceStatusCode(auth *coreauth.Auth, result *coreauth.Result) int {
	if result != nil && result.Error != nil && result.Error.HTTPStatus > 0 {
		return result.Error.HTTPStatus
	}
	if auth == nil {
		return 0
	}
	if auth.LastError != nil && auth.LastError.HTTPStatus > 0 {
		return auth.LastError.HTTPStatus
	}
	switch strings.ToLower(strings.TrimSpace(auth.StatusMessage)) {
	case "unauthorized":
		return 401
	case "payment_required":
		return 402
	case "not_found":
		return 404
	case "quota exhausted":
		return 429
	default:
		return 0
	}
}

func authEligibleForMaintenanceDelete(auth *coreauth.Auth, result *coreauth.Result, cfg config.AuthMaintenanceConfig) (string, bool) {
	if reason := authMaintenanceReason(auth); authMaintenancePendingDelete(auth) {
		if reason == "" {
			reason = "pending_delete"
		}
		return reason, true
	}
	if auth == nil || auth.Disabled || auth.Status == coreauth.StatusDisabled {
		return "", false
	}
	if statusCode := authMaintenanceStatusCode(auth, result); containsStatusCode(cfg.DeleteStatusCodes, statusCode) {
		return fmt.Sprintf("http_%d", statusCode), true
	}
	if cfg.DeleteQuotaExceeded && auth.Quota.Exceeded && auth.Quota.StrikeCount >= cfg.QuotaStrikeThreshold {
		return fmt.Sprintf("quota_delete_%d", auth.Quota.StrikeCount), true
	}
	return "", false
}

func authEligibleForMaintenanceDisable(auth *coreauth.Auth, cfg config.AuthMaintenanceConfig) (string, bool) {
	if auth == nil || auth.Disabled || auth.Status == coreauth.StatusDisabled {
		return "", false
	}
	if cfg.DeleteQuotaExceeded && cfg.DisableQuotaExceeded {
		return "", false
	}
	if cfg.DisableQuotaExceeded && auth.Quota.Exceeded && auth.Quota.StrikeCount >= cfg.DisableQuotaStrikeThreshold {
		return fmt.Sprintf("quota_disable_%d", auth.Quota.StrikeCount), true
	}
	return "", false
}

func (s *Service) ensureAuthMaintenanceQueue() {
	if s == nil {
		return
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	if s.maintenancePending == nil {
		s.maintenancePending = make(map[string]struct{})
	}
	if s.maintenanceGeneration == nil {
		s.maintenanceGeneration = make(map[string]uint64)
	}
	if s.maintenanceStaged == nil {
		s.maintenanceStaged = make(map[string]int)
	}
	if s.maintenanceWake == nil {
		s.maintenanceWake = make(chan struct{}, 1)
	}
}

func (s *Service) wakeAuthMaintenance() {
	if s == nil {
		return
	}
	s.ensureAuthMaintenanceQueue()
	select {
	case s.maintenanceWake <- struct{}{}:
	default:
	}
}

func (s *Service) installAuthMaintenanceHook() {
	if s == nil || s.coreManager == nil {
		return
	}
	s.coreManager.AddHook(authMaintenanceHook{service: s})
}

func (s *Service) enqueueAuthMaintenanceCandidate(candidate authMaintenanceCandidate) bool {
	if s == nil {
		return false
	}
	key := strings.TrimSpace(candidate.Key)
	if key == "" || len(candidate.IDs) == 0 {
		return false
	}
	s.ensureAuthMaintenanceQueue()
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	if _, exists := s.maintenancePending[key]; exists {
		return false
	}
	candidate.Generation = s.maintenanceGeneration[key]
	s.maintenancePending[key] = struct{}{}
	s.maintenanceQueue = append(s.maintenanceQueue, candidate)
	return true
}

func (s *Service) dequeueAuthMaintenanceCandidate() (authMaintenanceCandidate, bool) {
	if s == nil {
		return authMaintenanceCandidate{}, false
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	if len(s.maintenanceQueue) == 0 {
		return authMaintenanceCandidate{}, false
	}
	candidate := s.maintenanceQueue[0]
	s.maintenanceQueue = append([]authMaintenanceCandidate(nil), s.maintenanceQueue[1:]...)
	delete(s.maintenancePending, strings.TrimSpace(candidate.Key))
	return candidate, true
}

func (s *Service) hasQueuedAuthMaintenanceCandidates() bool {
	if s == nil {
		return false
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	return len(s.maintenanceQueue) > 0
}

func (s *Service) authMaintenanceCandidateQueued(candidate authMaintenanceCandidate) bool {
	if s == nil {
		return false
	}
	key := strings.TrimSpace(candidate.Key)
	if key == "" {
		return false
	}
	s.ensureAuthMaintenanceQueue()
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	_, exists := s.maintenancePending[key]
	return exists
}

func (s *Service) cancelAuthMaintenanceCandidate(candidate authMaintenanceCandidate) bool {
	return s.cancelAuthMaintenanceKey(strings.TrimSpace(candidate.Key))
}

func (s *Service) cancelAuthMaintenanceKey(key string) bool {
	if s == nil {
		return false
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	s.ensureAuthMaintenanceQueue()
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()

	removed := false
	filtered := s.maintenanceQueue[:0]
	for _, candidate := range s.maintenanceQueue {
		if strings.TrimSpace(candidate.Key) == key {
			removed = true
			continue
		}
		filtered = append(filtered, candidate)
	}
	s.maintenanceQueue = filtered
	if _, exists := s.maintenancePending[key]; exists {
		delete(s.maintenancePending, key)
		removed = true
	}
	s.maintenanceGeneration[key]++
	return removed
}

func (s *Service) authMaintenanceCandidateCanceled(candidate authMaintenanceCandidate) bool {
	if s == nil {
		return false
	}
	key := strings.TrimSpace(candidate.Key)
	if key == "" {
		return false
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	return s.maintenanceGeneration[key] != candidate.Generation
}

func (s *Service) markAuthMaintenanceStagedPath(path string) {
	if s == nil {
		return
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	s.ensureAuthMaintenanceQueue()
	s.maintenanceMu.Lock()
	s.maintenanceStaged[path]++
	s.maintenanceMu.Unlock()
}

func (s *Service) unmarkAuthMaintenanceStagedPath(path string) {
	if s == nil {
		return
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	if count, ok := s.maintenanceStaged[path]; ok {
		if count <= 1 {
			delete(s.maintenanceStaged, path)
			return
		}
		s.maintenanceStaged[path] = count - 1
	}
}

func (s *Service) releaseAuthMaintenanceStagedPath(path string) {
	if s == nil {
		return
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	time.AfterFunc(authMaintenanceStagedIgnoreWindow, func() {
		s.unmarkAuthMaintenanceStagedPath(path)
	})
}

func (s *Service) authMaintenancePathStaged(path string) bool {
	if s == nil {
		return false
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	return s.maintenanceStaged[path] > 0
}

func (s *Service) authMaintenanceCandidateForAuth(auth *coreauth.Auth, authDir string, reason string) (authMaintenanceCandidate, bool) {
	if s == nil || s.coreManager == nil || auth == nil {
		return authMaintenanceCandidate{}, false
	}
	path := resolveAuthFilePath(auth, authDir)
	if strings.TrimSpace(path) == "" {
		id := strings.TrimSpace(auth.ID)
		if id == "" {
			return authMaintenanceCandidate{}, false
		}
		return authMaintenanceCandidate{
			Key:    id,
			IDs:    []string{id},
			Reason: strings.TrimSpace(reason),
		}, true
	}

	ids := make([]string, 0, 1)
	seen := make(map[string]struct{})
	for _, current := range s.coreManager.List() {
		if resolveAuthFilePath(current, authDir) != path {
			continue
		}
		id := strings.TrimSpace(current.ID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		id := strings.TrimSpace(auth.ID)
		if id == "" {
			return authMaintenanceCandidate{}, false
		}
		ids = append(ids, id)
	}
	return authMaintenanceCandidate{
		Key:    path,
		Path:   path,
		IDs:    ids,
		Reason: strings.TrimSpace(reason),
	}, true
}

func (s *Service) authMaintenanceCandidateForID(id, authDir, reason string) (authMaintenanceCandidate, bool) {
	if s == nil || s.coreManager == nil {
		return authMaintenanceCandidate{}, false
	}
	auth, ok := s.coreManager.GetByID(strings.TrimSpace(id))
	if !ok || auth == nil {
		id = strings.TrimSpace(id)
		if id == "" {
			return authMaintenanceCandidate{}, false
		}
		return authMaintenanceCandidate{Key: id, IDs: []string{id}, Reason: strings.TrimSpace(reason)}, true
	}
	return s.authMaintenanceCandidateForAuth(auth, authDir, reason)
}

func (s *Service) scanAuthMaintenanceCandidates(cfg config.AuthMaintenanceConfig, authDir string) []authMaintenanceCandidate {
	if s == nil || s.coreManager == nil || !cfg.Enable {
		return nil
	}
	snapshot := s.coreManager.List()
	grouped := make(map[string]authMaintenanceCandidate)
	for _, auth := range snapshot {
		reason, ok := authEligibleForMaintenanceDelete(auth, nil, cfg)
		if !ok {
			continue
		}
		candidate, ok := s.authMaintenanceCandidateForAuth(auth, authDir, reason)
		if !ok || strings.TrimSpace(candidate.Path) == "" {
			continue
		}
		group := grouped[candidate.Key]
		if group.Key == "" {
			group = candidate
		}
		if group.Reason == "" {
			group.Reason = candidate.Reason
		}
		seen := make(map[string]struct{}, len(group.IDs))
		for _, id := range group.IDs {
			seen[id] = struct{}{}
		}
		for _, id := range candidate.IDs {
			if _, exists := seen[id]; exists {
				continue
			}
			group.IDs = append(group.IDs, id)
			seen[id] = struct{}{}
		}
		grouped[candidate.Key] = group
	}
	candidates := make([]authMaintenanceCandidate, 0, len(grouped))
	for _, candidate := range grouped {
		candidates = append(candidates, candidate)
	}
	return candidates
}

func (s *Service) startAuthMaintenance(parent context.Context) {
	if s == nil {
		return
	}
	s.ensureAuthMaintenanceQueue()
	s.maintenanceMu.Lock()
	if s.maintenanceCancel != nil {
		s.maintenanceMu.Unlock()
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	s.maintenanceCancel = cancel
	s.maintenanceDone = done
	s.maintenanceMu.Unlock()

	go func() {
		defer close(done)
		var lastDeleteAt time.Time
		for {
			cfg, authDir := s.snapshotAuthMaintenanceConfig()
			s.warnAuthMaintenanceConfig(cfg)

			if cfg.Enable {
				if candidate, ok := s.dequeueAuthMaintenanceCandidate(); ok {
					if s.authMaintenanceCandidateCanceled(candidate) {
						continue
					}
					deleteInterval := time.Duration(cfg.DeleteIntervalSeconds) * time.Second
					if deleteInterval <= 0 {
						deleteInterval = time.Duration(defaultMaintenanceDeleteIntervalSeconds) * time.Second
					}
					if !lastDeleteAt.IsZero() {
						wait := deleteInterval - time.Since(lastDeleteAt)
						if wait > 0 {
							timer := time.NewTimer(wait)
							select {
							case <-ctx.Done():
								if !timer.Stop() {
									select {
									case <-timer.C:
									default:
									}
								}
								return
							case <-timer.C:
							}
						}
					}
					if s.authMaintenanceCandidateCanceled(candidate) {
						continue
					}
					deleted, err := s.deleteAuthMaintenanceCandidate(ctx, candidate)
					if err != nil {
						log.WithError(err).Warnf("auth maintenance delete failed for %s", candidate.Path)
					} else if deleted {
						lastDeleteAt = time.Now()
					}
					continue
				}
				for _, candidate := range s.scanAuthMaintenanceCandidates(cfg, authDir) {
					if s.authMaintenanceCandidateQueued(candidate) {
						continue
					}
					if !s.disableAuthMaintenanceCandidate(context.Background(), candidate, true) {
						continue
					}
					if s.enqueueAuthMaintenanceCandidate(candidate) {
						log.Debugf("auth maintenance queued %s (%s)", candidate.Path, candidate.Reason)
					}
				}
				if s.hasQueuedAuthMaintenanceCandidates() {
					continue
				}
			}

			wait := authMaintenanceDisabledPollInterval
			if cfg.Enable {
				wait = time.Duration(cfg.ScanIntervalSeconds) * time.Second
			}
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			case <-s.maintenanceWake:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			case <-timer.C:
			}
		}
	}()
}

func (s *Service) stopAuthMaintenance() {
	if s == nil {
		return
	}
	s.maintenanceMu.Lock()
	cancel := s.maintenanceCancel
	done := s.maintenanceDone
	s.maintenanceCancel = nil
	s.maintenanceDone = nil
	s.maintenanceMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (s *Service) handleAuthMaintenanceResult(_ context.Context, result coreauth.Result) {
	if s == nil || s.coreManager == nil || result.Success {
		return
	}
	cfg, authDir := s.snapshotAuthMaintenanceConfig()
	if !cfg.Enable {
		return
	}
	authID := strings.TrimSpace(result.AuthID)
	if authID == "" {
		return
	}
	auth, ok := s.coreManager.GetByID(authID)
	if !ok || auth == nil {
		return
	}
	if reason, ok := authEligibleForMaintenanceDelete(auth, &result, cfg); ok {
		candidate, candidateOK := s.authMaintenanceCandidateForAuth(auth, authDir, reason)
		if !candidateOK {
			return
		}
		if strings.TrimSpace(candidate.Path) == "" {
			s.disableAuthMaintenanceCandidate(context.Background(), candidate, false)
			return
		}
		if !s.disableAuthMaintenanceCandidate(context.Background(), candidate, true) {
			return
		}
		if s.enqueueAuthMaintenanceCandidate(candidate) {
			s.wakeAuthMaintenance()
		}
		return
	}
	if reason, ok := authEligibleForMaintenanceDisable(auth, cfg); ok {
		candidate, candidateOK := s.authMaintenanceCandidateForAuth(auth, authDir, reason)
		if !candidateOK {
			return
		}
		s.disableAuthMaintenanceCandidate(context.Background(), candidate, false)
	}
}

func (s *Service) disableAuthMaintenanceCandidate(ctx context.Context, candidate authMaintenanceCandidate, pendingDelete bool) bool {
	if s == nil {
		return false
	}
	success := true
	for _, id := range candidate.IDs {
		if !s.applyCoreAuthRemovalWithReason(ctx, id, candidate.Reason, pendingDelete) {
			success = false
		}
	}
	return success
}

func (s *Service) deleteAuthMaintenanceCandidate(ctx context.Context, candidate authMaintenanceCandidate) (bool, error) {
	if s == nil {
		return false, nil
	}
	path := strings.TrimSpace(candidate.Path)
	if path == "" {
		return false, nil
	}
	s.ensureAuthMaintenanceQueue()
	if s.authMaintenanceCandidateCanceled(candidate) {
		return false, nil
	}

	info, err := statAuthMaintenanceFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat auth file before maintenance delete: %w", err)
	}
	contents, err := readAuthMaintenanceFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read auth file before maintenance delete: %w", err)
	}
	unchanged, err := authMaintenanceFileMatchesSnapshot(path, contents)
	if err != nil {
		return false, err
	}
	if !unchanged {
		return false, nil
	}

	restoreIfNeeded := func() error {
		if _, statErr := statAuthMaintenanceFile(path); statErr == nil {
			return nil
		} else if !os.IsNotExist(statErr) {
			return fmt.Errorf("stat auth file during maintenance restore: %w", statErr)
		}
		if s.restoreCurrentAuthMaintenanceFile(context.WithoutCancel(ctx), candidate, path) {
			return nil
		}
		if errWrite := os.WriteFile(path, contents, info.Mode().Perm()); errWrite != nil {
			return fmt.Errorf("restore auth file after canceled delete: %w", errWrite)
		}
		return nil
	}
	skipDeleteUpdate := func() (bool, error) {
		if s.authMaintenanceCandidateCanceled(candidate) {
			if errRestore := restoreIfNeeded(); errRestore != nil {
				return false, errRestore
			}
			return true, nil
		}
		if _, statErr := statAuthMaintenanceFile(path); statErr == nil {
			return true, nil
		} else if statErr != nil && !os.IsNotExist(statErr) {
			return false, fmt.Errorf("stat auth file after maintenance delete: %w", statErr)
		}
		return false, nil
	}

	s.markAuthMaintenanceStagedPath(path)
	defer s.releaseAuthMaintenanceStagedPath(path)

	stagedPath, removed, err := removeAuthMaintenanceFileIfSnapshotMatches(path, contents)
	if err != nil {
		return false, err
	}
	if !removed {
		return false, nil
	}
	cleanupStaged := func() error {
		if strings.TrimSpace(stagedPath) == "" {
			return nil
		}
		if errRemove := removeAuthMaintenanceFile(stagedPath); errRemove != nil && !os.IsNotExist(errRemove) {
			return fmt.Errorf("remove staged auth file: %w", errRemove)
		}
		return nil
	}
	restoreStaged := func() error {
		if strings.TrimSpace(stagedPath) == "" {
			return nil
		}
		if _, statErr := statAuthMaintenanceFile(path); statErr == nil {
			return cleanupStaged()
		} else if !os.IsNotExist(statErr) {
			return fmt.Errorf("stat auth file during staged restore: %w", statErr)
		}
		if errRename := renameAuthMaintenanceFile(stagedPath, path); errRename != nil {
			if os.IsNotExist(errRename) {
				return nil
			}
			return fmt.Errorf("restore staged auth file: %w", errRename)
		}
		return nil
	}

	skip, err := skipDeleteUpdate()
	if err != nil {
		return false, err
	}
	if skip {
		if errRestore := restoreStaged(); errRestore != nil {
			return false, errRestore
		}
		return false, nil
	}

	if errCleanup := cleanupStaged(); errCleanup != nil {
		return false, errCleanup
	}
	skip, err = skipDeleteUpdate()
	if err != nil {
		return false, err
	}
	if skip {
		return false, nil
	}

	indexes := s.usageAuthIndexesForIDs(candidate.IDs)
	for _, id := range candidate.IDs {
		skip, err = skipDeleteUpdate()
		if err != nil {
			return false, err
		}
		if skip {
			return false, nil
		}
		if errDelete := s.deleteCoreAuth(ctx, strings.TrimSpace(id)); errDelete != nil {
			if errRestore := restoreIfNeeded(); errRestore != nil {
				return false, errRestore
			}
			return false, errDelete
		}
	}
	s.removeUsageStatisticsForAuthIndexes(indexes, "auth maintenance delete")
	if s.reconcileUsageStatistics("auth maintenance delete") > 0 {
		s.persistUsageStatistics("auth-maintenance-delete-reconcile")
	}
	return true, nil
}

func (s *Service) restoreCurrentAuthMaintenanceFile(ctx context.Context, candidate authMaintenanceCandidate, path string) bool {
	if s == nil || s.coreManager == nil {
		return false
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	authDir := ""
	if cfg := s.currentConfig(); cfg != nil {
		authDir = strings.TrimSpace(cfg.AuthDir)
	}
	for _, id := range candidate.IDs {
		auth, ok := s.coreManager.GetByID(strings.TrimSpace(id))
		if !ok || auth == nil || authMaintenancePendingDelete(auth) {
			continue
		}
		if resolveAuthFilePath(auth, authDir) != path {
			continue
		}
		if _, err := s.coreManager.Update(ctx, auth.Clone()); err != nil {
			log.WithError(err).Debugf("auth maintenance restore persist failed for %s", path)
			return false
		}
		if _, err := statAuthMaintenanceFile(path); err == nil {
			return true
		}
		return false
	}
	return false
}

func authMaintenanceFileMatchesSnapshot(path string, contents []byte) (bool, error) {
	if strings.TrimSpace(path) == "" {
		return false, nil
	}
	current, err := readAuthMaintenanceFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read auth file before maintenance delete confirmation: %w", err)
	}
	return bytes.Equal(current, contents), nil
}

func stageAuthMaintenanceFileIfSnapshotMatches(path string, contents []byte) (string, bool, error) {
	unchanged, err := authMaintenanceFileMatchesSnapshot(path, contents)
	if err != nil {
		return "", false, err
	}
	if !unchanged {
		return "", false, nil
	}
	stagedPath := fmt.Sprintf("%s.auth-maintenance.%d", path, time.Now().UnixNano())
	if err := renameAuthMaintenanceFile(path, stagedPath); err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("stage auth file: %w", err)
	}
	stagedContents, err := readAuthMaintenanceFile(stagedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read staged auth file: %w", err)
	}
	if !bytes.Equal(stagedContents, contents) {
		if _, statErr := statAuthMaintenanceFile(path); statErr == nil {
			if errRemove := removeAuthMaintenanceFile(stagedPath); errRemove != nil && !os.IsNotExist(errRemove) {
				return "", false, fmt.Errorf("cleanup staged auth file after mismatch: %w", errRemove)
			}
		} else if os.IsNotExist(statErr) {
			if errRename := renameAuthMaintenanceFile(stagedPath, path); errRename != nil && !os.IsNotExist(errRename) {
				return "", false, fmt.Errorf("restore staged auth file after mismatch: %w", errRename)
			}
		} else {
			return "", false, fmt.Errorf("stat auth file after staged mismatch: %w", statErr)
		}
		return "", false, nil
	}
	return stagedPath, true, nil
}

func (s *Service) ensureAuthUpdateQueue(ctx context.Context) {
	if s == nil {
		return
	}
	if s.authUpdates == nil {
		s.authUpdates = make(chan watcher.AuthUpdate, 256)
	}
	if s.authQueueStop != nil {
		return
	}
	queueCtx, cancel := context.WithCancel(ctx)
	s.authQueueStop = cancel
	go s.consumeAuthUpdates(queueCtx)
}

func (s *Service) consumeAuthUpdates(ctx context.Context) {
	ctx = coreauth.WithSkipPersist(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case update, ok := <-s.authUpdates:
			if !ok {
				return
			}
			s.handleAuthUpdate(ctx, update)
		labelDrain:
			for {
				select {
				case nextUpdate := <-s.authUpdates:
					s.handleAuthUpdate(ctx, nextUpdate)
				default:
					break labelDrain
				}
			}
		}
	}
}

func (s *Service) emitAuthUpdate(ctx context.Context, update watcher.AuthUpdate) {
	if s == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if s.watcher != nil && s.watcher.DispatchRuntimeAuthUpdate(update) {
		return
	}
	if s.authUpdates != nil {
		select {
		case s.authUpdates <- update:
			return
		default:
			log.Debugf("auth update queue saturated, applying inline action=%v id=%s", update.Action, update.ID)
		}
	}
	s.handleAuthUpdate(ctx, update)
}

func (s *Service) handleAuthUpdate(ctx context.Context, update watcher.AuthUpdate) {
	if s == nil {
		return
	}
	s.cfgMu.RLock()
	cfg := s.cfg
	s.cfgMu.RUnlock()
	if cfg == nil || s.coreManager == nil {
		return
	}
	switch update.Action {
	case watcher.AuthUpdateActionAdd, watcher.AuthUpdateActionModify:
		if update.Auth == nil || update.Auth.ID == "" {
			return
		}
		if !authMaintenancePendingDelete(update.Auth) {
			if candidate, ok := s.authMaintenanceCandidateForAuth(update.Auth, strings.TrimSpace(cfg.AuthDir), ""); ok {
				s.cancelAuthMaintenanceCandidate(candidate)
			}
		}
		s.applyCoreAuthAddOrUpdate(ctx, update.Auth)
	case watcher.AuthUpdateActionDelete:
		id := update.ID
		if id == "" && update.Auth != nil {
			id = update.Auth.ID
		}
		if id == "" {
			return
		}
		deletedPath := authUpdateDeletionPath(update.Auth, strings.TrimSpace(cfg.AuthDir))
		if deletedPath != "" && s.authMaintenancePathStaged(deletedPath) {
			return
		}
		if deletedPath != "" {
			current, ok := s.coreManager.GetByID(id)
			if !ok || current == nil {
				return
			}
			if resolveAuthFilePath(current, strings.TrimSpace(cfg.AuthDir)) != deletedPath {
				return
			}
			if authUpdateIsMaintenanceDelete(update.Auth) && !authMaintenancePendingDelete(current) {
				return
			}
			indexes := s.usageAuthIndexesForIDs([]string{id})
			ctx = coreauth.WithSkipPersist(ctx)
			if errDelete := s.deleteCoreAuth(ctx, id); errDelete != nil {
				return
			}
			s.removeUsageStatisticsForAuthIndexes(indexes, "auth delete")
			if s.reconcileUsageStatistics("auth delete") > 0 {
				s.persistUsageStatistics("auth-delete-reconcile")
			}
			return
		}
		candidate, ok := s.authMaintenanceCandidateForID(id, strings.TrimSpace(cfg.AuthDir), "file_removed")
		if !ok {
			_ = s.deleteCoreAuth(coreauth.WithSkipPersist(ctx), id)
			return
		}
		indexes := s.usageAuthIndexesForIDs(candidate.IDs)
		ctx = coreauth.WithSkipPersist(ctx)
		for _, candidateID := range candidate.IDs {
			if errDelete := s.deleteCoreAuth(ctx, candidateID); errDelete != nil {
				return
			}
		}
		s.removeUsageStatisticsForAuthIndexes(indexes, "auth delete")
		if s.reconcileUsageStatistics("auth delete") > 0 {
			s.persistUsageStatistics("auth-delete-reconcile")
		}
	default:
		log.Debugf("received unknown auth update action: %v", update.Action)
	}
}

func (s *Service) ensureWebsocketGateway() {
	if s == nil {
		return
	}
	if s.wsGateway != nil {
		return
	}
	opts := wsrelay.Options{
		Path:           "/v1/ws",
		OnConnected:    s.wsOnConnected,
		OnDisconnected: s.wsOnDisconnected,
		LogDebugf:      log.Debugf,
		LogInfof:       log.Infof,
		LogWarnf:       log.Warnf,
	}
	s.wsGateway = wsrelay.NewManager(opts)
}

func (s *Service) wsOnConnected(channelID string) {
	if s == nil || channelID == "" {
		return
	}
	if !strings.HasPrefix(strings.ToLower(channelID), "aistudio-") {
		return
	}
	if s.coreManager != nil {
		if existing, ok := s.coreManager.GetByID(channelID); ok && existing != nil {
			if !existing.Disabled && existing.Status == coreauth.StatusActive {
				return
			}
		}
	}
	now := time.Now().UTC()
	auth := &coreauth.Auth{
		ID:         channelID,  // keep channel identifier as ID
		Provider:   "aistudio", // logical provider for switch routing
		Label:      channelID,  // display original channel id
		Status:     coreauth.StatusActive,
		CreatedAt:  now,
		UpdatedAt:  now,
		Attributes: map[string]string{"runtime_only": "true"},
		Metadata:   map[string]any{"email": channelID}, // metadata drives logging and usage tracking
	}
	log.Infof("websocket provider connected: %s", channelID)
	s.emitAuthUpdate(context.Background(), watcher.AuthUpdate{
		Action: watcher.AuthUpdateActionAdd,
		ID:     auth.ID,
		Auth:   auth,
	})
}

func (s *Service) wsOnDisconnected(channelID string, reason error) {
	if s == nil || channelID == "" {
		return
	}
	if reason != nil {
		if strings.Contains(reason.Error(), "replaced by new connection") {
			log.Infof("websocket provider replaced: %s", channelID)
			return
		}
		log.Warnf("websocket provider disconnected: %s (%v)", channelID, reason)
	} else {
		log.Infof("websocket provider disconnected: %s", channelID)
	}
	ctx := context.Background()
	s.emitAuthUpdate(ctx, watcher.AuthUpdate{
		Action: watcher.AuthUpdateActionDelete,
		ID:     channelID,
	})
}

func (s *Service) applyCoreAuthAddOrUpdate(ctx context.Context, auth *coreauth.Auth) {
	if s == nil || s.coreManager == nil || auth == nil || auth.ID == "" {
		return
	}
	auth = auth.Clone()
	s.ensureExecutorsForAuth(auth)

	// IMPORTANT: Update coreManager FIRST, before model registration.
	// This ensures that configuration changes (proxy_url, prefix, etc.) take effect
	// immediately for API calls, rather than waiting for model registration to complete.
	op := "register"
	var err error
	if existing, ok := s.coreManager.GetByID(auth.ID); ok {
		auth.CreatedAt = existing.CreatedAt
		if !existing.Disabled && existing.Status != coreauth.StatusDisabled && !auth.Disabled && auth.Status != coreauth.StatusDisabled {
			auth.LastRefreshedAt = existing.LastRefreshedAt
			auth.NextRefreshAfter = existing.NextRefreshAfter
			if len(auth.ModelStates) == 0 && len(existing.ModelStates) > 0 {
				auth.ModelStates = existing.ModelStates
			}
		}
		op = "update"
		_, err = s.coreManager.Update(ctx, auth)
	} else {
		_, err = s.coreManager.Register(ctx, auth)
	}
	if err != nil {
		log.Errorf("failed to %s auth %s: %v", op, auth.ID, err)
		current, ok := s.coreManager.GetByID(auth.ID)
		if !ok || current.Disabled {
			GlobalModelRegistry().UnregisterClient(auth.ID)
			return
		}
		auth = current
	}

	// Register models after auth is updated in coreManager.
	// When the background model sync pool is running, keep this work off the
	// auth update hot path so watcher bursts do not block on registry sync.
	if !s.enqueueModelSync(auth.ID) {
		s.syncAuthModelsInline(ctx, auth.ID)
	}
}

func (s *Service) applyCoreAuthRemoval(ctx context.Context, id string) {
	s.applyCoreAuthRemovalWithReason(ctx, id, "", false)
}

func (s *Service) deleteCoreAuth(ctx context.Context, id string) error {
	if s == nil || s.coreManager == nil {
		return nil
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.coreManager.Delete(ctx, id); err != nil {
		log.Errorf("failed to delete auth %s: %v", id, err)
		return err
	}
	return nil
}

func (s *Service) applyCoreAuthRemovalWithReason(ctx context.Context, id string, reason string, pendingDelete bool) bool {
	if s == nil || strings.TrimSpace(id) == "" {
		return false
	}
	if s.coreManager == nil {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	id = strings.TrimSpace(id)
	existing, ok := s.coreManager.GetByID(id)
	if !ok || existing == nil {
		GlobalModelRegistry().UnregisterClient(id)
		return true
	}

	now := time.Now().UTC()
	existing.Disabled = true
	existing.Unavailable = true
	existing.Status = coreauth.StatusDisabled
	if pendingDelete {
		if strings.TrimSpace(reason) == "" {
			reason = "pending_delete"
		}
		existing.StatusMessage = fmt.Sprintf("disabled by auth maintenance (%s)", reason)
	} else if strings.TrimSpace(reason) != "" {
		existing.StatusMessage = fmt.Sprintf("disabled by auth maintenance (%s)", reason)
	} else if existing.StatusMessage == "" {
		existing.StatusMessage = "disabled"
	}
	existing.UpdatedAt = now
	if existing.Metadata == nil {
		existing.Metadata = make(map[string]any)
	}
	existing.Metadata["disabled"] = true
	if pendingDelete {
		existing.Metadata[authMaintenanceActionMetadataKey] = authMaintenanceDeleteAction
		existing.Metadata[authMaintenancePendingDeleteMetadataKey] = true
	} else {
		delete(existing.Metadata, authMaintenancePendingDeleteMetadataKey)
	}
	if strings.TrimSpace(reason) != "" {
		if !pendingDelete {
			existing.Metadata[authMaintenanceActionMetadataKey] = authMaintenanceDisableAction
		}
		existing.Metadata[authMaintenanceReasonMetadataKey] = strings.TrimSpace(reason)
		existing.Metadata[authMaintenanceMarkedAtMetadataKey] = now.Format(time.RFC3339Nano)
	} else {
		if pendingDelete {
			existing.Metadata[authMaintenanceMarkedAtMetadataKey] = now.Format(time.RFC3339Nano)
		} else {
			delete(existing.Metadata, authMaintenanceActionMetadataKey)
			delete(existing.Metadata, authMaintenanceMarkedAtMetadataKey)
		}
		delete(existing.Metadata, authMaintenanceReasonMetadataKey)
	}

	if _, err := s.coreManager.Update(ctx, existing); err != nil {
		log.Errorf("failed to disable auth %s: %v", id, err)
		return false
	}
	GlobalModelRegistry().UnregisterClient(id)
	if strings.EqualFold(strings.TrimSpace(existing.Provider), "codex") {
		executor.CloseCodexWebsocketSessionsForAuthID(existing.ID, "auth_removed")
		s.ensureExecutorsForAuth(existing)
	}
	return true
}

func (s *Service) applyRetryConfig(cfg *config.Config) {
	if s == nil || s.coreManager == nil || cfg == nil {
		return
	}
	maxInterval := time.Duration(cfg.MaxRetryInterval) * time.Second
	s.coreManager.SetRetryConfig(cfg.RequestRetry, maxInterval, cfg.MaxRetryCredentials)
}

func (s *Service) enqueueModelSync(authID string) bool {
	if s == nil {
		return false
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return false
	}
	s.modelSyncMu.Lock()
	if s.modelSyncQueue == nil || s.modelSyncCancel == nil {
		s.modelSyncMu.Unlock()
		return false
	}
	if s.modelSyncPending == nil {
		s.modelSyncPending = make(map[string]modelSyncTaskState)
	}
	if state, exists := s.modelSyncPending[authID]; exists {
		state.dirty = true
		s.modelSyncPending[authID] = state
		s.modelSyncMu.Unlock()
		return true
	}
	select {
	case s.modelSyncQueue <- authID:
		s.modelSyncPending[authID] = modelSyncTaskState{}
		s.modelSyncMu.Unlock()
		return true
	default:
		s.modelSyncPending[authID] = modelSyncTaskState{}
		s.modelSyncMu.Unlock()
		return false
	}
}

func (s *Service) finishModelSync(authID string) bool {
	if s == nil {
		return false
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return false
	}
	s.modelSyncMu.Lock()
	defer s.modelSyncMu.Unlock()
	state, exists := s.modelSyncPending[authID]
	if !exists {
		return false
	}
	if state.dirty {
		state.dirty = false
		s.modelSyncPending[authID] = state
		return true
	}
	delete(s.modelSyncPending, authID)
	return false
}

func (s *Service) syncAuthModels(ctx context.Context, authID string) {
	if s == nil || s.coreManager == nil {
		return
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, ok := s.coreManager.GetByID(authID)
	if !ok || current == nil {
		GlobalModelRegistry().UnregisterClient(authID)
		return
	}
	s.registerModelsForAuth(current)
	s.coreManager.ReconcileRegistryModelStates(ctx, current.ID)
	s.coreManager.RefreshSchedulerEntry(current.ID)
}

func (s *Service) syncAuthModelsInline(ctx context.Context, authID string) {
	if s == nil {
		return
	}
	for {
		s.syncAuthModels(ctx, authID)
		if !s.finishModelSync(authID) {
			return
		}
	}
}

func (s *Service) handleManagementAuthStatusChange(ctx context.Context, auth *coreauth.Auth) {
	if s == nil || auth == nil {
		return
	}
	if strings.TrimSpace(auth.ID) == "" || auth.Disabled || auth.Status == coreauth.StatusDisabled {
		return
	}
	authDir := ""
	if cfg := s.currentConfig(); cfg != nil {
		authDir = strings.TrimSpace(cfg.AuthDir)
	}
	if candidate, ok := s.authMaintenanceCandidateForAuth(auth, authDir, ""); ok {
		s.cancelAuthMaintenanceCandidate(candidate)
	}
	s.ensureExecutorsForAuth(auth)
	s.syncAuthModels(ctx, auth.ID)
}

func (s *Service) startModelSyncLoop(parent context.Context) {
	if s == nil {
		return
	}
	s.modelSyncMu.Lock()
	if s.modelSyncCancel != nil {
		s.modelSyncMu.Unlock()
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	queue := make(chan string, defaultModelSyncQueueSize)
	done := make(chan struct{})
	s.modelSyncCancel = cancel
	s.modelSyncDone = done
	s.modelSyncQueue = queue
	s.modelSyncPending = make(map[string]modelSyncTaskState)
	s.modelSyncMu.Unlock()

	go func() {
		defer close(done)
		var workers sync.WaitGroup
		for i := 0; i < defaultModelSyncWorkers; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case authID := <-queue:
						s.syncAuthModels(ctx, authID)
						if s.finishModelSync(authID) {
							select {
							case <-ctx.Done():
							case queue <- authID:
							}
						}
					}
				}
			}()
		}
		workers.Wait()
	}()
}

func (s *Service) stopModelSyncLoop() {
	if s == nil {
		return
	}
	s.modelSyncMu.Lock()
	cancel := s.modelSyncCancel
	done := s.modelSyncDone
	s.modelSyncCancel = nil
	s.modelSyncDone = nil
	s.modelSyncQueue = nil
	s.modelSyncPending = nil
	s.modelSyncMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func openAICompatInfoFromAuth(a *coreauth.Auth) (providerKey string, compatName string, ok bool) {
	if a == nil {
		return "", "", false
	}
	if len(a.Attributes) > 0 {
		providerKey = strings.TrimSpace(a.Attributes["provider_key"])
		compatName = strings.TrimSpace(a.Attributes["compat_name"])
		if compatName != "" {
			if providerKey == "" {
				providerKey = compatName
			}
			return strings.ToLower(providerKey), compatName, true
		}
	}
	if strings.EqualFold(strings.TrimSpace(a.Provider), "openai-compatibility") {
		return "openai-compatibility", strings.TrimSpace(a.Label), true
	}
	return "", "", false
}

func (s *Service) ensureExecutorsForAuth(a *coreauth.Auth) {
	s.ensureExecutorsForAuthWithMode(a, false)
}

func (s *Service) ensureExecutorsForAuthWithMode(a *coreauth.Auth, forceReplace bool) {
	if s == nil || s.coreManager == nil || a == nil {
		return
	}
	if strings.EqualFold(strings.TrimSpace(a.Provider), "codex") {
		if !forceReplace {
			existingExecutor, hasExecutor := s.coreManager.Executor("codex")
			if hasExecutor {
				_, isCodexAutoExecutor := existingExecutor.(*executor.CodexAutoExecutor)
				if isCodexAutoExecutor {
					return
				}
			}
		}
		s.coreManager.RegisterExecutor(executor.NewCodexAutoExecutor(s.cfg))
		return
	}
	// Skip disabled auth entries when (re)binding executors.
	// Disabled auths can linger during config reloads (e.g., removed OpenAI-compat entries)
	// and must not override active provider executors.
	if a.Disabled {
		return
	}
	if compatProviderKey, _, isCompat := openAICompatInfoFromAuth(a); isCompat {
		if compatProviderKey == "" {
			compatProviderKey = strings.ToLower(strings.TrimSpace(a.Provider))
		}
		if compatProviderKey == "" {
			compatProviderKey = "openai-compatibility"
		}
		s.coreManager.RegisterExecutor(executor.NewOpenAICompatExecutor(compatProviderKey, s.cfg))
		return
	}
	switch strings.ToLower(a.Provider) {
	case "gemini":
		s.coreManager.RegisterExecutor(executor.NewGeminiExecutor(s.cfg))
	case "vertex":
		s.coreManager.RegisterExecutor(executor.NewGeminiVertexExecutor(s.cfg))
	case "gemini-cli":
		s.coreManager.RegisterExecutor(executor.NewGeminiCLIExecutor(s.cfg))
	case "aistudio":
		if s.wsGateway != nil {
			s.coreManager.RegisterExecutor(executor.NewAIStudioExecutor(s.cfg, a.ID, s.wsGateway))
		}
		return
	case "antigravity":
		s.coreManager.RegisterExecutor(executor.NewAntigravityExecutor(s.cfg))
	case "claude":
		s.coreManager.RegisterExecutor(executor.NewClaudeExecutor(s.cfg))
	case "kimi":
		s.coreManager.RegisterExecutor(executor.NewKimiExecutor(s.cfg))
	default:
		providerKey := strings.ToLower(strings.TrimSpace(a.Provider))
		if providerKey == "" {
			providerKey = "openai-compatibility"
		}
		s.coreManager.RegisterExecutor(executor.NewOpenAICompatExecutor(providerKey, s.cfg))
	}
}

func (s *Service) registerResolvedModelsForAuth(a *coreauth.Auth, providerKey string, models []*ModelInfo) {
	if a == nil || a.ID == "" {
		return
	}
	if len(models) == 0 {
		GlobalModelRegistry().UnregisterClient(a.ID)
		return
	}
	GlobalModelRegistry().RegisterClient(a.ID, providerKey, models)
}

// rebindExecutors refreshes provider executors so they observe the latest configuration.
func (s *Service) rebindExecutors() {
	if s == nil || s.coreManager == nil {
		return
	}
	auths := s.coreManager.List()
	reboundCodex := false
	for _, auth := range auths {
		if auth != nil && strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
			if reboundCodex {
				continue
			}
			reboundCodex = true
		}
		s.ensureExecutorsForAuthWithMode(auth, true)
	}
}

// Run starts the service and blocks until the context is cancelled or the server stops.
// It initializes all components including authentication, file watching, HTTP server,
// and starts processing requests. The method blocks until the context is cancelled.
//
// Parameters:
//   - ctx: The context for controlling the service lifecycle
//
// Returns:
//   - error: An error if the service fails to start or run
func (s *Service) Run(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("cliproxy: service is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	sdkusage.StartDefault(ctx)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	defer func() {
		if err := s.Shutdown(shutdownCtx); err != nil {
			log.Errorf("service shutdown returned error: %v", err)
		}
	}()

	if err := s.ensureAuthDir(); err != nil {
		return err
	}

	s.applyRetryConfig(s.cfg)

	if s.coreManager != nil {
		if errLoad := s.coreManager.Load(ctx); errLoad != nil {
			log.Warnf("failed to load auth store: %v", errLoad)
		}
	}
	s.restoreUsageStatistics()
	if s.reconcileUsageStatistics("startup") > 0 {
		s.persistUsageStatistics("startup-reconcile")
	}

	tokenResult, err := s.tokenProvider.Load(ctx, s.cfg)
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	if tokenResult == nil {
		tokenResult = &TokenClientResult{}
	}
	_ = tokenResult

	apiKeyResult, err := s.apiKeyProvider.Load(ctx, s.cfg)
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	if apiKeyResult == nil {
		apiKeyResult = &APIKeyClientResult{}
	}
	_ = apiKeyResult

	// legacy clients removed; no caches to refresh

	// handlers no longer depend on legacy clients; pass nil slice initially
	serverOpts := append([]api.ServerOption(nil), s.serverOptions...)
	serverOpts = append(serverOpts, api.WithAuthStatusHook(s.handleManagementAuthStatusChange))
	s.server = api.NewServer(s.cfg, s.coreManager, s.accessManager, s.configPath, serverOpts...)

	if s.authManager == nil {
		s.authManager = newDefaultAuthManager()
	}
	s.startModelSyncLoop(ctx)
	s.installAuthMaintenanceHook()
	if cfg, _ := s.snapshotAuthMaintenanceConfig(); cfg.Enable {
		s.warnAuthMaintenanceConfig(cfg)
	}

	s.ensureWebsocketGateway()
	if s.server != nil && s.wsGateway != nil {
		s.server.AttachWebsocketRoute(s.wsGateway.Path(), s.wsGateway.Handler())
		s.server.SetWebsocketAuthChangeHandler(func(oldEnabled, newEnabled bool) {
			if oldEnabled == newEnabled {
				return
			}
			if !oldEnabled && newEnabled {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if errStop := s.wsGateway.Stop(ctx); errStop != nil {
					log.Warnf("failed to reset websocket connections after ws-auth change %t -> %t: %v", oldEnabled, newEnabled, errStop)
					return
				}
				log.Debugf("ws-auth enabled; existing websocket sessions terminated to enforce authentication")
				return
			}
			log.Debugf("ws-auth disabled; existing websocket sessions remain connected")
		})
	}

	if s.hooks.OnBeforeStart != nil {
		s.hooks.OnBeforeStart(s.cfg)
	}

	// Register callback for startup and periodic model catalog refresh.
	// When remote model definitions change, re-register models for affected providers.
	// This intentionally rebuilds per-auth model availability from the latest catalog
	// snapshot instead of preserving prior registry suppression state.
	registry.SetModelRefreshCallback(func(changedProviders []string) {
		if s == nil || s.coreManager == nil || len(changedProviders) == 0 {
			return
		}

		providerSet := make(map[string]bool, len(changedProviders))
		for _, p := range changedProviders {
			providerSet[strings.ToLower(strings.TrimSpace(p))] = true
		}

		auths := s.coreManager.List()
		refreshed := 0
		for _, item := range auths {
			if item == nil || item.ID == "" {
				continue
			}
			auth, ok := s.coreManager.GetByID(item.ID)
			if !ok || auth == nil || auth.Disabled {
				continue
			}
			provider := strings.ToLower(strings.TrimSpace(auth.Provider))
			if !providerSet[provider] {
				continue
			}
			if s.refreshModelRegistrationForAuth(auth) {
				refreshed++
			}
		}

		if refreshed > 0 {
			log.Infof("re-registered models for %d auth(s) due to model catalog changes: %v", refreshed, changedProviders)
		}
	})

	s.serverErr = make(chan error, 1)
	go func() {
		if errStart := s.server.Start(); errStart != nil {
			s.serverErr <- errStart
		} else {
			s.serverErr <- nil
		}
	}()

	time.Sleep(100 * time.Millisecond)
	fmt.Printf("API server started successfully on: %s:%d\n", s.cfg.Host, s.cfg.Port)

	s.applyPprofConfig(s.cfg)

	if s.hooks.OnAfterStart != nil {
		s.hooks.OnAfterStart(s)
	}

	var watcherWrapper *WatcherWrapper
	reloadCallback := func(newCfg *config.Config) {
		previousStrategy := ""
		previousUsageEnabled := false
		previousUsageInterval := time.Duration(0)
		var previousSessionAffinity bool
		var previousSessionAffinityTTL string
		var previousCfgSnapshot *config.Config
		s.cfgMu.RLock()
		if s.cfg != nil {
			previousStrategy = strings.ToLower(strings.TrimSpace(s.cfg.Routing.Strategy))
			previousUsageEnabled = s.cfg.UsageStatisticsEnabled
			previousUsageInterval = usagePersistenceIntervalForConfig(s.cfg)
			previousSessionAffinity = s.cfg.Routing.ClaudeCodeSessionAffinity || s.cfg.Routing.SessionAffinity
			previousSessionAffinityTTL = s.cfg.Routing.SessionAffinityTTL
			previousCfgSnapshot = s.cfg
		}
		s.cfgMu.RUnlock()

		if newCfg == nil {
			s.cfgMu.RLock()
			newCfg = s.cfg
			s.cfgMu.RUnlock()
		}
		if newCfg == nil {
			return
		}

		nextStrategy := strings.ToLower(strings.TrimSpace(newCfg.Routing.Strategy))
		normalizeStrategy := func(strategy string) string {
			switch strategy {
			case "fill-first", "fillfirst", "ff":
				return "fill-first"
			case "random", "rand", "r":
				return "random"
			default:
				return "round-robin"
			}
		}
		previousStrategy = normalizeStrategy(previousStrategy)
		nextStrategy = normalizeStrategy(nextStrategy)

		nextSessionAffinity := newCfg.Routing.ClaudeCodeSessionAffinity || newCfg.Routing.SessionAffinity
		nextSessionAffinityTTL := newCfg.Routing.SessionAffinityTTL

		selectorChanged := previousStrategy != nextStrategy ||
			previousSessionAffinity != nextSessionAffinity ||
			previousSessionAffinityTTL != nextSessionAffinityTTL

		if s.coreManager != nil && selectorChanged {
			var selector coreauth.Selector
			switch nextStrategy {
			case "fill-first":
				selector = &coreauth.FillFirstSelector{}
			case "random":
				selector = &coreauth.RandomSelector{}
			default:
				selector = &coreauth.RoundRobinSelector{}
			}

			if nextSessionAffinity {
				ttl := time.Hour
				if ttlStr := strings.TrimSpace(nextSessionAffinityTTL); ttlStr != "" {
					if parsed, err := time.ParseDuration(ttlStr); err == nil && parsed > 0 {
						ttl = parsed
					}
				}
				selector = coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{
					Fallback: selector,
					TTL:      ttl,
				})
			}

			s.coreManager.SetSelector(selector)
		}

		s.applyRetryConfig(newCfg)
		s.applyPprofConfig(newCfg)
		if s.server != nil {
			s.server.UpdateClients(newCfg)
		}
		s.cfgMu.Lock()
		s.cfg = newCfg
		s.cfgMu.Unlock()
		if s.coreManager != nil {
			s.coreManager.SetConfig(newCfg)
			s.coreManager.SetOAuthModelAlias(newCfg.OAuthModelAlias)
		}
		s.rebindExecutors()
		if s.coreManager != nil && shouldRefreshCodexImageRegistrations(previousCfgSnapshot, newCfg) {
			for _, auth := range s.coreManager.List() {
				if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
					continue
				}
				s.refreshModelRegistrationForAuth(auth)
			}
		}
		s.applyUsagePersistenceConfigChange(previousUsageEnabled, previousUsageInterval, newCfg)
		s.warnAuthMaintenanceConfig(newCfg.AuthMaintenance)
		s.wakeAuthMaintenance()
	}

	watcherWrapper, err = s.watcherFactory(s.configPath, s.cfg.AuthDir, reloadCallback)
	if err != nil {
		return fmt.Errorf("cliproxy: failed to create watcher: %w", err)
	}
	s.watcher = watcherWrapper
	s.ensureAuthUpdateQueue(ctx)
	if s.authUpdates != nil {
		watcherWrapper.SetAuthUpdateQueue(s.authUpdates)
	}
	watcherWrapper.SetConfig(s.cfg)

	watcherCtx, watcherCancel := context.WithCancel(context.Background())
	s.watcherCancel = watcherCancel
	if err = watcherWrapper.Start(watcherCtx); err != nil {
		return fmt.Errorf("cliproxy: failed to start watcher: %w", err)
	}
	log.Info("file watcher started for config and auth directory changes")
	s.startUsagePersistenceLoop()
	s.startAuthMaintenance(context.Background())

	// Prefer core auth manager auto refresh if available.
	if s.coreManager != nil {
		interval := 15 * time.Minute
		s.coreManager.StartAutoRefresh(context.Background(), interval)
		log.Infof("core auth auto-refresh started (interval=%s)", interval)
	}

	select {
	case <-ctx.Done():
		log.Debug("service context cancelled, shutting down...")
		return ctx.Err()
	case err = <-s.serverErr:
		return err
	}
}

// Shutdown gracefully stops background workers and the HTTP server.
// It ensures all resources are properly cleaned up and connections are closed.
// The shutdown is idempotent and can be called multiple times safely.
//
// Parameters:
//   - ctx: The context for controlling the shutdown timeout
//
// Returns:
//   - error: An error if shutdown fails
func (s *Service) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	var shutdownErr error
	s.shutdownOnce.Do(func() {
		if ctx == nil {
			ctx = context.Background()
		}

		// legacy refresh loop removed; only stopping core auth manager below

		if s.watcherCancel != nil {
			s.watcherCancel()
		}
		if s.coreManager != nil {
			s.coreManager.StopAutoRefresh()
		}
		if s.watcher != nil {
			if err := s.watcher.Stop(); err != nil {
				log.Errorf("failed to stop file watcher: %v", err)
				shutdownErr = err
			}
		}
		if s.wsGateway != nil {
			if err := s.wsGateway.Stop(ctx); err != nil {
				log.Errorf("failed to stop websocket gateway: %v", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			}
		}
		if s.authQueueStop != nil {
			s.authQueueStop()
			s.authQueueStop = nil
		}
		s.stopModelSyncLoop()
		s.stopAuthMaintenance()
		s.reconcileUsageStatistics("shutdown")
		s.persistUsageStatistics("shutdown")
		s.stopUsagePersistenceLoop()

		if errShutdownPprof := s.shutdownPprof(ctx); errShutdownPprof != nil {
			log.Errorf("failed to stop pprof server: %v", errShutdownPprof)
			if shutdownErr == nil {
				shutdownErr = errShutdownPprof
			}
		}

		// no legacy clients to persist

		if s.server != nil {
			shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := s.server.Stop(shutdownCtx); err != nil {
				log.Errorf("error stopping API server: %v", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			}
		}

		sdkusage.StopDefault()
	})
	return shutdownErr
}

func (s *Service) ensureAuthDir() error {
	info, err := os.Stat(s.cfg.AuthDir)
	if err != nil {
		if os.IsNotExist(err) {
			if mkErr := os.MkdirAll(s.cfg.AuthDir, 0o755); mkErr != nil {
				return fmt.Errorf("cliproxy: failed to create auth directory %s: %w", s.cfg.AuthDir, mkErr)
			}
			log.Infof("created missing auth directory: %s", s.cfg.AuthDir)
			return nil
		}
		return fmt.Errorf("cliproxy: error checking auth directory %s: %w", s.cfg.AuthDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cliproxy: auth path exists but is not a directory: %s", s.cfg.AuthDir)
	}
	return nil
}

// registerModelsForAuth (re)binds provider models in the global registry using the core auth ID as client identifier.
func (s *Service) registerModelsForAuth(a *coreauth.Auth) {
	if a == nil || a.ID == "" {
		return
	}
	if a.Disabled {
		GlobalModelRegistry().UnregisterClient(a.ID)
		return
	}
	authKind := strings.ToLower(strings.TrimSpace(a.Attributes["auth_kind"]))
	if authKind == "" {
		if kind, _ := a.AccountInfo(); strings.EqualFold(kind, "api_key") {
			authKind = "apikey"
		}
	}
	if a.Attributes != nil {
		if v := strings.TrimSpace(a.Attributes["gemini_virtual_primary"]); strings.EqualFold(v, "true") {
			GlobalModelRegistry().UnregisterClient(a.ID)
			return
		}
	}
	// Unregister legacy client ID (if present) to avoid double counting
	if a.Runtime != nil {
		if idGetter, ok := a.Runtime.(interface{ GetClientID() string }); ok {
			if rid := idGetter.GetClientID(); rid != "" && rid != a.ID {
				GlobalModelRegistry().UnregisterClient(rid)
			}
		}
	}
	provider := strings.ToLower(strings.TrimSpace(a.Provider))
	compatProviderKey, compatDisplayName, compatDetected := openAICompatInfoFromAuth(a)
	if compatDetected {
		provider = "openai-compatibility"
	}
	excluded := s.oauthExcludedModels(provider, authKind)
	// The synthesizer pre-merges per-account and global exclusions into the "excluded_models" attribute.
	// If this attribute is present, it represents the complete list of exclusions and overrides the global config.
	if a.Attributes != nil {
		if val, ok := a.Attributes["excluded_models"]; ok && strings.TrimSpace(val) != "" {
			excluded = strings.Split(val, ",")
		}
	}
	var models []*ModelInfo
	switch provider {
	case "gemini":
		models = registry.GetGeminiModels()
		if entry := s.resolveConfigGeminiKey(a); entry != nil {
			if len(entry.Models) > 0 {
				models = buildGeminiConfigModels(entry)
			}
			if authKind == "apikey" {
				excluded = entry.ExcludedModels
			}
		}
		models = applyExcludedModels(models, excluded)
	case "vertex":
		// Vertex AI Gemini supports the same model identifiers as Gemini.
		models = registry.GetGeminiVertexModels()
		if entry := s.resolveConfigVertexCompatKey(a); entry != nil {
			if len(entry.Models) > 0 {
				models = buildVertexCompatConfigModels(entry)
			}
			if authKind == "apikey" {
				excluded = entry.ExcludedModels
			}
		}
		models = applyExcludedModels(models, excluded)
	case "gemini-cli":
		models = registry.GetGeminiCLIModels()
		models = applyExcludedModels(models, excluded)
	case "aistudio":
		models = registry.GetAIStudioModels()
		models = applyExcludedModels(models, excluded)
	case "antigravity":
		models = registry.GetAntigravityModels()
		models = applyExcludedModels(models, excluded)
	case "claude":
		models = registry.GetClaudeModels()
		if entry := s.resolveConfigClaudeKey(a); entry != nil {
			if len(entry.Models) > 0 {
				models = buildClaudeConfigModels(entry)
			}
			if authKind == "apikey" {
				excluded = entry.ExcludedModels
			}
		}
		models = applyExcludedModels(models, excluded)
	case "codex":
		codexPlanType := codexPlanTypeForRegistration(a)
		models = codexModelsForPlan(codexPlanType)
		if entry := s.resolveConfigCodexKey(a); entry != nil {
			if len(entry.Models) > 0 {
				models = buildCodexConfigModels(entry)
			}
			if authKind == "apikey" {
				excluded = entry.ExcludedModels
			}
		}
		allowImageModel := codexPlanAllowsImageModel(codexPlanType)
		if strings.EqualFold(codexPlanType, "free") && freePlanImageModelEnabled(s.cfg) {
			allowImageModel = true
		}
		if allowImageModel {
			models = upsertModelInfo(models, codexDynamicImageModelInfo(s.cfg))
		}
		models = applyExcludedModels(models, excluded)
	case "kimi":
		models = registry.GetKimiModels()
		models = applyExcludedModels(models, excluded)
	default:
		// Handle OpenAI-compatibility providers by name using config
		if s.cfg != nil {
			providerKey := provider
			compatName := strings.TrimSpace(a.Provider)
			isCompatAuth := false
			if compatDetected {
				if compatProviderKey != "" {
					providerKey = compatProviderKey
				}
				if compatDisplayName != "" {
					compatName = compatDisplayName
				}
				isCompatAuth = true
			}
			if strings.EqualFold(providerKey, "openai-compatibility") {
				isCompatAuth = true
				if a.Attributes != nil {
					if v := strings.TrimSpace(a.Attributes["compat_name"]); v != "" {
						compatName = v
					}
					if v := strings.TrimSpace(a.Attributes["provider_key"]); v != "" {
						providerKey = strings.ToLower(v)
						isCompatAuth = true
					}
				}
				if providerKey == "openai-compatibility" && compatName != "" {
					providerKey = strings.ToLower(compatName)
				}
			} else if a.Attributes != nil {
				if v := strings.TrimSpace(a.Attributes["compat_name"]); v != "" {
					compatName = v
					isCompatAuth = true
				}
				if v := strings.TrimSpace(a.Attributes["provider_key"]); v != "" {
					providerKey = strings.ToLower(v)
					isCompatAuth = true
				}
			}
			for i := range s.cfg.OpenAICompatibility {
				compat := &s.cfg.OpenAICompatibility[i]
				if strings.EqualFold(compat.Name, compatName) {
					isCompatAuth = true
					// Convert compatibility models to registry models
					ms := make([]*ModelInfo, 0, len(compat.Models))
					for j := range compat.Models {
						m := compat.Models[j]
						// Use alias as model ID, fallback to name if alias is empty
						modelID := m.Alias
						if modelID == "" {
							modelID = m.Name
						}
						thinking := m.Thinking
						if thinking == nil {
							thinking = &registry.ThinkingSupport{Levels: []string{"low", "medium", "high"}}
						}
						ms = append(ms, &ModelInfo{
							ID:          modelID,
							Object:      "model",
							Created:     time.Now().Unix(),
							OwnedBy:     compat.Name,
							Type:        "openai-compatibility",
							DisplayName: modelID,
							UserDefined: false,
							Thinking:    thinking,
						})
					}
					// Register and return
					if len(ms) > 0 {
						if providerKey == "" {
							providerKey = "openai-compatibility"
						}
						s.registerResolvedModelsForAuth(a, providerKey, applyModelPrefixes(ms, a.Prefix, s.cfg.ForceModelPrefix))
					} else {
						// Ensure stale registrations are cleared when model list becomes empty.
						GlobalModelRegistry().UnregisterClient(a.ID)
					}
					return
				}
			}
			if isCompatAuth {
				// No matching provider found or models removed entirely; drop any prior registration.
				GlobalModelRegistry().UnregisterClient(a.ID)
				return
			}
		}
	}
	models = applyOAuthModelAlias(s.cfg, provider, authKind, models)
	if len(models) > 0 {
		key := provider
		if key == "" {
			key = strings.ToLower(strings.TrimSpace(a.Provider))
		}
		s.registerResolvedModelsForAuth(a, key, applyModelPrefixes(models, a.Prefix, s.cfg != nil && s.cfg.ForceModelPrefix))
		return
	}

	GlobalModelRegistry().UnregisterClient(a.ID)
}

// refreshModelRegistrationForAuth re-applies the latest model registration for
// one auth and reconciles any concurrent auth changes that race with the
// refresh. Callers are expected to pre-filter provider membership.
//
// Re-registration is deliberate: registry cooldown/suspension state is treated
// as part of the previous registration snapshot and is cleared when the auth is
// rebound to the refreshed model catalog.
func (s *Service) refreshModelRegistrationForAuth(current *coreauth.Auth) bool {
	if s == nil || s.coreManager == nil || current == nil || current.ID == "" {
		return false
	}

	if !current.Disabled {
		s.ensureExecutorsForAuth(current)
	}
	s.registerModelsForAuth(current)
	s.coreManager.ReconcileRegistryModelStates(context.Background(), current.ID)

	latest, ok := s.latestAuthForModelRegistration(current.ID)
	if !ok || latest.Disabled {
		GlobalModelRegistry().UnregisterClient(current.ID)
		s.coreManager.RefreshSchedulerEntry(current.ID)
		return false
	}

	// Re-apply the latest auth snapshot so concurrent auth updates cannot leave
	// stale model registrations behind. This may duplicate registration work when
	// no auth fields changed, but keeps the refresh path simple and correct.
	s.ensureExecutorsForAuth(latest)
	s.registerModelsForAuth(latest)
	s.coreManager.ReconcileRegistryModelStates(context.Background(), latest.ID)
	s.coreManager.RefreshSchedulerEntry(current.ID)
	return true
}

// latestAuthForModelRegistration returns the latest auth snapshot regardless of
// provider membership. Callers use this after a registration attempt to restore
// whichever state currently owns the client ID in the global registry.
func (s *Service) latestAuthForModelRegistration(authID string) (*coreauth.Auth, bool) {
	if s == nil || s.coreManager == nil || authID == "" {
		return nil, false
	}
	auth, ok := s.coreManager.GetByID(authID)
	if !ok || auth == nil || auth.ID == "" {
		return nil, false
	}
	return auth, true
}

func (s *Service) resolveConfigClaudeKey(auth *coreauth.Auth) *config.ClaudeKey {
	if auth == nil || s.cfg == nil {
		return nil
	}
	var attrKey, attrBase string
	if auth.Attributes != nil {
		attrKey = strings.TrimSpace(auth.Attributes["api_key"])
		attrBase = strings.TrimSpace(auth.Attributes["base_url"])
	}
	for i := range s.cfg.ClaudeKey {
		entry := &s.cfg.ClaudeKey[i]
		cfgKey := strings.TrimSpace(entry.APIKey)
		cfgBase := strings.TrimSpace(entry.BaseURL)
		if attrKey != "" && attrBase != "" {
			if strings.EqualFold(cfgKey, attrKey) && strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
			continue
		}
		if attrKey != "" && strings.EqualFold(cfgKey, attrKey) {
			if cfgBase == "" || strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
		}
		if attrKey == "" && attrBase != "" && strings.EqualFold(cfgBase, attrBase) {
			return entry
		}
	}
	if attrKey != "" {
		for i := range s.cfg.ClaudeKey {
			entry := &s.cfg.ClaudeKey[i]
			if strings.EqualFold(strings.TrimSpace(entry.APIKey), attrKey) {
				return entry
			}
		}
	}
	return nil
}

func (s *Service) resolveConfigGeminiKey(auth *coreauth.Auth) *config.GeminiKey {
	if auth == nil || s.cfg == nil {
		return nil
	}
	var attrKey, attrBase string
	if auth.Attributes != nil {
		attrKey = strings.TrimSpace(auth.Attributes["api_key"])
		attrBase = strings.TrimSpace(auth.Attributes["base_url"])
	}
	for i := range s.cfg.GeminiKey {
		entry := &s.cfg.GeminiKey[i]
		cfgKey := strings.TrimSpace(entry.APIKey)
		cfgBase := strings.TrimSpace(entry.BaseURL)
		if attrKey != "" && strings.EqualFold(cfgKey, attrKey) {
			if cfgBase == "" || strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
			continue
		}
		if attrKey == "" && attrBase != "" && strings.EqualFold(cfgBase, attrBase) {
			return entry
		}
	}
	return nil
}

func (s *Service) resolveConfigVertexCompatKey(auth *coreauth.Auth) *config.VertexCompatKey {
	if auth == nil || s.cfg == nil {
		return nil
	}
	var attrKey, attrBase string
	if auth.Attributes != nil {
		attrKey = strings.TrimSpace(auth.Attributes["api_key"])
		attrBase = strings.TrimSpace(auth.Attributes["base_url"])
	}
	for i := range s.cfg.VertexCompatAPIKey {
		entry := &s.cfg.VertexCompatAPIKey[i]
		cfgKey := strings.TrimSpace(entry.APIKey)
		cfgBase := strings.TrimSpace(entry.BaseURL)
		if attrKey != "" && strings.EqualFold(cfgKey, attrKey) {
			if cfgBase == "" || strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
			continue
		}
		if attrKey == "" && attrBase != "" && strings.EqualFold(cfgBase, attrBase) {
			return entry
		}
	}
	if attrKey != "" {
		for i := range s.cfg.VertexCompatAPIKey {
			entry := &s.cfg.VertexCompatAPIKey[i]
			if strings.EqualFold(strings.TrimSpace(entry.APIKey), attrKey) {
				return entry
			}
		}
	}
	return nil
}

func (s *Service) resolveConfigCodexKey(auth *coreauth.Auth) *config.CodexKey {
	if auth == nil || s.cfg == nil {
		return nil
	}
	var attrKey, attrBase string
	if auth.Attributes != nil {
		attrKey = strings.TrimSpace(auth.Attributes["api_key"])
		attrBase = strings.TrimSpace(auth.Attributes["base_url"])
	}
	for i := range s.cfg.CodexKey {
		entry := &s.cfg.CodexKey[i]
		cfgKey := strings.TrimSpace(entry.APIKey)
		cfgBase := strings.TrimSpace(entry.BaseURL)
		if attrKey != "" && strings.EqualFold(cfgKey, attrKey) {
			if cfgBase == "" || strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
			continue
		}
		if attrKey == "" && attrBase != "" && strings.EqualFold(cfgBase, attrBase) {
			return entry
		}
	}
	return nil
}

func (s *Service) oauthExcludedModels(provider, authKind string) []string {
	cfg := s.cfg
	if cfg == nil {
		return nil
	}
	authKindKey := strings.ToLower(strings.TrimSpace(authKind))
	providerKey := strings.ToLower(strings.TrimSpace(provider))
	if authKindKey == "apikey" {
		return nil
	}
	return cfg.OAuthExcludedModels[providerKey]
}

func codexPlanTypeForRegistration(auth *coreauth.Auth) string {
	planType := ""
	if auth != nil && auth.Attributes != nil {
		planType = strings.ToLower(strings.TrimSpace(auth.Attributes["plan_type"]))
	}
	if planType == "" && auth != nil {
		planType = strings.ToLower(strings.TrimSpace(internalcodex.EffectivePlanType(auth.Metadata)))
	}
	switch planType {
	case "plus", "free", "team", "business", "go":
		return planType
	case "pro":
		return "pro"
	default:
		return "pro"
	}
}

func codexModelsForPlan(planType string) []*ModelInfo {
	switch strings.ToLower(strings.TrimSpace(planType)) {
	case "plus":
		return registry.GetCodexPlusModels()
	case "free":
		return registry.GetCodexFreeModels()
	case "team", "business", "go":
		return registry.GetCodexTeamModels()
	default:
		return registry.GetCodexProModels()
	}
}

func codexPlanAllowsImageModel(planType string) bool {
	switch strings.ToLower(strings.TrimSpace(planType)) {
	case "plus", "pro", "team", "business", "go":
		return true
	case "free":
		return false
	default:
		return false
	}
}

func configuredImagesImageModel(cfg *config.Config) string {
	if cfg == nil {
		return "gpt-image-2"
	}
	modelID := strings.TrimSpace(cfg.Images.ImageModel)
	if modelID == "" {
		return "gpt-image-2"
	}
	return modelID
}

func shouldRefreshCodexImageRegistrations(previousCfg, nextCfg *config.Config) bool {
	if configuredImagesImageModel(previousCfg) != configuredImagesImageModel(nextCfg) {
		return true
	}
	return freePlanImageModelEnabled(previousCfg) != freePlanImageModelEnabled(nextCfg)
}

func freePlanImageModelEnabled(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	return cfg.Images.EnableFreePlanImageModel
}

func codexDynamicImageModelInfo(cfg *config.Config) *ModelInfo {
	modelID := configuredImagesImageModel(cfg)
	if modelID == "" {
		return nil
	}
	return &ModelInfo{
		ID:          modelID,
		Object:      "model",
		Created:     1704067200, // 2024-01-01
		OwnedBy:     "openai",
		Type:        "openai",
		DisplayName: modelID,
		Version:     modelID,
	}
}

func upsertModelInfo(models []*ModelInfo, extra *ModelInfo) []*ModelInfo {
	if extra == nil {
		return models
	}
	extraID := strings.TrimSpace(extra.ID)
	if extraID == "" {
		return models
	}
	out := make([]*ModelInfo, 0, len(models)+1)
	for _, model := range models {
		if model == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(model.ID), extraID) {
			continue
		}
		out = append(out, model)
	}
	out = append(out, extra)
	return out
}

func applyExcludedModels(models []*ModelInfo, excluded []string) []*ModelInfo {
	if len(models) == 0 || len(excluded) == 0 {
		return models
	}

	patterns := make([]string, 0, len(excluded))
	for _, item := range excluded {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			patterns = append(patterns, strings.ToLower(trimmed))
		}
	}
	if len(patterns) == 0 {
		return models
	}

	filtered := make([]*ModelInfo, 0, len(models))
	for _, model := range models {
		if model == nil {
			continue
		}
		modelID := strings.ToLower(strings.TrimSpace(model.ID))
		blocked := false
		for _, pattern := range patterns {
			if matchWildcard(pattern, modelID) {
				blocked = true
				break
			}
		}
		if !blocked {
			filtered = append(filtered, model)
		}
	}
	return filtered
}

func applyModelPrefixes(models []*ModelInfo, prefix string, forceModelPrefix bool) []*ModelInfo {
	trimmedPrefix := strings.TrimSpace(prefix)
	if trimmedPrefix == "" || len(models) == 0 {
		return models
	}

	out := make([]*ModelInfo, 0, len(models)*2)
	seen := make(map[string]struct{}, len(models)*2)

	addModel := func(model *ModelInfo) {
		if model == nil {
			return
		}
		id := strings.TrimSpace(model.ID)
		if id == "" {
			return
		}
		if _, exists := seen[id]; exists {
			return
		}
		seen[id] = struct{}{}
		out = append(out, model)
	}

	for _, model := range models {
		if model == nil {
			continue
		}
		baseID := strings.TrimSpace(model.ID)
		if baseID == "" {
			continue
		}
		if !forceModelPrefix || trimmedPrefix == baseID {
			addModel(model)
		}
		clone := *model
		clone.ID = trimmedPrefix + "/" + baseID
		addModel(&clone)
	}
	return out
}

// matchWildcard performs case-insensitive wildcard matching where '*' matches any substring.
func matchWildcard(pattern, value string) bool {
	if pattern == "" {
		return false
	}

	// Fast path for exact match (no wildcard present).
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}

	parts := strings.Split(pattern, "*")
	// Handle prefix.
	if prefix := parts[0]; prefix != "" {
		if !strings.HasPrefix(value, prefix) {
			return false
		}
		value = value[len(prefix):]
	}

	// Handle suffix.
	if suffix := parts[len(parts)-1]; suffix != "" {
		if !strings.HasSuffix(value, suffix) {
			return false
		}
		value = value[:len(value)-len(suffix)]
	}

	// Handle middle segments in order.
	for i := 1; i < len(parts)-1; i++ {
		segment := parts[i]
		if segment == "" {
			continue
		}
		idx := strings.Index(value, segment)
		if idx < 0 {
			return false
		}
		value = value[idx+len(segment):]
	}

	return true
}

type modelEntry interface {
	GetName() string
	GetAlias() string
}

func buildConfigModels[T modelEntry](models []T, ownedBy, modelType string) []*ModelInfo {
	if len(models) == 0 {
		return nil
	}
	now := time.Now().Unix()
	out := make([]*ModelInfo, 0, len(models))
	seen := make(map[string]struct{}, len(models))
	for i := range models {
		model := models[i]
		name := strings.TrimSpace(model.GetName())
		alias := strings.TrimSpace(model.GetAlias())
		if alias == "" {
			alias = name
		}
		if alias == "" {
			continue
		}
		key := strings.ToLower(alias)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		display := name
		if display == "" {
			display = alias
		}
		info := &ModelInfo{
			ID:          alias,
			Object:      "model",
			Created:     now,
			OwnedBy:     ownedBy,
			Type:        modelType,
			DisplayName: display,
			UserDefined: true,
		}
		if name != "" {
			if upstream := registry.LookupStaticModelInfo(name); upstream != nil && upstream.Thinking != nil {
				info.Thinking = upstream.Thinking
			}
		}
		out = append(out, info)
	}
	return out
}

func buildVertexCompatConfigModels(entry *config.VertexCompatKey) []*ModelInfo {
	if entry == nil {
		return nil
	}
	return buildConfigModels(entry.Models, "google", "vertex")
}

func buildGeminiConfigModels(entry *config.GeminiKey) []*ModelInfo {
	if entry == nil {
		return nil
	}
	return buildConfigModels(entry.Models, "google", "gemini")
}

func buildClaudeConfigModels(entry *config.ClaudeKey) []*ModelInfo {
	if entry == nil {
		return nil
	}
	return buildConfigModels(entry.Models, "anthropic", "claude")
}

func buildCodexConfigModels(entry *config.CodexKey) []*ModelInfo {
	if entry == nil {
		return nil
	}
	return buildConfigModels(entry.Models, "openai", "openai")
}

func rewriteModelInfoName(name, oldID, newID string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return name
	}
	oldID = strings.TrimSpace(oldID)
	newID = strings.TrimSpace(newID)
	if oldID == "" || newID == "" {
		return name
	}
	if strings.EqualFold(oldID, newID) {
		return name
	}
	if strings.EqualFold(trimmed, oldID) {
		return newID
	}
	if strings.HasSuffix(trimmed, "/"+oldID) {
		prefix := strings.TrimSuffix(trimmed, oldID)
		return prefix + newID
	}
	if trimmed == "models/"+oldID {
		return "models/" + newID
	}
	return name
}

func applyOAuthModelAlias(cfg *config.Config, provider, authKind string, models []*ModelInfo) []*ModelInfo {
	if cfg == nil || len(models) == 0 {
		return models
	}
	channel := coreauth.OAuthModelAliasChannel(provider, authKind)
	if channel == "" || len(cfg.OAuthModelAlias) == 0 {
		return models
	}
	aliases := cfg.OAuthModelAlias[channel]
	if len(aliases) == 0 {
		return models
	}

	type aliasEntry struct {
		alias string
		fork  bool
	}

	forward := make(map[string][]aliasEntry, len(aliases))
	for i := range aliases {
		name := strings.TrimSpace(aliases[i].Name)
		alias := strings.TrimSpace(aliases[i].Alias)
		if name == "" || alias == "" {
			continue
		}
		if strings.EqualFold(name, alias) {
			continue
		}
		key := strings.ToLower(name)
		forward[key] = append(forward[key], aliasEntry{alias: alias, fork: aliases[i].Fork})
	}
	if len(forward) == 0 {
		return models
	}

	out := make([]*ModelInfo, 0, len(models))
	seen := make(map[string]struct{}, len(models))
	for _, model := range models {
		if model == nil {
			continue
		}
		id := strings.TrimSpace(model.ID)
		if id == "" {
			continue
		}
		key := strings.ToLower(id)
		entries := forward[key]
		if len(entries) == 0 {
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, model)
			continue
		}

		keepOriginal := false
		for _, entry := range entries {
			if entry.fork {
				keepOriginal = true
				break
			}
		}
		if keepOriginal {
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				out = append(out, model)
			}
		}

		addedAlias := false
		for _, entry := range entries {
			mappedID := strings.TrimSpace(entry.alias)
			if mappedID == "" {
				continue
			}
			if strings.EqualFold(mappedID, id) {
				continue
			}
			aliasKey := strings.ToLower(mappedID)
			if _, exists := seen[aliasKey]; exists {
				continue
			}
			seen[aliasKey] = struct{}{}
			clone := *model
			clone.ID = mappedID
			if clone.Name != "" {
				clone.Name = rewriteModelInfoName(clone.Name, id, mappedID)
			}
			out = append(out, &clone)
			addedAlias = true
		}

		if !keepOriginal && !addedAlias {
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, model)
		}
	}
	return out
}
