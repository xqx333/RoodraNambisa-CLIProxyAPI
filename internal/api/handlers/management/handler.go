// Package management provides the management API handlers and middleware
// for configuring the server and managing auth files.
package management

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/buildinfo"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/proxypool"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/sentinelservice"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/usage"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v6/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type attemptInfo struct {
	count        int
	blockedUntil time.Time
	lastActivity time.Time // track last activity for cleanup
}

type managementContextMutex struct {
	once      sync.Once
	semaphore chan struct{}
}

func (lock *managementContextMutex) lock(ctx context.Context) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	lock.once.Do(func() {
		lock.semaphore = make(chan struct{}, 1)
		lock.semaphore <- struct{}{}
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-lock.semaphore:
	}
	if errContext := ctx.Err(); errContext != nil {
		lock.semaphore <- struct{}{}
		return nil, errContext
	}
	var unlockOnce sync.Once
	return func() {
		unlockOnce.Do(func() { lock.semaphore <- struct{}{} })
	}, nil
}

// attemptCleanupInterval controls how often stale IP entries are purged
const attemptCleanupInterval = 1 * time.Hour

// attemptMaxIdleTime controls how long an IP can be idle before cleanup
const attemptMaxIdleTime = 2 * time.Hour

const managementResponseFieldsKey = "management_response_fields"

// Handler aggregates config reference, persistence path and helpers.
type Handler struct {
	sentinelSolver          *sentinelservice.Service
	sentinelOnly            bool
	cfg                     *config.Config
	configSnapshot          atomic.Pointer[config.Config]
	configFilePath          string
	mu                      sync.Mutex
	xaiPKCEMu               sync.Mutex
	xaiPKCE                 map[string]*xaiPKCEPending
	setConfigMu             sync.Mutex
	codexPlanRefreshMu      sync.Mutex
	codexPlanRefresh        codexPlanTypeRefreshTask
	attemptsMu              sync.Mutex
	failedAttempts          map[string]*attemptInfo // keyed by client IP
	authManager             *coreauth.Manager
	usageStats              *usage.RequestStatistics
	tokenStoreMu            sync.Mutex
	tokenStore              coreauth.Store
	localPassword           string
	allowRemoteOverride     bool
	envSecret               string
	logDir                  string
	postAuthHook            coreauth.PostAuthHook
	authStatusHook          coreauth.AuthStatusHook
	authDeleteHook          func(context.Context, []*coreauth.Auth)
	dependencyReconcileHook func(context.Context, string) ([]string, error)
	deadAuthDeleteCount     func() uint64
	usageRestoreStatus      func() usage.RestoreRuntimeSnapshot
	usagePruneTasks         *usagePruneTaskManager
	usagePruneRunner        usagePruneRunner
	proxyPoolManager        *proxypool.Manager
	runtimeConfigApplier    func(context.Context, *config.Config) (config.RuntimeApplyResult, error)
	chatGPTWebTasks         *chatGPTWebLoginTaskManager
	chatGPTWebMutationTasks *chatGPTWebMutationTaskManager
	libraryCleanupTasks     *libraryCleanupTaskManager
	agentIdentityTasks      *codexAgentIdentityTaskManager
	agentIdentityBaseURL    string
	configMutationMu        managementContextMutex
	chatGPTWebDependencyMu  managementContextMutex
	cleanupCancel           context.CancelFunc
	cleanupWG               sync.WaitGroup
	cleanupStopOnce         sync.Once
	authFilesPagination     authFilesPaginationCache
	usageAuthCatalog        usageAuthCatalogCache
	usageAuthPagination     usageAuthPaginationCache
}

// ConfigMutationMiddleware serializes management writes that replace runtime
// configuration. Operational mutations such as auth imports, deletes and
// refresh tasks intentionally remain outside this transaction.
func (h *Handler) ConfigMutationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h == nil || !isManagementConfigMutation(c.Request.Method, c.FullPath()) {
			c.Next()
			return
		}
		unlock, errLock := h.configMutationMu.lock(c.Request.Context())
		if errLock != nil {
			c.AbortWithStatusJSON(http.StatusRequestTimeout, gin.H{"error": "configuration update canceled"})
			return
		}
		defer unlock()
		c.Next()
	}
}

func isManagementConfigMutation(method, fullPath string) bool {
	const marker = "/v0/management"
	if index := strings.Index(fullPath, marker); index >= 0 {
		fullPath = fullPath[index+len(marker):]
	}
	switch method {
	case http.MethodPut, http.MethodPatch:
		switch fullPath {
		case "/auth-files/codex/plan-type-refresh", "/auth-files/status", "/auth-files/fields":
			return false
		default:
			return true
		}
	case http.MethodPost:
		return fullPath == "/proxy-pools"
	case http.MethodDelete:
		if fullPath == "/usage/prices" || strings.HasPrefix(fullPath, "/usage/prices/") {
			return true
		}
		switch fullPath {
		case "/proxy-url", "/api-keys", "/api-key-groups", "/gemini-api-key",
			"/interactions-api-key", "/claude-api-key", "/codex-api-key",
			"/openai-compatibility", "/vertex-api-key", "/oauth-excluded-models",
			"/oauth-model-alias":
			return true
		}
		return strings.HasPrefix(fullPath, "/proxy-pools/")
	default:
		return false
	}
}

// NewHandler creates a new management handler instance.
func NewHandler(cfg *config.Config, configFilePath string, manager *coreauth.Manager) *Handler {
	envSecret, _ := os.LookupEnv("MANAGEMENT_PASSWORD")
	envSecret = strings.TrimSpace(envSecret)

	mutationTasks := newChatGPTWebMutationTaskManager()
	if cfg != nil {
		mutationTasks.updateWorkerLimit(cfg.ChatGPTWeb.Import.Resolved().Workers)
	}
	loginTasks := newChatGPTWebLoginTaskManager()
	if errJournal := loginTasks.configureManualReloginJournal(
		chatGPTWebManualReloginJournalPath(configFilePath),
	); errJournal != nil {
		log.WithError(errJournal).Warn("failed to initialize manual ChatGPT Web re-login operation journal")
	}
	h := &Handler{
		cfg:                     cfg,
		configFilePath:          configFilePath,
		failedAttempts:          make(map[string]*attemptInfo),
		authManager:             manager,
		usageStats:              usage.GetRequestStatistics(),
		tokenStore:              sdkAuth.GetTokenStore(),
		allowRemoteOverride:     envSecret != "",
		envSecret:               envSecret,
		chatGPTWebTasks:         loginTasks,
		chatGPTWebMutationTasks: mutationTasks,
		agentIdentityTasks:      newCodexAgentIdentityTaskManager(),
		usagePruneTasks:         newUsagePruneTaskManager(),
	}
	if errSnapshot := h.publishConfigSnapshot(cfg); errSnapshot != nil {
		log.WithError(errSnapshot).Error("failed to initialize management configuration snapshot")
	}
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	h.cleanupCancel = cleanupCancel
	h.startAttemptCleanup(cleanupCtx)
	return h
}

// currentConfig returns the immutable configuration published for concurrent
// request readers. Callers must not mutate the returned value.
func (h *Handler) currentConfig() *config.Config {
	if h == nil {
		return nil
	}
	if snapshot := h.configSnapshot.Load(); snapshot != nil {
		return snapshot
	}
	// A few embedders construct Handler values directly. Lazily publish their
	// initial mutable configuration so those readers receive the same immutable
	// snapshot as handlers created through NewHandler.
	h.mu.Lock()
	defer h.mu.Unlock()
	if snapshot := h.configSnapshot.Load(); snapshot != nil {
		return snapshot
	}
	snapshot, errClone := config.Clone(h.cfg)
	if errClone != nil {
		log.WithError(errClone).Error("failed to create management configuration snapshot")
		return nil
	}
	h.configSnapshot.Store(snapshot)
	return snapshot
}

// publishConfigSnapshot clones the mutable management configuration before
// making it visible to concurrent request readers.
func (h *Handler) publishConfigSnapshot(cfg *config.Config) error {
	if h == nil {
		return nil
	}
	snapshot, errClone := config.Clone(cfg)
	if errClone != nil {
		return errClone
	}
	h.configSnapshot.Store(snapshot)
	return nil
}

// startAttemptCleanup launches a background goroutine that periodically
// removes stale IP entries from failedAttempts to prevent memory leaks.
func (h *Handler) startAttemptCleanup(ctx context.Context) {
	h.cleanupWG.Add(1)
	go func() {
		defer h.cleanupWG.Done()
		ticker := time.NewTicker(attemptCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				h.purgeStaleAttempts()
				h.mu.Lock()
				taskManager := h.chatGPTWebTasks
				h.mu.Unlock()
				if taskManager != nil {
					taskManager.prune()
				}
				h.mu.Lock()
				mutationTaskManager := h.chatGPTWebMutationTasks
				h.mu.Unlock()
				if mutationTaskManager != nil {
					mutationTaskManager.prune()
				}
				h.mu.Lock()
				agentIdentityTasks := h.agentIdentityTasks
				h.mu.Unlock()
				if agentIdentityTasks != nil {
					agentIdentityTasks.prune()
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Shutdown cancels and waits for provider-owned management tasks.
func (h *Handler) Shutdown(ctx context.Context) error {
	if h == nil {
		return nil
	}
	h.cleanupStopOnce.Do(func() {
		h.mu.Lock()
		cancel := h.cleanupCancel
		h.cleanupCancel = nil
		h.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	})
	h.cleanupWG.Wait()
	h.mu.Lock()
	taskManager := h.chatGPTWebTasks
	mutationTaskManager := h.chatGPTWebMutationTasks
	agentIdentityTasks := h.agentIdentityTasks
	usagePruneTasks := h.usagePruneTasks
	libraryCleanupTasks := h.libraryCleanupTasks
	h.mu.Unlock()
	type shutdownResult struct{ err error }
	results := make(chan shutdownResult, 5)
	count := 0
	if taskManager != nil {
		count++
		go func() { results <- shutdownResult{err: taskManager.shutdown(ctx)} }()
	}
	if mutationTaskManager != nil {
		count++
		go func() { results <- shutdownResult{err: mutationTaskManager.shutdown(ctx)} }()
	}
	if agentIdentityTasks != nil {
		count++
		go func() { results <- shutdownResult{err: agentIdentityTasks.shutdown(ctx)} }()
	}
	if usagePruneTasks != nil {
		count++
		go func() { results <- shutdownResult{err: usagePruneTasks.shutdown(ctx)} }()
	}
	if libraryCleanupTasks != nil {
		count++
		go func() { results <- shutdownResult{err: libraryCleanupTasks.Shutdown(ctx)} }()
	}
	var shutdownErr error
	for range count {
		shutdownErr = errors.Join(shutdownErr, (<-results).err)
	}
	return shutdownErr
}

// purgeStaleAttempts removes IP entries that have been idle beyond attemptMaxIdleTime
// and whose ban (if any) has expired.
func (h *Handler) purgeStaleAttempts() {
	now := time.Now()
	h.attemptsMu.Lock()
	defer h.attemptsMu.Unlock()
	for ip, ai := range h.failedAttempts {
		// Skip if still banned
		if !ai.blockedUntil.IsZero() && now.Before(ai.blockedUntil) {
			continue
		}
		// Remove if idle too long
		if now.Sub(ai.lastActivity) > attemptMaxIdleTime {
			delete(h.failedAttempts, ip)
		}
	}
}

// NewHandler creates a new management handler instance.
func NewHandlerWithoutConfigFilePath(cfg *config.Config, manager *coreauth.Manager) *Handler {
	return NewHandler(cfg, "", manager)
}

// SetConfig updates the in-memory config reference when the server hot-reloads.
func (h *Handler) SetConfig(cfg *config.Config) error {
	if h == nil {
		return nil
	}
	h.setConfigMu.Lock()
	defer h.setConfigMu.Unlock()
	snapshot, errClone := config.Clone(cfg)
	if errClone != nil {
		return errClone
	}
	published, errPublished := config.Clone(snapshot)
	if errPublished != nil {
		return errPublished
	}
	h.mu.Lock()
	proxyPoolManager := h.proxyPoolManager
	mutationTasks := h.chatGPTWebMutationTasks
	workers := config.DefaultChatGPTWebImportWorkers
	if snapshot != nil {
		workers = snapshot.ChatGPTWeb.Import.Resolved().Workers
	}
	h.mu.Unlock()
	if proxyPoolManager != nil {
		if errProxyConfig := proxyPoolManager.UpdateConfig(snapshot); errProxyConfig != nil {
			return errProxyConfig
		}
	}
	h.mu.Lock()
	h.cfg = snapshot
	h.configSnapshot.Store(published)
	h.mu.Unlock()
	if mutationTasks != nil {
		mutationTasks.updateWorkerLimit(workers)
	}
	return nil
}

// SetRuntimeConfigApplier registers the service-owned runtime configuration
// transaction. The callback is always invoked without the handler mutex held.
func (h *Handler) SetRuntimeConfigApplier(apply func(context.Context, *config.Config) (config.RuntimeApplyResult, error)) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.runtimeConfigApplier = apply
	h.mu.Unlock()
}

// SetAuthManager updates the auth manager reference used by management endpoints.
func (h *Handler) SetAuthManager(manager *coreauth.Manager) {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.authManager != manager {
		h.libraryCleanupTasks = nil
	}
	h.authManager = manager
	h.mu.Unlock()
}

// SetProxyPoolManager updates the structured proxy runtime used by management endpoints.
func (h *Handler) SetProxyPoolManager(manager *proxypool.Manager) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.proxyPoolManager = manager
	h.mu.Unlock()
	cfg := h.currentConfig()
	if manager != nil {
		if errProxyConfig := manager.UpdateConfig(cfg); errProxyConfig != nil {
			log.WithError(errProxyConfig).Error("failed to initialize proxy pool runtime configuration")
		}
	}
}

// SetUsageStatistics allows replacing the usage statistics reference.
func (h *Handler) SetUsageStatistics(stats *usage.RequestStatistics) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.usageStats = stats
	h.mu.Unlock()
}

func (h *Handler) usageStatisticsFilePath() string {
	if h == nil {
		return usage.StatisticsFilePath(nil)
	}
	authDir := ""
	if cfg := h.currentConfig(); cfg != nil {
		authDir = cfg.AuthDir
	}
	return usage.StatisticsFilePath(&config.Config{AuthDir: authDir})
}

// SetLocalPassword configures the runtime-local password accepted for localhost requests.
func (h *Handler) SetLocalPassword(password string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.localPassword = password
	h.mu.Unlock()
}

// SetLogDirectory updates the directory where main.log should be looked up.
func (h *Handler) SetLogDirectory(dir string) {
	if dir == "" {
		return
	}
	if !filepath.IsAbs(dir) {
		if abs, err := filepath.Abs(dir); err == nil {
			dir = abs
		}
	}
	h.mu.Lock()
	h.logDir = dir
	h.mu.Unlock()
}

// SetPostAuthHook registers a hook to be called after auth record creation but before persistence.
func (h *Handler) SetPostAuthHook(hook coreauth.PostAuthHook) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.postAuthHook = hook
}

// SetAuthStatusHook registers a hook to be called after auth status changes.
func (h *Handler) SetAuthStatusHook(hook coreauth.AuthStatusHook) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.authStatusHook = hook
}

// SetAuthDeleteHook registers service-owned cleanup after managed credentials are deleted.
func (h *Handler) SetAuthDeleteHook(hook func(context.Context, []*coreauth.Auth)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.authDeleteHook = hook
}

// SetChatGPTWebDependencyReconcileHook registers the service-level dependency cleanup hook.
func (h *Handler) SetChatGPTWebDependencyReconcileHook(hook func(context.Context, string) ([]string, error)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dependencyReconcileHook = hook
}

// SetChatGPTWebDeadAuthDeleteCountProvider registers the process-local deletion count provider.
func (h *Handler) SetChatGPTWebDeadAuthDeleteCountProvider(provider func() uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.deadAuthDeleteCount = provider
}

// SetUsageRestoreStatusProvider registers the service-owned restore snapshot provider.
func (h *Handler) SetUsageRestoreStatusProvider(provider func() usage.RestoreRuntimeSnapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.usageRestoreStatus = provider
}

func (h *Handler) usageRestoreStatusSnapshot() usage.RestoreRuntimeSnapshot {
	if h == nil {
		return usage.RestoreRuntimeSnapshot{Status: "unavailable"}
	}
	h.mu.Lock()
	provider := h.usageRestoreStatus
	h.mu.Unlock()
	if provider == nil {
		return usage.RestoreRuntimeSnapshot{Status: "unavailable"}
	}
	return provider()
}

func (h *Handler) usageStatisticsSnapshot() *usage.RequestStatistics {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	stats := h.usageStats
	h.mu.Unlock()
	return stats
}

func (h *Handler) postAuthHookSnapshot() coreauth.PostAuthHook {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	hook := h.postAuthHook
	h.mu.Unlock()
	return hook
}

func (h *Handler) authStatusHookSnapshot() coreauth.AuthStatusHook {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	hook := h.authStatusHook
	h.mu.Unlock()
	return hook
}

func (h *Handler) authDeleteHookSnapshot() func(context.Context, []*coreauth.Auth) {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	hook := h.authDeleteHook
	h.mu.Unlock()
	return hook
}

func (h *Handler) dependencyReconcileHookSnapshot() func(context.Context, string) ([]string, error) {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	hook := h.dependencyReconcileHook
	h.mu.Unlock()
	return hook
}

func (h *Handler) deadAuthDeleteCountSnapshot() func() uint64 {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	provider := h.deadAuthDeleteCount
	h.mu.Unlock()
	return provider
}

// Middleware enforces access control for management endpoints.
// All requests (local and remote) require a valid management key.
// Additionally, remote access requires allow-remote-management=true.
func (h *Handler) Middleware() gin.HandlerFunc {
	const maxFailures = 5
	const banDuration = 30 * time.Minute

	return func(c *gin.Context) {
		c.Header("X-CPA-VERSION", buildinfo.Version)
		c.Header("X-CPA-COMMIT", buildinfo.Commit)
		c.Header("X-CPA-BUILD-DATE", buildinfo.BuildDate)

		clientIP := c.ClientIP()
		localClient := clientIP == "127.0.0.1" || clientIP == "::1"
		cfg := h.currentConfig()
		var (
			allowRemote         bool
			secretHash          string
			allowRemoteOverride bool
			envSecret           string
			localPassword       string
		)
		if cfg != nil {
			allowRemote = cfg.RemoteManagement.AllowRemote
			secretHash = cfg.RemoteManagement.SecretKey
		}
		h.mu.Lock()
		allowRemoteOverride = h.allowRemoteOverride
		envSecret = h.envSecret
		localPassword = h.localPassword
		h.mu.Unlock()
		if allowRemoteOverride {
			allowRemote = true
		}

		fail := func() {}
		if !localClient {
			h.attemptsMu.Lock()
			ai := h.failedAttempts[clientIP]
			if ai != nil {
				if !ai.blockedUntil.IsZero() {
					if time.Now().Before(ai.blockedUntil) {
						remaining := time.Until(ai.blockedUntil).Round(time.Second)
						h.attemptsMu.Unlock()
						c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("IP banned due to too many failed attempts. Try again in %s", remaining)})
						return
					}
					// Ban expired, reset state
					ai.blockedUntil = time.Time{}
					ai.count = 0
				}
			}
			h.attemptsMu.Unlock()

			if !allowRemote {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "remote management disabled"})
				return
			}

			fail = func() {
				h.attemptsMu.Lock()
				aip := h.failedAttempts[clientIP]
				if aip == nil {
					aip = &attemptInfo{}
					h.failedAttempts[clientIP] = aip
				}
				aip.count++
				aip.lastActivity = time.Now()
				if aip.count >= maxFailures {
					aip.blockedUntil = time.Now().Add(banDuration)
					aip.count = 0
				}
				h.attemptsMu.Unlock()
			}
		}
		if secretHash == "" && envSecret == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "remote management key not set"})
			return
		}

		// Accept either Authorization: Bearer <key> or X-Management-Key
		var provided string
		if ah := c.GetHeader("Authorization"); ah != "" {
			parts := strings.SplitN(ah, " ", 2)
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
				provided = parts[1]
			} else {
				provided = ah
			}
		}
		if provided == "" {
			provided = c.GetHeader("X-Management-Key")
		}

		if provided == "" {
			if !localClient {
				fail()
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing management key"})
			return
		}

		if localClient {
			if lp := localPassword; lp != "" {
				if subtle.ConstantTimeCompare([]byte(provided), []byte(lp)) == 1 {
					c.Next()
					return
				}
			}
		}

		if envSecret != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(envSecret)) == 1 {
			if !localClient {
				h.attemptsMu.Lock()
				if ai := h.failedAttempts[clientIP]; ai != nil {
					ai.count = 0
					ai.blockedUntil = time.Time{}
				}
				h.attemptsMu.Unlock()
			}
			c.Next()
			return
		}

		if secretHash == "" || bcrypt.CompareHashAndPassword([]byte(secretHash), []byte(provided)) != nil {
			if !localClient {
				fail()
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid management key"})
			return
		}

		if !localClient {
			h.attemptsMu.Lock()
			if ai := h.failedAttempts[clientIP]; ai != nil {
				ai.count = 0
				ai.blockedUntil = time.Time{}
			}
			h.attemptsMu.Unlock()
		}

		c.Next()
	}
}

// persist saves the current in-memory config to disk.
func (h *Handler) persist(c *gin.Context) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.persistLocked(c)
}

// persistLocked saves the current in-memory config to disk.
// It expects the caller to hold h.mu.
func (h *Handler) persistLocked(c *gin.Context) bool {
	if errKeys := h.cfg.ValidateXAIKeys(); errKeys != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errKeys.Error()})
		return false
	}
	if errWeight := h.cfg.ValidateCredentialWeights(); errWeight != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errWeight.Error()})
		return false
	}
	if errRetry := h.cfg.ValidateCredentialRequestRetries(); errRetry != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errRetry.Error()})
		return false
	}
	if errRules := h.cfg.ValidateRequestScopedErrorRules(); errRules != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errRules.Error()})
		return false
	}
	if errModels := h.cfg.ValidateModelContextLengths(); errModels != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errModels.Error()})
		return false
	}
	if errThinking := h.cfg.ValidateModelThinking(); errThinking != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errThinking.Error()})
		return false
	}
	if errModalities := h.cfg.ValidateModelInputModalities(); errModalities != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errModalities.Error()})
		return false
	}
	previousBody, previousExisted, errPreviousBody := h.readPersistedConfigBodyLocked()
	if errPreviousBody != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read current config"})
		return false
	}
	previousCfg, errPreviousConfig := config.LoadConfigOptional(h.configFilePath, true)
	if errPreviousConfig != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load current config"})
		return false
	}
	candidate, errCandidate := config.Clone(h.cfg)
	if errCandidate != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to snapshot runtime configuration"})
		return false
	}
	publishedCandidate, errPublishedCandidate := config.Clone(candidate)
	if errPublishedCandidate != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to snapshot published configuration"})
		return false
	}
	// Preserve comments when writing.
	if err := config.SaveConfigPreserveComments(h.configFilePath, h.cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to save config: %v", err)})
		return false
	}

	// Runtime application can rebuild executors, logging and background workers.
	// Release the handler lock before invoking it to preserve the global lock order.
	h.mu.Unlock()
	result, errApply := h.applyRuntimeConfig(c.Request.Context(), candidate)
	h.mu.Lock()
	if errApply != nil {
		errRollbackFile := h.restorePersistedConfigLocked(previousBody, previousExisted, previousCfg)
		h.mu.Unlock()
		var errRollbackRuntime error
		if previousCfg != nil {
			_, errRollbackRuntime = h.applyRuntimeConfig(context.WithoutCancel(c.Request.Context()), previousCfg)
		}
		h.mu.Lock()
		if errRollbackFile != nil || errRollbackRuntime != nil {
			log.WithError(errors.Join(errApply, errRollbackFile, errRollbackRuntime)).Error("runtime configuration update failed and rollback was incomplete")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "runtime configuration update failed and rollback was incomplete"})
			return false
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "runtime_update_failed", "message": errApply.Error()})
		return false
	}
	h.configSnapshot.Store(publishedCandidate)
	response := gin.H{"status": "ok", "applied": result.Applied}
	if rawFields, exists := c.Get(managementResponseFieldsKey); exists {
		if fields, ok := rawFields.(gin.H); ok {
			for key, value := range fields {
				response[key] = value
			}
		}
	}
	if result.RestartRequired {
		response["restart_required"] = true
		response["restart_fields"] = result.RestartFields
	}
	c.JSON(http.StatusOK, response)
	return true
}

func (h *Handler) applyRuntimeConfig(ctx context.Context, candidate *config.Config) (config.RuntimeApplyResult, error) {
	if h == nil || candidate == nil {
		return config.RuntimeApplyResult{}, errors.New("runtime configuration is unavailable")
	}
	h.mu.Lock()
	applier := h.runtimeConfigApplier
	proxyPoolManager := h.proxyPoolManager
	authManager := h.authManager
	mutationTasks := h.chatGPTWebMutationTasks
	h.mu.Unlock()
	if applier != nil {
		return applier(ctx, candidate)
	}
	if proxyPoolManager != nil {
		if errProxyConfig := proxyPoolManager.UpdateConfig(candidate); errProxyConfig != nil {
			return config.RuntimeApplyResult{}, errProxyConfig
		}
	}
	if authManager != nil {
		authManager.SetConfig(candidate)
	}
	if mutationTasks != nil {
		mutationTasks.updateWorkerLimit(candidate.ChatGPTWeb.Import.Resolved().Workers)
	}
	return config.RuntimeApplyResult{Applied: true}, nil
}

func (h *Handler) restorePersistedConfigLocked(previousBody []byte, previousExisted bool, previousCfg *config.Config) error {
	if h == nil {
		return nil
	}
	if h.cfg != nil && previousCfg != nil {
		*h.cfg = *previousCfg
	} else {
		h.cfg = previousCfg
	}
	return h.restorePersistedConfigFileLocked(previousBody, previousExisted)
}

func (h *Handler) readPersistedConfigBodyLocked() ([]byte, bool, error) {
	if h == nil {
		return nil, false, nil
	}
	body, errRead := os.ReadFile(h.configFilePath)
	if errRead == nil {
		return body, true, nil
	}
	if errors.Is(errRead, os.ErrNotExist) {
		return nil, false, nil
	}
	return nil, false, errRead
}

func (h *Handler) restorePersistedConfigFileLocked(previousBody []byte, previousExisted bool) error {
	if h == nil {
		return nil
	}
	if previousExisted {
		return WriteConfig(h.configFilePath, previousBody)
	}
	if errRemove := os.Remove(h.configFilePath); errRemove != nil && !errors.Is(errRemove, os.ErrNotExist) {
		return errRemove
	}
	return nil
}

// Helper methods for simple types
func (h *Handler) updateBoolField(c *gin.Context, set func(bool)) {
	var body struct {
		Value *bool `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	set(*body.Value)
	h.persistLocked(c)
}

func (h *Handler) updateIntField(c *gin.Context, set func(int)) {
	h.updateIntFieldNormalized(c, nil, set)
}

func (h *Handler) updateIntFieldNormalized(c *gin.Context, normalize func(int) int, set func(int)) {
	var body struct {
		Value *int `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	value := *body.Value
	if normalize != nil {
		value = normalize(value)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	set(value)
	h.persistLocked(c)
}

func (h *Handler) updateStringField(c *gin.Context, set func(string)) {
	var body struct {
		Value *string `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	set(*body.Value)
	h.persistLocked(c)
}
