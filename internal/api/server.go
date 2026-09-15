// Package api provides the HTTP API server implementation for the CLI Proxy API.
// It includes the main server struct, routing setup, middleware for CORS and authentication,
// and integration with various AI API handlers (OpenAI, Claude, Gemini).
// The server supports hot-reloading of clients and configuration.
package api

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/access"
	managementHandlers "github.com/router-for-me/CLIProxyAPI/v6/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/api/middleware"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/cache"
	codexlive "github.com/router-for-me/CLIProxyAPI/v6/internal/client/codex/live"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/managementasset"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/proxypool"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/sentinelservice"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/usage"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v6/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/api/handlers/claude"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/api/handlers/gemini"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/api/handlers/openai"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v6/sdk/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const oauthCallbackSuccessHTML = `<html><head><meta charset="utf-8"><title>Authentication successful</title><script>setTimeout(function(){window.close();},5000);</script></head><body><h1>Authentication successful!</h1><p>You can close this window.</p><p>This window will close automatically in 5 seconds.</p></body></html>`

type serverOptionConfig struct {
	extraMiddleware      []gin.HandlerFunc
	engineConfigurator   func(*gin.Engine)
	routerConfigurator   func(*gin.Engine, *handlers.BaseAPIHandler, *config.Config)
	requestLoggerFactory func(*config.Config, string) logging.RequestLogger
	localPassword        string
	keepAliveEnabled     bool
	keepAliveTimeout     time.Duration
	keepAliveOnTimeout   func()
	postAuthHook         auth.PostAuthHook
	authStatusHook       auth.AuthStatusHook
	authDeleteHook       func(context.Context, []*auth.Auth)
	dependencyReconcile  func(context.Context, string) ([]string, error)
	deadAuthDeleteCount  func() uint64
	proxyPoolManager     *proxypool.Manager
	runtimeConfigApply   func(context.Context, *config.Config) (config.RuntimeApplyResult, error)
	startupState         *StartupState
	usageRestoreStatus   func() usage.RestoreRuntimeSnapshot
}

// ServerOption customises HTTP server construction.
type ServerOption func(*serverOptionConfig)

func defaultRequestLoggerFactory(cfg *config.Config, configPath string) logging.RequestLogger {
	configDir := filepath.Dir(configPath)
	logsDir := logging.ResolveLogDirectory(cfg)
	return logging.NewFileRequestLogger(cfg.RequestLog, logsDir, configDir, cfg.ErrorLogsMaxFiles)
}

// WithMiddleware appends additional Gin middleware during server construction.
func WithMiddleware(mw ...gin.HandlerFunc) ServerOption {
	return func(cfg *serverOptionConfig) {
		cfg.extraMiddleware = append(cfg.extraMiddleware, mw...)
	}
}

// WithEngineConfigurator allows callers to mutate the Gin engine prior to middleware setup.
func WithEngineConfigurator(fn func(*gin.Engine)) ServerOption {
	return func(cfg *serverOptionConfig) {
		cfg.engineConfigurator = fn
	}
}

// WithRouterConfigurator appends a callback after default routes are registered.
func WithRouterConfigurator(fn func(*gin.Engine, *handlers.BaseAPIHandler, *config.Config)) ServerOption {
	return func(cfg *serverOptionConfig) {
		cfg.routerConfigurator = fn
	}
}

// WithLocalManagementPassword stores a runtime-only management password accepted for localhost requests.
func WithLocalManagementPassword(password string) ServerOption {
	return func(cfg *serverOptionConfig) {
		cfg.localPassword = password
	}
}

// WithKeepAliveEndpoint enables a keep-alive endpoint with the provided timeout and callback.
func WithKeepAliveEndpoint(timeout time.Duration, onTimeout func()) ServerOption {
	return func(cfg *serverOptionConfig) {
		if timeout <= 0 || onTimeout == nil {
			return
		}
		cfg.keepAliveEnabled = true
		cfg.keepAliveTimeout = timeout
		cfg.keepAliveOnTimeout = onTimeout
	}
}

// WithRequestLoggerFactory customises request logger creation.
func WithRequestLoggerFactory(factory func(*config.Config, string) logging.RequestLogger) ServerOption {
	return func(cfg *serverOptionConfig) {
		cfg.requestLoggerFactory = factory
	}
}

// WithPostAuthHook registers a hook to be called after auth record creation.
func WithPostAuthHook(hook auth.PostAuthHook) ServerOption {
	return func(cfg *serverOptionConfig) {
		cfg.postAuthHook = hook
	}
}

// WithAuthStatusHook registers a hook to be called after auth status changes.
func WithAuthStatusHook(hook auth.AuthStatusHook) ServerOption {
	return func(cfg *serverOptionConfig) {
		cfg.authStatusHook = hook
	}
}

// WithAuthDeleteHook registers service-owned cleanup after management deletes credentials.
func WithAuthDeleteHook(hook func(context.Context, []*auth.Auth)) ServerOption {
	return func(cfg *serverOptionConfig) {
		cfg.authDeleteHook = hook
	}
}

// WithChatGPTWebDependencyReconcileHook registers dependency cleanup owned by the service.
func WithChatGPTWebDependencyReconcileHook(hook func(context.Context, string) ([]string, error)) ServerOption {
	return func(cfg *serverOptionConfig) {
		cfg.dependencyReconcile = hook
	}
}

// WithChatGPTWebDeadAuthDeleteCountProvider exposes the process-local automatic deletion count.
func WithChatGPTWebDeadAuthDeleteCountProvider(provider func() uint64) ServerOption {
	return func(cfg *serverOptionConfig) {
		cfg.deadAuthDeleteCount = provider
	}
}

// WithProxyPoolManager exposes structured proxy runtime state to management endpoints.
func WithProxyPoolManager(manager *proxypool.Manager) ServerOption {
	return func(cfg *serverOptionConfig) {
		cfg.proxyPoolManager = manager
	}
}

// WithRuntimeConfigApply registers the service-owned runtime configuration
// transaction used by both management writes and file-watcher reloads.
func WithRuntimeConfigApply(apply func(context.Context, *config.Config) (config.RuntimeApplyResult, error)) ServerOption {
	return func(cfg *serverOptionConfig) {
		cfg.runtimeConfigApply = apply
	}
}

// WithStartupState installs a service-owned readiness and startup diagnostics
// state. Servers created without this option remain immediately ready for SDK
// compatibility.
func WithStartupState(state *StartupState) ServerOption {
	return func(cfg *serverOptionConfig) {
		cfg.startupState = state
	}
}

// WithUsageRestoreStatusProvider exposes safe background Usage restore state.
func WithUsageRestoreStatusProvider(provider func() usage.RestoreRuntimeSnapshot) ServerOption {
	return func(cfg *serverOptionConfig) {
		cfg.usageRestoreStatus = provider
	}
}

// Server represents the main API server.
// It encapsulates the Gin engine, HTTP server, handlers, and configuration.
type Server struct {
	sentinelOnly    bool
	sentinelSolver  *sentinelservice.Service
	sentinelInitErr error
	// engine is the Gin web framework engine instance.
	engine *gin.Engine

	// server is the underlying HTTP server.
	server *http.Server

	// handlers contains the API handlers for processing requests.
	handlers  *handlers.BaseAPIHandler
	codexLive *codexlive.Handler

	// cfg holds the current server configuration.
	configMu sync.RWMutex
	cfg      *config.Config

	// configUpdateMu serializes direct UpdateClients callers. Service-owned
	// runtime transactions already serialize their work, but the API package can
	// also be embedded without a Service.
	configUpdateMu sync.Mutex

	// oldConfigYaml stores a YAML snapshot of the previous configuration for change detection.
	// This prevents issues when the config object is modified in place by Management API.
	oldConfigYaml []byte

	// accessManager handles request authentication providers.
	accessManager *sdkaccess.Manager

	// requestLogger is the request logger instance for dynamic configuration updates.
	requestLogger logging.RequestLogger
	loggerToggle  func(bool)

	// configFilePath is the absolute path to the YAML config file for persistence.
	configFilePath  string
	managementPanel managementasset.FileServer

	// currentPath is the absolute path to the current working directory.
	currentPath string

	// wsRoutes tracks registered websocket upgrade paths.
	wsRouteMu     sync.Mutex
	wsRoutes      map[string]struct{}
	wsAuthChanged func(bool, bool)
	wsAuthEnabled atomic.Bool

	// management handler
	mgmt *managementHandlers.Handler

	// managementRoutesEnabled controls whether management endpoints serve real handlers.
	managementRoutesEnabled atomic.Bool
	// managementRoutesMu protects route registration maps for hot-reloaded access paths.
	managementRoutesMu sync.Mutex
	// managementAPIPrefixes tracks registered management API prefixes.
	managementAPIPrefixes map[string]struct{}
	// managementSurfacePaths tracks registered management page and OAuth callback paths.
	managementSurfacePaths map[string]struct{}

	// envManagementSecret indicates whether MANAGEMENT_PASSWORD is configured.
	envManagementSecret bool

	localPassword string

	keepAliveEnabled   bool
	keepAliveTimeout   time.Duration
	keepAliveOnTimeout func()
	keepAliveHeartbeat chan struct{}
	keepAliveStop      chan struct{}

	startupState *StartupState
}

// currentConfig returns the immutable configuration currently used by the API
// server. Runtime updates replace the pointer instead of mutating the value.
func (s *Server) currentConfig() *config.Config {
	if s == nil {
		return nil
	}
	s.configMu.RLock()
	current := s.cfg
	s.configMu.RUnlock()
	return current
}

func (s *Server) setCurrentConfig(cfg *config.Config) {
	if s == nil {
		return
	}
	s.configMu.Lock()
	s.cfg = cfg
	s.configMu.Unlock()
}

// NewServer creates and initializes a new API server instance.
// It sets up the Gin engine, middleware, routes, and handlers.
//
// Parameters:
//   - cfg: The server configuration
//   - authManager: core runtime auth manager
//   - accessManager: request authentication manager
//
// Returns:
//   - *Server: A new server instance
func NewServer(cfg *config.Config, authManager *auth.Manager, accessManager *sdkaccess.Manager, configFilePath string, opts ...ServerOption) *Server {
	optionState := &serverOptionConfig{
		requestLoggerFactory: defaultRequestLoggerFactory,
	}
	for i := range opts {
		opts[i](optionState)
	}
	// Set gin mode
	if !cfg.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create gin engine
	engine := gin.New()
	if optionState.engineConfigurator != nil {
		optionState.engineConfigurator(engine)
	}

	// Add middleware
	engine.Use(logging.GinLogrusLogger())
	engine.Use(logging.GinLogrusRecovery())
	for _, mw := range optionState.extraMiddleware {
		engine.Use(mw)
	}

	// Add request logging middleware (positioned after recovery, before auth)
	// Resolve logs directory relative to the configuration file directory.
	var requestLogger logging.RequestLogger
	var toggle func(bool)
	var serverRef *Server
	if !cfg.CommercialMode {
		if optionState.requestLoggerFactory != nil {
			requestLogger = optionState.requestLoggerFactory(cfg, configFilePath)
		}
		if requestLogger != nil {
			engine.Use(middleware.RequestLoggingMiddleware(requestLogger, func() config.RequestBodyReleaseConfig {
				if serverRef != nil {
					if current := serverRef.currentConfig(); current != nil {
						return current.RequestBodyRelease
					}
				}
				if cfg != nil {
					return cfg.RequestBodyRelease
				}
				return config.RequestBodyReleaseConfig{}
			}))
			if setter, ok := requestLogger.(interface{ SetEnabled(bool) }); ok {
				toggle = setter.SetEnabled
			}
		}
	}

	engine.Use(corsMiddleware())
	wd, err := os.Getwd()
	if err != nil {
		wd = configFilePath
	}

	envAdminPassword, envAdminPasswordSet := os.LookupEnv("MANAGEMENT_PASSWORD")
	envAdminPassword = strings.TrimSpace(envAdminPassword)
	envManagementSecret := envAdminPasswordSet && envAdminPassword != ""

	// Create server instance
	s := &Server{
		engine:                 engine,
		handlers:               handlers.NewBaseAPIHandlers(sdkHandlerConfig(cfg), authManager),
		codexLive:              codexlive.NewHandler(cfg, authManager),
		cfg:                    cfg,
		accessManager:          accessManager,
		requestLogger:          requestLogger,
		loggerToggle:           toggle,
		configFilePath:         configFilePath,
		currentPath:            wd,
		envManagementSecret:    envManagementSecret,
		wsRoutes:               make(map[string]struct{}),
		managementAPIPrefixes:  make(map[string]struct{}),
		managementSurfacePaths: make(map[string]struct{}),
		startupState:           optionState.startupState,
	}
	if s.startupState == nil {
		s.startupState = newReadyStartupState()
	}
	serverRef = s
	s.wsAuthEnabled.Store(cfg.WebsocketAuth)
	// Save initial YAML snapshot
	s.oldConfigYaml, _ = yaml.Marshal(cfg)
	s.applyAccessConfig(nil, cfg)
	if authManager != nil {
		authManager.SetRetryConfig(cfg.RequestRetry, time.Duration(cfg.MaxRetryInterval)*time.Second, cfg.MaxRetryCredentials)
		authManager.SetConfig(cfg)
	}
	managementasset.SetCurrentConfig(cfg)
	auth.SetQuotaCooldownDisabled(cfg.DisableCooling)
	applySignatureCacheConfig(nil, cfg)
	// Initialize management with an isolated snapshot so handler mutations do
	// not change the live service configuration before the runtime transaction.
	managementCfg, errManagementClone := config.Clone(cfg)
	if errManagementClone != nil {
		log.WithError(errManagementClone).Error("failed to isolate management configuration snapshot")
		managementCfg = cfg
	}
	s.mgmt = managementHandlers.NewHandler(managementCfg, configFilePath, authManager)
	if errSolverPath := cfg.ValidateSentinelSolver(); errSolverPath != nil {
		s.sentinelInitErr = errSolverPath
	} else {
		s.sentinelSolver, s.sentinelInitErr = sentinelservice.New(cfg.SentinelSolver)
	}
	if s.sentinelSolver != nil {
		s.mgmt.SetSentinelSolver(s.sentinelSolver)
	}
	s.mgmt.SetProxyPoolManager(optionState.proxyPoolManager)
	runtimeConfigApply := optionState.runtimeConfigApply
	if runtimeConfigApply == nil {
		runtimeConfigApply = func(_ context.Context, candidate *config.Config) (config.RuntimeApplyResult, error) {
			if errUpdate := s.UpdateClients(candidate); errUpdate != nil {
				return config.RuntimeApplyResult{}, errUpdate
			}
			return config.RuntimeApplyResult{Applied: true}, nil
		}
	}
	s.mgmt.SetRuntimeConfigApplier(runtimeConfigApply)
	if optionState.localPassword != "" {
		s.mgmt.SetLocalPassword(optionState.localPassword)
	}
	logDir := logging.ResolveLogDirectory(cfg)
	s.mgmt.SetLogDirectory(logDir)
	if optionState.postAuthHook != nil {
		s.mgmt.SetPostAuthHook(optionState.postAuthHook)
	}
	if optionState.authStatusHook != nil {
		s.mgmt.SetAuthStatusHook(optionState.authStatusHook)
	}
	if optionState.authDeleteHook != nil {
		s.mgmt.SetAuthDeleteHook(optionState.authDeleteHook)
	}
	if optionState.dependencyReconcile != nil {
		s.mgmt.SetChatGPTWebDependencyReconcileHook(optionState.dependencyReconcile)
	}
	if optionState.deadAuthDeleteCount != nil {
		s.mgmt.SetChatGPTWebDeadAuthDeleteCountProvider(optionState.deadAuthDeleteCount)
	}
	if optionState.usageRestoreStatus != nil {
		s.mgmt.SetUsageRestoreStatusProvider(optionState.usageRestoreStatus)
	}
	s.localPassword = optionState.localPassword

	// Setup routes
	s.setupRoutes()

	// Apply additional router configurators from options
	if optionState.routerConfigurator != nil {
		optionState.routerConfigurator(engine, s.handlers, cfg)
	}

	// Register management routes before the HTTP server starts. Runtime updates
	// only toggle availability; Gin route mutation is not safe while serving.
	hasManagementSecret := cfg.RemoteManagement.SecretKey != "" || envManagementSecret || s.localPassword != ""
	s.managementRoutesEnabled.Store(hasManagementSecret)
	s.registerManagementRoutes()

	if optionState.keepAliveEnabled {
		s.enableKeepAlive(optionState.keepAliveTimeout, optionState.keepAliveOnTimeout)
	}

	// Create HTTP server
	s.server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler: engine,
	}
	if s.sentinelSolver != nil {
		s.server.Handler = s.sentinelSolver.Handler(engine)
	}

	return s
}

// setupRoutes configures the API routes for the server.
// It defines the endpoints and associates them with their respective handlers.
func (s *Server) setupRoutes() {
	healthzHandler := func(c *gin.Context) {
		if c.Request.Method == http.MethodHead {
			c.Status(http.StatusOK)
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
	s.engine.GET("/healthz", healthzHandler)
	s.engine.HEAD("/healthz", healthzHandler)
	readyzHandler := func(c *gin.Context) {
		snapshot := s.startupState.Snapshot()
		if !snapshot.Ready {
			c.Header("Retry-After", "2")
			if c.Request.Method == http.MethodHead {
				c.Status(http.StatusServiceUnavailable)
				return
			}
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "initializing",
				"phase":  snapshot.Phase,
			})
			return
		}
		if c.Request.Method == http.MethodHead {
			c.Status(http.StatusOK)
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok", "phase": snapshot.Phase})
	}
	s.engine.GET("/readyz", readyzHandler)
	s.engine.HEAD("/readyz", readyzHandler)

	s.registerManagementSurfaceRoutes()
	openaiHandlers := openai.NewOpenAIAPIHandler(s.handlers)
	geminiHandlers := gemini.NewGeminiAPIHandler(s.handlers)
	claudeCodeHandlers := claude.NewClaudeCodeAPIHandler(s.handlers)
	openaiResponsesHandlers := openai.NewOpenAIResponsesAPIHandler(s.handlers)
	openaiImagesHandlers := openai.NewOpenAIImagesAPIHandler(s.handlers)
	codexSearchHandlers := handlers.NewCodexAlphaSearchAPIHandler(s.handlers)

	// OpenAI compatible API routes
	v1 := s.engine.Group("/v1")
	v1.Use(AuthMiddleware(s.accessManager))
	v1.Use(s.proxyReadinessMiddleware())
	v1.Use(s.requestBodyAuditMiddleware())
	{
		v1.GET("/models", s.unifiedModelsHandler(openaiHandlers, claudeCodeHandlers))
		v1.POST("/chat/completions", openaiHandlers.ChatCompletions)
		v1.POST("/completions", openaiHandlers.Completions)
		v1.POST("/messages", claudeCodeHandlers.ClaudeMessages)
		v1.POST("/messages/count_tokens", claudeCodeHandlers.ClaudeCountTokens)
		v1.POST("/interactions", geminiHandlers.Interactions)
		v1.GET("/responses", openaiResponsesHandlers.ResponsesWebsocket)
		v1.POST("/realtime/client_secrets", s.codexLive.CreateClientSecret)
		v1.POST("/realtime/sessions", s.codexLive.CreateLegacySession)
		v1.POST("/realtime/calls/:call_id/hangup", s.codexLive.HandleHangup)
		v1.POST("/realtime/transcription_sessions", s.codexLive.Unsupported("Transcription-only sessions"))
		v1.GET("/realtime/translations", s.codexLive.Unsupported("Realtime translations"))
		v1.POST("/realtime/translations", s.codexLive.Unsupported("Realtime translations"))
		v1.POST("/realtime/translations/client_secrets", s.codexLive.Unsupported("Realtime translations"))
		v1.POST("/realtime/calls/:call_id/accept", s.codexLive.Unsupported("SIP controls"))
		v1.POST("/realtime/calls/:call_id/reject", s.codexLive.Unsupported("SIP controls"))
		v1.POST("/realtime/calls/:call_id/refer", s.codexLive.Unsupported("SIP controls"))
		v1.POST("/responses", openaiResponsesHandlers.Responses)
		v1.POST("/responses/compact", openaiResponsesHandlers.Compact)
		v1.POST("/alpha/search", codexSearchHandlers.Search)
		v1.POST("/images/generations", openaiImagesHandlers.Generations)
		v1.POST("/images/edits", openaiImagesHandlers.Edits)
		v1.POST("/videos", openaiHandlers.XAIVideosGenerations)
		v1.POST("/videos/generations", openaiHandlers.XAIVideosGenerations)
		v1.POST("/videos/edits", openaiHandlers.XAIVideosEdits)
		v1.POST("/videos/extensions", openaiHandlers.XAIVideosExtensions)
		v1.GET("/videos/:request_id", openaiHandlers.XAIVideosRetrieve)
	}

	// Local temporary credentials are accepted only by native connection routes.
	liveV1 := s.engine.Group("/v1", s.codexLiveAuthMiddleware(), s.proxyReadinessMiddleware(), s.requestBodyAuditMiddleware())
	liveV1.GET("/realtime", s.codexLive.HandleRealtimeWebsocket)
	liveV1.GET("/live/:call_id", s.codexLive.HandleSideband)
	liveV1.GET("/realtime/calls/:call_id", s.codexLive.HandleSideband)
	liveV1.POST("/live", s.codexLive.HandleCall)
	liveV1.POST("/realtime", s.codexLive.HandleCall)
	liveV1.POST("/realtime/calls", s.codexLive.HandleCall)

	// Codex CLI search alias uses the same authentication and request policies.
	s.engine.POST("/backend-api/codex/alpha/search", AuthMiddleware(s.accessManager), s.proxyReadinessMiddleware(), s.requestBodyAuditMiddleware(), codexSearchHandlers.Search)

	// Gemini compatible API routes
	v1beta := s.engine.Group("/v1beta")
	v1beta.Use(AuthMiddleware(s.accessManager))
	v1beta.Use(s.proxyReadinessMiddleware())
	v1beta.Use(s.requestBodyAuditMiddleware())
	{
		v1beta.GET("/models", geminiHandlers.GeminiModels)
		v1beta.POST("/interactions", geminiHandlers.Interactions)
		v1beta.POST("/models/*action", geminiHandlers.GeminiHandler)
		v1beta.GET("/models/*action", geminiHandlers.GeminiGetHandler)
	}

	// Root endpoint
	s.engine.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "CLI Proxy API Server",
			"endpoints": []string{
				"POST /v1/chat/completions",
				"POST /v1/completions",
				"GET /v1/models",
			},
		})
	})
	// Management routes are registered lazily by registerManagementRoutes when a secret is configured.
}

func (s *Server) proxyReadinessMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		snapshot := s.startupState.Snapshot()
		if snapshot.Ready {
			c.Next()
			return
		}
		code, message := startupUnavailableResponse(snapshot)
		c.Header("Retry-After", "2")
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
			"error": gin.H{
				"message": message,
				"type":    "service_unavailable",
				"code":    code,
			},
			"startup_phase": snapshot.Phase,
		})
	}
}

func (s *Server) requestBodyAuditMiddleware() gin.HandlerFunc {
	return middleware.RequestBodyAuditMiddleware(func() config.RequestBodyAuditConfig {
		current := s.currentConfig()
		if current == nil {
			return config.RequestBodyAuditConfig{}
		}
		return current.RequestBodyAudit
	})
}

// AttachWebsocketRoute registers a websocket upgrade handler on the primary Gin engine.
// The handler is served as-is without additional middleware beyond the standard stack already configured.
func (s *Server) AttachWebsocketRoute(path string, handler http.Handler) {
	if s == nil || s.engine == nil || handler == nil {
		return
	}
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		trimmed = "/v1/ws"
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	s.wsRouteMu.Lock()
	if _, exists := s.wsRoutes[trimmed]; exists {
		s.wsRouteMu.Unlock()
		return
	}
	s.wsRoutes[trimmed] = struct{}{}
	s.wsRouteMu.Unlock()

	authMiddleware := AuthMiddleware(s.accessManager)
	conditionalAuth := func(c *gin.Context) {
		if !s.wsAuthEnabled.Load() {
			c.Next()
			return
		}
		authMiddleware(c)
	}
	finalHandler := func(c *gin.Context) {
		handler.ServeHTTP(c.Writer, c.Request)
		c.Abort()
	}

	s.engine.GET(trimmed, conditionalAuth, s.proxyReadinessMiddleware(), finalHandler)
}

func (s *Server) currentManagementAccessPrefix() string {
	current := s.currentConfig()
	if current == nil {
		return ""
	}
	return config.ManagementAccessPathPrefix(current.RemoteManagement.AccessPath)
}

// ReconcileChatGPTWebManualReloginOperations finalizes durable operations after auth loading completes.
func (s *Server) ReconcileChatGPTWebManualReloginOperations() error {
	if s == nil || s.mgmt == nil {
		return nil
	}
	return s.mgmt.ReconcileChatGPTWebManualReloginOperations()
}

func (s *Server) activeManagementPrefixMiddleware(registeredPrefix string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.currentManagementAccessPrefix() != registeredPrefix {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		c.Next()
	}
}

func (s *Server) registerManagementSurfaceRoutes() {
	if s == nil || s.engine == nil {
		return
	}
	prefix := s.currentManagementAccessPrefix()
	routes := []struct {
		path    string
		handler gin.HandlerFunc
	}{
		{config.JoinManagementAccessPath(prefix, "/management.html"), s.serveManagementControlPanel},
		{config.JoinManagementAccessPath(prefix, "/anthropic/callback"), s.oauthCallbackHandler("anthropic")},
		{config.JoinManagementAccessPath(prefix, "/codex/callback"), s.oauthCallbackHandler("codex")},
		{config.JoinManagementAccessPath(prefix, "/antigravity/callback"), s.oauthCallbackHandler("antigravity")},
	}

	s.managementRoutesMu.Lock()
	defer s.managementRoutesMu.Unlock()
	for _, route := range routes {
		if _, exists := s.managementSurfacePaths[route.path]; exists {
			continue
		}
		s.managementSurfacePaths[route.path] = struct{}{}
		s.engine.GET(route.path, s.activeManagementPrefixMiddleware(prefix), route.handler)
	}
}

func (s *Server) oauthCallbackHandler(provider string) gin.HandlerFunc {
	return func(c *gin.Context) {
		code := c.Query("code")
		state := c.Query("state")
		errStr := c.Query("error")
		if errStr == "" {
			errStr = c.Query("error_description")
		}
		if current := s.currentConfig(); state != "" && current != nil {
			_, _ = managementHandlers.WriteOAuthCallbackFileForPendingSession(current.AuthDir, provider, state, code, errStr)
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, oauthCallbackSuccessHTML)
	}
}

func (s *Server) registerManagementRoutes() {
	if s == nil || s.engine == nil || s.mgmt == nil {
		return
	}
	prefix := s.currentManagementAccessPrefix()
	apiPrefix := config.JoinManagementAccessPath(prefix, "/v0/management")

	s.managementRoutesMu.Lock()
	if _, exists := s.managementAPIPrefixes[apiPrefix]; exists {
		s.managementRoutesMu.Unlock()
		return
	}
	s.managementAPIPrefixes[apiPrefix] = struct{}{}
	s.managementRoutesMu.Unlock()

	log.Infof("management routes registered at %s", apiPrefix)

	mgmt := s.engine.Group(apiPrefix)
	mgmt.Use(s.activeManagementPrefixMiddleware(prefix), s.managementAvailabilityMiddleware(), s.mgmt.Middleware(), s.startupManagementMiddleware(), s.mgmt.ConfigMutationMiddleware())
	{
		mgmt.GET("/startup/status", s.getStartupStatus)
		mgmt.GET("/usage", s.mgmt.GetUsageStatistics)
		mgmt.DELETE("/usage", s.mgmt.ClearUsageStatistics)
		mgmt.POST("/usage/prune", s.mgmt.PruneUsageHistory)
		mgmt.GET("/usage/prune/:task_id", s.mgmt.GetUsagePruneTask)
		mgmt.GET("/usage/meta", s.mgmt.GetUsageMeta)
		mgmt.GET("/usage/summary", s.mgmt.GetUsageSummary)
		mgmt.GET("/usage/details", s.mgmt.GetUsageDetails)
		mgmt.GET("/usage/failures/summary", s.mgmt.GetUsageFailureSummary)
		mgmt.GET("/usage/auths", s.mgmt.GetUsageAuthSummaries)
		mgmt.GET("/usage/facets", s.mgmt.GetUsageFacets)
		mgmt.GET("/usage/series", s.mgmt.GetUsageSeries)
		mgmt.GET("/usage/health", s.mgmt.GetUsageHealth)
		mgmt.GET("/usage/rates", s.mgmt.GetUsageRates)
		mgmt.GET("/usage/tokens", s.mgmt.GetUsageTokens)
		mgmt.GET("/usage/costs", s.mgmt.GetUsageCosts)
		mgmt.GET("/usage/prices", s.mgmt.GetUsagePrices)
		mgmt.PUT("/usage/prices", s.mgmt.PutUsagePrices)
		mgmt.PATCH("/usage/prices", s.mgmt.PatchUsagePrices)
		mgmt.DELETE("/usage/prices", s.mgmt.DeleteUsagePrices)
		mgmt.DELETE("/usage/prices/*model", s.mgmt.DeleteUsagePrice)
		mgmt.GET("/usage/auths/:auth_index/models", s.mgmt.GetUsageAuthModelSummaries)
		mgmt.GET("/usage/auths/:auth_index", s.mgmt.GetUsageAuthSummary)
		mgmt.GET("/usage/export", s.mgmt.ExportUsageStatistics)
		mgmt.POST("/usage/import", s.mgmt.ImportUsageStatistics)
		mgmt.GET("/usage/storage-config", s.mgmt.GetUsageStorageConfig)
		mgmt.PUT("/usage/storage-config", s.mgmt.PutUsageStorageConfig)
		mgmt.PATCH("/usage/storage-config", s.mgmt.PutUsageStorageConfig)
		mgmt.GET("/config", s.mgmt.GetConfig)
		mgmt.GET("/config.yaml", s.mgmt.GetConfigYAML)
		mgmt.PUT("/config.yaml", s.mgmt.PutConfigYAML)
		mgmt.GET("/request-body-audit", s.mgmt.GetRequestBodyAudit)
		mgmt.PUT("/request-body-audit", s.mgmt.PutRequestBodyAudit)
		mgmt.GET("/latest-version", s.mgmt.GetLatestVersion)
		mgmt.GET("/control-panel/update", s.mgmt.GetControlPanelUpdate)
		mgmt.POST("/control-panel/update", s.mgmt.PostControlPanelUpdate)

		mgmt.GET("/debug", s.mgmt.GetDebug)
		mgmt.PUT("/debug", s.mgmt.PutDebug)
		mgmt.PATCH("/debug", s.mgmt.PutDebug)

		mgmt.GET("/pprof/config", s.mgmt.GetPprofConfig)
		mgmt.GET("/pprof/enable", s.mgmt.GetPprofEnable)
		mgmt.PUT("/pprof/enable", s.mgmt.PutPprofEnable)
		mgmt.PATCH("/pprof/enable", s.mgmt.PutPprofEnable)
		mgmt.GET("/pprof/addr", s.mgmt.GetPprofAddr)
		mgmt.PUT("/pprof/addr", s.mgmt.PutPprofAddr)
		mgmt.PATCH("/pprof/addr", s.mgmt.PutPprofAddr)
		mgmt.GET("/pprof/profile/:profile", s.mgmt.GetPprofProfile)
		mgmt.GET("/system/metrics", s.mgmt.GetSystemMetrics)
		mgmt.GET("/storage/history", s.mgmt.GetStorageHistory)
		mgmt.GET("/routing/diagnostics", s.mgmt.GetRoutingDiagnostics)

		mgmt.GET("/logging-to-file", s.mgmt.GetLoggingToFile)
		mgmt.PUT("/logging-to-file", s.mgmt.PutLoggingToFile)
		mgmt.PATCH("/logging-to-file", s.mgmt.PutLoggingToFile)

		mgmt.GET("/logs-max-total-size-mb", s.mgmt.GetLogsMaxTotalSizeMB)
		mgmt.PUT("/logs-max-total-size-mb", s.mgmt.PutLogsMaxTotalSizeMB)
		mgmt.PATCH("/logs-max-total-size-mb", s.mgmt.PutLogsMaxTotalSizeMB)
		mgmt.GET("/logs-retention-days", s.mgmt.GetLogsRetentionDays)
		mgmt.PUT("/logs-retention-days", s.mgmt.PutLogsRetentionDays)
		mgmt.PATCH("/logs-retention-days", s.mgmt.PutLogsRetentionDays)

		mgmt.GET("/error-logs-max-files", s.mgmt.GetErrorLogsMaxFiles)
		mgmt.PUT("/error-logs-max-files", s.mgmt.PutErrorLogsMaxFiles)
		mgmt.PATCH("/error-logs-max-files", s.mgmt.PutErrorLogsMaxFiles)

		mgmt.GET("/usage-statistics-enabled", s.mgmt.GetUsageStatisticsEnabled)
		mgmt.PUT("/usage-statistics-enabled", s.mgmt.PutUsageStatisticsEnabled)
		mgmt.PATCH("/usage-statistics-enabled", s.mgmt.PutUsageStatisticsEnabled)

		mgmt.GET("/proxy-url", s.mgmt.GetProxyURL)
		mgmt.PUT("/proxy-url", s.mgmt.PutProxyURL)
		mgmt.PATCH("/proxy-url", s.mgmt.PutProxyURL)
		mgmt.DELETE("/proxy-url", s.mgmt.DeleteProxyURL)
		mgmt.GET("/proxy-url/check", s.mgmt.GetProxyURLCheck)
		mgmt.POST("/proxy-url/check", s.mgmt.PostProxyURLCheck)
		mgmt.GET("/proxy-health-check", s.mgmt.GetProxyHealthCheck)
		mgmt.PATCH("/proxy-health-check", s.mgmt.PatchProxyHealthCheck)
		mgmt.POST("/proxy-health-check/test", s.mgmt.PostProxyHealthCheckTest)
		mgmt.GET("/proxy-pools", s.mgmt.GetProxyPools)
		mgmt.POST("/proxy-pools", s.mgmt.PostProxyPool)
		mgmt.PATCH("/proxy-pools/:name", s.mgmt.PatchProxyPool)
		mgmt.DELETE("/proxy-pools/:name", s.mgmt.DeleteProxyPool)
		mgmt.GET("/proxy-pools/:name/status", s.mgmt.GetProxyPoolStatus)
		mgmt.POST("/proxy-pools/:name/check", s.mgmt.CheckProxyPool)
		mgmt.POST("/proxy-pools/:name/check-tasks", s.mgmt.PostProxyPoolCheckTask)
		mgmt.GET("/proxy-pools/:name/check-tasks", s.mgmt.GetProxyPoolCheckTasks)
		mgmt.GET("/proxy-pools/:name/check-tasks/:task_id", s.mgmt.GetProxyPoolCheckTask)
		mgmt.GET("/proxy-rules", s.mgmt.GetProxyRules)
		mgmt.PUT("/proxy-rules", s.mgmt.PutProxyRules)
		mgmt.GET("/proxy-bindings", s.mgmt.GetProxyBindings)
		mgmt.POST("/proxy-bindings/rebind", s.mgmt.RebindProxyBindings)

		mgmt.POST("/api-call", s.mgmt.APICall)

		mgmt.GET("/quota-exceeded/switch-project", s.mgmt.GetSwitchProject)
		mgmt.PUT("/quota-exceeded/switch-project", s.mgmt.PutSwitchProject)
		mgmt.PATCH("/quota-exceeded/switch-project", s.mgmt.PutSwitchProject)

		mgmt.GET("/quota-exceeded/switch-preview-model", s.mgmt.GetSwitchPreviewModel)
		mgmt.PUT("/quota-exceeded/switch-preview-model", s.mgmt.PutSwitchPreviewModel)
		mgmt.PATCH("/quota-exceeded/switch-preview-model", s.mgmt.PutSwitchPreviewModel)

		mgmt.GET("/api-keys", s.mgmt.GetAPIKeys)
		mgmt.PUT("/api-keys", s.mgmt.PutAPIKeys)
		mgmt.PATCH("/api-keys", s.mgmt.PatchAPIKeys)
		mgmt.DELETE("/api-keys", s.mgmt.DeleteAPIKeys)
		mgmt.GET("/api-key-groups", s.mgmt.GetAPIKeyGroups)
		mgmt.PUT("/api-key-groups", s.mgmt.PutAPIKeyGroups)
		mgmt.PATCH("/api-key-groups", s.mgmt.PatchAPIKeyGroups)
		mgmt.DELETE("/api-key-groups", s.mgmt.DeleteAPIKeyGroups)

		mgmt.GET("/gemini-api-key", s.mgmt.GetGeminiKeys)
		mgmt.PUT("/gemini-api-key", s.mgmt.PutGeminiKeys)
		mgmt.PATCH("/gemini-api-key", s.mgmt.PatchGeminiKey)
		mgmt.DELETE("/gemini-api-key", s.mgmt.DeleteGeminiKey)

		mgmt.GET("/interactions-api-key", s.mgmt.GetInteractionsKeys)
		mgmt.PUT("/interactions-api-key", s.mgmt.PutInteractionsKeys)
		mgmt.PATCH("/interactions-api-key", s.mgmt.PatchInteractionsKey)
		mgmt.DELETE("/interactions-api-key", s.mgmt.DeleteInteractionsKey)

		mgmt.GET("/logs", s.mgmt.GetLogs)
		mgmt.GET("/logs/stream", s.mgmt.StreamLogs)
		mgmt.DELETE("/logs", s.mgmt.DeleteLogs)
		mgmt.POST("/logs/prune", s.mgmt.PruneLogHistory)
		mgmt.GET("/request-error-logs", s.mgmt.GetRequestErrorLogs)
		mgmt.GET("/request-error-logs/:name", s.mgmt.DownloadRequestErrorLog)
		mgmt.GET("/request-log-by-id/:id", s.mgmt.GetRequestLogByID)
		mgmt.GET("/request-log", s.mgmt.GetRequestLog)
		mgmt.PUT("/request-log", s.mgmt.PutRequestLog)
		mgmt.PATCH("/request-log", s.mgmt.PutRequestLog)
		mgmt.GET("/ws-auth", s.mgmt.GetWebsocketAuth)
		mgmt.PUT("/ws-auth", s.mgmt.PutWebsocketAuth)
		mgmt.PATCH("/ws-auth", s.mgmt.PutWebsocketAuth)

		mgmt.GET("/request-retry", s.mgmt.GetRequestRetry)
		mgmt.PUT("/request-retry", s.mgmt.PutRequestRetry)
		mgmt.PATCH("/request-retry", s.mgmt.PutRequestRetry)
		mgmt.GET("/request-body-release", s.mgmt.GetRequestBodyRelease)
		mgmt.PUT("/request-body-release", s.mgmt.PutRequestBodyRelease)
		mgmt.PATCH("/request-body-release", s.mgmt.PutRequestBodyRelease)
		mgmt.GET("/non-retryable-errors", s.mgmt.GetNonRetryableErrors)
		mgmt.PUT("/non-retryable-errors", s.mgmt.PutNonRetryableErrors)
		mgmt.PATCH("/non-retryable-errors", s.mgmt.PutNonRetryableErrors)
		mgmt.GET("/auth-model-exclusions", s.mgmt.GetAuthModelExclusions)
		mgmt.PUT("/auth-model-exclusions", s.mgmt.PutAuthModelExclusions)
		mgmt.PATCH("/auth-model-exclusions", s.mgmt.PutAuthModelExclusions)
		mgmt.GET("/max-retry-credentials", s.mgmt.GetMaxRetryCredentials)
		mgmt.PUT("/max-retry-credentials", s.mgmt.PutMaxRetryCredentials)
		mgmt.PATCH("/max-retry-credentials", s.mgmt.PutMaxRetryCredentials)
		mgmt.GET("/max-retry-interval", s.mgmt.GetMaxRetryInterval)
		mgmt.PUT("/max-retry-interval", s.mgmt.PutMaxRetryInterval)
		mgmt.PATCH("/max-retry-interval", s.mgmt.PutMaxRetryInterval)

		mgmt.GET("/force-model-prefix", s.mgmt.GetForceModelPrefix)
		mgmt.PUT("/force-model-prefix", s.mgmt.PutForceModelPrefix)
		mgmt.PATCH("/force-model-prefix", s.mgmt.PutForceModelPrefix)

		mgmt.GET("/routing/strategy", s.mgmt.GetRoutingStrategy)
		mgmt.PUT("/routing/strategy", s.mgmt.PutRoutingStrategy)
		mgmt.PATCH("/routing/strategy", s.mgmt.PutRoutingStrategy)
		mgmt.GET("/routing/fill-first-range", s.mgmt.GetRoutingFillFirstRange)
		mgmt.PUT("/routing/fill-first-range", s.mgmt.PutRoutingFillFirstRange)
		mgmt.PATCH("/routing/fill-first-range", s.mgmt.PutRoutingFillFirstRange)
		mgmt.GET("/routing/fill-first-per-auth-rpm", s.mgmt.GetRoutingFillFirstPerAuthRPM)
		mgmt.PUT("/routing/fill-first-per-auth-rpm", s.mgmt.PutRoutingFillFirstPerAuthRPM)
		mgmt.PATCH("/routing/fill-first-per-auth-rpm", s.mgmt.PutRoutingFillFirstPerAuthRPM)
		mgmt.GET("/routing/per-auth-request-limit", s.mgmt.GetRoutingPerAuthRequestLimit)
		mgmt.PUT("/routing/per-auth-request-limit", s.mgmt.PutRoutingPerAuthRequestLimit)
		mgmt.PATCH("/routing/per-auth-request-limit", s.mgmt.PutRoutingPerAuthRequestLimit)
		mgmt.GET("/routing/per-auth-request-window-minutes", s.mgmt.GetRoutingPerAuthRequestWindowMinutes)
		mgmt.PUT("/routing/per-auth-request-window-minutes", s.mgmt.PutRoutingPerAuthRequestWindowMinutes)
		mgmt.PATCH("/routing/per-auth-request-window-minutes", s.mgmt.PutRoutingPerAuthRequestWindowMinutes)
		mgmt.GET("/routing/priority-overrides", s.mgmt.GetRoutingPriorityOverrides)
		mgmt.PUT("/routing/priority-overrides", s.mgmt.PutRoutingPriorityOverrides)
		mgmt.PATCH("/routing/priority-overrides", s.mgmt.PutRoutingPriorityOverrides)

		mgmt.GET("/claude-api-key", s.mgmt.GetClaudeKeys)
		mgmt.PUT("/claude-api-key", s.mgmt.PutClaudeKeys)
		mgmt.PATCH("/claude-api-key", s.mgmt.PatchClaudeKey)
		mgmt.DELETE("/claude-api-key", s.mgmt.DeleteClaudeKey)

		mgmt.GET("/xai-api-key", s.mgmt.GetXAIKeys)
		mgmt.PUT("/xai-api-key", s.mgmt.PutXAIKeys)
		mgmt.PATCH("/xai-api-key", s.mgmt.PatchXAIKey)
		mgmt.DELETE("/xai-api-key", s.mgmt.DeleteXAIKey)
		mgmt.GET("/codex-api-key", s.mgmt.GetCodexKeys)
		mgmt.PUT("/codex-api-key", s.mgmt.PutCodexKeys)
		mgmt.PATCH("/codex-api-key", s.mgmt.PatchCodexKey)
		mgmt.DELETE("/codex-api-key", s.mgmt.DeleteCodexKey)

		mgmt.GET("/openai-compatibility", s.mgmt.GetOpenAICompat)
		mgmt.PUT("/openai-compatibility", s.mgmt.PutOpenAICompat)
		mgmt.PATCH("/openai-compatibility", s.mgmt.PatchOpenAICompat)
		mgmt.DELETE("/openai-compatibility", s.mgmt.DeleteOpenAICompat)

		mgmt.GET("/vertex-api-key", s.mgmt.GetVertexCompatKeys)
		mgmt.PUT("/vertex-api-key", s.mgmt.PutVertexCompatKeys)
		mgmt.PATCH("/vertex-api-key", s.mgmt.PatchVertexCompatKey)
		mgmt.DELETE("/vertex-api-key", s.mgmt.DeleteVertexCompatKey)

		mgmt.GET("/oauth-excluded-models", s.mgmt.GetOAuthExcludedModels)
		mgmt.PUT("/oauth-excluded-models", s.mgmt.PutOAuthExcludedModels)
		mgmt.PATCH("/oauth-excluded-models", s.mgmt.PatchOAuthExcludedModels)
		mgmt.DELETE("/oauth-excluded-models", s.mgmt.DeleteOAuthExcludedModels)

		mgmt.GET("/oauth-request-scoped-errors", s.mgmt.GetOAuthRequestScopedErrors)
		mgmt.PUT("/oauth-request-scoped-errors", s.mgmt.PutOAuthRequestScopedErrors)
		mgmt.PATCH("/oauth-request-scoped-errors", s.mgmt.PatchOAuthRequestScopedErrors)
		mgmt.DELETE("/oauth-request-scoped-errors", s.mgmt.DeleteOAuthRequestScopedErrors)

		mgmt.GET("/oauth-model-alias", s.mgmt.GetOAuthModelAlias)
		mgmt.PUT("/oauth-model-alias", s.mgmt.PutOAuthModelAlias)
		mgmt.PATCH("/oauth-model-alias", s.mgmt.PatchOAuthModelAlias)
		mgmt.DELETE("/oauth-model-alias", s.mgmt.DeleteOAuthModelAlias)

		mgmt.GET("/auth-files", s.mgmt.ListAuthFiles)
		mgmt.GET("/auth-files/selection", s.mgmt.ListAuthFileSelection)
		mgmt.GET("/auth-files/models", s.mgmt.GetAuthFileModels)
		mgmt.POST("/auth-files/xai/models/refresh", s.mgmt.RefreshXAIModels)
		mgmt.POST("/auth-files/models/probe", s.mgmt.ProbeAuthFileModel)
		mgmt.GET("/model-definitions/:channel", s.mgmt.GetStaticModelDefinitions)
		mgmt.GET("/auth-files/download", s.mgmt.DownloadAuthFile)
		mgmt.POST("/auth-files/archive", s.mgmt.DownloadAuthFilesArchive)
		mgmt.POST("/auth-files", s.mgmt.UploadAuthFile)
		mgmt.DELETE("/auth-files", s.mgmt.DeleteAuthFile)
		mgmt.POST("/auth-files/restore", s.mgmt.RestoreAuthFile)
		mgmt.GET("/auth-files/codex/plan-type-refresh", s.mgmt.GetCodexPlanTypeRefreshStatus)
		mgmt.POST("/auth-files/codex/plan-type-refresh", s.mgmt.StartCodexPlanTypeRefresh)
		mgmt.PATCH("/auth-files/codex/plan-type-refresh", s.mgmt.ControlCodexPlanTypeRefresh)
		mgmt.DELETE("/auth-files/codex/plan-type-refresh", s.mgmt.ClearCodexPlanTypeRefresh)
		mgmt.POST("/codex/agent-identity/conversion-tasks", s.mgmt.StartCodexAgentIdentityConversionTask)
		mgmt.GET("/codex/agent-identity/conversion-tasks/:id", s.mgmt.GetCodexAgentIdentityConversionTask)
		mgmt.DELETE("/codex/agent-identity/conversion-tasks/:id", s.mgmt.CancelCodexAgentIdentityConversionTask)
		mgmt.POST("/auth-files/cooldowns/clear", s.mgmt.ClearAllAuthCooldowns)
		mgmt.POST("/auth-files/cooldowns/clear-selected", s.mgmt.ClearSelectedAuthCooldowns)
		mgmt.PATCH("/auth-files/status", s.mgmt.PatchAuthFileStatus)
		mgmt.PATCH("/auth-files/fields", s.mgmt.PatchAuthFileFields)
		mgmt.POST("/vertex/import", s.mgmt.ImportVertexCredential)
		mgmt.POST("/chatgpt-web/login-tasks", s.mgmt.StartChatGPTWebLoginTask)
		mgmt.GET("/chatgpt-web/login-tasks/:id", s.mgmt.GetChatGPTWebLoginTask)
		mgmt.DELETE("/chatgpt-web/login-tasks/:id", s.mgmt.CancelChatGPTWebLoginTask)
		mgmt.POST("/chatgpt-web/import-tasks", s.mgmt.StartChatGPTWebImportTask)
		mgmt.GET("/chatgpt-web/import-tasks/:id", s.mgmt.GetChatGPTWebImportTask)
		mgmt.DELETE("/chatgpt-web/import-tasks/:id", s.mgmt.CancelChatGPTWebImportTask)
		mgmt.GET("/chatgpt-web/capabilities", s.mgmt.GetChatGPTWebCapabilities)
		mgmt.GET("/chatgpt-web/library-cleanup", s.mgmt.GetChatGPTWebLibraryCleanup)
		mgmt.POST("/chatgpt-web/library-cleanup", s.mgmt.StartChatGPTWebLibraryCleanup)
		mgmt.DELETE("/chatgpt-web/library-cleanup/:id", s.mgmt.CancelChatGPTWebLibraryCleanup)
		mgmt.GET("/chatgpt-web/import", s.mgmt.GetChatGPTWebImport)
		mgmt.PUT("/chatgpt-web/import", s.mgmt.PutChatGPTWebImport)
		mgmt.PATCH("/chatgpt-web/import", s.mgmt.PatchChatGPTWebImport)
		mgmt.POST("/chatgpt-web/conversion-tasks", s.mgmt.StartChatGPTWebConversionTask)
		mgmt.GET("/chatgpt-web/conversion-tasks/:id", s.mgmt.GetChatGPTWebConversionTask)
		mgmt.DELETE("/chatgpt-web/conversion-tasks/:id", s.mgmt.CancelChatGPTWebConversionTask)
		mgmt.POST("/chatgpt-web/auth-files/:name/relogin", s.mgmt.ReloginChatGPTWebAuth)
		mgmt.POST("/chatgpt-web/auth-files/:name/relogin-operations", s.mgmt.StartChatGPTWebReloginOperation)
		mgmt.GET("/chatgpt-web/relogin-operations/:id", s.mgmt.GetChatGPTWebReloginOperation)
		mgmt.GET("/chatgpt-web/auth-files/:name/relogin-operation", s.mgmt.FindChatGPTWebReloginOperation)
		mgmt.GET("/chatgpt-web/auto-delete-dead/stats", s.mgmt.GetChatGPTWebAutoDeleteDeadStats)
		mgmt.GET("/chatgpt-web/image-tasks", s.mgmt.GetChatGPTWebImageTasks)
		mgmt.DELETE("/chatgpt-web/image-tasks/:id", s.mgmt.CancelChatGPTWebImageTask)
		mgmt.GET("/chatgpt-web/sentinel", s.mgmt.GetChatGPTWebSentinel)
		mgmt.GET("/runtime/capabilities", s.mgmt.GetRuntimeCapabilities)
		mgmt.GET("/sentinel-solver", s.mgmt.GetSentinelSolver)
		mgmt.PATCH("/sentinel-solver", s.mgmt.PatchSentinelSolver)
		mgmt.POST("/sentinel-solver/test-node", s.mgmt.TestSentinelNode)
		mgmt.PUT("/chatgpt-web/sentinel", s.mgmt.PutChatGPTWebSentinel)
		mgmt.PATCH("/chatgpt-web/sentinel", s.mgmt.PatchChatGPTWebSentinel)
		mgmt.GET("/chatgpt-web/account-info", s.mgmt.GetChatGPTWebAccountInfo)
		mgmt.PUT("/chatgpt-web/account-info", s.mgmt.PutChatGPTWebAccountInfo)
		mgmt.PATCH("/chatgpt-web/account-info", s.mgmt.PatchChatGPTWebAccountInfo)
		mgmt.GET("/chatgpt-web/account-info/diagnostics", s.mgmt.GetChatGPTWebAccountInfoDiagnostics)
		mgmt.DELETE("/chatgpt-web/account-info/diagnostics", s.mgmt.ClearChatGPTWebAccountInfoDiagnostics)
		mgmt.GET("/chatgpt-web/account-info/raw-quota-responses", s.mgmt.GetChatGPTWebAccountInfoRawQuotaResponses)
		mgmt.DELETE("/chatgpt-web/account-info/raw-quota-responses", s.mgmt.ClearChatGPTWebAccountInfoRawQuotaResponses)
		mgmt.POST("/chatgpt-web/account-info/refresh-tasks", s.mgmt.StartChatGPTWebAccountInfoRefreshTask)
		mgmt.GET("/chatgpt-web/account-info/refresh-tasks/:id", s.mgmt.GetChatGPTWebAccountInfoRefreshTask)
		mgmt.DELETE("/chatgpt-web/account-info/refresh-tasks/:id", s.mgmt.CancelChatGPTWebAccountInfoRefreshTask)
		mgmt.GET("/chatgpt-web/usage-cache", s.mgmt.GetChatGPTWebUsageCache)
		mgmt.PUT("/chatgpt-web/usage-cache", s.mgmt.PutChatGPTWebUsageCache)
		mgmt.PATCH("/chatgpt-web/usage-cache", s.mgmt.PatchChatGPTWebUsageCache)
		mgmt.GET("/chatgpt-web/login-proxy", s.mgmt.GetChatGPTWebLoginProxy)
		mgmt.PUT("/chatgpt-web/login-proxy", s.mgmt.PutChatGPTWebLoginProxy)
		mgmt.PATCH("/chatgpt-web/login-proxy", s.mgmt.PatchChatGPTWebLoginProxy)

		mgmt.GET("/anthropic-auth-url", s.mgmt.RequestAnthropicToken)
		mgmt.GET("/gemini-cli-auth-url", s.mgmt.RequestGeminiCLIToken)
		mgmt.GET("/codex-auth-url", s.mgmt.RequestCodexToken)
		mgmt.GET("/antigravity-auth-url", s.mgmt.RequestAntigravityToken)
		mgmt.GET("/kimi-auth-url", s.mgmt.RequestKimiToken)
		mgmt.GET("/xai-auth-url", s.mgmt.RequestXAIToken)
		mgmt.POST("/oauth-callback", s.mgmt.PostOAuthCallback)
		mgmt.GET("/get-auth-status", s.mgmt.GetAuthStatus)
		mgmt.DELETE("/oauth-session", s.mgmt.CancelAuthSession)
	}
}

func (s *Server) getStartupStatus(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, s.startupState.Snapshot())
}

func (s *Server) startupManagementMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		snapshot := s.startupState.Snapshot()
		if snapshot.Ready || (startupManagementMethodAvailable(c.Request.Method) && startupManagementPathAvailable(c.Request.URL.Path)) {
			c.Next()
			return
		}
		code, message := startupUnavailableResponse(snapshot)
		c.Header("Retry-After", "2")
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
			"error":         message,
			"code":          code,
			"startup_phase": snapshot.Phase,
		})
	}
}

func startupManagementMethodAvailable(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func startupUnavailableResponse(snapshot StartupSnapshot) (code, message string) {
	if snapshot.Status == StartupStatusFailed || snapshot.Phase == StartupPhaseFailed {
		return "service_startup_failed", "service startup failed"
	}
	return "service_initializing", "service is initializing"
}

func startupManagementPathAvailable(path string) bool {
	const marker = "/v0/management"
	if index := strings.LastIndex(path, marker); index >= 0 {
		managementPath := path[index+len(marker):]
		if strings.HasPrefix(managementPath, "/usage/prune/") ||
			strings.HasPrefix(managementPath, "/chatgpt-web/relogin-operations/") ||
			strings.HasSuffix(managementPath, "/relogin-operation") {
			return true
		}
	}
	for _, suffix := range []string{
		"/startup/status",
		"/config",
		"/config.yaml",
		"/system/metrics",
		"/storage/history",
		"/latest-version",
		"/control-panel/update",
		"/debug",
		"/pprof/config",
		"/pprof/enable",
		"/pprof/addr",
		"/logging-to-file",
		"/logs-max-total-size-mb",
		"/logs-retention-days",
		"/error-logs-max-files",
		"/usage-statistics-enabled",
		"/usage/storage-config",
		"/logs",
		"/logs/stream",
	} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func (s *Server) managementAvailabilityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !s.managementRoutesEnabled.Load() {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		c.Next()
	}
}

func (s *Server) serveManagementControlPanel(c *gin.Context) {
	cfg := s.currentConfig()
	if cfg == nil || cfg.RemoteManagement.DisableControlPanel {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	filePath := managementasset.FilePath(s.configFilePath)
	if strings.TrimSpace(filePath) == "" {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			// Synchronously ensure management.html is available with a detached context.
			// Control panel bootstrap should not be canceled by client disconnects.
			if !managementasset.EnsureLatestManagementHTML(context.Background(), managementasset.StaticDir(s.configFilePath), cfg.ProxyURL, cfg.RemoteManagement.PanelGitHubRepository) {
				c.AbortWithStatus(http.StatusNotFound)
				return
			}
		} else {
			log.WithError(err).Error("failed to stat management control panel asset")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	}

	s.managementPanel.ServeFile(c.Writer, c.Request, filePath)
}

func (s *Server) enableKeepAlive(timeout time.Duration, onTimeout func()) {
	if timeout <= 0 || onTimeout == nil {
		return
	}

	s.keepAliveEnabled = true
	s.keepAliveTimeout = timeout
	s.keepAliveOnTimeout = onTimeout
	s.keepAliveHeartbeat = make(chan struct{}, 1)
	s.keepAliveStop = make(chan struct{}, 1)

	s.engine.GET("/keep-alive", s.handleKeepAlive)

	go s.watchKeepAlive()
}

func (s *Server) handleKeepAlive(c *gin.Context) {
	if s.localPassword != "" {
		provided := strings.TrimSpace(c.GetHeader("Authorization"))
		if provided != "" {
			parts := strings.SplitN(provided, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
				provided = parts[1]
			}
		}
		if provided == "" {
			provided = strings.TrimSpace(c.GetHeader("X-Local-Password"))
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(s.localPassword)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
			return
		}
	}

	s.signalKeepAlive()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) signalKeepAlive() {
	if !s.keepAliveEnabled {
		return
	}
	select {
	case s.keepAliveHeartbeat <- struct{}{}:
	default:
	}
}

func (s *Server) watchKeepAlive() {
	if !s.keepAliveEnabled {
		return
	}

	timer := time.NewTimer(s.keepAliveTimeout)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			log.Warnf("keep-alive endpoint idle for %s, shutting down", s.keepAliveTimeout)
			if s.keepAliveOnTimeout != nil {
				s.keepAliveOnTimeout()
			}
			return
		case <-s.keepAliveHeartbeat:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(s.keepAliveTimeout)
		case <-s.keepAliveStop:
			return
		}
	}
}

// unifiedModelsHandler creates a unified handler for the /v1/models endpoint
// that routes to different handlers based on the User-Agent header.
// If User-Agent starts with "claude-cli", it routes to Claude handler,
// otherwise it routes to OpenAI handler.
func (s *Server) unifiedModelsHandler(openaiHandler *openai.OpenAIAPIHandler, claudeHandler *claude.ClaudeCodeAPIHandler) gin.HandlerFunc {
	return func(c *gin.Context) {
		userAgent := c.GetHeader("User-Agent")

		// Route to Claude handler if User-Agent starts with "claude-cli"
		if strings.HasPrefix(userAgent, "claude-cli") {
			// log.Debugf("Routing /v1/models to Claude handler for User-Agent: %s", userAgent)
			claudeHandler.ClaudeModels(c)
		} else {
			// log.Debugf("Routing /v1/models to OpenAI handler for User-Agent: %s", userAgent)
			openaiHandler.OpenAIModels(c)
		}
	}
}

// Start begins listening for and serving HTTP or HTTPS requests.
// It's a blocking call and will only return on an unrecoverable error.
//
// Returns:
//   - error: An error if the server fails to start
func (s *Server) Start() error {
	_, serverErr, errListen := s.StartListening()
	if errListen != nil {
		return errListen
	}
	return <-serverErr
}

// StartListening synchronously binds the configured socket and validates TLS
// material before starting Serve in the background. A successful return proves
// that the listener is owned by this server; callers can safely publish
// listener readiness without relying on a timing heuristic.
func (s *Server) StartListening() (net.Addr, <-chan error, error) {
	if s == nil || s.server == nil {
		return nil, nil, fmt.Errorf("failed to start HTTP server: server not initialized")
	}

	current := s.currentConfig()
	useTLS := current != nil && current.TLS.Enable
	cert := ""
	key := ""
	if useTLS {
		cert = strings.TrimSpace(current.TLS.Cert)
		key = strings.TrimSpace(current.TLS.Key)
		if cert == "" || key == "" {
			return nil, nil, fmt.Errorf("failed to start HTTPS server: tls.cert or tls.key is empty")
		}
		if _, errCertificate := tls.LoadX509KeyPair(cert, key); errCertificate != nil {
			return nil, nil, fmt.Errorf("failed to start HTTPS server: load TLS certificate: %w", errCertificate)
		}
	}

	listener, errListen := net.Listen("tcp", s.server.Addr)
	if errListen != nil {
		return nil, nil, fmt.Errorf("failed to bind API server on %s: %w", s.server.Addr, errListen)
	}
	if s.sentinelInitErr != nil {
		_ = listener.Close()
		return nil, nil, s.sentinelInitErr
	}
	if s.sentinelSolver != nil {
		if err := s.sentinelSolver.Start(listener.Addr().String()); err != nil {
			_ = listener.Close()
			return nil, nil, err
		}
	}
	serverErr := make(chan error, 1)
	go func() {
		var errServe error
		if useTLS {
			log.Debugf("Starting API server on %s with TLS", listener.Addr())
			errServe = s.server.ServeTLS(listener, cert, key)
		} else {
			log.Debugf("Starting API server on %s", listener.Addr())
			errServe = s.server.Serve(listener)
		}
		if errors.Is(errServe, http.ErrServerClosed) {
			errServe = nil
		}
		if errServe != nil {
			errServe = fmt.Errorf("API server stopped: %w", errServe)
		}
		serverErr <- errServe
	}()
	return listener.Addr(), serverErr, nil
}

// Stop gracefully shuts down the API server without interrupting any
// active connections.
//
// Parameters:
//   - ctx: The context for graceful shutdown
//
// Returns:
//   - error: An error if the server fails to stop
func (s *Server) Stop(ctx context.Context) error {
	log.Debug("Stopping API server...")
	solverDone := make(chan error, 1)
	if s.sentinelSolver != nil {
		go func() { solverDone <- s.sentinelSolver.Stop(ctx) }()
	} else {
		solverDone <- nil
	}
	if s.codexLive != nil {
		s.codexLive.Close()
	}

	if s.keepAliveEnabled {
		select {
		case s.keepAliveStop <- struct{}{}:
		default:
		}
	}

	// Cancel management-owned work while the HTTP server drains active requests.
	managementDone := make(chan error, 1)
	if s.mgmt != nil {
		go func() {
			managementDone <- s.mgmt.Shutdown(ctx)
		}()
	} else {
		managementDone <- nil
	}
	errSolver := <-solverDone
	// Stateful solver RPCs need the shared listener until the drain completes.
	errShutdown := s.server.Shutdown(ctx)
	errManagement := <-managementDone
	var shutdownErrors []error
	if errSolver != nil {
		shutdownErrors = append(shutdownErrors, fmt.Errorf("failed to shutdown solver: %w", errSolver))
	}
	if errShutdown != nil {
		shutdownErrors = append(shutdownErrors, fmt.Errorf("failed to shutdown HTTP server: %w", errShutdown))
	}
	if errManagement != nil {
		shutdownErrors = append(shutdownErrors, fmt.Errorf("failed to shutdown management tasks: %w", errManagement))
	}
	if len(shutdownErrors) > 0 {
		return errors.Join(shutdownErrors...)
	}

	log.Debug("API server stopped")
	return nil
}

// corsMiddleware returns a Gin middleware handler that adds CORS headers
// to every response, allowing cross-origin requests.
//
// Returns:
//   - gin.HandlerFunc: The CORS middleware handler
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "*")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func (s *Server) applyAccessConfig(oldCfg, newCfg *config.Config) error {
	if s == nil || s.accessManager == nil || newCfg == nil {
		return nil
	}
	if _, errApply := access.ApplyAccessProviders(s.accessManager, oldCfg, newCfg); errApply != nil {
		return errApply
	}
	return nil
}

// UpdateClients updates the server's client list and configuration.
// This method is called when the configuration or authentication tokens change.
//
// Parameters:
//   - clients: The new slice of AI service clients
//   - cfg: The new application configuration
func (s *Server) UpdateClients(cfg *config.Config) error {
	if s == nil {
		return errors.New("runtime configuration is unavailable")
	}
	if s.sentinelOnly {
		return s.updateSentinelOnlyClients(cfg)
	}
	s.configUpdateMu.Lock()
	defer s.configUpdateMu.Unlock()
	return s.updateClients(cfg, true)
}

func (s *Server) updateClients(cfg *config.Config, rollbackOnError bool) error {
	if s == nil || cfg == nil {
		return errors.New("runtime configuration is unavailable")
	}
	runtimeCfg, errClone := config.Clone(cfg)
	if errClone != nil {
		return errClone
	}
	if errSolverPath := runtimeCfg.ValidateSentinelSolver(); errSolverPath != nil {
		return errSolverPath
	}
	if errWeight := runtimeCfg.ValidateCredentialWeights(); errWeight != nil {
		return errWeight
	}
	if errRetry := runtimeCfg.ValidateCredentialRequestRetries(); errRetry != nil {
		return errRetry
	}
	if errRules := runtimeCfg.ValidateRequestScopedErrorRules(); errRules != nil {
		return errRules
	}
	if errModels := runtimeCfg.ValidateModelContextLengths(); errModels != nil {
		return errModels
	}
	if errThinking := runtimeCfg.ValidateModelThinking(); errThinking != nil {
		return errThinking
	}
	if errModalities := runtimeCfg.ValidateModelInputModalities(); errModalities != nil {
		return errModalities
	}
	// Reconstruct old config from YAML snapshot to avoid reference sharing issues
	var oldCfg *config.Config
	if len(s.oldConfigYaml) > 0 {
		_ = yaml.Unmarshal(s.oldConfigYaml, &oldCfg)
	}
	// The management access path determines Gin route registration and cannot
	// be replaced safely after the server starts. Service-owned updates already
	// preserve it; keep the same guarantee for direct embedded callers.
	if oldCfg != nil {
		runtimeCfg.RemoteManagement.AccessPath = oldCfg.RemoteManagement.AccessPath
	}
	// Record the attempted state before applying side effects. If a later step
	// fails, the rollback pass must compare the previous configuration against
	// the attempted one rather than against the last successful snapshot.
	nextConfigYAML, errMarshal := yaml.Marshal(runtimeCfg)
	if errMarshal != nil {
		return fmt.Errorf("snapshot API server runtime configuration: %w", errMarshal)
	}
	s.oldConfigYaml = nextConfigYAML
	rollback := func(errApply error) error {
		if !rollbackOnError || oldCfg == nil {
			return errApply
		}
		if errRollback := s.updateClients(oldCfg, false); errRollback != nil {
			return errors.Join(errApply, fmt.Errorf("rollback API server runtime configuration: %w", errRollback))
		}
		return errApply
	}

	// Update request logger enabled state if it has changed
	previousRequestLog := false
	if oldCfg != nil {
		previousRequestLog = oldCfg.RequestLog
	}
	if s.requestLogger != nil && (oldCfg == nil || previousRequestLog != runtimeCfg.RequestLog) {
		if s.loggerToggle != nil {
			s.loggerToggle(runtimeCfg.RequestLog)
		} else if toggler, ok := s.requestLogger.(interface{ SetEnabled(bool) }); ok {
			toggler.SetEnabled(runtimeCfg.RequestLog)
		}
	}

	if oldCfg == nil || oldCfg.LoggingToFile != runtimeCfg.LoggingToFile ||
		oldCfg.LogsMaxTotalSizeMB != runtimeCfg.LogsMaxTotalSizeMB ||
		oldCfg.LogsRetentionDays != runtimeCfg.LogsRetentionDays {
		if errLogOutput := logging.ConfigureLogOutput(runtimeCfg); errLogOutput != nil {
			return rollback(errLogOutput)
		}
	} else if oldCfg.RemoteManagement.LiveLogs.Enabled != runtimeCfg.RemoteManagement.LiveLogs.Enabled ||
		oldCfg.RemoteManagement.Diagnostics.ResolvedDetailLevel() != runtimeCfg.RemoteManagement.Diagnostics.ResolvedDetailLevel() {
		logging.ConfigureManagementDiagnostics(
			runtimeCfg.RemoteManagement.LiveLogs.Enabled,
			runtimeCfg.RemoteManagement.Diagnostics.ResolvedDetailLevel(),
		)
	}

	if oldCfg == nil || oldCfg.UsageStatisticsEnabled != runtimeCfg.UsageStatisticsEnabled {
		usage.SetStatisticsEnabled(runtimeCfg.UsageStatisticsEnabled)
	}

	if s.requestLogger != nil && (oldCfg == nil || oldCfg.ErrorLogsMaxFiles != runtimeCfg.ErrorLogsMaxFiles) {
		if setter, ok := s.requestLogger.(interface{ SetErrorLogsMaxFiles(int) }); ok {
			setter.SetErrorLogsMaxFiles(runtimeCfg.ErrorLogsMaxFiles)
		}
	}

	if oldCfg == nil || oldCfg.DisableCooling != runtimeCfg.DisableCooling {
		auth.SetQuotaCooldownDisabled(runtimeCfg.DisableCooling)
	}

	applySignatureCacheConfig(oldCfg, runtimeCfg)

	if s.handlers != nil && s.handlers.AuthManager != nil {
		s.handlers.AuthManager.SetRetryConfig(runtimeCfg.RequestRetry, time.Duration(runtimeCfg.MaxRetryInterval)*time.Second, runtimeCfg.MaxRetryCredentials)
		s.handlers.AuthManager.SetConfig(runtimeCfg)
	}

	// Update log level dynamically when debug flag changes
	if oldCfg == nil || oldCfg.Debug != runtimeCfg.Debug {
		util.SetLogLevel(runtimeCfg)
	}

	s.setCurrentConfig(runtimeCfg)
	if s.sentinelSolver != nil {
		if err := s.sentinelSolver.UpdateConfig(runtimeCfg.SentinelSolver); err != nil {
			return rollback(err)
		}
	}

	if errAccess := s.applyAccessConfig(oldCfg, runtimeCfg); errAccess != nil {
		return rollback(fmt.Errorf("update access providers: %w", errAccess))
	}
	s.wsAuthEnabled.Store(runtimeCfg.WebsocketAuth)
	if oldCfg != nil && s.wsAuthChanged != nil && oldCfg.WebsocketAuth != runtimeCfg.WebsocketAuth {
		s.wsAuthChanged(oldCfg.WebsocketAuth, runtimeCfg.WebsocketAuth)
	}
	managementasset.SetCurrentConfig(runtimeCfg)

	s.handlers.UpdateClients(sdkHandlerConfig(runtimeCfg))

	if s.mgmt != nil {
		if errManagement := s.mgmt.SetConfig(runtimeCfg); errManagement != nil {
			return rollback(fmt.Errorf("update management runtime configuration: %w", errManagement))
		}
		s.mgmt.SetAuthManager(s.handlers.AuthManager)
	}

	// Publish management availability only after the handler has the matching
	// authentication snapshot. This avoids a window where a newly enabled route
	// authenticates against the previous secret.
	previousManagementEnabled := s.managementRoutesEnabled.Load()
	newSecretEmpty := runtimeCfg.RemoteManagement.SecretKey == ""
	managementEnabled := s.envManagementSecret || s.localPassword != "" || !newSecretEmpty
	s.managementRoutesEnabled.Store(managementEnabled)
	if !previousManagementEnabled && managementEnabled {
		switch {
		case s.envManagementSecret:
			log.Info("management routes enabled via MANAGEMENT_PASSWORD")
		case s.localPassword != "":
			log.Info("management routes enabled via local password")
		default:
			log.Info("management routes enabled after secret key update")
		}
	} else if previousManagementEnabled && !managementEnabled {
		log.Info("management routes disabled after secret key removal")
	}

	// Publish Live admission only after fallible configuration updates complete.
	if s.codexLive != nil {
		s.codexLive.UpdateConfig(runtimeCfg)
	}

	// Count client sources from configuration and auth store.
	tokenStore := sdkAuth.GetTokenStore()
	if dirSetter, ok := tokenStore.(interface{ SetBaseDir(string) }); ok {
		dirSetter.SetBaseDir(runtimeCfg.AuthDir)
	}
	authEntries := 0
	if s.handlers != nil && s.handlers.AuthManager != nil {
		authEntries = s.handlers.AuthManager.Count()
	}
	geminiAPIKeyCount := len(runtimeCfg.GeminiKey)
	interactionsAPIKeyCount := len(runtimeCfg.InteractionsKey)
	claudeAPIKeyCount := len(runtimeCfg.ClaudeKey)
	codexAPIKeyCount := len(runtimeCfg.CodexKey)
	vertexAICompatCount := len(runtimeCfg.VertexCompatAPIKey)
	openAICompatCount := 0
	for i := range runtimeCfg.OpenAICompatibility {
		entry := runtimeCfg.OpenAICompatibility[i]
		if entry.Disabled {
			continue
		}
		openAICompatCount += len(entry.APIKeyEntries)
	}

	total := authEntries + geminiAPIKeyCount + interactionsAPIKeyCount + claudeAPIKeyCount + codexAPIKeyCount + vertexAICompatCount + openAICompatCount
	fmt.Printf("server clients and configuration updated: %d clients (%d auth entries + %d Gemini API keys + %d Interactions API keys + %d Claude API keys + %d Codex keys + %d Vertex-compat + %d OpenAI-compat)\n",
		total,
		authEntries,
		geminiAPIKeyCount,
		interactionsAPIKeyCount,
		claudeAPIKeyCount,
		codexAPIKeyCount,
		vertexAICompatCount,
		openAICompatCount,
	)
	return nil
}

// SetManagementConfig updates the management handler's persisted configuration
// snapshot after a service-owned runtime transaction succeeds.
func (s *Server) SetManagementConfig(cfg *config.Config) error {
	if s == nil || s.mgmt == nil {
		return nil
	}
	return s.mgmt.SetConfig(cfg)
}

func (s *Server) SetWebsocketAuthChangeHandler(fn func(bool, bool)) {
	if s == nil {
		return
	}
	s.wsAuthChanged = fn
}

// (management handlers moved to internal/api/handlers/management)

// AuthMiddleware returns a Gin middleware handler that authenticates requests
// using the configured authentication providers. When no providers are available,
// it allows all requests (legacy behaviour).
func AuthMiddleware(manager *sdkaccess.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		if manager == nil {
			c.Next()
			return
		}

		result, err := manager.Authenticate(c.Request.Context(), c.Request)
		if err == nil {
			if result != nil {
				c.Set("apiKey", result.Principal)
				c.Set("accessProvider", result.Provider)
				if len(result.Metadata) > 0 {
					c.Set("accessMetadata", result.Metadata)
				}
			}
			c.Next()
			return
		}

		statusCode := err.HTTPStatusCode()
		if statusCode >= http.StatusInternalServerError {
			log.Errorf("authentication middleware error: %v", err)
		}
		c.AbortWithStatusJSON(statusCode, gin.H{"error": err.Message})
	}
}

func configuredSignatureCacheEnabled(cfg *config.Config) bool {
	if cfg != nil && cfg.AntigravitySignatureCacheEnabled != nil {
		return *cfg.AntigravitySignatureCacheEnabled
	}
	return true
}

func applySignatureCacheConfig(oldCfg, cfg *config.Config) {
	newVal := configuredSignatureCacheEnabled(cfg)
	newStrict := configuredSignatureBypassStrict(cfg)
	if oldCfg == nil {
		cache.SetSignatureCacheEnabled(newVal)
		cache.SetSignatureBypassStrictMode(newStrict)
		return
	}

	oldVal := configuredSignatureCacheEnabled(oldCfg)
	if oldVal != newVal {
		cache.SetSignatureCacheEnabled(newVal)
	}

	oldStrict := configuredSignatureBypassStrict(oldCfg)
	if oldStrict != newStrict {
		cache.SetSignatureBypassStrictMode(newStrict)
	}
}

func configuredSignatureBypassStrict(cfg *config.Config) bool {
	if cfg != nil && cfg.AntigravitySignatureBypassStrict != nil {
		return *cfg.AntigravitySignatureBypassStrict
	}
	return false
}
