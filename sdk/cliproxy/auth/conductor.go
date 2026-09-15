package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	chatgptwebauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/chatgptweb"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/authfileguard"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	coreusage "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/usage"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"golang.org/x/sync/singleflight"
)

// ProviderExecutor defines the contract required by Manager to execute provider calls.
type ProviderExecutor interface {
	// Identifier returns the provider key handled by this executor.
	Identifier() string
	// Execute handles non-streaming execution and returns the provider response payload.
	Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error)
	// ExecuteStream handles streaming execution and returns a StreamResult containing
	// upstream headers and a channel of provider chunks.
	ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error)
	// Refresh attempts to refresh provider credentials and returns the updated auth state.
	Refresh(ctx context.Context, auth *Auth) (*Auth, error)
	// CountTokens returns the token count for the given request.
	CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error)
	// HttpRequest injects provider credentials into the supplied HTTP request and executes it.
	// Callers must close the response body when non-nil.
	HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error)
}

// ProviderRequestPreparer performs provider-specific deterministic work before
// auth selection and returns an immutable request-scoped execution plan.
type ProviderRequestPreparer interface {
	PrepareProviderRequest(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, operation cliproxyexecutor.RequestOperation) (any, error)
}

// DeferredAuthRequestCommitter marks executors that commit a selected auth
// request slot immediately before their first model upstream request.
type DeferredAuthRequestCommitter interface {
	DeferAuthRequestCommitUntilUpstream() bool
}

// DurableRefreshExecutor waits for provider-owned credential acquisition to
// finish after it starts, even if the initiating request stops waiting. The
// implementation must keep that acquisition bounded independently of request
// cancellation.
type DurableRefreshExecutor interface {
	RefreshToCompletion(ctx context.Context, auth *Auth) (*Auth, error)
}

// UnauthorizedRequestRefreshValidator validates a refreshed credential against
// an authenticated provider endpoint before it can re-enter request routing.
type UnauthorizedRequestRefreshValidator interface {
	ValidateUnauthorizedRequestRefresh(ctx context.Context, failedAccessToken string, previous, refreshed *Auth) (*Auth, error)
}

type backgroundReloginTrigger interface {
	TriggerBackgroundRelogin(expected *Auth) bool
}

// RequestAuthPreparer lets an executor fill required auth metadata immediately before execution.
type RequestAuthPreparer interface {
	ShouldPrepareRequestAuth(auth *Auth) bool
	PrepareRequestAuth(ctx context.Context, auth *Auth) (*Auth, error)
}

// UnauthorizedAuthRecoverer lets an executor repair narrowly classified
// authentication state before the request falls back to another credential.
type UnauthorizedAuthRecoverer interface {
	ShouldRecoverUnauthorized(auth *Auth, err error) bool
	RecoverUnauthorized(ctx context.Context, auth *Auth) (*Auth, error)
}

// ExecutionSessionCloser allows executors to release per-session runtime resources.
type ExecutionSessionCloser interface {
	CloseExecutionSession(sessionID string)
}

// AuthExecutionSessionCloser allows executors to release runtime resources for one auth.
type AuthExecutionSessionCloser interface {
	CloseAuthExecutionSessions(authID string, reason string)
}

// AuthInstanceExecutionSessionCloser allows executors to release runtime resources for one auth instance.
type AuthInstanceExecutionSessionCloser interface {
	CloseAuthInstanceExecutionSessions(authID string, authInstanceID string, reason string)
}

// PassiveAuthInstanceStateTracker reports auth state created without an execution binding.
type PassiveAuthInstanceStateTracker interface {
	HasPassiveAuthInstanceState(authID string, authInstanceID string) bool
}

const (
	// CloseAllExecutionSessionsID asks an executor to release all active execution sessions.
	// Executors that do not support this marker may ignore it.
	CloseAllExecutionSessionsID = "__all_execution_sessions__"
)

// RefreshEvaluator allows runtime state to override refresh decisions.
type RefreshEvaluator interface {
	ShouldRefresh(now time.Time, auth *Auth) bool
}

const (
	refreshCheckInterval           = 5 * time.Second
	refreshMaxConcurrency          = 16
	refreshPendingBackoff          = time.Minute
	refreshFailureBackoff          = 5 * time.Minute
	refreshShutdownTimeout         = 5 * time.Second
	refreshCommitTimeout           = 10 * time.Second
	refreshCommitAttempts          = 3
	chatGPTWebRefreshFlightTimeout = chatgptwebauth.DefaultAcquisitionTimeout +
		time.Duration(refreshCommitAttempts)*refreshCommitTimeout + 5*time.Second
	// refreshIneffectiveBackoff throttles refresh attempts when an executor returns
	// success but the auth still evaluates as needing refresh (e.g. token expiry
	// wasn't updated). Without this guard, the auto-refresh loop can tight-loop and
	// burn CPU at idle.
	refreshIneffectiveBackoff = 30 * time.Second
	quotaBackoffBase          = time.Second
	quotaBackoffMax           = 30 * time.Minute
)

const (
	cooldownScopeModel = "model"
	cooldownScopeAuth  = "auth"
)

var quotaCooldownDisabled atomic.Bool

// SetQuotaCooldownDisabled toggles quota cooldown scheduling globally.
func SetQuotaCooldownDisabled(disable bool) {
	quotaCooldownDisabled.Store(disable)
}

func quotaCooldownDisabledForAuth(auth *Auth) bool {
	if auth != nil {
		if override, ok := auth.DisableCoolingOverride(); ok {
			return override
		}
	}
	return quotaCooldownDisabled.Load()
}

func (m *Manager) currentConfig() *internalconfig.Config {
	if m == nil {
		return nil
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	return cfg
}

func (m *Manager) cooldownSkippedForStatus(statusCode int, contexts ...context.Context) bool {
	if m == nil || statusCode == 0 {
		return false
	}
	for _, code := range m.requestCooldownRules(contexts...).noCooldownStatusCodes {
		if code == statusCode {
			return true
		}
	}
	return false
}

type fixedErrorCooldownMatch struct {
	cooldown time.Duration
	scope    string
}

func (m *Manager) fixedErrorCooldownForResult(err *Error, contexts ...context.Context) (fixedErrorCooldownMatch, bool) {
	statusCode := statusCodeFromResult(err)
	if m == nil || err == nil {
		return fixedErrorCooldownMatch{}, false
	}
	rules := m.requestCooldownRules(contexts...).fixedErrorCooldowns
	if len(rules) == 0 {
		return fixedErrorCooldownMatch{}, false
	}
	errorText := fixedErrorCooldownMatchText(err)
	lowerText := strings.ToLower(errorText)
	for _, rule := range rules {
		if rule.StatusCode != 0 && rule.StatusCode != statusCode {
			continue
		}
		needle := strings.ToLower(strings.TrimSpace(rule.MessageContains))
		if rule.StatusCode == 0 && needle == "" {
			continue
		}
		if needle != "" && !strings.Contains(lowerText, needle) {
			continue
		}
		if rule.CooldownSeconds <= 0 {
			continue
		}
		scope := strings.ToLower(strings.TrimSpace(rule.Scope))
		switch scope {
		case "", cooldownScopeModel:
			scope = cooldownScopeModel
		case cooldownScopeAuth:
		default:
			continue
		}
		return fixedErrorCooldownMatch{
			cooldown: time.Duration(rule.CooldownSeconds) * time.Second,
			scope:    scope,
		}, true
	}
	return fixedErrorCooldownMatch{}, false
}

func fixedErrorCooldownMatchText(err *Error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Message)
	if message == "" {
		return ""
	}
	if parsed := gjson.Parse(message); parsed.Exists() {
		if value := strings.TrimSpace(parsed.Get("error.message").String()); value != "" {
			return value
		}
		if value := strings.TrimSpace(parsed.Get("message").String()); value != "" {
			return value
		}
	}
	return message
}

// Result captures execution outcome used to adjust auth state.
type Result struct {
	// AuthID references the auth that produced this result.
	AuthID string
	// Provider is copied for convenience when emitting hooks.
	Provider string
	// Model is the upstream model identifier used for the request.
	Model string
	// Success marks whether the execution succeeded.
	Success bool
	// RetryAfter carries a provider supplied retry hint (e.g. 429 retryDelay).
	RetryAfter *time.Duration
	// Error describes the failure when Success is false.
	Error *Error
}

type executionResult struct {
	Result
	authInstanceID          string
	additionalSuccessModels []string
	imageSuccessCount       int64
	imageSuccessModels      []string
	quotaProjectionOnly     bool
	availabilityNeutral     bool
}

func resultForAuth(auth *Auth, provider, model string, success bool) executionResult {
	result := executionResult{Result: Result{Provider: provider, Model: model, Success: success}}
	if auth != nil {
		result.AuthID = auth.ID
		result.authInstanceID = auth.instanceID
	}
	return result
}

func successfulExecutionResultForAuth(auth *Auth, provider, model string, opts cliproxyexecutor.Options) executionResult {
	result := resultForAuth(auth, provider, model, true)
	state, _ := opts.Metadata[cliproxyexecutor.ImageGenerationResultStateMetadataKey].(*cliproxyexecutor.ImageGenerationResultState)
	if state != nil && strings.EqualFold(strings.TrimSpace(provider), chatgptwebauth.Provider) {
		result.imageSuccessCount = state.TakeProducedCount()
		if result.imageSuccessCount == 0 && state.Succeeded() {
			result.imageSuccessCount = state.SucceededCount()
		}
	}
	if result.imageSuccessCount > 0 {
		result.imageSuccessModels = ChatGPTWebImageModelIDs(auth)
		for _, imageModel := range result.imageSuccessModels {
			if canonicalModelKey(model) != canonicalModelKey(imageModel) {
				result.additionalSuccessModels = append(result.additionalSuccessModels, imageModel)
			}
		}
	}
	return result
}

func imageQuotaProjectionResultForAuth(auth *Auth, provider, model string, opts cliproxyexecutor.Options) (executionResult, bool) {
	if !strings.EqualFold(strings.TrimSpace(provider), chatgptwebauth.Provider) {
		return executionResult{}, false
	}
	state, _ := opts.Metadata[cliproxyexecutor.ImageGenerationResultStateMetadataKey].(*cliproxyexecutor.ImageGenerationResultState)
	count := state.TakeProducedCount()
	if count <= 0 {
		return executionResult{}, false
	}
	result := resultForAuth(auth, provider, model, false)
	result.imageSuccessCount = count
	result.imageSuccessModels = ChatGPTWebImageModelIDs(auth)
	result.quotaProjectionOnly = true
	return result, true
}

func (m *Manager) projectFailedImageGenerationQuota(ctx context.Context, auth *Auth, provider, model string, opts cliproxyexecutor.Options) {
	if result, ok := imageQuotaProjectionResultForAuth(auth, provider, model, opts); ok {
		m.markExecutionResult(ctx, result)
	}
}

func executionResultModelForError(model string, err error) string {
	if err == nil {
		return model
	}
	type modelProvider interface {
		ExecutionResultModel() string
	}
	var target modelProvider
	if errors.As(err, &target) && target != nil {
		if override := strings.TrimSpace(target.ExecutionResultModel()); override != "" {
			return override
		}
	}
	return model
}

func executionResultErrorCode(err error) string {
	if err == nil {
		return ""
	}
	type codeProvider interface {
		ExecutionResultErrorCode() string
	}
	var target codeProvider
	if errors.As(err, &target) && target != nil {
		return strings.TrimSpace(target.ExecutionResultErrorCode())
	}
	if IsModelNotFoundError(err) {
		return "model_not_found"
	}
	return ""
}

// Selector chooses an auth candidate for execution.
type Selector interface {
	Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error)
}

// StoppableSelector is an optional interface for selectors that hold resources.
// Selectors that implement this interface will have Stop called during shutdown.
type StoppableSelector interface {
	Selector
	Stop()
}

// Hook captures lifecycle callbacks for observing auth changes.
type Hook interface {
	// OnAuthRegistered fires when a new auth is registered.
	OnAuthRegistered(ctx context.Context, auth *Auth)
	// OnAuthUpdated fires when an existing auth changes state.
	OnAuthUpdated(ctx context.Context, auth *Auth)
	// OnResult fires when execution result is recorded.
	OnResult(ctx context.Context, result Result)
}

// NoopHook provides optional hook defaults.
type NoopHook struct{}

// OnAuthRegistered implements Hook.
func (NoopHook) OnAuthRegistered(context.Context, *Auth) {}

// OnAuthUpdated implements Hook.
func (NoopHook) OnAuthUpdated(context.Context, *Auth) {}

// OnResult implements Hook.
func (NoopHook) OnResult(context.Context, Result) {}

type hookState struct {
	hook Hook
}

// Manager orchestrates auth lifecycle, selection, execution, and persistence.
type Manager struct {
	store     Store
	executors map[string]ProviderExecutor
	selector  Selector
	hookValue atomic.Value
	loadMu    sync.Mutex
	mu        sync.RWMutex
	auths     map[string]*Auth
	// backingPathAuthIDs indexes runtime auths by their normalized backing path.
	// All fields in this block are protected by mu and are updated atomically
	// with auths through installAuthLocked and removeAuthLocked.
	backingPathAuthIDs         map[string]map[string]struct{}
	backingPathByAuthID        map[string]string
	backingPathAuthDir         string
	providerAuthIDs            map[string]map[string]struct{}
	providerByAuthID           map[string]string
	providerPrefixedAuthIDs    map[string]map[string]struct{}
	providerRetryByAuthID      map[string]providerRequestRetryEntry
	providerRetryAggregates    map[string]*providerRequestRetryAggregate
	chatGPTWebImageBlockedIDs  map[string]string
	chatGPTWebImageQuotaChecks map[string]chatGPTWebImageQuotaCheck
	chatGPTWebImageQuotaHeap   chatGPTWebImageQuotaCheckHeap
	chatGPTWebQuotaGeneration  uint64
	authIndexesByID            map[string]string
	authIDsByIndex             map[string]map[string]struct{}
	managedFileAuthIDs         map[string]map[string]struct{}
	managedFileKeysByAuthID    map[string][]string
	managementAuthCatalog      map[string]*Auth
	usageAuthCatalog           map[string]UsageAuthInfo
	managementCatalogRevision  uint64
	authPlanTypesByID          map[string]string
	dependencyAuthsByID        map[string]*Auth
	dependencySourceIDs        map[string]map[string]struct{}
	dependencyDependentIDs     map[string]map[string]struct{}
	dependencyIndexComplete    bool
	chatGPTWebIdentityIDs      map[string]map[string]struct{}
	chatGPTWebIdentityKeysByID map[string][]string
	persistedAuthsByID         map[string]*Auth
	chatGPTWebIdentityComplete bool
	authIndexRevision          uint64
	// persistedAuthRevision changes only when the authoritative store view is
	// mutated or invalidated. Runtime-only status updates must not force an
	// expensive full-store refresh of the ChatGPT Web identity index.
	persistedAuthRevision uint64
	storeRevision         uint64
	scheduler             *authScheduler
	executionMetrics      *cliproxyexecutor.RequestExecutionMetrics
	// executorLifecycleMu serializes registry changes with executor shutdown.
	executorLifecycleMu sync.Mutex
	executorCloseCond   *sync.Cond
	executorCloseWG     sync.WaitGroup
	refreshFlightWG     sync.WaitGroup
	executorCloseSealed bool
	executorCloseFinal  bool
	executorSealedClose int
	executorShutdownSet []ProviderExecutor
	executorAsyncErr    error
	executorsClosed     bool
	executorsCloseDone  chan struct{}
	executorsCloseErr   error
	// sessionCleanups quarantines auth IDs while stale executor sessions are being closed.
	sessionCleanups  map[string]int
	maintenanceAuths map[string]*authMaintenanceState
	libraryCleanup   *LibraryCleanupManager
	// sessionCleanupInstances tracks retired instances until their auth ID leaves quarantine.
	sessionCleanupInstances map[string]map[*authInstanceState]struct{}
	// providerOffsets tracks per-model provider rotation state for multi-provider routing.
	providerOffsets map[string]int

	// Retry settings are published together and captured at request entry.
	retryConfig atomic.Pointer[retrySettingsSnapshot]

	// oauthModelAlias stores global OAuth model alias mappings (alias -> upstream name) keyed by channel.
	oauthModelAlias atomic.Value

	// apiKeyModelRouting publishes aliases and capabilities from one config.
	apiKeyModelRouting atomic.Pointer[apiKeyModelRoutingSnapshot]

	// modelPoolOffsets tracks per-auth alias pool rotation state.
	modelPoolOffsets map[string]int

	// runtimeConfig stores the latest application config for request-time decisions.
	// It is initialized in NewManager; never Load() before first Store().
	runtimeConfig   atomic.Value
	routingPolicy   atomic.Pointer[routingRequestPolicy]
	routingUpdateMu sync.Mutex

	// Optional HTTP RoundTripper provider injected by host.
	rtProviderMu     sync.RWMutex
	rtProvider       RoundTripperProvider
	rtProviderClosed bool
	// Optional structured proxy resolver injected by the host service.
	proxyResolver ProxyResolver

	// Auto refresh state
	refreshCancel      context.CancelFunc
	refreshLoop        *authAutoRefreshLoop
	refreshExecutions  map[*authInstanceState]map[chan struct{}]struct{}
	refreshCleanupWait time.Duration
	// requestRefreshLocks serializes request-time provider refreshes by auth ID.
	requestRefreshLocksMu           sync.Mutex
	requestRefreshLocks             sync.Map
	requestRefreshFlights           singleflight.Group
	requestPrepareFlights           singleflight.Group
	chatGPTWebRefreshMu             sync.Mutex
	chatGPTWebRefreshes             map[string]*chatGPTWebRequestRefreshFlight
	chatGPTWebRequestRefreshMetrics chatGPTWebRequestRefreshMetrics

	// persistLocks serializes store operations per auth ID.
	persistBarrier              sync.RWMutex
	persistBarrierTurnstileOnce sync.Once
	persistBarrierTurnstile     chan struct{}
	// persistBarrierReadObserved is used by concurrency tests to observe reader intent.
	persistBarrierReadObserved   func()
	persistLocks                 sync.Map
	chatGPTWebDependencyMutation contextMutex
	// persistedSnapshotRefresh serializes authoritative store enumeration. The
	// first waiter refreshes the incremental indexes; later waiters reuse them.
	persistedSnapshotRefresh contextMutex
	// refreshApplyObserved is used by refresh tests to pause before durable commit.
	refreshApplyObserved func(string)
	// refreshCommitAttemptTimeout and refreshCommitMaxAttempts override commit policy in tests.
	refreshCommitAttemptTimeout time.Duration
	refreshCommitMaxAttempts    int
	// refreshCommitRetryObserved is used by tests to observe a failed commit attempt.
	refreshCommitRetryObserved func(string, int)
	refreshPersistence         atomic.Pointer[refreshPersistenceCoordinator]
	resultPersistence          *resultPersistenceCoordinator
	resultMutationLocks        [resultPersistenceLockStripes]sync.Mutex
	resultProducerMu           sync.Mutex
	resultProducers            map[*resultPersistenceProducer]struct{}
	resultProducerClosing      bool
	resultProducerWaitTimeout  time.Duration
	resultProducerCancelWait   time.Duration
	resultProducerWaitTimeouts uint64
	resultProducerCancelLimits uint64
	resultProducerAbandoned    uint64
	// refreshFlightWaitObserved is used by shutdown tests to observe the executor close barrier.
	refreshFlightWaitObserved func()
	// schedulerRouteRefreshMu coalesces the rare registry/scheduler repair path.
	schedulerRouteRefreshMu       sync.Mutex
	schedulerRouteRefreshedAt     map[string]time.Time
	schedulerRouteRefreshObserved func(string, int)
	// prioritySelectors stores built-in legacy selectors used by per-priority overrides.
	prioritySelectors sync.Map
}

type requestRetryBudgetContextKey struct{}

type requestRetryBudget struct {
	remaining atomic.Int64
}

type requestRoundState struct {
	tried               map[string]struct{}
	attempted           map[string]struct{}
	attemptedByPriority map[int]map[string]struct{}
	blockedProviders    map[string]struct{}
	lastErr             error
	lastErrAuthID       string
}

type runtimeExecutionResponseBody struct {
	io.ReadCloser
	release          func() bool
	once             sync.Once
	retiredAtRelease bool
}

func (b *runtimeExecutionResponseBody) finish() bool {
	if b == nil {
		return false
	}
	b.once.Do(func() {
		if b.release != nil {
			b.retiredAtRelease = b.release()
		}
	})
	return b.retiredAtRelease
}

func (b *runtimeExecutionResponseBody) Read(p []byte) (int, error) {
	n, errRead := b.ReadCloser.Read(p)
	if errRead != nil && b.finish() && !errors.Is(errRead, io.EOF) {
		return n, runtimeAuthInstanceRetiredError()
	}
	return n, errRead
}

func (b *runtimeExecutionResponseBody) Close() (err error) {
	defer b.finish()
	return b.ReadCloser.Close()
}

func runtimeAuthInstanceRetiredError() *Error {
	return &Error{Code: "auth_instance_retired", Message: "selected auth instance was replaced or removed", HTTPStatus: http.StatusServiceUnavailable, Retryable: true}
}

func isRuntimeAuthInstanceRetiredError(err error) bool {
	var authErr *Error
	return errors.As(err, &authErr) && authErr != nil && authErr.Code == "auth_instance_retired"
}

func releaseRetiredAuthRequestSlot(opts cliproxyexecutor.Options) {
	if opts.AuthRequestSlot != nil {
		opts.AuthRequestSlot.Release()
	}
}

func runtimeAuthInstanceRetiredContext(ctx context.Context) bool {
	return ctx != nil && errors.Is(context.Cause(ctx), errRuntimeAuthInstanceRetired)
}

func newRequestRoundState() *requestRoundState {
	return &requestRoundState{
		tried:               make(map[string]struct{}),
		attempted:           make(map[string]struct{}),
		attemptedByPriority: make(map[int]map[string]struct{}),
		blockedProviders:    make(map[string]struct{}),
	}
}

func (s *requestRoundState) ensure() *requestRoundState {
	if s == nil {
		return newRequestRoundState()
	}
	if s.tried == nil {
		s.tried = make(map[string]struct{})
	}
	if s.attempted == nil {
		s.attempted = make(map[string]struct{})
	}
	if s.attemptedByPriority == nil {
		s.attemptedByPriority = make(map[int]map[string]struct{})
	}
	if s.blockedProviders == nil {
		s.blockedProviders = make(map[string]struct{})
	}
	return s
}

func (s *requestRoundState) blockProvider(provider string) {
	if s == nil {
		return
	}
	s = s.ensure()
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider != "" {
		s.blockedProviders[provider] = struct{}{}
	}
}

func (s *requestRoundState) providerBlocked(provider string) bool {
	if s == nil {
		return false
	}
	s = s.ensure()
	_, blocked := s.blockedProviders[strings.ToLower(strings.TrimSpace(provider))]
	return blocked
}

func (s *requestRoundState) markAttempted(auth *Auth) {
	if s == nil || auth == nil || auth.ID == "" {
		return
	}
	s = s.ensure()
	priority := authPriority(auth)
	s.attempted[auth.ID] = struct{}{}
	attempted := s.attemptedByPriority[priority]
	if attempted == nil {
		attempted = make(map[string]struct{})
		s.attemptedByPriority[priority] = attempted
	}
	attempted[auth.ID] = struct{}{}
}

func (s *requestRoundState) setLastError(auth *Auth, err error) {
	if s == nil {
		return
	}
	s.lastErr = withAuthErrorResponseSource(err, auth, "")
	s.lastErrAuthID = ""
	if auth != nil {
		s.lastErrAuthID = auth.ID
	}
}

func (s *requestRoundState) forgetRetiredAttempt(auth *Auth) {
	if s == nil || auth == nil || auth.ID == "" {
		return
	}
	s = s.ensure()
	delete(s.tried, auth.ID)
	delete(s.attempted, auth.ID)
	for priority, attempted := range s.attemptedByPriority {
		delete(attempted, auth.ID)
		if len(attempted) == 0 {
			delete(s.attemptedByPriority, priority)
		}
	}
}

func waitForRetiredAuthInstanceCleanup(ctx context.Context, auth *Auth) error {
	if auth == nil || !auth.RuntimeInstanceRetired() {
		return nil
	}
	done := auth.RuntimeInstanceCleanupDone()
	if done == nil {
		return nil
	}
	if ctx == nil {
		<-done
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *requestRoundState) attemptedCountAtPriority(priority int) int {
	if s == nil {
		return 0
	}
	s = s.ensure()
	return len(s.attemptedByPriority[priority])
}

// NewManager constructs a manager with optional custom selector and hook.
func NewManager(store Store, selector Selector, hook Hook) *Manager {
	if selector == nil {
		selector = &RoundRobinSelector{}
	}
	if hook == nil {
		hook = NoopHook{}
	}
	manager := &Manager{
		store:                       store,
		executors:                   make(map[string]ProviderExecutor),
		selector:                    selector,
		auths:                       make(map[string]*Auth),
		backingPathAuthIDs:          make(map[string]map[string]struct{}),
		backingPathByAuthID:         make(map[string]string),
		providerAuthIDs:             make(map[string]map[string]struct{}),
		providerByAuthID:            make(map[string]string),
		providerPrefixedAuthIDs:     make(map[string]map[string]struct{}),
		providerRetryByAuthID:       make(map[string]providerRequestRetryEntry),
		providerRetryAggregates:     make(map[string]*providerRequestRetryAggregate),
		chatGPTWebImageBlockedIDs:   make(map[string]string),
		chatGPTWebImageQuotaChecks:  make(map[string]chatGPTWebImageQuotaCheck),
		authIndexesByID:             make(map[string]string),
		authIDsByIndex:              make(map[string]map[string]struct{}),
		managedFileAuthIDs:          make(map[string]map[string]struct{}),
		managedFileKeysByAuthID:     make(map[string][]string),
		managementAuthCatalog:       make(map[string]*Auth),
		usageAuthCatalog:            make(map[string]UsageAuthInfo),
		managementCatalogRevision:   1,
		authPlanTypesByID:           make(map[string]string),
		dependencyAuthsByID:         make(map[string]*Auth),
		dependencySourceIDs:         make(map[string]map[string]struct{}),
		dependencyDependentIDs:      make(map[string]map[string]struct{}),
		chatGPTWebIdentityIDs:       make(map[string]map[string]struct{}),
		chatGPTWebIdentityKeysByID:  make(map[string][]string),
		persistedAuthsByID:          make(map[string]*Auth),
		storeRevision:               1,
		sessionCleanups:             make(map[string]int),
		sessionCleanupInstances:     make(map[string]map[*authInstanceState]struct{}),
		refreshExecutions:           make(map[*authInstanceState]map[chan struct{}]struct{}),
		refreshCleanupWait:          refreshShutdownTimeout,
		refreshCommitAttemptTimeout: refreshCommitTimeout,
		refreshCommitMaxAttempts:    refreshCommitAttempts,
		schedulerRouteRefreshedAt:   make(map[string]time.Time),
		providerOffsets:             make(map[string]int),
		modelPoolOffsets:            make(map[string]int),
	}
	manager.executorCloseWG.Add(1)
	manager.executorCloseCond = sync.NewCond(&manager.executorLifecycleMu)
	manager.hookValue.Store(hookState{hook: hook})
	// atomic.Value requires non-nil initial value.
	manager.runtimeConfig.Store(&internalconfig.Config{})
	manager.routingPolicy.Store(newRoutingRequestPolicy(manager, selector, internalconfig.RoutingConfig{FillFirstRange: fillFirstRangeFromSelector(selector)}))
	manager.apiKeyModelRouting.Store(&apiKeyModelRoutingSnapshot{config: manager.currentConfig()})
	manager.scheduler = newAuthScheduler(selector)
	manager.executionMetrics = &cliproxyexecutor.RequestExecutionMetrics{}
	manager.refreshPersistence.Store(newRefreshPersistenceCoordinator(store))
	manager.resultPersistence = newResultPersistenceCoordinator(manager)
	manager.resultProducers = make(map[*resultPersistenceProducer]struct{})
	manager.resultProducerWaitTimeout = resultPersistenceProducerWaitTimeout
	manager.resultProducerCancelWait = resultPersistenceProducerCancelTimeout
	return manager
}

// RequestExecutionMetrics returns process-local model request boundary metrics.
func (m *Manager) RequestExecutionMetrics() cliproxyexecutor.RequestExecutionMetricsSnapshot {
	if m == nil {
		return cliproxyexecutor.RequestExecutionMetricsSnapshot{}
	}
	return m.executionMetrics.Snapshot()
}

// RoutingDiagnostics returns a read-only availability snapshot for one
// provider/model shard without cloning credential material.
func (m *Manager) RoutingDiagnostics(provider, model string, now time.Time) RoutingDiagnosticsSnapshot {
	if m == nil || m.scheduler == nil {
		return RoutingDiagnosticsSnapshot{
			Provider:   strings.ToLower(strings.TrimSpace(provider)),
			Model:      canonicalModelKey(model),
			Priorities: make([]RoutingPriorityDiagnostics, 0),
		}
	}
	return m.scheduler.RoutingDiagnostics(provider, model, now)
}

func isBuiltInSelector(selector Selector) bool {
	switch selector.(type) {
	case *RoundRobinSelector, *FillFirstSelector, *RandomSelector, *WeightedRoundRobinSelector:
		return true
	default:
		return false
	}
}

func (m *Manager) syncSchedulerFromSnapshot(auths []*Auth) {
	if m == nil || m.scheduler == nil {
		return
	}
	m.scheduler.rebuild(auths)
}

func (m *Manager) syncScheduler() {
	if m == nil || m.scheduler == nil {
		return
	}
	m.syncSchedulerFromSnapshot(m.snapshotAuths())
}

const (
	schedulerRouteRefreshInterval   = 30 * time.Second
	schedulerRouteRefreshMaxEntries = 1024
)

// refreshSchedulerRoute repairs only auth entries whose registered model set
// is newer than the scheduler snapshot. A pick failure caused by cooldown or
// request saturation is not evidence that every credential changed, so it must
// not trigger a full credential clone and rebuild.
func (m *Manager) refreshSchedulerRoute(providers []string, model string) {
	if m == nil || m.scheduler == nil {
		return
	}
	providerKeys := normalizeProviderKeys(providers)
	modelKey := canonicalModelKey(model)
	if len(providerKeys) == 0 || modelKey == "" {
		return
	}
	sort.Strings(providerKeys)
	key := strings.Join(providerKeys, ",") + ":" + modelKey
	registryRef := registry.GetGlobalRegistry()
	registeredProviders := registryRef.GetModelProviders(modelKey)
	registeredProviderSet := make(map[string]struct{}, len(registeredProviders))
	for _, providerKey := range registeredProviders {
		registeredProviderSet[strings.ToLower(strings.TrimSpace(providerKey))] = struct{}{}
	}
	providerRegistered := false
	for _, providerKey := range providerKeys {
		if _, ok := registeredProviderSet[providerKey]; ok {
			providerRegistered = true
			break
		}
	}
	if !providerRegistered {
		return
	}

	m.schedulerRouteRefreshMu.Lock()
	defer m.schedulerRouteRefreshMu.Unlock()
	now := time.Now()
	if refreshedAt := m.schedulerRouteRefreshedAt[key]; !refreshedAt.IsZero() && now.Sub(refreshedAt) < schedulerRouteRefreshInterval {
		return
	}

	supported := m.scheduler.authIDsSupportingModel(providerKeys, modelKey)
	candidates := make([]string, 0)
	m.mu.RLock()
	for _, providerKey := range providerKeys {
		for authID := range m.providerAuthIDs[providerKey] {
			if _, ok := supported[authID]; ok {
				continue
			}
			auth := m.auths[authID]
			if auth == nil || auth.Disabled || m.authSelectionBlockedLocked(authID) {
				continue
			}
			candidates = append(candidates, authID)
		}
	}
	m.mu.RUnlock()
	sort.Strings(candidates)

	refreshed := 0
	for _, authID := range candidates {
		models := registryRef.GetModelsForClient(authID)
		for _, registeredModel := range models {
			if registeredModel != nil && canonicalModelKey(registeredModel.ID) == modelKey {
				m.RefreshSchedulerEntry(authID)
				refreshed++
				break
			}
		}
	}
	m.rememberSchedulerRouteRefreshLocked(key, now)
	if m.schedulerRouteRefreshObserved != nil {
		m.schedulerRouteRefreshObserved(key, refreshed)
	}
}

func (m *Manager) rememberSchedulerRouteRefreshLocked(key string, now time.Time) {
	if m.schedulerRouteRefreshedAt == nil {
		m.schedulerRouteRefreshedAt = make(map[string]time.Time)
	}
	for cachedKey, refreshedAt := range m.schedulerRouteRefreshedAt {
		if refreshedAt.IsZero() || now.Sub(refreshedAt) >= schedulerRouteRefreshInterval {
			delete(m.schedulerRouteRefreshedAt, cachedKey)
		}
	}
	if _, exists := m.schedulerRouteRefreshedAt[key]; !exists && len(m.schedulerRouteRefreshedAt) >= schedulerRouteRefreshMaxEntries {
		oldestKey := ""
		var oldestAt time.Time
		for cachedKey, refreshedAt := range m.schedulerRouteRefreshedAt {
			if oldestKey == "" || refreshedAt.Before(oldestAt) {
				oldestKey = cachedKey
				oldestAt = refreshedAt
			}
		}
		delete(m.schedulerRouteRefreshedAt, oldestKey)
	}
	m.schedulerRouteRefreshedAt[key] = now
}

func (m *Manager) snapshotAuths() []*Auth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Auth, 0, len(m.auths))
	for _, a := range m.auths {
		out = append(out, a.Clone())
	}
	return out
}

// RefreshSchedulerEntry re-upserts a single auth into the scheduler so that its
// supportedModelSet is rebuilt from the current global model registry state.
// This must be called after models have been registered for a newly added auth,
// because the initial scheduler.upsertAuth during Register/Update runs before
// registerModelsForAuth and therefore snapshots an empty model set.
func (m *Manager) RefreshSchedulerEntry(authID string) {
	if m == nil || m.scheduler == nil || authID == "" {
		return
	}
	m.mu.RLock()
	auth, ok := m.auths[authID]
	if !ok || auth == nil {
		m.mu.RUnlock()
		return
	}
	snapshot := auth.Clone()
	m.mu.RUnlock()
	m.scheduler.upsertAuth(snapshot)
}

// ClearModelCooldownByReason resets one model state only when it was created
// for the supplied quota reason. Other model failures remain untouched.
func (m *Manager) ClearModelCooldownByReason(ctx context.Context, authID, model, reason string) bool {
	if m == nil || strings.TrimSpace(authID) == "" || strings.TrimSpace(model) == "" || strings.TrimSpace(reason) == "" {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	unlockMutation, errLock := m.lockAuthIDMutationContext(context.WithoutCancel(ctx), authID)
	if errLock != nil {
		logEntryWithRequestID(ctx).WithField("auth_id", authID).Warnf("failed to lock model cooldown mutation: %v", errLock)
		return false
	}
	defer unlockMutation()

	modelKey := canonicalModelKey(model)
	reason = strings.TrimSpace(reason)
	var persistAuth *Auth
	now := time.Now()

	m.mu.Lock()
	auth := m.auths[authID]
	if clearModelCooldownByReasonOnAuth(auth, modelKey, reason, now) {
		persistAuth = auth
		m.updateManagementAuthCatalogLocked(auth)
	}
	m.mu.Unlock()
	if persistAuth == nil {
		return false
	}

	snapshot, errPersist := m.snapshotCurrentAuthForPersistenceLocked(ctx, persistAuth)
	if errPersist != nil {
		logEntryWithRequestID(ctx).WithField("auth_id", authID).Warnf("failed to persist cleared model cooldown: %v", errPersist)
	}
	if m.scheduler != nil && snapshot != nil {
		m.scheduler.upsertAuth(snapshot)
	}
	registry.GetGlobalRegistry().ClearModelQuotaExceeded(authID, model)
	registry.GetGlobalRegistry().ResumeClientModel(authID, model)
	return true
}

func clearModelCooldownByReasonOnAuth(auth *Auth, modelKey, reason string, now time.Time) bool {
	if auth == nil {
		return false
	}
	for stateModel, state := range auth.ModelStates {
		if state == nil || canonicalModelKey(stateModel) != modelKey || !strings.EqualFold(strings.TrimSpace(state.Quota.Reason), reason) {
			continue
		}
		resetModelState(state, now)
		updateAggregatedAvailability(auth, now)
		if !hasModelError(auth, now) && !hasActiveAuthWideCooldown(auth, now) {
			auth.LastError = nil
			auth.StatusMessage = ""
			auth.Status = StatusActive
		}
		auth.UpdatedAt = now
		return true
	}
	return false
}

// ReconcileRegistryModelStates aligns per-model runtime state with the current
// registry snapshot for one auth.
//
// Supported models are reset to a clean state because re-registration already
// cleared the registry-side cooldown/suspension snapshot. ModelStates for
// models that are no longer present in the registry are pruned entirely so
// renamed/removed models cannot keep auth-level status stale.
func (m *Manager) ReconcileRegistryModelStates(ctx context.Context, authID string) {
	m.reconcileRegistryModelStates(ctx, authID, nil, true)
}

// PruneRegistryModelStates removes state for models that are no longer
// registered while preserving state for overlapping model IDs.
func (m *Manager) PruneRegistryModelStates(ctx context.Context, authID string) {
	m.reconcileRegistryModelStates(ctx, authID, nil, false)
}

// ReconcileRegistryModelStatesIfCurrent aligns model state only when expected
// still identifies the current auth installation.
func (m *Manager) ReconcileRegistryModelStatesIfCurrent(ctx context.Context, expected *Auth) bool {
	if expected == nil {
		return false
	}
	return m.reconcileRegistryModelStates(ctx, expected.ID, expected, true)
}

// PruneRegistryModelStatesIfCurrent prunes model state only when expected still
// identifies the current auth installation.
func (m *Manager) PruneRegistryModelStatesIfCurrent(ctx context.Context, expected *Auth) bool {
	if expected == nil {
		return false
	}
	return m.reconcileRegistryModelStates(ctx, expected.ID, expected, false)
}

func (m *Manager) reconcileRegistryModelStates(ctx context.Context, authID string, expected *Auth, resetSupported bool) bool {
	if m == nil || authID == "" {
		return false
	}

	supportedModels := registry.GetGlobalRegistry().GetModelsForClient(authID)
	supported := make(map[string]struct{}, len(supportedModels))
	for _, model := range supportedModels {
		if model == nil {
			continue
		}
		modelKey := canonicalModelKey(model.ID)
		if modelKey == "" {
			continue
		}
		supported[modelKey] = struct{}{}
	}

	var (
		snapshot    *Auth
		persistAuth *Auth
	)
	now := time.Now()

	m.mu.Lock()
	auth, ok := m.auths[authID]
	if expected != nil && !requestPreparationMatchesCurrent(auth, expected) {
		m.mu.Unlock()
		return false
	}
	if ok && auth != nil && len(auth.ModelStates) > 0 {
		changed := false
		for modelKey, state := range auth.ModelStates {
			baseModel := canonicalModelKey(modelKey)
			if baseModel == "" {
				baseModel = strings.TrimSpace(modelKey)
			}
			if _, supportedModel := supported[baseModel]; !supportedModel {
				// Drop state for models that disappeared from the current registry
				// snapshot. Keeping them around leaks stale errors into auth-level
				// status, management output, and websocket fallback checks.
				delete(auth.ModelStates, modelKey)
				changed = true
				continue
			}
			if !resetSupported || state == nil {
				continue
			}
			if modelStateIsClean(state) {
				continue
			}
			resetModelState(state, now)
			changed = true
		}
		if len(auth.ModelStates) == 0 {
			auth.ModelStates = nil
		}
		if changed {
			updateAggregatedAvailability(auth, now)
			if !hasModelError(auth, now) {
				auth.LastError = nil
				auth.StatusMessage = ""
				auth.Status = StatusActive
			}
			auth.UpdatedAt = now
			persistAuth = auth
			m.updateManagementAuthCatalogLocked(auth)
		}
	}
	m.mu.Unlock()

	if persistAuth != nil {
		var errPersist error
		snapshot, errPersist = m.snapshotCurrentAuthForPersistence(ctx, persistAuth)
		if errPersist != nil {
			logEntryWithRequestID(ctx).WithField("auth_id", persistAuth.ID).Warnf("failed to persist auth changes during model state reconciliation: %v", errPersist)
		}
	}

	if m.scheduler != nil && snapshot != nil {
		m.scheduler.upsertAuth(snapshot)
	}
	return true
}

func (m *Manager) SetSelector(selector Selector) {
	if m == nil {
		return
	}
	m.routingUpdateMu.Lock()
	defer m.routingUpdateMu.Unlock()
	if selector == nil {
		selector = &RoundRobinSelector{}
	}
	m.mu.Lock()
	previousSelector := m.selector
	m.selector = selector
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	routing := internalconfig.RoutingConfig{}
	if cfg != nil {
		routing = cfg.Routing
	}
	routing.FillFirstRange = fillFirstRangeFromSelector(selector)
	policy := newRoutingRequestPolicy(m, selector, routing)
	policy.observeCodexQuota = cfg != nil && cfg.Codex.ObserveQuota
	if previous := m.routingPolicy.Load(); previous != nil {
		policy.oauthErrorRules = previous.oauthErrorRules
		policy.clientKeyPriorities = previous.clientKeyPriorities
	}
	m.routingPolicy.Store(policy)
	m.mu.Unlock()
	if m.scheduler != nil {
		m.scheduler.setSelector(selector)
		m.syncScheduler()
	}
	stopReplacedSessionCacheMaintenance(previousSelector, selector)
}

// Hook returns the currently configured lifecycle hook.
func (m *Manager) Hook() Hook {
	if m == nil {
		return NoopHook{}
	}
	state, _ := m.hookValue.Load().(hookState)
	if state.hook == nil {
		return NoopHook{}
	}
	return state.hook
}

// SetHook replaces the lifecycle hook used for auth callbacks.
func (m *Manager) SetHook(hook Hook) {
	if m == nil {
		return
	}
	if hook == nil {
		hook = NoopHook{}
	}
	m.hookValue.Store(hookState{hook: hook})
}

type chainedHook struct {
	hooks []Hook
}

func (h chainedHook) OnAuthRegistered(ctx context.Context, auth *Auth) {
	for _, hook := range h.hooks {
		if hook != nil {
			hook.OnAuthRegistered(ctx, auth)
		}
	}
}

func (h chainedHook) OnAuthUpdated(ctx context.Context, auth *Auth) {
	for _, hook := range h.hooks {
		if hook != nil {
			hook.OnAuthUpdated(ctx, auth)
		}
	}
}

func (h chainedHook) OnResult(ctx context.Context, result Result) {
	for _, hook := range h.hooks {
		if hook != nil {
			hook.OnResult(ctx, result)
		}
	}
}

// AddHook appends another lifecycle hook without replacing the existing one.
func (m *Manager) AddHook(hook Hook) {
	if m == nil || hook == nil {
		return
	}
	current := m.Hook()
	if _, ok := current.(NoopHook); ok {
		m.SetHook(hook)
		return
	}
	if chained, ok := current.(chainedHook); ok {
		hooks := append([]Hook(nil), chained.hooks...)
		hooks = append(hooks, hook)
		m.SetHook(chainedHook{hooks: hooks})
		return
	}
	m.SetHook(chainedHook{hooks: []Hook{current, hook}})
}

// SetStore swaps the underlying persistence store.
func (m *Manager) SetStore(store Store) {
	unlockBarrier, errBarrier := m.lockPersistBarrierWrite(context.Background())
	if errBarrier != nil {
		return
	}
	defer unlockBarrier()
	m.mu.Lock()
	m.store = store
	previousCoordinator := m.refreshPersistence.Swap(newRefreshPersistenceCoordinator(store))
	m.storeRevision++
	m.rebuildAuthIndexesLocked(nil, false)
	m.mu.Unlock()
	previousCoordinator.close()
}

// SetRoundTripperProvider register a provider that returns a per-auth RoundTripper.
func (m *Manager) SetRoundTripperProvider(p RoundTripperProvider) {
	m.rtProviderMu.Lock()
	defer m.rtProviderMu.Unlock()
	m.mu.Lock()
	m.rtProvider = p
	m.rtProviderClosed = false
	m.mu.Unlock()
}

// SetConfig updates the runtime config snapshot used by request-time helpers.
// Callers should provide the latest config on reload so per-credential alias mapping stays in sync.
func (m *Manager) SetConfig(cfg *internalconfig.Config) {
	if m == nil {
		return
	}
	if cfg.ValidateAPIKeyPriorities() != nil {
		log.Warn("ignoring invalid client API key priority configuration")
		return
	}
	if errModels := cfg.ValidateModelContextLengths(); errModels != nil {
		log.WithError(errModels).Warn("ignoring invalid model context length configuration")
		return
	}
	if errThinking := cfg.ValidateModelThinking(); errThinking != nil {
		log.WithError(errThinking).Warn("ignoring invalid model thinking configuration")
		return
	}
	if errModalities := cfg.ValidateModelInputModalities(); errModalities != nil {
		log.WithError(errModalities).Warn("ignoring invalid model input modalities configuration")
		return
	}
	if errRules := cfg.ValidateRequestScopedErrorRules(); errRules != nil {
		log.WithError(errRules).Warn("ignoring invalid request-scoped error configuration")
		return
	}
	m.routingUpdateMu.Lock()
	defer m.routingUpdateMu.Unlock()
	m.setConfigLocked(cfg)
}

// SetConfigAndSelector publishes one complete routing policy during service reload.
// Existing request snapshots keep their selector and priority rules together.
func (m *Manager) SetConfigAndSelector(cfg *internalconfig.Config, selector Selector) {
	if m == nil {
		return
	}
	if cfg.ValidateAPIKeyPriorities() != nil {
		log.Warn("ignoring invalid client API key priority configuration")
		return
	}
	if errModels := cfg.ValidateModelContextLengths(); errModels != nil {
		log.WithError(errModels).Warn("ignoring invalid model context length configuration")
		return
	}
	if errThinking := cfg.ValidateModelThinking(); errThinking != nil {
		log.WithError(errThinking).Warn("ignoring invalid model thinking configuration")
		return
	}
	if errModalities := cfg.ValidateModelInputModalities(); errModalities != nil {
		log.WithError(errModalities).Warn("ignoring invalid model input modalities configuration")
		return
	}
	if errRules := cfg.ValidateRequestScopedErrorRules(); errRules != nil {
		log.WithError(errRules).Warn("ignoring invalid request-scoped error configuration")
		return
	}
	m.routingUpdateMu.Lock()
	defer m.routingUpdateMu.Unlock()
	if selector == nil {
		selector = &RoundRobinSelector{}
	}
	if m.scheduler != nil {
		m.scheduler.setSelector(selector)
	}
	m.mu.Lock()
	previousSelector := m.selector
	m.selector = selector
	m.mu.Unlock()
	m.setConfigLocked(cfg)
	if m.scheduler != nil {
		m.syncScheduler()
	}
	stopReplacedSessionCacheMaintenance(previousSelector, selector)
}

// setConfigLocked requires routingUpdateMu.
func (m *Manager) setConfigLocked(cfg *internalconfig.Config) {
	if cfg == nil {
		cfg = &internalconfig.Config{}
	}
	// Both public configuration setters validate before publishing any state.
	oauthErrorRules, _ := cfg.CompileOAuthRequestScopedErrors()
	if m.scheduler != nil {
		m.scheduler.setRoutingConfig(cfg.Routing)
	}
	m.mu.Lock()
	m.runtimeConfig.Store(cfg)
	m.rebuildAPIKeyModelAliasLocked(cfg)
	policy := newRoutingRequestPolicy(m, m.selector, cfg.Routing)
	policy.observeCodexQuota = cfg.Codex.ObserveQuota
	policy.oauthErrorRules = oauthErrorRules
	policy.clientKeyPriorities = compileClientKeyPriorities(cfg)
	m.routingPolicy.Store(policy)
	if m.backingPathAuthDir != strings.TrimSpace(cfg.AuthDir) {
		m.rebuildBackingPathIndexLocked(cfg)
	}
	m.mu.Unlock()
}

func (m *Manager) lookupAPIKeyUpstreamModel(authID, requestedModel string, snapshots ...*apiKeyModelRoutingSnapshot) string {
	if m == nil {
		return ""
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return ""
	}
	requestedModel = strings.TrimSpace(requestedModel)
	if requestedModel == "" {
		return ""
	}
	table := m.modelRoutingForAttempt(snapshots).aliases
	if table == nil {
		return ""
	}
	byAlias := table[authID]
	if len(byAlias) == 0 {
		return ""
	}
	key := strings.ToLower(thinking.ParseSuffix(requestedModel).ModelName)
	if key == "" {
		key = strings.ToLower(requestedModel)
	}
	resolved := strings.TrimSpace(byAlias[key])
	if resolved == "" {
		return ""
	}
	return preserveRequestedModelSuffix(requestedModel, resolved)
}

func isAPIKeyAuth(auth *Auth) bool {
	if auth == nil {
		return false
	}
	kind, _ := auth.AccountInfo()
	return strings.EqualFold(strings.TrimSpace(kind), "api_key")
}

func isOpenAICompatAPIKeyAuth(auth *Auth) bool {
	if !isAPIKeyAuth(auth) {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(auth.Provider), "openai-compatibility") {
		return true
	}
	if auth.Attributes == nil {
		return false
	}
	return strings.TrimSpace(auth.Attributes["compat_name"]) != ""
}

func openAICompatProviderKey(auth *Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Attributes != nil {
		if providerKey := strings.TrimSpace(auth.Attributes["provider_key"]); providerKey != "" {
			return strings.ToLower(providerKey)
		}
		if compatName := strings.TrimSpace(auth.Attributes["compat_name"]); compatName != "" {
			return strings.ToLower(compatName)
		}
	}
	return strings.ToLower(strings.TrimSpace(auth.Provider))
}

func openAICompatModelPoolKey(auth *Auth, requestedModel string) string {
	base := strings.TrimSpace(thinking.ParseSuffix(requestedModel).ModelName)
	if base == "" {
		base = strings.TrimSpace(requestedModel)
	}
	return strings.ToLower(strings.TrimSpace(auth.ID)) + "|" + openAICompatProviderKey(auth) + "|" + strings.ToLower(base)
}

func (m *Manager) nextModelPoolOffset(key string, size int) int {
	if m == nil || size <= 1 {
		return 0
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.modelPoolOffsets == nil {
		m.modelPoolOffsets = make(map[string]int)
	}
	offset := m.modelPoolOffsets[key]
	if offset >= 2_147_483_640 {
		offset = 0
	}
	m.modelPoolOffsets[key] = offset + 1
	if size <= 0 {
		return 0
	}
	return offset % size
}

func rotateStrings(values []string, offset int) []string {
	if len(values) <= 1 {
		return values
	}
	if offset <= 0 {
		out := make([]string, len(values))
		copy(out, values)
		return out
	}
	offset = offset % len(values)
	out := make([]string, 0, len(values))
	out = append(out, values[offset:]...)
	out = append(out, values[:offset]...)
	return out
}

func (m *Manager) resolveOpenAICompatUpstreamModelPool(auth *Auth, requestedModel string, snapshots ...*apiKeyModelRoutingSnapshot) []string {
	if m == nil || !isOpenAICompatAPIKeyAuth(auth) {
		return nil
	}
	requestedModel = strings.TrimSpace(requestedModel)
	if requestedModel == "" {
		return nil
	}
	cfg := m.modelRoutingForAttempt(snapshots).config
	if cfg == nil {
		cfg = &internalconfig.Config{}
	}
	providerKey := ""
	compatName := ""
	if auth.Attributes != nil {
		providerKey = strings.TrimSpace(auth.Attributes["provider_key"])
		compatName = strings.TrimSpace(auth.Attributes["compat_name"])
	}
	entry := resolveOpenAICompatConfig(cfg, providerKey, compatName, auth.Provider)
	if entry == nil {
		return nil
	}
	return resolveModelAliasPoolFromConfigModels(requestedModel, asModelAliasEntries(entry.Models))
}

func preserveRequestedModelSuffix(requestedModel, resolved string) string {
	return preserveResolvedModelSuffix(resolved, thinking.ParseSuffix(requestedModel))
}

func (m *Manager) executionModelCandidates(auth *Auth, executionRouteModel string, snapshots ...*apiKeyModelRoutingSnapshot) []string {
	routing := m.modelRoutingForAttempt(snapshots)
	requestedModel := rewriteModelForAuth(executionRouteModel, auth)
	requestedModel = m.applyOAuthModelAlias(auth, requestedModel)
	if pool := m.resolveOpenAICompatUpstreamModelPool(auth, requestedModel, routing); len(pool) > 0 {
		if len(pool) == 1 {
			return pool
		}
		offset := m.nextModelPoolOffset(openAICompatModelPoolKey(auth, requestedModel), len(pool))
		return rotateStrings(pool, offset)
	}
	resolved := m.applyAPIKeyModelAlias(auth, requestedModel, routing)
	if strings.TrimSpace(resolved) == "" {
		resolved = requestedModel
	}
	return []string{resolved}
}

func (m *Manager) selectionModelForAuth(auth *Auth, routeModel string) string {
	requestedModel := rewriteModelForAuth(routeModel, auth)
	if strings.TrimSpace(requestedModel) == "" {
		requestedModel = strings.TrimSpace(routeModel)
	}
	resolvedModel := m.applyOAuthModelAlias(auth, requestedModel)
	if strings.TrimSpace(resolvedModel) == "" {
		resolvedModel = requestedModel
	}
	return resolvedModel
}

func (m *Manager) selectionModelKeyForAuth(auth *Auth, routeModel string) string {
	return canonicalModelKey(m.selectionModelForAuth(auth, routeModel))
}

func (m *Manager) stateModelForExecution(auth *Auth, routeModel, upstreamModel string, pooled bool) string {
	stateModel := executionResultModel(routeModel, upstreamModel, pooled)
	selectionModel := m.selectionModelForAuth(auth, routeModel)
	if canonicalModelKey(selectionModel) == canonicalModelKey(upstreamModel) && strings.TrimSpace(selectionModel) != "" {
		return strings.TrimSpace(upstreamModel)
	}
	return stateModel
}

func executionResultModel(routeModel, upstreamModel string, pooled bool) string {
	if pooled {
		if resolved := strings.TrimSpace(upstreamModel); resolved != "" {
			return resolved
		}
	}
	if requested := strings.TrimSpace(routeModel); requested != "" {
		return requested
	}
	return strings.TrimSpace(upstreamModel)
}

func (m *Manager) filterExecutionModels(auth *Auth, routeModel string, candidates []string, pooled bool) []string {
	if len(candidates) == 0 {
		return nil
	}
	now := time.Now()
	out := make([]string, 0, len(candidates))
	for _, upstreamModel := range candidates {
		stateModel := m.stateModelForExecution(auth, routeModel, upstreamModel, pooled)
		blocked, _, _ := isAuthBlockedForModel(auth, stateModel, now)
		if blocked {
			continue
		}
		out = append(out, upstreamModel)
	}
	return out
}

func (m *Manager) preparedExecutionModels(auth *Auth, routeModel string, opts cliproxyexecutor.Options) ([]string, bool) {
	candidates := m.executionModelCandidates(auth, effectiveExecutionRouteModel(routeModel, opts))
	pooled := len(candidates) > 1
	return m.filterExecutionModels(auth, routeModel, candidates, pooled), pooled
}

func (m *Manager) preparedExecutionModelsWithAlias(auth *Auth, routeModel string, opts cliproxyexecutor.Options) ([]string, bool, OAuthModelAliasResult, *apiKeyModelRoutingSnapshot) {
	routing := m.loadAPIKeyModelRouting()
	executionRouteModel := effectiveExecutionRouteModel(routeModel, opts)
	candidates := m.executionModelCandidates(auth, executionRouteModel, routing)
	pooled := len(candidates) > 1
	models := m.filterExecutionModels(auth, routeModel, candidates, pooled)
	return models, pooled, m.resolveExecutionAliasResult(auth, executionRouteModel, routing), routing
}

func (m *Manager) resolveExecutionAliasResult(auth *Auth, executionRouteModel string, snapshots ...*apiKeyModelRoutingSnapshot) OAuthModelAliasResult {
	requestedModel := rewriteModelForAuth(executionRouteModel, auth)
	if isAPIKeyAuth(auth) {
		return m.resolveAPIKeyModelAliasWithResult(auth, requestedModel, snapshots...)
	}
	return m.applyOAuthModelAliasWithResult(auth, requestedModel)
}

func (m *Manager) prepareExecutionModels(auth *Auth, routeModel string, opts cliproxyexecutor.Options) []string {
	models, _ := m.preparedExecutionModels(auth, routeModel, opts)
	return models
}

func rewriteForceMappedResponse(resp *cliproxyexecutor.Response, aliasResult OAuthModelAliasResult) {
	if resp == nil || !aliasResult.ForceMapping || strings.TrimSpace(aliasResult.OriginalAlias) == "" {
		return
	}
	resp.Payload = rewriteModelInResponse(resp.Payload, aliasResult.OriginalAlias)
}

func rewriteForceMappedStreamChunk(rewriter *StreamRewriter, payload []byte) []byte {
	if rewriter == nil || len(payload) == 0 {
		return payload
	}
	rewritten := rewriter.RewriteChunk(payload)
	if len(rewritten) > 0 {
		return rewritten
	}
	if len(rewriter.pendingBuf) > 0 {
		return nil
	}
	if bytes.Contains(payload, []byte("data:")) {
		if lineWise := rewriteSSEPayloadLines(payload, rewriter.options.RewriteModel); len(lineWise) > 0 {
			return lineWise
		}
	}
	return payload
}

func finishForceMappedStreamChunks(rewriter *StreamRewriter) []byte {
	if rewriter == nil {
		return nil
	}
	return rewriter.Finish()
}

func (m *Manager) availableAuthsForRouteModel(auths []*Auth, provider, routeModel string, opts cliproxyexecutor.Options, now time.Time) ([]*Auth, error) {
	auths = m.weightedEligibleAuths(auths)
	return selectAvailableAuthsForAttempt(auths, provider, routeModel, now, selectionAttemptFromMetadata(opts.Metadata), func(auth *Auth) string {
		return m.selectionModelForAuth(auth, routeModel)
	})
}

func (m *Manager) availableAuthsForRouteModelFiltered(auths []*Auth, provider, routeModel string, opts cliproxyexecutor.Options, now time.Time, pickAllowed func(*Auth) bool) ([]*Auth, error) {
	auths = m.weightedEligibleAuths(auths)
	return selectAvailableAuthsForAttemptFiltered(auths, provider, routeModel, now, selectionAttemptFromMetadata(opts.Metadata), func(auth *Auth) string {
		return m.selectionModelForAuth(auth, routeModel)
	}, pickAllowed)
}

func (m *Manager) availableAuthsForRouteModelFilteredForContext(ctx context.Context, auths []*Auth, provider, routeModel string, opts cliproxyexecutor.Options, now time.Time, pickAllowed func(*Auth) bool) ([]*Auth, error) {
	return m.availableAuthsForRouteModelWithPreference(ctx, auths, provider, routeModel, opts, now, pickAllowed, "")
}

func (m *Manager) availableAuthsForRouteModelWithPreference(ctx context.Context, auths []*Auth, provider, routeModel string, opts cliproxyexecutor.Options, now time.Time, pickAllowed func(*Auth) bool, preferred string) ([]*Auth, error) {
	auths = m.weightedEligibleAuths(auths, ctx)
	if shouldPreferCodexWebsocket(ctx, provider) {
		websocketAuths := make([]*Auth, 0, len(auths))
		hasReadyWebsocket := false
		for _, auth := range auths {
			if !authWebsocketsEnabled(auth) {
				continue
			}
			websocketAuths = append(websocketAuths, auth)
			checkModel := m.selectionModelForAuth(auth, routeModel)
			blocked, _, _ := isAuthBlockedForModel(auth, checkModel, now)
			if !blocked && (pickAllowed == nil || pickAllowed(auth)) {
				hasReadyWebsocket = true
			}
		}
		if hasReadyWebsocket {
			return selectAvailableAuthsForAttemptFilteredWithPriority(websocketAuths, provider, routeModel, now, selectionAttemptFromMetadata(opts.Metadata), func(auth *Auth) string {
				return m.selectionModelForAuth(auth, routeModel)
			}, pickAllowed, false, preferred)
		}
	}
	return selectAvailableAuthsForAttemptFilteredWithPriority(auths, provider, routeModel, now, selectionAttemptFromMetadata(opts.Metadata), func(auth *Auth) string {
		return m.selectionModelForAuth(auth, routeModel)
	}, pickAllowed, true, preferred)
}

// Keep bound selection separate from fallback tier selection. A bound auth can
// have different routing and limiter rules than the tier used after failover.
func (m *Manager) pickBoundAcrossPriorities(ctx context.Context, auths []*Auth, provider, model string, opts cliproxyexecutor.Options, now time.Time, pickAllowed func(*Auth) bool) (*Auth, bool, error) {
	selector, ok := m.selectorForContext(ctx).(*SessionAffinitySelector)
	if !ok || selector == nil || !selector.acrossPriorities {
		return nil, false, nil
	}
	preferred := selector.cachedAuthID(provider, model, opts, ctx)
	if preferred == "" {
		return nil, false, nil
	}
	available, err := m.availableAuthsForRouteModelWithPreference(ctx, auths, provider, model, opts, now, pickAllowed, preferred)
	if err != nil || len(available) != 1 || available[0].ID != preferred {
		return nil, false, nil
	}
	bound := available[0]
	priority := authPriority(bound)
	if m.routingStrategyForPriority(priority, ctx) == schedulerStrategyFillFirst && m.routingAuthRequestLimitPolicyForAuth(bound).limit == 0 {
		rpm := m.routingFillFirstPerAuthRPMForPriority(priority, ctx)
		if rpm > 0 && !m.fillFirstLimiter().tryAcquireAt(bound.ID, rpm, now) {
			if !selector.failover && selector.cachedStrictAuthID(ctx, provider, model, opts) == bound.ID {
				return nil, true, newAuthRPMLimitedError(fillFirstRPMRetryAfterAt(m.fillFirstLimiter(), now))
			}
			return nil, false, nil
		}
	}
	return bound, true, nil
}

func selectionArgForSelector(selector Selector, routeModel string) string {
	if isBuiltInSelector(selector) {
		return ""
	}
	return routeModel
}

func (m *Manager) routingStrategyOverrideForPriority(priority int, contexts ...context.Context) (schedulerStrategy, bool) {
	if p := m.selectionPolicy(contexts...); p != nil {
		strategy, ok := p.strategies[priority]
		return strategy, ok
	}
	if m == nil {
		return schedulerStrategyRoundRobin, false
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		return schedulerStrategyRoundRobin, false
	}
	for _, override := range cfg.Routing.PriorityOverrides {
		if override.Priority != priority || strings.TrimSpace(override.Strategy) == "" {
			continue
		}
		strategy, ok := schedulerStrategyFromName(override.Strategy)
		return strategy, ok
	}
	return schedulerStrategyRoundRobin, false
}

func (m *Manager) routingFillFirstRangeOverrideForPriority(priority int) (int, bool) {
	if m == nil {
		return 1, false
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		return 1, false
	}
	for _, override := range cfg.Routing.PriorityOverrides {
		if override.Priority != priority || override.FillFirstRange == nil {
			continue
		}
		return normalizeFillFirstRangeValue(*override.FillFirstRange), true
	}
	return 1, false
}

func (m *Manager) routingFillFirstRangeForPriority(priority int, contexts ...context.Context) int {
	if p := m.selectionPolicy(contexts...); p != nil {
		return p.rangeForPriority(priority)
	}
	if m == nil {
		return 1
	}
	if value, ok := m.routingFillFirstRangeOverrideForPriority(priority); ok {
		return value
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		return 1
	}
	return normalizeFillFirstRangeValue(cfg.Routing.FillFirstRange)
}

func (m *Manager) routingFillFirstPerAuthRPMOverrideForPriority(priority int) (int, bool) {
	if m == nil {
		return 0, false
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		return 0, false
	}
	for _, override := range cfg.Routing.PriorityOverrides {
		if override.Priority != priority || override.FillFirstPerAuthRPM == nil {
			continue
		}
		return normalizeFillFirstPerAuthRPMValue(*override.FillFirstPerAuthRPM), true
	}
	return 0, false
}

func (m *Manager) routingFillFirstPerAuthRPMForPriority(priority int, contexts ...context.Context) int {
	if p := m.selectionPolicy(contexts...); p != nil {
		return p.rpmForPriority(priority)
	}
	if m == nil {
		return 0
	}
	if value, ok := m.routingFillFirstPerAuthRPMOverrideForPriority(priority); ok {
		return value
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		return 0
	}
	return normalizeFillFirstPerAuthRPMValue(cfg.Routing.FillFirstPerAuthRPM)
}

func (m *Manager) fillFirstLimiter() *fillFirstMinuteLimiter {
	if m == nil || m.scheduler == nil {
		return nil
	}
	return m.scheduler.fillFirstLimiter
}

func (m *Manager) routingAuthRequestLimitPolicyForPriority(priority int) authRequestLimitPolicy {
	if m == nil {
		return normalizeAuthRequestLimitPolicy(authRequestLimitPolicy{})
	}
	if m.scheduler != nil {
		return m.scheduler.requestLimitPolicyForPriority(priority)
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		return normalizeAuthRequestLimitPolicy(authRequestLimitPolicy{})
	}
	return authRequestLimitPolicyForRouting(cfg.Routing, priority)
}

func (m *Manager) routingAuthRequestLimitPolicyForAuth(auth *Auth) authRequestLimitPolicy {
	if m == nil {
		return normalizeAuthRequestLimitPolicy(authRequestLimitPolicy{})
	}
	if m.scheduler != nil {
		return m.scheduler.requestLimitPolicyForAuth(auth)
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		return normalizeAuthRequestLimitPolicy(authRequestLimitPolicy{})
	}
	return authRequestLimitPolicyForRoutingAuth(cfg.Routing, auth)
}

func (m *Manager) authRequestLimiter() *authRequestWindowLimiter {
	if m == nil || m.scheduler == nil {
		return nil
	}
	return m.scheduler.requestLimiter
}

func preferAuthRequestLimitError(err error, block authRequestLimitBlock) error {
	if !block.limited() {
		return err
	}
	if resetIn, isAvailabilityBlocker := availabilityBlockerResetIn(err); isAvailabilityBlocker {
		if resetIn <= block.resetIn {
			return err
		}
		return newAuthRequestLimitedError(block)
	}
	var authErr *Error
	if err == nil || (errors.As(err, &authErr) && authErr != nil && (authErr.Code == "auth_not_found" || authErr.Code == "auth_unavailable" || authErr.Code == "session_bound_auth_unavailable")) {
		return newAuthRequestLimitedError(block)
	}
	return err
}

func availabilityBlockerResetIn(err error) (time.Duration, bool) {
	var requestLimitErr *authRequestLimitedError
	if errors.As(err, &requestLimitErr) && requestLimitErr != nil {
		return requestLimitErr.resetIn, true
	}
	var cooldownErr *modelCooldownError
	if errors.As(err, &cooldownErr) && cooldownErr != nil {
		return cooldownErr.resetIn, true
	}
	var rpmLimitErr *authRPMLimitedError
	if errors.As(err, &rpmLimitErr) && rpmLimitErr != nil {
		return rpmLimitErr.resetIn, true
	}
	if statusCodeFromError(err) == http.StatusTooManyRequests {
		if retryAfter := retryAfterFromError(err); retryAfter != nil && *retryAfter > 0 {
			return *retryAfter, true
		}
	}
	return 0, false
}

func earlierAvailabilityBlocker(current, candidate error) error {
	candidateReset, candidateOK := availabilityBlockerResetIn(candidate)
	if !candidateOK {
		return current
	}
	currentReset, currentOK := availabilityBlockerResetIn(current)
	if !currentOK || candidateReset < currentReset {
		return candidate
	}
	return current
}

func (m *Manager) preferEarlierRoundAvailabilityError(selectionErr error, roundState *requestRoundState) error {
	if roundState == nil || roundState.lastErr == nil {
		return selectionErr
	}
	if roundState.lastErrAuthID != "" {
		auth, ok := m.GetByID(roundState.lastErrAuthID)
		if !ok || auth == nil {
			return selectionErr
		}
		limiter := m.authRequestLimiter()
		if limiter != nil {
			now := limiter.nowTime()
			policy := m.routingAuthRequestLimitPolicyForAuth(auth)
			if available, _ := limiter.availableAt(auth.ID, policy, now); !available {
				return selectionErr
			}
		}
	}
	if isAuthRequestLimitedError(selectionErr) {
		if _, isAvailabilityBlocker := availabilityBlockerResetIn(roundState.lastErr); !isAvailabilityBlocker {
			return roundState.lastErr
		}
	}
	return earlierAvailabilityBlocker(selectionErr, roundState.lastErr)
}

func (m *Manager) routingStrategyForPriority(priority int, contexts ...context.Context) schedulerStrategy {
	if strategy, ok := m.routingStrategyOverrideForPriority(priority, contexts...); ok {
		return strategy
	}
	if m == nil {
		return schedulerStrategyRoundRobin
	}
	return selectorStrategy(m.selectorForContext(contexts...))
}

func (m *Manager) legacyPrioritySelector(priority int, strategy schedulerStrategy, fillFirstRange int, contexts ...context.Context) Selector {
	if m == nil {
		return &RoundRobinSelector{}
	}
	fillFirstRange = normalizeFillFirstRangeValue(fillFirstRange)
	base := baseSelector(m.selectorForContext(contexts...))
	if selectorStrategy(base) == strategy && (strategy != schedulerStrategyFillFirst || fillFirstRangeFromSelector(base) == fillFirstRange) {
		return base
	}
	key := strconv.Itoa(priority) + ":" + strconv.Itoa(int(strategy)) + ":" + strconv.Itoa(fillFirstRange)
	if cached, ok := m.prioritySelectors.Load(key); ok {
		if selector, okSelector := cached.(Selector); okSelector && selector != nil {
			return selector
		}
	}
	var selector Selector
	switch strategy {
	case schedulerStrategyFillFirst:
		selector = &FillFirstSelector{Range: fillFirstRange}
	case schedulerStrategyRandom:
		selector = &RandomSelector{}
	case schedulerStrategyWeightedRoundRobin:
		selector = &WeightedRoundRobinSelector{}
	default:
		selector = &RoundRobinSelector{}
	}
	actual, _ := m.prioritySelectors.LoadOrStore(key, selector)
	if stored, ok := actual.(Selector); ok && stored != nil {
		return stored
	}
	return selector
}

func (m *Manager) prioritySelectorForAvailable(available []*Auth, contexts ...context.Context) (Selector, bool) {
	if len(available) == 0 {
		return nil, false
	}
	priority := authPriority(available[0])
	strategy, ok := m.routingStrategyOverrideForPriority(priority, contexts...)
	fillFirstRange := m.routingFillFirstRangeForPriority(priority, contexts...)
	fillFirstPerAuthRPM := m.routingFillFirstPerAuthRPMForPriority(priority, contexts...)
	if !ok {
		strategy = selectorStrategy(m.selectorForContext(contexts...))
		if strategy != schedulerStrategyFillFirst || (fillFirstRange <= 1 && fillFirstPerAuthRPM <= 0) {
			return nil, false
		}
		if fillFirstPerAuthRPM > 0 {
			return nil, false
		}
		return m.legacyPrioritySelector(priority, strategy, fillFirstRange, contexts...), true
	}
	if strategy != schedulerStrategyFillFirst {
		fillFirstRange = 1
		fillFirstPerAuthRPM = 0
	}
	if fillFirstPerAuthRPM > 0 {
		return nil, false
	}
	return m.legacyPrioritySelector(priority, strategy, fillFirstRange, contexts...), true
}

func (m *Manager) pickLegacyFillFirstRangeAuth(ctx context.Context, provider, routeModel string, opts cliproxyexecutor.Options, candidates []*Auth, pickAllowed func(*Auth) bool) (*Auth, bool, error) {
	auth, handled, bind, err := m.pickLegacyFillFirstRangeAuthWithDeferredBinding(ctx, provider, routeModel, opts, candidates, pickAllowed)
	if err == nil && bind != nil {
		bind()
	}
	return auth, handled, err
}

func (m *Manager) pickLegacyFillFirstRangeAuthWithDeferredBinding(ctx context.Context, provider, routeModel string, opts cliproxyexecutor.Options, candidates []*Auth, pickAllowed func(*Auth) bool) (*Auth, bool, func(), error) {
	if len(candidates) == 0 || m == nil {
		return nil, false, nil, nil
	}
	sessionSelector, hasSessionSelector := m.selectorForContext(ctx).(*SessionAffinitySelector)
	if !isBuiltInSelector(m.selectorForContext(ctx)) && !hasSessionSelector {
		return nil, false, nil, nil
	}
	available, errAvailable := m.availableAuthsForRouteModelFilteredForContext(ctx, candidates, provider, routeModel, opts, time.Now(), pickAllowed)
	if errAvailable != nil {
		return nil, true, nil, errAvailable
	}
	if len(available) == 0 {
		return nil, true, nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	priority := authPriority(available[0])
	strategy := m.routingStrategyForPriority(priority, ctx)
	if strategy != schedulerStrategyFillFirst {
		return nil, false, nil, nil
	}
	fillFirstRange := m.routingFillFirstRangeForPriority(priority, ctx)
	fillFirstPerAuthRPM := m.routingFillFirstPerAuthRPMForPriority(priority, ctx)
	if fillFirstRange <= 1 && fillFirstPerAuthRPM <= 0 {
		return nil, false, nil, nil
	}
	fillFirstRangeForPriority := func(priority int) int {
		if m.routingStrategyForPriority(priority, ctx) != schedulerStrategyFillFirst {
			return 1
		}
		return m.routingFillFirstRangeForPriority(priority, ctx)
	}
	fillFirstPerAuthRPMForPriority := func(priority int) int {
		if m.routingStrategyForPriority(priority, ctx) != schedulerStrategyFillFirst {
			return 0
		}
		return m.routingFillFirstPerAuthRPMForPriority(priority, ctx)
	}
	pickFallback := func() (*Auth, error) {
		return selectFillFirstAuthsForContextWithPolicy(ctx, candidates, provider, routeModel, time.Now(), selectionAttemptFromMetadata(opts.Metadata), fillFirstRangeForPriority, fillFirstPerAuthRPMForPriority, m.fillFirstLimiter(), func(auth *Auth) bool {
			return m.routingAuthRequestLimitPolicyForAuth(auth).limit > 0
		}, func(auth *Auth) string {
			return m.selectionModelForAuth(auth, routeModel)
		}, pickAllowed)
	}
	useSessionSelector := hasSessionSelector && sessionSelector != nil
	if useSessionSelector && fillFirstPerAuthRPM > 0 {
		if cachedAuthID := sessionSelector.cachedAuthID(provider, routeModel, opts, ctx); cachedAuthID != "" {
			cachedAuth := authFromListByID(available, cachedAuthID)
			if cachedAuth == nil || m.routingAuthRequestLimitPolicyForAuth(cachedAuth).limit == 0 {
				useSessionSelector = false
			}
		}
	}
	if useSessionSelector {
		selected, bind, errPick := sessionSelector.pickWithPreparedFallbackDeferredBinding(ctx, provider, routeModel, opts, available, pickFallback)
		if errPick == nil && selected != nil && fillFirstPerAuthRPM > 0 && m.routingAuthRequestLimitPolicyForAuth(selected).limit == 0 {
			bind = nil
		}
		return selected, true, bind, errPick
	}
	selected, errPick := pickFallback()
	return selected, true, nil, errPick
}

func (m *Manager) pickAvailableAuthWithPriorityPolicy(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, available []*Auth, acceptors ...func(*Auth) bool) (*Auth, error) {
	if len(available) == 0 {
		return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	if m == nil {
		return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	var accept func(*Auth) bool
	if len(acceptors) > 0 {
		accept = acceptors[0]
	}
	pick := func(selector Selector) (*Auth, error) {
		candidates := available
		if model == "" && isBuiltInSelector(selector) {
			candidates = preparedAuthsForEmptyModelSelection(available)
		}
		if weighted, ok := selector.(*WeightedRoundRobinSelector); ok {
			return weighted.pickAccepted(ctx, provider, model, opts, candidates, accept)
		}
		return selector.Pick(ctx, provider, model, opts, candidates)
	}
	if selector, ok := m.selectorForContext(ctx).(*SessionAffinitySelector); ok && selector != nil {
		fallback, hasOverride := m.prioritySelectorForAvailable(available, ctx)
		if !hasOverride {
			fallback = selector.fallback
		}
		selected, _, err := selector.pickWithPreparedFallbackDeferredBinding(ctx, provider, model, opts, available, func() (*Auth, error) {
			return pick(fallback)
		})
		return selected, err
	}
	if !isBuiltInSelector(m.selectorForContext(ctx)) {
		return pick(m.selectorForContext(ctx))
	}
	selector, hasOverride := m.prioritySelectorForAvailable(available, ctx)
	if !hasOverride {
		selector = m.selectorForContext(ctx)
	}
	return pick(selector)
}

func authFromListByID(auths []*Auth, authID string) *Auth {
	if authID == "" {
		return nil
	}
	for _, auth := range auths {
		if auth != nil && auth.ID == authID {
			return auth
		}
	}
	return nil
}

func setSelectionAttemptMetadata(opts cliproxyexecutor.Options, selectionAttempt int) cliproxyexecutor.Options {
	if selectionAttempt < 0 {
		selectionAttempt = 0
	}
	if len(opts.Metadata) == 0 {
		opts.Metadata = map[string]any{cliproxyexecutor.SelectionAttemptMetadataKey: selectionAttempt}
		return opts
	}
	meta := make(map[string]any, len(opts.Metadata)+1)
	for key, value := range opts.Metadata {
		meta[key] = value
	}
	meta[cliproxyexecutor.SelectionAttemptMetadataKey] = selectionAttempt
	opts.Metadata = meta
	return opts
}

// AuthSupportsRouteModel checks declared model capability, including local
// prefixes and OAuth aliases. It does not select, reserve or authorize a request.
func (m *Manager) AuthSupportsRouteModel(auth *Auth, routeModel string) bool {
	return m != nil && auth != nil && strings.TrimSpace(routeModel) != "" &&
		m.authSupportsRouteModel(registry.GetGlobalRegistry(), auth, routeModel)
}

func (m *Manager) authSupportsRouteModel(registryRef *registry.ModelRegistry, auth *Auth, routeModel string) bool {
	if registryRef == nil || auth == nil {
		return true
	}
	routeKey := canonicalModelKey(routeModel)
	if routeKey == "" {
		return true
	}
	if registryRef.ClientSupportsModel(auth.ID, routeKey) {
		return true
	}
	selectionKey := m.selectionModelKeyForAuth(auth, routeModel)
	return selectionKey != "" && selectionKey != routeKey && registryRef.ClientSupportsModel(auth.ID, selectionKey)
}

const streamDiscardDrainTimeout = time.Second

func discardStreamChunks(ctx context.Context, ch <-chan cliproxyexecutor.StreamChunk) <-chan struct{} {
	return discardStreamChunksWithin(ctx, ch, streamDiscardDrainTimeout)
}

func discardStreamChunksWithin(ctx context.Context, ch <-chan cliproxyexecutor.StreamChunk, timeout time.Duration) <-chan struct{} {
	done := make(chan struct{})
	if ch == nil {
		close(done)
		return done
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil || timeout <= 0 {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				return
			case _, ok := <-ch:
				if !ok {
					return
				}
			}
		}
	}()
	return done
}

type streamBootstrapError struct {
	cause   error
	headers http.Header
}

func cloneHTTPHeader(headers http.Header) http.Header {
	if headers == nil {
		return nil
	}
	return headers.Clone()
}

func newStreamBootstrapError(err error, headers http.Header) error {
	if err == nil {
		return nil
	}
	return &streamBootstrapError{
		cause:   err,
		headers: cloneHTTPHeader(headers),
	}
}

func (e *streamBootstrapError) Error() string {
	if e == nil || e.cause == nil {
		return ""
	}
	return e.cause.Error()
}

func (e *streamBootstrapError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *streamBootstrapError) Headers() http.Header {
	if e == nil {
		return nil
	}
	return cloneHTTPHeader(e.headers)
}

func streamErrorResult(headers http.Header, err error) *cliproxyexecutor.StreamResult {
	ch := make(chan cliproxyexecutor.StreamChunk, 1)
	ch <- cliproxyexecutor.StreamChunk{Err: err}
	close(ch)
	return &cliproxyexecutor.StreamResult{
		Headers: cloneHTTPHeader(headers),
		Chunks:  ch,
	}
}

func validateStreamResult(result *cliproxyexecutor.StreamResult, err error) (*cliproxyexecutor.StreamResult, error) {
	if err != nil {
		return result, err
	}
	if result == nil || result.Chunks == nil {
		return result, &Error{Code: "empty_stream", Message: "upstream stream has no source", Retryable: true}
	}
	return result, nil
}

func enqueueTerminalStreamChunk(ctx context.Context, out chan cliproxyexecutor.StreamChunk, chunk cliproxyexecutor.StreamChunk) {
	if ctx == nil {
		out <- chunk
		return
	}
	select {
	case out <- chunk:
	case <-ctx.Done():
	}
}

func readStreamBootstrap(ctx context.Context, ch <-chan cliproxyexecutor.StreamChunk) ([]cliproxyexecutor.StreamChunk, bool, error) {
	const maxBufferedBytes = 64 << 10

	if ch == nil {
		return nil, true, nil
	}
	buffered := make([]cliproxyexecutor.StreamChunk, 0, 1)
	var payload bytes.Buffer
	for {
		var (
			chunk cliproxyexecutor.StreamChunk
			ok    bool
		)
		if ctx != nil {
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case chunk, ok = <-ch:
			}
		} else {
			chunk, ok = <-ch
		}
		if !ok {
			return buffered, true, nil
		}
		if chunk.Err != nil {
			return nil, false, chunk.Err
		}
		buffered = append(buffered, chunk)
		if cliproxyexecutor.IsSuccessfulStreamTerminalChunk(chunk) {
			return buffered, true, nil
		}
		if cliproxyexecutor.IsBootstrapCommitStreamChunk(chunk) {
			return buffered, false, nil
		}
		if len(chunk.Payload) > maxBufferedBytes-payload.Len() {
			buffered = append(buffered, cliproxyexecutor.BootstrapCommitStreamChunk())
			return buffered, false, nil
		}
		appendStreamBootstrapPayload(&payload, chunk.Payload)
		if streamBootstrapPayloadHasSemanticPayload(payload.Bytes()) {
			return buffered, false, nil
		}
	}
}

func streamBootstrapHasSemanticPayload(chunks []cliproxyexecutor.StreamChunk) bool {
	var payload bytes.Buffer
	for _, chunk := range chunks {
		appendStreamBootstrapPayload(&payload, chunk.Payload)
	}
	return streamBootstrapPayloadHasSemanticPayload(payload.Bytes())
}

func streamBootstrapHasSuccessfulTerminal(chunks []cliproxyexecutor.StreamChunk) bool {
	for _, chunk := range chunks {
		if cliproxyexecutor.IsSuccessfulStreamTerminalChunk(chunk) {
			return true
		}
	}
	return false
}

func appendStreamBootstrapPayload(payload *bytes.Buffer, chunk []byte) {
	if payload == nil || len(chunk) == 0 {
		return
	}
	if streamBootstrapNeedsLineBreak(payload.Bytes(), chunk) {
		payload.WriteByte('\n')
	}
	payload.Write(chunk)
}

func streamBootstrapNeedsLineBreak(pending, chunk []byte) bool {
	if len(pending) == 0 || len(chunk) == 0 ||
		bytes.HasSuffix(pending, []byte("\n")) || bytes.HasSuffix(pending, []byte("\r")) ||
		chunk[0] == '\n' || chunk[0] == '\r' {
		return false
	}
	trimmed := bytes.TrimLeft(chunk, " \t")
	for _, prefix := range [][]byte{[]byte("data:"), []byte("event:"), []byte("id:"), []byte("retry:"), []byte(":")} {
		if bytes.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

func streamBootstrapPayloadHasSemanticPayload(payload []byte) bool {
	for _, line := range bytes.Split(payload, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == ':' {
			continue
		}
		return true
	}
	return false
}

func (m *Manager) wrapStreamResult(ctx, resultCtx context.Context, auth *Auth, affinityProviders []string, provider, routeModel, resultModel string, opts cliproxyexecutor.Options, headers http.Header, buffered []cliproxyexecutor.StreamChunk, remaining <-chan cliproxyexecutor.StreamChunk, aliasResult OAuthModelAliasResult, onDone func() bool) *cliproxyexecutor.StreamResult {
	out := make(chan cliproxyexecutor.StreamChunk, cliproxyexecutor.StreamBufferSize)
	releaseProducer := claimResultPersistenceProducer(resultCtx)
	go func() {
		defer releaseProducer()
		if resultCtx == nil {
			resultCtx = context.Background()
		}
		var runtimeDone <-chan struct{}
		if ctx != nil {
			runtimeDone = ctx.Done()
		}
		released := false
		retiredAtRelease := false
		finishLease := func() bool {
			if !released {
				released = true
				if onDone != nil {
					retiredAtRelease = onDone()
				}
			}
			return retiredAtRelease
		}
		retiredErrorSent := false
		terminalSent := false
		emitRetiredError := func() {
			if retiredErrorSent {
				return
			}
			retiredErrorSent = true
			publishErrorResponseSourceMetadata(opts.Metadata, errorResponseSourceForAuth(auth, provider))
			enqueueTerminalStreamChunk(resultCtx, out, cliproxyexecutor.StreamChunk{Err: runtimeAuthInstanceRetiredError()})
		}
		defer func() {
			retiredAtFinish := finishLease()
			if timeout := cliproxyexecutor.ImageRequestContextError(ctx, nil); timeout != nil {
				timeout = withAuthErrorResponseSource(timeout, auth, provider)
				m.recordExecutionResultMetrics(opts, timeout)
				opts.UsageOutcome.FinalizeFailure()
				select {
				case out <- cliproxyexecutor.StreamChunk{Err: timeout}:
				default:
				}
			}
			if !terminalSent && (retiredAtFinish || runtimeAuthInstanceRetiredContext(ctx)) {
				emitRetiredError()
			}
			close(out)
		}()
		var failed bool
		forward := true
		var rewriter *StreamRewriter
		if aliasResult.ForceMapping && strings.TrimSpace(aliasResult.OriginalAlias) != "" {
			rewriter = NewStreamRewriter(StreamRewriteOptions{RewriteModel: aliasResult.OriginalAlias})
		}
		send := func(chunk cliproxyexecutor.StreamChunk, retiredChunk bool) bool {
			select {
			case <-resultCtx.Done():
				forward = false
				return false
			case out <- chunk:
				if retiredChunk {
					retiredErrorSent = true
				}
				return true
			}
		}
		emit := func(chunk cliproxyexecutor.StreamChunk) bool {
			chunk.Err = cliproxyexecutor.ImageRequestContextError(ctx, chunk.Err)
			if cliproxyexecutor.IsSuccessfulStreamTerminalChunk(chunk) {
				if tail := finishForceMappedStreamChunks(rewriter); len(tail) > 0 {
					rewriter = nil
					if !send(cliproxyexecutor.StreamChunk{Payload: tail}, false) {
						return false
					}
				}
				terminalSent = true
				return true
			}
			retiredChunk := false
			if chunk.Err != nil && !failed {
				failed = true
				if runtimeAuthInstanceRetiredContext(ctx) {
					retiredChunk = true
					chunk.Err = runtimeAuthInstanceRetiredError()
				} else {
					chunk.Err = m.reportProxyFailure(resultCtx, auth, chunk.Err)
					chunk.Err = recordExecutionAttemptError(ctx, auth, provider, chunk.Err)
					if strings.EqualFold(strings.TrimSpace(provider), "chatgpt-web") && isChatGPTWebAuthenticationRecoveryError(chunk.Err) {
						chunk.Err = m.wrapChatGPTWebUnauthorizedRequestError(resultCtx, auth, chunk.Err)
						triggerChatGPTWebUnauthorizedRequestRefresh(chunk.Err)
					}
				}
				rerr := &Error{Message: chunk.Err.Error()}
				if se, ok := errors.AsType[cliproxyexecutor.StatusError](chunk.Err); ok && se != nil {
					rerr.HTTPStatus = se.StatusCode()
				}
				m.projectFailedImageGenerationQuota(
					resultCtx,
					auth,
					provider,
					executionResultModelForError(resultModel, chunk.Err),
					opts,
				)
				if !runtimeAuthInstanceRetiredContext(ctx) && !skipAuthResultForError(chunk.Err) {
					result := resultForAuth(auth, provider, executionResultModelForError(resultModel, chunk.Err), false)
					rerr.Code = executionResultErrorCode(chunk.Err)
					result.Error = rerr
					result.RetryAfter = retryAfterFromError(chunk.Err)
					result.availabilityNeutral = isResponsesCompactAvailabilityNeutralError(opts, chunk.Err)
					action, matchedAction := m.matchRequestScopedErrorAction(ctx, auth, opts, chunk.Err)
					applyRequestScopedActionToResult(action, matchedAction, &result)
					m.markExecutionResult(resultCtx, result, opts)
					chunk.Err = wrapRequestScopedAction(chunk.Err, action, matchedAction)
				}
			}
			if !forward {
				return false
			}
			if chunk.Err != nil {
				publishErrorResponseSourceMetadata(opts.Metadata, errorResponseSourceForAuth(auth, provider))
			}
			if chunk.Err == nil && len(chunk.Payload) > 0 {
				payload := rewriteForceMappedStreamChunk(rewriter, chunk.Payload)
				if len(payload) == 0 {
					return true
				}
				chunk.Payload = payload
			}
			if chunk.Err != nil {
				terminalSent = true
			}
			return send(chunk, retiredChunk)
		}
		for _, chunk := range buffered {
			if ok := emit(chunk); !ok {
				discardStreamChunks(resultCtx, remaining)
				return
			}
			if terminalSent {
				discardStreamChunks(resultCtx, remaining)
				goto streamDone
			}
		}
		for {
			var (
				chunk cliproxyexecutor.StreamChunk
				ok    bool
			)
			select {
			case chunk, ok = <-remaining:
			default:
				select {
				case <-resultCtx.Done():
					discardStreamChunks(resultCtx, remaining)
					return
				case <-runtimeDone:
					select {
					case chunk, ok = <-remaining:
					default:
						discardStreamChunks(resultCtx, remaining)
						return
					}
				case chunk, ok = <-remaining:
				}
			}
			if !ok {
				break
			}
			if ok := emit(chunk); !ok {
				discardStreamChunks(resultCtx, remaining)
				return
			}
			if terminalSent {
				discardStreamChunks(resultCtx, remaining)
				goto streamDone
			}
		}
		if tail := finishForceMappedStreamChunks(rewriter); len(tail) > 0 {
			rewriter = nil
			if ok := emit(cliproxyexecutor.StreamChunk{Payload: tail}); !ok {
				return
			}
		}
	streamDone:
		ctxErr := error(nil)
		if ctx != nil {
			ctxErr = ctx.Err()
		}
		retiredAtFinish := finishLease()
		if !terminalSent && (retiredAtFinish || runtimeAuthInstanceRetiredContext(ctx)) {
			emitRetiredError()
			return
		}
		if ctxErr != nil {
			return
		}
		if !failed && !retiredAtFinish && !runtimeAuthInstanceRetiredContext(ctx) {
			m.markExecutionResult(resultCtx, successfulExecutionResultForAuth(auth, provider, resultModel, opts))
			m.bindSessionAffinity(resultCtx, affinityProviders, routeModel, opts, auth)
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: headers, Chunks: out}
}

func (m *Manager) executeStreamWithModelPool(ctx, resultCtx context.Context, executor ProviderExecutor, auth *Auth, affinityProviders []string, provider string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, routeModel string, execModels []string, pooled bool, aliasResult OAuthModelAliasResult, onDone func() bool, snapshots ...*apiKeyModelRoutingSnapshot) (*cliproxyexecutor.StreamResult, error) {
	if executor == nil {
		return nil, &Error{Code: "executor_not_found", Message: "executor not registered"}
	}
	routing := m.modelRoutingForAttempt(snapshots)
	var lastErr error
	for idx, execModel := range execModels {
		if !requestBodyReplayable(ctx, opts) {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, &Error{Code: "request_body_released", Message: "request body released; retry disabled"}
		}
		if idx > 0 {
			if errLimit := m.acquireAdditionalAuthRequest(auth, executor, opts.AuthRequestSlot); errLimit != nil {
				return nil, errLimit
			}
		}
		resultModel := m.stateModelForExecution(auth, routeModel, execModel, pooled)
		execReq := req
		execReq.Model = execModel
		execReq = attachResolvedAPIKeyModelInfo(routing, execReq, auth, effectiveExecutionRouteModel(routeModel, opts), execModel)
		releaseMu := sync.Mutex{}
		execOpts := opts
		replayOpts := cliproxyexecutor.Options{Alt: opts.Alt, Metadata: opts.Metadata}
		unregisterRelease := registerRequestBodyReleaseCallback(ctx, opts, func([]byte) {
			releaseMu.Lock()
			defer releaseMu.Unlock()
			req.Payload = nil
			execReq.Payload = nil
			opts.OriginalRequest = nil
			execOpts.OriginalRequest = nil
		})
		if !requestBodyReplayable(ctx, replayOpts) {
			unregisterRelease()
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, &Error{Code: "request_body_released", Message: "request body released; retry disabled"}
		}
		attemptCtx, usageAttempt := cliproxyexecutor.WithRequestUsageAttempt(ctx)
		attemptCtx = cliproxyexecutor.WithUpstreamAttempt(attemptCtx)
		streamResult, errStream := executeProviderStream(attemptCtx, executor, auth, execReq, execOpts)
		streamResult, errStream = validateStreamResult(streamResult, errStream)
		errStream = recordExecutionAttemptError(attemptCtx, auth, provider, errStream)
		if errStream != nil {
			unregisterRelease()
			if errCtx := ctx.Err(); errCtx != nil {
				return nil, errCtx
			}
			if cliproxyexecutor.IsImageExecutionCapacityError(errStream) {
				return nil, errStream
			}
			errStream = m.reportProxyFailure(ctx, auth, errStream)
			m.projectFailedImageGenerationQuota(ctx, auth, provider, executionResultModelForError(resultModel, errStream), opts)
			rerr := &Error{Message: errStream.Error()}
			if se, ok := errors.AsType[cliproxyexecutor.StatusError](errStream); ok && se != nil {
				rerr.HTTPStatus = se.StatusCode()
			}
			result := resultForAuth(auth, provider, executionResultModelForError(resultModel, errStream), false)
			rerr.Code = executionResultErrorCode(errStream)
			result.Error = rerr
			result.RetryAfter = retryAfterFromError(errStream)
			result.availabilityNeutral = isResponsesCompactAvailabilityNeutralError(opts, errStream)
			action, matchedAction := m.matchRequestScopedErrorAction(ctx, auth, replayOpts, errStream)
			applyRequestScopedActionToResult(action, matchedAction, &result)
			if !skipAuthResultForError(errStream) && (matchedAction || !deferUnauthorizedStreamResult(auth, errStream)) {
				m.markExecutionResult(ctx, result, replayOpts)
			}
			errStream = wrapRequestScopedAction(errStream, action, matchedAction)
			if isResponsesCompactRequestFaultError(opts, errStream) || m.isRequestInvalidError(errStream, ctx) {
				return nil, errStream
			}
			lastErr = errStream
			if !requestBodyReplayable(ctx, replayOpts) {
				return nil, errStream
			}
			continue
		}
		buffered, closed, bootstrapErr := readStreamBootstrap(ctx, streamResult.Chunks)
		bootstrapErr = recordExecutionAttemptError(attemptCtx, auth, provider, bootstrapErr, streamResult.Headers)
		unregisterRelease()
		releaseMu.Lock()
		wrapOpts := opts
		releaseMu.Unlock()
		if bootstrapErr != nil {
			if errCtx := ctx.Err(); errCtx != nil {
				discardStreamChunks(ctx, streamResult.Chunks)
				return nil, errCtx
			}
			bootstrapErr = m.reportProxyFailure(ctx, auth, bootstrapErr)
			m.projectFailedImageGenerationQuota(ctx, auth, provider, executionResultModelForError(resultModel, bootstrapErr), opts)
			action, matchedAction := m.matchRequestScopedErrorAction(ctx, auth, replayOpts, bootstrapErr)
			bootstrapErr = wrapRequestScopedAction(bootstrapErr, action, matchedAction)
			if isResponsesCompactRequestFaultError(opts, bootstrapErr) || m.isRequestInvalidError(bootstrapErr, ctx) {
				rerr := &Error{Message: bootstrapErr.Error()}
				if se, ok := errors.AsType[cliproxyexecutor.StatusError](bootstrapErr); ok && se != nil {
					rerr.HTTPStatus = se.StatusCode()
				}
				result := resultForAuth(auth, provider, executionResultModelForError(resultModel, bootstrapErr), false)
				rerr.Code = executionResultErrorCode(bootstrapErr)
				result.Error = rerr
				result.RetryAfter = retryAfterFromError(bootstrapErr)
				result.availabilityNeutral = isResponsesCompactAvailabilityNeutralError(opts, bootstrapErr)
				applyRequestScopedActionToResult(action, matchedAction, &result)
				if !skipAuthResultForError(bootstrapErr) && (matchedAction || !deferUnauthorizedStreamResult(auth, bootstrapErr)) {
					m.markExecutionResult(ctx, result, replayOpts)
				}
				discardStreamChunks(ctx, streamResult.Chunks)
				if matchedAction {
					return nil, newStreamBootstrapError(bootstrapErr, streamResult.Headers)
				}
				return nil, bootstrapErr
			}
			if idx < len(execModels)-1 && requestBodyReplayable(ctx, replayOpts) {
				rerr := &Error{Message: bootstrapErr.Error()}
				if se, ok := errors.AsType[cliproxyexecutor.StatusError](bootstrapErr); ok && se != nil {
					rerr.HTTPStatus = se.StatusCode()
				}
				result := resultForAuth(auth, provider, executionResultModelForError(resultModel, bootstrapErr), false)
				rerr.Code = executionResultErrorCode(bootstrapErr)
				result.Error = rerr
				result.RetryAfter = retryAfterFromError(bootstrapErr)
				result.availabilityNeutral = isResponsesCompactAvailabilityNeutralError(opts, bootstrapErr)
				applyRequestScopedActionToResult(action, matchedAction, &result)
				if !skipAuthResultForError(bootstrapErr) && (matchedAction || !deferUnauthorizedStreamResult(auth, bootstrapErr)) {
					m.markExecutionResult(ctx, result, replayOpts)
				}
				discardStreamChunks(ctx, streamResult.Chunks)
				lastErr = bootstrapErr
				continue
			}
			rerr := &Error{Message: bootstrapErr.Error()}
			if se, ok := errors.AsType[cliproxyexecutor.StatusError](bootstrapErr); ok && se != nil {
				rerr.HTTPStatus = se.StatusCode()
			}
			result := resultForAuth(auth, provider, executionResultModelForError(resultModel, bootstrapErr), false)
			rerr.Code = executionResultErrorCode(bootstrapErr)
			result.Error = rerr
			result.RetryAfter = retryAfterFromError(bootstrapErr)
			result.availabilityNeutral = isResponsesCompactAvailabilityNeutralError(opts, bootstrapErr)
			applyRequestScopedActionToResult(action, matchedAction, &result)
			if !skipAuthResultForError(bootstrapErr) && (matchedAction || !deferUnauthorizedStreamResult(auth, bootstrapErr)) {
				m.markExecutionResult(ctx, result, replayOpts)
			}
			discardStreamChunks(ctx, streamResult.Chunks)
			return nil, newStreamBootstrapError(bootstrapErr, streamResult.Headers)
		}

		if closed && !streamBootstrapHasSemanticPayload(buffered) && !streamBootstrapHasSuccessfulTerminal(buffered) {
			if errCtx := ctx.Err(); errCtx != nil {
				return nil, errCtx
			}
			emptyErr := &Error{Code: "empty_stream", Message: "upstream stream closed before first payload", Retryable: true}
			result := resultForAuth(auth, provider, resultModel, false)
			result.Error = emptyErr
			result.availabilityNeutral = isResponsesCompactAvailabilityNeutralError(opts, emptyErr)
			m.markExecutionResult(ctx, result)
			observedEmptyErr := recordExecutionAttemptError(attemptCtx, auth, provider, emptyErr, streamResult.Headers)
			if idx < len(execModels)-1 && requestBodyReplayable(ctx, replayOpts) {
				lastErr = observedEmptyErr
				continue
			}
			return nil, newStreamBootstrapError(observedEmptyErr, streamResult.Headers)
		}

		remaining := streamResult.Chunks
		if closed {
			closedCh := make(chan cliproxyexecutor.StreamChunk)
			close(closedCh)
			remaining = closedCh
		}
		opts.UsageOutcome.AcceptStreamAttempt(usageAttempt)
		return m.wrapStreamResult(attemptCtx, resultCtx, auth.Clone(), affinityProviders, provider, routeModel, resultModel, wrapOpts, streamResult.Headers, buffered, remaining, aliasResult, onDone), nil
	}
	if lastErr == nil {
		lastErr = &Error{Code: "auth_not_found", Message: "no upstream model available"}
	}
	return nil, lastErr
}

func (m *Manager) rebuildAPIKeyModelAliasFromRuntimeConfig() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		cfg = &internalconfig.Config{}
	}
	m.rebuildAPIKeyModelAliasLocked(cfg)
}

func (m *Manager) rebuildAPIKeyModelAliasLocked(cfg *internalconfig.Config) {
	if m == nil {
		return
	}
	m.apiKeyModelRouting.Store(buildAPIKeyModelRoutingSnapshot(m.auths, cfg))
}

func buildAPIKeyModelAliasTable(auths map[string]*Auth, cfg *internalconfig.Config) apiKeyModelAliasTable {
	if cfg == nil {
		cfg = &internalconfig.Config{}
	}

	out := make(apiKeyModelAliasTable)
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		if strings.TrimSpace(auth.ID) == "" {
			continue
		}
		kind, _ := auth.AccountInfo()
		if !strings.EqualFold(strings.TrimSpace(kind), "api_key") {
			continue
		}

		byAlias := make(map[string]string)
		provider := strings.ToLower(strings.TrimSpace(auth.Provider))
		switch provider {
		case "gemini":
			if entry := resolveGeminiAPIKeyConfig(cfg, auth); entry != nil {
				compileAPIKeyModelAliasForModels(byAlias, entry.Models)
			}
		case "gemini-interactions":
			if entry := resolveInteractionsAPIKeyConfig(cfg, auth); entry != nil {
				compileAPIKeyModelAliasForModels(byAlias, entry.Models)
			}
		case "claude":
			if entry := resolveClaudeAPIKeyConfig(cfg, auth); entry != nil {
				compileAPIKeyModelAliasForModels(byAlias, entry.Models)
			}
		case "codex":
			if entry := resolveCodexAPIKeyConfig(cfg, auth); entry != nil {
				compileAPIKeyModelAliasForModels(byAlias, entry.Models)
			}
		case "vertex":
			if entry := resolveVertexAPIKeyConfig(cfg, auth); entry != nil {
				compileAPIKeyModelAliasForModels(byAlias, entry.Models)
			}
		default:
			// OpenAI-compat uses config selection from auth.Attributes.
			providerKey := ""
			compatName := ""
			if auth.Attributes != nil {
				providerKey = strings.TrimSpace(auth.Attributes["provider_key"])
				compatName = strings.TrimSpace(auth.Attributes["compat_name"])
			}
			if compatName != "" || strings.EqualFold(strings.TrimSpace(auth.Provider), "openai-compatibility") {
				if entry := resolveOpenAICompatConfig(cfg, providerKey, compatName, auth.Provider); entry != nil {
					compileAPIKeyModelAliasForModels(byAlias, entry.Models)
				}
			}
		}

		if len(byAlias) > 0 {
			out[auth.ID] = byAlias
		}
	}

	return out
}

func (m *Manager) removeAPIKeyModelAliasForAuthLocked(auth *Auth) {
	if m == nil || auth == nil || strings.TrimSpace(auth.ID) == "" {
		return
	}
	kind, _ := auth.AccountInfo()
	if !strings.EqualFold(strings.TrimSpace(kind), "api_key") {
		return
	}
	current := m.loadAPIKeyModelRouting()
	if len(current.aliases) == 0 && len(current.capabilities) == 0 {
		return
	}
	next := make(apiKeyModelAliasTable, len(current.aliases))
	for id, aliases := range current.aliases {
		if id != auth.ID {
			next[id] = aliases
		}
	}
	capabilities := make(apiKeyModelCapabilityTable, len(current.capabilities))
	for id, models := range current.capabilities {
		if id != auth.ID {
			capabilities[id] = models
		}
	}
	m.apiKeyModelRouting.Store(&apiKeyModelRoutingSnapshot{config: current.config, aliases: next, capabilities: capabilities})
}

func compileAPIKeyModelAliasForModels[T interface {
	GetName() string
	GetAlias() string
}](out map[string]string, models []T) {
	if out == nil {
		return
	}
	for i := range models {
		alias := strings.TrimSpace(models[i].GetAlias())
		name := strings.TrimSpace(models[i].GetName())
		if alias == "" || name == "" {
			continue
		}
		aliasKey := strings.ToLower(thinking.ParseSuffix(alias).ModelName)
		if aliasKey == "" {
			aliasKey = strings.ToLower(alias)
		}
		// Config priority: first alias wins.
		if _, exists := out[aliasKey]; exists {
			continue
		}
		out[aliasKey] = name
		// Also allow direct lookup by upstream name (case-insensitive), so lookups on already-upstream
		// models remain a cheap no-op.
		nameKey := strings.ToLower(thinking.ParseSuffix(name).ModelName)
		if nameKey == "" {
			nameKey = strings.ToLower(name)
		}
		if nameKey != "" {
			if _, exists := out[nameKey]; !exists {
				out[nameKey] = name
			}
		}
		// Preserve config suffix priority by seeding a base-name lookup when name already has suffix.
		nameResult := thinking.ParseSuffix(name)
		if nameResult.HasSuffix {
			baseKey := strings.ToLower(strings.TrimSpace(nameResult.ModelName))
			if baseKey != "" {
				if _, exists := out[baseKey]; !exists {
					out[baseKey] = name
				}
			}
		}
	}
}

// SetRetryConfig updates retry attempts, credential retry limit and cooldown wait interval.
func (m *Manager) SetRetryConfig(retry int, maxRetryInterval time.Duration, maxRetryCredentials int) {
	if m == nil {
		return
	}
	if retry < 0 {
		retry = 0
	}
	if maxRetryCredentials < 0 {
		maxRetryCredentials = 0
	}
	if maxRetryInterval < 0 {
		maxRetryInterval = 0
	}
	m.retryConfig.Store(&retrySettingsSnapshot{retries: retry, credentials: maxRetryCredentials, wait: maxRetryInterval})
}

// RegisterExecutor registers a provider executor with the manager.
func (m *Manager) RegisterExecutor(executor ProviderExecutor) {
	m.registerExecutor(executor, false)
}

// RegisterExecutorIfTypeChanged atomically preserves an installed executor of
// the same concrete type. False transfers no ownership and performs no cleanup.
func (m *Manager) RegisterExecutorIfTypeChanged(executor ProviderExecutor) bool {
	return m.registerExecutor(executor, true)
}

func (m *Manager) registerExecutor(executor ProviderExecutor, preserveType bool) bool {
	if executor == nil {
		return false
	}
	provider := strings.TrimSpace(executor.Identifier())
	if provider == "" {
		return false
	}

	m.executorLifecycleMu.Lock()
	if m.executorsClosed {
		if preserveType {
			m.executorLifecycleMu.Unlock()
			return false
		}
		m.mu.RLock()
		current := m.executors[provider]
		alreadyOwned := sameProviderExecutor(current, executor) || m.executorTrackedForShutdownLocked(executor)
		m.mu.RUnlock()
		if alreadyOwned {
			m.executorLifecycleMu.Unlock()
			return false
		}
		m.executorShutdownSet = append(m.executorShutdownSet, executor)
		trackedClose := !m.executorCloseSealed
		sealedClose := m.executorCloseSealed && !m.executorCloseFinal
		if trackedClose {
			m.executorCloseWG.Add(1)
		} else if sealedClose {
			m.executorSealedClose++
		}
		m.executorLifecycleMu.Unlock()
		errClose := closeProviderExecutor(executor)
		if trackedClose {
			if errClose != nil {
				m.recordExecutorAsyncCloseError(errClose)
			}
			m.executorCloseWG.Done()
		} else if sealedClose {
			m.executorLifecycleMu.Lock()
			if errClose != nil {
				m.executorAsyncErr = errors.Join(m.executorAsyncErr, errClose)
			}
			m.executorSealedClose--
			m.executorCloseCond.Broadcast()
			m.executorLifecycleMu.Unlock()
		}
		if errClose != nil {
			log.Errorf("failed to close provider executor registered after shutdown %s: %v", provider, errClose)
		}
		return false
	}

	var replaced ProviderExecutor
	m.mu.Lock()
	replaced = m.executors[provider]
	if preserveType && reflect.TypeOf(replaced) == reflect.TypeOf(executor) {
		m.mu.Unlock()
		m.executorLifecycleMu.Unlock()
		return false
	}
	m.executors[provider] = executor
	m.mu.Unlock()

	if replaced == nil || sameProviderExecutor(replaced, executor) {
		m.executorLifecycleMu.Unlock()
		return true
	}
	m.executorCloseWG.Add(1)
	m.executorLifecycleMu.Unlock()
	defer m.executorCloseWG.Done()
	if errClose := closeProviderExecutor(replaced); errClose != nil {
		log.Errorf("failed to close replaced provider executor %s: %v", provider, errClose)
		m.recordExecutorAsyncCloseError(errClose)
	}
	return true
}

func (m *Manager) executorTrackedForShutdownLocked(executor ProviderExecutor) bool {
	for _, tracked := range m.executorShutdownSet {
		if sameProviderExecutor(tracked, executor) {
			return true
		}
	}
	return false
}

func (m *Manager) recordExecutorAsyncCloseError(errClose error) {
	if m == nil || errClose == nil {
		return
	}
	m.executorLifecycleMu.Lock()
	if m.executorsClosed {
		m.executorAsyncErr = errors.Join(m.executorAsyncErr, errClose)
	}
	m.executorLifecycleMu.Unlock()
}

func sameProviderExecutor(left, right ProviderExecutor) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	leftValue := reflect.ValueOf(left)
	rightValue := reflect.ValueOf(right)
	if leftValue.Type() != rightValue.Type() {
		return false
	}
	if leftValue.Type().Comparable() {
		return left == right
	}
	// Preserve copied interface identity without inspecting mutable executor state.
	return leftValue == rightValue
}

// UnregisterExecutor removes the executor associated with the provider key.
func (m *Manager) UnregisterExecutor(provider string) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return
	}
	m.executorLifecycleMu.Lock()
	m.mu.Lock()
	replaced := m.executors[provider]
	delete(m.executors, provider)
	m.mu.Unlock()
	if m.executorsClosed {
		m.executorLifecycleMu.Unlock()
		return
	}
	if replaced == nil {
		m.executorLifecycleMu.Unlock()
		return
	}
	m.executorCloseWG.Add(1)
	m.executorLifecycleMu.Unlock()
	defer m.executorCloseWG.Done()
	if errClose := closeProviderExecutor(replaced); errClose != nil {
		log.Errorf("failed to close unregistered provider executor %s: %v", provider, errClose)
		m.recordExecutorAsyncCloseError(errClose)
	}
}

func closeProviderExecutor(executor ProviderExecutor) error {
	if executor == nil {
		return nil
	}
	if closer, ok := executor.(ExecutionSessionCloser); ok && closer != nil {
		closer.CloseExecutionSession(CloseAllExecutionSessionsID)
	}
	if closer, ok := executor.(io.Closer); ok && closer != nil {
		return closer.Close()
	}
	return nil
}

// ErrAuthAlreadyExists reports a conditional registration conflict.
var ErrAuthAlreadyExists = errors.New("auth already exists")

// ErrChatGPTWebEmailAlreadyExists reports a duplicate ChatGPT Web account.
// The legacy name is retained for compatibility; strong identities may share
// an email when they belong to different workspaces.
var ErrChatGPTWebEmailAlreadyExists = errors.New("chatgpt web email already exists")

// ErrChatGPTWebEmailImmutable reports an attempt to change a persisted account identity.
var ErrChatGPTWebEmailImmutable = errors.New("chatgpt web email cannot be changed")

// ErrAuthMutationIdentityChanged reports reuse of a mutation lock for another identity.
var ErrAuthMutationIdentityChanged = errors.New("auth mutation identity changed while locked")

// Register inserts or replaces an auth entry in the manager.
func (m *Manager) Register(ctx context.Context, auth *Auth) (*Auth, error) {
	return m.register(ctx, auth, false)
}

// RegisterIfAbsent inserts an auth entry only when the ID is still unused.
// The existence check and persistence are serialized with all writes for the ID.
func (m *Manager) RegisterIfAbsent(ctx context.Context, auth *Auth) (*Auth, error) {
	return m.register(ctx, auth, true)
}

func (m *Manager) register(ctx context.Context, auth *Auth, requireAbsent bool) (*Auth, error) {
	if auth == nil {
		return nil, nil
	}
	if errWeight := ValidateAuthWeight(auth); errWeight != nil {
		return nil, errWeight
	}
	if errRules := prepareAuthRequestScopedErrors(auth); errRules != nil {
		return nil, errRules
	}
	auth.requestRefreshFamilyID = ""
	auth.ID = strings.TrimSpace(auth.ID)
	if auth.ID == "" {
		auth.ID = uuid.NewString()
	}
	if IsRetiredGeminiCLIAuth(auth) {
		WarnRetiredGeminiCLIAuthIgnored()
		return nil, retiredGeminiCLIAuthError()
	}
	lockedDependencyCtx, unlockDependency, errDependency := m.lockChatGPTWebDependencyMutationContext(ctx, auth.ID, auth, false)
	if errDependency != nil {
		return nil, errDependency
	}
	ctx = lockedDependencyCtx
	dependencyLocked := true
	defer func() {
		if dependencyLocked {
			unlockDependency()
		}
	}()
	if m.canonicalizeNewChatGPTWebAuth(ctx, auth) && !requireAbsent {
		_, requireAbsent = m.store.(ConditionalCreateStore)
	}
	lockedCtx, unlockPersist, errLock := m.lockAuthMutationContext(ctx, auth)
	if errLock != nil {
		return nil, errLock
	}
	ctx = lockedCtx
	if requireAbsent {
		m.mu.RLock()
		_, exists := m.auths[auth.ID]
		m.mu.RUnlock()
		if exists {
			unlockPersist()
			return nil, ErrAuthAlreadyExists
		}
	}
	m.mu.RLock()
	existingIdentity := m.auths[auth.ID]
	identityChanged := chatGPTWebEmailChanged(existingIdentity, auth)
	m.mu.RUnlock()
	if identityChanged && m.shouldPersistAuth(ctx, auth) {
		unlockPersist()
		return nil, ErrChatGPTWebEmailImmutable
	}
	if chatGPTWebRegistrationEmail(auth) != "" {
		m.mu.RLock()
		conflict := m.chatGPTWebCredentialConflictLocked(auth.ID, auth)
		identityIndexComplete := m.chatGPTWebIdentityComplete
		m.mu.RUnlock()
		if conflict {
			unlockPersist()
			return nil, ErrChatGPTWebEmailAlreadyExists
		}
		if requireAbsent && m.shouldPersistAuth(ctx, auth) && !identityIndexComplete {
			storedConflict, errStored := m.chatGPTWebStoredCredentialConflict(ctx, auth.ID, auth)
			if errStored != nil {
				unlockPersist()
				return nil, fmt.Errorf("inspect persisted chatgpt web credentials: %w", errStored)
			}
			if storedConflict {
				unlockPersist()
				return nil, ErrChatGPTWebEmailAlreadyExists
			}
			m.mu.RLock()
			identityIndexComplete = m.chatGPTWebIdentityComplete
			m.mu.RUnlock()
		}
		if requireAbsent && identityIndexComplete {
			ctx = authfileguard.WithManagerValidatedChatGPTWebIdentity(ctx)
		}
	}
	skipStateCarryForward := shouldSkipStateCarryForward(ctx)
	forceRuntimeReplacement := shouldForceRuntimeReplacement(ctx)
	replacementNow := time.Now()
	m.mu.RLock()
	existingBeforePersist := m.auths[auth.ID]
	credentialChanged := prepareChatGPTWebCredentialReplacement(existingBeforePersist, auth, replacementNow)
	if credentialChanged {
		skipStateCarryForward = true
		forceRuntimeReplacement = true
	}
	prepareAuthReplacement(existingBeforePersist, auth, skipStateCarryForward)
	m.mu.RUnlock()
	var errPersist error
	if requireAbsent {
		errPersist = m.persistNewWithoutLock(ctx, auth)
	} else {
		errPersist = m.persistWithoutLock(ctx, auth, false)
	}
	if errPersist != nil {
		unlockPersist()
		return nil, errPersist
	}
	var replaced *Auth
	m.mu.Lock()
	if m.shouldPersistAuth(ctx, auth) {
		m.installPersistedAuthIndexLocked(auth)
	}
	existing := m.auths[auth.ID]
	credentialChanged = prepareChatGPTWebCredentialReplacement(existing, auth, replacementNow)
	if credentialChanged {
		skipStateCarryForward = true
		forceRuntimeReplacement = true
	}
	instanceID := ""
	var instanceState *authInstanceState
	if existing != nil && !forceRuntimeReplacement && authRuntimeInstanceEquivalent(existing, auth) {
		instanceID = existing.instanceID
		instanceState = existing.instanceState
		prepareAuthReplacement(existing, auth, skipStateCarryForward)
	} else if existing != nil {
		m.beginAuthInstanceCleanupLocked(auth.ID)
		replaced = existing.Clone()
	}
	if instanceID == "" {
		instanceID = uuid.NewString()
	}
	if instanceState == nil {
		instanceState = &authInstanceState{}
		instanceState.bindExecutorOwner(m.executors[executorKeyFromAuth(auth)])
	}
	auth.EnsureIndex()
	authClone := auth.Clone()
	authClone.installationID = uuid.NewString()
	authClone.requestRefreshFamilyID = uuid.NewString()
	authClone.instanceID = instanceID
	authClone.instanceState = instanceState
	m.installAuthLocked(auth.ID, authClone)
	cleanupPending := m.authSelectionBlockedLocked(auth.ID)
	installed := authClone.Clone()
	if isAPIKeyAuth(existingBeforePersist) || isAPIKeyAuth(auth) {
		m.rebuildAPIKeyModelAliasLocked(m.currentConfig())
	}
	m.mu.Unlock()
	if m.scheduler != nil {
		m.scheduler.upsertAuth(installed.Clone())
	}
	if !cleanupPending {
		m.queueRefreshReschedule(auth.ID)
	}
	unlockPersist()
	unlockDependency()
	dependencyLocked = false
	hookCtx := withoutChatGPTWebCredentialUpdateMarkers(ctx)
	if credentialChanged {
		hookCtx = withChatGPTWebCredentialReplacement(hookCtx)
	}
	notifyRegistered := func() {
		if !m.authInstallationCurrent(authClone) {
			return
		}
		m.Hook().OnAuthRegistered(hookCtx, installed.Clone())
	}
	if replaced != nil {
		m.finishAuthSessionCleanup(auth.ID, replaced, "auth_replaced", notifyRegistered)
	} else {
		notifyRegistered()
	}
	return installed, nil
}

func chatGPTWebRegistrationEmail(auth *Auth) string {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), chatgptwebauth.Provider) {
		return ""
	}
	return strings.ToLower(chatGPTWebIdentityMetadataString(auth.Metadata, "email"))
}

func chatGPTWebEmailChanged(existing, updated *Auth) bool {
	if existing == nil || updated == nil ||
		!strings.EqualFold(strings.TrimSpace(existing.Provider), chatgptwebauth.Provider) ||
		!strings.EqualFold(strings.TrimSpace(updated.Provider), chatgptwebauth.Provider) {
		return false
	}
	return chatGPTWebRegistrationEmail(existing) != chatGPTWebRegistrationEmail(updated)
}

func (m *Manager) canonicalizeNewChatGPTWebAuth(ctx context.Context, auth *Auth) bool {
	if auth == nil || !m.shouldPersistAuth(ctx, auth) {
		return false
	}
	email := chatGPTWebRegistrationEmail(auth)
	if email == "" {
		return false
	}
	authID := strings.TrimSpace(auth.ID)
	m.mu.RLock()
	_, exists := m.auths[authID]
	m.mu.RUnlock()
	if exists {
		return false
	}
	fileName := chatgptwebauth.CredentialFileName(email)
	requestedFileName := strings.TrimSpace(auth.FileName)
	if requestedFileName != "" && filepath.Base(requestedFileName) == requestedFileName &&
		!strings.ContainsAny(requestedFileName, "/\\") && !strings.ContainsRune(requestedFileName, 0) &&
		strings.HasSuffix(strings.ToLower(requestedFileName), ".json") && requestedFileName == authID &&
		!strings.EqualFold(requestedFileName, fileName) {
		return false
	}
	auth.ID = fileName
	auth.FileName = fileName
	if auth.Attributes != nil {
		delete(auth.Attributes, "path")
	}
	return true
}

func (m *Manager) chatGPTWebCredentialConflictLocked(authID string, auth *Auth) bool {
	candidateIDs := make(map[string]struct{})
	for _, key := range chatGPTWebIdentityIndexKeys(auth) {
		for id := range m.chatGPTWebIdentityIDs[key] {
			if id != authID {
				candidateIDs[id] = struct{}{}
			}
		}
	}
	for id := range candidateIDs {
		candidate := m.auths[id]
		if candidate == nil {
			candidate = m.persistedAuthsByID[id]
		}
		if candidate != nil && ChatGPTWebCredentialIdentityConflict(candidate, auth) {
			return true
		}
	}
	return false
}

func (m *Manager) chatGPTWebStoredCredentialConflict(ctx context.Context, authID string, auth *Auth) (bool, error) {
	if m == nil || m.store == nil || auth == nil {
		return false, nil
	}
	auths, errList := m.PersistedAuthSnapshot(ctx)
	if errList != nil {
		return false, errList
	}
	for _, candidate := range auths {
		if candidate == nil || candidate.ID == authID {
			continue
		}
		if ChatGPTWebCredentialIdentityConflict(candidate, auth) {
			return true, nil
		}
	}
	return false, nil
}

// Update replaces an existing auth entry and notifies hooks.
func (m *Manager) Update(ctx context.Context, auth *Auth) (*Auth, error) {
	if auth == nil || strings.TrimSpace(auth.ID) == "" {
		return nil, nil
	}
	if errWeight := ValidateAuthWeight(auth); errWeight != nil {
		return nil, errWeight
	}
	auth = auth.Clone()
	if errRules := prepareAuthRequestScopedErrors(auth); errRules != nil {
		return nil, errRules
	}
	auth.ID = strings.TrimSpace(auth.ID)
	clearRuntimeProxy(auth)
	auth.requestRefreshFamilyID = ""
	if IsRetiredGeminiCLIAuth(auth) {
		WarnRetiredGeminiCLIAuthIgnored()
		return nil, retiredGeminiCLIAuthError()
	}
	lockedDependencyCtx, unlockDependency, errDependency := m.lockChatGPTWebDependencyMutationContext(ctx, auth.ID, auth, false)
	if errDependency != nil {
		return nil, errDependency
	}
	ctx = lockedDependencyCtx
	dependencyLocked := true
	defer func() {
		if dependencyLocked {
			unlockDependency()
		}
	}()
	m.canonicalizeNewChatGPTWebAuth(ctx, auth)
	lockedCtx, unlockPersist, errLock := m.lockAuthMutationContext(ctx, auth)
	if errLock != nil {
		return nil, errLock
	}
	ctx = lockedCtx
	m.mu.RLock()
	existingIdentity := m.auths[auth.ID]
	identityChanged := chatGPTWebEmailChanged(existingIdentity, auth)
	m.mu.RUnlock()
	if identityChanged && m.shouldPersistAuth(ctx, auth) {
		unlockPersist()
		return nil, ErrChatGPTWebEmailImmutable
	}
	if chatGPTWebRegistrationEmail(auth) != "" {
		m.mu.RLock()
		conflict := m.chatGPTWebCredentialConflictLocked(auth.ID, auth)
		m.mu.RUnlock()
		if conflict {
			unlockPersist()
			return nil, ErrChatGPTWebEmailAlreadyExists
		}
	}
	skipStateCarryForward := shouldSkipStateCarryForward(ctx)
	forceRuntimeReplacement := shouldForceRuntimeReplacement(ctx)
	replacementNow := time.Now()
	m.mu.RLock()
	existingBeforePersist := m.auths[auth.ID]
	credentialChanged := prepareChatGPTWebCredentialReplacement(existingBeforePersist, auth, replacementNow)
	if credentialChanged {
		skipStateCarryForward = true
		forceRuntimeReplacement = true
	}
	prepareAuthReplacement(existingBeforePersist, auth, skipStateCarryForward)
	m.mu.RUnlock()
	if err := m.persistWithoutLock(ctx, auth, false); err != nil {
		unlockPersist()
		return nil, err
	}
	var replaced *Auth
	m.mu.Lock()
	if m.shouldPersistAuth(ctx, auth) {
		m.installPersistedAuthIndexLocked(auth)
	}
	existing := m.auths[auth.ID]
	credentialChanged = prepareChatGPTWebCredentialReplacement(existing, auth, replacementNow)
	if credentialChanged {
		skipStateCarryForward = true
		forceRuntimeReplacement = true
	}
	instanceID := ""
	var instanceState *authInstanceState
	if existing != nil && !forceRuntimeReplacement && authRuntimeInstanceEquivalent(existing, auth) {
		instanceID = existing.instanceID
		instanceState = existing.instanceState
		prepareAuthReplacement(existing, auth, skipStateCarryForward)
	} else if existing != nil {
		m.beginAuthInstanceCleanupLocked(auth.ID)
		replaced = existing.Clone()
	}
	if instanceID == "" {
		instanceID = uuid.NewString()
	}
	if instanceState == nil {
		instanceState = &authInstanceState{}
		instanceState.bindExecutorOwner(m.executors[executorKeyFromAuth(auth)])
	}
	auth.EnsureIndex()
	authClone := auth.Clone()
	authClone.installationID = uuid.NewString()
	authClone.requestRefreshFamilyID = uuid.NewString()
	authClone.instanceID = instanceID
	authClone.instanceState = instanceState
	m.installAuthLocked(auth.ID, authClone)
	cleanupPending := m.authSelectionBlockedLocked(auth.ID)
	installed := authClone.Clone()
	if isAPIKeyAuth(existingBeforePersist) || isAPIKeyAuth(auth) {
		m.rebuildAPIKeyModelAliasLocked(m.currentConfig())
	}
	m.mu.Unlock()
	if m.scheduler != nil {
		m.scheduler.upsertAuth(installed.Clone())
	}
	if !cleanupPending {
		m.queueRefreshReschedule(auth.ID)
	}
	unlockPersist()
	unlockDependency()
	dependencyLocked = false
	hookCtx := withoutChatGPTWebCredentialUpdateMarkers(ctx)
	if credentialChanged {
		hookCtx = withChatGPTWebCredentialReplacement(hookCtx)
	}
	notifyUpdated := func() {
		if !m.authInstallationCurrent(authClone) {
			return
		}
		m.Hook().OnAuthUpdated(hookCtx, installed.Clone())
	}
	if replaced != nil {
		m.finishAuthSessionCleanup(auth.ID, replaced, "auth_replaced", notifyUpdated)
	} else {
		notifyUpdated()
	}
	return installed, nil
}

func (m *Manager) handleRetiredAuth(ctx context.Context, auth, expected *Auth) (*Auth, error) {
	if m == nil || auth == nil || auth.ID == "" {
		return nil, nil
	}
	WarnRetiredGeminiCLIAuthIgnored()
	unlockPersist, errLock := m.lockAuthIDMutationContext(ctx, auth.ID)
	if errLock != nil {
		return nil, errLock
	}
	auth.EnsureIndex()
	m.mu.Lock()
	current := m.auths[auth.ID]
	if expected != nil && current != expected {
		m.mu.Unlock()
		unlockPersist()
		return nil, nil
	}
	if current != nil && authIsRuntimeOnly(current) {
		m.mu.Unlock()
		unlockPersist()
		return auth.Clone(), nil
	}
	var removed *Auth
	if current != nil {
		m.beginAuthInstanceCleanupLocked(auth.ID)
		removed = current.Clone()
		m.removeAuthLocked(auth.ID)
	}
	m.mu.Unlock()
	if removed != nil {
		m.cleanupRemovedAuthRuntimeStateAfterQuarantine(auth.ID)
	}
	result := auth.Clone()
	unlockPersist()
	if removed != nil {
		m.finishAuthSessionCleanup(auth.ID, removed, "auth_retired", nil)
	}
	return result, nil
}

func (m *Manager) cleanupRemovedAuthRuntimeStateAfterQuarantine(id string) {
	if m == nil || id == "" {
		return
	}
	registry.GetGlobalRegistry().UnregisterClient(id)
	if m.scheduler != nil {
		m.scheduler.removeAuth(id)
	}
	m.queueRefreshReschedule(id)
}

func (m *Manager) invalidateSessionAffinity(id string) {
	if m == nil || id == "" {
		return
	}
	m.mu.RLock()
	selector, ok := m.selectorForContext().(sessionAffinityInvalidator)
	m.mu.RUnlock()
	if ok && selector != nil {
		selector.InvalidateAuth(id)
	}
}

func (m *Manager) finishAuthSessionCleanup(id string, removed *Auth, reason string, afterClose func()) {
	if m == nil || id == "" {
		return
	}
	defer m.endSessionCleanup(id)
	if removed != nil {
		removed.retireInstance()
		m.waitForRefreshExecutions(removed)
	}
	if removed != nil {
		executorOwners := removed.executorOwners()
		currentExecutor := m.executorFor(executorKeyFromAuth(removed))
		if len(executorOwners) == 0 {
			if currentExecutor != nil {
				executorOwners = append(executorOwners, currentExecutor)
			}
		} else if tracker, ok := currentExecutor.(PassiveAuthInstanceStateTracker); ok &&
			tracker != nil &&
			tracker.HasPassiveAuthInstanceState(id, removed.RuntimeInstanceID()) {
			tracked := false
			for _, owner := range executorOwners {
				if sameProviderExecutor(owner, currentExecutor) {
					tracked = true
					break
				}
			}
			if !tracked {
				executorOwners = append(executorOwners, currentExecutor)
			}
		}
		for _, providerExecutor := range executorOwners {
			if closer, ok := providerExecutor.(AuthInstanceExecutionSessionCloser); ok && closer != nil {
				m.runSessionCleanupCallback(id, reason, "execution_sessions", func() {
					closer.CloseAuthInstanceExecutionSessions(id, removed.RuntimeInstanceID(), reason)
				})
			} else if closer, ok := providerExecutor.(AuthExecutionSessionCloser); ok && closer != nil {
				m.runSessionCleanupCallback(id, reason, "execution_sessions", func() {
					closer.CloseAuthExecutionSessions(id, reason)
				})
			}
		}
	}
	m.runSessionCleanupCallback(id, reason, "session_affinity", func() {
		m.invalidateSessionAffinity(id)
	})
	m.runSessionCleanupCallback(id, reason, "auth_hook", afterClose)
}

func (m *Manager) authInstallationCurrent(installed *Auth) bool {
	if m == nil || installed == nil || installed.ID == "" {
		return false
	}
	m.mu.RLock()
	current := m.auths[installed.ID]
	m.mu.RUnlock()
	if current == nil {
		return false
	}
	if installed.installationID != "" {
		return current.installationID == installed.installationID
	}
	return current == installed
}

// CurrentAuthInstallation returns the current auth only when expected still
// identifies the installed generation for its auth ID.
func (m *Manager) CurrentAuthInstallation(expected *Auth) (*Auth, bool) {
	if m == nil || expected == nil || expected.ID == "" {
		return nil, false
	}
	m.mu.RLock()
	current := m.auths[expected.ID]
	if current == nil ||
		(expected.installationID != "" && current.installationID != expected.installationID) ||
		(expected.installationID == "" && expected.instanceID != "" && current.instanceID != expected.instanceID) {
		m.mu.RUnlock()
		return nil, false
	}
	snapshot := current.Clone()
	m.mu.RUnlock()
	return snapshot, true
}

func (m *Manager) waitForRefreshExecutions(auth *Auth) {
	if m == nil || auth == nil || auth.instanceState == nil {
		return
	}
	waitTimeout := m.refreshCleanupWait
	if waitTimeout <= 0 {
		waitTimeout = refreshShutdownTimeout
	}
	timer := time.NewTimer(waitTimeout)
	defer timer.Stop()
	for {
		m.mu.RLock()
		tracked := m.refreshExecutions[auth.instanceState]
		wait := make([]<-chan struct{}, 0, len(tracked))
		for done := range tracked {
			wait = append(wait, done)
		}
		m.mu.RUnlock()
		if len(wait) == 0 {
			return
		}
		for _, done := range wait {
			select {
			case <-done:
			case <-timer.C:
				log.WithField("auth_id", auth.ID).Warn("timed out waiting for retired auth refresh cleanup")
				return
			}
		}
	}
}

func (m *Manager) runSessionCleanupCallback(id, reason, component string, callback func()) {
	if callback == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			log.WithFields(log.Fields{
				"auth_id":   id,
				"reason":    reason,
				"component": component,
			}).Errorf("auth session cleanup callback panicked: %v", recovered)
		}
	}()
	callback()
}

func (m *Manager) beginSessionCleanup(id string) {
	m.mu.Lock()
	m.beginSessionCleanupLocked(id)
	m.mu.Unlock()
}

func (m *Manager) beginAuthInstanceCleanupLocked(id string) {
	current := m.auths[id]
	m.beginSessionCleanupLocked(id)
	if current == nil {
		return
	}
	if current.instanceState != nil {
		if m.sessionCleanupInstances == nil {
			m.sessionCleanupInstances = make(map[string]map[*authInstanceState]struct{})
		}
		instances := m.sessionCleanupInstances[id]
		if instances == nil {
			instances = make(map[*authInstanceState]struct{})
			m.sessionCleanupInstances[id] = instances
		}
		instances[current.instanceState] = struct{}{}
	}
	current.retireInstance()
}

func (m *Manager) beginSessionCleanupLocked(id string) {
	if m.sessionCleanups == nil {
		m.sessionCleanups = make(map[string]int)
	}
	m.sessionCleanups[id]++
	if m.scheduler != nil {
		m.scheduler.blockAuth(id)
	}
}

func (m *Manager) endSessionCleanup(id string) {
	var (
		current            *Auth
		completedInstances map[*authInstanceState]struct{}
	)
	m.mu.Lock()
	remaining := m.sessionCleanups[id] - 1
	if remaining > 0 {
		m.sessionCleanups[id] = remaining
		m.mu.Unlock()
		return
	}
	delete(m.sessionCleanups, id)
	completedInstances = m.sessionCleanupInstances[id]
	delete(m.sessionCleanupInstances, id)
	if auth := m.auths[id]; auth != nil {
		current = auth.Clone()
	}
	if m.scheduler != nil && m.maintenanceAuths[id] == nil {
		m.scheduler.unblockAuth(id, current)
	}
	m.mu.Unlock()
	for instance := range completedInstances {
		instance.completeCleanup()
	}
	if current != nil {
		m.queueRefreshReschedule(id)
	} else {
		m.evictRoundTripperForAuth(id)
	}
}

func (m *Manager) sessionCleanupPendingLocked(id string) bool {
	return m != nil && m.sessionCleanups[id] > 0
}

func carryForwardAuthModelStates(existing *Auth, next *Auth) {
	if !authStateCarryForwardAllowed(existing, next) {
		return
	}
	if len(next.ModelStates) == 0 && len(existing.ModelStates) > 0 {
		next.ModelStates = cloneAuthModelStates(existing.ModelStates)
	}
}

func carryForwardAuthRuntimeState(existing *Auth, next *Auth) {
	if !authStateCarryForwardAllowed(existing, next) {
		return
	}
	if existing.Unavailable && !next.Unavailable {
		next.Unavailable = true
	}
	if (next.Status == "" || next.Status == StatusActive) && existing.Status != "" && existing.Status != StatusActive {
		next.Status = existing.Status
	}
	if next.LastError == nil && existing.LastError != nil {
		next.LastError = cloneError(existing.LastError)
	}
	if next.StatusMessage == "" && existing.StatusMessage != "" {
		next.StatusMessage = existing.StatusMessage
	}
	if next.NextRetryAfter.IsZero() && !existing.NextRetryAfter.IsZero() {
		next.NextRetryAfter = existing.NextRetryAfter
	}
	if next.CooldownScope == "" && existing.CooldownScope != "" && !next.NextRetryAfter.IsZero() {
		next.CooldownScope = existing.CooldownScope
	}
	if quotaStateEmpty(next.Quota) && !quotaStateEmpty(existing.Quota) {
		next.Quota = existing.Quota
	}
}

func prepareAuthReplacement(existing *Auth, next *Auth, skipStateCarryForward bool) {
	if next == nil {
		return
	}
	carryForwardXAIConfigIdentity(existing, next)
	normalizeChatGPTWebDependencyState(next)
	if existing != nil && !next.indexAssigned && next.Index == "" {
		next.Index = existing.Index
		next.indexAssigned = existing.indexAssigned
	}
	if existing != nil && !skipStateCarryForward && authStateCarryForwardAllowed(existing, next) {
		carryForwardAuthRuntimeState(existing, next)
		carryForwardAuthModelStates(existing, next)
	}
	next.EnsureIndex()
}

func authStateCarryForwardAllowed(existing *Auth, next *Auth) bool {
	if existing == nil || next == nil {
		return false
	}
	if existing.Disabled || existing.Status == StatusDisabled || next.Disabled || next.Status == StatusDisabled {
		return false
	}
	existingHash := authSourceHash(existing)
	nextHash := authSourceHash(next)
	if existingHash == "" || nextHash == "" {
		return false
	}
	if existingHash != nextHash {
		return false
	}
	return true
}

func authRuntimeInstanceEquivalent(existing *Auth, next *Auth) bool {
	if existing == nil || next == nil {
		return false
	}
	if existing.Disabled || existing.Status == StatusDisabled || next.Disabled || next.Status == StatusDisabled {
		return false
	}
	existingHash := authSourceHash(existing)
	nextHash := authSourceHash(next)
	if existingHash != "" || nextHash != "" {
		return existingHash != "" && existingHash == nextHash
	}
	if !hashlessConfigAuth(existing) || !hashlessConfigAuth(next) {
		return false
	}
	return existing.ID == next.ID &&
		strings.EqualFold(strings.TrimSpace(existing.Provider), strings.TrimSpace(next.Provider)) &&
		existing.Prefix == next.Prefix &&
		existing.Label == next.Label &&
		existing.FileName == next.FileName &&
		existing.ProxyURL == next.ProxyURL &&
		reflect.DeepEqual(existing.Attributes, next.Attributes) &&
		reflect.DeepEqual(existing.Metadata, next.Metadata)
}

type loadAuthInstanceSummary struct {
	id            string
	provider      string
	prefix        string
	label         string
	fileName      string
	proxyURL      string
	disabled      bool
	status        Status
	sourceHash    string
	hashless      bool
	attributes    map[string]string
	metadata      map[string]any
	instanceID    string
	instanceState *authInstanceState
}

func snapshotLoadAuthInstance(auth *Auth) loadAuthInstanceSummary {
	if auth == nil {
		return loadAuthInstanceSummary{}
	}
	summary := loadAuthInstanceSummary{
		id:            auth.ID,
		provider:      auth.Provider,
		prefix:        auth.Prefix,
		label:         auth.Label,
		fileName:      auth.FileName,
		proxyURL:      auth.ProxyURL,
		disabled:      auth.Disabled,
		status:        auth.Status,
		sourceHash:    authSourceHash(auth),
		hashless:      hashlessConfigAuth(auth),
		instanceID:    auth.instanceID,
		instanceState: auth.instanceState,
	}
	if summary.hashless {
		if len(auth.Attributes) > 0 {
			summary.attributes = make(map[string]string, len(auth.Attributes))
			for key, value := range auth.Attributes {
				summary.attributes[key] = value
			}
		}
		if len(auth.Metadata) > 0 {
			summary.metadata = make(map[string]any, len(auth.Metadata))
			for key, value := range auth.Metadata {
				summary.metadata[key] = value
			}
		}
	}
	return summary
}

func (s loadAuthInstanceSummary) equivalent(next *Auth) bool {
	if next == nil || s.id == "" || s.disabled || s.status == StatusDisabled || next.Disabled || next.Status == StatusDisabled {
		return false
	}
	nextHash := authSourceHash(next)
	if s.sourceHash != "" || nextHash != "" {
		return s.sourceHash != "" && s.sourceHash == nextHash
	}
	if !s.hashless || !hashlessConfigAuth(next) {
		return false
	}
	return s.id == next.ID &&
		strings.EqualFold(strings.TrimSpace(s.provider), strings.TrimSpace(next.Provider)) &&
		s.prefix == next.Prefix &&
		s.label == next.Label &&
		s.fileName == next.FileName &&
		s.proxyURL == next.ProxyURL &&
		reflect.DeepEqual(s.attributes, next.Attributes) &&
		reflect.DeepEqual(s.metadata, next.Metadata)
}

func hashlessConfigAuth(auth *Auth) bool {
	if auth == nil || strings.TrimSpace(auth.FileName) != "" {
		return false
	}
	source := ""
	authKind := ""
	apiKey := ""
	if auth.Attributes != nil {
		source = strings.ToLower(strings.TrimSpace(auth.Attributes["source"]))
		authKind = strings.ToLower(strings.TrimSpace(auth.Attributes["auth_kind"]))
		apiKey = strings.TrimSpace(auth.Attributes["api_key"])
	}
	return strings.HasPrefix(source, "config:") || authKind == "apikey" || apiKey != ""
}

func authSourceHash(auth *Auth) string {
	if auth == nil || auth.Attributes == nil {
		return ""
	}
	return strings.TrimSpace(auth.Attributes[SourceHashAttributeKey])
}

func cloneAuthModelStates(states map[string]*ModelState) map[string]*ModelState {
	if len(states) == 0 {
		return nil
	}
	cloned := make(map[string]*ModelState, len(states))
	for key, state := range states {
		cloned[key] = state.Clone()
	}
	return cloned
}

func quotaStateEmpty(state QuotaState) bool {
	return !state.Exceeded &&
		state.Reason == "" &&
		state.NextRecoverAt.IsZero() &&
		state.BackoffLevel == 0 &&
		state.StrikeCount == 0
}

func persistedAuthIndexConflict(err error) bool {
	return errors.Is(err, ErrAuthAlreadyExists) ||
		errors.Is(err, ErrChatGPTWebEmailAlreadyExists) ||
		errors.Is(err, authfileguard.ErrPersistGenerationStale)
}

// Delete removes an auth entry from runtime state and optionally from the backing store.
func (m *Manager) Delete(ctx context.Context, id string) error {
	_, err := m.deleteIf(ctx, id, nil)
	return err
}

// DeleteIf removes an auth only when predicate still matches the current
// runtime entry while the per-auth persistence lock is held.
func (m *Manager) DeleteIf(ctx context.Context, id string, predicate func(*Auth) bool) (bool, error) {
	return m.deleteIf(ctx, id, predicate)
}

func (m *Manager) deleteIf(ctx context.Context, id string, predicate func(*Auth) bool) (bool, error) {
	if m == nil {
		return false, nil
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	lockedDependencyCtx, unlockDependency, errDependency := m.lockChatGPTWebDependencyMutationContext(ctx, id, nil, false)
	if errDependency != nil {
		return false, errDependency
	}
	ctx = lockedDependencyCtx
	dependencyLocked := true
	defer func() {
		if dependencyLocked {
			unlockDependency()
		}
	}()

	unlockPersist, errLock := m.lockAuthIDMutationContext(ctx, id)
	if errLock != nil {
		return false, errLock
	}

	var deleted *Auth
	var deletedRuntime *Auth
	m.mu.RLock()
	if existing, ok := m.auths[id]; ok && existing != nil {
		deletedRuntime = existing
		deleted = existing.Clone()
	}
	m.mu.RUnlock()
	if deleted == nil {
		unlockPersist()
		return false, nil
	}
	if predicate != nil && !predicate(deleted.Clone()) {
		unlockPersist()
		return false, nil
	}

	shouldPersistDelete := m.store != nil && !shouldSkipPersist(ctx)
	if shouldPersistDelete && authIsRuntimeOnly(deleted) {
		shouldPersistDelete = false
	}
	var deleteErr error
	cleanupReason := "auth_removed"
	if shouldPersistDelete {
		deleteStore := m.store.Delete
		if generation := authfileguard.DeleteGenerationFromContext(ctx); generation != nil && strings.TrimSpace(generation.ExpectedHash()) != "" {
			conditionalStore, ok := m.store.(SourceConditionalDeleteStore)
			if !ok || conditionalStore == nil {
				unlockPersist()
				return false, NewDeleteOutcomeError(DeleteOutcomeRolledBack, errors.New("auth store does not support source-conditional deletion"))
			}
			deleteStore = func(deleteCtx context.Context, deleteID string) error {
				return conditionalStore.DeleteIfSourceHashMatches(deleteCtx, deleteID, generation.ExpectedHash())
			}
		}
		deleteErr = deleteStore(ctx, id)
		if deleteErr != nil {
			outcome, explicitOutcome := DeleteOutcomeFromError(deleteErr)
			if !explicitOutcome || outcome == DeleteOutcomeRolledBack {
				if persistedAuthIndexConflict(deleteErr) {
					m.MarkChatGPTWebDependencyIndexDirty()
				}
				unlockPersist()
				return false, deleteErr
			}
			if outcome == DeleteOutcomeCommitted {
				deleteErr = nil
			} else {
				cleanupReason = "auth_delete_uncertain"
			}
		}
	}

	removed := false
	m.mu.Lock()
	if current, ok := m.auths[id]; ok && current == deletedRuntime {
		m.beginAuthInstanceCleanupLocked(id)
		m.removeAuthLocked(id)
		if !shouldPersistDelete && authRelevantToChatGPTWebDependencyIndex(deleted) {
			m.dependencyIndexComplete = false
		}
		if !shouldPersistDelete && strings.EqualFold(strings.TrimSpace(deleted.Provider), "chatgpt-web") {
			m.chatGPTWebIdentityComplete = false
		}
		removed = true
	}
	if shouldPersistDelete {
		if deleteErr == nil {
			m.recordPersistedAuthDeleteLocked(id)
		} else {
			m.markChatGPTWebDependencyIndexDirtyLocked()
		}
	}
	m.mu.Unlock()
	if !removed {
		unlockPersist()
		return false, deleteErr
	}

	m.cleanupRemovedAuthRuntimeStateAfterQuarantine(id)
	unlockPersist()
	unlockDependency()
	dependencyLocked = false
	m.finishAuthSessionCleanup(id, deleted, cleanupReason, nil)
	return true, deleteErr
}

// DeleteWithOperation retires an auth, runs a backing-store deletion while the
// auth persistence key is locked, and removes the runtime entry only on success.
func (m *Manager) DeleteWithOperation(ctx context.Context, id string, operation func(context.Context) error) error {
	return m.deleteWithOperation(ctx, id, operation, true)
}

// DeleteWithOperationFailClosed keeps the runtime auth removed when a backing
// deletion is rolled back. It is intended for credentials that must not become
// executable again even when their historical backing file remains.
func (m *Manager) DeleteWithOperationFailClosed(ctx context.Context, id string, operation func(context.Context) error) error {
	return m.deleteWithOperation(ctx, id, operation, false)
}

func (m *Manager) deleteWithOperation(ctx context.Context, id string, operation func(context.Context) error, restoreOnRollback bool) error {
	if operation == nil {
		return errors.New("auth manager: delete operation is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	id = strings.TrimSpace(id)
	if m == nil || id == "" {
		return operation(ctx)
	}
	lockedDependencyCtx, unlockDependency, errDependency := m.lockChatGPTWebDependencyMutationContext(ctx, id, nil, false)
	if errDependency != nil {
		return errDependency
	}
	ctx = lockedDependencyCtx
	dependencyLocked := true
	defer func() {
		if dependencyLocked {
			unlockDependency()
		}
	}()

	unlockPersist, errLock := m.lockAuthIDMutationContext(ctx, id)
	if errLock != nil {
		return errLock
	}
	var current *Auth
	var deleted *Auth
	m.mu.Lock()
	if existing := m.auths[id]; existing != nil {
		current = existing
		deleted = existing.Clone()
		m.beginAuthInstanceCleanupLocked(id)
	}
	m.mu.Unlock()

	errOperation := operation(ctx)
	if errOperation != nil {
		outcome, explicitOutcome := DeleteOutcomeFromError(errOperation)
		if !explicitOutcome {
			outcome = DeleteOutcomeUncertain
		}
		if outcome == DeleteOutcomeRolledBack && restoreOnRollback && deleted != nil {
			m.mu.Lock()
			if m.auths[id] == current {
				restored := current.Clone()
				restored.installationID = uuid.NewString()
				restored.requestRefreshFamilyID = uuid.NewString()
				restored.instanceID = uuid.NewString()
				restored.instanceState = &authInstanceState{}
				restored.bindExecutorOwner(m.executors[executorKeyFromAuth(restored)])
				m.installAuthLocked(id, restored)
			}
			m.mu.Unlock()
		}
		removed := false
		m.mu.Lock()
		if (outcome != DeleteOutcomeRolledBack || !restoreOnRollback) && deleted != nil {
			if m.auths[id] == current {
				m.removeAuthLocked(id)
				removed = true
			}
		}
		switch outcome {
		case DeleteOutcomeCommitted:
			m.recordPersistedAuthDeleteLocked(id)
		case DeleteOutcomeUncertain:
			m.markChatGPTWebDependencyIndexDirtyLocked()
		case DeleteOutcomeRolledBack:
			if persistedAuthIndexConflict(errOperation) {
				m.markChatGPTWebDependencyIndexDirtyLocked()
			} else if !restoreOnRollback && deleted != nil {
				if authRelevantToChatGPTWebDependencyIndex(deleted) {
					m.dependencyIndexComplete = false
				}
				if strings.EqualFold(strings.TrimSpace(deleted.Provider), "chatgpt-web") {
					m.chatGPTWebIdentityComplete = false
				}
			}
		}
		m.mu.Unlock()
		if removed {
			m.cleanupRemovedAuthRuntimeStateAfterQuarantine(id)
		}
		unlockPersist()
		unlockDependency()
		dependencyLocked = false
		if deleted != nil {
			reason := "auth_delete_uncertain"
			if outcome == DeleteOutcomeRolledBack {
				reason = "auth_delete_rolled_back"
			} else if outcome == DeleteOutcomeCommitted {
				reason = "auth_removed"
			}
			m.finishAuthSessionCleanup(id, deleted, reason, nil)
		}
		if outcome == DeleteOutcomeCommitted {
			return nil
		}
		return errOperation
	}

	removed := false
	m.mu.Lock()
	if deleted != nil {
		if m.auths[id] == current {
			m.removeAuthLocked(id)
			removed = true
		}
	}
	m.recordPersistedAuthDeleteLocked(id)
	m.mu.Unlock()
	if removed {
		m.cleanupRemovedAuthRuntimeStateAfterQuarantine(id)
	}
	unlockPersist()
	unlockDependency()
	dependencyLocked = false
	if deleted != nil {
		m.finishAuthSessionCleanup(id, deleted, "auth_removed", nil)
	}
	return nil
}

// Load resets manager state from the backing store.
func (m *Manager) Load(ctx context.Context) error {
	_, err := m.LoadWithReport(ctx)
	return err
}

// LoadWithReport resets manager state and returns a safe aggregate describing
// records scanned, installed, and skipped by standard stores and manager-level
// credential filtering.
func (m *Manager) LoadWithReport(ctx context.Context) (StoreLoadReport, error) {
	report := StoreLoadReport{}
	if m == nil {
		return report, nil
	}
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	if errLock := m.chatGPTWebDependencyMutation.lock(ctx); errLock != nil {
		return report, errLock
	}
	dependencyLocked := true
	defer func() {
		if dependencyLocked {
			m.chatGPTWebDependencyMutation.unlock()
		}
	}()
	unlockBarrier, errBarrier := m.lockPersistBarrierWrite(ctx)
	if errBarrier != nil {
		return report, errBarrier
	}
	defer unlockBarrier()
	m.mu.RLock()
	store := m.store
	storeRevision := m.storeRevision
	previous := make(map[string]loadAuthInstanceSummary, len(m.auths))
	for id, auth := range m.auths {
		previous[id] = snapshotLoadAuthInstance(auth)
	}
	m.mu.RUnlock()
	if store == nil {
		return report, nil
	}
	var items []*Auth
	var err error
	if reportingStore, ok := store.(LoadReportingStore); ok {
		items, report, err = reportingStore.ListWithReport(ctx)
	} else {
		items, err = store.List(ctx)
		report.Scanned = int64(len(items))
		report.Loaded = int64(len(items))
	}
	if err != nil {
		return report, err
	}
	items = deduplicateLoadedChatGPTWebAuths(items)
	loaded := make(map[string]*Auth, len(items))
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		cfg = &internalconfig.Config{}
	}
	for _, auth := range items {
		if auth == nil || auth.ID == "" {
			continue
		}
		if IsRetiredGeminiCLIAuth(auth) {
			WarnRetiredGeminiCLIAuthIgnored()
			continue
		}
		if authFilePathQuarantined(auth, cfg.AuthDir) {
			continue
		}
		auth.EnsureIndex()
		loadedAuth := auth.Clone()
		normalizeModelStates(loadedAuth)
		if errRules := prepareAuthRequestScopedErrors(loadedAuth); errRules != nil {
			log.WithError(errRules).Warn("auth: skipping credential with invalid request-scoped error rules")
			continue
		}
		projectionPath := ""
		if loadedAuth.Attributes != nil {
			projectionPath = strings.TrimSpace(loadedAuth.Attributes["path"])
		}
		if projectionPath == "" {
			projectionPath = strings.TrimSpace(loadedAuth.FileName)
		}
		if projectionPath != "" && loadedAuth.Metadata != nil {
			if errProjection := ApplyFileAuthProjection(loadedAuth, FileAuthProjectionOptions{
				Config:  cfg,
				AuthDir: cfg.AuthDir,
				Path:    projectionPath,
				Now:     loadedAuth.UpdatedAt,
			}); errProjection != nil {
				log.WithError(errProjection).Warnf("auth: skipping %s with invalid file projection", auth.ID)
				continue
			}
		}
		loadedAuth.EnsureIndex()
		normalizeChatGPTWebDependencyState(loadedAuth)
		stampChatGPTWebCredentialGeneration(loadedAuth)
		applyLifecycleRuntimeState(loadedAuth)
		loadedAuth.installationID = uuid.NewString()
		loadedAuth.requestRefreshFamilyID = uuid.NewString()
		if existing, ok := previous[auth.ID]; ok && existing.equivalent(loadedAuth) {
			loadedAuth.instanceID = existing.instanceID
			loadedAuth.instanceState = existing.instanceState
		}
		if loadedAuth.instanceID == "" {
			loadedAuth.instanceID = uuid.NewString()
		}
		if loadedAuth.instanceState == nil {
			loadedAuth.instanceState = &authInstanceState{}
		}
		loaded[auth.ID] = loadedAuth
	}
	schedulerAuths := make([]*Auth, 0, len(loaded))
	for _, auth := range loaded {
		schedulerAuths = append(schedulerAuths, auth.Clone())
	}
	sort.Slice(schedulerAuths, func(i, j int) bool {
		return schedulerAuths[i].ID < schedulerAuths[j].ID
	})

	var (
		removed  map[string]*Auth
		replaced map[string]*Auth
	)
	for {
		cfg = m.currentConfig()
		indexState := buildManagerAuthIndexState(loaded, items, true, cfg)
		modelRouting := buildAPIKeyModelRoutingSnapshot(loaded, cfg)

		m.mu.Lock()
		if m.storeRevision != storeRevision {
			m.mu.Unlock()
			return report, errors.New("auth store changed during load")
		}
		if m.currentConfig() != cfg {
			m.mu.Unlock()
			continue
		}
		removed = make(map[string]*Auth)
		replaced = make(map[string]*Auth)
		for id, auth := range m.auths {
			loadedAuth, ok := loaded[id]
			if (!ok || loadedAuth == nil) && auth != nil {
				removed[id] = auth.Clone()
			} else if auth != nil && loadedAuth.instanceID != auth.instanceID {
				replaced[id] = auth.Clone()
			}
		}
		for id := range removed {
			m.beginAuthInstanceCleanupLocked(id)
		}
		for id := range replaced {
			m.beginAuthInstanceCleanupLocked(id)
		}
		for _, loadedAuth := range loaded {
			if loadedAuth != nil && loadedAuth.instanceState != nil {
				loadedAuth.bindExecutorOwner(m.executors[executorKeyFromAuth(loadedAuth)])
			}
		}
		m.auths = loaded
		m.applyManagerAuthIndexStateLocked(indexState)
		m.apiKeyModelRouting.Store(modelRouting)
		m.mu.Unlock()
		break
	}

	m.syncSchedulerFromSnapshot(schedulerAuths)
	for id := range removed {
		m.cleanupRemovedAuthRuntimeStateAfterQuarantine(id)
	}
	unlockBarrier()
	m.chatGPTWebDependencyMutation.unlock()
	dependencyLocked = false
	for id, auth := range removed {
		m.finishAuthSessionCleanup(id, auth, "auth_reloaded", nil)
	}
	for id, auth := range replaced {
		m.finishAuthSessionCleanup(id, auth, "auth_replaced", nil)
	}
	report.Loaded = int64(len(loaded))
	if report.Scanned < report.Loaded {
		report.Scanned = report.Loaded
	}
	report.Skipped = report.Scanned - report.Loaded
	return report, nil
}

func deduplicateLoadedChatGPTWebAuths(items []*Auth) []*Auth {
	if len(items) < 2 {
		return items
	}
	selected := make([]*Auth, 0, len(items))
	byEmail := make(map[string][]int)
	for _, auth := range items {
		email := chatGPTWebRegistrationEmail(auth)
		if email == "" {
			selected = append(selected, auth)
			continue
		}
		index := -1
		for _, candidateIndex := range byEmail[email] {
			if ChatGPTWebCredentialIdentityConflict(selected[candidateIndex], auth) {
				index = candidateIndex
				break
			}
		}
		if index < 0 {
			byEmail[email] = append(byEmail[email], len(selected))
			selected = append(selected, auth)
			continue
		}
		kept := selected[index]
		ignored := auth
		if preferLoadedChatGPTWebAuth(auth, kept, email) {
			selected[index] = auth
			kept, ignored = auth, kept
		}
		log.WithFields(log.Fields{
			"kept_auth_id":    strings.TrimSpace(kept.ID),
			"ignored_auth_id": strings.TrimSpace(ignored.ID),
		}).Warn("ignoring duplicate ChatGPT Web credential during auth reload")
	}
	return selected
}

func preferLoadedChatGPTWebAuth(candidate, current *Auth, email string) bool {
	canonicalName := chatgptwebauth.CredentialFileName(email)
	candidateCanonical := chatGPTWebAuthUsesFileName(candidate, canonicalName)
	currentCanonical := chatGPTWebAuthUsesFileName(current, canonicalName)
	if candidateCanonical != currentCanonical {
		return candidateCanonical
	}
	return strings.ToLower(strings.TrimSpace(candidate.ID)) < strings.ToLower(strings.TrimSpace(current.ID))
}

func chatGPTWebAuthUsesFileName(auth *Auth, fileName string) bool {
	if auth == nil || fileName == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(auth.ID), fileName) {
		return true
	}
	return strings.EqualFold(filepath.Base(strings.TrimSpace(auth.FileName)), fileName)
}

func authFilePathQuarantined(auth *Auth, authDir string) bool {
	if auth == nil {
		return false
	}
	path := ""
	if auth.Attributes != nil {
		path = strings.TrimSpace(auth.Attributes["source"])
		if path == "" {
			path = strings.TrimSpace(auth.Attributes["path"])
		}
	}
	if path == "" {
		path = strings.TrimSpace(auth.FileName)
	}
	if path == "" {
		return false
	}
	if !filepath.IsAbs(path) && strings.TrimSpace(authDir) != "" {
		path = filepath.Join(authDir, path)
	}
	return authfileguard.IsQuarantined(path)
}

// Execute performs a non-streaming execution using the configured selector and executor.
// It supports multiple providers for the same model and round-robins the starting provider per model.
func (m *Manager) Execute(ctx context.Context, providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (response cliproxyexecutor.Response, err error) {
	ctx = coreusage.WithStreamDefault(ctx, false)
	ctx = contextWithGenerateMetadata(ctx, opts)
	ctx = m.WithRoutingPolicySnapshot(ctx)
	ctx = m.withCodexQuotaObservation(ctx)
	ctx, upstreamErrors := withUpstreamErrorHistory(ctx)
	var releaseProducer func()
	ctx, _, releaseProducer, err = m.beginResultPersistenceProducer(ctx)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	defer releaseProducer()
	opts = m.ensureExecutionDiagnostics(opts)
	ctx = cliproxyexecutor.WithRequestUsageOutcome(
		cliproxyexecutor.WithRequestExecutionDiagnostics(ctx, opts.ExecutionDiagnostics), opts.UsageOutcome)
	defer func() {
		err = upstreamErrors.preferred(err)
		if timeout := cliproxyexecutor.ImageRequestContextError(ctx, nil); timeout != nil {
			err = withInheritedErrorResponseSource(timeout, err)
		}
		if err != nil {
			err = finalizeErrorResponseSource(opts.Metadata, err)
		}
		m.recordExecutionResultMetrics(opts, err)
		if err != nil {
			opts.UsageOutcome.FinalizeFailure()
			return
		}
		opts.ExecutionDiagnostics.ClearFailure()
		opts.UsageOutcome.FinalizeSuccess()
	}()
	if usesRetiredGeminiCLIExecutionFormat(req, opts) || usesRetiredGeminiCLIProvider(providers) {
		return cliproxyexecutor.Response{}, retiredGeminiCLIAuthError()
	}
	normalized := m.normalizeProviders(providers)
	if len(normalized) == 0 {
		return cliproxyexecutor.Response{}, &Error{Code: "provider_not_found", Message: "no provider supplied"}
	}
	var errPrepare error
	normalized, opts, errPrepare = m.prepareProviderRequests(ctx, normalized, req, opts, cliproxyexecutor.RequestOperationExecute)
	if errPrepare != nil {
		return cliproxyexecutor.Response{}, errPrepare
	}
	strictSessionAffinity := m.strictSessionAffinityForRequest(ctx, req, opts)

	defaultRequestRetry, maxRetryCredentials, maxWait := m.retrySettings(ctx)
	requestRetry := m.maxRequestRetryForProviders(normalized, defaultRequestRetry)
	roundState := newRequestRoundState()

	var lastErr error
	for attempt := 0; ; {
		resp, errExec := m.executeMixedOnce(ctx, normalized, req, opts, attempt, maxRetryCredentials, defaultRequestRetry, roundState)
		if errExec == nil {
			return resp, nil
		}
		if lastErr != nil && emptyCredentialRetryRound(roundState, errExec) {
			break
		}
		lastErr = errExec
		if !requestBodyReplayable(ctx, opts) {
			break
		}
		if wait, shouldWait := cooldownWaitFromError(errExec, maxWait); shouldWait {
			if errWait := waitForCooldown(ctx, wait); errWait != nil {
				return cliproxyexecutor.Response{}, withInheritedErrorResponseSource(errWait, errExec)
			}
			if !requestBodyReplayable(ctx, opts) {
				break
			}
			continue
		}
		if strictSessionAffinity || !requestBodyReplayable(ctx, opts) || isResponsesCompactRequestFaultError(opts, errExec) || !shouldRetryRequestRound(errExec, m.requestNonRetryableErrorRules(ctx)) || attempt >= requestRetry {
			break
		}
		if wait, shouldWait := retryAfterWaitFromError(errExec, maxWait); shouldWait {
			if errWait := waitForCooldown(ctx, wait); errWait != nil {
				return cliproxyexecutor.Response{}, withInheritedErrorResponseSource(errWait, errExec)
			}
			if !requestBodyReplayable(ctx, opts) {
				break
			}
		}
		attempt++
		roundState = newRequestRoundState()
	}
	if lastErr != nil {
		if requestBodyReplayable(ctx, opts) && !strictSessionAffinity && shouldAttemptAntigravityCreditsFallback(m, lastErr, normalized) {
			if resp, ok, errCredits := m.tryAntigravityCreditsExecute(ctx, req, opts); ok {
				return resp, nil
			} else if errCredits != nil {
				lastErr = errCredits
			}
		}
		return cliproxyexecutor.Response{}, finalAuthSelectionError(lastErr)
	}
	return cliproxyexecutor.Response{}, &Error{Code: "auth_not_found", Message: "no auth available"}
}

// ExecuteCount performs a non-streaming execution using the configured selector and executor.
// It supports multiple providers for the same model and round-robins the starting provider per model.
func (m *Manager) ExecuteCount(ctx context.Context, providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (response cliproxyexecutor.Response, err error) {
	ctx = coreusage.WithStreamDefault(ctx, false)
	ctx = contextWithGenerateMetadata(ctx, opts)
	ctx = m.WithRoutingPolicySnapshot(ctx)
	ctx = cliproxyexecutor.WithCodexQuotaObserver(ctx, nil)
	ctx, upstreamErrors := withUpstreamErrorHistory(ctx)
	var releaseProducer func()
	ctx, _, releaseProducer, err = m.beginResultPersistenceProducer(ctx)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	defer releaseProducer()
	opts = m.ensureExecutionDiagnostics(opts)
	ctx = cliproxyexecutor.WithRequestUsageOutcome(
		cliproxyexecutor.WithRequestExecutionDiagnostics(ctx, opts.ExecutionDiagnostics), opts.UsageOutcome)
	defer func() {
		err = upstreamErrors.preferred(err)
		if err != nil {
			err = finalizeErrorResponseSource(opts.Metadata, err)
		}
		m.recordExecutionResultMetrics(opts, err)
		if err != nil {
			opts.UsageOutcome.FinalizeFailure()
			return
		}
		opts.ExecutionDiagnostics.ClearFailure()
		opts.UsageOutcome.FinalizeSuccess()
	}()
	if usesRetiredGeminiCLIExecutionFormat(req, opts) || usesRetiredGeminiCLIProvider(providers) {
		return cliproxyexecutor.Response{}, retiredGeminiCLIAuthError()
	}
	normalized := m.normalizeProviders(providers)
	if len(normalized) == 0 {
		return cliproxyexecutor.Response{}, &Error{Code: "provider_not_found", Message: "no provider supplied"}
	}
	var errPrepare error
	normalized, opts, errPrepare = m.prepareProviderRequests(ctx, normalized, req, opts, cliproxyexecutor.RequestOperationCount)
	if errPrepare != nil {
		return cliproxyexecutor.Response{}, errPrepare
	}
	strictSessionAffinity := m.strictSessionAffinityForRequest(ctx, req, opts)

	defaultRequestRetry, maxRetryCredentials, maxWait := m.retrySettings(ctx)
	requestRetry := m.maxRequestRetryForProviders(normalized, defaultRequestRetry)
	roundState := newRequestRoundState()

	var lastErr error
	for attempt := 0; ; {
		resp, errExec := m.executeCountMixedOnce(ctx, normalized, req, opts, attempt, maxRetryCredentials, defaultRequestRetry, roundState)
		if errExec == nil {
			return resp, nil
		}
		if lastErr != nil && emptyCredentialRetryRound(roundState, errExec) {
			break
		}
		lastErr = errExec
		if !requestBodyReplayable(ctx, opts) {
			break
		}
		if wait, shouldWait := cooldownWaitFromError(errExec, maxWait); shouldWait {
			if errWait := waitForCooldown(ctx, wait); errWait != nil {
				return cliproxyexecutor.Response{}, withInheritedErrorResponseSource(errWait, errExec)
			}
			if !requestBodyReplayable(ctx, opts) {
				break
			}
			continue
		}
		if strictSessionAffinity || !requestBodyReplayable(ctx, opts) || !shouldRetryRequestRound(errExec, m.requestNonRetryableErrorRules(ctx)) || attempt >= requestRetry {
			break
		}
		if wait, shouldWait := retryAfterWaitFromError(errExec, maxWait); shouldWait {
			if errWait := waitForCooldown(ctx, wait); errWait != nil {
				return cliproxyexecutor.Response{}, withInheritedErrorResponseSource(errWait, errExec)
			}
			if !requestBodyReplayable(ctx, opts) {
				break
			}
		}
		attempt++
		roundState = newRequestRoundState()
	}
	if lastErr != nil {
		return cliproxyexecutor.Response{}, finalAuthSelectionError(lastErr)
	}
	return cliproxyexecutor.Response{}, &Error{Code: "auth_not_found", Message: "no auth available"}
}

// ExecuteStream performs a streaming execution using the configured selector and executor.
// It supports multiple providers for the same model and round-robins the starting provider per model.
func (m *Manager) ExecuteStream(ctx context.Context, providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (result *cliproxyexecutor.StreamResult, err error) {
	ctx = coreusage.WithStreamDefault(ctx, true)
	ctx = contextWithGenerateMetadata(ctx, opts)
	ctx = m.WithRoutingPolicySnapshot(ctx)
	ctx = m.withCodexQuotaObservation(ctx)
	ctx, upstreamErrors := withUpstreamErrorHistory(ctx)
	var producer *resultPersistenceProducer
	var releaseProducer func()
	ctx, producer, releaseProducer, err = m.beginResultPersistenceProducer(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil || result == nil || producer == nil || !producer.claimed.Load() {
			releaseProducer()
		}
	}()
	opts = m.ensureExecutionDiagnostics(opts)
	ctx = cliproxyexecutor.WithRequestUsageOutcome(
		cliproxyexecutor.WithRequestExecutionDiagnostics(ctx, opts.ExecutionDiagnostics), opts.UsageOutcome)
	defer func() {
		err = upstreamErrors.preferred(err)
		if timeout := cliproxyexecutor.ImageRequestContextError(ctx, nil); timeout != nil {
			err = withInheritedErrorResponseSource(timeout, err)
		}
		if err != nil {
			err = finalizeErrorResponseSource(opts.Metadata, err)
		}
		m.recordExecutionResultMetrics(opts, err)
		if err != nil {
			opts.UsageOutcome.FinalizeFailure()
			return
		}
		opts.ExecutionDiagnostics.ClearFailure()
		opts.UsageOutcome.AcceptStream()
	}()
	if usesRetiredGeminiCLIExecutionFormat(req, opts) || usesRetiredGeminiCLIProvider(providers) {
		return nil, retiredGeminiCLIAuthError()
	}
	normalized := m.normalizeProviders(providers)
	if len(normalized) == 0 {
		return nil, &Error{Code: "provider_not_found", Message: "no provider supplied"}
	}
	var errPrepare error
	normalized, opts, errPrepare = m.prepareProviderRequests(ctx, normalized, req, opts, cliproxyexecutor.RequestOperationStream)
	if errPrepare != nil {
		return nil, errPrepare
	}
	strictSessionAffinity := m.strictSessionAffinityForRequest(ctx, req, opts)

	defaultRequestRetry, maxRetryCredentials, maxWait := m.retrySettings(ctx)
	requestRetry := m.maxRequestRetryForProviders(normalized, defaultRequestRetry)
	roundState := newRequestRoundState()

	var lastErr error
	for attempt := 0; ; {
		result, errStream := m.executeStreamMixedOnce(ctx, normalized, req, opts, attempt, maxRetryCredentials, defaultRequestRetry, roundState)
		if errStream == nil {
			return result, nil
		}
		if lastErr != nil && emptyCredentialRetryRound(roundState, errStream) {
			break
		}
		lastErr = errStream
		if !requestBodyReplayable(ctx, opts) {
			break
		}
		if wait, shouldWait := cooldownWaitFromError(errStream, maxWait); shouldWait {
			if errWait := waitForCooldown(ctx, wait); errWait != nil {
				return nil, withInheritedErrorResponseSource(errWait, errStream)
			}
			if !requestBodyReplayable(ctx, opts) {
				break
			}
			continue
		}
		if strictSessionAffinity || !requestBodyReplayable(ctx, opts) || isResponsesCompactRequestFaultError(opts, errStream) || !shouldRetryRequestRound(errStream, m.requestNonRetryableErrorRules(ctx)) || attempt >= requestRetry {
			break
		}
		if wait, shouldWait := retryAfterWaitFromError(errStream, maxWait); shouldWait {
			if errWait := waitForCooldown(ctx, wait); errWait != nil {
				return nil, withInheritedErrorResponseSource(errWait, errStream)
			}
			if !requestBodyReplayable(ctx, opts) {
				break
			}
		}
		attempt++
		roundState = newRequestRoundState()
	}
	if lastErr != nil {
		if requestBodyReplayable(ctx, opts) && !strictSessionAffinity && shouldAttemptAntigravityCreditsFallback(m, lastErr, normalized) {
			if result, ok, errCredits := m.tryAntigravityCreditsExecuteStream(ctx, req, opts); ok {
				return result, nil
			} else if errCredits != nil {
				lastErr = errCredits
			}
		}
		var bootstrapErr *streamBootstrapError
		if errors.As(lastErr, &bootstrapErr) && bootstrapErr != nil {
			if source, ok := cliproxyexecutor.ErrorResponseSourceOf(lastErr); ok {
				publishErrorResponseSourceMetadata(opts.Metadata, source)
			}
			return streamErrorResult(bootstrapErr.Headers(), bootstrapErr.cause), nil
		}
		return nil, finalAuthSelectionError(lastErr)
	}
	return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
}

type requestAuthPersistenceError struct {
	err error
}

func (e requestAuthPersistenceError) Error() string      { return e.err.Error() }
func (e requestAuthPersistenceError) Unwrap() error      { return e.err }
func (requestAuthPersistenceError) SkipAuthResult() bool { return true }

func (m *Manager) prepareRequestAuth(ctx context.Context, executor ProviderExecutor, auth *Auth, options ...cliproxyexecutor.Options) (*Auth, error) {
	if m == nil || executor == nil || auth == nil {
		return auth, nil
	}
	preparer, ok := executor.(RequestAuthPreparer)
	if len(options) > 0 {
		if prepared, exists := cliproxyexecutor.ProviderPreparedRequest(options[0], executor.Identifier()); exists {
			if scoped, scopedOK := prepared.(RequestAuthPreparer); scopedOK {
				preparer, ok = scoped, true
			}
		}
	}
	if !ok || !preparer.ShouldPrepareRequestAuth(auth) {
		return auth, nil
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	if provider != "chatgpt-web" && provider != "codex" || strings.TrimSpace(auth.ID) == "" {
		return m.prepareRequestAuthSynchronized(ctx, executor, preparer, auth)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return auth, err
	}
	resultChannel := m.requestPrepareFlights.DoChan(requestAuthPrepareFlightKey(auth), func() (any, error) {
		workerCtx := context.WithoutCancel(ctx)
		if provider == "chatgpt-web" {
			releaseFlight, errFlight := m.beginRequestRefreshFlight()
			if errFlight != nil {
				return nil, errFlight
			}
			defer releaseFlight()
			var cancelWorker context.CancelFunc
			workerCtx, cancelWorker = context.WithTimeout(workerCtx, chatGPTWebRefreshFlightTimeout)
			defer cancelWorker()
			reservation, errReserve := m.refreshPersistence.Load().acquireContext(
				workerCtx,
				RefreshPersistencePrioritySession,
				auth.ID,
			)
			if errReserve != nil {
				return nil, requestAuthPersistenceError{err: errReserve}
			}
			defer reservation.release()
			workerCtx = reservation.context(workerCtx)
		}
		return m.prepareRequestAuthSynchronized(workerCtx, executor, preparer, auth)
	})
	select {
	case <-ctx.Done():
		return auth, ctx.Err()
	case result := <-resultChannel:
		if result.Err != nil {
			return auth, result.Err
		}
		prepared, ok := result.Val.(*Auth)
		if !ok && result.Val != nil {
			return auth, fmt.Errorf("chatgpt-web request auth preparation returned %T", result.Val)
		}
		return prepared, nil
	}
}

func requestAuthPrepareFlightKey(auth *Auth) string {
	if auth == nil {
		return ""
	}
	key := strings.ToLower(strings.TrimSpace(auth.Provider)) + "\x00" + strings.TrimSpace(auth.ID)
	if auth.installationID != "" || auth.RuntimeInstanceID() != "" {
		key += "\x00" + auth.installationID + "\x00" + auth.RuntimeInstanceID()
	}
	if sourceHash := authSourceHash(auth); sourceHash != "" {
		key += "\x00" + sourceHash
	}
	return key
}

func (m *Manager) prepareRequestAuthSynchronized(ctx context.Context, executor ProviderExecutor, preparer RequestAuthPreparer, auth *Auth) (*Auth, error) {
	id := strings.TrimSpace(auth.ID)
	if id == "" {
		return preparer.PrepareRequestAuth(ctx, auth.Clone())
	}
	lockIDs := authRequestRefreshLockIDs(auth, id)
	lockedCtx, releaseLocks, errLock := m.lockCredentialRefreshesContext(ctx, lockIDs)
	if errLock != nil {
		return auth, errLock
	}
	defer releaseLocks()
	ctx = lockedCtx

	m.mu.RLock()
	current := m.auths[id]
	if !requestPreparationMatchesCurrent(current, auth) {
		if agentIdentityTaskAlreadyAdvanced(current, auth) {
			target := current.Clone()
			m.mu.RUnlock()
			carryRuntimeProxy(auth, target)
			return target, nil
		}
		m.mu.RUnlock()
		return auth, runtimeAuthInstanceRetiredError()
	}
	target := current.Clone()
	m.mu.RUnlock()
	carryRuntimeProxy(auth, target)
	if !preparer.ShouldPrepareRequestAuth(target) {
		return target, nil
	}

	target.bindExecutorOwner(executor)
	prepareCtx, releasePreparation, active := target.BeginRuntimeExecution(ctx)
	if !active {
		return auth, runtimeAuthInstanceRetiredError()
	}
	updated, errPrepare := preparer.PrepareRequestAuth(prepareCtx, target.Clone())
	retiredDuringPreparation := releasePreparation()
	if retiredDuringPreparation || runtimeAuthInstanceRetiredContext(prepareCtx) {
		return auth, runtimeAuthInstanceRetiredError()
	}
	if errPrepare != nil && (updated == nil || !persistAuthUpdateForError(errPrepare)) {
		return auth, errPrepare
	}
	if updated == nil {
		return target, nil
	}
	refreshAware := isNativeChatGPTWebCredentialAuth(target) && isNativeChatGPTWebCredentialAuth(updated)
	installed, errUpdate := m.installPreparedRequestAuthDurably(ctx, target, updated, refreshAware)
	if errUpdate != nil {
		return updated, errUpdate
	}
	if errPrepare != nil {
		if installed != nil {
			return installed, errPrepare
		}
		return updated, errPrepare
	}
	if installed != nil {
		return installed, nil
	}
	return updated, nil
}

func (m *Manager) installPreparedRequestAuthDurably(ctx context.Context, expected, updated *Auth, refreshAware bool) (*Auth, error) {
	if !refreshAware {
		return m.installPreparedRequestAuth(ctx, expected, updated, false)
	}
	return m.commitChatGPTWebRefreshDurably(ctx, expected, updated, time.Time{}, func(commitCtx context.Context) (*Auth, error) {
		return m.installPreparedRequestAuth(commitCtx, expected, updated, true)
	})
}

func (m *Manager) installPreparedRequestAuth(ctx context.Context, expected, updated *Auth, refreshAware bool) (*Auth, error) {
	return m.installPreparedRequestAuthWithRuntimeMetadata(ctx, expected, updated, refreshAware, false, false)
}

func (m *Manager) installPreparedRequestAuthWithRuntimeMetadata(
	ctx context.Context,
	expected, updated *Auth,
	refreshAware bool,
	allowRuntimeMetadataChanges bool,
	applyUpdatedLastError bool,
) (*Auth, error) {
	if m == nil || expected == nil || updated == nil || strings.TrimSpace(expected.ID) == "" {
		return updated, nil
	}
	id := expected.ID
	updated.ID = id
	lockedDependencyCtx, unlockDependency, errDependency := m.lockChatGPTWebDependencyMutationContext(ctx, id, updated, false)
	if errDependency != nil {
		return nil, errDependency
	}
	ctx = lockedDependencyCtx
	var unlockDependencyOnce sync.Once
	releaseDependency := func() { unlockDependencyOnce.Do(unlockDependency) }
	defer releaseDependency()
	forceRuntimeReplacement := shouldForceRuntimeReplacement(ctx)
	skipRuntimeStateCarryForward := shouldSkipStateCarryForward(ctx)
	lockedCtx, unlockPersist, errLock := m.lockAuthMutationContext(ctx, updated)
	if errLock != nil {
		return nil, errLock
	}
	ctx = lockedCtx
	var unlockOnce sync.Once
	releasePersist := func() { unlockOnce.Do(unlockPersist) }
	defer releasePersist()

	m.mu.Lock()
	current := m.auths[id]
	if !preparedRequestAuthMatchesCurrent(current, expected, allowRuntimeMetadataChanges) {
		m.mu.Unlock()
		return nil, runtimeAuthInstanceRetiredError()
	}
	candidate := updated.Clone()
	if allowRuntimeMetadataChanges || strings.EqualFold(strings.TrimSpace(current.Provider), "codex") {
		carryForwardConcurrentRefreshMetadata(expected, current, updated, candidate)
	}
	if refreshAware || authWeightConfigurationChanged(expected, current) {
		carryForwardConfiguredAuthWeight(current, candidate)
	}
	if refreshAware || requestScopedErrorConfigurationChanged(expected, current) {
		carryForwardConfiguredRequestScopedErrors(current, candidate)
	}
	clearRuntimeProxy(candidate)
	if chatGPTWebEmailChanged(current, candidate) && m.shouldPersistAuth(ctx, candidate) {
		m.mu.Unlock()
		return nil, ErrChatGPTWebEmailImmutable
	}
	candidate.requestRefreshFamilyID = current.requestRefreshFamilyID
	if candidate.requestRefreshFamilyID == "" {
		candidate.requestRefreshFamilyID = uuid.NewString()
	}
	credentialChanged := preparePreparedRequestCredentialReplacement(current, candidate, time.Now(), refreshAware)
	if !credentialChanged && !skipRuntimeStateCarryForward {
		carryForwardPreparedAuthRuntimeState(current, candidate)
	}
	if applyUpdatedLastError {
		candidate.LastError = cloneError(updated.LastError)
	}
	normalizeChatGPTWebDependencyState(candidate)
	if chatGPTWebRegistrationEmail(candidate) != "" && m.chatGPTWebCredentialConflictLocked(id, candidate) {
		m.mu.Unlock()
		return nil, ErrChatGPTWebEmailAlreadyExists
	}
	candidate.EnsureIndex()
	expectedSourceHash := authSourceHash(current)
	m.mu.Unlock()

	persistCtx := ctx
	if expectedSourceHash != "" && m.SupportsSourceConditionalSave() {
		persistCtx = WithSourceHashSavePrecondition(persistCtx, expectedSourceHash)
	}
	if errPersist := m.persistWithoutLock(persistCtx, candidate, false); errPersist != nil {
		return nil, requestAuthPersistenceError{err: errPersist}
	}

	m.mu.Lock()
	current = m.auths[id]
	if !preparedRequestAuthMatchesCurrent(current, expected, allowRuntimeMetadataChanges) {
		m.mu.Unlock()
		return nil, runtimeAuthInstanceRetiredError()
	}
	credentialChanged = preparePreparedRequestCredentialReplacement(current, candidate, time.Now(), refreshAware)
	if !credentialChanged && !skipRuntimeStateCarryForward {
		carryForwardPreparedAuthRuntimeState(current, candidate)
	}
	if applyUpdatedLastError {
		candidate.LastError = cloneError(updated.LastError)
	}
	normalizeChatGPTWebDependencyState(candidate)
	candidate.installationID = uuid.NewString()
	var replaced *Auth
	if credentialChanged || forceRuntimeReplacement {
		m.beginAuthInstanceCleanupLocked(id)
		replaced = current.Clone()
		candidate.instanceID = uuid.NewString()
		candidate.instanceState = &authInstanceState{}
		candidate.instanceState.bindExecutorOwner(m.executors[executorKeyFromAuth(candidate)])
		candidate.requestRefreshFamilyID = uuid.NewString()
	} else {
		candidate.instanceID = current.instanceID
		candidate.instanceState = current.instanceState
	}
	installedAuth := candidate.Clone()
	m.installAuthLocked(id, installedAuth)
	installed := installedAuth.Clone()
	cleanupPending := m.authSelectionBlockedLocked(id)
	m.mu.Unlock()

	if m.scheduler != nil {
		m.scheduler.upsertAuth(installed.Clone())
	}
	if !cleanupPending {
		m.queueRefreshReschedule(id)
	}
	carryRuntimeProxy(expected, installed)
	releasePersist()
	releaseDependency()
	if replaced != nil {
		hookCtx := context.Background()
		if ctx != nil {
			hookCtx = context.WithoutCancel(ctx)
		}
		hookCtx = withoutChatGPTWebCredentialUpdateMarkers(hookCtx)
		cleanupReason := "auth_runtime_replaced"
		if credentialChanged {
			hookCtx = withChatGPTWebCredentialReplacement(hookCtx)
			cleanupReason = "auth_identity_changed"
		}
		hookAuth := installed.Clone()
		go m.finishAuthSessionCleanup(id, replaced, cleanupReason, func() {
			if m.authInstallationCurrent(installedAuth) {
				m.Hook().OnAuthUpdated(hookCtx, hookAuth.Clone())
			}
		})
	} else if m.authInstallationCurrent(installedAuth) {
		m.Hook().OnAuthUpdated(withoutChatGPTWebCredentialUpdateMarkers(ctx), installed.Clone())
	}
	return installed, nil
}

// UpdateIfCurrent persists updated only when expected still identifies the
// currently installed auth instance and source generation. It is intended for
// asynchronous provider work that must not overwrite a concurrent file reload
// or management edit.
func (m *Manager) UpdateIfCurrent(ctx context.Context, expected, updated *Auth) (*Auth, bool, error) {
	installed, err := m.installPreparedRequestAuth(ctx, expected, updated, false)
	if isRuntimeAuthInstanceRetiredError(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return installed, true, nil
}

// UpdateChatGPTWebReloginIfCurrent installs a re-login result while allowing
// runtime-only metadata, such as rotated session cookies, Passkey counters, or
// image quota, to advance on the same installed credential. Management edits
// and credential replacements still supersede the re-login.
func (m *Manager) UpdateChatGPTWebReloginIfCurrent(ctx context.Context, expected, updated *Auth) (*Auth, bool, error) {
	installed, err := m.installPreparedRequestAuthWithRuntimeMetadata(
		WithForceRuntimeReplacement(ctx),
		expected,
		updated,
		false,
		true,
		true,
	)
	if isRuntimeAuthInstanceRetiredError(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return installed, true, nil
}

// UpdateRefreshedIfCurrent installs a controlled refresh result while treating
// opaque token rotation as the same credential when account evidence agrees.
func (m *Manager) UpdateRefreshedIfCurrent(ctx context.Context, expected, updated *Auth) (*Auth, bool, error) {
	installed, err := m.installPreparedRequestAuthDurably(ctx, expected, updated, true)
	if isRuntimeAuthInstanceRetiredError(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return installed, true, nil
}

func preparePreparedRequestCredentialReplacement(existing, next *Auth, now time.Time, refreshAware bool) bool {
	if refreshAware {
		return prepareRefreshedChatGPTWebCredentialReplacement(existing, next, now)
	}
	return prepareChatGPTWebCredentialReplacement(existing, next, now)
}

// UpdateRuntimeMetadataIfCurrent persists selected runtime metadata without
// replacing the current auth installation or notifying model-sync hooks.
func (m *Manager) UpdateRuntimeMetadataIfCurrent(ctx context.Context, expected *Auth, updates map[string]any) (*Auth, bool, error) {
	if len(updates) == 0 {
		return m.MutateRuntimeMetadataIfCurrent(ctx, expected, nil)
	}
	return m.MutateRuntimeMetadataIfCurrent(ctx, expected, func(auth *Auth) {
		applyRuntimeMetadataUpdates(auth, updates)
	})
}

// MutateRuntimeMetadataIfCurrent persists runtime metadata changes without
// replacing the current auth installation or notifying model-sync hooks.
// mutate must only update Metadata and must not call back into Manager.
func (m *Manager) MutateRuntimeMetadataIfCurrent(ctx context.Context, expected *Auth, mutate func(*Auth)) (*Auth, bool, error) {
	return m.mutateRuntimeMetadataIfCurrent(ctx, expected, mutate, nil, "")
}

// MutateRuntimeMetadataAndClearModelCooldownIfCurrent atomically persists
// metadata changes and clears one reason-owned model cooldown.
func (m *Manager) MutateRuntimeMetadataAndClearModelCooldownIfCurrent(
	ctx context.Context,
	expected *Auth,
	model string,
	reason string,
	mutate func(*Auth),
) (*Auth, bool, error) {
	model = strings.TrimSpace(model)
	reason = strings.TrimSpace(reason)
	if model == "" || reason == "" {
		return m.MutateRuntimeMetadataIfCurrent(ctx, expected, mutate)
	}
	return m.MutateRuntimeMetadataAndClearModelCooldownsIfCurrent(ctx, expected, []string{model}, reason, mutate)
}

// MutateRuntimeMetadataAndClearModelCooldownsIfCurrent atomically persists
// metadata changes and clears matching reason-owned model cooldowns.
func (m *Manager) MutateRuntimeMetadataAndClearModelCooldownsIfCurrent(
	ctx context.Context,
	expected *Auth,
	models []string,
	reason string,
	mutate func(*Auth),
) (*Auth, bool, error) {
	reason = strings.TrimSpace(reason)
	normalizedModels := make([]string, 0, len(models))
	seen := make(map[string]struct{}, len(models))
	for _, model := range models {
		model = strings.TrimSpace(model)
		key := strings.ToLower(canonicalModelKey(model))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalizedModels = append(normalizedModels, model)
	}
	if len(normalizedModels) == 0 || reason == "" {
		return m.MutateRuntimeMetadataIfCurrent(ctx, expected, mutate)
	}
	return m.mutateRuntimeMetadataIfCurrent(ctx, expected, mutate, normalizedModels, reason)
}

func (m *Manager) mutateRuntimeMetadataIfCurrent(
	ctx context.Context,
	expected *Auth,
	mutate func(*Auth),
	clearModels []string,
	clearReason string,
) (*Auth, bool, error) {
	if m == nil || expected == nil || strings.TrimSpace(expected.ID) == "" {
		return nil, false, nil
	}
	if mutate == nil && len(clearModels) == 0 {
		m.mu.RLock()
		current := m.auths[expected.ID]
		if !runtimeMetadataMutationMatchesCurrent(current, expected) {
			m.mu.RUnlock()
			return nil, false, nil
		}
		snapshot := current.Clone()
		m.mu.RUnlock()
		return snapshot, true, nil
	}
	id := expected.ID
	lockedDependencyCtx, unlockDependency, errDependency := m.lockChatGPTWebDependencyMutationContext(ctx, id, expected, false)
	if errDependency != nil {
		return nil, false, errDependency
	}
	ctx = lockedDependencyCtx
	defer unlockDependency()
	unlockPersist, errLock := m.lockAuthIDMutationContext(ctx, id)
	if errLock != nil {
		return nil, false, errLock
	}
	defer unlockPersist()

	now := time.Now()
	imageModels := ChatGPTWebImageModelIDs(expected)
	modelKeys := make([]string, 0, len(clearModels))
	for _, model := range clearModels {
		modelKeys = append(modelKeys, canonicalModelKey(model))
	}

	m.mu.Lock()
	current := m.auths[id]
	if !runtimeMetadataMutationMatchesCurrent(current, expected) {
		m.mu.Unlock()
		return nil, false, nil
	}
	candidate := current.Clone()
	clearObservationMatches := modelStatesObservationMatch(current, expected, modelKeys)
	clearBaselines := make(map[string]*ModelState, len(modelKeys))
	if clearObservationMatches {
		for _, modelKey := range modelKeys {
			if baseline := cloneReasonOwnedModelState(candidate, modelKey, clearReason); baseline != nil {
				clearBaselines[modelKey] = baseline
			}
		}
	}
	if mutate != nil {
		previousLifecycle := candidate.LifecycleState()
		mutate(candidate)
		if candidate.LifecycleState() != previousLifecycle {
			applyLifecycleRuntimeState(candidate)
		}
		if clearObservationMatches {
			clearChatGPTWebImageRateLimitsAfterFreshQuotaForModels(candidate, now, imageModels)
		}
	}
	for modelKey := range clearBaselines {
		clearModelCooldownByReasonOnAuth(candidate, modelKey, clearReason, now)
	}
	expectedSourceHash := authSourceHash(current)
	m.mu.Unlock()

	persistCtx := ctx
	if expectedSourceHash != "" && m.SupportsSourceConditionalSave() {
		persistCtx = WithSourceHashSavePrecondition(persistCtx, expectedSourceHash)
	}
	if errPersist := m.persistWithoutLock(persistCtx, candidate, false); errPersist != nil {
		return nil, false, errPersist
	}

	m.mu.Lock()
	current = m.auths[id]
	if !runtimeMetadataMutationMatchesCurrent(current, expected) {
		m.mu.Unlock()
		return nil, false, nil
	}
	installed := current.Clone()
	var clearedFreshImageRateLimits []string
	if mutate != nil {
		previousLifecycle := installed.LifecycleState()
		mutate(installed)
		if installed.LifecycleState() != previousLifecycle {
			applyLifecycleRuntimeState(installed)
		}
		if clearObservationMatches {
			clearedFreshImageRateLimits = clearChatGPTWebImageRateLimitsAfterFreshQuotaForModels(installed, now, imageModels)
		}
	}
	clearedModels := make([]string, 0, len(clearBaselines))
	for index, modelKey := range modelKeys {
		clearBaseline := clearBaselines[modelKey]
		if clearBaseline == nil || !reasonOwnedModelStateMatches(installed, modelKey, clearReason, clearBaseline) {
			continue
		}
		if clearModelCooldownByReasonOnAuth(installed, modelKey, clearReason, now) {
			clearedModels = append(clearedModels, clearModels[index])
		}
	}
	if persistedHash := authSourceHash(candidate); persistedHash != "" {
		if installed.Attributes == nil {
			installed.Attributes = make(map[string]string)
		}
		installed.Attributes[SourceHashAttributeKey] = persistedHash
	}
	m.installAuthLocked(id, installed)
	m.mu.Unlock()
	snapshot := installed.Clone()
	if len(clearedModels) > 0 || len(clearedFreshImageRateLimits) > 0 {
		if m.scheduler != nil {
			m.scheduler.upsertAuth(snapshot)
		}
	}
	for _, model := range clearedModels {
		registry.GetGlobalRegistry().ClearModelQuotaExceeded(id, model)
		registry.GetGlobalRegistry().ResumeClientModel(id, model)
	}
	for _, model := range clearedFreshImageRateLimits {
		registry.GetGlobalRegistry().ClearModelQuotaExceeded(id, model)
		registry.GetGlobalRegistry().ResumeClientModel(id, model)
	}
	return snapshot, true, nil
}

func modelStatesObservationMatch(current, expected *Auth, modelKeys []string) bool {
	for _, modelKey := range modelKeys {
		if !modelStateObservationMatches(current, expected, modelKey) {
			return false
		}
	}
	return true
}

func modelStateObservationMatches(current, expected *Auth, modelKey string) bool {
	return reflect.DeepEqual(
		cloneModelStateByKey(current, modelKey),
		cloneModelStateByKey(expected, modelKey),
	)
}

func cloneModelStateByKey(auth *Auth, modelKey string) *ModelState {
	if auth == nil || modelKey == "" {
		return nil
	}
	for stateModel, state := range auth.ModelStates {
		if state != nil && canonicalModelKey(stateModel) == modelKey {
			return state.Clone()
		}
	}
	return nil
}

func cloneReasonOwnedModelState(auth *Auth, modelKey, reason string) *ModelState {
	if auth == nil || modelKey == "" || reason == "" {
		return nil
	}
	for stateModel, state := range auth.ModelStates {
		if state == nil || canonicalModelKey(stateModel) != modelKey ||
			!strings.EqualFold(strings.TrimSpace(state.Quota.Reason), reason) {
			continue
		}
		cloned := *state
		if state.LastError != nil {
			cloned.LastError = cloneError(state.LastError)
		}
		return &cloned
	}
	return nil
}

func reasonOwnedModelStateMatches(auth *Auth, modelKey, reason string, expected *ModelState) bool {
	if expected == nil {
		return false
	}
	current := cloneReasonOwnedModelState(auth, modelKey, reason)
	return current != nil && reflect.DeepEqual(current, expected)
}

func applyRuntimeMetadataUpdates(auth *Auth, updates map[string]any) {
	if auth == nil || len(updates) == 0 {
		return
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any, len(updates))
	}
	for key, value := range updates {
		auth.Metadata[key] = value
	}
}

func requestPreparationMatchesCurrent(current, expected *Auth) bool {
	if current == nil || expected == nil || current.ID != expected.ID {
		return false
	}
	if current.instanceID == "" || current.instanceID != expected.instanceID || current.instanceState != expected.instanceState {
		return false
	}
	if current.installationID != expected.installationID {
		return false
	}
	expectedHash := authSourceHash(expected)
	currentHash := authSourceHash(current)
	if expectedHash != "" || currentHash != "" {
		return expectedHash != "" && expectedHash == currentHash
	}
	return true
}

func preparedRequestAuthMatchesCurrent(current, expected *Auth, allowRuntimeMetadataChanges bool) bool {
	if !allowRuntimeMetadataChanges {
		return requestPreparationMatchesCurrent(current, expected)
	}
	if !runtimeMetadataMutationMatchesCurrent(current, expected) ||
		!isNativeChatGPTWebCredentialAuth(current) ||
		!isNativeChatGPTWebCredentialAuth(expected) ||
		!chatGPTWebReloginRuntimeMetadataMatches(expected, current) {
		return false
	}
	expectedUID := chatGPTWebIdentityMetadataString(expected.Metadata, chatGPTWebCredentialUIDKey)
	currentUID := chatGPTWebIdentityMetadataString(current.Metadata, chatGPTWebCredentialUIDKey)
	return expectedUID == currentUID
}

func chatGPTWebReloginRuntimeMetadataMatches(expected, current *Auth) bool {
	if expected == nil || current == nil {
		return false
	}
	for key, value := range expected.Attributes {
		if key == SourceHashAttributeKey {
			continue
		}
		currentValue, ok := current.Attributes[key]
		if !ok || currentValue != value {
			return false
		}
	}
	for key := range current.Attributes {
		if key == SourceHashAttributeKey {
			continue
		}
		if _, ok := expected.Attributes[key]; !ok {
			return false
		}
	}
	expectedCredential, errExpected := chatgptwebauth.ParseCredential(expected.Metadata)
	currentCredential, errCurrent := chatgptwebauth.ParseCredential(current.Metadata)
	if errExpected != nil || errCurrent != nil {
		return false
	}
	if !chatGPTWebReloginRuntimeIdentityCompatible(expectedCredential, currentCredential) {
		return false
	}
	expectedComparable := *expectedCredential
	currentComparable := *currentCredential
	clearChatGPTWebReloginRuntimeCredentialMetadata(&expectedComparable)
	clearChatGPTWebReloginRuntimeCredentialMetadata(&currentComparable)
	if !reflect.DeepEqual(expectedComparable, currentComparable) {
		return false
	}
	knownMetadata := make(map[string]struct{})
	for _, credential := range []*chatgptwebauth.Credential{expectedCredential, currentCredential} {
		metadata := make(map[string]any)
		credential.ApplyToMetadata(metadata)
		for key := range metadata {
			knownMetadata[key] = struct{}{}
		}
	}
	return authMetadataMatchesExceptKeys(expected.Metadata, current.Metadata, knownMetadata)
}

func chatGPTWebReloginRuntimeIdentityCompatible(expected, current *chatgptwebauth.Credential) bool {
	if expected == nil || current == nil {
		return false
	}
	for _, values := range [][2]string{
		{expected.AccountID, current.AccountID},
		{expected.UserID, current.UserID},
	} {
		expectedValue := strings.TrimSpace(values[0])
		currentValue := strings.TrimSpace(values[1])
		if expectedValue != "" && currentValue != "" && expectedValue != currentValue {
			return false
		}
	}
	return true
}

func clearChatGPTWebReloginRuntimeCredentialMetadata(credential *chatgptwebauth.Credential) {
	if credential == nil {
		return
	}
	credential.Cookies = nil
	credential.SessionToken = ""
	credential.Persona = chatgptwebauth.Persona{}
	credential.DeviceID = ""
	credential.SessionID = ""
	credential.AccountID = ""
	credential.UserID = ""
	credential.PlanType = ""
	credential.ProfileUpdatedAt = ""
	credential.ImageQuotaRemaining = nil
	credential.ImageQuotaResetAt = ""
	credential.QuotaState = ""
	credential.QuotaUpdatedAt = ""
	credential.QuotaStale = false
	credential.QuotaLastError = ""
	if credential.WebAuthn != nil {
		webAuthn := *credential.WebAuthn
		webAuthn.Transports = append([]string(nil), credential.WebAuthn.Transports...)
		credential.WebAuthn = &webAuthn
		credential.WebAuthn.SignCount = 0
		credential.WebAuthn.LastUsedAt = ""
	}
	if credential.AdvancedAccountSecurity != nil {
		credential.AdvancedAccountSecurity = chatgptwebauth.CloneAdvancedAccountSecurityCredential(credential.AdvancedAccountSecurity)
		for index := range credential.AdvancedAccountSecurity.Passkeys {
			credential.AdvancedAccountSecurity.Passkeys[index].Credential.SignCount = 0
			credential.AdvancedAccountSecurity.Passkeys[index].Credential.LastUsedAt = ""
		}
	}
}

func authMetadataMatchesExceptKeys(expected, current map[string]any, ignored map[string]struct{}) bool {
	for key, value := range expected {
		if _, skip := ignored[key]; skip {
			continue
		}
		currentValue, ok := current[key]
		if !ok || !reflect.DeepEqual(currentValue, value) {
			return false
		}
	}
	for key := range current {
		if _, skip := ignored[key]; skip {
			continue
		}
		if _, ok := expected[key]; !ok {
			return false
		}
	}
	return true
}

func agentIdentityTaskAlreadyAdvanced(current, expected *Auth) bool {
	if current == nil || expected == nil || current.ID != expected.ID {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(current.Provider), "codex") ||
		!strings.EqualFold(strings.TrimSpace(expected.Provider), "codex") {
		return false
	}
	if current.Metadata == nil || expected.Metadata == nil ||
		!strings.EqualFold(authMetadataString(current, "auth_mode"), "agentIdentity") ||
		!strings.EqualFold(authMetadataString(expected, "auth_mode"), "agentIdentity") {
		return false
	}
	currentRuntimeID := authMetadataString(current, "agent_runtime_id")
	expectedRuntimeID := authMetadataString(expected, "agent_runtime_id")
	currentPrivateKey := authMetadataString(current, "agent_private_key")
	expectedPrivateKey := authMetadataString(expected, "agent_private_key")
	if currentRuntimeID == "" || currentRuntimeID != expectedRuntimeID ||
		currentPrivateKey == "" || currentPrivateKey != expectedPrivateKey {
		return false
	}
	currentTaskID := authMetadataString(current, "task_id")
	expectedTaskID := authMetadataString(expected, "task_id")
	return currentTaskID != "" && currentTaskID != expectedTaskID
}

func runtimeMetadataMutationMatchesCurrent(current, expected *Auth) bool {
	if current == nil || expected == nil || current.ID != expected.ID {
		return false
	}
	if current.instanceID == "" || current.instanceID != expected.instanceID || current.instanceState != expected.instanceState {
		return false
	}
	return current.installationID == expected.installationID
}

func carryForwardPreparedAuthRuntimeState(current, next *Auth) {
	if current == nil || next == nil {
		return
	}
	next.Index = current.Index
	next.indexAssigned = current.indexAssigned
	next.Status = current.Status
	next.StatusMessage = current.StatusMessage
	next.Disabled = current.Disabled
	next.Unavailable = current.Unavailable
	next.Quota = current.Quota
	next.LastError = cloneError(current.LastError)
	next.CreatedAt = current.CreatedAt
	next.UpdatedAt = current.UpdatedAt
	next.LastRefreshedAt = current.LastRefreshedAt
	next.NextRefreshAfter = current.NextRefreshAfter
	next.NextRetryAfter = current.NextRetryAfter
	next.CooldownScope = current.CooldownScope
	next.ModelStates = cloneAuthModelStates(current.ModelStates)
	next.Runtime = current.Runtime
	applyLifecycleRuntimeState(next)
}

func (m *Manager) prepareRequestAuthWithUnauthorizedRefresh(ctx context.Context, executor ProviderExecutor, auth *Auth, options ...cliproxyexecutor.Options) (*Auth, bool, error) {
	if err := cliproxyexecutor.ImageRequestBudgetFromContext(ctx).Select(auth.Provider); err != nil {
		return auth, false, err
	}
	prepared, errPrepare := m.prepareRequestAuth(ctx, executor, auth, options...)
	if errPrepare == nil {
		return prepared, false, nil
	}
	refreshed, attemptedRefresh, errRefresh := m.tryRefreshAfterUnauthorized(ctx, executor, auth, errPrepare, false)
	if errRefresh != nil {
		return prepared, attemptedRefresh, errRefresh
	}
	if !attemptedRefresh {
		return prepared, false, errPrepare
	}
	prepared, errPrepare = m.prepareRequestAuth(ctx, executor, refreshed, options...)
	return prepared, true, errPrepare
}

func (m *Manager) executeMixedOnce(ctx context.Context, providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, requestAttempt int, maxRetryCredentials int, defaultRequestRetry int, roundState *requestRoundState) (cliproxyexecutor.Response, error) {
	if len(providers) == 0 {
		return cliproxyexecutor.Response{}, &Error{Code: "provider_not_found", Message: "no provider supplied"}
	}
	roundState = roundState.ensure()
	routeModel := req.Model
	opts = ensureRequestedModelMetadata(opts, routeModel)
	opts = setSelectionAttemptMetadata(opts, requestAttempt)
	opts = withImageGenerationResultState(req, opts)
	opts.AuthRequestSlot = newAuthRequestSlot(opts.ExecutionDiagnostics, opts.ExecutionMetrics)
	defer opts.AuthRequestSlot.Release()
	strictSessionAffinity := m.strictSessionAffinityForRequest(ctx, req, opts)
	pickAllowed := m.requestRoundPickAllowed(ctx, roundState, maxRetryCredentials, requestAttempt, defaultRequestRetry)
	unregisterRelease := registerRequestBodyReleaseCallback(ctx, opts, func([]byte) {
		req.Payload = nil
		opts.OriginalRequest = nil
	})
	defer unregisterRelease()
	for {
		if !requestBodyReplayable(ctx, opts) {
			if roundState.lastErr != nil {
				return cliproxyexecutor.Response{}, roundState.lastErr
			}
			return cliproxyexecutor.Response{}, &Error{Code: "request_body_released", Message: "request body released; retry disabled"}
		}
		selectionStarted := time.Now()
		requestSlotBefore := opts.AuthRequestSlot.ReservationDurationNanos()
		opts = m.withSessionAffinityResultSnapshot(ctx, providers, routeModel, opts)
		auth, executor, provider, errPick := m.pickNextMixedWithImageToolFallback(ctx, providers, routeModel, req, opts, roundState.tried, pickAllowed)
		observeImageRequestSelectionPhases(opts.Metadata, opts.AuthRequestSlot, selectionStarted, requestSlotBefore)
		if errPick != nil {
			if chatGPTWebImageQuotaRefreshPendingError(errPick) {
				return cliproxyexecutor.Response{}, errPick
			}
			if _, isAvailabilityBlocker := availabilityBlockerResetIn(errPick); isAvailabilityBlocker {
				return cliproxyexecutor.Response{}, m.preferEarlierRoundAvailabilityError(errPick, roundState)
			}
			if roundState.lastErr != nil {
				return cliproxyexecutor.Response{}, roundState.lastErr
			}
			return cliproxyexecutor.Response{}, errPick
		}
		commitImmediateAuthRequestReservation(executor, opts.AuthRequestSlot)
		roundState.tried[auth.ID] = struct{}{}
		resolvedAuth, errProxy := m.ResolveProxyAuth(ctx, auth)
		if errProxy != nil {
			roundState.markAttempted(auth)
			if strictSessionAffinity {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errProxy, auth, provider)
			}
			roundState.setLastError(auth, errProxy)
			continue
		}
		auth = resolvedAuth

		entry := logEntryWithRequestID(ctx)
		debugLogAuthSelection(entry, auth, provider, req.Model)
		publishSelectedAuthMetadata(ctx, opts.Metadata, auth, provider)
		opts = withSelectedAuthInstanceMetadata(opts, auth)

		execCtx := ctx
		if rt := m.roundTripperFor(auth); rt != nil {
			execCtx = context.WithValue(execCtx, roundTripperContextKey{}, rt)
			execCtx = context.WithValue(execCtx, "cliproxy.roundtripper", rt)
		}
		preparedAuth, refreshedOnUnauthorized, errPrepare := m.prepareRequestAuthWithUnauthorizedRefresh(execCtx, executor, auth, opts)
		if errPrepare != nil {
			if errCtx := execCtx.Err(); errCtx != nil {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errCtx, auth, provider)
			}
			if isRuntimeAuthInstanceRetiredError(errPrepare) {
				releaseRetiredAuthRequestSlot(opts)
				roundState.forgetRetiredAttempt(auth)
				if errWait := waitForRetiredAuthInstanceCleanup(execCtx, auth); errWait != nil {
					return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errWait, auth, provider)
				}
				continue
			}
			errPrepare = m.reportProxyFailure(execCtx, auth, errPrepare)
			roundState.markAttempted(auth)
			result := resultForAuth(auth, provider, routeModel, false)
			result.Error = executionResultError(auth, errPrepare)
			if statusErr, ok := errors.AsType[cliproxyexecutor.StatusError](errPrepare); ok && statusErr != nil {
				result.Error.HTTPStatus = statusErr.StatusCode()
			}
			result.RetryAfter = retryAfterFromError(errPrepare)
			if !skipAuthResultForError(errPrepare) {
				m.markExecutionResult(execCtx, result)
			}
			if isChatGPTWebUnauthorizedRequestError(errPrepare) {
				triggerChatGPTWebUnauthorizedRequestRefresh(errPrepare)
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errPrepare, auth, provider)
			}
			if strictSessionAffinity {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errPrepare, auth, provider)
			}
			roundState.setLastError(auth, errPrepare)
			continue
		}
		carryRuntimeProxy(auth, preparedAuth)
		auth = preparedAuth
		publishErrorResponseSourceMetadata(opts.Metadata, errorResponseSourceForAuth(auth, provider))
		opts = withSelectedAuthInstanceMetadata(opts, auth)

		models, pooled, aliasResult, routing := m.preparedExecutionModelsWithAlias(auth, routeModel, opts)
		if len(models) == 0 {
			if strictSessionAffinity {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(newStrictSessionAffinityError("session bound auth has no executable models"), auth, provider)
			}
			continue
		}
		baseReq := sanitizeDownstreamWebsocketFallbackRequest(execCtx, auth, req)
		var authErr error
		didRefreshOnUnauthorized := refreshedOnUnauthorized
		for modelIndex, upstreamModel := range models {
			if !requestBodyReplayable(execCtx, opts) {
				break
			}
			if modelIndex > 0 {
				if errLimit := m.acquireAdditionalAuthRequest(auth, executor, opts.AuthRequestSlot); errLimit != nil {
					authErr = errLimit
					break
				}
			}
			resultModel := m.stateModelForExecution(auth, routeModel, upstreamModel, pooled)
			execReq := baseReq
			execReq.Model = upstreamModel
			execReq = attachResolvedAPIKeyModelInfo(routing, execReq, auth, effectiveExecutionRouteModel(routeModel, opts), upstreamModel)
			unregisterAttemptRelease := registerRequestBodyReleaseCallback(execCtx, opts, func([]byte) {
				execReq.Payload = nil
				opts.OriginalRequest = nil
			})
			if !requestBodyReplayable(execCtx, opts) {
				unregisterAttemptRelease()
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(&Error{Code: "request_body_released", Message: "request body released; retry disabled"}, auth, provider)
			}
			auth.bindExecutorOwner(executor)
			runtimeCtx, releaseExecution, active := auth.BeginRuntimeExecution(execCtx)
			if !active {
				unregisterAttemptRelease()
				releaseRetiredAuthRequestSlot(opts)
				roundState.forgetRetiredAttempt(auth)
				if errWait := waitForRetiredAuthInstanceCleanup(execCtx, auth); errWait != nil {
					return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errWait, auth, provider)
				}
				break
			}
			roundState.markAttempted(auth)
			runtimeCtx = cliproxyexecutor.WithUpstreamAttempt(runtimeCtx)
			resp, errExec := executeProviderRequest(runtimeCtx, executor, auth, execReq, opts)
			retiredDuringExecution := releaseExecution()
			if !retiredDuringExecution {
				errExec = recordExecutionAttemptError(runtimeCtx, auth, provider, errExec)
			}
			unregisterAttemptRelease()
			if errExec == nil {
				if !retiredDuringExecution {
					m.markExecutionResult(execCtx, successfulExecutionResultForAuth(auth, provider, resultModel, opts))
					m.bindSessionAffinity(ctx, providers, routeModel, opts, auth)
				}
				rewriteForceMappedResponse(&resp, aliasResult)
				return resp, nil
			}
			if retiredDuringExecution {
				releaseRetiredAuthRequestSlot(opts)
				roundState.forgetRetiredAttempt(auth)
				if errWait := waitForRetiredAuthInstanceCleanup(execCtx, auth); errWait != nil {
					return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errWait, auth, provider)
				}
				authErr = nil
				break
			}
			if errCtx := execCtx.Err(); errCtx != nil {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errCtx, auth, provider)
			}
			if cliproxyexecutor.IsImageExecutionCapacityError(errExec) {
				roundState.blockProvider(provider)
				authErr = errExec
				break
			}
			action, matchedAction := m.matchRequestScopedErrorAction(execCtx, auth, opts, errExec)
			if !matchedAction && errExec != nil && requestBodyReplayable(execCtx, opts) {
				refreshed, attemptedRefresh, errRefresh := m.tryRefreshAfterUnauthorized(execCtx, executor, auth, errExec, didRefreshOnUnauthorized)
				if attemptedRefresh {
					didRefreshOnUnauthorized = true
				}
				if errRefresh != nil {
					if errCtx := execCtx.Err(); errCtx != nil {
						return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errCtx, auth, provider)
					}
					errExec = errRefresh
				} else if attemptedRefresh {
					carryRuntimeProxy(auth, refreshed)
					auth = refreshed
					publishErrorResponseSourceMetadata(opts.Metadata, errorResponseSourceForAuth(auth, provider))
					opts = withSelectedAuthInstanceMetadata(opts, auth)
					auth.bindExecutorOwner(executor)
					if errLimit := m.acquireAdditionalAuthRequest(auth, executor, opts.AuthRequestSlot); errLimit != nil {
						authErr = errLimit
						break
					}
					retryCtx, releaseRetry, retryActive := auth.BeginRuntimeExecution(execCtx)
					if !retryActive {
						releaseRetiredAuthRequestSlot(opts)
						roundState.forgetRetiredAttempt(auth)
						if errWait := waitForRetiredAuthInstanceCleanup(execCtx, auth); errWait != nil {
							return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errWait, auth, provider)
						}
						authErr = nil
						break
					}
					retryCtx = cliproxyexecutor.WithUpstreamAttempt(retryCtx)
					resp, errExec = executeProviderRequest(retryCtx, executor, auth, execReq, opts)
					retiredDuringRetry := releaseRetry()
					if !retiredDuringRetry {
						errExec = recordExecutionAttemptError(retryCtx, auth, provider, errExec)
					}
					if errExec == nil {
						if !retiredDuringRetry {
							m.markExecutionResult(execCtx, successfulExecutionResultForAuth(auth, provider, resultModel, opts))
							m.bindSessionAffinity(ctx, providers, routeModel, opts, auth)
						}
						rewriteForceMappedResponse(&resp, aliasResult)
						return resp, nil
					}
					if retiredDuringRetry {
						releaseRetiredAuthRequestSlot(opts)
						roundState.forgetRetiredAttempt(auth)
						if errWait := waitForRetiredAuthInstanceCleanup(execCtx, auth); errWait != nil {
							return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errWait, auth, provider)
						}
						authErr = nil
						break
					}
					if errCtx := execCtx.Err(); errCtx != nil {
						return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errCtx, auth, provider)
					}
				}
			}
			errExec = m.reportProxyFailure(execCtx, auth, errExec)
			resultModel = executionResultModelForError(resultModel, errExec)
			m.projectFailedImageGenerationQuota(execCtx, auth, provider, resultModel, opts)
			result := resultForAuth(auth, provider, resultModel, false)
			result.Error = executionResultError(auth, errExec)
			result.Error.Code = executionResultErrorCode(errExec)
			result.availabilityNeutral = isResponsesCompactAvailabilityNeutralError(opts, errExec)
			if se, ok := errors.AsType[cliproxyexecutor.StatusError](errExec); ok && se != nil {
				result.Error.HTTPStatus = se.StatusCode()
			}
			if ra := retryAfterFromError(errExec); ra != nil {
				result.RetryAfter = ra
			}
			if !matchedAction {
				action, matchedAction = m.matchRequestScopedErrorAction(execCtx, auth, opts, errExec)
			}
			applyRequestScopedActionToResult(action, matchedAction, &result)
			if !skipAuthResultForError(errExec) {
				m.markExecutionResult(execCtx, result, opts)
			}
			if matchedAction && (action == internalconfig.RequestScopedActionStop || action == internalconfig.RequestScopedActionStopAndCooldown) {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(&requestScopedActionError{error: errExec, action: action}, auth, provider)
			}
			triggerChatGPTWebUnauthorizedRequestRefresh(errExec)
			if isResponsesCompactRequestFaultError(opts, errExec) || m.isRequestInvalidError(errExec, ctx) {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errExec, auth, provider)
			}
			authErr = errExec
			if !requestBodyReplayable(execCtx, opts) {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errExec, auth, provider)
			}
			continue
		}
		if authErr != nil {
			if isResponsesCompactRequestFaultError(opts, authErr) || m.isRequestInvalidError(authErr, ctx) {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(authErr, auth, provider)
			}
			if strictSessionAffinity {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(authErr, auth, provider)
			}
			roundState.setLastError(auth, authErr)
			if !requestBodyReplayable(ctx, opts) {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(authErr, auth, provider)
			}
			continue
		}
	}
}

func (m *Manager) executeCountMixedOnce(ctx context.Context, providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, requestAttempt int, maxRetryCredentials int, defaultRequestRetry int, roundState *requestRoundState) (cliproxyexecutor.Response, error) {
	if len(providers) == 0 {
		return cliproxyexecutor.Response{}, &Error{Code: "provider_not_found", Message: "no provider supplied"}
	}
	roundState = roundState.ensure()
	routeModel := req.Model
	opts = ensureRequestedModelMetadata(opts, routeModel)
	opts = setSelectionAttemptMetadata(opts, requestAttempt)
	opts.AuthRequestSlot = newAuthRequestSlot(opts.ExecutionDiagnostics, opts.ExecutionMetrics)
	defer opts.AuthRequestSlot.Release()
	strictSessionAffinity := m.strictSessionAffinityForRequest(ctx, req, opts)
	pickAllowed := m.requestRoundPickAllowed(ctx, roundState, maxRetryCredentials, requestAttempt, defaultRequestRetry)
	unregisterRelease := registerRequestBodyReleaseCallback(ctx, opts, func([]byte) {
		req.Payload = nil
		opts.OriginalRequest = nil
	})
	defer unregisterRelease()
	for {
		if !requestBodyReplayable(ctx, opts) {
			if roundState.lastErr != nil {
				return cliproxyexecutor.Response{}, roundState.lastErr
			}
			return cliproxyexecutor.Response{}, &Error{Code: "request_body_released", Message: "request body released; retry disabled"}
		}
		opts = m.withSessionAffinityResultSnapshot(ctx, providers, routeModel, opts)
		auth, executor, provider, errPick := m.pickNextMixed(ctx, providers, routeModel, opts, roundState.tried, pickAllowed)
		if errPick != nil {
			if chatGPTWebImageQuotaRefreshPendingError(errPick) {
				return cliproxyexecutor.Response{}, errPick
			}
			if _, isAvailabilityBlocker := availabilityBlockerResetIn(errPick); isAvailabilityBlocker {
				return cliproxyexecutor.Response{}, m.preferEarlierRoundAvailabilityError(errPick, roundState)
			}
			if roundState.lastErr != nil {
				return cliproxyexecutor.Response{}, roundState.lastErr
			}
			return cliproxyexecutor.Response{}, errPick
		}
		commitImmediateAuthRequestReservation(executor, opts.AuthRequestSlot)
		roundState.tried[auth.ID] = struct{}{}
		resolvedAuth, errProxy := m.ResolveProxyAuth(ctx, auth)
		if errProxy != nil {
			roundState.markAttempted(auth)
			if strictSessionAffinity {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errProxy, auth, provider)
			}
			roundState.setLastError(auth, errProxy)
			continue
		}
		auth = resolvedAuth

		entry := logEntryWithRequestID(ctx)
		debugLogAuthSelection(entry, auth, provider, req.Model)
		publishSelectedAuthMetadata(ctx, opts.Metadata, auth, provider)
		opts = withSelectedAuthInstanceMetadata(opts, auth)

		execCtx := ctx
		if rt := m.roundTripperFor(auth); rt != nil {
			execCtx = context.WithValue(execCtx, roundTripperContextKey{}, rt)
			execCtx = context.WithValue(execCtx, "cliproxy.roundtripper", rt)
		}
		preparedAuth, refreshedOnUnauthorized, errPrepare := m.prepareRequestAuthWithUnauthorizedRefresh(execCtx, executor, auth, opts)
		if errPrepare != nil {
			if errCtx := execCtx.Err(); errCtx != nil {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errCtx, auth, provider)
			}
			if isRuntimeAuthInstanceRetiredError(errPrepare) {
				releaseRetiredAuthRequestSlot(opts)
				roundState.forgetRetiredAttempt(auth)
				if errWait := waitForRetiredAuthInstanceCleanup(execCtx, auth); errWait != nil {
					return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errWait, auth, provider)
				}
				continue
			}
			errPrepare = m.reportProxyFailure(execCtx, auth, errPrepare)
			roundState.markAttempted(auth)
			result := resultForAuth(auth, provider, routeModel, false)
			result.Error = executionResultError(auth, errPrepare)
			if statusErr, ok := errors.AsType[cliproxyexecutor.StatusError](errPrepare); ok && statusErr != nil {
				result.Error.HTTPStatus = statusErr.StatusCode()
			}
			result.RetryAfter = retryAfterFromError(errPrepare)
			if !skipAuthResultForError(errPrepare) {
				m.markExecutionResult(execCtx, result)
			}
			if isChatGPTWebUnauthorizedRequestError(errPrepare) {
				triggerChatGPTWebUnauthorizedRequestRefresh(errPrepare)
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errPrepare, auth, provider)
			}
			if strictSessionAffinity {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errPrepare, auth, provider)
			}
			roundState.setLastError(auth, errPrepare)
			continue
		}
		carryRuntimeProxy(auth, preparedAuth)
		auth = preparedAuth
		publishErrorResponseSourceMetadata(opts.Metadata, errorResponseSourceForAuth(auth, provider))
		opts = withSelectedAuthInstanceMetadata(opts, auth)

		models, pooled, _, routing := m.preparedExecutionModelsWithAlias(auth, routeModel, opts)
		if len(models) == 0 {
			if strictSessionAffinity {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(newStrictSessionAffinityError("session bound auth has no executable models"), auth, provider)
			}
			continue
		}
		baseReq := sanitizeDownstreamWebsocketFallbackRequest(execCtx, auth, req)
		var authErr error
		didRefreshOnUnauthorized := refreshedOnUnauthorized
		for modelIndex, upstreamModel := range models {
			if !requestBodyReplayable(execCtx, opts) {
				break
			}
			if modelIndex > 0 {
				if errLimit := m.acquireAdditionalAuthRequest(auth, executor, opts.AuthRequestSlot); errLimit != nil {
					authErr = errLimit
					break
				}
			}
			resultModel := m.stateModelForExecution(auth, routeModel, upstreamModel, pooled)
			execReq := baseReq
			execReq.Model = upstreamModel
			execReq = attachResolvedAPIKeyModelInfo(routing, execReq, auth, effectiveExecutionRouteModel(routeModel, opts), upstreamModel)
			unregisterAttemptRelease := registerRequestBodyReleaseCallback(execCtx, opts, func([]byte) {
				execReq.Payload = nil
				opts.OriginalRequest = nil
			})
			if !requestBodyReplayable(execCtx, opts) {
				unregisterAttemptRelease()
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(&Error{Code: "request_body_released", Message: "request body released; retry disabled"}, auth, provider)
			}
			auth.bindExecutorOwner(executor)
			runtimeCtx, releaseExecution, active := auth.BeginRuntimeExecution(execCtx)
			if !active {
				unregisterAttemptRelease()
				releaseRetiredAuthRequestSlot(opts)
				roundState.forgetRetiredAttempt(auth)
				if errWait := waitForRetiredAuthInstanceCleanup(execCtx, auth); errWait != nil {
					return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errWait, auth, provider)
				}
				break
			}
			roundState.markAttempted(auth)
			runtimeCtx = cliproxyexecutor.WithUpstreamAttempt(runtimeCtx)
			resp, errExec := executor.CountTokens(runtimeCtx, auth, execReq, opts)
			retiredDuringExecution := releaseExecution()
			if !retiredDuringExecution {
				errExec = recordExecutionAttemptError(runtimeCtx, auth, provider, errExec)
			}
			unregisterAttemptRelease()
			if errExec == nil {
				if !retiredDuringExecution {
					m.markExecutionResult(execCtx, resultForAuth(auth, provider, resultModel, true))
					m.bindSessionAffinity(ctx, providers, routeModel, opts, auth)
				}
				return resp, nil
			}
			if retiredDuringExecution {
				releaseRetiredAuthRequestSlot(opts)
				roundState.forgetRetiredAttempt(auth)
				if errWait := waitForRetiredAuthInstanceCleanup(execCtx, auth); errWait != nil {
					return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errWait, auth, provider)
				}
				authErr = nil
				break
			}
			if errCtx := execCtx.Err(); errCtx != nil {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errCtx, auth, provider)
			}
			action, matchedAction := m.matchRequestScopedErrorAction(execCtx, auth, opts, errExec)
			if !matchedAction && errExec != nil && requestBodyReplayable(execCtx, opts) {
				refreshed, attemptedRefresh, errRefresh := m.tryRefreshAfterUnauthorized(execCtx, executor, auth, errExec, didRefreshOnUnauthorized)
				if attemptedRefresh {
					didRefreshOnUnauthorized = true
				}
				if errRefresh != nil {
					if errCtx := execCtx.Err(); errCtx != nil {
						return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errCtx, auth, provider)
					}
					errExec = errRefresh
				} else if attemptedRefresh {
					carryRuntimeProxy(auth, refreshed)
					auth = refreshed
					publishErrorResponseSourceMetadata(opts.Metadata, errorResponseSourceForAuth(auth, provider))
					opts = withSelectedAuthInstanceMetadata(opts, auth)
					auth.bindExecutorOwner(executor)
					if errLimit := m.acquireAdditionalAuthRequest(auth, executor, opts.AuthRequestSlot); errLimit != nil {
						authErr = errLimit
						break
					}
					retryCtx, releaseRetry, retryActive := auth.BeginRuntimeExecution(execCtx)
					if !retryActive {
						releaseRetiredAuthRequestSlot(opts)
						roundState.forgetRetiredAttempt(auth)
						if errWait := waitForRetiredAuthInstanceCleanup(execCtx, auth); errWait != nil {
							return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errWait, auth, provider)
						}
						authErr = nil
						break
					}
					retryCtx = cliproxyexecutor.WithUpstreamAttempt(retryCtx)
					resp, errExec = executor.CountTokens(retryCtx, auth, execReq, opts)
					retiredDuringRetry := releaseRetry()
					if !retiredDuringRetry {
						errExec = recordExecutionAttemptError(retryCtx, auth, provider, errExec)
					}
					if errExec == nil {
						if !retiredDuringRetry {
							m.markExecutionResult(execCtx, resultForAuth(auth, provider, resultModel, true))
							m.bindSessionAffinity(ctx, providers, routeModel, opts, auth)
						}
						return resp, nil
					}
					if retiredDuringRetry {
						releaseRetiredAuthRequestSlot(opts)
						roundState.forgetRetiredAttempt(auth)
						if errWait := waitForRetiredAuthInstanceCleanup(execCtx, auth); errWait != nil {
							return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errWait, auth, provider)
						}
						authErr = nil
						break
					}
					if errCtx := execCtx.Err(); errCtx != nil {
						return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errCtx, auth, provider)
					}
				}
			}
			errExec = m.reportProxyFailure(execCtx, auth, errExec)
			result := resultForAuth(auth, provider, resultModel, false)
			result.Error = executionResultError(auth, errExec)
			if se, ok := errors.AsType[cliproxyexecutor.StatusError](errExec); ok && se != nil {
				result.Error.HTTPStatus = se.StatusCode()
			}
			if ra := retryAfterFromError(errExec); ra != nil {
				result.RetryAfter = ra
			}
			if !matchedAction {
				action, matchedAction = m.matchRequestScopedErrorAction(execCtx, auth, opts, errExec)
			}
			applyRequestScopedActionToResult(action, matchedAction, &result)
			if !skipAuthResultForError(errExec) {
				m.markExecutionResult(execCtx, result, opts)
			}
			if matchedAction && (action == internalconfig.RequestScopedActionStop || action == internalconfig.RequestScopedActionStopAndCooldown) {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(&requestScopedActionError{error: errExec, action: action}, auth, provider)
			}
			triggerChatGPTWebUnauthorizedRequestRefresh(errExec)
			if m.isRequestInvalidError(errExec, ctx) {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errExec, auth, provider)
			}
			authErr = errExec
			if !requestBodyReplayable(execCtx, opts) {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(errExec, auth, provider)
			}
			continue
		}
		if authErr != nil {
			if m.isRequestInvalidError(authErr, ctx) {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(authErr, auth, provider)
			}
			if strictSessionAffinity {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(authErr, auth, provider)
			}
			roundState.setLastError(auth, authErr)
			if !requestBodyReplayable(ctx, opts) {
				return cliproxyexecutor.Response{}, withAuthErrorResponseSource(authErr, auth, provider)
			}
			continue
		}
	}
}

func (m *Manager) executeStreamMixedOnce(ctx context.Context, providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, requestAttempt int, maxRetryCredentials int, defaultRequestRetry int, roundState *requestRoundState) (*cliproxyexecutor.StreamResult, error) {
	if len(providers) == 0 {
		return nil, &Error{Code: "provider_not_found", Message: "no provider supplied"}
	}
	roundState = roundState.ensure()
	routeModel := req.Model
	opts = ensureRequestedModelMetadata(opts, routeModel)
	opts = setSelectionAttemptMetadata(opts, requestAttempt)
	opts = withImageGenerationResultState(req, opts)
	opts.AuthRequestSlot = newAuthRequestSlot(opts.ExecutionDiagnostics, opts.ExecutionMetrics)
	defer opts.AuthRequestSlot.Release()
	strictSessionAffinity := m.strictSessionAffinityForRequest(ctx, req, opts)
	pickAllowed := m.requestRoundPickAllowed(ctx, roundState, maxRetryCredentials, requestAttempt, defaultRequestRetry)
	unregisterRelease := registerRequestBodyReleaseCallback(ctx, opts, func([]byte) {
		req.Payload = nil
		opts.OriginalRequest = nil
	})
	defer unregisterRelease()
	for {
		if !requestBodyReplayable(ctx, opts) {
			if roundState.lastErr != nil {
				return nil, roundState.lastErr
			}
			return nil, &Error{Code: "request_body_released", Message: "request body released; retry disabled"}
		}
		selectionStarted := time.Now()
		requestSlotBefore := opts.AuthRequestSlot.ReservationDurationNanos()
		opts = m.withSessionAffinityResultSnapshot(ctx, providers, routeModel, opts)
		auth, executor, provider, errPick := m.pickNextMixedWithImageToolFallback(ctx, providers, routeModel, req, opts, roundState.tried, pickAllowed)
		observeImageRequestSelectionPhases(opts.Metadata, opts.AuthRequestSlot, selectionStarted, requestSlotBefore)
		if errPick != nil {
			if chatGPTWebImageQuotaRefreshPendingError(errPick) {
				return nil, errPick
			}
			if _, isAvailabilityBlocker := availabilityBlockerResetIn(errPick); isAvailabilityBlocker {
				return nil, m.preferEarlierRoundAvailabilityError(errPick, roundState)
			}
			if roundState.lastErr != nil {
				return nil, roundState.lastErr
			}
			return nil, errPick
		}
		commitImmediateAuthRequestReservation(executor, opts.AuthRequestSlot)
		roundState.tried[auth.ID] = struct{}{}
		resolvedAuth, errProxy := m.ResolveProxyAuth(ctx, auth)
		if errProxy != nil {
			roundState.markAttempted(auth)
			if strictSessionAffinity {
				return nil, withAuthErrorResponseSource(errProxy, auth, provider)
			}
			roundState.setLastError(auth, errProxy)
			continue
		}
		auth = resolvedAuth

		entry := logEntryWithRequestID(ctx)
		debugLogAuthSelection(entry, auth, provider, req.Model)
		publishSelectedAuthMetadata(ctx, opts.Metadata, auth, provider)
		opts = withSelectedAuthInstanceMetadata(opts, auth)

		execCtx := ctx
		if rt := m.roundTripperFor(auth); rt != nil {
			execCtx = context.WithValue(execCtx, roundTripperContextKey{}, rt)
			execCtx = context.WithValue(execCtx, "cliproxy.roundtripper", rt)
		}
		preparedAuth, refreshedOnUnauthorized, errPrepare := m.prepareRequestAuthWithUnauthorizedRefresh(execCtx, executor, auth, opts)
		if errPrepare != nil {
			if errCtx := execCtx.Err(); errCtx != nil {
				return nil, withAuthErrorResponseSource(errCtx, auth, provider)
			}
			if isRuntimeAuthInstanceRetiredError(errPrepare) {
				releaseRetiredAuthRequestSlot(opts)
				roundState.forgetRetiredAttempt(auth)
				if errWait := waitForRetiredAuthInstanceCleanup(execCtx, auth); errWait != nil {
					return nil, withAuthErrorResponseSource(errWait, auth, provider)
				}
				continue
			}
			errPrepare = m.reportProxyFailure(execCtx, auth, errPrepare)
			roundState.markAttempted(auth)
			result := resultForAuth(auth, provider, routeModel, false)
			result.Error = executionResultError(auth, errPrepare)
			if statusErr, ok := errors.AsType[cliproxyexecutor.StatusError](errPrepare); ok && statusErr != nil {
				result.Error.HTTPStatus = statusErr.StatusCode()
			}
			result.RetryAfter = retryAfterFromError(errPrepare)
			if !skipAuthResultForError(errPrepare) {
				m.markExecutionResult(execCtx, result)
			}
			if isChatGPTWebUnauthorizedRequestError(errPrepare) {
				triggerChatGPTWebUnauthorizedRequestRefresh(errPrepare)
				return nil, withAuthErrorResponseSource(errPrepare, auth, provider)
			}
			if strictSessionAffinity {
				return nil, withAuthErrorResponseSource(errPrepare, auth, provider)
			}
			roundState.setLastError(auth, errPrepare)
			continue
		}
		carryRuntimeProxy(auth, preparedAuth)
		auth = preparedAuth
		publishErrorResponseSourceMetadata(opts.Metadata, errorResponseSourceForAuth(auth, provider))
		opts = withSelectedAuthInstanceMetadata(opts, auth)
		models, pooled, aliasResult, routing := m.preparedExecutionModelsWithAlias(auth, routeModel, opts)
		if len(models) == 0 {
			if strictSessionAffinity {
				return nil, withAuthErrorResponseSource(newStrictSessionAffinityError("session bound auth has no executable models"), auth, provider)
			}
			continue
		}
		execReq := sanitizeDownstreamWebsocketFallbackRequest(execCtx, auth, req)
		didRefreshOnUnauthorized := refreshedOnUnauthorized
		unregisterAttemptRelease := registerRequestBodyReleaseCallback(execCtx, opts, func([]byte) {
			execReq.Payload = nil
			opts.OriginalRequest = nil
		})
		if !requestBodyReplayable(execCtx, opts) {
			unregisterAttemptRelease()
			return nil, withAuthErrorResponseSource(&Error{Code: "request_body_released", Message: "request body released; retry disabled"}, auth, provider)
		}
		auth.bindExecutorOwner(executor)
		runtimeCtx, releaseExecution, active := auth.BeginRuntimeExecution(execCtx)
		if !active {
			unregisterAttemptRelease()
			releaseRetiredAuthRequestSlot(opts)
			roundState.forgetRetiredAttempt(auth)
			if errWait := waitForRetiredAuthInstanceCleanup(execCtx, auth); errWait != nil {
				return nil, withAuthErrorResponseSource(errWait, auth, provider)
			}
			continue
		}
		roundState.markAttempted(auth)
		streamResult, errStream := m.executeStreamWithModelPool(runtimeCtx, execCtx, executor, auth, providers, provider, execReq, opts, routeModel, models, pooled, aliasResult, releaseExecution, routing)
		unregisterAttemptRelease()
		if errStream != nil {
			retiredDuringExecution := releaseExecution()
			if retiredDuringExecution {
				releaseRetiredAuthRequestSlot(opts)
				roundState.forgetRetiredAttempt(auth)
				if errWait := waitForRetiredAuthInstanceCleanup(execCtx, auth); errWait != nil {
					return nil, withAuthErrorResponseSource(errWait, auth, provider)
				}
				continue
			}
			if errCtx := execCtx.Err(); errCtx != nil {
				return nil, withAuthErrorResponseSource(errCtx, auth, provider)
			}
			if cliproxyexecutor.IsImageExecutionCapacityError(errStream) {
				roundState.blockProvider(provider)
				roundState.setLastError(auth, errStream)
				if strictSessionAffinity || !requestBodyReplayable(execCtx, opts) {
					return nil, withAuthErrorResponseSource(errStream, auth, provider)
				}
				continue
			}
			markDeferredFailure := deferUnauthorizedStreamResult(auth, errStream)
			if requestBodyReplayable(execCtx, opts) {
				refreshed, attemptedRefresh, errRefresh := m.tryRefreshAfterUnauthorized(execCtx, executor, auth, errStream, didRefreshOnUnauthorized)
				if attemptedRefresh {
					didRefreshOnUnauthorized = true
				}
				if errRefresh != nil {
					if errCtx := execCtx.Err(); errCtx != nil {
						return nil, withAuthErrorResponseSource(errCtx, auth, provider)
					}
					errStream = errRefresh
					markDeferredFailure = true
				} else if attemptedRefresh {
					carryRuntimeProxy(auth, refreshed)
					auth = refreshed
					publishErrorResponseSourceMetadata(opts.Metadata, errorResponseSourceForAuth(auth, provider))
					opts = withSelectedAuthInstanceMetadata(opts, auth)
					auth.bindExecutorOwner(executor)
					if errLimit := m.acquireAdditionalAuthRequest(auth, executor, opts.AuthRequestSlot); errLimit != nil {
						errStream = errLimit
						markDeferredFailure = false
					} else {
						retryCtx, releaseRetry, retryActive := auth.BeginRuntimeExecution(execCtx)
						if !retryActive {
							releaseRetiredAuthRequestSlot(opts)
							roundState.forgetRetiredAttempt(auth)
							if errWait := waitForRetiredAuthInstanceCleanup(execCtx, auth); errWait != nil {
								return nil, withAuthErrorResponseSource(errWait, auth, provider)
							}
							continue
						}
						streamResult, errStream = m.executeStreamWithModelPool(retryCtx, execCtx, executor, auth, providers, provider, execReq, opts, routeModel, models, pooled, aliasResult, releaseRetry, routing)
						if errStream == nil {
							return streamResult, nil
						}
						if releaseRetry() {
							releaseRetiredAuthRequestSlot(opts)
							roundState.forgetRetiredAttempt(auth)
							if errWait := waitForRetiredAuthInstanceCleanup(execCtx, auth); errWait != nil {
								return nil, withAuthErrorResponseSource(errWait, auth, provider)
							}
							continue
						}
						if errCtx := execCtx.Err(); errCtx != nil {
							return nil, withAuthErrorResponseSource(errCtx, auth, provider)
						}
						markDeferredFailure = deferUnauthorizedStreamResult(auth, errStream)
					}
				}
			}
			if markDeferredFailure && !skipAuthResultForError(errStream) {
				resultModel := routeModel
				if len(models) > 0 {
					resultModel = m.stateModelForExecution(auth, routeModel, models[0], pooled)
				}
				resultModel = executionResultModelForError(resultModel, errStream)
				result := resultForAuth(auth, provider, resultModel, false)
				result.Error = executionResultError(auth, errStream)
				result.Error.Code = executionResultErrorCode(errStream)
				if statusErr, ok := errors.AsType[cliproxyexecutor.StatusError](errStream); ok && statusErr != nil {
					result.Error.HTTPStatus = statusErr.StatusCode()
				}
				result.RetryAfter = retryAfterFromError(errStream)
				m.markExecutionResult(execCtx, result)
			}
			triggerChatGPTWebUnauthorizedRequestRefresh(errStream)
			if isResponsesCompactRequestFaultError(opts, errStream) || m.isRequestInvalidError(errStream, ctx) {
				return nil, withAuthErrorResponseSource(errStream, auth, provider)
			}
			if strictSessionAffinity {
				return nil, withAuthErrorResponseSource(errStream, auth, provider)
			}
			roundState.setLastError(auth, errStream)
			if !requestBodyReplayable(execCtx, opts) {
				return nil, withAuthErrorResponseSource(errStream, auth, provider)
			}
			continue
		}
		return streamResult, nil
	}
}

func sanitizeDownstreamWebsocketFallbackRequest(ctx context.Context, auth *Auth, req cliproxyexecutor.Request) cliproxyexecutor.Request {
	if !cliproxyexecutor.DownstreamWebsocket(ctx) || authWebsocketsEnabled(auth) || len(req.Payload) == 0 {
		return req
	}
	updated, errDelete := sjson.DeleteBytes(req.Payload, "generate")
	if errDelete != nil {
		return req
	}
	req.Payload = updated
	return req
}

func (m *Manager) strictSessionAffinityForRequest(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) bool {
	if m == nil {
		return false
	}
	if policy := m.selectionPolicy(ctx); policy == nil || !policy.strictAffinity {
		return false
	}
	if captured, ok := opts.Metadata[basicAffinityIdentityMetadataKey].(basicAffinityIdentity); ok && captured.selector == m.selectorForContext(ctx) {
		return captured.primary != ""
	}
	if selector, ok := m.selectorForContext(ctx).(*SessionAffinitySelector); ok && selector != nil && (selector.subagents || selector.lcp) {
		primary, _ := selector.sessionIDs(ctx, opts)
		if primary != "" {
			return true
		}
		_, _, hasHistory := selector.historyRequest(ctx, "", req.Model, opts)
		return hasHistory
	}
	payload := opts.OriginalRequest
	if len(payload) == 0 {
		payload = req.Payload
	}
	return ExtractSessionID(opts.Headers, payload, opts.Metadata) != ""
}

type sessionAffinityBinder interface {
	BindSession(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, authID string)
}

// SessionAffinityTransactionalBinder lets external selectors roll back a
// binding if the selected auth instance retires during BindSession.
type SessionAffinityTransactionalBinder interface {
	BindSessionWithRollback(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, authID string) func()
}

type sessionAffinityInvalidator interface {
	InvalidateAuth(authID string)
}

func (m *Manager) bindSessionAffinity(ctx context.Context, providers []string, routeModel string, opts cliproxyexecutor.Options, auth *Auth) {
	if m == nil || auth == nil || auth.ID == "" {
		return
	}
	m.mu.RLock()
	current := m.auths[auth.ID]
	if current == nil || current.instanceID != auth.instanceID || m.authSelectionBlockedLocked(auth.ID) {
		m.mu.RUnlock()
		return
	}
	selector := m.selectorForContext(ctx)
	binder, ok := selector.(sessionAffinityBinder)
	m.mu.RUnlock()
	if !ok || binder == nil {
		return
	}
	providerKey := affinityProviderKey(providers)
	if providerKey == "" {
		return
	}
	selectionModel := selectionArgForSelector(selector, routeModel)
	var rollback func()
	if transactionalBinder, okTransactional := selector.(SessionAffinityTransactionalBinder); okTransactional && transactionalBinder != nil {
		rollback = transactionalBinder.BindSessionWithRollback(ctx, providerKey, selectionModel, opts, auth.ID)
	} else {
		binder.BindSession(ctx, providerKey, selectionModel, opts, auth.ID)
	}
	m.mu.RLock()
	current = m.auths[auth.ID]
	stillCurrent := current != nil && current.instanceID == auth.instanceID && !m.authSelectionBlockedLocked(auth.ID)
	m.mu.RUnlock()
	if !stillCurrent {
		if rollback != nil {
			rollback()
		} else if invalidator, okInvalidator := selector.(sessionAffinityInvalidator); okInvalidator && invalidator != nil {
			invalidator.InvalidateAuth(auth.ID)
		}
	}
}

func affinityProviderKey(providers []string) string {
	normalized := normalizeProviderKeys(providers)
	if len(normalized) == 0 {
		return ""
	}
	if len(normalized) == 1 {
		return normalized[0]
	}
	return "mixed"
}

func sessionAffinityFailoverEnabled(cfg *internalconfig.Config) bool {
	if cfg == nil || cfg.Routing.SessionAffinityFailover == nil {
		return true
	}
	return *cfg.Routing.SessionAffinityFailover
}

func newStrictSessionAffinityError(message string) *Error {
	return &Error{
		Code:       "session_bound_auth_unavailable",
		Message:    message,
		HTTPStatus: http.StatusServiceUnavailable,
	}
}

type creditsCandidateEntry struct {
	auth     *Auth
	executor ProviderExecutor
	provider string
	known    bool
	eligible bool
}

func (m *Manager) findAllAntigravityCreditsCandidateAuths(routeModel string, opts cliproxyexecutor.Options) []creditsCandidateEntry {
	entries := m.collectAntigravityCreditsCandidateAuths(routeModel, opts)
	candidates := make([]creditsCandidateEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.eligible {
			candidates = append(candidates, entry)
		}
	}
	return candidates
}

func (m *Manager) collectAntigravityCreditsCandidateAuths(routeModel string, opts cliproxyexecutor.Options) []creditsCandidateEntry {
	if m == nil {
		return nil
	}
	if !strings.Contains(strings.ToLower(strings.TrimSpace(routeModel)), "claude") {
		return nil
	}
	pinnedAuthID := pinnedAuthIDFromMetadata(opts.Metadata)
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := make([]creditsCandidateEntry, 0)
	for _, auth := range m.auths {
		if auth == nil || auth.Disabled || auth.Status == StatusDisabled || m.authSelectionBlockedLocked(auth.ID) {
			continue
		}
		if pinnedAuthID != "" && auth.ID != pinnedAuthID {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(auth.Provider), "antigravity") {
			continue
		}
		providerKey := strings.TrimSpace(strings.ToLower(auth.Provider))
		executor, ok := m.executors[providerKey]
		if !ok {
			continue
		}
		checkModel := m.selectionModelForAuth(auth, routeModel)
		eligible := true
		if blocked, _, _ := isAuthBlockedForModel(auth, checkModel, now); blocked && !antigravityCreditsQuotaCooldown(auth, checkModel, now) {
			eligible = false
		}
		known := false
		hint, okHint := GetAntigravityCreditsHint(auth.ID)
		if okHint && hint.MatchesAuth(auth) && (hint.IsFresh(now) || hint.BlocksRouting(now)) {
			known = true
			if !hint.Available {
				eligible = false
			}
		}
		entries = append(entries, creditsCandidateEntry{auth: auth.Clone(), executor: executor, provider: providerKey, known: known, eligible: eligible})
	}
	sort.Slice(entries, func(i, j int) bool {
		leftPriority := authPriority(entries[i].auth)
		rightPriority := authPriority(entries[j].auth)
		if leftPriority != rightPriority {
			return leftPriority > rightPriority
		}
		if entries[i].known != entries[j].known {
			return entries[i].known
		}
		return entries[i].auth.ID < entries[j].auth.ID
	})
	return entries
}

func antigravityCreditsQuotaCooldown(auth *Auth, model string, now time.Time) bool {
	if auth == nil {
		return false
	}
	hasQuotaBlocker := false
	if auth.Unavailable && auth.CooldownScope == cooldownScopeAuth && auth.NextRetryAfter.After(now) {
		if !auth.Quota.Exceeded {
			return false
		}
		hasQuotaBlocker = true
	}
	if model == "" {
		if auth.Unavailable && auth.NextRetryAfter.After(now) && auth.CooldownScope != cooldownScopeAuth {
			if !auth.Quota.Exceeded {
				return false
			}
			hasQuotaBlocker = true
		}
		return hasQuotaBlocker
	}
	modelKey := canonicalModelKey(model)
	for stateModel, state := range auth.ModelStates {
		if state == nil || canonicalModelKey(stateModel) != modelKey {
			continue
		}
		if state.Status == StatusDisabled {
			return false
		}
		if state.Unavailable && state.NextRetryAfter.After(now) {
			if !state.Quota.Exceeded {
				return false
			}
			hasQuotaBlocker = true
		}
	}
	return hasQuotaBlocker
}

func antigravityCreditsRoutingAuth(auth *Auth) *Auth {
	clone := auth.Clone()
	if clone == nil {
		return nil
	}
	if clone.Unavailable && clone.Quota.Exceeded {
		clone.Unavailable = false
		clone.NextRetryAfter = time.Time{}
		clone.CooldownScope = ""
		clone.Quota.Exceeded = false
		clone.Quota.NextRecoverAt = time.Time{}
	}
	return clone
}

func (m *Manager) pickAntigravityCreditsAtPriority(ctx context.Context, opts cliproxyexecutor.Options, priority int, entries []creditsCandidateEntry, pickAllowed func(*Auth) bool) (*creditsCandidateEntry, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	auths := make([]*Auth, 0, len(entries))
	entryByID := make(map[string]*creditsCandidateEntry, len(entries))
	for index := range entries {
		routingAuth := antigravityCreditsRoutingAuth(entries[index].auth)
		if routingAuth == nil {
			continue
		}
		auths = append(auths, routingAuth)
		entryByID[routingAuth.ID] = &entries[index]
	}
	if len(auths) == 0 {
		return nil, nil
	}
	opts = setSelectionAttemptMetadata(opts, 0)
	strategy := m.routingStrategyForPriority(priority, ctx)
	requestLimiter := m.authRequestLimiter()
	requestBlocked := authRequestLimitBlock{}
	dynamicallyLimited := make(map[string]struct{})
	for {
		now := requestLimiter.nowTime()
		reservation := weightedRequestReservation{manager: m, options: opts, now: now, blocked: &requestBlocked, rejected: dynamicallyLimited}
		combinedAllowed := func(auth *Auth) bool {
			if auth == nil || (pickAllowed != nil && !pickAllowed(auth)) {
				return false
			}
			if strategy == schedulerStrategyWeightedRoundRobin && authWeight(auth) <= 0 {
				return false
			}
			if _, limited := dynamicallyLimited[auth.ID]; limited {
				return false
			}
			requestPolicy := m.routingAuthRequestLimitPolicyForAuth(auth)
			available, block := requestLimiter.availableAt(auth.ID, requestPolicy, now)
			if !available {
				requestBlocked = earlierAuthRequestLimitBlock(requestBlocked, block)
			}
			return available
		}
		var selected *Auth
		var errPick error
		if strategy == schedulerStrategyFillFirst {
			fillFirstRange := m.routingFillFirstRangeForPriority(priority, ctx)
			fillFirstRPM := m.routingFillFirstPerAuthRPMForPriority(priority, ctx)
			selected, errPick = selectFillFirstAuthsForContextWithPolicy(ctx, auths, "antigravity", "", now, 0, func(int) int {
				return fillFirstRange
			}, func(int) int {
				return fillFirstRPM
			}, m.fillFirstLimiter(), func(auth *Auth) bool {
				return m.routingAuthRequestLimitPolicyForAuth(auth).limit > 0
			}, nil, combinedAllowed)
		} else {
			filtered := make([]*Auth, 0, len(auths))
			for _, auth := range auths {
				if combinedAllowed(auth) {
					filtered = append(filtered, auth)
				}
			}
			if len(filtered) == 0 {
				return nil, preferAuthRequestLimitError(nil, requestBlocked)
			}
			selector := baseSelector(m.selectorForContext(ctx))
			if strategy != schedulerStrategyCustom {
				selector = m.legacyPrioritySelector(priority, strategy, m.routingFillFirstRangeForPriority(priority, ctx), ctx)
			}
			if selector == nil {
				selector = &RoundRobinSelector{}
			}
			if weighted, ok := selector.(*WeightedRoundRobinSelector); ok {
				selected, errPick = weighted.pickAccepted(ctx, "antigravity", "", opts, filtered, reservation.acquire)
			} else {
				selected, errPick = selector.Pick(ctx, "antigravity", "", opts, filtered)
			}
			if errPick == nil && selected != nil {
				selected = authFromListByID(filtered, selected.ID)
				if selected == nil {
					return nil, &Error{Code: "auth_not_found", Message: "selector returned unavailable auth"}
				}
			}
		}
		if reservation.stalePolicy {
			requestBlocked = authRequestLimitBlock{}
			clear(dynamicallyLimited)
			continue
		}
		if errPick != nil {
			return nil, preferAuthRequestLimitError(errPick, requestBlocked)
		}
		if selected == nil {
			return nil, preferAuthRequestLimitError(nil, requestBlocked)
		}
		if !reservation.acquire(selected) {
			if reservation.stalePolicy {
				requestBlocked = authRequestLimitBlock{}
				clear(dynamicallyLimited)
				continue
			}
			continue
		}
		return entryByID[selected.ID], nil
	}
}

func (m *Manager) pickAntigravityCreditsCandidate(ctx context.Context, routeModel string, opts cliproxyexecutor.Options, roundState *requestRoundState, maxRetryCredentials int) (*creditsCandidateEntry, error) {
	roundState = roundState.ensure()
	candidates := m.collectAntigravityCreditsCandidateAuths(routeModel, opts)
	pickAllowed := clientKeyPriorityFilter(ctx, m.roundPickAllowed(roundState, maxRetryCredentials, ctx))
	var lastPickErr error
	var earliestBlocker error
	for start := 0; start < len(candidates); {
		priority := authPriority(candidates[start].auth)
		end := start + 1
		for end < len(candidates) && authPriority(candidates[end].auth) == priority {
			end++
		}
		for _, known := range []bool{true, false} {
			entries := make([]creditsCandidateEntry, 0, end-start)
			allowedByID := make(map[string]struct{}, end-start)
			for index := start; index < end; index++ {
				candidate := candidates[index]
				if candidate.known != known {
					continue
				}
				entries = append(entries, candidate)
				if _, tried := roundState.tried[candidate.auth.ID]; !tried && candidate.eligible && pickAllowed(candidate.auth) {
					allowedByID[candidate.auth.ID] = struct{}{}
				}
			}
			if len(allowedByID) == 0 {
				continue
			}
			selected, errPick := m.pickAntigravityCreditsAtPriority(ctx, opts, priority, entries, func(auth *Auth) bool {
				_, allowed := allowedByID[auth.ID]
				return allowed
			})
			if errPick != nil {
				if _, isBlocker := availabilityBlockerResetIn(errPick); isBlocker {
					earliestBlocker = earlierAvailabilityBlocker(earliestBlocker, errPick)
				} else {
					lastPickErr = errPick
				}
				continue
			}
			if selected != nil {
				return selected, nil
			}
		}
		start = end
	}
	if lastPickErr != nil {
		return nil, lastPickErr
	}
	return nil, earliestBlocker
}

func shouldAttemptAntigravityCreditsFallback(m *Manager, lastErr error, providers []string) bool {
	if m == nil || lastErr == nil {
		return false
	}
	if isAuthRequestLimitedError(lastErr) {
		return false
	}
	hasAntigravity := len(providers) == 0
	for _, p := range providers {
		if strings.EqualFold(strings.TrimSpace(p), "antigravity") {
			hasAntigravity = true
			break
		}
	}
	if !hasAntigravity {
		return false
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil || !cfg.QuotaExceeded.AntigravityCredits {
		return false
	}
	switch statusCodeFromError(lastErr) {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return true
	case 0:
		var authErr *Error
		if errors.As(lastErr, &authErr) && authErr != nil {
			return strings.EqualFold(authErr.Code, "auth_not_found")
		}
		return false
	default:
		return false
	}
}

func (m *Manager) tryAntigravityCreditsExecute(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, bool, error) {
	if !requestBodyReplayable(ctx, opts) {
		return cliproxyexecutor.Response{}, false, nil
	}
	routeModel := req.Model
	_, maxRetryCredentials, _ := m.retrySettings(ctx)
	roundState := newRequestRoundState()
	var lastPrepareErr error
	for {
		if ctx.Err() != nil || !requestBodyReplayable(ctx, opts) {
			return cliproxyexecutor.Response{}, false, ctx.Err()
		}
		candidate, errPick := m.pickAntigravityCreditsCandidate(ctx, routeModel, opts, roundState, maxRetryCredentials)
		if candidate == nil {
			if lastPrepareErr != nil {
				return cliproxyexecutor.Response{}, false, lastPrepareErr
			}
			return cliproxyexecutor.Response{}, false, errPick
		}
		c := *candidate
		roundState.tried[c.auth.ID] = struct{}{}
		roundState.markAttempted(c.auth)
		resolvedAuth, errProxy := m.ResolveProxyAuth(ctx, c.auth)
		if errProxy != nil {
			lastPrepareErr = withAuthErrorResponseSource(errProxy, c.auth, c.provider)
			continue
		}
		c.auth = resolvedAuth
		creditsCtx := WithAntigravityCredits(ctx)
		if rt := m.roundTripperFor(c.auth); rt != nil {
			creditsCtx = context.WithValue(creditsCtx, roundTripperContextKey{}, rt)
			creditsCtx = context.WithValue(creditsCtx, "cliproxy.roundtripper", rt)
		}
		creditsOpts := ensureRequestedModelMetadata(opts, routeModel)
		preparedAuth, _, errPrepare := m.prepareRequestAuthWithUnauthorizedRefresh(creditsCtx, c.executor, c.auth)
		if errPrepare != nil {
			if errCtx := creditsCtx.Err(); errCtx != nil {
				return cliproxyexecutor.Response{}, false, errCtx
			}
			if !isRuntimeAuthInstanceRetiredError(errPrepare) {
				errPrepare = m.reportProxyFailure(creditsCtx, c.auth, errPrepare)
				result := resultForAuth(c.auth, c.provider, routeModel, false)
				result.Error = executionResultError(c.auth, errPrepare)
				result.RetryAfter = retryAfterFromError(errPrepare)
				if !skipAuthResultForError(errPrepare) {
					m.markExecutionResult(creditsCtx, result)
				}
				lastPrepareErr = withAuthErrorResponseSource(errPrepare, c.auth, c.provider)
			} else {
				roundState.forgetRetiredAttempt(c.auth)
			}
			continue
		}
		carryRuntimeProxy(c.auth, preparedAuth)
		c.auth = preparedAuth
		publishSelectedAuthMetadata(creditsCtx, creditsOpts.Metadata, c.auth, c.provider)
		creditsOpts = withSelectedAuthInstanceMetadata(creditsOpts, c.auth)
		models := m.executionModelCandidates(c.auth, routeModel)
		if len(models) == 0 {
			continue
		}
		pooled := len(models) > 1
		for _, upstreamModel := range models {
			if !requestBodyReplayable(creditsCtx, creditsOpts) {
				return cliproxyexecutor.Response{}, false, nil
			}
			resultModel := m.stateModelForExecution(c.auth, routeModel, upstreamModel, pooled)
			execReq := req
			execReq.Model = upstreamModel
			c.auth.bindExecutorOwner(c.executor)
			runtimeCtx, releaseExecution, active := c.auth.BeginRuntimeExecution(creditsCtx)
			if !active {
				break
			}
			lastPrepareErr = nil
			runtimeCtx = cliproxyexecutor.WithUpstreamAttempt(runtimeCtx)
			resp, errExec := executeProviderRequest(runtimeCtx, c.executor, c.auth, execReq, creditsOpts)
			retiredDuringExecution := releaseExecution()
			if !retiredDuringExecution {
				errExec = recordExecutionAttemptError(runtimeCtx, c.auth, c.provider, errExec)
			}
			if errExec == nil {
				if !retiredDuringExecution {
					m.markExecutionResult(creditsCtx, resultForAuth(c.auth, c.provider, resultModel, true))
				}
				return resp, true, nil
			}
			if retiredDuringExecution {
				break
			}
			errExec = m.reportProxyFailure(creditsCtx, c.auth, errExec)
			result := resultForAuth(c.auth, c.provider, resultModel, false)
			result.Error = executionResultError(c.auth, errExec)
			if se, ok := errors.AsType[cliproxyexecutor.StatusError](errExec); ok && se != nil {
				result.Error.HTTPStatus = se.StatusCode()
			}
			if ra := retryAfterFromError(errExec); ra != nil {
				result.RetryAfter = ra
			}
			m.markExecutionResult(creditsCtx, result)
			continue
		}
	}
}

func (m *Manager) tryAntigravityCreditsExecuteStream(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, bool, error) {
	if !requestBodyReplayable(ctx, opts) {
		return nil, false, nil
	}
	routeModel := req.Model
	_, maxRetryCredentials, _ := m.retrySettings(ctx)
	roundState := newRequestRoundState()
	var lastPrepareErr error
	for {
		if ctx.Err() != nil || !requestBodyReplayable(ctx, opts) {
			return nil, false, ctx.Err()
		}
		candidate, errPick := m.pickAntigravityCreditsCandidate(ctx, routeModel, opts, roundState, maxRetryCredentials)
		if candidate == nil {
			if lastPrepareErr != nil {
				return nil, false, lastPrepareErr
			}
			return nil, false, errPick
		}
		c := *candidate
		roundState.tried[c.auth.ID] = struct{}{}
		roundState.markAttempted(c.auth)
		resolvedAuth, errProxy := m.ResolveProxyAuth(ctx, c.auth)
		if errProxy != nil {
			lastPrepareErr = withAuthErrorResponseSource(errProxy, c.auth, c.provider)
			continue
		}
		c.auth = resolvedAuth
		creditsCtx := WithAntigravityCredits(ctx)
		if rt := m.roundTripperFor(c.auth); rt != nil {
			creditsCtx = context.WithValue(creditsCtx, roundTripperContextKey{}, rt)
			creditsCtx = context.WithValue(creditsCtx, "cliproxy.roundtripper", rt)
		}
		creditsOpts := ensureRequestedModelMetadata(opts, routeModel)
		preparedAuth, _, errPrepare := m.prepareRequestAuthWithUnauthorizedRefresh(creditsCtx, c.executor, c.auth)
		if errPrepare != nil {
			if errCtx := creditsCtx.Err(); errCtx != nil {
				return nil, false, errCtx
			}
			if !isRuntimeAuthInstanceRetiredError(errPrepare) {
				errPrepare = m.reportProxyFailure(creditsCtx, c.auth, errPrepare)
				result := resultForAuth(c.auth, c.provider, routeModel, false)
				result.Error = executionResultError(c.auth, errPrepare)
				result.RetryAfter = retryAfterFromError(errPrepare)
				if !skipAuthResultForError(errPrepare) {
					m.markExecutionResult(creditsCtx, result)
				}
				lastPrepareErr = withAuthErrorResponseSource(errPrepare, c.auth, c.provider)
			} else {
				roundState.forgetRetiredAttempt(c.auth)
			}
			continue
		}
		carryRuntimeProxy(c.auth, preparedAuth)
		c.auth = preparedAuth
		publishSelectedAuthMetadata(creditsCtx, creditsOpts.Metadata, c.auth, c.provider)
		creditsOpts = withSelectedAuthInstanceMetadata(creditsOpts, c.auth)
		models := m.executionModelCandidates(c.auth, routeModel)
		if len(models) == 0 {
			continue
		}
		aliasResult := m.resolveExecutionAliasResult(c.auth, effectiveExecutionRouteModel(routeModel, creditsOpts))
		c.auth.bindExecutorOwner(c.executor)
		runtimeCtx, releaseExecution, active := c.auth.BeginRuntimeExecution(creditsCtx)
		if !active {
			continue
		}
		lastPrepareErr = nil
		result, errStream := m.executeStreamWithModelPool(runtimeCtx, creditsCtx, c.executor, c.auth, []string{c.provider}, c.provider, req, creditsOpts, routeModel, models, len(models) > 1, aliasResult, releaseExecution)
		if errStream != nil {
			releaseExecution()
			continue
		}
		return result, true, nil
	}
}

func ensureRequestedModelMetadata(opts cliproxyexecutor.Options, requestedModel string) cliproxyexecutor.Options {
	requestedModel = strings.TrimSpace(requestedModel)
	if requestedModel == "" {
		return opts
	}
	if hasRequestedModelMetadata(opts.Metadata) {
		return opts
	}
	if len(opts.Metadata) == 0 {
		opts.Metadata = map[string]any{cliproxyexecutor.RequestedModelMetadataKey: requestedModel}
		return opts
	}
	meta := make(map[string]any, len(opts.Metadata)+1)
	for k, v := range opts.Metadata {
		meta[k] = v
	}
	meta[cliproxyexecutor.RequestedModelMetadataKey] = requestedModel
	opts.Metadata = meta
	return opts
}

func withImageGenerationResultState(req cliproxyexecutor.Request, opts cliproxyexecutor.Options) cliproxyexecutor.Options {
	maxResults, compatibilityImageRequest := opts.Metadata[cliproxyexecutor.ImageGenerationMaxResultsMetadataKey].(int)
	if (!compatibilityImageRequest || maxResults <= 0) && !requestHasImageGenerationToolForFallback(req, opts) {
		return opts
	}
	meta := make(map[string]any, len(opts.Metadata)+1)
	for key, value := range opts.Metadata {
		meta[key] = value
	}
	meta[cliproxyexecutor.ImageGenerationResultStateMetadataKey] = &cliproxyexecutor.ImageGenerationResultState{}
	opts.Metadata = meta
	return opts
}

func withSelectedAuthInstanceMetadata(opts cliproxyexecutor.Options, auth *Auth) cliproxyexecutor.Options {
	if auth == nil || strings.TrimSpace(auth.instanceID) == "" {
		return opts
	}
	meta := make(map[string]any, len(opts.Metadata)+1)
	for key, value := range opts.Metadata {
		meta[key] = value
	}
	meta[cliproxyexecutor.SelectedAuthInstanceMetadataKey] = auth.instanceID
	meta[cliproxyexecutor.StreamTerminalMarkerMetadataKey] = true
	if auth.instanceState != nil {
		meta[cliproxyexecutor.SelectedAuthInstanceRetirementMetadataKey] = auth.instanceState
	}
	opts.Metadata = meta
	return opts
}

func hasRequestedModelMetadata(meta map[string]any) bool {
	if len(meta) == 0 {
		return false
	}
	raw, ok := meta[cliproxyexecutor.RequestedModelMetadataKey]
	if !ok || raw == nil {
		return false
	}
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v) != ""
	case []byte:
		return strings.TrimSpace(string(v)) != ""
	default:
		return false
	}
}

func executionModelOverrideFromMetadata(meta map[string]any) string {
	if len(meta) == 0 {
		return ""
	}
	raw, ok := meta[cliproxyexecutor.ExecutionModelOverrideMetadataKey]
	if !ok || raw == nil {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case []byte:
		return strings.TrimSpace(string(v))
	default:
		return ""
	}
}

func effectiveExecutionRouteModel(routeModel string, opts cliproxyexecutor.Options) string {
	if override := executionModelOverrideFromMetadata(opts.Metadata); override != "" {
		return override
	}
	return routeModel
}

func pinnedAuthIDFromMetadata(meta map[string]any) string {
	if len(meta) == 0 {
		return ""
	}
	raw, ok := meta[cliproxyexecutor.PinnedAuthMetadataKey]
	if !ok || raw == nil {
		return ""
	}
	switch val := raw.(type) {
	case string:
		return strings.TrimSpace(val)
	case []byte:
		return strings.TrimSpace(string(val))
	default:
		return ""
	}
}

func publishSelectedAuthMetadata(ctx context.Context, meta map[string]any, auth *Auth, fallbackProvider string) {
	if auth != nil {
		identity := auth.LogIdentity()
		if identity.Provider == "" {
			identity.Provider = fallbackProvider
		}
		logging.SetRequestCredential(ctx, identity)
	}
	if len(meta) == 0 {
		return
	}
	if auth == nil {
		return
	}
	authID := strings.TrimSpace(auth.ID)
	if authID == "" {
		return
	}
	meta[cliproxyexecutor.SelectedAuthMetadataKey] = authID
	if budget, ok := meta[cliproxyexecutor.ImageRequestBudgetMetadataKey].(*cliproxyexecutor.ImageRequestBudget); ok {
		provider := auth.Provider
		if provider == "" {
			provider = fallbackProvider
		}
		_ = budget.Select(provider)
	}
	if callback, ok := meta[cliproxyexecutor.SelectedAuthCallbackMetadataKey].(func(string)); ok && callback != nil {
		callback(authID)
	}
	publishErrorResponseSourceMetadata(meta, errorResponseSourceForAuth(auth, fallbackProvider))
}

func rewriteModelForAuth(model string, auth *Auth) string {
	if auth == nil || model == "" {
		return model
	}
	prefix := strings.TrimSpace(auth.Prefix)
	if prefix == "" {
		return model
	}
	needle := prefix + "/"
	if !strings.HasPrefix(model, needle) {
		return model
	}
	return strings.TrimPrefix(model, needle)
}

func (m *Manager) applyAPIKeyModelAlias(auth *Auth, requestedModel string, snapshots ...*apiKeyModelRoutingSnapshot) string {
	if m == nil || auth == nil {
		return requestedModel
	}

	kind, _ := auth.AccountInfo()
	if !strings.EqualFold(strings.TrimSpace(kind), "api_key") {
		return requestedModel
	}

	requestedModel = strings.TrimSpace(requestedModel)
	if requestedModel == "" {
		return requestedModel
	}

	// Fast path: lookup per-auth mapping table (keyed by auth.ID).
	routing := m.modelRoutingForAttempt(snapshots)
	if resolved := m.lookupAPIKeyUpstreamModel(auth.ID, requestedModel, routing); resolved != "" {
		return resolved
	}

	// Slow path: scan config for the matching credential entry and resolve alias.
	// This acts as a safety net if mappings are stale or auth.ID is missing.
	cfg := routing.config
	if cfg == nil {
		cfg = &internalconfig.Config{}
	}

	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	upstreamModel := ""
	switch provider {
	case "gemini":
		upstreamModel = resolveUpstreamModelForGeminiAPIKey(cfg, auth, requestedModel)
	case "gemini-interactions":
		upstreamModel = resolveUpstreamModelForInteractionsAPIKey(cfg, auth, requestedModel)
	case "claude":
		upstreamModel = resolveUpstreamModelForClaudeAPIKey(cfg, auth, requestedModel)
	case "xai":
		if entry := resolveXAIAPIKeyConfig(cfg, auth); entry != nil {
			upstreamModel = resolveModelAliasFromConfigModels(requestedModel, asModelAliasEntries(entry.Models))
		}
	case "codex":
		upstreamModel = resolveUpstreamModelForCodexAPIKey(cfg, auth, requestedModel)
	case "vertex":
		upstreamModel = resolveUpstreamModelForVertexAPIKey(cfg, auth, requestedModel)
	default:
		upstreamModel = resolveUpstreamModelForOpenAICompatAPIKey(cfg, auth, requestedModel)
	}

	// Return upstream model if found, otherwise return requested model.
	if upstreamModel != "" {
		return upstreamModel
	}
	return requestedModel
}

func (m *Manager) resolveAPIKeyModelAliasWithResult(auth *Auth, requestedModel string, snapshots ...*apiKeyModelRoutingSnapshot) OAuthModelAliasResult {
	if m == nil || auth == nil {
		return OAuthModelAliasResult{}
	}
	requestedModel = strings.TrimSpace(requestedModel)
	if requestedModel == "" {
		return OAuthModelAliasResult{}
	}
	cfg := m.modelRoutingForAttempt(snapshots).config
	if cfg == nil {
		cfg = &internalconfig.Config{}
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	var models []modelAliasEntry
	switch provider {
	case "gemini":
		if entry := resolveGeminiAPIKeyConfig(cfg, auth); entry != nil {
			models = asModelAliasEntries(entry.Models)
		}
	case "gemini-interactions":
		if entry := resolveInteractionsAPIKeyConfig(cfg, auth); entry != nil {
			models = asModelAliasEntries(entry.Models)
		}
	case "claude":
		if entry := resolveClaudeAPIKeyConfig(cfg, auth); entry != nil {
			models = asModelAliasEntries(entry.Models)
		}
	case "xai":
		if entry := resolveXAIAPIKeyConfig(cfg, auth); entry != nil {
			models = asModelAliasEntries(entry.Models)
		}
	case "codex":
		if entry := resolveCodexAPIKeyConfig(cfg, auth); entry != nil {
			models = asModelAliasEntries(entry.Models)
		}
	case "vertex":
		if entry := resolveVertexAPIKeyConfig(cfg, auth); entry != nil {
			models = asModelAliasEntries(entry.Models)
		}
	default:
		providerKey := ""
		compatName := ""
		if auth.Attributes != nil {
			providerKey = strings.TrimSpace(auth.Attributes["provider_key"])
			compatName = strings.TrimSpace(auth.Attributes["compat_name"])
		}
		if compatName != "" || strings.EqualFold(strings.TrimSpace(auth.Provider), "openai-compatibility") {
			if entry := resolveOpenAICompatConfig(cfg, providerKey, compatName, auth.Provider); entry != nil {
				models = asModelAliasEntries(entry.Models)
			}
		}
	}
	if len(models) == 0 {
		return OAuthModelAliasResult{UpstreamModel: requestedModel}
	}
	result := resolveModelAliasResultFromConfigModels(requestedModel, models)
	if strings.TrimSpace(result.UpstreamModel) == "" {
		return OAuthModelAliasResult{UpstreamModel: requestedModel}
	}
	return result
}

// APIKeyConfigEntry is a generic interface for API key configurations.
type APIKeyConfigEntry interface {
	GetAPIKey() string
	GetBaseURL() string
}

func resolveAPIKeyConfig[T APIKeyConfigEntry](entries []T, auth *Auth) *T {
	if auth == nil || len(entries) == 0 {
		return nil
	}
	attrKey, attrBase := "", ""
	if auth.Attributes != nil {
		attrKey = strings.TrimSpace(auth.Attributes["api_key"])
		attrBase = strings.TrimSpace(auth.Attributes["base_url"])
	}
	for i := range entries {
		entry := &entries[i]
		cfgKey := strings.TrimSpace((*entry).GetAPIKey())
		cfgBase := strings.TrimSpace((*entry).GetBaseURL())
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
		for i := range entries {
			entry := &entries[i]
			if strings.EqualFold(strings.TrimSpace((*entry).GetAPIKey()), attrKey) {
				return entry
			}
		}
	}
	return nil
}

func resolveAPIKeyConfigExact[T APIKeyConfigEntry](entries []T, auth *Auth) *T {
	if auth == nil || len(entries) == 0 {
		return nil
	}
	attrKey, attrBase := "", ""
	if auth.Attributes != nil {
		attrKey = strings.TrimSpace(auth.Attributes["api_key"])
		attrBase = strings.TrimSpace(auth.Attributes["base_url"])
	}
	for i := range entries {
		entry := &entries[i]
		cfgKey := strings.TrimSpace((*entry).GetAPIKey())
		cfgBase := strings.TrimSpace((*entry).GetBaseURL())
		switch {
		case attrKey != "" && attrBase != "" && cfgKey == attrKey && cfgBase == attrBase:
			return entry
		case attrKey != "" && attrBase == "" && cfgKey == attrKey && cfgBase == "":
			return entry
		case attrKey == "" && attrBase != "" && cfgBase == attrBase:
			return entry
		}
	}
	return nil
}

func resolveGeminiAPIKeyConfig(cfg *internalconfig.Config, auth *Auth) *internalconfig.GeminiKey {
	if cfg == nil {
		return nil
	}
	return resolveAPIKeyConfig(cfg.GeminiKey, auth)
}

func resolveInteractionsAPIKeyConfig(cfg *internalconfig.Config, auth *Auth) *internalconfig.GeminiKey {
	if cfg == nil {
		return nil
	}
	return resolveAPIKeyConfigExact(cfg.InteractionsKey, auth)
}

func resolveClaudeAPIKeyConfig(cfg *internalconfig.Config, auth *Auth) *internalconfig.ClaudeKey {
	if cfg == nil {
		return nil
	}
	return resolveAPIKeyConfig(cfg.ClaudeKey, auth)
}

func resolveCodexAPIKeyConfig(cfg *internalconfig.Config, auth *Auth) *internalconfig.CodexKey {
	if cfg == nil {
		return nil
	}
	return resolveAPIKeyConfig(cfg.CodexKey, auth)
}

func resolveVertexAPIKeyConfig(cfg *internalconfig.Config, auth *Auth) *internalconfig.VertexCompatKey {
	if cfg == nil {
		return nil
	}
	return resolveAPIKeyConfig(cfg.VertexCompatAPIKey, auth)
}

func resolveUpstreamModelForGeminiAPIKey(cfg *internalconfig.Config, auth *Auth, requestedModel string) string {
	entry := resolveGeminiAPIKeyConfig(cfg, auth)
	if entry == nil {
		return ""
	}
	return resolveModelAliasFromConfigModels(requestedModel, asModelAliasEntries(entry.Models))
}

func resolveUpstreamModelForInteractionsAPIKey(cfg *internalconfig.Config, auth *Auth, requestedModel string) string {
	entry := resolveInteractionsAPIKeyConfig(cfg, auth)
	if entry == nil {
		return ""
	}
	return resolveModelAliasFromConfigModels(requestedModel, asModelAliasEntries(entry.Models))
}

func resolveUpstreamModelForClaudeAPIKey(cfg *internalconfig.Config, auth *Auth, requestedModel string) string {
	entry := resolveClaudeAPIKeyConfig(cfg, auth)
	if entry == nil {
		return ""
	}
	return resolveModelAliasFromConfigModels(requestedModel, asModelAliasEntries(entry.Models))
}

func resolveUpstreamModelForCodexAPIKey(cfg *internalconfig.Config, auth *Auth, requestedModel string) string {
	entry := resolveCodexAPIKeyConfig(cfg, auth)
	if entry == nil {
		return ""
	}
	return resolveModelAliasFromConfigModels(requestedModel, asModelAliasEntries(entry.Models))
}

func resolveUpstreamModelForVertexAPIKey(cfg *internalconfig.Config, auth *Auth, requestedModel string) string {
	entry := resolveVertexAPIKeyConfig(cfg, auth)
	if entry == nil {
		return ""
	}
	return resolveModelAliasFromConfigModels(requestedModel, asModelAliasEntries(entry.Models))
}

func resolveUpstreamModelForOpenAICompatAPIKey(cfg *internalconfig.Config, auth *Auth, requestedModel string) string {
	providerKey := ""
	compatName := ""
	if auth != nil && len(auth.Attributes) > 0 {
		providerKey = strings.TrimSpace(auth.Attributes["provider_key"])
		compatName = strings.TrimSpace(auth.Attributes["compat_name"])
	}
	if compatName == "" && !strings.EqualFold(strings.TrimSpace(auth.Provider), "openai-compatibility") {
		return ""
	}
	entry := resolveOpenAICompatConfig(cfg, providerKey, compatName, auth.Provider)
	if entry == nil {
		return ""
	}
	return resolveModelAliasFromConfigModels(requestedModel, asModelAliasEntries(entry.Models))
}

type apiKeyModelAliasTable map[string]map[string]string

func resolveOpenAICompatConfig(cfg *internalconfig.Config, providerKey, compatName, authProvider string) *internalconfig.OpenAICompatibility {
	if cfg == nil {
		return nil
	}
	candidates := make([]string, 0, 3)
	if v := strings.TrimSpace(compatName); v != "" {
		candidates = append(candidates, v)
	}
	if v := strings.TrimSpace(providerKey); v != "" {
		candidates = append(candidates, v)
	}
	if v := strings.TrimSpace(authProvider); v != "" {
		candidates = append(candidates, v)
	}
	for i := range cfg.OpenAICompatibility {
		compat := &cfg.OpenAICompatibility[i]
		if compat.Disabled {
			continue
		}
		for _, candidate := range candidates {
			if candidate != "" && strings.EqualFold(strings.TrimSpace(candidate), compat.Name) {
				return compat
			}
		}
	}
	return nil
}

func asModelAliasEntries[T interface {
	GetName() string
	GetAlias() string
	GetForceMapping() bool
}](models []T) []modelAliasEntry {
	if len(models) == 0 {
		return nil
	}
	out := make([]modelAliasEntry, 0, len(models))
	for i := range models {
		out = append(out, models[i])
	}
	return out
}

func (m *Manager) normalizeProviders(providers []string) []string {
	if len(providers) == 0 {
		return nil
	}
	result := make([]string, 0, len(providers))
	seen := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		p := strings.TrimSpace(strings.ToLower(provider))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		result = append(result, p)
	}
	return result
}

func (m *Manager) prepareProviderRequests(
	ctx context.Context,
	providers []string,
	req cliproxyexecutor.Request,
	opts cliproxyexecutor.Options,
	operation cliproxyexecutor.RequestOperation,
) ([]string, cliproxyexecutor.Options, error) {
	budget := cliproxyexecutor.ImageRequestBudgetFromOptions(opts)
	if err := budget.Candidates(providers); err != nil {
		return nil, opts, err
	}
	if selector, ok := m.selectorForContext(ctx).(*SessionAffinitySelector); ok && selector != nil {
		if len(providers) == 1 && providers[0] == "xai" {
			metadata := make(map[string]any, len(opts.Metadata)+1)
			for key, value := range opts.Metadata {
				metadata[key] = value
			}
			metadata[grokSessionIdentityMetadataKey] = true
			opts.Metadata = metadata
		}
		if selector.subagents || selector.lcp {
			opts = withCapturedAffinityIdentity(opts, captureAffinityIdentityWithHistoryPolicy(ctx, req, opts, selector.lcp, !selector.disableHistory))
		} else {
			opts = selector.withBasicAffinityIdentity(ctx, req, opts)
		}
	}
	preparedProviders := make([]string, 0, len(providers))
	preparedOpts := opts
	var firstErr error
	for _, provider := range providers {
		exec := m.executorFor(provider)
		preparer, ok := exec.(ProviderRequestPreparer)
		if !ok {
			preparedProviders = append(preparedProviders, provider)
			continue
		}
		providerReq, providerOpts := cliproxyexecutor.PrepareImageRequestForProvider(provider, req, opts)
		prepareCtx, cancelPrepare := budget.PreflightContext(ctx, provider)
		prepared, errPrepare := preparer.PrepareProviderRequest(prepareCtx, providerReq, providerOpts, operation)
		errPrepare = cliproxyexecutor.ImageRequestContextError(prepareCtx, errPrepare)
		cancelPrepare()
		if errPrepare != nil {
			if cliproxyexecutor.IsImageRequestTimeout(errPrepare) {
				firstErr = errPrepare
				continue
			}
			if cliproxyexecutor.ProviderRequestPreparationScopeOf(errPrepare) != cliproxyexecutor.ProviderRequestPreparationProviderIncompatible {
				preparedOpts.ExecutionMetrics.RecordPreflightRejected()
				if preparedOpts.ExecutionDiagnostics != nil {
					preparedOpts.ExecutionDiagnostics.SetFailure("preflight", requestErrorCode(errPrepare))
				}
				return nil, opts, errPrepare
			}
			if firstErr == nil {
				firstErr = errPrepare
			}
			continue
		}
		preparedOpts = cliproxyexecutor.WithProviderPreparedRequest(preparedOpts, provider, prepared)
		preparedProviders = append(preparedProviders, provider)
	}
	if len(preparedProviders) == 0 && firstErr != nil {
		preparedOpts.ExecutionMetrics.RecordPreflightRejected()
		if preparedOpts.ExecutionDiagnostics != nil {
			preparedOpts.ExecutionDiagnostics.SetFailure("preflight", requestErrorCode(firstErr))
		}
		return nil, opts, firstErr
	}
	if err := budget.Candidates(preparedProviders); err != nil {
		return nil, opts, err
	}
	return preparedProviders, preparedOpts, nil
}

func (m *Manager) ensureExecutionDiagnostics(opts cliproxyexecutor.Options) cliproxyexecutor.Options {
	if opts.ExecutionDiagnostics == nil {
		opts.ExecutionDiagnostics = &cliproxyexecutor.RequestExecutionDiagnostics{}
	}
	if opts.UsageOutcome == nil {
		opts.UsageOutcome = &cliproxyexecutor.RequestUsageOutcome{}
	}
	if opts.ExecutionMetrics == nil && m != nil {
		opts.ExecutionMetrics = m.executionMetrics
	}
	return opts
}

func newAuthRequestSlot(diagnostics *cliproxyexecutor.RequestExecutionDiagnostics, metrics *cliproxyexecutor.RequestExecutionMetrics) *cliproxyexecutor.AuthRequestSlot {
	slot := &cliproxyexecutor.AuthRequestSlot{}
	slot.SetDiagnostics(diagnostics)
	slot.SetMetrics(metrics)
	return slot
}

func observeImageRequestSelectionPhases(metadata map[string]any, slot *cliproxyexecutor.AuthRequestSlot, started time.Time, reservationBefore uint64) {
	elapsed := time.Since(started)
	reservationDuration := time.Duration(0)
	if slot != nil {
		reservationAfter := slot.ReservationDurationNanos()
		if reservationAfter > reservationBefore {
			reservationNanos := reservationAfter - reservationBefore
			if elapsedNanos := uint64(max(elapsed.Nanoseconds(), int64(0))); reservationNanos > elapsedNanos {
				reservationNanos = elapsedNanos
			}
			reservationDuration = time.Duration(reservationNanos)
		}
	}
	cliproxyexecutor.ObserveRequestPhaseDuration(metadata, cliproxyexecutor.ImagePhaseRequestSlot, reservationDuration)
	cliproxyexecutor.ObserveRequestPhaseDuration(metadata, cliproxyexecutor.ImagePhaseCredentialSelection, elapsed-reservationDuration)
}

func (m *Manager) recordExecutionResultMetrics(opts cliproxyexecutor.Options, err error) {
	if err == nil {
		return
	}
	var limited *authRequestLimitedError
	if errors.As(err, &limited) {
		if opts.ExecutionMetrics != nil {
			opts.ExecutionMetrics.RecordAuthRequestLimited()
		}
		if opts.ExecutionDiagnostics != nil {
			opts.ExecutionDiagnostics.SetFailure("selection", "auth_request_limited")
		}
	}
}

func requestErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var authErr *Error
	if errors.As(err, &authErr) && authErr != nil && strings.TrimSpace(authErr.Code) != "" {
		return strings.TrimSpace(authErr.Code)
	}
	var status interface{ StatusCode() int }
	if errors.As(err, &status) {
		return fmt.Sprintf("http_%d", status.StatusCode())
	}
	return "invalid_request"
}

func (m *Manager) maxRetryCredentialsForPriority(priority int, globalMaxRetryCredentials int, contexts ...context.Context) int {
	if policy := m.selectionPolicy(contexts...); policy != nil {
		if value, exists := policy.priorityMaxRetries[priority]; exists {
			return value
		}
	}
	return globalMaxRetryCredentials
}

func (m *Manager) roundPickAllowed(roundState *requestRoundState, globalMaxRetryCredentials int, contexts ...context.Context) func(*Auth) bool {
	return func(auth *Auth) bool {
		if auth == nil || auth.RuntimeInstanceRetired() {
			return false
		}
		if roundState.providerBlocked(auth.Provider) {
			return false
		}
		priority := authPriority(auth)
		maxRetryCredentials := m.maxRetryCredentialsForPriority(priority, globalMaxRetryCredentials, contexts...)
		if maxRetryCredentials <= 0 {
			return true
		}
		if _, attempted := roundState.attempted[auth.ID]; attempted {
			return true
		}
		return roundState.attemptedCountAtPriority(priority) < maxRetryCredentials
	}
}

// WithRequestRetryBudget returns a context carrying bootstrap retry budget for stream recovery.
func (m *Manager) WithRequestRetryBudget(ctx context.Context, bootstrapRetries int) context.Context {
	return m.withRequestRetryBudget(ctx, nil, bootstrapRetries)
}

// WithRequestRetryBudgetForProviders returns a context carrying bootstrap retry budget for stream recovery.
func (m *Manager) WithRequestRetryBudgetForProviders(ctx context.Context, providers []string, bootstrapRetries int) context.Context {
	return m.withRequestRetryBudget(ctx, providers, bootstrapRetries)
}

// ConsumeRequestRetryBudget spends one bootstrap retry from the context budget.
func ConsumeRequestRetryBudget(ctx context.Context) bool {
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	if ctrl := cliproxyexecutor.RequestBodyReleaseControllerFromContext(ctx); ctrl != nil && !ctrl.Replayable() {
		return false
	}
	budget := requestRetryBudgetFromContext(ctx)
	if budget == nil {
		return true
	}
	return budget.consume()
}

func requestBodyReplayable(ctx context.Context, opts cliproxyexecutor.Options) bool {
	if ctrl := cliproxyexecutor.RequestBodyReleaseControllerFromOptions(opts); ctrl != nil {
		return ctrl.Replayable()
	}
	if ctrl := cliproxyexecutor.RequestBodyReleaseControllerFromContext(ctx); ctrl != nil {
		return ctrl.Replayable()
	}
	return true
}

func registerRequestBodyReleaseCallback(ctx context.Context, opts cliproxyexecutor.Options, callback func([]byte)) func() {
	return cliproxyexecutor.RegisterRequestBodyReleaseCallback(ctx, opts, callback)
}

func (m *Manager) withRequestRetryBudget(ctx context.Context, providers []string, bootstrapRetries int) context.Context {
	_ = providers
	if ctx == nil {
		ctx = context.Background()
	}
	if bootstrapRetries < 0 {
		bootstrapRetries = 0
	}
	// Nested setup shares the original budget, including an exhausted one.
	if existing := requestRetryBudgetFromContext(ctx); existing != nil {
		return ctx
	}
	return context.WithValue(ctx, requestRetryBudgetContextKey{}, newRequestRetryBudget(bootstrapRetries))
}

func (m *Manager) maxRequestRetryForProviders(providers []string, capturedDefault ...int) int {
	defaultRetry, _, _ := m.retrySettings()
	if len(capturedDefault) > 0 {
		defaultRetry = capturedDefault[0]
	}
	if defaultRetry < 0 {
		defaultRetry = 0
	}
	if m == nil || len(providers) == 0 {
		return defaultRetry
	}
	providerSet := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		key := strings.TrimSpace(strings.ToLower(provider))
		if key == "" {
			continue
		}
		providerSet[key] = struct{}{}
	}
	if len(providerSet) == 0 {
		return defaultRetry
	}

	maxRetry := 0
	m.mu.RLock()
	for provider := range providerSet {
		aggregate := m.providerRetryAggregates[provider]
		effectiveRetry := defaultRetry
		if aggregate != nil && aggregate.authCount > 0 {
			effectiveRetry = aggregate.maxOverride
			if aggregate.defaultCount > 0 && defaultRetry > effectiveRetry {
				effectiveRetry = defaultRetry
			}
		}
		if effectiveRetry > maxRetry {
			maxRetry = effectiveRetry
		}
	}
	m.mu.RUnlock()
	return maxRetry
}

func requestRetryBudgetFromContext(ctx context.Context) *requestRetryBudget {
	if ctx == nil {
		return nil
	}
	raw := ctx.Value(requestRetryBudgetContextKey{})
	budget, _ := raw.(*requestRetryBudget)
	return budget
}

func newRequestRetryBudget(total int) *requestRetryBudget {
	if total < 0 {
		total = 0
	}
	budget := &requestRetryBudget{}
	budget.remaining.Store(int64(total))
	return budget
}

func (b *requestRetryBudget) consume() bool {
	if b == nil {
		return true
	}
	for {
		remaining := b.remaining.Load()
		if remaining <= 0 {
			return false
		}
		if b.remaining.CompareAndSwap(remaining, remaining-1) {
			return true
		}
	}
}

func shouldRetryRequestRound(err error, rules []internalconfig.NonRetryableErrorRule) bool {
	if err == nil {
		return false
	}
	if retryOtherAuthForError(err) {
		return false
	}
	if isAuthRequestLimitedError(err) {
		return false
	}
	status := statusCodeFromError(err)
	if status == http.StatusOK {
		return false
	}
	if isRequestInvalidErrorWithRules(err, rules) {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return true
}

func (m *Manager) isRequestInvalidError(err error, contexts ...context.Context) bool {
	return isRequestInvalidErrorWithRules(err, m.requestNonRetryableErrorRules(contexts...))
}

func finalAuthSelectionError(err error) error {
	if err == nil {
		return nil
	}
	var cooldownErr *modelCooldownError
	if errors.As(err, &cooldownErr) {
		converted := WithStoredAuthFailure(&Error{Code: "auth_unavailable", Message: "no auth available"}, StoredAuthFailureOf(err))
		converted = WithResponseHeaders(converted, cooldownErr.Headers())
		if source, ok := cliproxyexecutor.ErrorResponseSourceOf(err); ok {
			converted = cliproxyexecutor.WithErrorResponseSource(converted, source)
		}
		return converted
	}
	return err
}

func isModelCooldownError(err error) bool {
	var cooldownErr *modelCooldownError
	return errors.As(err, &cooldownErr)
}

func isAuthRequestLimitedError(err error) bool {
	var limitErr *authRequestLimitedError
	return errors.As(err, &limitErr)
}

func cooldownWaitFromError(err error, maxWait time.Duration) (time.Duration, bool) {
	if maxWait <= 0 {
		return 0, false
	}
	var wait time.Duration
	var imageRateLimitErr *chatGPTWebImageRateLimitError
	if errors.As(err, &imageRateLimitErr) && imageRateLimitErr != nil {
		if !imageRateLimitErr.retryKnown || imageRateLimitErr.cooldown == nil {
			return 0, false
		}
		wait = imageRateLimitErr.cooldown.resetIn
	} else {
		var cooldownErr *modelCooldownError
		if !errors.As(err, &cooldownErr) || cooldownErr == nil {
			return 0, false
		}
		wait = cooldownErr.resetIn
	}
	if wait <= 0 || wait > maxWait {
		return 0, false
	}
	return wait, true
}

func retryAfterWaitFromError(err error, maxWait time.Duration) (time.Duration, bool) {
	if maxWait <= 0 || statusCodeFromError(err) != http.StatusTooManyRequests {
		return 0, false
	}
	retryAfter := retryAfterFromError(err)
	if retryAfter == nil || *retryAfter <= 0 || *retryAfter > maxWait {
		return 0, false
	}
	return *retryAfter, true
}

func waitForCooldown(ctx context.Context, wait time.Duration) error {
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// MarkResult records an execution result and notifies hooks.
func (m *Manager) MarkResult(ctx context.Context, result Result) {
	m.markResult(ctx, result, "", nil, 0, nil, false, false)
}

func (m *Manager) markExecutionResult(ctx context.Context, result executionResult, requestOptions ...cliproxyexecutor.Options) {
	m.markResult(
		ctx,
		result.Result,
		result.authInstanceID,
		result.additionalSuccessModels,
		result.imageSuccessCount,
		result.imageSuccessModels,
		result.quotaProjectionOnly,
		result.availabilityNeutral,
	)
	if len(requestOptions) > 0 {
		m.releaseNotFoundSessionBinding(ctx, result, requestOptions[0])
	}
}

func (m *Manager) markResult(
	ctx context.Context,
	result Result,
	authInstanceID string,
	additionalSuccessModels []string,
	imageSuccessCount int64,
	imageSuccessModels []string,
	quotaProjectionOnly bool,
	availabilityNeutral bool,
) {
	if result.AuthID == "" {
		return
	}
	modelNotFound := IsModelNotFoundError(result.Error)
	if modelNotFound && result.Error.Code != "model_not_found" {
		result.Error = cloneError(result.Error)
		result.Error.Code = "model_not_found"
	}
	modelKey := canonicalModelKey(result.Model)
	if ctx == nil {
		ctx = context.Background()
	}
	asyncResultPersistence := m.canPersistResultAsynchronously(result)
	var unlockMutation func()
	if asyncResultPersistence {
		unlockMutation = m.lockResultMutation(result.AuthID)
	} else {
		var errLock error
		unlockMutation, errLock = m.lockAuthIDMutationContext(context.WithoutCancel(ctx), result.AuthID)
		if errLock != nil {
			logEntryWithRequestID(ctx).WithField("auth_id", result.AuthID).Warnf("failed to lock result mutation: %v", errLock)
			return
		}
	}
	mutationLocked := true
	unlockResultMutation := func() {
		if mutationLocked {
			mutationLocked = false
			unlockMutation()
		}
	}
	defer unlockResultMutation()

	registeredModels := registry.GetGlobalRegistry().GetModelsForClient(result.AuthID)
	registeredExecutionModels := make(map[string]struct{}, len(registeredModels)*2)
	for _, registeredModel := range registeredModels {
		if registeredModel == nil {
			continue
		}
		if modelKey := canonicalModelKey(registeredModel.ID); modelKey != "" {
			registeredExecutionModels[modelKey] = struct{}{}
		}
		if modelKey := canonicalModelKey(registeredModel.UpstreamID); modelKey != "" {
			registeredExecutionModels[modelKey] = struct{}{}
		}
	}
	supportsExecutionModel := func(model string) bool {
		_, supported := registeredExecutionModels[canonicalModelKey(model)]
		return supported
	}
	registeredImageModels := chatGPTWebImageModelIDs(registeredModels)

	shouldResumeModel := false
	shouldSuspendModel := false
	suspendReason := ""
	clearModelQuota := false
	setModelQuota := false
	var additionalSuccessModelsApplied []string
	var imageQuotaSuspendModels []string
	imageQuotaEvidenceRefresh := false
	var (
		authSnapshot *Auth
		persistAuth  *Auth
	)
	if quotaProjectionOnly {
		newlyExhausted := false
		m.mu.Lock()
		if auth, ok := m.auths[result.AuthID]; ok && auth != nil &&
			(authInstanceID == "" || authInstanceID == auth.instanceID) {
			knownQuota := metadataInt(auth.Metadata["image_quota_remaining"]) != nil
			imageQuotaSuspendModels, newlyExhausted = projectChatGPTWebImageSuccess(
				auth,
				imageSuccessCount,
				imageSuccessModels,
				time.Now(),
			)
			if knownQuota {
				persistAuth = auth
			}
		}
		m.mu.Unlock()
		if persistAuth != nil {
			authSnapshot = m.snapshotResultStateForPersistence(ctx, persistAuth.ID, asyncResultPersistence)
		}
		m.upsertCurrentResultAuthState(authSnapshot)
		applyProjection := func() {
			for _, imageModel := range imageQuotaSuspendModels {
				registry.GetGlobalRegistry().SetModelQuotaExceeded(result.AuthID, imageModel)
				registry.GetGlobalRegistry().SuspendClientModel(result.AuthID, imageModel, "chatgpt_web_image_quota")
			}
		}
		stillCurrent := persistAuth != nil
		if stillCurrent && authInstanceID != "" {
			m.mu.RLock()
			current := m.auths[result.AuthID]
			stillCurrent = current != nil && current.instanceID == authInstanceID && !m.sessionCleanupPendingLocked(result.AuthID)
			m.mu.RUnlock()
		}
		if stillCurrent {
			applyProjection()
		}
		unlockResultMutation()
		if stillCurrent && newlyExhausted {
			m.triggerChatGPTWebImageQuotaEvidenceRefresh(result.AuthID, authInstanceID)
		}
		return
	}
	acceptedResult := authInstanceID == ""
	now := time.Time{}
	dynamicModelResult := false
	staleDynamicModelResult := false
	var beforeDynamicModelResult *Auth
	pendingDynamicFinalize := false
	finalizeAcceptedResultLocked := func(auth *Auth) {
		if auth == nil || staleDynamicModelResult {
			return
		}
		if result.Success && imageSuccessCount > 0 {
			var newlyExhausted bool
			imageQuotaSuspendModels, newlyExhausted = projectChatGPTWebImageSuccess(auth, imageSuccessCount, imageSuccessModels, now)
			imageQuotaEvidenceRefresh = imageQuotaEvidenceRefresh || newlyExhausted
		}
		persistAuth = auth
	}

	m.mu.Lock()
	if auth, ok := m.auths[result.AuthID]; ok && auth != nil && (authInstanceID == "" || authInstanceID == auth.instanceID) {
		acceptedResult = true
		now = time.Now()
		dynamicFixedCooldown, hasDynamicFixedCooldown := m.fixedErrorCooldownForResult(result.Error, ctx)
		resultStatusCode := statusCodeFromResult(result.Error)
		if modelNotFound || resultStatusCode == http.StatusNotFound {
			dynamicFixedCooldown.scope = cooldownScopeModel
		}
		chatGPTWebImageQuotaResult := result.Error != nil &&
			strings.EqualFold(strings.TrimSpace(result.Error.Code), "chatgpt_web_image_quota")
		chatGPTWebImage429Result := resultStatusCode == http.StatusTooManyRequests &&
			chatGPTWebImageModelProjectionForModels(auth, result.Model, registeredImageModels)
		if (chatGPTWebImageQuotaResult || chatGPTWebImage429Result) && hasDynamicFixedCooldown {
			dynamicFixedCooldown.scope = cooldownScopeModel
		}
		chatGPTWebInFlightModelResult := authInstanceID != "" &&
			result.Model != "" &&
			strings.EqualFold(strings.TrimSpace(auth.Provider), "chatgpt-web") &&
			!(!result.Success && isInvalidGrantResultError(result.Error))
		authWideDynamicCooldown := chatGPTWebInFlightModelResult &&
			((hasDynamicFixedCooldown && dynamicFixedCooldown.scope == cooldownScopeAuth) ||
				(!hasDynamicFixedCooldown && resultStatusCode == http.StatusUnauthorized))
		dynamicModelResult = chatGPTWebInFlightModelResult && !authWideDynamicCooldown
		staleDynamicModelResult = dynamicModelResult && !supportsExecutionModel(result.Model)
		removedDynamicModelWithAuthCooldown := authWideDynamicCooldown &&
			!supportsExecutionModel(result.Model)
		if dynamicModelResult && !staleDynamicModelResult {
			beforeDynamicModelResult = auth.Clone()
		}

		if !result.Success && isInvalidGrantResultError(result.Error) {
			disableAuthForInvalidGrant(auth, result.Error, now)
		} else if !result.Success && (auth.Disabled || auth.Status == StatusDisabled) {
			// Preserve an explicit disabled state against late in-flight results.
		} else if !result.Success && (availabilityNeutral || isCredentialNeutralFailure(result.Error)) {
			// Request faults and connection lifecycles do not change credential availability.
		} else if staleDynamicModelResult {
			// A dynamic catalog refresh already removed this model while the
			// request was in flight. Keep the result observable to hooks without
			// recreating stale per-model cooldown state.
		} else if result.Success {
			if modelKey != "" {
				state := ensureModelState(auth, result.Model)
				if !chatGPTWebImageQuotaOwnedModelStateForModels(auth, result.Model, state, registeredImageModels) {
					resetModelState(state, now)
					shouldResumeModel = true
					clearModelQuota = true
				}
			}
			if strings.EqualFold(strings.TrimSpace(auth.Provider), chatgptwebauth.Provider) {
				for _, additionalModel := range additionalSuccessModels {
					additionalModel = strings.TrimSpace(additionalModel)
					if additionalModel == "" ||
						canonicalModelKey(additionalModel) == canonicalModelKey(result.Model) ||
						!supportsExecutionModel(additionalModel) {
						continue
					}
					state := ensureModelState(auth, additionalModel)
					if !chatGPTWebImageQuotaOwnedModelStateForModels(auth, additionalModel, state, registeredImageModels) {
						resetModelState(state, now)
						additionalSuccessModelsApplied = append(additionalSuccessModelsApplied, additionalModel)
					}
				}
			}
			if modelKey != "" || len(additionalSuccessModelsApplied) > 0 {
				updateAggregatedAvailability(auth, now)
				if !hasModelError(auth, now) && !hasActiveAuthWideCooldown(auth, now) {
					auth.LastError = nil
					auth.StatusMessage = ""
					auth.Status = StatusActive
				}
				auth.UpdatedAt = now
			} else {
				clearAuthStateOnSuccess(auth, now)
			}
		} else {
			if chatGPTWebImageQuotaResult {
				imageQuotaSuspendModels = projectChatGPTWebImageQuotaExhausted(auth, registeredImageModels, now)
			}
			if modelKey != "" {
				if authWideDynamicCooldown {
					skipCooling := !hasDynamicFixedCooldown && m.cooldownSkippedForStatus(resultStatusCode, ctx)
					auth.Status = StatusError
					auth.UpdatedAt = now
					if result.Error != nil {
						auth.LastError = cloneError(result.Error)
						auth.StatusMessage = result.Error.Message
					}
					if !skipCooling {
						cooldown := 30 * time.Minute
						if hasDynamicFixedCooldown {
							cooldown = dynamicFixedCooldown.cooldown
						}
						applyAuthWideCooldown(auth, cooldown, now, quotaCooldownDisabledForAuth(auth))
					}
				} else if !isRequestScopedNotFoundResultError(result.Error) {
					state := ensureModelState(auth, result.Model)
					state.Status = StatusError
					state.UpdatedAt = now
					if result.Error != nil {
						state.LastError = cloneError(result.Error)
						state.StatusMessage = result.Error.Message
						auth.LastError = cloneError(result.Error)
						auth.StatusMessage = result.Error.Message
					}

					statusCode := statusCodeFromResult(result.Error)
					fixedCooldown, hasFixedCooldown := m.fixedErrorCooldownForResult(result.Error, ctx)
					if modelNotFound || statusCode == http.StatusNotFound {
						fixedCooldown.scope = cooldownScopeModel
					}
					if (chatGPTWebImageQuotaResult || chatGPTWebImage429Result) && hasFixedCooldown {
						fixedCooldown.scope = cooldownScopeModel
					}
					skipCooling := !hasFixedCooldown && m.cooldownSkippedForStatus(statusCode, ctx)
					disableCooling := quotaCooldownDisabledForAuth(auth)
					if hasFixedCooldown && fixedCooldown.scope == cooldownScopeAuth && !skipCooling {
						applyAuthWideCooldown(auth, fixedCooldown.cooldown, now, disableCooling)
					} else if !skipCooling {
						state.Unavailable = true
					}
					if modelNotFound && !skipCooling {
						state.NextRetryAfter = cooldownTime(now, notFoundCooldown, fixedCooldown, hasFixedCooldown, disableCooling)
						suspendReason = "model_not_found"
						shouldSuspendModel = !disableCooling
					} else if isModelSupportResultError(result.Error) && !skipCooling {
						next := cooldownTime(now, 12*time.Hour, fixedCooldown, hasFixedCooldown, disableCooling)
						state.NextRetryAfter = next
						suspendReason = "model_not_supported"
						shouldSuspendModel = true
					} else if !skipCooling && !(hasFixedCooldown && fixedCooldown.scope == cooldownScopeAuth) {
						switch statusCode {
						case 401:
							if disableCooling {
								state.NextRetryAfter = time.Time{}
							} else {
								next := cooldownTime(now, 30*time.Minute, fixedCooldown, hasFixedCooldown, disableCooling)
								state.NextRetryAfter = next
								suspendReason = "unauthorized"
								shouldSuspendModel = true
							}
						case 402, 403:
							if disableCooling {
								state.NextRetryAfter = time.Time{}
							} else {
								next := cooldownTime(now, 30*time.Minute, fixedCooldown, hasFixedCooldown, disableCooling)
								state.NextRetryAfter = next
								suspendReason = "payment_required"
								shouldSuspendModel = true
							}
						case 404:
							if disableCooling {
								state.NextRetryAfter = time.Time{}
							} else {
								next := cooldownTime(now, notFoundCooldown, fixedCooldown, hasFixedCooldown, disableCooling)
								state.NextRetryAfter = next
								suspendReason = "not_found"
								shouldSuspendModel = true
							}
						case 429:
							var next time.Time
							backoffLevel := state.Quota.BackoffLevel
							strikeCount := state.Quota.StrikeCount + 1
							quotaReason := "quota"
							if chatGPTWebImageQuotaResult {
								quotaReason = "chatgpt_web_image_quota"
							}
							if !disableCooling {
								if hasFixedCooldown {
									next = cooldownTime(now, 0, fixedCooldown, true, false)
								} else if result.RetryAfter != nil {
									next = now.Add(*result.RetryAfter)
								} else {
									cooldown, nextLevel := nextQuotaCooldown(backoffLevel, disableCooling)
									if cooldown > 0 {
										next = now.Add(cooldown)
									}
									backoffLevel = nextLevel
								}
							}
							state.NextRetryAfter = next
							state.Quota = QuotaState{
								Exceeded:      true,
								Reason:        quotaReason,
								NextRecoverAt: next,
								BackoffLevel:  backoffLevel,
								StrikeCount:   strikeCount,
							}
							if !disableCooling {
								suspendReason = quotaReason
								shouldSuspendModel = true
								setModelQuota = true
							}
						case 408, 500, 502, 503, 504:
							if disableCooling {
								state.NextRetryAfter = time.Time{}
							} else if hasFixedCooldown {
								state.NextRetryAfter = cooldownTime(now, time.Minute, fixedCooldown, true, false)
							} else if result.RetryAfter != nil {
								state.NextRetryAfter = now.Add(*result.RetryAfter)
							} else {
								state.NextRetryAfter = now.Add(time.Minute)
							}
						default:
							if hasFixedCooldown {
								state.NextRetryAfter = cooldownTime(now, 0, fixedCooldown, true, disableCooling)
							} else if requestScopedActionNeedsFallbackCooldown(result.Error) && !disableCooling {
								delay := time.Minute
								if result.RetryAfter != nil {
									delay = *result.RetryAfter
								}
								state.NextRetryAfter = now.Add(delay)
							} else {
								state.NextRetryAfter = time.Time{}
							}
						}
					}

					auth.Status = StatusError
					auth.UpdatedAt = now
					if !(hasFixedCooldown && fixedCooldown.scope == cooldownScopeAuth && !skipCooling) {
						updateAggregatedAvailability(auth, now)
					}
				}
			} else {
				statusCode := statusCodeFromResult(result.Error)
				fixedCooldown, hasFixedCooldown := m.fixedErrorCooldownForResult(result.Error, ctx)
				applyAuthFailureState(auth, result.Error, result.RetryAfter, now, !hasFixedCooldown && m.cooldownSkippedForStatus(statusCode, ctx), fixedCooldown, hasFixedCooldown)
			}
		}

		if removedDynamicModelWithAuthCooldown {
			delete(auth.ModelStates, modelKey)
			if len(auth.ModelStates) == 0 {
				auth.ModelStates = nil
			}
		}
		if dynamicModelResult && !staleDynamicModelResult {
			pendingDynamicFinalize = true
		} else {
			finalizeAcceptedResultLocked(auth)
		}
		m.updateManagementAuthCatalogLocked(auth)
	}
	m.mu.Unlock()
	if pendingDynamicFinalize {
		stillSupported := clientRegistrySupportsExecutionModel(result.AuthID, result.Model)
		m.mu.Lock()
		auth := m.auths[result.AuthID]
		if auth != nil && auth.instanceID == authInstanceID {
			if !stillSupported {
				*auth = *beforeDynamicModelResult
				shouldResumeModel = false
				shouldSuspendModel = false
				suspendReason = ""
				clearModelQuota = false
				setModelQuota = false
				additionalSuccessModelsApplied = nil
				staleDynamicModelResult = true
			}
			finalizeAcceptedResultLocked(auth)
			m.updateManagementAuthCatalogLocked(auth)
		}
		m.mu.Unlock()
	}
	if persistAuth != nil {
		authSnapshot = m.snapshotResultStateForPersistence(ctx, persistAuth.ID, asyncResultPersistence)
	}
	m.upsertCurrentResultAuthState(authSnapshot)

	applyRegistryResult := func() {
		if clearModelQuota && modelKey != "" {
			registry.GetGlobalRegistry().ClearModelQuotaExceeded(result.AuthID, modelKey)
		}
		if setModelQuota && modelKey != "" {
			registry.GetGlobalRegistry().SetModelQuotaExceeded(result.AuthID, modelKey)
		}
		if shouldResumeModel {
			registry.GetGlobalRegistry().ResumeClientModel(result.AuthID, modelKey)
		} else if shouldSuspendModel {
			registry.GetGlobalRegistry().SuspendClientModel(result.AuthID, modelKey, suspendReason)
		}
		for _, additionalModel := range additionalSuccessModelsApplied {
			registry.GetGlobalRegistry().ClearModelQuotaExceeded(result.AuthID, additionalModel)
			registry.GetGlobalRegistry().ResumeClientModel(result.AuthID, additionalModel)
		}
		for _, imageModel := range imageQuotaSuspendModels {
			registry.GetGlobalRegistry().SetModelQuotaExceeded(result.AuthID, imageModel)
			registry.GetGlobalRegistry().SuspendClientModel(result.AuthID, imageModel, "chatgpt_web_image_quota")
		}
	}

	if authInstanceID != "" {
		m.mu.RLock()
		current := m.auths[result.AuthID]
		stillCurrent := current != nil && current.instanceID == authInstanceID && !m.sessionCleanupPendingLocked(result.AuthID)
		m.mu.RUnlock()
		if stillCurrent {
			applyRegistryResult()
		}
		unlockResultMutation()
		if !stillCurrent {
			return
		}
		m.mu.RLock()
		current = m.auths[result.AuthID]
		stillCurrent = current != nil && current.instanceID == authInstanceID && !m.sessionCleanupPendingLocked(result.AuthID)
		m.mu.RUnlock()
		if stillCurrent {
			if imageQuotaEvidenceRefresh {
				m.triggerChatGPTWebImageQuotaEvidenceRefresh(result.AuthID, authInstanceID)
			}
			m.Hook().OnResult(ctx, result)
		}
		return
	}

	applyRegistryResult()
	unlockResultMutation()
	if acceptedResult {
		if imageQuotaEvidenceRefresh {
			m.triggerChatGPTWebImageQuotaEvidenceRefresh(result.AuthID, authInstanceID)
		}
		m.Hook().OnResult(ctx, result)
	}
}

func clientRegistrySupportsExecutionModel(authID, model string) bool {
	target := canonicalModelKey(model)
	if strings.TrimSpace(authID) == "" || target == "" {
		return false
	}
	for _, registered := range registry.GetGlobalRegistry().GetModelsForClient(authID) {
		if registered == nil {
			continue
		}
		if canonicalModelKey(registered.ID) == target || canonicalModelKey(registered.UpstreamID) == target {
			return true
		}
	}
	return false
}

func ensureModelState(auth *Auth, model string) *ModelState {
	model = canonicalModelKey(model)
	if auth == nil || model == "" {
		return nil
	}
	normalizeModelStates(auth)
	if auth.ModelStates == nil {
		auth.ModelStates = make(map[string]*ModelState)
	}
	if state, ok := auth.ModelStates[model]; ok && state != nil {
		return state
	}
	state := &ModelState{Status: StatusActive}
	auth.ModelStates[model] = state
	return state
}

func resetModelState(state *ModelState, now time.Time) {
	if state == nil {
		return
	}
	state.Unavailable = false
	state.Status = StatusActive
	state.StatusMessage = ""
	state.NextRetryAfter = time.Time{}
	state.LastError = nil
	state.Quota = QuotaState{}
	state.UpdatedAt = now
}

func modelStateIsClean(state *ModelState) bool {
	if state == nil {
		return true
	}
	if state.Status != StatusActive {
		return false
	}
	if state.Unavailable || state.StatusMessage != "" || !state.NextRetryAfter.IsZero() || state.LastError != nil {
		return false
	}
	if state.Quota.Exceeded || state.Quota.Reason != "" || !state.Quota.NextRecoverAt.IsZero() || state.Quota.BackoffLevel != 0 || state.Quota.StrikeCount != 0 {
		return false
	}
	return true
}

// HasAccountMaintenanceQuotaExceeded reports whether account-level quota
// maintenance may act on this auth. ChatGPT Web image quota is model-scoped.
func (auth *Auth) HasAccountMaintenanceQuotaExceeded() bool {
	if auth == nil || !auth.Quota.Exceeded {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), chatgptwebauth.Provider) ||
		auth.CooldownScope == cooldownScopeAuth {
		return true
	}
	imageQuotaProjected := false
	for model, state := range auth.ModelStates {
		if state == nil || !state.Quota.Exceeded {
			continue
		}
		if !chatGPTWebImageModelProjection(auth, model) {
			return true
		}
		imageQuotaProjected = true
	}
	return !imageQuotaProjected
}

func updateAggregatedAvailability(auth *Auth, now time.Time) {
	if auth == nil {
		return
	}
	preserveAuthWideCooldown := hasActiveAuthWideCooldown(auth, now)
	authWideNextRetry := auth.NextRetryAfter
	authWideQuota := auth.Quota
	if len(auth.ModelStates) == 0 {
		if preserveAuthWideCooldown {
			return
		}
		clearAggregatedAvailability(auth)
		return
	}
	allUnavailable := true
	earliestRetry := time.Time{}
	quotaExceeded := false
	quotaRecover := time.Time{}
	maxBackoffLevel := 0
	maxStrikeCount := 0
	hasState := false
	for _, state := range auth.ModelStates {
		if state == nil {
			continue
		}
		hasState = true
		stateUnavailable := false
		if state.Status == StatusDisabled {
			stateUnavailable = true
		} else if state.Unavailable {
			if state.NextRetryAfter.IsZero() {
				stateUnavailable = false
			} else if state.NextRetryAfter.After(now) {
				stateUnavailable = true
				if earliestRetry.IsZero() || state.NextRetryAfter.Before(earliestRetry) {
					earliestRetry = state.NextRetryAfter
				}
			} else {
				state.Unavailable = false
				state.NextRetryAfter = time.Time{}
			}
		}
		if !stateUnavailable {
			allUnavailable = false
		}
		if state.Quota.Exceeded {
			quotaExceeded = true
			if quotaRecover.IsZero() || (!state.Quota.NextRecoverAt.IsZero() && state.Quota.NextRecoverAt.Before(quotaRecover)) {
				quotaRecover = state.Quota.NextRecoverAt
			}
			if state.Quota.BackoffLevel > maxBackoffLevel {
				maxBackoffLevel = state.Quota.BackoffLevel
			}
			if state.Quota.StrikeCount > maxStrikeCount {
				maxStrikeCount = state.Quota.StrikeCount
			}
		}
	}
	if !hasState {
		if preserveAuthWideCooldown {
			return
		}
		clearAggregatedAvailability(auth)
		return
	}
	if preserveAuthWideCooldown {
		auth.Unavailable = true
		auth.NextRetryAfter = authWideNextRetry
		auth.CooldownScope = cooldownScopeAuth
		auth.Quota = authWideQuota
		return
	}
	auth.Unavailable = allUnavailable
	if allUnavailable {
		auth.NextRetryAfter = earliestRetry
		auth.CooldownScope = cooldownScopeModel
	} else {
		auth.NextRetryAfter = time.Time{}
		auth.CooldownScope = ""
	}
	if quotaExceeded {
		auth.Quota.Exceeded = true
		auth.Quota.Reason = "quota"
		auth.Quota.NextRecoverAt = quotaRecover
		auth.Quota.BackoffLevel = maxBackoffLevel
		auth.Quota.StrikeCount = maxStrikeCount
	} else {
		auth.Quota.Exceeded = false
		auth.Quota.Reason = ""
		auth.Quota.NextRecoverAt = time.Time{}
		auth.Quota.BackoffLevel = 0
		auth.Quota.StrikeCount = 0
	}
}

func hasActiveAuthWideCooldown(auth *Auth, now time.Time) bool {
	return auth != nil && auth.Unavailable && auth.CooldownScope == cooldownScopeAuth && auth.NextRetryAfter.After(now)
}

func clearAggregatedAvailability(auth *Auth) {
	if auth == nil {
		return
	}
	auth.Unavailable = false
	auth.NextRetryAfter = time.Time{}
	auth.CooldownScope = ""
	auth.Quota = QuotaState{}
}

func hasModelError(auth *Auth, now time.Time) bool {
	if auth == nil || len(auth.ModelStates) == 0 {
		return false
	}
	for _, state := range auth.ModelStates {
		if state == nil {
			continue
		}
		if state.LastError != nil {
			return true
		}
		if state.Status == StatusError {
			if state.Unavailable && (state.NextRetryAfter.IsZero() || state.NextRetryAfter.After(now)) {
				return true
			}
		}
	}
	return false
}

func clearAuthStateOnSuccess(auth *Auth, now time.Time) {
	if auth == nil {
		return
	}
	auth.Unavailable = false
	auth.Status = StatusActive
	auth.StatusMessage = ""
	auth.Quota.Exceeded = false
	auth.Quota.Reason = ""
	auth.Quota.NextRecoverAt = time.Time{}
	auth.Quota.BackoffLevel = 0
	auth.Quota.StrikeCount = 0
	auth.LastError = nil
	auth.NextRetryAfter = time.Time{}
	auth.CooldownScope = ""
	auth.UpdatedAt = now
}

func cloneError(err *Error) *Error {
	if err == nil {
		return nil
	}
	return &Error{
		Code:                err.Code,
		Message:             err.Message,
		Retryable:           err.Retryable,
		HTTPStatus:          err.HTTPStatus,
		Diagnostic:          err.Diagnostic.Clone(),
		requestScopedAction: err.requestScopedAction,
	}
}

func executionResultError(auth *Auth, err error) *Error {
	if err == nil {
		return nil
	}
	result := &Error{
		Code:       executionResultErrorCode(err),
		Message:    err.Error(),
		HTTPStatus: statusCodeFromError(err),
	}
	result.Diagnostic = providerErrorDiagnostic(err)
	if result.Diagnostic != nil {
		if result.HTTPStatus == 0 {
			result.HTTPStatus = result.Diagnostic.HTTPStatus
		}
		result.Retryable = result.Diagnostic.Retryable
		enrichExecutionErrorDiagnostic(result.Diagnostic, auth)
	}
	return result
}

// NewProviderError converts a provider failure into the manager's safe error shape.
func NewProviderError(auth *Auth, err error) *Error {
	return executionResultError(auth, err)
}

func providerErrorDiagnostic(err error) *ErrorDiagnostic {
	if err == nil {
		return nil
	}
	type diagnosticProvider interface {
		AuthErrorDiagnostic() *ErrorDiagnostic
	}
	var provider diagnosticProvider
	if errors.As(err, &provider) && provider != nil {
		return provider.AuthErrorDiagnostic().Clone()
	}
	authError, ok := chatgptwebauth.AsAuthError(err)
	if !ok || authError == nil {
		return nil
	}
	code := chatgptwebauth.SafeDiagnosticCode(authError.DiagnosticCode)
	if code == "" {
		code = chatgptwebauth.SafeDiagnosticCode(authError.Code)
	}
	return &ErrorDiagnostic{
		Provider:              chatgptwebauth.Provider,
		Stage:                 strings.TrimSpace(authError.FailureStage),
		Code:                  code,
		ResponseType:          strings.TrimSpace(authError.ResponseType),
		ContentType:           strings.TrimSpace(authError.ContentType),
		CFRay:                 strings.TrimSpace(authError.CFRay),
		TargetHost:            strings.TrimSpace(authError.TargetHost),
		TargetPath:            strings.TrimSpace(authError.TargetPath),
		ResponseBytes:         authError.ResponseBytes,
		ResponseBody:          authError.ResponseBody,
		ResponseBodyTruncated: authError.ResponseBodyTruncated,
		Attempts:              authError.Attempts,
		HTTPStatus:            authError.StatusCode,
		Cloudflare:            authError.Cloudflare,
		Retryable:             authError.Retryable,
	}
}

func enrichExecutionErrorDiagnostic(diagnostic *ErrorDiagnostic, auth *Auth) {
	if diagnostic == nil || auth == nil {
		return
	}
	if diagnostic.Provider == "" {
		diagnostic.Provider = executorKeyFromAuth(auth)
	}
	diagnostic.AuthIndex = auth.EnsureIndex()
	if !strings.EqualFold(diagnostic.Provider, chatgptwebauth.Provider) || len(auth.Metadata) == 0 {
		return
	}
	credential, errCredential := chatgptwebauth.ParseCredential(auth.Metadata)
	if errCredential != nil || credential == nil {
		return
	}
	chatgptwebauth.ResolveCredentialPersona(credential, auth.ID)
	browserEnvironment := chatgptwebauth.ResolveCredentialBrowserEnvironment(credential, auth.ID)
	if diagnostic.Persona == "" {
		diagnostic.Persona = strings.TrimSpace(credential.Persona.Profile)
	}
	if diagnostic.CatalogVersion == "" {
		diagnostic.CatalogVersion = strings.TrimSpace(credential.Persona.CatalogVersion)
	}
	if diagnostic.CatalogID == "" {
		diagnostic.CatalogID = strings.TrimSpace(credential.Persona.CatalogID)
	}
	if diagnostic.TransportPersonaID == "" {
		diagnostic.TransportPersonaID = strings.TrimSpace(credential.Persona.CatalogID)
	}
	if diagnostic.BrowserEnvironmentID == "" {
		diagnostic.BrowserEnvironmentID = strings.TrimSpace(browserEnvironment.CatalogID)
	}
	if diagnostic.TLSProfile == "" {
		diagnostic.TLSProfile = strings.TrimSpace(credential.Persona.Profile)
	}
	if diagnostic.Platform == "" {
		diagnostic.Platform = strings.TrimSpace(credential.Persona.Platform)
	}
	if diagnostic.UAMajor == "" {
		diagnostic.UAMajor = userAgentMajorVersion(credential.Persona.UserAgent)
	}
}

func userAgentMajorVersion(userAgent string) string {
	for _, marker := range []string{"Chrome/", "CriOS/", "Firefox/", "Version/"} {
		index := strings.Index(userAgent, marker)
		if index < 0 {
			continue
		}
		version := userAgent[index+len(marker):]
		if end := strings.IndexAny(version, ". ;)"); end >= 0 {
			version = version[:end]
		}
		return strings.TrimSpace(version)
	}
	return ""
}

func statusCodeFromError(err error) int {
	if err == nil {
		return 0
	}
	type statusCoder interface {
		StatusCode() int
	}
	var sc statusCoder
	if errors.As(err, &sc) && sc != nil {
		return sc.StatusCode()
	}
	return 0
}

func isUnauthorizedError(err error) bool {
	if err == nil {
		return false
	}
	if statusCodeFromError(err) == http.StatusUnauthorized {
		return true
	}
	raw := strings.ToLower(err.Error())
	return strings.Contains(raw, "status 401") || strings.Contains(raw, "401 unauthorized")
}

func isChatGPTWebAuthenticationRecoveryError(err error) bool {
	if isUnauthorizedError(err) {
		return true
	}
	if statusCodeFromError(err) != http.StatusForbidden {
		return false
	}
	var lifecycleProvider interface {
		ChatGPTWebLifecycleError() *chatgptwebauth.AuthError
	}
	return errors.As(err, &lifecycleProvider) && lifecycleProvider != nil && lifecycleProvider.ChatGPTWebLifecycleError() != nil
}

// chatGPTWebUnauthorizedRequestError keeps the original upstream error while
// preventing the rejected request from waiting for credential recovery or
// falling through to another credential.
type chatGPTWebUnauthorizedRequestError struct {
	cause        error
	startRefresh func()
	skipResult   bool
	startOnce    sync.Once
}

type chatGPTWebUnauthorizedRefreshContextKey struct{}

type chatGPTWebRequestRefreshFlight struct {
	done   chan struct{}
	result singleflight.Result
}

func (err *chatGPTWebUnauthorizedRequestError) Error() string {
	if err == nil || err.cause == nil {
		return "chatgpt web request unauthorized"
	}
	return err.cause.Error()
}

func (err *chatGPTWebUnauthorizedRequestError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

func (err *chatGPTWebUnauthorizedRequestError) StatusCode() int {
	if err == nil {
		return 0
	}
	return statusCodeFromError(err.cause)
}

func (err *chatGPTWebUnauthorizedRequestError) SkipAuthResult() bool {
	return err != nil && err.skipResult
}

func wrapChatGPTWebUnauthorizedRequestError(err error, startRefresh func()) error {
	return wrapChatGPTWebUnauthorizedRequestErrorWithResultPolicy(err, startRefresh, true)
}

func wrapChatGPTWebUnauthorizedRequestErrorWithResultPolicy(err error, startRefresh func(), skipResult bool) error {
	if err == nil {
		return nil
	}
	var wrapped *chatGPTWebUnauthorizedRequestError
	if errors.As(err, &wrapped) {
		return err
	}
	return &chatGPTWebUnauthorizedRequestError{cause: err, startRefresh: startRefresh, skipResult: skipResult}
}

func isChatGPTWebUnauthorizedRequestError(err error) bool {
	var wrapped *chatGPTWebUnauthorizedRequestError
	return errors.As(err, &wrapped)
}

func triggerChatGPTWebUnauthorizedRequestRefresh(err error) {
	var wrapped *chatGPTWebUnauthorizedRequestError
	if !errors.As(err, &wrapped) || wrapped == nil || wrapped.startRefresh == nil {
		return
	}
	wrapped.startOnce.Do(wrapped.startRefresh)
}

func (m *Manager) wrapChatGPTWebUnauthorizedRequestError(ctx context.Context, auth *Auth, err error) error {
	if isChatGPTWebUnauthorizedRequestError(err) {
		return err
	}
	if m != nil && isUnauthorizedError(err) {
		m.chatGPTWebRequestRefreshMetrics.received.Add(1)
	}
	var lifecycleProvider interface {
		ChatGPTWebLifecycleError() *chatgptwebauth.AuthError
	}
	if errors.As(err, &lifecycleProvider) && lifecycleProvider != nil {
		if lifecycle := lifecycleProvider.ChatGPTWebLifecycleError(); lifecycle != nil && lifecycle.State == chatgptwebauth.LifecycleDead {
			reason := chatgptwebauth.SafeLifecycleReason(lifecycle.Code)
			if reason != "account_deleted" && reason != "account_deactivated" {
				if m != nil {
					m.chatGPTWebRequestRefreshMetrics.noStart.Add(1)
				}
				return wrapChatGPTWebUnauthorizedRequestErrorWithResultPolicy(err, nil, false)
			}
			if m != nil {
				m.chatGPTWebRequestRefreshMetrics.noStart.Add(1)
				m.chatGPTWebRequestRefreshMetrics.deadConfirmed.Add(1)
			}
			if m == nil || auth == nil || !isNativeChatGPTWebCredentialAuth(auth) {
				return wrapChatGPTWebUnauthorizedRequestError(err, nil)
			}
			terminalAuth := auth.Clone()
			startTerminal := func() {
				m.markChatGPTWebTerminalLifecycle(terminalAuth, lifecycle)
			}
			return wrapChatGPTWebUnauthorizedRequestError(err, startTerminal)
		}
	}
	if auth == nil {
		if m != nil {
			m.chatGPTWebRequestRefreshMetrics.noStart.Add(1)
		}
		return wrapChatGPTWebUnauthorizedRequestError(err, nil)
	}
	if !isNativeChatGPTWebCredentialAuth(auth) || !auth.LifecycleRefreshable() {
		if m != nil {
			m.chatGPTWebRequestRefreshMetrics.noStart.Add(1)
		}
		// There is no safe refresh flight for this credential. Preserve the
		// request-invalid contract while allowing the normal result mutation to
		// persist a cooldown instead of leaving the credential ready.
		return wrapChatGPTWebUnauthorizedRequestErrorWithResultPolicy(err, nil, false)
	}
	refreshAuth := auth.Clone()
	failedAccessToken := authAccessToken(refreshAuth)
	startRefresh := func() {
		refreshCtx := context.Background()
		if ctx != nil {
			refreshCtx = context.WithoutCancel(ctx)
		}
		_, errStart := m.startChatGPTWebRequestRefreshFlight(refreshCtx, refreshAuth.ID, failedAccessToken, refreshAuth, true)
		if errStart != nil {
			m.chatGPTWebRequestRefreshMetrics.noStart.Add(1)
			if !errors.Is(errStart, context.Canceled) {
				m.markChatGPTWebUnauthorizedRefreshFailure(refreshAuth, failedAccessToken)
			}
			log.Debugf("chatgpt-web credential background refresh could not start for %s: %v", refreshAuth.ID, errStart)
		}
	}
	return wrapChatGPTWebUnauthorizedRequestError(err, startRefresh)
}

func authAccessToken(auth *Auth) string {
	if token := authMetadataString(auth, "access_token"); token != "" {
		return token
	}
	return authMetadataString(auth, "accessToken")
}

func authMetadataString(auth *Auth, key string) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	value, _ := auth.Metadata[key].(string)
	return strings.TrimSpace(value)
}

func authHasRefreshCredential(auth *Auth) bool {
	return authMetadataString(auth, "refresh_token") != "" || authMetadataString(auth, "refreshToken") != ""
}

func deferUnauthorizedStreamResult(auth *Auth, err error) bool {
	if _, handled := requestScopedActionFromError(err); handled {
		return false
	}
	if auth == nil || isKnownRequestFault(err) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(auth.Provider)) {
	case "antigravity":
		return isUnauthorizedError(err) && authHasRefreshCredential(auth)
	case "chatgpt-web":
		return isChatGPTWebAuthenticationRecoveryError(err) && isNativeChatGPTWebCredentialAuth(auth) && auth.LifecycleRefreshable()
	default:
		return false
	}
}

func clearUnauthorizedRefreshState(auth *Auth, now time.Time, requestUnauthorized bool) []string {
	if auth == nil {
		return nil
	}
	unauthorized := auth.LastError != nil &&
		(auth.LastError.StatusCode() == http.StatusUnauthorized || strings.EqualFold(auth.LastError.Code, "unauthorized"))
	if !unauthorized && requestUnauthorized && auth.LastError == nil && auth.CooldownScope == cooldownScopeAuth {
		unauthorized = true
	}
	if unauthorized {
		auth.LastError = nil
		auth.StatusMessage = ""
		if auth.Status == StatusError {
			auth.Status = StatusActive
		}
		if auth.CooldownScope == cooldownScopeAuth {
			auth.Unavailable = false
			auth.NextRetryAfter = time.Time{}
			auth.CooldownScope = ""
		}
	}
	resumed := make([]string, 0)
	for model, state := range auth.ModelStates {
		if state == nil || state.LastError == nil {
			continue
		}
		if state.LastError.StatusCode() != http.StatusUnauthorized && !strings.EqualFold(state.LastError.Code, "unauthorized") {
			continue
		}
		resetModelState(state, now)
		resumed = append(resumed, model)
	}
	if len(resumed) > 0 {
		updateAggregatedAvailability(auth, now)
	}
	return resumed
}

func retryAfterFromError(err error) *time.Duration {
	if err == nil {
		return nil
	}
	type retryAfterProvider interface {
		RetryAfter() *time.Duration
	}
	var rap retryAfterProvider
	if !errors.As(err, &rap) || rap == nil {
		return nil
	}
	retryAfter := rap.RetryAfter()
	if retryAfter == nil {
		return nil
	}
	return new(*retryAfter)
}

func skipAuthResultForError(err error) bool {
	if err == nil {
		return false
	}
	type skipAuthResultError interface {
		SkipAuthResult() bool
	}
	var target skipAuthResultError
	return errors.As(err, &target) && target.SkipAuthResult()
}

func persistAuthUpdateForError(err error) bool {
	if err == nil {
		return false
	}
	type persistAuthUpdateError interface {
		PersistAuthUpdateOnError() bool
	}
	var target persistAuthUpdateError
	return errors.As(err, &target) && target.PersistAuthUpdateOnError()
}

func retryOtherAuthForError(err error) bool {
	if err == nil {
		return false
	}
	type retryOtherAuthError interface {
		RetryOtherAuth() bool
	}
	var target retryOtherAuthError
	return errors.As(err, &target) && target.RetryOtherAuth()
}

func statusCodeFromResult(err *Error) int {
	if err == nil {
		return 0
	}
	return err.StatusCode()
}

func isModelSupportErrorMessage(message string) bool {
	lower := strings.ToLower(strings.TrimSpace(message))
	if lower == "" {
		return false
	}
	patterns := [...]string{
		"model_not_supported",
		"requested model is not supported",
		"requested model is unsupported",
		"requested model is unavailable",
		"model is not supported",
		"model not supported",
		"unsupported model",
		"model unavailable",
		"not available for your plan",
		"not available for your account",
	}
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func isModelSupportError(err error) bool {
	if err == nil {
		return false
	}
	if IsModelNotFoundError(err) {
		return true
	}
	status := statusCodeFromError(err)
	if status != http.StatusBadRequest && status != http.StatusUnprocessableEntity {
		return false
	}
	return isModelSupportErrorMessage(err.Error())
}

func isInvalidGrantErrorMessage(message string) bool {
	return strings.Contains(strings.ToLower(message), "invalid_grant")
}

func isInvalidGrantError(err error) bool {
	if err == nil {
		return false
	}
	status := statusCodeFromError(err)
	if status != http.StatusBadRequest && status != http.StatusUnauthorized {
		return false
	}
	return isInvalidGrantErrorMessage(err.Error())
}

func isInvalidGrantResultError(err *Error) bool {
	if err == nil {
		return false
	}
	status := statusCodeFromResult(err)
	if status != http.StatusBadRequest && status != http.StatusUnauthorized {
		return false
	}
	return isInvalidGrantErrorMessage(err.Code) || isInvalidGrantErrorMessage(err.Message)
}

func disableAuthForInvalidGrant(auth *Auth, resultErr *Error, now time.Time) {
	if auth == nil {
		return
	}
	auth.Disabled = true
	auth.Status = StatusDisabled
	auth.StatusMessage = "invalid_grant"
	auth.Unavailable = true
	auth.LastError = cloneError(resultErr)
	auth.NextRetryAfter = time.Time{}
	auth.CooldownScope = ""
	auth.Quota = QuotaState{}
	auth.UpdatedAt = now
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["disabled"] = true
}

func isModelSupportResultError(err *Error) bool {
	if err == nil {
		return false
	}
	if IsModelNotFoundError(err) {
		return true
	}
	status := statusCodeFromResult(err)
	if status != http.StatusBadRequest && status != http.StatusUnprocessableEntity {
		return false
	}
	return isModelSupportErrorMessage(err.Message)
}

func isRequestScopedNotFoundMessage(message string) bool {
	if message == "" {
		return false
	}
	lower := strings.ToLower(message)
	return strings.Contains(lower, "item with id") &&
		strings.Contains(lower, "not found") &&
		strings.Contains(lower, "items are not persisted when `store` is set to false")
}

func isRequestScopedNotFoundResultError(err *Error) bool {
	if err == nil || statusCodeFromResult(err) != http.StatusNotFound {
		return false
	}
	return isRequestScopedNotFoundMessage(err.Message)
}

// isRequestInvalidErrorWithConfig returns true if the error represents a client
// request error that should not be retried. Built-in request-shape failures are
// preserved, and custom non-retryable error rules can add stable upstream errors.
func isRequestInvalidErrorWithConfig(err error, cfg *internalconfig.Config) bool {
	return isRequestInvalidErrorWithRules(err, nonRetryableErrorRulesForConfig(cfg))
}

func isRequestInvalidErrorWithRules(err error, rules []internalconfig.NonRetryableErrorRule) bool {
	if err == nil {
		return false
	}
	if isRequestScopedStopError(err) {
		return true
	}
	if isChatGPTWebUnauthorizedRequestError(err) {
		return true
	}
	var committed interface{ RequestCommitted() bool }
	if errors.As(err, &committed) && committed.RequestCommitted() {
		return true
	}
	if skipAuthResultForError(err) && !retryOtherAuthForError(err) {
		return true
	}
	if isInvalidGrantError(err) {
		return false
	}
	if isModelSupportError(err) {
		return false
	}
	if isKnownRequestFault(err) {
		return true
	}
	status := statusCodeFromError(err)
	switch status {
	case http.StatusBadRequest:
		if strings.Contains(strings.ToLower(err.Error()), "invalid_request_error") {
			return true
		}
	case http.StatusNotFound:
		return isRequestScopedNotFoundMessage(err.Error())
	case http.StatusUnprocessableEntity:
		return true
	}
	return matchesNonRetryableErrorRules(err, status, rules)
}

func matchesNonRetryableErrorRules(err error, statusCode int, rules []internalconfig.NonRetryableErrorRule) bool {
	if err == nil {
		return false
	}
	if len(rules) == 0 {
		return false
	}
	fields := nonRetryableErrorFieldsFromError(err)
	for _, rule := range rules {
		if rule.StatusCode != 0 && rule.StatusCode != statusCode {
			continue
		}
		if rule.Type != "" && !strings.EqualFold(rule.Type, fields.errType) {
			continue
		}
		if rule.Code != "" && !strings.EqualFold(rule.Code, fields.code) {
			continue
		}
		if rule.MessageContains != "" {
			needle := strings.ToLower(strings.TrimSpace(rule.MessageContains))
			if needle == "" {
				continue
			}
			if !strings.Contains(fields.messageLower, needle) && !strings.Contains(fields.rawLower, needle) {
				continue
			}
		}
		return true
	}
	return false
}

func nonRetryableErrorRulesForConfig(cfg *internalconfig.Config) []internalconfig.NonRetryableErrorRule {
	if cfg == nil || cfg.NonRetryableErrors == nil {
		return internalconfig.DefaultNonRetryableErrorRules()
	}
	return cfg.NonRetryableErrors
}

type nonRetryableErrorFields struct {
	errType      string
	code         string
	messageLower string
	rawLower     string
}

func nonRetryableErrorFieldsFromError(err error) nonRetryableErrorFields {
	raw := ""
	if err != nil {
		raw = strings.TrimSpace(err.Error())
	}
	payload := raw
	if idx := strings.Index(payload, "{"); idx >= 0 {
		payload = payload[idx:]
	}
	errType := strings.TrimSpace(gjson.Get(payload, "error.type").String())
	if errType == "" {
		errType = strings.TrimSpace(gjson.Get(payload, "type").String())
	}
	code := strings.TrimSpace(gjson.Get(payload, "error.code").String())
	if code == "" {
		code = strings.TrimSpace(gjson.Get(payload, "code").String())
	}
	message := strings.TrimSpace(gjson.Get(payload, "error.message").String())
	if message == "" {
		message = strings.TrimSpace(gjson.Get(payload, "message").String())
	}
	if message == "" {
		message = raw
	}
	return nonRetryableErrorFields{
		errType:      strings.ToLower(errType),
		code:         strings.ToLower(code),
		messageLower: strings.ToLower(message),
		rawLower:     strings.ToLower(raw),
	}
}

func cooldownTime(now time.Time, defaultCooldown time.Duration, fixed fixedErrorCooldownMatch, hasFixed, disableCooling bool) time.Time {
	if disableCooling {
		return time.Time{}
	}
	cooldown := defaultCooldown
	if hasFixed {
		cooldown = fixed.cooldown
	}
	if cooldown <= 0 {
		return time.Time{}
	}
	return now.Add(cooldown)
}

func applyAuthWideCooldown(auth *Auth, cooldown time.Duration, now time.Time, disableCooling bool) {
	if auth == nil {
		return
	}
	auth.Unavailable = true
	auth.CooldownScope = cooldownScopeAuth
	auth.NextRetryAfter = cooldownTime(now, 0, fixedErrorCooldownMatch{cooldown: cooldown}, true, disableCooling)
}

func applyAuthFailureState(auth *Auth, resultErr *Error, retryAfter *time.Duration, now time.Time, skipCooling bool, fixed fixedErrorCooldownMatch, hasFixed bool) {
	if auth == nil {
		return
	}
	if isCredentialNeutralFailure(resultErr) {
		return
	}
	auth.Status = StatusError
	auth.UpdatedAt = now
	if resultErr != nil {
		auth.LastError = cloneError(resultErr)
		if resultErr.Message != "" {
			auth.StatusMessage = resultErr.Message
		}
	}
	if skipCooling || statusCodeFromResult(resultErr) == http.StatusNotFound || IsModelNotFoundError(resultErr) {
		// Without a model key, a model availability failure cannot justify
		// cooling every model on the credential.
		return
	}
	disableCooling := quotaCooldownDisabledForAuth(auth)
	auth.Unavailable = true
	auth.CooldownScope = cooldownScopeAuth
	statusCode := statusCodeFromResult(resultErr)
	switch statusCode {
	case 401:
		auth.StatusMessage = "unauthorized"
		if disableCooling {
			auth.NextRetryAfter = time.Time{}
		} else {
			auth.NextRetryAfter = cooldownTime(now, 30*time.Minute, fixed, hasFixed, disableCooling)
		}
	case 402, 403:
		auth.StatusMessage = "payment_required"
		if disableCooling {
			auth.NextRetryAfter = time.Time{}
		} else {
			auth.NextRetryAfter = cooldownTime(now, 30*time.Minute, fixed, hasFixed, disableCooling)
		}
	case 429:
		auth.StatusMessage = "quota exhausted"
		auth.Quota.Exceeded = true
		auth.Quota.Reason = "quota"
		auth.Quota.StrikeCount++
		var next time.Time
		if !disableCooling {
			if hasFixed {
				next = cooldownTime(now, 0, fixed, true, false)
			} else if retryAfter != nil {
				next = now.Add(*retryAfter)
			} else {
				cooldown, nextLevel := nextQuotaCooldown(auth.Quota.BackoffLevel, disableCooling)
				if cooldown > 0 {
					next = now.Add(cooldown)
				}
				auth.Quota.BackoffLevel = nextLevel
			}
		}
		auth.Quota.NextRecoverAt = next
		auth.NextRetryAfter = next
	case 408, 500, 502, 503, 504:
		auth.StatusMessage = "transient upstream error"
		auth.Quota.Exceeded = false
		auth.Quota.Reason = ""
		auth.Quota.NextRecoverAt = time.Time{}
		if disableCooling {
			auth.NextRetryAfter = time.Time{}
		} else if hasFixed {
			auth.NextRetryAfter = cooldownTime(now, time.Minute, fixed, true, false)
		} else if retryAfter != nil {
			auth.NextRetryAfter = now.Add(*retryAfter)
		} else {
			auth.NextRetryAfter = now.Add(time.Minute)
		}
	default:
		auth.Quota.Exceeded = false
		auth.Quota.Reason = ""
		auth.Quota.NextRecoverAt = time.Time{}
		if auth.StatusMessage == "" {
			auth.StatusMessage = "request failed"
		}
		if hasFixed {
			auth.NextRetryAfter = cooldownTime(now, 0, fixed, true, disableCooling)
		} else if requestScopedActionNeedsFallbackCooldown(resultErr) && !disableCooling {
			delay := time.Minute
			if retryAfter != nil {
				delay = *retryAfter
			}
			auth.NextRetryAfter = now.Add(delay)
		}
	}
}

// nextQuotaCooldown returns the next cooldown duration and updated backoff level for repeated quota errors.
func nextQuotaCooldown(prevLevel int, disableCooling bool) (time.Duration, int) {
	if prevLevel < 0 {
		prevLevel = 0
	}
	if disableCooling {
		return 0, prevLevel
	}
	cooldown := quotaBackoffBase * time.Duration(1<<prevLevel)
	if cooldown < quotaBackoffBase {
		cooldown = quotaBackoffBase
	}
	if cooldown >= quotaBackoffMax {
		return quotaBackoffMax, prevLevel
	}
	return cooldown, prevLevel + 1
}

// List returns all auth entries currently known by the manager.
func (m *Manager) List() []*Auth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]*Auth, 0, len(m.auths))
	for _, auth := range m.auths {
		list = append(list, auth.Clone())
	}
	return list
}

// Count returns the number of runtime credentials without cloning them.
func (m *Manager) Count() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	count := len(m.auths)
	m.mu.RUnlock()
	return count
}

// ListMetadataSummaries returns lightweight runtime auth snapshots containing
// only the requested metadata keys. It is intended for management indexes that
// must inspect every credential without cloning tokens, cookies, or model maps.
func (m *Manager) ListMetadataSummaries(metadataKeys ...string) []*Auth {
	if m == nil {
		return nil
	}
	keySet := make(map[string]struct{}, len(metadataKeys))
	for _, key := range metadataKeys {
		if key = strings.TrimSpace(key); key != "" {
			keySet[key] = struct{}{}
		}
	}
	m.mu.RLock()
	ids := make([]string, 0, len(m.auths))
	for id := range m.auths {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	list := make([]*Auth, 0, len(ids))
	for _, id := range ids {
		auth := m.auths[id]
		if auth == nil {
			continue
		}
		summary := &Auth{
			ID:               auth.ID,
			Index:            auth.Index,
			Provider:         auth.Provider,
			Prefix:           auth.Prefix,
			FileName:         auth.FileName,
			Label:            auth.Label,
			Status:           auth.Status,
			StatusMessage:    auth.StatusMessage,
			Disabled:         auth.Disabled,
			Unavailable:      auth.Unavailable,
			CreatedAt:        auth.CreatedAt,
			UpdatedAt:        auth.UpdatedAt,
			LastRefreshedAt:  auth.LastRefreshedAt,
			NextRefreshAfter: auth.NextRefreshAfter,
			NextRetryAfter:   auth.NextRetryAfter,
			CooldownScope:    auth.CooldownScope,
		}
		if len(auth.Attributes) > 0 {
			summary.Attributes = make(map[string]string, len(auth.Attributes))
			for key, value := range auth.Attributes {
				summary.Attributes[key] = value
			}
		}
		if len(keySet) > 0 && len(auth.Metadata) > 0 {
			summary.Metadata = make(map[string]any, len(keySet))
			for key := range keySet {
				if value, ok := auth.Metadata[key]; ok {
					summary.Metadata[key] = value
				}
			}
		}
		if _, requested := keySet["plan_type"]; requested {
			if summary.Metadata == nil {
				summary.Metadata = make(map[string]any, 1)
			}
			if _, explicit := summary.Metadata["plan_type"]; !explicit {
				if planType := strings.TrimSpace(m.authPlanTypesByID[id]); planType != "" {
					summary.Metadata["plan_type"] = planType
				}
			}
		}
		if auth.LastError != nil {
			summary.LastError = cloneError(auth.LastError)
		}
		list = append(list, summary)
	}
	m.mu.RUnlock()
	return list
}

// GetByID retrieves an auth entry by its ID.

func (m *Manager) GetByID(id string) (*Auth, bool) {
	if id == "" {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	auth, ok := m.auths[id]
	if !ok {
		return nil, false
	}
	return auth.Clone(), true
}

// Executor returns the registered provider executor for a provider key.
func (m *Manager) Executor(provider string) (ProviderExecutor, bool) {
	if m == nil {
		return nil, false
	}
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return nil, false
	}

	m.mu.RLock()
	executor, okExecutor := m.executors[provider]
	if !okExecutor {
		lowerProvider := strings.ToLower(provider)
		if lowerProvider != provider {
			executor, okExecutor = m.executors[lowerProvider]
		}
	}
	m.mu.RUnlock()

	if !okExecutor || executor == nil {
		return nil, false
	}
	return executor, true
}

// CloseExecutionSession asks all registered executors to release the supplied execution session.
func (m *Manager) CloseExecutionSession(sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if m == nil || sessionID == "" {
		return
	}

	m.mu.RLock()
	executors := make([]ProviderExecutor, 0, len(m.executors))
	for _, exec := range m.executors {
		executors = append(executors, exec)
	}
	m.mu.RUnlock()

	for i := range executors {
		if closer, ok := executors[i].(ExecutionSessionCloser); ok && closer != nil {
			closer.CloseExecutionSession(sessionID)
		}
	}
}

func (m *Manager) useSchedulerFastPath(contexts ...context.Context) bool {
	if m == nil || m.scheduler == nil {
		return false
	}
	return isBuiltInSelector(m.selectorForContext(contexts...))
}

func shouldRetrySchedulerPick(err error) bool {
	if err == nil {
		return false
	}
	var cooldownErr *modelCooldownError
	if errors.As(err, &cooldownErr) {
		return true
	}
	var authErr *Error
	if !errors.As(err, &authErr) || authErr == nil {
		return false
	}
	return authErr.Code == "auth_not_found" || authErr.Code == "auth_unavailable"
}

func (m *Manager) routeAwareSelectionRequired(auth *Auth, routeModel string) bool {
	if auth == nil || strings.TrimSpace(routeModel) == "" {
		return false
	}
	return m.selectionModelKeyForAuth(auth, routeModel) != canonicalModelKey(routeModel)
}

func (m *Manager) routeAwareSelectionRequiredForProviders(providers []string, routeModel string, tried map[string]struct{}) bool {
	if m == nil || strings.TrimSpace(routeModel) == "" {
		return false
	}
	providerSet := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		provider = strings.ToLower(strings.TrimSpace(provider))
		if provider == "" {
			continue
		}
		providerSet[provider] = struct{}{}
		if m.oauthModelAliasMayRewrite(provider, routeModel) {
			return true
		}
	}
	if len(providerSet) == 0 {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for provider := range providerSet {
		for id := range m.providerPrefixedAuthIDs[provider] {
			candidate := m.auths[id]
			if candidate == nil || candidate.Disabled || m.authSelectionBlockedLocked(id) {
				continue
			}
			if _, used := tried[id]; used {
				continue
			}
			if m.routeAwareSelectionRequired(candidate, routeModel) {
				return true
			}
		}
	}
	return false
}

func (m *Manager) pickNextLegacy(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, ProviderExecutor, error) {
	pinnedAuthID := pinnedAuthIDFromMetadata(opts.Metadata)
	registryRef := registry.GetGlobalRegistry()

	m.mu.RLock()
	executor, okExecutor := m.executors[provider]
	if !okExecutor {
		m.mu.RUnlock()
		return nil, nil, &Error{Code: "executor_not_found", Message: "executor not registered"}
	}
	candidates := make([]*Auth, 0, len(m.auths))
	modelKey := strings.TrimSpace(model)
	// Always use base model name (without thinking suffix) for auth matching.
	if modelKey != "" {
		parsed := thinking.ParseSuffix(modelKey)
		if parsed.ModelName != "" {
			modelKey = strings.TrimSpace(parsed.ModelName)
		}
	}
	for _, candidate := range m.auths {
		if candidate.Provider != provider || candidate.Disabled || m.authSelectionBlockedLocked(candidate.ID) {
			continue
		}
		if !credentialSupportsExecutionFormat(candidate, opts.SourceFormat) || !clientKeyPriorityAllowed(ctx, candidate) {
			continue
		}
		if pinnedAuthID != "" && candidate.ID != pinnedAuthID {
			continue
		}
		candidates = append(candidates, candidate.Clone())
	}
	m.mu.RUnlock()
	if modelKey != "" {
		filtered := candidates[:0]
		for _, candidate := range candidates {
			if m.authSupportsRouteModel(registryRef, candidate, model) {
				filtered = append(filtered, candidate)
			}
		}
		candidates = filtered
	}
	candidates = m.weightedEligibleAuths(candidates, ctx)
	if len(candidates) == 0 {
		return nil, nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	requestLimiter := m.authRequestLimiter()
	requestBlocked := authRequestLimitBlock{}
	dynamicallyLimited := make(map[string]struct{})
	strictBoundAuthID := ""
	if sessionSelector, ok := m.selectorForContext(ctx).(*SessionAffinitySelector); ok && sessionSelector != nil && !sessionSelector.failover {
		strictBoundAuthID = sessionSelector.cachedStrictAuthID(ctx, provider, selectionArgForSelector(m.selectorForContext(ctx), model), opts)
		for _, candidate := range candidates {
			if candidate == nil || candidate.ID != strictBoundAuthID {
				continue
			}
			now := requestLimiter.nowTime()
			if blocked, _, _ := isAuthBlockedForModel(candidate, m.selectionModelForAuth(candidate, model), now); blocked {
				break
			}
			policy := m.routingAuthRequestLimitPolicyForAuth(candidate)
			if available, block := requestLimiter.availableAt(candidate.ID, policy, now); !available {
				return nil, nil, newAuthRequestLimitedError(block)
			}
			break
		}
	}
	for {
		now := requestLimiter.nowTime()
		reservation := weightedRequestReservation{manager: m, options: opts, now: now, blocked: &requestBlocked, rejected: dynamicallyLimited}
		pickAllowed := func(auth *Auth) bool {
			if auth == nil {
				return false
			}
			if _, used := tried[auth.ID]; used {
				return false
			}
			if _, limited := dynamicallyLimited[auth.ID]; limited {
				return false
			}
			if strictBoundAuthID != "" && auth.ID != strictBoundAuthID {
				return true
			}
			if strictBoundAuthID != "" {
				if blocked, _, _ := isAuthBlockedForModel(auth, m.selectionModelForAuth(auth, model), now); blocked {
					return true
				}
			}
			policy := m.routingAuthRequestLimitPolicyForAuth(auth)
			available, block := requestLimiter.availableAt(auth.ID, policy, now)
			if !available {
				requestBlocked = earlierAuthRequestLimitBlock(requestBlocked, block)
			}
			return available
		}

		var selected *Auth
		if bound, handled, errPick := m.pickBoundAcrossPriorities(ctx, candidates, provider, model, opts, now, pickAllowed); handled {
			if errPick != nil {
				return nil, nil, preferAuthRequestLimitError(errPick, requestBlocked)
			}
			selected = bound
		} else if picked, handled, _, errPick := m.pickLegacyFillFirstRangeAuthWithDeferredBinding(ctx, provider, model, opts, candidates, pickAllowed); handled {
			if errPick != nil {
				return nil, nil, preferAuthRequestLimitError(errPick, requestBlocked)
			}
			selected = picked
		} else {
			available, errAvailable := m.availableAuthsForRouteModelFilteredForContext(ctx, candidates, provider, model, opts, now, pickAllowed)
			if errAvailable != nil {
				return nil, nil, preferAuthRequestLimitError(errAvailable, requestBlocked)
			}
			var errPick error
			selected, errPick = m.pickAvailableAuthWithPriorityPolicy(ctx, provider, selectionArgForSelector(m.selectorForContext(ctx), model), opts, available, reservation.acquire)
			if isBuiltInSelector(m.selectorForContext(ctx)) {
				errPick = restoreModelCooldownErrorModel(errPick, model)
			}
			if reservation.stalePolicy {
				requestBlocked = authRequestLimitBlock{}
				clear(dynamicallyLimited)
				continue
			}
			if errPick != nil {
				return nil, nil, preferAuthRequestLimitError(errPick, requestBlocked)
			}
			if selected != nil {
				selected = authFromListByID(available, selected.ID)
			}
			if selected == nil {
				return nil, nil, &Error{Code: "auth_not_found", Message: "selector returned unavailable auth"}
			}
		}
		if selected == nil {
			return nil, nil, preferAuthRequestLimitError(&Error{Code: "auth_not_found", Message: "selector returned no auth"}, requestBlocked)
		}
		if !reservation.acquire(selected) {
			if reservation.stalePolicy {
				requestBlocked = authRequestLimitBlock{}
				clear(dynamicallyLimited)
				continue
			}
			continue
		}
		authCopy := selected.Clone()
		if !selected.indexAssigned {
			m.mu.Lock()
			if current := m.auths[authCopy.ID]; current != nil &&
				current.instanceID == selected.instanceID &&
				!current.indexAssigned {
				current.EnsureIndex()
				authCopy = current.Clone()
			}
			m.mu.Unlock()
		}
		return authCopy, executor, nil
	}
}

func (m *Manager) pickNext(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, ProviderExecutor, error) {
	ctx = m.WithRoutingPolicySnapshot(ctx)
	if ctx != nil && ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	allowed := clientKeyPriorityFilter(ctx, nil)
	m.triggerDueChatGPTWebImageQuotaRefreshes([]string{provider}, model, opts, tried, allowed, false)
	if !m.useSchedulerFastPath(ctx) {
		auth, executor, errPick := m.pickNextLegacy(ctx, provider, model, opts, tried)
		if errPick != nil {
			errPick = m.preferChatGPTWebImageQuotaError(errPick, []string{provider}, model, opts, tried, allowed)
		}
		return auth, executor, errPick
	}
	if m.routeAwareSelectionRequiredForProviders([]string{provider}, model, tried) {
		auth, executor, errPick := m.pickNextLegacy(ctx, provider, model, opts, tried)
		if errPick != nil {
			errPick = m.preferChatGPTWebImageQuotaError(errPick, []string{provider}, model, opts, tried, allowed)
		}
		return auth, executor, errPick
	}
	executor, okExecutor := m.Executor(provider)
	if !okExecutor {
		return nil, nil, &Error{Code: "executor_not_found", Message: "executor not registered"}
	}
	selected, errPick := m.scheduler.pickSingle(ctx, provider, model, opts, tried)
	if errPick != nil && model != "" && shouldRetrySchedulerPick(errPick) {
		m.refreshSchedulerRoute([]string{provider}, model)
		selected, errPick = m.scheduler.pickSingle(ctx, provider, model, opts, tried)
	}
	if errPick != nil {
		return nil, nil, m.preferChatGPTWebImageQuotaError(errPick, []string{provider}, model, opts, tried, allowed)
	}
	if selected == nil {
		return nil, nil, &Error{Code: "auth_not_found", Message: "selector returned no auth"}
	}
	authCopy := selected.Clone()
	if !selected.indexAssigned {
		m.mu.Lock()
		if current := m.auths[authCopy.ID]; current != nil && !current.indexAssigned {
			current.EnsureIndex()
			authCopy = current.Clone()
		}
		m.mu.Unlock()
	}
	return authCopy, executor, nil
}

func (m *Manager) pickNextMixedLegacy(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}, pickAllowed func(*Auth) bool) (*Auth, ProviderExecutor, string, error) {
	pinnedAuthID := pinnedAuthIDFromMetadata(opts.Metadata)

	providerSet := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		p := strings.TrimSpace(strings.ToLower(provider))
		if p == "" {
			continue
		}
		providerSet[p] = struct{}{}
	}
	if len(providerSet) == 0 {
		return nil, nil, "", &Error{Code: "provider_not_found", Message: "no provider supplied"}
	}
	registryRef := registry.GetGlobalRegistry()

	m.mu.RLock()
	candidates := make([]*Auth, 0, len(m.auths))
	executors := make(map[string]ProviderExecutor, len(providerSet))
	for providerKey := range providerSet {
		if executor := m.executors[providerKey]; executor != nil {
			executors[providerKey] = executor
		}
	}
	modelKey := strings.TrimSpace(model)
	// Always use base model name (without thinking suffix) for auth matching.
	if modelKey != "" {
		parsed := thinking.ParseSuffix(modelKey)
		if parsed.ModelName != "" {
			modelKey = strings.TrimSpace(parsed.ModelName)
		}
	}
	for _, candidate := range m.auths {
		if candidate == nil || candidate.Disabled || m.authSelectionBlockedLocked(candidate.ID) {
			continue
		}
		if !credentialSupportsExecutionFormat(candidate, opts.SourceFormat) || !clientKeyPriorityAllowed(ctx, candidate) {
			continue
		}
		if pinnedAuthID != "" && candidate.ID != pinnedAuthID {
			continue
		}
		providerKey := strings.TrimSpace(strings.ToLower(candidate.Provider))
		if providerKey == "" {
			continue
		}
		if _, ok := providerSet[providerKey]; !ok {
			continue
		}
		if _, ok := executors[providerKey]; !ok {
			continue
		}
		candidates = append(candidates, candidate.Clone())
	}
	m.mu.RUnlock()
	if modelKey != "" {
		filtered := candidates[:0]
		for _, candidate := range candidates {
			if m.authSupportsRouteModel(registryRef, candidate, model) {
				filtered = append(filtered, candidate)
			}
		}
		candidates = filtered
	}
	candidates = m.weightedEligibleAuths(candidates, ctx)
	if len(candidates) == 0 {
		return nil, nil, "", &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	selectorProvider := "mixed"
	if len(providerSet) == 1 {
		for providerKey := range providerSet {
			selectorProvider = providerKey
		}
	}
	requestLimiter := m.authRequestLimiter()
	requestBlocked := authRequestLimitBlock{}
	dynamicallyLimited := make(map[string]struct{})
	strictBoundAuthID := ""
	if sessionSelector, ok := m.selectorForContext(ctx).(*SessionAffinitySelector); ok && sessionSelector != nil && !sessionSelector.failover {
		strictBoundAuthID = sessionSelector.cachedStrictAuthID(ctx, selectorProvider, selectionArgForSelector(m.selectorForContext(ctx), model), opts)
		for _, candidate := range candidates {
			if candidate == nil || candidate.ID != strictBoundAuthID {
				continue
			}
			now := requestLimiter.nowTime()
			if blocked, _, _ := isAuthBlockedForModel(candidate, m.selectionModelForAuth(candidate, model), now); blocked {
				break
			}
			policy := m.routingAuthRequestLimitPolicyForAuth(candidate)
			if available, block := requestLimiter.availableAt(candidate.ID, policy, now); !available {
				return nil, nil, "", newAuthRequestLimitedError(block)
			}
			break
		}
	}
	for {
		now := requestLimiter.nowTime()
		reservation := weightedRequestReservation{manager: m, options: opts, now: now, blocked: &requestBlocked, rejected: dynamicallyLimited}
		pickAllowedForSelection := func(auth *Auth) bool {
			if auth == nil {
				return false
			}
			if _, used := tried[auth.ID]; used {
				return false
			}
			if _, limited := dynamicallyLimited[auth.ID]; limited {
				return false
			}
			if pickAllowed != nil && !pickAllowed(auth) {
				return false
			}
			if strictBoundAuthID != "" && auth.ID != strictBoundAuthID {
				return true
			}
			if strictBoundAuthID != "" {
				if blocked, _, _ := isAuthBlockedForModel(auth, m.selectionModelForAuth(auth, model), now); blocked {
					return true
				}
			}
			policy := m.routingAuthRequestLimitPolicyForAuth(auth)
			available, block := requestLimiter.availableAt(auth.ID, policy, now)
			if !available {
				requestBlocked = earlierAuthRequestLimitBlock(requestBlocked, block)
			}
			return available
		}

		var selected *Auth
		if bound, handled, errPick := m.pickBoundAcrossPriorities(ctx, candidates, selectorProvider, model, opts, now, pickAllowedForSelection); handled {
			if errPick != nil {
				return nil, nil, "", preferAuthRequestLimitError(errPick, requestBlocked)
			}
			selected = bound
		} else if picked, handled, _, errPick := m.pickLegacyFillFirstRangeAuthWithDeferredBinding(ctx, selectorProvider, model, opts, candidates, pickAllowedForSelection); handled {
			if errPick != nil {
				return nil, nil, "", preferAuthRequestLimitError(errPick, requestBlocked)
			}
			selected = picked
		} else {
			available, errAvailable := m.availableAuthsForRouteModelFilteredForContext(ctx, candidates, selectorProvider, model, opts, now, pickAllowedForSelection)
			if errAvailable != nil {
				return nil, nil, "", preferAuthRequestLimitError(errAvailable, requestBlocked)
			}
			var errPick error
			selected, errPick = m.pickAvailableAuthWithPriorityPolicy(ctx, selectorProvider, selectionArgForSelector(m.selectorForContext(ctx), model), opts, available, reservation.acquire)
			if isBuiltInSelector(m.selectorForContext(ctx)) {
				errPick = restoreModelCooldownErrorModel(errPick, model)
			}
			if reservation.stalePolicy {
				requestBlocked = authRequestLimitBlock{}
				clear(dynamicallyLimited)
				continue
			}
			if errPick != nil {
				return nil, nil, "", preferAuthRequestLimitError(errPick, requestBlocked)
			}
			if selected != nil {
				selected = authFromListByID(available, selected.ID)
			}
			if selected == nil {
				return nil, nil, "", &Error{Code: "auth_not_found", Message: "selector returned unavailable auth"}
			}
		}
		if selected == nil {
			return nil, nil, "", preferAuthRequestLimitError(&Error{Code: "auth_not_found", Message: "selector returned no auth"}, requestBlocked)
		}
		if !reservation.acquire(selected) {
			if reservation.stalePolicy {
				requestBlocked = authRequestLimitBlock{}
				clear(dynamicallyLimited)
				continue
			}
			continue
		}
		providerKey := strings.TrimSpace(strings.ToLower(selected.Provider))
		executor, okExecutor := executors[providerKey]
		if !okExecutor {
			return nil, nil, "", &Error{Code: "executor_not_found", Message: "executor not registered"}
		}
		authCopy := selected.Clone()
		if !selected.indexAssigned {
			m.mu.Lock()
			if current := m.auths[authCopy.ID]; current != nil &&
				current.instanceID == selected.instanceID &&
				!current.indexAssigned {
				current.EnsureIndex()
				authCopy = current.Clone()
			}
			m.mu.Unlock()
		}
		return authCopy, executor, providerKey, nil
	}
}

func (m *Manager) pickNextMixed(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}, pickAllowed ...func(*Auth) bool) (*Auth, ProviderExecutor, string, error) {
	ctx = m.WithRoutingPolicySnapshot(ctx)
	if ctx != nil && ctx.Err() != nil {
		return nil, nil, "", ctx.Err()
	}
	var allowed func(*Auth) bool
	if len(pickAllowed) > 0 {
		allowed = pickAllowed[0]
	}
	allowed = clientKeyPriorityFilter(ctx, allowed)
	m.triggerDueChatGPTWebImageQuotaRefreshes(providers, model, opts, tried, allowed, false)
	if !m.useSchedulerFastPath(ctx) {
		auth, executor, provider, errPick := m.pickNextMixedLegacy(ctx, providers, model, opts, tried, allowed)
		if errPick != nil {
			errPick = m.preferChatGPTWebImageQuotaError(errPick, providers, model, opts, tried, allowed)
		}
		return auth, executor, provider, errPick
	}

	eligibleProviders := make([]string, 0, len(providers))
	seenProviders := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		providerKey := strings.TrimSpace(strings.ToLower(provider))
		if providerKey == "" {
			continue
		}
		if _, seen := seenProviders[providerKey]; seen {
			continue
		}
		if _, okExecutor := m.Executor(providerKey); !okExecutor {
			continue
		}
		seenProviders[providerKey] = struct{}{}
		eligibleProviders = append(eligibleProviders, providerKey)
	}
	if len(eligibleProviders) == 0 {
		return nil, nil, "", &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	if m.routeAwareSelectionRequiredForProviders(eligibleProviders, model, tried) {
		auth, executor, selectedProvider, errPick := m.pickNextMixedLegacy(ctx, providers, model, opts, tried, allowed)
		if errPick != nil {
			errPick = m.preferChatGPTWebImageQuotaError(errPick, eligibleProviders, model, opts, tried, allowed)
		}
		return auth, executor, selectedProvider, errPick
	}

	selected, providerKey, errPick := m.scheduler.pickMixed(ctx, eligibleProviders, model, opts, tried, allowed)
	if errPick != nil && model != "" && shouldRetrySchedulerPick(errPick) {
		m.refreshSchedulerRoute(eligibleProviders, model)
		selected, providerKey, errPick = m.scheduler.pickMixed(ctx, eligibleProviders, model, opts, tried, allowed)
	}
	if errPick != nil {
		return nil, nil, "", m.preferChatGPTWebImageQuotaError(errPick, eligibleProviders, model, opts, tried, allowed)
	}
	if selected == nil {
		return nil, nil, "", &Error{Code: "auth_not_found", Message: "selector returned no auth"}
	}
	executor, okExecutor := m.Executor(providerKey)
	if !okExecutor {
		return nil, nil, "", &Error{Code: "executor_not_found", Message: "executor not registered"}
	}
	authCopy := selected.Clone()
	if !selected.indexAssigned {
		m.mu.Lock()
		if current := m.auths[authCopy.ID]; current != nil && !current.indexAssigned {
			current.EnsureIndex()
			authCopy = current.Clone()
		}
		m.mu.Unlock()
	}
	return authCopy, executor, providerKey, nil
}

func (m *Manager) pickNextMixedWithImageToolFallback(ctx context.Context, providers []string, model string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, tried map[string]struct{}, pickAllowed func(*Auth) bool) (*Auth, ProviderExecutor, string, error) {
	cfg := m.currentConfig()
	if !requestHasImageGenerationToolForFallback(req, opts) {
		return m.pickNextMixed(ctx, providers, model, opts, tried, pickAllowed)
	}
	m.triggerDueChatGPTWebImageQuotaRefreshes(providers, model, opts, tried, pickAllowed, true)
	now := time.Now()
	quotaAllowed := func(auth *Auth) bool {
		if pickAllowed != nil && !pickAllowed(auth) {
			return false
		}
		blocked, _ := chatGPTWebImageCapabilityUnavailable(auth, now)
		return !blocked
	}
	if !disabledImageGenerationToolFallbackEnabled(cfg) {
		auth, executor, provider, errPick := m.pickNextMixed(ctx, providers, model, opts, tried, quotaAllowed)
		if errPick != nil {
			errPick = m.preferChatGPTWebImageToolQuotaError(errPick, providers, model, opts, tried, pickAllowed)
		}
		return auth, executor, provider, errPick
	}
	explicitImageTool := requestExplicitlySelectsImageGenerationTool(req, opts)
	imageCapableAllowed := func(auth *Auth) bool {
		if !quotaAllowed(auth) {
			return false
		}
		if strings.EqualFold(strings.TrimSpace(auth.Provider), "chatgpt-web") {
			return chatGPTWebImageModelProjection(auth, m.selectionModelKeyForAuth(auth, model)) || explicitImageTool
		}
		if !isCodexProvider(auth, auth.Provider) {
			return false
		}
		return !AuthDisablesImageGeneration(cfg, auth, auth.Provider)
	}
	auth, executor, provider, errPick := m.pickNextMixed(ctx, providers, model, opts, tried, imageCapableAllowed)
	if errPick == nil {
		return auth, executor, provider, nil
	}
	if !shouldFallbackToDisabledImageGenerationToolAction(errPick) {
		return nil, nil, "", m.preferChatGPTWebImageToolQuotaError(errPick, providers, model, opts, tried, pickAllowed)
	}
	auth, executor, provider, errPick = m.pickNextMixed(ctx, providers, model, opts, tried, quotaAllowed)
	if errPick != nil {
		errPick = m.preferChatGPTWebImageToolQuotaError(errPick, providers, model, opts, tried, pickAllowed)
	}
	return auth, executor, provider, errPick
}

func disabledImageGenerationToolFallbackEnabled(cfg *internalconfig.Config) bool {
	return cfg != nil && cfg.DisabledImageGenerationToolFallback
}

func requestHasImageGenerationToolForFallback(req cliproxyexecutor.Request, opts cliproxyexecutor.Options) bool {
	if opts.SourceFormat == sdktranslator.FormatCodexAlphaSearch {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(opts.SourceFormat.String()), "openai-image") {
		return false
	}
	if executionModelOverrideFromMetadata(opts.Metadata) != "" {
		return false
	}
	payload := req.Payload
	if len(payload) == 0 {
		payload = opts.OriginalRequest
	}
	return PayloadMaySelectImageGenerationTool(payload)
}

func requestExplicitlySelectsImageGenerationTool(req cliproxyexecutor.Request, opts cliproxyexecutor.Options) bool {
	payload := req.Payload
	if len(payload) == 0 {
		payload = opts.OriginalRequest
	}
	return PayloadExplicitlySelectsImageGenerationTool(payload)
}

func shouldFallbackToDisabledImageGenerationToolAction(err error) bool {
	if err == nil || isModelCooldownError(err) {
		return false
	}
	var authErr *Error
	if !errors.As(err, &authErr) || authErr == nil {
		return false
	}
	return authErr.Code == "auth_unavailable" || authErr.Code == "auth_not_found"
}

func (m *Manager) persist(ctx context.Context, auth *Auth) error {
	if m == nil || auth == nil {
		return nil
	}
	unlockPersist, errLock := m.lockAuthIDMutationContext(ctx, auth.ID)
	if errLock != nil {
		return errLock
	}
	defer unlockPersist()
	return m.persistWithoutLock(ctx, auth, true)
}

func (m *Manager) shouldPersistAuth(ctx context.Context, auth *Auth) bool {
	if m == nil || m.store == nil || auth == nil {
		return false
	}
	if shouldSkipPersist(ctx) {
		return false
	}
	if authIsRuntimeOnly(auth) {
		return false
	}
	if auth.Metadata == nil {
		return false
	}
	return true
}

func authIsRuntimeOnly(auth *Auth) bool {
	if auth == nil || auth.Attributes == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(auth.Attributes["runtime_only"]), "true")
}

func (m *Manager) persistWithoutLock(ctx context.Context, auth *Auth, syncCurrentHash bool) error {
	if errRules := prepareAuthRequestScopedErrors(auth); errRules != nil {
		return errRules
	}
	if errWeight := ValidateAuthWeight(auth); errWeight != nil {
		return errWeight
	}
	if !m.shouldPersistAuth(ctx, auth) {
		return nil
	}
	_, err := m.store.Save(authfileguard.WithManagerOwnedPersistence(ctx), auth)
	if err != nil {
		outcome, explicit := SaveOutcomeFromError(err)
		if explicit && outcome == SaveOutcomeCommitted {
			log.WithField("auth_id", auth.ID).Warn("auth save committed with cleanup warning")
		} else {
			if !explicit || outcome == SaveOutcomeUncertain || persistedAuthIndexConflict(err) {
				m.MarkChatGPTWebDependencyIndexDirty()
			}
			return err
		}
	}
	if syncCurrentHash {
		m.syncRuntimeSourceHash(auth)
	}
	m.recordPersistedAuthSave(auth)
	return nil
}

func (m *Manager) persistNewWithoutLock(ctx context.Context, auth *Auth) error {
	if errRules := prepareAuthRequestScopedErrors(auth); errRules != nil {
		return errRules
	}
	if errWeight := ValidateAuthWeight(auth); errWeight != nil {
		return errWeight
	}
	if !m.shouldPersistAuth(ctx, auth) {
		return nil
	}
	store, ok := m.store.(ConditionalCreateStore)
	if !ok {
		return errors.New("auth store does not support conditional create")
	}
	_, err := store.SaveIfAbsent(authfileguard.WithManagerOwnedPersistence(ctx), auth)
	if err == nil {
		m.recordPersistedAuthSave(auth)
		return nil
	}
	if outcome, explicit := SaveOutcomeFromError(err); explicit {
		if outcome == SaveOutcomeCommitted {
			log.WithField("auth_id", auth.ID).Warn("auth create committed with cleanup warning")
			m.recordPersistedAuthSave(auth)
			return nil
		}
		if outcome == SaveOutcomeUncertain || persistedAuthIndexConflict(err) {
			m.MarkChatGPTWebDependencyIndexDirty()
		}
		return err
	}
	if errors.Is(err, ErrAuthAlreadyExists) {
		m.MarkChatGPTWebDependencyIndexDirty()
		return NewSaveOutcomeError(SaveOutcomeRolledBack, err)
	}
	m.MarkChatGPTWebDependencyIndexDirty()
	return NewSaveOutcomeError(SaveOutcomeUncertain, err)
}

func (m *Manager) snapshotCurrentAuthForPersistence(ctx context.Context, current *Auth) (*Auth, error) {
	if m == nil || current == nil {
		return nil, nil
	}
	id := strings.TrimSpace(current.ID)
	if id == "" {
		return nil, nil
	}
	unlockPersist, errLock := m.lockAuthIDMutationContext(ctx, id)
	if errLock != nil {
		return nil, errLock
	}
	defer unlockPersist()

	return m.snapshotCurrentAuthForPersistenceLocked(ctx, current)
}

func (m *Manager) snapshotCurrentAuthForPersistenceLocked(ctx context.Context, current *Auth) (*Auth, error) {
	if m == nil || current == nil {
		return nil, nil
	}
	id := strings.TrimSpace(current.ID)
	if id == "" {
		return nil, nil
	}
	m.mu.RLock()
	latest, ok := m.auths[id]
	if !ok || latest == nil {
		m.mu.RUnlock()
		return nil, nil
	}
	snapshot := latest.Clone()
	m.mu.RUnlock()

	persistCtx := ctx
	if expectedSourceHash := authSourceHash(snapshot); expectedSourceHash != "" && m.SupportsSourceConditionalSave() {
		persistCtx = WithSourceHashSavePrecondition(persistCtx, expectedSourceHash)
	}
	if err := m.persistWithoutLock(persistCtx, snapshot, true); err != nil {
		return nil, err
	}
	return snapshot, nil
}

type authPersistLock struct {
	semaphore chan struct{}
}

type authMutationLockContextKey struct{}

type authMutationLockToken struct {
	manager *Manager
	id      string
	email   string
	parent  *authMutationLockToken
	active  atomic.Bool
	nested  chan struct{}
	once    sync.Once
	release func()
}

func authMutationTokenForManager(ctx context.Context, manager *Manager) *authMutationLockToken {
	if ctx == nil || manager == nil {
		return nil
	}
	token, _ := ctx.Value(authMutationLockContextKey{}).(*authMutationLockToken)
	for token != nil {
		if token.manager == manager && token.active.Load() {
			return token
		}
		token = token.parent
	}
	return nil
}

func (token *authMutationLockToken) lockNested(ctx context.Context) (func(), bool, error) {
	if token == nil || token.nested == nil {
		return nil, false, nil
	}
	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	case <-token.nested:
	}
	if errContext := ctx.Err(); errContext != nil {
		token.nested <- struct{}{}
		return nil, false, errContext
	}
	if !token.active.Load() {
		token.nested <- struct{}{}
		return nil, false, nil
	}
	var once sync.Once
	return func() {
		once.Do(func() { token.nested <- struct{}{} })
	}, true, nil
}

func (token *authMutationLockToken) unlock() {
	if token == nil {
		return
	}
	token.once.Do(func() {
		if token.nested != nil {
			<-token.nested
		}
		token.active.Store(false)
		if token.release != nil {
			token.release()
		}
		if token.nested != nil {
			token.nested <- struct{}{}
		}
	})
}

func newAuthPersistLock() *authPersistLock {
	lock := &authPersistLock{semaphore: make(chan struct{}, 1)}
	lock.semaphore <- struct{}{}
	return lock
}

// LockAuthMutation serializes an auth update by ChatGPT Web email and auth ID.
// The returned context lets Register and Update reuse the dependency and auth
// lock ownership in their canonical order.
func (m *Manager) LockAuthMutation(ctx context.Context, auth *Auth) (context.Context, func(), error) {
	if m == nil {
		return ctx, func() {}, nil
	}
	authID := ""
	if auth != nil {
		authID = strings.TrimSpace(auth.ID)
	}
	lockedDependencyCtx, unlockDependency, errDependency := m.lockChatGPTWebDependencyMutationContext(ctx, authID, auth, false)
	if errDependency != nil {
		return ctx, nil, errDependency
	}
	lockedCtx, unlockAuth, errLock := m.lockAuthMutationContext(lockedDependencyCtx, auth)
	if errLock != nil {
		unlockDependency()
		return ctx, nil, errLock
	}
	return lockedCtx, func() {
		unlockAuth()
		unlockDependency()
	}, nil
}

func (m *Manager) lockAuthMutationContext(ctx context.Context, auth *Auth) (context.Context, func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	m.canonicalizeNewChatGPTWebAuth(ctx, auth)
	id := ""
	email := ""
	if auth != nil {
		auth.ID = strings.TrimSpace(auth.ID)
		if auth.ID == "" {
			auth.ID = uuid.NewString()
		}
		id = auth.ID
		email = chatGPTWebRegistrationEmail(auth)
	}
	parentToken, _ := ctx.Value(authMutationLockContextKey{}).(*authMutationLockToken)
	if token := authMutationTokenForManager(ctx, m); token != nil {
		unlockNested, reused, errNested := token.lockNested(ctx)
		if errNested != nil {
			return ctx, nil, errNested
		}
		if reused {
			if token.id != id || token.email != email {
				unlockNested()
				return ctx, nil, ErrAuthMutationIdentityChanged
			}
			return ctx, unlockNested, nil
		}
	}
	keys := []string{id}
	if email != "" {
		keys = append(keys, "\x00chatgpt-web-email:"+email)
	}
	if auth != nil && strings.EqualFold(strings.TrimSpace(auth.Provider), "chatgpt-web") {
		for _, identityKey := range chatGPTWebIdentityIndexKeys(auth) {
			keys = append(keys, "\x00chatgpt-web-identity:"+identityKey)
		}
	}
	unlockPersist, errPersist := m.lockPersistKeysContext(ctx, keys...)
	if errPersist != nil {
		return ctx, nil, errPersist
	}
	token := &authMutationLockToken{
		manager: m,
		id:      id,
		email:   email,
		parent:  parentToken,
		nested:  make(chan struct{}, 1),
		release: unlockPersist,
	}
	token.nested <- struct{}{}
	token.active.Store(true)
	return context.WithValue(ctx, authMutationLockContextKey{}, token), token.unlock, nil
}

func (m *Manager) lockAuthIDMutationContext(ctx context.Context, id string) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	id = strings.TrimSpace(id)
	if token := authMutationTokenForManager(ctx, m); token != nil {
		unlockNested, reused, errNested := token.lockNested(ctx)
		if errNested != nil {
			return nil, errNested
		}
		if reused {
			if token.id != id {
				unlockNested()
				return nil, ErrAuthMutationIdentityChanged
			}
			return unlockNested, nil
		}
	}
	return m.lockPersistKeyContext(ctx, id)
}

func (m *Manager) lockPersistKeyContext(ctx context.Context, id string) (func(), error) {
	return m.lockPersistKeysContext(ctx, id)
}

func (m *Manager) lockPersistKeysContext(ctx context.Context, ids ...string) (func(), error) {
	if m == nil {
		return func() {}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	unique := make(map[string]struct{}, len(ids))
	keys := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, exists := unique[id]; exists {
			continue
		}
		unique[id] = struct{}{}
		keys = append(keys, id)
	}
	sort.Strings(keys)
	if err := m.lockPersistBarrierRead(ctx); err != nil {
		return nil, err
	}
	locks := make([]*authPersistLock, 0, len(keys))
	for _, key := range keys {
		raw, _ := m.persistLocks.LoadOrStore(key, newAuthPersistLock())
		lock, ok := raw.(*authPersistLock)
		if !ok || lock == nil || lock.semaphore == nil {
			m.persistBarrier.RUnlock()
			return nil, errors.New("invalid auth persistence lock")
		}
		locks = append(locks, lock)
	}
	acquired := 0
	for _, lock := range locks {
		select {
		case <-ctx.Done():
			for index := acquired - 1; index >= 0; index-- {
				locks[index].semaphore <- struct{}{}
			}
			m.persistBarrier.RUnlock()
			return nil, ctx.Err()
		case <-lock.semaphore:
			acquired++
		}
	}
	if err := ctx.Err(); err != nil {
		for index := len(locks) - 1; index >= 0; index-- {
			locks[index].semaphore <- struct{}{}
		}
		m.persistBarrier.RUnlock()
		return nil, err
	}
	if !m.refreshPersistenceCoordinatorMatchesContext(ctx) {
		for index := len(locks) - 1; index >= 0; index-- {
			locks[index].semaphore <- struct{}{}
		}
		m.persistBarrier.RUnlock()
		return nil, errRefreshPersistenceStoreChanged
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for index := len(locks) - 1; index >= 0; index-- {
				locks[index].semaphore <- struct{}{}
			}
			m.persistBarrier.RUnlock()
		})
	}, nil
}

func (m *Manager) lockPersistBarrierRead(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if m.persistBarrierReadObserved != nil {
		m.persistBarrierReadObserved()
	}
	unlockTurnstile, errTurnstile := m.lockPersistBarrierTurnstile(ctx)
	if errTurnstile != nil {
		return errTurnstile
	}
	defer unlockTurnstile()
	if errContext := ctx.Err(); errContext != nil {
		return errContext
	}
	if ctx.Done() == nil {
		m.persistBarrier.RLock()
		return nil
	}
	for {
		if m.persistBarrier.TryRLock() {
			if errContext := ctx.Err(); errContext != nil {
				m.persistBarrier.RUnlock()
				return errContext
			}
			return nil
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (m *Manager) lockPersistBarrierWrite(ctx context.Context) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	unlockTurnstile, errTurnstile := m.lockPersistBarrierTurnstile(ctx)
	if errTurnstile != nil {
		return nil, errTurnstile
	}
	if ctx.Done() == nil {
		m.persistBarrier.Lock()
		return m.persistBarrierWriteUnlock(unlockTurnstile), nil
	}
	for {
		if m.persistBarrier.TryLock() {
			if errContext := ctx.Err(); errContext != nil {
				m.persistBarrier.Unlock()
				unlockTurnstile()
				return nil, errContext
			}
			return m.persistBarrierWriteUnlock(unlockTurnstile), nil
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			unlockTurnstile()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (m *Manager) lockPersistBarrierTurnstile(ctx context.Context) (func(), error) {
	if m == nil {
		return func() {}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.persistBarrierTurnstileOnce.Do(func() {
		m.persistBarrierTurnstile = make(chan struct{}, 1)
		m.persistBarrierTurnstile <- struct{}{}
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.persistBarrierTurnstile:
	}
	if errContext := ctx.Err(); errContext != nil {
		m.persistBarrierTurnstile <- struct{}{}
		return nil, errContext
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			m.persistBarrierTurnstile <- struct{}{}
		})
	}, nil
}

func (m *Manager) persistBarrierWriteUnlock(unlockTurnstile func()) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			m.persistBarrier.Unlock()
			if unlockTurnstile != nil {
				unlockTurnstile()
			}
		})
	}
}

func (m *Manager) syncRuntimeSourceHash(auth *Auth) {
	if m == nil || auth == nil {
		return
	}
	hash := authSourceHash(auth)
	if hash == "" {
		return
	}
	id := strings.TrimSpace(auth.ID)
	if id == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.auths[id]
	if !ok || current == nil {
		return
	}
	if current.Attributes == nil {
		current.Attributes = make(map[string]string)
	}
	current.Attributes[SourceHashAttributeKey] = hash
}

// StartAutoRefresh launches a background loop that evaluates auth freshness
// every few seconds and triggers refresh operations when required.
// Only one loop is kept alive; starting a new one cancels the previous run.
func (m *Manager) StartAutoRefresh(parent context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = refreshCheckInterval
	}

	m.mu.Lock()
	cancelPrev := m.refreshCancel
	loopPrev := m.refreshLoop
	m.refreshCancel = nil
	m.refreshLoop = nil
	m.mu.Unlock()
	if cancelPrev != nil {
		cancelPrev()
	}
	if loopPrev != nil && !loopPrev.wait(refreshShutdownTimeout) {
		log.Warn("auth refresh loop did not stop before replacement")
	}

	ctx, cancelCtx := context.WithCancel(parent)
	workers := refreshMaxConcurrency
	if cfg, ok := m.runtimeConfig.Load().(*internalconfig.Config); ok && cfg != nil && cfg.AuthAutoRefreshWorkers > 0 {
		workers = cfg.AuthAutoRefreshWorkers
	}
	loop := newAuthAutoRefreshLoop(m, interval, workers)

	m.mu.Lock()
	m.refreshCancel = cancelCtx
	m.refreshLoop = loop
	m.mu.Unlock()

	loop.rebuild(time.Now())
	go loop.run(ctx)
}

// StopAutoRefresh cancels the background refresh loop, if running.
// It also stops the selector if it implements StoppableSelector.
func (m *Manager) StopAutoRefresh() {
	m.mu.Lock()
	cancel := m.refreshCancel
	loop := m.refreshLoop
	m.refreshCancel = nil
	m.refreshLoop = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if loop != nil && !loop.wait(refreshShutdownTimeout) {
		log.Warn("auth refresh loop did not stop before shutdown")
	}
	// Stop selector if it implements StoppableSelector (e.g., SessionAffinitySelector)
	if stoppable, ok := m.selectorForContext().(StoppableSelector); ok {
		stoppable.Stop()
	}
}

// CloseExecutorsContext stops background work owned by registered executors.
// Callers may stop waiting without abandoning the single manager-owned close task.
func (m *Manager) CloseExecutorsContext(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	done := m.beginCloseExecutors()

	select {
	case <-done:
		m.executorLifecycleMu.Lock()
		closeErr := m.executorsCloseErr
		m.executorLifecycleMu.Unlock()
		return closeErr
	case <-ctx.Done():
		select {
		case <-done:
			m.executorLifecycleMu.Lock()
			closeErr := m.executorsCloseErr
			m.executorLifecycleMu.Unlock()
			return closeErr
		default:
			return ctx.Err()
		}
	}
}

// BeginCloseExecutors starts the manager-owned executor close task without waiting.
func (m *Manager) BeginCloseExecutors() {
	if m != nil {
		m.beginCloseExecutors()
	}
}

func (m *Manager) beginCloseExecutors() <-chan struct{} {
	m.executorLifecycleMu.Lock()
	if !m.executorsClosed {
		m.executorsClosed = true
		m.stopAcceptingResultPersistenceProducers()
		m.executorsCloseDone = make(chan struct{})
		m.mu.RLock()
		executors := make([]ProviderExecutor, 0, len(m.executors))
		for _, executor := range m.executors {
			executors = append(executors, executor)
			if !m.executorTrackedForShutdownLocked(executor) {
				m.executorShutdownSet = append(m.executorShutdownSet, executor)
			}
		}
		m.mu.RUnlock()
		go m.closeExecutors(executors, m.executorsCloseDone)
	}
	done := m.executorsCloseDone
	m.executorLifecycleMu.Unlock()
	return done
}

func (m *Manager) closeExecutors(executors []ProviderExecutor, done chan struct{}) {
	_ = m.LibraryCleanup().Shutdown(context.Background())
	if m.refreshFlightWaitObserved != nil {
		m.refreshFlightWaitObserved()
	}
	m.refreshFlightWG.Wait()
	var closeErr error
	for _, executor := range executors {
		if errClose := closeProviderExecutor(executor); errClose != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close executor %s: %w", executor.Identifier(), errClose))
		}
	}
	m.executorLifecycleMu.Lock()
	if !m.executorCloseSealed {
		m.executorCloseSealed = true
		m.executorCloseWG.Done()
	}
	m.executorLifecycleMu.Unlock()
	m.executorCloseWG.Wait()
	m.waitForResultPersistenceProducers()
	if m.resultPersistence != nil {
		m.resultPersistence.close()
	}
	m.refreshPersistence.Load().close()
	m.closeRoundTripperProvider()
	m.executorLifecycleMu.Lock()
	for m.executorSealedClose > 0 {
		m.executorCloseCond.Wait()
	}
	m.executorCloseFinal = true
	m.executorsCloseErr = errors.Join(closeErr, m.executorAsyncErr)
	close(done)
	m.executorLifecycleMu.Unlock()
}

// CloseExecutors stops background work owned by registered executors.
func (m *Manager) CloseExecutors() error {
	return m.CloseExecutorsContext(context.Background())
}

func (m *Manager) queueRefreshReschedule(authID string) {
	if m == nil || authID == "" {
		return
	}
	m.mu.RLock()
	loop := m.refreshLoop
	m.mu.RUnlock()
	if loop == nil {
		return
	}
	loop.queueReschedule(authID)
}

func (m *Manager) shouldRefresh(a *Auth, now time.Time) bool {
	if a == nil || a.Disabled || !a.LifecycleRefreshable() {
		return false
	}
	if !a.NextRefreshAfter.IsZero() && now.Before(a.NextRefreshAfter) {
		return false
	}
	if evaluator, ok := a.Runtime.(RefreshEvaluator); ok && evaluator != nil {
		return evaluator.ShouldRefresh(now, a)
	}

	lastRefresh := a.LastRefreshedAt
	if lastRefresh.IsZero() {
		if ts, ok := authLastRefreshTimestamp(a); ok {
			lastRefresh = ts
		}
	}

	expiry, hasExpiry := a.ExpirationTime()

	if interval := authPreferredInterval(a); interval > 0 {
		if hasExpiry && !expiry.IsZero() {
			if !expiry.After(now) {
				return true
			}
			if expiry.Sub(now) <= interval {
				return true
			}
		}
		if lastRefresh.IsZero() {
			return true
		}
		return now.Sub(lastRefresh) >= interval
	}

	provider := strings.ToLower(a.Provider)
	lead := ProviderRefreshLead(provider, a.Runtime)
	if lead == nil {
		return false
	}
	if *lead <= 0 {
		if hasExpiry && !expiry.IsZero() {
			return now.After(expiry)
		}
		return false
	}
	if hasExpiry && !expiry.IsZero() {
		return time.Until(expiry) <= *lead
	}
	if !lastRefresh.IsZero() {
		return now.Sub(lastRefresh) >= *lead
	}
	return true
}

func authPreferredInterval(a *Auth) time.Duration {
	if a == nil {
		return 0
	}
	if d := durationFromMetadata(a.Metadata, "refresh_interval_seconds", "refreshIntervalSeconds", "refresh_interval", "refreshInterval"); d > 0 {
		return d
	}
	if d := durationFromAttributes(a.Attributes, "refresh_interval_seconds", "refreshIntervalSeconds", "refresh_interval", "refreshInterval"); d > 0 {
		return d
	}
	return 0
}

func durationFromMetadata(meta map[string]any, keys ...string) time.Duration {
	if len(meta) == 0 {
		return 0
	}
	for _, key := range keys {
		if val, ok := meta[key]; ok {
			if dur := parseDurationValue(val); dur > 0 {
				return dur
			}
		}
	}
	return 0
}

func durationFromAttributes(attrs map[string]string, keys ...string) time.Duration {
	if len(attrs) == 0 {
		return 0
	}
	for _, key := range keys {
		if val, ok := attrs[key]; ok {
			if dur := parseDurationString(val); dur > 0 {
				return dur
			}
		}
	}
	return 0
}

func parseDurationValue(val any) time.Duration {
	switch v := val.(type) {
	case time.Duration:
		if v <= 0 {
			return 0
		}
		return v
	case int:
		if v <= 0 {
			return 0
		}
		return time.Duration(v) * time.Second
	case int32:
		if v <= 0 {
			return 0
		}
		return time.Duration(v) * time.Second
	case int64:
		if v <= 0 {
			return 0
		}
		return time.Duration(v) * time.Second
	case uint:
		if v == 0 {
			return 0
		}
		return time.Duration(v) * time.Second
	case uint32:
		if v == 0 {
			return 0
		}
		return time.Duration(v) * time.Second
	case uint64:
		if v == 0 {
			return 0
		}
		return time.Duration(v) * time.Second
	case float32:
		if v <= 0 {
			return 0
		}
		return time.Duration(float64(v) * float64(time.Second))
	case float64:
		if v <= 0 {
			return 0
		}
		return time.Duration(v * float64(time.Second))
	case json.Number:
		if i, err := v.Int64(); err == nil {
			if i <= 0 {
				return 0
			}
			return time.Duration(i) * time.Second
		}
		if f, err := v.Float64(); err == nil && f > 0 {
			return time.Duration(f * float64(time.Second))
		}
	case string:
		return parseDurationString(v)
	}
	return 0
}

func parseDurationString(raw string) time.Duration {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0
	}
	if dur, err := time.ParseDuration(s); err == nil && dur > 0 {
		return dur
	}
	if secs, err := strconv.ParseFloat(s, 64); err == nil && secs > 0 {
		return time.Duration(secs * float64(time.Second))
	}
	return 0
}

func authLastRefreshTimestamp(a *Auth) (time.Time, bool) {
	if a == nil {
		return time.Time{}, false
	}
	if a.Metadata != nil {
		if ts, ok := lookupMetadataTime(a.Metadata, "last_refresh", "lastRefresh", "last_refreshed_at", "lastRefreshedAt"); ok {
			return ts, true
		}
	}
	if a.Attributes != nil {
		for _, key := range []string{"last_refresh", "lastRefresh", "last_refreshed_at", "lastRefreshedAt"} {
			if val := strings.TrimSpace(a.Attributes[key]); val != "" {
				if ts, ok := parseTimeValue(val); ok {
					return ts, true
				}
			}
		}
	}
	return time.Time{}, false
}

func lookupMetadataTime(meta map[string]any, keys ...string) (time.Time, bool) {
	for _, key := range keys {
		if val, ok := meta[key]; ok {
			if ts, ok1 := parseTimeValue(val); ok1 {
				return ts, true
			}
		}
	}
	return time.Time{}, false
}

func (m *Manager) markRefreshPending(id string, now time.Time) (authRefreshJob, bool) {
	m.mu.Lock()
	auth, ok := m.auths[id]
	if !ok || auth == nil || auth.Disabled || m.authSelectionBlockedLocked(id) {
		m.mu.Unlock()
		return authRefreshJob{}, false
	}
	if !auth.NextRefreshAfter.IsZero() && now.Before(auth.NextRefreshAfter) {
		m.mu.Unlock()
		return authRefreshJob{}, false
	}
	pendingUntil := now.Add(refreshPendingBackoff)
	auth.NextRefreshAfter = pendingUntil
	m.installAuthLocked(id, auth)
	job := authRefreshJob{authID: id, expected: auth, pendingUntil: pendingUntil}
	m.mu.Unlock()

	m.queueRefreshReschedule(id)
	return job, true
}

func (m *Manager) refreshAuth(ctx context.Context, id string) {
	m.refreshAuthExpected(ctx, id, nil, time.Time{})
}

const authRequestRefreshResultLimit = 32

type authRequestRefreshResult struct {
	provider                string
	sourceInstallationID    string
	sourceRuntimeInstanceID string
	resultInstallationID    string
	resultRuntimeInstanceID string
}

type authRequestRefreshLock struct {
	semaphore chan struct{}
	active    int

	mu          sync.Mutex
	results     map[string]authRequestRefreshResult
	resultOrder []string
	failures    map[string]error
	waiters     map[string]int
}

type authRequestRefreshLocksContextKey struct{}

type authRequestRefreshLocksContext struct {
	manager *Manager
	locks   map[string]*authRequestRefreshLock
}

func authRequestRefreshLockIDs(auth *Auth, fallbackID string) []string {
	unique := make(map[string]struct{}, 2)
	if id := strings.TrimSpace(fallbackID); id != "" {
		unique[id] = struct{}{}
	}
	if auth != nil {
		if id := strings.TrimSpace(auth.ID); id != "" {
			unique[id] = struct{}{}
		}
		if strings.EqualFold(strings.TrimSpace(auth.Provider), "chatgpt-web") &&
			strings.EqualFold(chatGPTWebIdentityMetadataString(auth.Metadata, "refresh_strategy"), "codex_source") {
			if sourceID := chatGPTWebIdentityMetadataString(auth.Metadata, "source_auth_id"); sourceID != "" {
				unique[sourceID] = struct{}{}
			}
		}
	}
	ordered := make([]string, 0, len(unique))
	for id := range unique {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	return ordered
}

func sameAuthRequestRefreshLockIDs(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// tryRefreshAfterUnauthorized applies the provider-specific recovery policy
// after an unauthorized response.
func (m *Manager) tryRefreshAfterUnauthorized(ctx context.Context, executor ProviderExecutor, auth *Auth, execErr error, alreadyTried bool) (*Auth, bool, error) {
	if _, handled := requestScopedActionFromError(execErr); handled {
		return auth, false, nil
	}
	if m == nil || auth == nil || alreadyTried || execErr == nil || isKnownRequestFault(execErr) {
		return auth, false, nil
	}
	if recoverer, ok := executor.(UnauthorizedAuthRecoverer); ok && recoverer.ShouldRecoverUnauthorized(auth, execErr) {
		recovered, errRecover := m.recoverUnauthorizedAuth(ctx, executor, recoverer, auth, execErr)
		if errRecover != nil {
			return auth, true, errRecover
		}
		resolved, errProxy := m.ResolveProxyAuth(ctx, recovered)
		if errProxy != nil {
			return auth, true, errProxy
		}
		return resolved, true, nil
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	if provider == "chatgpt-web" {
		if !isChatGPTWebAuthenticationRecoveryError(execErr) {
			return auth, false, nil
		}
		wrapped := m.wrapChatGPTWebUnauthorizedRequestError(ctx, auth, execErr)
		return auth, isNativeChatGPTWebCredentialAuth(auth) && auth.LifecycleRefreshable(), wrapped
	}
	if !isUnauthorizedError(execErr) {
		return auth, false, nil
	}
	switch provider {
	case "antigravity", "xai":
		if provider == "xai" && isAPIKeyAuth(auth) {
			return auth, false, nil
		}
		if !authHasRefreshCredential(auth) {
			return auth, false, nil
		}
	default:
		return auth, false, nil
	}

	refreshed, errRefresh := m.refreshProviderForRequest(ctx, auth.ID, authAccessToken(auth), provider, auth)
	if errRefresh != nil {
		log.Debugf("%s credential refresh before fallback failed for %s: %v", provider, auth.ID, errRefresh)
		if provider == "chatgpt-web" && isChatGPTWebCredentialUnavailableError(errRefresh) && !persistAuthUpdateForError(errRefresh) {
			return auth, true, execErr
		}
		return auth, true, errRefresh
	}
	if refreshed == nil {
		errRefresh = fmt.Errorf("%s credential refresh returned no auth", provider)
		log.Debugf("%s credential refresh before fallback failed for %s: %v", provider, auth.ID, errRefresh)
		return auth, true, errRefresh
	}
	resolved, errProxy := m.ResolveProxyAuth(ctx, refreshed)
	if errProxy != nil {
		return auth, true, errProxy
	}
	return resolved, true, nil
}

func (m *Manager) recoverUnauthorizedAuth(ctx context.Context, executor ProviderExecutor, recoverer UnauthorizedAuthRecoverer, auth *Auth, execErr error) (*Auth, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return auth, err
	}
	key := requestAuthPrepareFlightKey(auth) + "\x00unauthorized"
	if taskID := authMetadataString(auth, "task_id"); taskID != "" {
		key += "\x00" + taskID
	}
	workerCtx := context.WithoutCancel(ctx)
	resultChannel := m.requestPrepareFlights.DoChan(key, func() (any, error) {
		return m.recoverUnauthorizedAuthSynchronized(workerCtx, executor, recoverer, auth, execErr)
	})
	select {
	case <-ctx.Done():
		return auth, ctx.Err()
	case result := <-resultChannel:
		if result.Err != nil {
			return auth, result.Err
		}
		recovered, ok := result.Val.(*Auth)
		if !ok && result.Val != nil {
			return auth, fmt.Errorf("unauthorized auth recovery returned %T", result.Val)
		}
		return recovered, nil
	}
}

func (m *Manager) recoverUnauthorizedAuthSynchronized(ctx context.Context, executor ProviderExecutor, recoverer UnauthorizedAuthRecoverer, auth *Auth, execErr error) (*Auth, error) {
	if auth == nil || strings.TrimSpace(auth.ID) == "" {
		return recoverer.RecoverUnauthorized(ctx, auth)
	}
	lockedCtx, releaseLocks, errLock := m.lockCredentialRefreshesContext(ctx, authRequestRefreshLockIDs(auth, auth.ID))
	if errLock != nil {
		return auth, errLock
	}
	defer releaseLocks()
	ctx = lockedCtx

	m.mu.RLock()
	current := m.auths[auth.ID]
	if !requestPreparationMatchesCurrent(current, auth) {
		if agentIdentityTaskAlreadyAdvanced(current, auth) {
			target := current.Clone()
			m.mu.RUnlock()
			carryRuntimeProxy(auth, target)
			return target, nil
		}
		m.mu.RUnlock()
		return auth, runtimeAuthInstanceRetiredError()
	}
	target := current.Clone()
	m.mu.RUnlock()
	carryRuntimeProxy(auth, target)
	if !recoverer.ShouldRecoverUnauthorized(target, execErr) {
		return target, nil
	}
	target.bindExecutorOwner(executor)
	recoveryCtx, releaseRecovery, active := target.BeginRuntimeExecution(ctx)
	if !active {
		return auth, runtimeAuthInstanceRetiredError()
	}
	updated, errRecover := recoverer.RecoverUnauthorized(recoveryCtx, target.Clone())
	retiredDuringRecovery := releaseRecovery()
	if retiredDuringRecovery || runtimeAuthInstanceRetiredContext(recoveryCtx) {
		return auth, runtimeAuthInstanceRetiredError()
	}
	if errRecover != nil {
		return auth, errRecover
	}
	if updated == nil {
		return target, nil
	}
	installed, errInstall := m.installPreparedRequestAuth(ctx, target, updated, false)
	if errInstall != nil {
		return updated, errInstall
	}
	if closer, ok := executor.(AuthExecutionSessionCloser); ok && installed != nil {
		closer.CloseAuthExecutionSessions(installed.ID, "agent_task_rotated")
	}
	if installed != nil {
		return installed, nil
	}
	return updated, nil
}

func (m *Manager) refreshAntigravityForRequest(ctx context.Context, id, failedAccessToken string) (*Auth, error) {
	return m.refreshProviderForRequest(ctx, id, failedAccessToken, "antigravity", nil)
}

func (m *Manager) beginRequestRefreshFlight() (func(), error) {
	if m == nil {
		return nil, errors.New("auth manager is nil")
	}
	m.executorLifecycleMu.Lock()
	defer m.executorLifecycleMu.Unlock()
	if m.executorsClosed || m.executorCloseSealed {
		return nil, errors.New("auth manager executors are closed")
	}
	m.refreshFlightWG.Add(1)
	return m.refreshFlightWG.Done, nil
}

func refreshExecutorCredential(ctx context.Context, executor ProviderExecutor, auth *Auth) (*Auth, error) {
	if durable, ok := executor.(DurableRefreshExecutor); ok {
		return durable.RefreshToCompletion(ctx, auth)
	}
	return executor.Refresh(ctx, auth)
}

func (m *Manager) refreshProviderForRequest(ctx context.Context, id, failedAccessToken, provider string, expected *Auth) (*Auth, error) {
	if m == nil {
		return nil, errors.New("auth manager is nil")
	}
	if !strings.EqualFold(strings.TrimSpace(provider), "chatgpt-web") {
		return m.refreshProviderForRequestSynchronized(ctx, id, failedAccessToken, provider, expected, nil)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return m.waitForChatGPTWebRequestRefresh(ctx, id, failedAccessToken, expected, true)
}

func (m *Manager) waitForChatGPTWebRequestRefresh(
	ctx context.Context,
	id string,
	failedAccessToken string,
	expected *Auth,
	validateUnauthorized bool,
) (*Auth, error) {
	flight, errStart := m.startChatGPTWebRequestRefreshFlight(ctx, id, failedAccessToken, expected, validateUnauthorized)
	if errStart != nil {
		return nil, errStart
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-flight.done:
		if flight.result.Err != nil {
			return nil, flight.result.Err
		}
		refreshed, ok := flight.result.Val.(*Auth)
		if !ok && flight.result.Val != nil {
			return nil, fmt.Errorf("chatgpt-web credential refresh returned %T", flight.result.Val)
		}
		return refreshed, nil
	}
}

func (m *Manager) startChatGPTWebRequestRefreshFlight(
	ctx context.Context,
	id string,
	failedAccessToken string,
	expected *Auth,
	validateUnauthorized bool,
) (*chatGPTWebRequestRefreshFlight, error) {
	if m == nil {
		return nil, errors.New("auth manager is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := chatGPTWebRequestRefreshFlightKey(id, expected)
	if validateUnauthorized {
		key += "\x00unauthorized"
	} else {
		key += "\x00maintenance"
	}
	m.chatGPTWebRefreshMu.Lock()
	if active := m.chatGPTWebRefreshes[key]; active != nil {
		if validateUnauthorized {
			m.chatGPTWebRequestRefreshMetrics.deduplicated.Add(1)
		}
		m.chatGPTWebRefreshMu.Unlock()
		return active, nil
	}
	releaseFlight, errFlight := m.beginRequestRefreshFlight()
	if errFlight != nil {
		m.chatGPTWebRefreshMu.Unlock()
		return nil, errFlight
	}
	if m.chatGPTWebRefreshes == nil {
		m.chatGPTWebRefreshes = make(map[string]*chatGPTWebRequestRefreshFlight)
	}
	flight := &chatGPTWebRequestRefreshFlight{done: make(chan struct{})}
	m.chatGPTWebRefreshes[key] = flight
	if validateUnauthorized {
		m.chatGPTWebRequestRefreshMetrics.queued.Add(1)
	}
	scheduler := m.scheduler
	if scheduler != nil {
		scheduler.blockAuthRequestRefresh(id)
	}
	m.chatGPTWebRefreshMu.Unlock()

	// Refresh tokens may rotate, so one shared worker per auth generation must
	// finish applying its result even when every initiating request stops waiting.
	go func() {
		defer releaseFlight()
		if validateUnauthorized {
			m.chatGPTWebRequestRefreshMetrics.queued.Add(-1)
			m.chatGPTWebRequestRefreshMetrics.running.Add(1)
			defer m.chatGPTWebRequestRefreshMetrics.running.Add(-1)
		}
		workerCtx, cancelWorker := context.WithTimeout(context.WithoutCancel(ctx), chatGPTWebRefreshFlightTimeout)
		defer cancelWorker()
		if validateUnauthorized {
			workerCtx = context.WithValue(workerCtx, chatGPTWebUnauthorizedRefreshContextKey{}, true)
		}
		refreshAttempted := false
		reservation, errReserve := m.refreshPersistence.Load().acquireContext(
			workerCtx,
			RefreshPersistencePrioritySession,
			id,
		)
		if errReserve != nil {
			flight.result.Err = errReserve
		} else {
			workerCtx = reservation.context(workerCtx)
			refreshAttempted = true
			flight.result.Val, flight.result.Err = m.refreshProviderForRequestSynchronized(workerCtx, id, failedAccessToken, "chatgpt-web", expected, nil)
			reservation.release()
		}
		if validateUnauthorized {
			if flight.result.Err == nil {
				m.chatGPTWebRequestRefreshMetrics.succeeded.Add(1)
			} else {
				m.chatGPTWebRequestRefreshMetrics.failed.Add(1)
				m.chatGPTWebRequestRefreshMetrics.observeOutcome(chatGPTWebRequestRefreshOutcome(flight.result.Err))
			}
			backpressured := (!refreshAttempted && chatGPTWebRequestRefreshBackpressured(errReserve)) ||
				chatGPTWebRequestRefreshPersistenceBackpressured(flight.result.Err)
			if backpressured {
				m.chatGPTWebRequestRefreshMetrics.backpressured.Add(1)
				m.markChatGPTWebUnauthorizedRefreshBackpressure(expected, failedAccessToken, flight.result.Err)
			} else if refreshAttempted && flight.result.Err != nil && !errors.Is(flight.result.Err, context.Canceled) {
				m.markChatGPTWebUnauthorizedRefreshFailure(expected, failedAccessToken)
			}
		}
		if validateUnauthorized {
			if recovered, ok := flight.result.Val.(*Auth); ok && recovered != nil {
				switch recovered.LifecycleState() {
				case LifecycleStateDead:
					m.chatGPTWebRequestRefreshMetrics.deadConfirmed.Add(1)
				case LifecycleStateReloginPending:
					m.mu.RLock()
					executor := m.executors["chatgpt-web"]
					m.mu.RUnlock()
					if trigger, okTrigger := executor.(backgroundReloginTrigger); okTrigger {
						trigger.TriggerBackgroundRelogin(recovered)
					}
				}
			}
		}

		m.chatGPTWebRefreshMu.Lock()
		if m.chatGPTWebRefreshes[key] == flight {
			delete(m.chatGPTWebRefreshes, key)
		}
		m.chatGPTWebRefreshMu.Unlock()
		if scheduler != nil {
			current, _ := m.GetByID(id)
			scheduler.unblockAuthRequestRefresh(id, current)
		}
		close(flight.done)
	}()
	return flight, nil
}

func chatGPTWebRequestRefreshBackpressured(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var authErr *Error
	return errors.As(err, &authErr) && authErr != nil && authErr.Code == "refresh_persist_backpressure"
}

func chatGPTWebRequestRefreshPersistenceBackpressured(err error) bool {
	if err == nil {
		return false
	}
	var authErr *Error
	return errors.As(err, &authErr) && authErr != nil && authErr.Code == "refresh_persist_backpressure"
}

func (m *Manager) markChatGPTWebUnauthorizedRefreshBackpressure(expected *Auth, failedAccessToken string, cause error) {
	if m == nil || expected == nil {
		return
	}
	now := time.Now()
	retryAt := now.Add(refreshPendingBackoff)
	failure := &Error{
		Code:       "refresh_persist_backpressure",
		Message:    "credential refresh is waiting for persistence capacity",
		Retryable:  true,
		HTTPStatus: http.StatusServiceUnavailable,
	}
	var authErr *Error
	if errors.As(cause, &authErr) && authErr != nil {
		failure = cloneError(authErr)
	}

	unblockResult := m.lockResultMutation(expected.ID)
	var snapshot *Auth
	m.mu.Lock()
	current := m.auths[expected.ID]
	if current != nil &&
		runtimeMetadataMutationMatchesCurrent(current, expected) &&
		current.LifecycleRefreshable() &&
		authAccessToken(current) == failedAccessToken {
		current.Status = StatusError
		current.StatusMessage = failure.Message
		current.LastError = failure
		current.Unavailable = true
		current.CooldownScope = cooldownScopeAuth
		current.NextRetryAfter = retryAt
		current.NextRefreshAfter = retryAt
		current.UpdatedAt = now
		m.updateManagementAuthCatalogLocked(current)
		snapshot = current.Clone()
	}
	m.mu.Unlock()
	if snapshot != nil && m.resultPersistence != nil && m.SupportsSourceConditionalSave() {
		m.resultPersistence.enqueue(snapshot.ID)
	}
	unblockResult()
	if snapshot == nil {
		return
	}
	if m.scheduler != nil {
		m.scheduler.upsertAuthState(snapshot)
	}
	m.queueRefreshReschedule(snapshot.ID)
	m.Hook().OnAuthUpdated(context.Background(), snapshot.Clone())
}

func (m *Manager) markChatGPTWebUnauthorizedRefreshFailure(expected *Auth, failedAccessToken string) {
	if m == nil || expected == nil {
		return
	}
	m.mu.RLock()
	current := m.auths[expected.ID]
	if current == nil ||
		!runtimeMetadataMutationMatchesCurrent(current, expected) ||
		!current.LifecycleRefreshable() ||
		authAccessToken(current) != failedAccessToken {
		m.mu.RUnlock()
		return
	}
	snapshot := current.Clone()
	m.mu.RUnlock()

	result := resultForAuth(snapshot, "chatgpt-web", "", false)
	result.Error = &Error{
		Code:       "unauthorized",
		Message:    "credential refresh did not recover upstream authorization",
		HTTPStatus: http.StatusUnauthorized,
	}
	m.markExecutionResult(context.Background(), result)
}

func (m *Manager) markChatGPTWebTerminalLifecycle(expected *Auth, lifecycle *chatgptwebauth.AuthError) {
	if m == nil || expected == nil || lifecycle == nil || lifecycle.State != chatgptwebauth.LifecycleDead {
		return
	}
	reason := chatgptwebauth.SafeLifecycleReason(lifecycle.Code)
	if reason != "account_deleted" && reason != "account_deactivated" {
		return
	}
	now := time.Now()
	status := lifecycle.StatusCode
	if status == 0 {
		status = lifecycle.Status
	}
	if status == 0 {
		status = http.StatusForbidden
	}
	unlockResult := m.lockResultMutation(expected.ID)
	var snapshot *Auth
	m.mu.Lock()
	current := m.auths[expected.ID]
	if runtimeMetadataMutationMatchesCurrent(current, expected) && isNativeChatGPTWebCredentialAuth(current) {
		if current.Metadata == nil {
			current.Metadata = make(map[string]any)
		}
		current.Metadata["lifecycle_state"] = LifecycleStateDead
		current.Metadata["lifecycle_reason"] = reason
		current.Metadata["lifecycle_updated_at"] = now.UTC().Format(time.RFC3339)
		current.LastError = &Error{
			Code:       reason,
			Message:    "upstream confirmed that the account is unavailable",
			HTTPStatus: status,
		}
		current.NextRetryAfter = time.Time{}
		current.NextRefreshAfter = time.Time{}
		current.UpdatedAt = now
		applyLifecycleRuntimeState(current)
		m.updateManagementAuthCatalogLocked(current)
		snapshot = current.Clone()
	}
	m.mu.Unlock()
	if snapshot != nil && m.resultPersistence != nil && authSourceHash(snapshot) != "" && m.SupportsSourceConditionalSave() {
		m.resultPersistence.enqueue(snapshot.ID)
	}
	unlockResult()
	if snapshot == nil {
		return
	}
	if m.scheduler != nil {
		m.scheduler.upsertAuthState(snapshot)
	}
	m.Hook().OnAuthUpdated(context.Background(), snapshot.Clone())
}

func chatGPTWebRequestRefreshFlightKey(id string, expected *Auth) string {
	key := strings.TrimSpace(id)
	if sourceKey := authRequestRefreshSourceKey("chatgpt-web", expected); sourceKey != "" {
		key += "\x00" + sourceKey
	}
	return key
}

func (m *Manager) refreshProviderForRequestSynchronized(ctx context.Context, id, failedAccessToken, provider string, expected *Auth, validate func(*Auth) error) (*Auth, error) {
	if m == nil {
		return nil, errors.New("auth manager is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("auth id is empty")
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return nil, errors.New("auth provider is empty")
	}
	requestUnauthorized, _ := ctx.Value(chatGPTWebUnauthorizedRefreshContextKey{}).(bool)

	lockIDs := []string{id}
	if provider == "chatgpt-web" {
		lockSource := expected
		if lockSource == nil {
			m.mu.RLock()
			lockSource = m.auths[id]
			m.mu.RUnlock()
		}
		lockIDs = authRequestRefreshLockIDs(lockSource, id)
	}
	lock, alreadyHeld := authRequestRefreshLockFromContext(ctx, m, id)
	if !alreadyHeld {
		lockedCtx, releaseLocks, errLock := m.lockCredentialRefreshesContext(ctx, lockIDs)
		if errLock != nil {
			return nil, errLock
		}
		defer releaseLocks()
		ctx = lockedCtx
		lock, alreadyHeld = authRequestRefreshLockFromContext(ctx, m, id)
	}
	if !alreadyHeld || lock == nil || lock.semaphore == nil {
		return nil, errors.New("invalid auth refresh lock")
	}
	for _, lockID := range lockIDs {
		if _, held := authRequestRefreshLockFromContext(ctx, m, lockID); !held {
			return nil, errors.New("incomplete auth refresh lock set")
		}
	}
	releaseResultWaiter := lock.track(provider, expected)
	defer releaseResultWaiter()

	m.mu.Lock()
	auth := m.auths[id]
	if auth == nil || m.authExecutionBlockedLocked(ctx, auth) || !strings.EqualFold(strings.TrimSpace(auth.Provider), provider) {
		m.mu.Unlock()
		return nil, fmt.Errorf("%s auth not available", provider)
	}
	if validate != nil {
		if errValidate := validate(auth); errValidate != nil {
			m.mu.Unlock()
			return nil, errValidate
		}
	}
	if provider == "chatgpt-web" && expected != nil {
		if !runtimeMetadataMutationMatchesCurrent(auth, expected) {
			reusable := chatGPTWebRequestRefreshResultReusable(lock, provider, expected, auth) ||
				chatGPTWebRefreshLineageMatches(expected, auth)
			if !reusable {
				m.mu.Unlock()
				return nil, runtimeAuthInstanceRetiredError()
			}
			lock.remember(provider, expected, auth)
		}
		if auth.Disabled || auth.Status == StatusDisabled || !auth.LifecycleRefreshable() {
			current := auth.Clone()
			errUnavailable := newChatGPTWebRefreshStateUnavailableError(auth)
			m.mu.Unlock()
			return current, errUnavailable
		}
	}
	exec := m.executors[auth.Provider]
	if exec == nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("%s executor not found", provider)
	}
	auth.bindExecutorOwner(exec)
	if failedAccessToken != "" {
		if currentToken := authAccessToken(auth); currentToken != "" && currentToken != failedAccessToken {
			current := auth.Clone()
			m.mu.Unlock()
			if provider == "chatgpt-web" && requestUnauthorized {
				return m.validateExistingChatGPTWebUnauthorizedRefresh(
					ctx,
					lock,
					exec,
					failedAccessToken,
					expected,
					current,
				)
			}
			return current, nil
		}
	}
	if provider == "chatgpt-web" && expected != nil {
		if sharedFailure, ok := lock.failure(provider, expected); ok {
			m.mu.Unlock()
			return nil, sharedFailure
		}
	}
	baseline := auth.Clone()
	refreshInput := auth.Clone()
	refreshCtx, releaseRefresh, active := m.beginRefreshExecutionLocked(
		ctx,
		auth,
	)
	m.mu.Unlock()
	if !active {
		return nil, runtimeAuthInstanceRetiredError()
	}
	resolvedRefreshInput, errProxy := m.ResolveProxyAuth(refreshCtx, refreshInput)
	if errProxy != nil {
		retiredDuringRefresh := releaseRefresh()
		if retiredDuringRefresh || runtimeAuthInstanceRetiredContext(refreshCtx) {
			return nil, runtimeAuthInstanceRetiredError()
		}
		return nil, errProxy
	}
	refreshInput = resolvedRefreshInput

	updated, errRefresh := refreshExecutorCredential(refreshCtx, exec, refreshInput)
	if errRefresh == nil && provider == "chatgpt-web" {
		if requestUnauthorized {
			if validator, ok := exec.(UnauthorizedRequestRefreshValidator); ok {
				m.observeChatGPTWebRequestRefreshToken(failedAccessToken, updated)
				updated, errRefresh = validator.ValidateUnauthorizedRequestRefresh(refreshCtx, failedAccessToken, baseline, updated)
				if errRefresh == nil {
					m.chatGPTWebRequestRefreshMetrics.observeOutcome(ChatGPTWebRequestRefreshOutcomeProbeSucceeded)
				}
			} else {
				errRefresh = errors.New("chatgpt-web executor cannot validate a replacement access token")
				updated = nil
			}
		}
	}
	if errRefresh != nil {
		errRefresh = m.reportProxyFailure(refreshCtx, refreshInput, errRefresh)
	}
	retiredDuringRefresh := releaseRefresh()
	if retiredDuringRefresh || runtimeAuthInstanceRetiredContext(refreshCtx) {
		if errRefresh == nil {
			if current, ok := m.concurrentRequestRefreshResult(lock, auth, id, provider, failedAccessToken, updated, requestUnauthorized); ok {
				if provider == "chatgpt-web" && requestUnauthorized {
					return m.validateExistingChatGPTWebUnauthorizedRefresh(ctx, lock, exec, failedAccessToken, auth, current)
				}
				lock.remember(provider, auth, current)
				return current, nil
			}
		}
		return nil, runtimeAuthInstanceRetiredError()
	}
	if errRefresh != nil {
		if updated != nil && persistAuthUpdateForError(errRefresh) {
			if validate != nil {
				if errValidate := validate(updated); errValidate != nil {
					return nil, errValidate
				}
			}
			carryRuntimeProxy(refreshInput, updated)
			if updated.Runtime == nil {
				updated.Runtime = baseline.Runtime
			}
			if chatGPTWebRequestRefreshOutcome(errRefresh) != ChatGPTWebRequestRefreshOutcomeProbeTransient {
				updated.NextRefreshAfter = time.Time{}
			}
			updated.UpdatedAt = time.Now()
			saved, errUpdate := m.applyRefreshedAuthDurably(ctx, provider, auth, baseline, updated, time.Time{})
			if errUpdate != nil {
				return nil, errUpdate
			}
			if saved == nil {
				return nil, fmt.Errorf("%s auth changed during refresh", provider)
			}
			lock.remember(provider, auth, saved)
			return saved, errRefresh
		}
		if provider == "chatgpt-web" && !errors.Is(errRefresh, context.Canceled) && !errors.Is(errRefresh, context.DeadlineExceeded) {
			lock.rememberFailure(provider, auth, errRefresh)
		}
		if skipAuthResultForError(errRefresh) {
			return nil, errRefresh
		}
		if provider == "antigravity" && isInvalidGrantError(errRefresh) {
			result := resultForAuth(auth, auth.Provider, "", false)
			result.Error = &Error{
				Code:       "invalid_grant",
				Message:    errRefresh.Error(),
				HTTPStatus: statusCodeFromError(errRefresh),
				Retryable:  false,
			}
			m.markExecutionResult(ctx, result)
		}
		return nil, errRefresh
	}
	if updated == nil {
		updated = refreshInput
	}
	if validate != nil {
		if errValidate := validate(updated); errValidate != nil {
			return nil, errValidate
		}
	}
	carryRuntimeProxy(refreshInput, updated)
	if updated.Runtime == nil {
		updated.Runtime = baseline.Runtime
	}
	now := time.Now()
	updated.LastRefreshedAt = now
	updated.NextRefreshAfter = time.Time{}
	updated.LastError = nil
	updated.UpdatedAt = now
	if m.shouldRefresh(updated, now) {
		updated.NextRefreshAfter = now.Add(refreshIneffectiveBackoff)
	}

	saved, errUpdate := m.applyRefreshedAuthDurably(ctx, provider, auth, baseline, updated, time.Time{})
	if errUpdate != nil {
		return nil, errUpdate
	}
	if saved == nil {
		if provider == "chatgpt-web" {
			if current, ok := m.concurrentRequestRefreshResult(lock, auth, id, provider, failedAccessToken, updated, requestUnauthorized); ok {
				if requestUnauthorized {
					return m.validateExistingChatGPTWebUnauthorizedRefresh(ctx, lock, exec, failedAccessToken, auth, current)
				}
				lock.remember(provider, auth, current)
				return current, nil
			}
		}
		return nil, fmt.Errorf("%s auth changed during refresh", provider)
	}
	lock.remember(provider, auth, saved)
	return saved, nil
}

func (m *Manager) validateExistingChatGPTWebUnauthorizedRefresh(
	ctx context.Context,
	lock *authRequestRefreshLock,
	exec ProviderExecutor,
	failedAccessToken string,
	previous *Auth,
	current *Auth,
) (*Auth, error) {
	validator, ok := exec.(UnauthorizedRequestRefreshValidator)
	if !ok || validator == nil {
		return nil, errors.New("chatgpt-web executor cannot validate a replacement access token")
	}
	m.observeChatGPTWebRequestRefreshToken(failedAccessToken, current)
	validated, errValidate := validator.ValidateUnauthorizedRequestRefresh(
		ctx,
		failedAccessToken,
		previous,
		current,
	)
	if errValidate == nil {
		m.chatGPTWebRequestRefreshMetrics.observeOutcome(ChatGPTWebRequestRefreshOutcomeProbeSucceeded)
	} else {
		errValidate = m.reportProxyFailure(ctx, current, errValidate)
	}
	if validated == nil {
		if errValidate != nil {
			return nil, errValidate
		}
		return nil, errors.New("chatgpt-web credential validation returned no credential")
	}
	if errValidate != nil && !persistAuthUpdateForError(errValidate) {
		return nil, errValidate
	}
	carryRuntimeProxy(current, validated)
	if validated.Runtime == nil {
		validated.Runtime = current.Runtime
	}
	validated.UpdatedAt = time.Now()
	saved, errUpdate := m.applyRefreshedAuthDurably(
		ctx,
		"chatgpt-web",
		current,
		current,
		validated,
		time.Time{},
	)
	if errUpdate != nil {
		return nil, errUpdate
	}
	if saved == nil {
		return nil, runtimeAuthInstanceRetiredError()
	}
	if lock != nil {
		lock.remember("chatgpt-web", previous, saved)
		lock.remember("chatgpt-web", current, saved)
	}
	return saved, errValidate
}

type chatGPTWebRequestRefreshOutcomeProvider interface {
	ChatGPTWebRequestRefreshOutcome() string
}

func chatGPTWebRequestRefreshOutcome(err error) string {
	var provider chatGPTWebRequestRefreshOutcomeProvider
	if errors.As(err, &provider) && provider != nil {
		return strings.TrimSpace(provider.ChatGPTWebRequestRefreshOutcome())
	}
	return ""
}

func (m *Manager) acquireRequestRefreshLock(id string) *authRequestRefreshLock {
	if m == nil || strings.TrimSpace(id) == "" {
		return nil
	}
	m.requestRefreshLocksMu.Lock()
	defer m.requestRefreshLocksMu.Unlock()
	lockValue, ok := m.requestRefreshLocks.Load(id)
	lock, _ := lockValue.(*authRequestRefreshLock)
	if !ok || lock == nil || lock.semaphore == nil {
		lock = &authRequestRefreshLock{semaphore: make(chan struct{}, 1)}
		lock.semaphore <- struct{}{}
		m.requestRefreshLocks.Store(id, lock)
	}
	lock.active++
	return lock
}

// LockCredentialRefresh serializes an external credential refresh with
// request-time refreshes for the same auth ID.
func (m *Manager) LockCredentialRefresh(ctx context.Context, id string) (func(), error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("auth id is empty")
	}
	return m.LockCredentialRefreshes(ctx, []string{id})
}

// LockCredentialRefreshes serializes an identity-discovery refresh with
// request-time refreshes for all supplied auth IDs.
func (m *Manager) LockCredentialRefreshes(ctx context.Context, ids []string) (func(), error) {
	_, release, errLock := m.lockCredentialRefreshesContext(ctx, ids)
	return release, errLock
}

func (m *Manager) lockCredentialRefreshesContext(ctx context.Context, ids []string) (context.Context, func(), error) {
	if m == nil {
		return ctx, func() {}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	unique := make(map[string]struct{}, len(ids))
	for _, rawID := range ids {
		if id := strings.TrimSpace(rawID); id != "" {
			unique[id] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(unique))
	for id := range unique {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	type heldRefreshLock struct {
		id   string
		lock *authRequestRefreshLock
	}
	held := make([]heldRefreshLock, 0, len(ordered))
	releaseHeld := func() {
		for index := len(held) - 1; index >= 0; index-- {
			held[index].lock.semaphore <- struct{}{}
			m.releaseRequestRefreshLock(held[index].id, held[index].lock)
		}
	}
	for _, id := range ordered {
		lock := m.acquireRequestRefreshLock(id)
		if lock == nil || lock.semaphore == nil {
			releaseHeld()
			return ctx, nil, errors.New("invalid auth refresh lock")
		}
		select {
		case <-ctx.Done():
			m.releaseRequestRefreshLock(id, lock)
			releaseHeld()
			return ctx, nil, ctx.Err()
		case <-lock.semaphore:
			held = append(held, heldRefreshLock{id: id, lock: lock})
		}
	}
	locks := make(map[string]*authRequestRefreshLock, len(held))
	for _, item := range held {
		locks[item.id] = item.lock
	}
	lockedCtx := context.WithValue(ctx, authRequestRefreshLocksContextKey{}, &authRequestRefreshLocksContext{manager: m, locks: locks})
	var once sync.Once
	return lockedCtx, func() {
		once.Do(releaseHeld)
	}, nil
}

func authRequestRefreshLockFromContext(ctx context.Context, manager *Manager, id string) (*authRequestRefreshLock, bool) {
	if ctx == nil || manager == nil {
		return nil, false
	}
	held, _ := ctx.Value(authRequestRefreshLocksContextKey{}).(*authRequestRefreshLocksContext)
	if held == nil || held.manager != manager {
		return nil, false
	}
	lock := held.locks[strings.TrimSpace(id)]
	return lock, lock != nil && lock.semaphore != nil
}

func (m *Manager) releaseRequestRefreshLock(id string, lock *authRequestRefreshLock) {
	if m == nil || lock == nil {
		return
	}
	m.requestRefreshLocksMu.Lock()
	if lock.active > 0 {
		lock.active--
	}
	if lock.active == 0 {
		if current, ok := m.requestRefreshLocks.Load(id); ok && current == lock {
			m.requestRefreshLocks.Delete(id)
		}
	}
	m.requestRefreshLocksMu.Unlock()
}

func (lock *authRequestRefreshLock) remember(provider string, source, result *Auth) {
	if lock == nil || source == nil || result == nil {
		return
	}
	key := authRequestRefreshSourceKey(provider, source)
	if key == "" || result.installationID == "" || result.RuntimeInstanceID() == "" {
		return
	}
	record := authRequestRefreshResult{
		provider:                strings.ToLower(strings.TrimSpace(provider)),
		sourceInstallationID:    source.installationID,
		sourceRuntimeInstanceID: source.RuntimeInstanceID(),
		resultInstallationID:    result.installationID,
		resultRuntimeInstanceID: result.RuntimeInstanceID(),
	}
	lock.mu.Lock()
	if lock.results == nil {
		lock.results = make(map[string]authRequestRefreshResult)
	}
	if _, exists := lock.results[key]; !exists {
		lock.resultOrder = append(lock.resultOrder, key)
	}
	lock.results[key] = record
	delete(lock.failures, key)
	lock.pruneResultsLocked()
	lock.mu.Unlock()
}

func (lock *authRequestRefreshLock) rememberFailure(provider string, source *Auth, err error) {
	key := authRequestRefreshSourceKey(provider, source)
	if lock == nil || key == "" || err == nil {
		return
	}
	lock.mu.Lock()
	if lock.failures == nil {
		lock.failures = make(map[string]error)
	}
	if lock.waiters[key] > 0 {
		lock.failures[key] = err
	}
	lock.mu.Unlock()
}

func (lock *authRequestRefreshLock) failure(provider string, source *Auth) (error, bool) {
	key := authRequestRefreshSourceKey(provider, source)
	if lock == nil || key == "" {
		return nil, false
	}
	lock.mu.Lock()
	err, ok := lock.failures[key]
	lock.mu.Unlock()
	return err, ok
}

func chatGPTWebRequestRefreshResultReusable(lock *authRequestRefreshLock, provider string, expected, current *Auth) bool {
	key := authRequestRefreshSourceKey(provider, expected)
	if lock == nil || key == "" || current == nil {
		return false
	}
	lock.mu.Lock()
	record, ok := lock.results[key]
	lock.mu.Unlock()
	return ok &&
		expected.requestRefreshFamilyID != "" &&
		expected.requestRefreshFamilyID == current.requestRefreshFamilyID &&
		record.provider == strings.ToLower(strings.TrimSpace(provider)) &&
		record.sourceInstallationID == expected.installationID &&
		record.sourceRuntimeInstanceID == expected.RuntimeInstanceID() &&
		record.resultInstallationID == current.installationID &&
		record.resultRuntimeInstanceID == current.RuntimeInstanceID()
}

func chatGPTWebRefreshLineageMatches(source, result *Auth) bool {
	return source != nil &&
		result != nil &&
		source.requestRefreshFamilyID != "" &&
		result.requestRefreshFamilyID == source.requestRefreshFamilyID
}

func authRequestRefreshSourceKey(provider string, source *Auth) string {
	if source == nil || source.installationID == "" || source.RuntimeInstanceID() == "" {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(provider)) + "\x00" +
		source.installationID + "\x00" + source.RuntimeInstanceID()
}

func (lock *authRequestRefreshLock) track(provider string, source *Auth) func() {
	key := authRequestRefreshSourceKey(provider, source)
	if lock == nil || key == "" {
		return func() {}
	}
	lock.mu.Lock()
	if lock.waiters == nil {
		lock.waiters = make(map[string]int)
	}
	lock.waiters[key]++
	lock.mu.Unlock()
	return func() {
		lock.mu.Lock()
		if lock.waiters[key] <= 1 {
			delete(lock.waiters, key)
			delete(lock.failures, key)
		} else {
			lock.waiters[key]--
		}
		lock.pruneResultsLocked()
		lock.mu.Unlock()
	}
}

func (lock *authRequestRefreshLock) pruneResultsLocked() {
	if lock == nil || len(lock.results) <= authRequestRefreshResultLimit {
		return
	}
	kept := lock.resultOrder[:0]
	for _, key := range lock.resultOrder {
		if len(lock.results) <= authRequestRefreshResultLimit {
			kept = append(kept, key)
			continue
		}
		if lock.waiters[key] > 0 {
			kept = append(kept, key)
			continue
		}
		delete(lock.results, key)
	}
	lock.resultOrder = kept
}

type chatGPTWebRefreshStateUnavailableError struct {
	state  string
	reason string
}

func newChatGPTWebRefreshStateUnavailableError(auth *Auth) *chatGPTWebRefreshStateUnavailableError {
	state := ""
	reason := ""
	if auth != nil {
		state = auth.LifecycleState()
		reason = strings.TrimSpace(auth.StatusMessage)
		if auth.Metadata != nil {
			if value, _ := auth.Metadata["lifecycle_reason"].(string); strings.TrimSpace(value) != "" {
				reason = chatgptwebauth.SafeLifecycleReason(value)
			}
		}
		reason = chatgptwebauth.SafeLifecycleReason(reason)
		if auth.Disabled || auth.Status == StatusDisabled {
			state = "disabled"
		}
	}
	return &chatGPTWebRefreshStateUnavailableError{state: state, reason: reason}
}

func (err *chatGPTWebRefreshStateUnavailableError) Error() string {
	if err == nil {
		return "chatgpt web credential is unavailable"
	}
	detail := strings.TrimSpace(err.reason)
	if detail == "" {
		detail = strings.TrimSpace(err.state)
	}
	if detail == "" {
		return "chatgpt web credential is unavailable"
	}
	return "chatgpt web credential is unavailable: " + detail
}

func (*chatGPTWebRefreshStateUnavailableError) StatusCode() int {
	return http.StatusServiceUnavailable
}

func (*chatGPTWebRefreshStateUnavailableError) SkipAuthResult() bool {
	return true
}

func (*chatGPTWebRefreshStateUnavailableError) RetryOtherAuth() bool {
	return true
}

func (*chatGPTWebRefreshStateUnavailableError) ChatGPTWebCredentialUnavailable() bool {
	return true
}

func (*chatGPTWebRefreshStateUnavailableError) PersistAuthUpdateOnError() bool {
	return true
}

func (m *Manager) concurrentRequestRefreshResult(lock *authRequestRefreshLock, source *Auth, id, provider, failedAccessToken string, updated *Auth, allowSameTokenCandidate bool) (*Auth, bool) {
	refreshedToken := authAccessToken(updated)
	if m == nil || updated == nil || refreshedToken == "" || (!allowSameTokenCandidate && refreshedToken == failedAccessToken) {
		return nil, false
	}
	m.mu.RLock()
	current := m.auths[id]
	if current == nil || current.Disabled || current.Status == StatusDisabled ||
		!strings.EqualFold(strings.TrimSpace(current.Provider), provider) ||
		authAccessToken(current) != refreshedToken {
		m.mu.RUnlock()
		return nil, false
	}
	if strings.EqualFold(provider, "chatgpt-web") {
		if !chatGPTWebRequestRefreshResultReusable(lock, provider, source, current) {
			m.mu.RUnlock()
			return nil, false
		}
	}
	snapshot := current.Clone()
	m.mu.RUnlock()
	return snapshot, true
}

func isChatGPTWebCredentialUnavailableError(err error) bool {
	if err == nil {
		return false
	}
	type chatGPTWebCredentialUnavailable interface {
		ChatGPTWebCredentialUnavailable() bool
	}
	var target chatGPTWebCredentialUnavailable
	return errors.As(err, &target) && target.ChatGPTWebCredentialUnavailable()
}

// RefreshAntigravityAfterUnauthorized refreshes an Antigravity credential after
// an upstream request rejects the supplied access token. Concurrent callers for
// the same credential share the existing request refresh lock.
func (m *Manager) RefreshAntigravityAfterUnauthorized(ctx context.Context, id, failedAccessToken string) (*Auth, error) {
	return m.refreshAntigravityForRequest(ctx, id, failedAccessToken)
}

// RefreshChatGPTWebForRequest refreshes and installs one ChatGPT Web
// credential through the request-time synchronization path.
func (m *Manager) RefreshChatGPTWebForRequest(ctx context.Context, expected *Auth) (*Auth, error) {
	if expected == nil {
		return nil, errors.New("chatgpt-web credential is nil")
	}
	if !strings.EqualFold(strings.TrimSpace(expected.Provider), "chatgpt-web") {
		return nil, fmt.Errorf("credential provider %q is not chatgpt-web", expected.Provider)
	}
	return m.waitForChatGPTWebRequestRefresh(
		ctx,
		expected.ID,
		authAccessToken(expected),
		expected,
		false,
	)
}

// LinkedCodexSourceToken is the non-secret subset a linked ChatGPT Web
// credential may inherit from its Codex source.
type LinkedCodexSourceToken struct {
	AccessToken string
	Expired     string
	Email       string
	AccountID   string
	Identity    string
}

// RefreshLinkedCodexSource refreshes one Codex source under the same per-auth
// lock used by request and background refresh paths.
func (m *Manager) RefreshLinkedCodexSource(ctx context.Context, sourceID, sourceUID, failedAccessToken, expectedIdentity string) (LinkedCodexSourceToken, error) {
	if m == nil {
		return LinkedCodexSourceToken{}, newLinkedCodexSourceError("source_auth_missing", "linked codex credential is unavailable")
	}
	sourceID = strings.TrimSpace(sourceID)
	sourceUID = strings.TrimSpace(sourceUID)
	expectedIdentity = strings.TrimSpace(expectedIdentity)
	if sourceID == "" || sourceUID == "" || expectedIdentity == "" {
		return LinkedCodexSourceToken{}, newLinkedCodexSourceError("source_auth_invalid", "linked codex credential reference is incomplete")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tokenDigest := sha256.Sum256([]byte(strings.TrimSpace(failedAccessToken)))
	identityDigest := sha256.Sum256([]byte(expectedIdentity))
	flightKey := fmt.Sprintf("linked-codex\x00%s\x00%s\x00%x\x00%x", sourceID, sourceUID, identityDigest[:8], tokenDigest[:8])
	resultChannel := m.requestRefreshFlights.DoChan(flightKey, func() (any, error) {
		releaseFlight, errFlight := m.beginRequestRefreshFlight()
		if errFlight != nil {
			return nil, errFlight
		}
		defer releaseFlight()
		workerCtx, cancelWorker := context.WithTimeout(context.WithoutCancel(ctx), chatgptwebauth.DefaultAcquisitionTimeout)
		defer cancelWorker()
		validate := func(source *Auth) error {
			if source == nil || !strings.EqualFold(strings.TrimSpace(source.Provider), "codex") {
				return newLinkedCodexSourceError("source_auth_missing", "linked codex credential is unavailable")
			}
			if (source.Disabled || source.Status == StatusDisabled) && !ChatGPTWebAuthRetainedForDependents(source) {
				return newLinkedCodexSourceError("source_auth_disabled", "linked codex credential is disabled")
			}
			if chatGPTWebIdentityMetadataString(source.Metadata, "credential_uid") != sourceUID {
				return newLinkedCodexSourceError("source_auth_replaced", "linked codex credential identity changed")
			}
			if !linkedCodexSourceIdentityMatches(expectedIdentity, source) {
				return newLinkedCodexSourceError("source_identity_mismatch", "linked codex account identity changed")
			}
			return nil
		}
		return m.refreshProviderForRequestSynchronized(workerCtx, sourceID, failedAccessToken, "codex", nil, validate)
	})
	select {
	case <-ctx.Done():
		return LinkedCodexSourceToken{}, ctx.Err()
	case flightResult := <-resultChannel:
		if flightResult.Err != nil {
			return LinkedCodexSourceToken{}, classifyLinkedCodexSourceRefreshError(flightResult.Err)
		}
		source, ok := flightResult.Val.(*Auth)
		if !ok || source == nil {
			return LinkedCodexSourceToken{}, newLinkedCodexSourceError("source_refresh_unavailable", "codex refresh returned no credential")
		}
		if chatGPTWebIdentityMetadataString(source.Metadata, "credential_uid") != sourceUID {
			return LinkedCodexSourceToken{}, newLinkedCodexSourceError("source_auth_replaced", "linked codex credential identity changed")
		}
		if !linkedCodexSourceIdentityMatches(expectedIdentity, source) {
			return LinkedCodexSourceToken{}, newLinkedCodexSourceError("source_identity_mismatch", "linked codex account identity changed")
		}
		identity := linkedCodexSourceIdentity(source)
		accessToken := chatGPTWebIdentityMetadataString(source.Metadata, "access_token")
		if accessToken == "" {
			return LinkedCodexSourceToken{}, newLinkedCodexSourceError("source_token_unavailable", "linked codex credential has no access token")
		}
		return LinkedCodexSourceToken{
			AccessToken: accessToken,
			Expired:     chatGPTWebIdentityMetadataString(source.Metadata, "expired"),
			Email:       chatGPTWebIdentityMetadataString(source.Metadata, "email"),
			AccountID:   chatGPTWebIdentityMetadataString(source.Metadata, "account_id"),
			Identity:    identity,
		}, nil
	}
}

func linkedCodexSourceIdentity(source *Auth) string {
	if source == nil {
		return ""
	}
	candidate := source.Clone()
	candidate.Provider = "chatgpt-web"
	return ChatGPTWebCredentialReferenceValue(candidate)
}

func linkedCodexSourceIdentityMatches(expected string, source *Auth) bool {
	if source == nil {
		return false
	}
	candidate := source.Clone()
	candidate.Provider = "chatgpt-web"
	return ChatGPTWebCredentialReferenceMatches(expected, candidate)
}

func classifyLinkedCodexSourceRefreshError(err error) error {
	if err == nil {
		return nil
	}
	var coded interface{ ChatGPTWebErrorCode() string }
	if errors.As(err, &coded) {
		return err
	}
	if isRuntimeAuthInstanceRetiredError(err) {
		return newLinkedCodexSourceError("source_auth_replaced", "linked codex credential identity changed")
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "codex auth not available"):
		return newLinkedCodexSourceError("source_auth_missing", "linked codex credential is unavailable")
	case strings.Contains(lower, "invalid_grant"), strings.Contains(lower, "refresh_token_reused"):
		return newLinkedCodexSourceError("source_auth_invalid", "linked codex credential must be authenticated again")
	default:
		return err
	}
}

type linkedCodexSourceError struct {
	code    string
	message string
}

func newLinkedCodexSourceError(code, message string) *linkedCodexSourceError {
	return &linkedCodexSourceError{code: code, message: message}
}

func (e *linkedCodexSourceError) Error() string               { return e.message }
func (e *linkedCodexSourceError) ChatGPTWebErrorCode() string { return e.code }

func (m *Manager) refreshAuthJob(ctx context.Context, job authRefreshJob) {
	if job.expected == nil || !strings.EqualFold(strings.TrimSpace(job.expected.Provider), "chatgpt-web") {
		m.refreshAuthExpected(ctx, job.authID, job.expected, job.pendingUntil)
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if errContext := ctx.Err(); errContext != nil {
		m.clearRefreshPendingJob(job)
		return
	}
	releaseFlight, errFlight := m.beginRequestRefreshFlight()
	if errFlight != nil {
		m.clearRefreshPendingJob(job)
		return
	}
	defer releaseFlight()
	workerCtx, cancelWorker := context.WithTimeout(context.WithoutCancel(ctx), chatGPTWebRefreshFlightTimeout)
	defer cancelWorker()
	m.refreshAuthExpected(workerCtx, job.authID, job.expected, job.pendingUntil)
}

// beginRefreshExecutionLocked acquires the auth instance lease and registers it
// with cleanup while m.mu is held.
func (m *Manager) beginRefreshExecutionLocked(ctx context.Context, auth *Auth) (context.Context, func() bool, bool) {
	runtimeCtx, releaseExecution, active := auth.BeginRuntimeExecution(ctx)
	if !active || auth.instanceState == nil {
		return runtimeCtx, releaseExecution, active
	}
	done := make(chan struct{})
	tracked := m.refreshExecutions[auth.instanceState]
	if tracked == nil {
		tracked = make(map[chan struct{}]struct{})
		m.refreshExecutions[auth.instanceState] = tracked
	}
	tracked[done] = struct{}{}

	var once sync.Once
	retiredAtRelease := false
	release := func() bool {
		once.Do(func() {
			retiredAtRelease = releaseExecution()
			m.mu.Lock()
			delete(m.refreshExecutions[auth.instanceState], done)
			if len(m.refreshExecutions[auth.instanceState]) == 0 {
				delete(m.refreshExecutions, auth.instanceState)
			}
			close(done)
			m.mu.Unlock()
		})
		return retiredAtRelease
	}
	return runtimeCtx, release, true
}

func (m *Manager) refreshAuthExpected(ctx context.Context, id string, expected *Auth, pendingUntil time.Time) {
	if ctx == nil {
		ctx = context.Background()
	}
	var (
		auth                *Auth
		lockedCtx           context.Context
		releaseRequestLocks func()
	)
	for {
		m.mu.RLock()
		lockIDs := authRequestRefreshLockIDs(m.auths[id], id)
		m.mu.RUnlock()
		var errLock error
		lockedCtx, releaseRequestLocks, errLock = m.lockCredentialRefreshesContext(ctx, lockIDs)
		if errLock != nil {
			return
		}
		m.mu.Lock()
		auth = m.auths[id]
		if sameAuthRequestRefreshLockIDs(lockIDs, authRequestRefreshLockIDs(auth, id)) {
			break
		}
		m.mu.Unlock()
		releaseRequestLocks()
		if errContext := ctx.Err(); errContext != nil {
			return
		}
	}
	defer releaseRequestLocks()
	ctx = lockedCtx
	var (
		exec            ProviderExecutor
		refreshInput    *Auth
		refreshBaseline *Auth
		refreshCtx      context.Context
		releaseRefresh  func() bool
		clearedPending  bool
	)
	if expected != nil && auth != expected {
		clearedPending = clearRefreshPendingMarker(auth, pendingUntil)
		auth = nil
	} else if auth != nil && m.authExecutionBlockedLocked(ctx, auth) {
		if expected != nil && auth == expected {
			clearedPending = clearRefreshPendingMarker(auth, pendingUntil)
		}
		auth = nil
	} else if auth != nil {
		exec = m.executors[auth.Provider]
		if exec == nil && expected != nil {
			clearedPending = clearRefreshPendingMarker(auth, pendingUntil)
			auth = nil
		} else if exec != nil {
			auth.bindExecutorOwner(exec)
			refreshBaseline = auth.Clone()
			refreshInput = auth.Clone()
			var active bool
			refreshCtx, releaseRefresh, active = m.beginRefreshExecutionLocked(
				ctx,
				auth,
			)
			if !active {
				clearedPending = clearRefreshPendingMarker(auth, pendingUntil)
				auth = nil
			}
		}
	}
	m.mu.Unlock()
	if clearedPending {
		m.queueRefreshReschedule(id)
	}
	if auth == nil || exec == nil {
		return
	}
	defer releaseRefresh()
	if strings.EqualFold(strings.TrimSpace(auth.Provider), "chatgpt-web") {
		priority := RefreshPersistencePriorityMaintenance
		if ChatGPTWebImportIntent(auth, ChatGPTWebImportSessionIntent) {
			priority = RefreshPersistencePriorityImport
		}
		reservation, errReserve := m.refreshPersistence.Load().acquireContext(ctx, priority, auth.ID)
		if errReserve != nil {
			var authErr *Error
			if errors.As(errReserve, &authErr) && authErr != nil && authErr.Code == "refresh_persist_backpressure" {
				m.markChatGPTWebRefreshBackpressure(auth, pendingUntil, authErr)
			} else {
				m.clearRefreshPendingJob(authRefreshJob{authID: id, expected: auth, pendingUntil: pendingUntil})
			}
			return
		}
		defer reservation.release()
		ctx = reservation.context(ctx)
	}
	if ChatGPTWebImportIntent(auth, ChatGPTWebImportSessionIntent) {
		ctx = WithChatGPTWebImportPolicy(ctx, ChatGPTWebImportPolicy{
			ValidateModels: ChatGPTWebImportIntent(auth, ChatGPTWebImportModelsIntent),
		})
	}
	resolvedRefreshInput, errProxy := m.ResolveProxyAuth(refreshCtx, refreshInput)
	if errProxy != nil {
		m.deferRefreshAfterProxyFailure(id, auth, pendingUntil, errProxy)
		return
	}
	refreshInput = resolvedRefreshInput
	updated, err := refreshExecutorCredential(refreshCtx, exec, refreshInput)
	if err != nil {
		err = m.reportProxyFailure(refreshCtx, refreshInput, err)
	}
	retiredDuringRefresh := releaseRefresh()
	if retiredDuringRefresh || runtimeAuthInstanceRetiredContext(refreshCtx) {
		m.clearRefreshPendingJob(authRefreshJob{authID: id, expected: auth, pendingUntil: pendingUntil})
		log.Debugf("discarded stale refresh for %s, %s", auth.Provider, auth.ID)
		return
	}
	if err != nil && errors.Is(err, context.Canceled) {
		m.clearRefreshPendingJob(authRefreshJob{authID: id, expected: auth, pendingUntil: pendingUntil})
		log.Debugf("refresh canceled for %s, %s", auth.Provider, auth.ID)
		return
	}
	log.Debugf("refreshed %s, %s, %v", auth.Provider, auth.ID, err)
	now := time.Now()
	if err != nil {
		if updated != nil && persistAuthUpdateForError(err) {
			updated.NextRefreshAfter = time.Time{}
			updated.UpdatedAt = now
			if m.refreshApplyObserved != nil {
				m.refreshApplyObserved(auth.ID)
			}
			if _, errUpdate := m.applyRefreshedAuthDurably(ctx, auth.Provider, auth, refreshBaseline, updated, pendingUntil); errUpdate != nil {
				logEntryWithRequestID(ctx).WithField("auth_id", updated.ID).Warnf("failed to persist auth state after refresh error: %v", errUpdate)
			}
			return
		}
		if skipAuthResultForError(err) {
			m.deferRefreshAfterProxyFailure(id, auth, pendingUntil, err)
			return
		}
		shouldReschedule := false
		m.mu.Lock()
		if current := m.auths[id]; runtimeMetadataMutationMatchesCurrent(current, auth) {
			current.NextRefreshAfter = now.Add(refreshFailureBackoff)
			if expiry, ok := codexAccessTokenExpiration(current); ok && expiry.After(now) && expiry.Before(current.NextRefreshAfter) {
				current.NextRefreshAfter = expiry
			}
			current.LastError = executionResultError(current, err)
			m.installAuthLocked(id, current)
			shouldReschedule = true
			if m.scheduler != nil {
				m.scheduler.upsertAuthState(current.Clone())
			}
		} else if expected != nil {
			shouldReschedule = clearRefreshPendingMarker(current, pendingUntil)
		}
		m.mu.Unlock()
		if shouldReschedule {
			m.queueRefreshReschedule(id)
		}
		return
	}
	if updated == nil {
		updated = refreshInput
	}
	// Preserve runtime created by the executor during Refresh.
	// If executor didn't set one, fall back to the previous runtime.
	if updated.Runtime == nil {
		updated.Runtime = refreshBaseline.Runtime
	}
	updated.LastRefreshedAt = now
	updated.NextRefreshAfter = time.Time{}
	updated.LastError = nil
	updated.UpdatedAt = now
	if m.shouldRefresh(updated, now) {
		updated.NextRefreshAfter = now.Add(refreshIneffectiveBackoff)
	}
	if m.refreshApplyObserved != nil {
		m.refreshApplyObserved(auth.ID)
	}
	if _, errUpdate := m.applyRefreshedAuthDurably(ctx, auth.Provider, auth, refreshBaseline, updated, pendingUntil); errUpdate != nil {
		logEntryWithRequestID(ctx).WithField("auth_id", updated.ID).Warnf("failed to persist refreshed auth state: %v", errUpdate)
	}
}

func (m *Manager) applyRefreshedAuthDurably(
	ctx context.Context,
	provider string,
	expected *Auth,
	refreshBaseline *Auth,
	updated *Auth,
	pendingUntil time.Time,
) (*Auth, error) {
	if !strings.EqualFold(strings.TrimSpace(provider), "chatgpt-web") {
		return m.applyRefreshedAuth(ctx, expected, refreshBaseline, updated, pendingUntil)
	}
	if m == nil || expected == nil || updated == nil || expected.ID == "" {
		return nil, nil
	}
	return m.commitChatGPTWebRefreshDurably(ctx, expected, updated, pendingUntil, func(commitCtx context.Context) (*Auth, error) {
		return m.applyRefreshedAuth(commitCtx, expected, refreshBaseline, updated, pendingUntil)
	})
}

func (m *Manager) commitChatGPTWebRefreshDurably(
	ctx context.Context,
	expected *Auth,
	updated *Auth,
	pendingUntil time.Time,
	commit func(context.Context) (*Auth, error),
) (*Auth, error) {
	if m == nil || expected == nil || updated == nil || expected.ID == "" || commit == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	priority := RefreshPersistencePriorityMaintenance
	if unauthorized, _ := ctx.Value(chatGPTWebUnauthorizedRefreshContextKey{}).(bool); unauthorized {
		priority = RefreshPersistencePrioritySession
	} else if ChatGPTWebImportIntent(updated, ChatGPTWebImportSessionIntent) {
		priority = RefreshPersistencePriorityImport
	}
	baseCtx := context.WithValue(ctx, refreshPersistenceReservationContextKey{}, (*refreshPersistenceReservation)(nil))
	baseCtx = WithRefreshPersistenceBatchInfo(baseCtx, RefreshPersistenceBatchInfo{})
	reservation := refreshPersistenceReservationFromContext(ctx)
	reservationOwned := false
	defer func() {
		if reservationOwned {
			reservation.release()
		}
	}()
	attemptTimeout := m.refreshCommitAttemptTimeout
	if attemptTimeout <= 0 {
		attemptTimeout = refreshCommitTimeout
	}
	maxAttempts := m.refreshCommitMaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = refreshCommitAttempts
	}
	for {
		currentCoordinator := m.refreshPersistence.Load()
		if reservation == nil || reservation.coordinator != currentCoordinator {
			if reservationOwned {
				reservation.release()
				reservationOwned = false
			}
			acquired, errReserve := currentCoordinator.acquireContext(baseCtx, priority, expected.ID)
			if errReserve != nil {
				if m.refreshPersistence.Load() != currentCoordinator {
					reservation = nil
					continue
				}
				var authErr *Error
				if errors.As(errReserve, &authErr) && authErr != nil && authErr.Code == "refresh_persist_backpressure" {
					m.markChatGPTWebRefreshBackpressure(expected, pendingUntil, authErr)
				}
				return nil, errReserve
			}
			reservation = acquired
			reservationOwned = true
		}

		commitBaseCtx := reservation.context(baseCtx)
		commitBaseCtx = withRefreshPersistenceCoordinatorExpectation(commitBaseCtx, currentCoordinator)
		if m.refreshPersistence.Load() != currentCoordinator {
			continue
		}

		var lastErr error
		storeChanged := false
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			commitCtx, cancelCommit := context.WithTimeout(context.WithoutCancel(commitBaseCtx), attemptTimeout)
			saved, errCommit := commit(commitCtx)
			cancelCommit()
			if errCommit == nil {
				return saved, nil
			}
			if errors.Is(errCommit, errRefreshPersistenceStoreChanged) {
				storeChanged = true
				break
			}
			lastErr = errCommit
			if errors.Is(errCommit, ErrRefreshPersistenceSuperseded) {
				return nil, ErrAuthMutationIdentityChanged
			}
			if errors.Is(errCommit, ErrAuthMutationIdentityChanged) {
				return nil, errCommit
			}
			if outcome, explicit := SaveOutcomeFromError(errCommit); explicit && outcome == SaveOutcomeRolledBack {
				failure := newChatGPTWebRefreshCommitFailure(updated)
				if m.markChatGPTWebRefreshCommitFailure(expected, updated, pendingUntil, failure) {
					m.logChatGPTWebRefreshCommitFailure(ctx, expected.ID, errCommit)
					return nil, failure
				}
				return nil, errCommit
			}
			if attempt < maxAttempts && m.refreshCommitRetryObserved != nil {
				m.refreshCommitRetryObserved(expected.ID, attempt)
			}
		}
		if storeChanged {
			if m.refreshPersistence.Load() == currentCoordinator {
				return nil, errRefreshPersistenceStoreChanged
			}
			continue
		}
		failure := newChatGPTWebRefreshCommitFailure(updated)
		m.markChatGPTWebRefreshCommitFailure(expected, updated, pendingUntil, failure)
		m.logChatGPTWebRefreshCommitFailure(ctx, expected.ID, lastErr)
		return nil, failure
	}
}

func (m *Manager) markChatGPTWebRefreshBackpressure(expected *Auth, pendingUntil time.Time, failure *Error) {
	if m == nil || expected == nil || failure == nil {
		return
	}
	now := time.Now()
	var snapshot *Auth
	m.mu.Lock()
	current := m.auths[expected.ID]
	if runtimeMetadataMutationMatchesCurrent(current, expected) {
		current.LastError = failure
		current.NextRefreshAfter = now.Add(refreshFailureBackoff)
		current.UpdatedAt = now
		clearRefreshPendingMarker(current, pendingUntil)
		m.installAuthLocked(current.ID, current)
		snapshot = current.Clone()
		if m.scheduler != nil {
			m.scheduler.upsertAuthState(snapshot)
		}
	}
	m.mu.Unlock()
	if snapshot != nil {
		m.queueRefreshReschedule(snapshot.ID)
		m.Hook().OnAuthUpdated(context.Background(), snapshot.Clone())
	}
}

func newChatGPTWebRefreshCommitFailure(updated *Auth) *Error {
	retryable := chatGPTWebRefreshCommitCanRetry(updated)
	return &Error{
		Code:       "refresh_persist_failed",
		Message:    "refreshed credential could not be persisted",
		Retryable:  retryable,
		HTTPStatus: http.StatusServiceUnavailable,
	}
}

func chatGPTWebRefreshCommitCanRetry(auth *Auth) bool {
	if auth == nil {
		return false
	}
	credential, errCredential := chatgptwebauth.ParseCredential(auth.Metadata)
	if errCredential != nil || credential == nil {
		return false
	}
	return credential.RefreshStrategy == chatgptwebauth.RefreshStrategyChatGPTSession ||
		credential.RefreshStrategy == chatgptwebauth.RefreshStrategyCodexSource
}

func (m *Manager) markChatGPTWebRefreshCommitFailure(expected, updated *Auth, pendingUntil time.Time, failure *Error) bool {
	if m == nil || expected == nil || failure == nil {
		return false
	}
	now := time.Now()
	var snapshot *Auth
	reschedule := false
	m.mu.Lock()
	current := m.auths[expected.ID]
	if runtimeMetadataMutationMatchesCurrent(current, expected) {
		if chatGPTWebRefreshCommitCanRetry(updated) {
			current.LastError = failure
			current.NextRefreshAfter = now.Add(refreshFailureBackoff)
			current.UpdatedAt = now
			clearRefreshPendingMarker(current, pendingUntil)
			reschedule = true
		} else {
			if current.Metadata == nil {
				current.Metadata = make(map[string]any)
			}
			current.Metadata["lifecycle_state"] = LifecycleStateReauthRequired
			current.Metadata["lifecycle_reason"] = failure.Code
			current.Metadata["lifecycle_updated_at"] = now.UTC().Format(time.RFC3339)
			current.LastError = failure
			current.NextRefreshAfter = time.Time{}
			current.UpdatedAt = now
			clearRefreshPendingMarker(current, pendingUntil)
			applyLifecycleRuntimeState(current)
		}
		m.updateManagementAuthCatalogLocked(current)
		snapshot = current.Clone()
	}
	m.mu.Unlock()
	if snapshot != nil && m.scheduler != nil {
		m.scheduler.upsertAuthState(snapshot)
	}
	if reschedule {
		m.queueRefreshReschedule(expected.ID)
	}
	return snapshot != nil
}

func (m *Manager) logChatGPTWebRefreshCommitFailure(ctx context.Context, authID string, err error) {
	logEntryWithRequestID(ctx).
		WithField("auth_id", authID).
		WithError(err).
		Error("failed to persist refreshed ChatGPT Web credential")
}

func (m *Manager) deferRefreshAfterProxyFailure(id string, expected *Auth, pendingUntil time.Time, err error) {
	if m == nil || strings.TrimSpace(id) == "" {
		return
	}
	delay := refreshFailureBackoff
	if retryAfter := retryAfterFromError(err); retryAfter != nil && *retryAfter > 0 {
		delay = *retryAfter
	}
	next := time.Now().Add(delay)
	shouldReschedule := false
	m.mu.Lock()
	if current := m.auths[id]; runtimeMetadataMutationMatchesCurrent(current, expected) {
		current.NextRefreshAfter = next
		shouldReschedule = true
	} else if expected != nil {
		shouldReschedule = clearRefreshPendingMarker(current, pendingUntil)
	}
	m.mu.Unlock()
	if shouldReschedule {
		m.queueRefreshReschedule(id)
	}
}

func (m *Manager) applyRefreshedAuth(ctx context.Context, expected, refreshBaseline, updated *Auth, pendingUntil time.Time) (*Auth, error) {
	if m == nil || expected == nil || updated == nil || expected.ID == "" {
		return nil, nil
	}
	id := expected.ID
	updated.ID = id
	clearRuntimeProxy(updated)
	if IsRetiredGeminiCLIAuth(updated) {
		result, errRetired := m.handleRetiredAuth(ctx, updated, expected)
		if result == nil {
			m.mu.Lock()
			clearedPending := false
			if current := m.auths[id]; !runtimeMetadataMutationMatchesCurrent(current, expected) {
				clearedPending = clearRefreshPendingMarker(current, pendingUntil)
			}
			m.mu.Unlock()
			if clearedPending {
				m.queueRefreshReschedule(id)
			}
		}
		return result, errRetired
	}
	refreshOutput := updated.Clone()
	refreshIdentityChanged := ChatGPTWebCredentialRefreshIdentityChanged(refreshBaseline, refreshOutput)
	requestUnauthorized, _ := ctx.Value(chatGPTWebUnauthorizedRefreshContextKey{}).(bool)
	requestUnauthorized = requestUnauthorized && refreshBaseline != nil && refreshBaseline.LastError != nil &&
		(refreshBaseline.LastError.StatusCode() == http.StatusUnauthorized || strings.EqualFold(refreshBaseline.LastError.Code, "unauthorized"))
	unlockPersist, errLock := m.lockAuthIDMutationContext(ctx, id)
	if errLock != nil {
		return nil, errLock
	}

	m.mu.Lock()
	current := m.auths[id]
	if !runtimeMetadataMutationMatchesCurrent(current, expected) {
		clearedPending := clearRefreshPendingMarker(current, pendingUntil)
		m.mu.Unlock()
		unlockPersist()
		if clearedPending {
			m.queueRefreshReschedule(id)
		}
		return nil, nil
	}
	if !updated.indexAssigned && updated.Index == "" {
		updated.Index = current.Index
		updated.indexAssigned = current.indexAssigned
	}
	updated.EnsureIndex()
	if !refreshIdentityChanged {
		carryForwardConcurrentRefreshMetadata(refreshBaseline, current, refreshOutput, updated)
	}
	carryForwardConfiguredAuthWeight(current, updated)
	carryForwardConfiguredRequestScopedErrors(current, updated)
	credentialChanged := prepareRefreshedChatGPTWebCredentialReplacement(current, updated, time.Now())
	if !credentialChanged {
		carryForwardConcurrentRefreshRuntimeState(refreshBaseline, current, updated)
	}
	clearUnauthorizedRefreshState(updated, time.Now(), requestUnauthorized)
	expectedSourceHash := authSourceHash(current)
	m.mu.Unlock()

	persistCtx := ctx
	if expectedSourceHash != "" && m.SupportsSourceConditionalSave() {
		persistCtx = WithSourceHashSavePrecondition(persistCtx, expectedSourceHash)
	}
	if errPersist := m.persistWithoutLock(persistCtx, updated, false); errPersist != nil {
		unlockPersist()
		return nil, errPersist
	}

	m.mu.Lock()
	current = m.auths[id]
	if !runtimeMetadataMutationMatchesCurrent(current, expected) {
		clearedPending := clearRefreshPendingMarker(current, pendingUntil)
		m.mu.Unlock()
		unlockPersist()
		if clearedPending {
			m.queueRefreshReschedule(id)
		}
		return nil, nil
	}
	if !refreshIdentityChanged {
		carryForwardConcurrentRefreshMetadata(refreshBaseline, current, refreshOutput, updated)
	}
	carryForwardConfiguredAuthWeight(current, updated)
	carryForwardConfiguredRequestScopedErrors(current, updated)
	credentialChanged = prepareRefreshedChatGPTWebCredentialReplacement(current, updated, time.Now())
	if !credentialChanged {
		carryForwardConcurrentRefreshRuntimeState(refreshBaseline, current, updated)
	}
	modelsToResume := clearUnauthorizedRefreshState(updated, time.Now(), requestUnauthorized)
	updated.EnsureIndex()
	preserveRuntimeInstance := isNativeChatGPTWebCredentialAuth(updated) && !credentialChanged
	var replaced *Auth
	if !preserveRuntimeInstance {
		m.beginAuthInstanceCleanupLocked(id)
		replaced = current.Clone()
	}
	updatedClone := updated.Clone()
	updatedClone.installationID = uuid.NewString()
	if preserveRuntimeInstance {
		updatedClone.instanceID = current.instanceID
		updatedClone.instanceState = current.instanceState
	} else {
		updatedClone.instanceID = uuid.NewString()
		updatedClone.instanceState = &authInstanceState{}
		updatedClone.bindExecutorOwner(m.executors[executorKeyFromAuth(updatedClone)])
	}
	if credentialChanged {
		updatedClone.requestRefreshFamilyID = uuid.NewString()
	} else {
		updatedClone.requestRefreshFamilyID = expected.requestRefreshFamilyID
		if updatedClone.requestRefreshFamilyID == "" {
			updatedClone.requestRefreshFamilyID = uuid.NewString()
		}
	}
	m.installAuthLocked(id, updatedClone)
	if strings.EqualFold(strings.TrimSpace(updatedClone.Provider), "chatgpt-web") {
		if lockValue, ok := m.requestRefreshLocks.Load(id); ok {
			if requestLock, _ := lockValue.(*authRequestRefreshLock); requestLock != nil {
				requestLock.remember(updatedClone.Provider, expected, updatedClone)
			}
		}
	}
	m.mu.Unlock()

	if isAPIKeyAuth(current) || isAPIKeyAuth(updatedClone) {
		m.rebuildAPIKeyModelAliasFromRuntimeConfig()
	}
	if m.scheduler != nil {
		m.scheduler.upsertAuth(updatedClone)
	}
	for _, model := range modelsToResume {
		registry.GetGlobalRegistry().ResumeClientModel(id, model)
	}
	result := updatedClone.Clone()
	unlockPersist()
	hookCtx := withoutChatGPTWebCredentialUpdateMarkers(ctx)
	if credentialChanged {
		hookCtx = withChatGPTWebCredentialReplacement(hookCtx)
	} else if isNativeChatGPTWebCredentialAuth(updatedClone) {
		hookCtx = withChatGPTWebCredentialRefresh(hookCtx)
	}
	notifyUpdated := func() {
		if !m.authInstallationCurrent(updatedClone) {
			return
		}
		m.Hook().OnAuthUpdated(hookCtx, result.Clone())
	}
	if replaced != nil {
		m.finishAuthSessionCleanup(id, replaced, "auth_refreshed", notifyUpdated)
	} else {
		notifyUpdated()
	}
	return result, nil
}

func carryForwardConcurrentRefreshRuntimeState(baseline, current, next *Auth) {
	if baseline == nil || current == nil || next == nil {
		return
	}
	if baseline.Status == current.Status &&
		baseline.StatusMessage == current.StatusMessage &&
		baseline.Unavailable == current.Unavailable &&
		reflect.DeepEqual(baseline.LastError, current.LastError) &&
		baseline.NextRetryAfter.Equal(current.NextRetryAfter) &&
		baseline.CooldownScope == current.CooldownScope &&
		baseline.Quota == current.Quota &&
		baseline.UpdatedAt.Equal(current.UpdatedAt) &&
		reflect.DeepEqual(baseline.ModelStates, current.ModelStates) {
		applyLifecycleRuntimeState(next)
		return
	}
	next.Status = current.Status
	next.StatusMessage = current.StatusMessage
	next.Unavailable = current.Unavailable
	next.LastError = cloneError(current.LastError)
	next.NextRetryAfter = current.NextRetryAfter
	next.CooldownScope = current.CooldownScope
	next.Quota = current.Quota
	next.UpdatedAt = current.UpdatedAt
	next.ModelStates = cloneAuthModelStates(current.ModelStates)
	applyLifecycleRuntimeState(next)
}

func carryForwardConcurrentRefreshMetadata(baseline, current, refreshed, next *Auth) {
	if baseline == nil || current == nil || refreshed == nil || next == nil {
		return
	}
	if strings.EqualFold(strings.TrimSpace(current.Provider), "codex") {
		next.Metadata = mergeCodexRefreshMetadata(baseline.Metadata, current.Metadata, refreshed.Metadata)
		return
	}
	baselineCredential, errBaseline := chatgptwebauth.ParseCredential(baseline.Metadata)
	currentCredential, errCurrent := chatgptwebauth.ParseCredential(current.Metadata)
	refreshedCredential, errRefreshed := chatgptwebauth.ParseCredential(refreshed.Metadata)
	if errBaseline == nil && errCurrent == nil && errRefreshed == nil {
		switch {
		case reflect.DeepEqual(currentCredential.Cookies, baselineCredential.Cookies):
			value, present := authMetadataEntry(refreshed.Metadata, "cookies")
			setAuthMetadataEntry(next, "cookies", value, present)
		case reflect.DeepEqual(refreshedCredential.Cookies, baselineCredential.Cookies):
			value, present := authMetadataEntry(current.Metadata, "cookies")
			setAuthMetadataEntry(next, "cookies", value, present)
		default:
			cookies := chatgptwebauth.MergeCookieDelta(
				currentCredential.Cookies,
				baselineCredential.Cookies,
				refreshedCredential.Cookies,
			)
			setAuthMetadataEntry(next, "cookies", append([]chatgptwebauth.Cookie(nil), cookies...), true)
		}
		carryForwardConcurrentWebAuthnMetadata(baselineCredential, currentCredential, refreshedCredential, next)
		carryForwardConcurrentAdvancedAccountSecurityMetadata(baselineCredential, currentCredential, refreshedCredential, next)
	}

	for _, key := range []string{
		"persona",
		"device_id",
		"session_id",
		"account_id",
		"user_id",
		"plan_type",
		"profile_updated_at",
		"image_quota_remaining",
		"image_quota_reset_at",
		"quota_state",
		"quota_updated_at",
		"quota_stale",
		"quota_last_error",
		"login_method",
		"api798_url",
	} {
		baselineValue, baselineOK := authMetadataEntry(baseline.Metadata, key)
		currentValue, currentOK := authMetadataEntry(current.Metadata, key)
		refreshedValue, refreshedOK := authMetadataEntry(refreshed.Metadata, key)
		baselineCompareValue, baselineCompareOK := baselineValue, baselineOK
		currentCompareValue, currentCompareOK := currentValue, currentOK
		refreshedCompareValue, refreshedCompareOK := refreshedValue, refreshedOK
		if errBaseline == nil && errCurrent == nil && errRefreshed == nil {
			baselineCompareValue, baselineCompareOK = chatGPTWebCredentialMetadataEntry(baselineCredential, key)
			currentCompareValue, currentCompareOK = chatGPTWebCredentialMetadataEntry(currentCredential, key)
			refreshedCompareValue, refreshedCompareOK = chatGPTWebCredentialMetadataEntry(refreshedCredential, key)
		}
		if !authMetadataEntriesEqual(currentCompareValue, currentCompareOK, baselineCompareValue, baselineCompareOK) &&
			authMetadataEntriesEqual(refreshedCompareValue, refreshedCompareOK, baselineCompareValue, baselineCompareOK) {
			setAuthMetadataEntry(next, key, currentValue, currentOK)
			continue
		}
		setAuthMetadataEntry(next, key, refreshedValue, refreshedOK)
	}
}

func carryForwardConcurrentWebAuthnMetadata(
	baseline, current, refreshed *chatgptwebauth.Credential,
	next *Auth,
) {
	if baseline == nil || current == nil || refreshed == nil || next == nil ||
		baseline.WebAuthn == nil || current.WebAuthn == nil || refreshed.WebAuthn == nil ||
		!chatgptwebauth.WebAuthnAuthenticatorMatches(baseline.WebAuthn, current.WebAuthn) ||
		!chatgptwebauth.WebAuthnAuthenticatorMatches(baseline.WebAuthn, refreshed.WebAuthn) {
		return
	}
	merged := *refreshed.WebAuthn
	merged.Transports = append([]string(nil), refreshed.WebAuthn.Transports...)
	if current.WebAuthn.SignCount > merged.SignCount {
		merged.SignCount = current.WebAuthn.SignCount
	}
	if chatgptwebauth.CompareWebAuthnLastUsedAt(current.WebAuthn.LastUsedAt, merged.LastUsedAt) > 0 {
		merged.LastUsedAt = current.WebAuthn.LastUsedAt
	}
	setAuthMetadataEntry(next, "webauthn", &merged, true)
}

func carryForwardConcurrentAdvancedAccountSecurityMetadata(
	baseline, current, refreshed *chatgptwebauth.Credential,
	next *Auth,
) {
	if baseline == nil || current == nil || refreshed == nil || next == nil ||
		baseline.AdvancedAccountSecurity == nil || current.AdvancedAccountSecurity == nil || refreshed.AdvancedAccountSecurity == nil ||
		!chatgptwebauth.AdvancedAccountSecurityMaterialMatches(baseline.AdvancedAccountSecurity, current.AdvancedAccountSecurity) ||
		!chatgptwebauth.AdvancedAccountSecurityMaterialMatches(baseline.AdvancedAccountSecurity, refreshed.AdvancedAccountSecurity) {
		return
	}
	merged := chatgptwebauth.CloneAdvancedAccountSecurityCredential(refreshed.AdvancedAccountSecurity)
	chatgptwebauth.MergeAdvancedAccountSecurityRuntimeState(merged, current.AdvancedAccountSecurity)
	setAuthMetadataEntry(next, "advanced_account_security", merged, true)
}

func chatGPTWebCredentialMetadataEntry(credential *chatgptwebauth.Credential, key string) (any, bool) {
	if credential == nil {
		return nil, false
	}
	switch key {
	case "persona":
		return credential.Persona, true
	case "device_id":
		return strings.TrimSpace(credential.DeviceID), true
	case "session_id":
		return strings.TrimSpace(credential.SessionID), true
	case "account_id":
		return strings.TrimSpace(credential.AccountID), true
	case "user_id":
		return strings.TrimSpace(credential.UserID), true
	case "plan_type":
		return strings.TrimSpace(credential.PlanType), true
	case "profile_updated_at":
		return strings.TrimSpace(credential.ProfileUpdatedAt), true
	case "image_quota_remaining":
		if credential.ImageQuotaRemaining == nil {
			return nil, false
		}
		return *credential.ImageQuotaRemaining, true
	case "image_quota_reset_at":
		return strings.TrimSpace(credential.ImageQuotaResetAt), true
	case "quota_state":
		return chatgptwebauth.NormalizeQuotaState(credential.QuotaState, credential.ImageQuotaRemaining), true
	case "quota_updated_at":
		return strings.TrimSpace(credential.QuotaUpdatedAt), true
	case "quota_stale":
		return credential.QuotaStale, true
	case "quota_last_error":
		return chatgptwebauth.SafeQuotaError(credential.QuotaLastError), true
	case "login_method":
		method, errNormalize := chatgptwebauth.NormalizeLoginMethod(credential.LoginMethod)
		if errNormalize != nil {
			return nil, false
		}
		return string(method), true
	case "api798_url":
		if credential.API798URL == "" {
			return nil, false
		}
		return credential.API798URL, true
	default:
		return nil, false
	}
}

func authMetadataEntry(metadata map[string]any, key string) (any, bool) {
	if metadata == nil {
		return nil, false
	}
	value, ok := metadata[key]
	return value, ok
}

func authMetadataEntriesEqual(first any, firstOK bool, second any, secondOK bool) bool {
	return firstOK == secondOK && reflect.DeepEqual(first, second)
}

func setAuthMetadataEntry(auth *Auth, key string, value any, present bool) {
	if auth == nil {
		return
	}
	if !present {
		if auth.Metadata != nil {
			delete(auth.Metadata, key)
		}
		return
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata[key] = value
}

func clearRefreshPendingMarker(auth *Auth, pendingUntil time.Time) bool {
	if auth != nil && !pendingUntil.IsZero() && auth.NextRefreshAfter.Equal(pendingUntil) {
		auth.NextRefreshAfter = time.Time{}
		return true
	}
	return false
}

func (m *Manager) clearRefreshPendingJob(job authRefreshJob) {
	if m == nil || job.authID == "" || job.expected == nil || job.pendingUntil.IsZero() {
		return
	}
	m.mu.Lock()
	cleared := clearRefreshPendingMarker(m.auths[job.authID], job.pendingUntil)
	m.mu.Unlock()
	if cleared {
		m.queueRefreshReschedule(job.authID)
	}
}

func (m *Manager) executorFor(provider string) ProviderExecutor {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.executors[provider]
}

// roundTripperContextKey is an unexported context key type to avoid collisions.
type roundTripperContextKey struct{}

// roundTripperFor retrieves an HTTP RoundTripper for the given auth if a provider is registered.
func (m *Manager) roundTripperFor(auth *Auth) http.RoundTripper {
	m.rtProviderMu.RLock()
	defer m.rtProviderMu.RUnlock()
	if m.rtProviderClosed || !m.authInstallationCurrent(auth) {
		return nil
	}
	m.mu.RLock()
	p := m.rtProvider
	m.mu.RUnlock()
	if p == nil || auth == nil {
		return nil
	}
	return p.RoundTripperFor(auth)
}

func (m *Manager) evictRoundTripperForAuth(authID string) {
	m.rtProviderMu.Lock()
	defer m.rtProviderMu.Unlock()
	m.mu.RLock()
	provider := m.rtProvider
	m.mu.RUnlock()
	if evicter, ok := provider.(interface{ EvictAuth(string) }); ok && evicter != nil {
		evicter.EvictAuth(authID)
	}
}

func (m *Manager) closeRoundTripperProvider() {
	m.rtProviderMu.Lock()
	defer m.rtProviderMu.Unlock()
	if m.rtProviderClosed {
		return
	}
	m.rtProviderClosed = true
	m.mu.RLock()
	provider := m.rtProvider
	m.mu.RUnlock()
	if closer, ok := provider.(interface{ CloseIdleConnections() }); ok && closer != nil {
		closer.CloseIdleConnections()
	}
}

// RoundTripperProvider defines a minimal provider of per-auth HTTP transports.
type RoundTripperProvider interface {
	RoundTripperFor(auth *Auth) http.RoundTripper
}

// RequestPreparer is an optional interface that provider executors can implement
// to mutate outbound HTTP requests with provider credentials.
type RequestPreparer interface {
	PrepareRequest(req *http.Request, auth *Auth) error
}

func executorKeyFromAuth(auth *Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Attributes != nil {
		providerKey := strings.TrimSpace(auth.Attributes["provider_key"])
		compatName := strings.TrimSpace(auth.Attributes["compat_name"])
		if compatName != "" {
			if providerKey == "" {
				providerKey = compatName
			}
			return strings.ToLower(providerKey)
		}
	}
	return strings.ToLower(strings.TrimSpace(auth.Provider))
}

// logEntryWithRequestID returns a logrus entry with request_id field if available in context.
func logEntryWithRequestID(ctx context.Context) *log.Entry {
	if ctx == nil {
		return log.NewEntry(log.StandardLogger())
	}
	if reqID := logging.GetRequestID(ctx); reqID != "" {
		return log.WithField("request_id", reqID)
	}
	return log.NewEntry(log.StandardLogger())
}

func debugLogAuthSelection(entry *log.Entry, auth *Auth, provider string, model string) {
	if !log.IsLevelEnabled(log.DebugLevel) {
		return
	}
	if entry == nil || auth == nil {
		return
	}
	accountType, accountInfo := auth.AccountInfo()
	proxyInfo := auth.ProxyInfo()
	suffix := ""
	if proxyInfo != "" {
		suffix = " " + proxyInfo
	}
	switch accountType {
	case "api_key":
		entry.Debugf("Use API key %s for model %s%s", util.HideAPIKey(accountInfo), model, suffix)
	case "oauth":
		ident := formatOauthIdentity(auth, provider, accountInfo)
		entry.Debugf("Use OAuth %s for model %s%s", ident, model, suffix)
	}
}

func formatOauthIdentity(auth *Auth, provider string, accountInfo string) string {
	if auth == nil {
		return ""
	}
	// Prefer the auth's provider when available.
	providerName := strings.TrimSpace(auth.Provider)
	if providerName == "" {
		providerName = strings.TrimSpace(provider)
	}
	// Only log the basename to avoid leaking host paths.
	// FileName may be unset for some auth backends; fall back to ID.
	authFile := strings.TrimSpace(auth.FileName)
	if authFile == "" {
		authFile = strings.TrimSpace(auth.ID)
	}
	if authFile != "" {
		authFile = filepath.Base(authFile)
	}
	parts := make([]string, 0, 3)
	if providerName != "" {
		parts = append(parts, "provider="+providerName)
	}
	if authFile != "" {
		parts = append(parts, "auth_file="+authFile)
	}
	if len(parts) == 0 {
		return accountInfo
	}
	return strings.Join(parts, " ")
}

func (m *Manager) beginCurrentAuthExecution(ctx context.Context, auth *Auth, executor ProviderExecutor) (context.Context, func() bool, bool) {
	if m == nil {
		return ctx, func() bool { return false }, false
	}
	m.mu.RLock()
	current := m.auths[auth.ID]
	managedInstance := current != nil || auth.instanceID != ""
	if managedInstance && (current == nil || current.instanceID != auth.instanceID || current.instanceState != auth.instanceState || m.authExecutionBlockedLocked(ctx, current)) {
		m.mu.RUnlock()
		return ctx, func() bool { return true }, false
	}
	auth.bindExecutorOwner(executor)
	runtimeCtx, releaseExecution, active := auth.BeginRuntimeExecution(ctx)
	m.mu.RUnlock()
	return runtimeCtx, releaseExecution, active
}

// InjectCredentials delegates per-provider HTTP request preparation when supported.
// If the registered executor for the auth provider implements RequestPreparer,
// it will be invoked to modify the request (e.g., add headers).
func (m *Manager) InjectCredentials(req *http.Request, authID string) error {
	if req == nil {
		return &Error{Code: "invalid_request", Message: "http request is nil"}
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return &Error{Code: "auth_not_found", Message: "auth id is empty"}
	}
	m.mu.RLock()
	a := m.auths[authID]
	var exec ProviderExecutor
	if a != nil {
		exec = m.executors[executorKeyFromAuth(a)]
	}
	m.mu.RUnlock()
	if a == nil {
		return &Error{Code: "auth_not_found", Message: "auth not found: " + authID}
	}
	if a.RuntimeInstanceRetired() {
		return runtimeAuthInstanceRetiredError()
	}
	if exec == nil {
		return &Error{Code: "provider_not_found", Message: "executor not registered for provider: " + executorKeyFromAuth(a)}
	}
	if p, ok := exec.(RequestPreparer); ok && p != nil {
		requestCtx := req.Context()
		runtimeCtx, releaseExecution, active := m.beginCurrentAuthExecution(requestCtx, a, exec)
		if !active {
			return runtimeAuthInstanceRetiredError()
		}
		*req = *req.WithContext(runtimeCtx)
		errPrepare := p.PrepareRequest(req, a)
		retiredDuringPreparation := releaseExecution()
		*req = *req.WithContext(requestCtx)
		if retiredDuringPreparation {
			return runtimeAuthInstanceRetiredError()
		}
		return errPrepare
	}
	return nil
}

// PrepareHttpRequest injects provider credentials into the supplied HTTP request.
func (m *Manager) PrepareHttpRequest(ctx context.Context, auth *Auth, req *http.Request) error {
	if m == nil {
		return &Error{Code: "provider_not_found", Message: "manager is nil"}
	}
	if auth == nil {
		return &Error{Code: "auth_not_found", Message: "auth is nil"}
	}
	if req == nil {
		return &Error{Code: "invalid_request", Message: "http request is nil"}
	}
	if IsRetiredGeminiCLIAuth(auth) {
		WarnRetiredGeminiCLIAuthIgnored()
		return retiredGeminiCLIAuthError()
	}
	if auth.RuntimeInstanceRetired() {
		return runtimeAuthInstanceRetiredError()
	}
	providerKey := executorKeyFromAuth(auth)
	if providerKey == "" {
		return &Error{Code: "provider_not_found", Message: "auth provider is empty"}
	}
	exec := m.executorFor(providerKey)
	if exec == nil {
		return &Error{Code: "provider_not_found", Message: "executor not registered for provider: " + providerKey}
	}
	preparer, ok := exec.(RequestPreparer)
	if !ok || preparer == nil {
		return &Error{Code: "not_supported", Message: "executor does not support http request preparation"}
	}
	requestCtx := req.Context()
	if ctx == nil {
		ctx = requestCtx
	}
	runtimeCtx, releaseExecution, active := m.beginCurrentAuthExecution(ctx, auth, exec)
	if !active {
		return runtimeAuthInstanceRetiredError()
	}
	*req = *req.WithContext(runtimeCtx)
	errPrepare := preparer.PrepareRequest(req, auth)
	retiredDuringPreparation := releaseExecution()
	*req = *req.WithContext(ctx)
	if retiredDuringPreparation {
		return runtimeAuthInstanceRetiredError()
	}
	return errPrepare
}

// NewHttpRequest constructs a new HTTP request and injects provider credentials into it.
func (m *Manager) NewHttpRequest(ctx context.Context, auth *Auth, method, targetURL string, body []byte, headers http.Header) (*http.Request, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	method = strings.TrimSpace(method)
	if method == "" {
		method = http.MethodGet
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, targetURL, reader)
	if err != nil {
		return nil, err
	}
	if headers != nil {
		httpReq.Header = headers.Clone()
	}
	if errPrepare := m.PrepareHttpRequest(ctx, auth, httpReq); errPrepare != nil {
		return nil, errPrepare
	}
	return httpReq, nil
}

// HttpRequest injects provider credentials into the supplied HTTP request and executes it.
func (m *Manager) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	if m == nil {
		return nil, &Error{Code: "provider_not_found", Message: "manager is nil"}
	}
	if auth == nil {
		return nil, &Error{Code: "auth_not_found", Message: "auth is nil"}
	}
	if req == nil {
		return nil, &Error{Code: "invalid_request", Message: "http request is nil"}
	}
	if IsRetiredGeminiCLIAuth(auth) {
		WarnRetiredGeminiCLIAuthIgnored()
		return nil, retiredGeminiCLIAuthError()
	}
	providerKey := executorKeyFromAuth(auth)
	if providerKey == "" {
		return nil, &Error{Code: "provider_not_found", Message: "auth provider is empty"}
	}
	exec := m.executorFor(providerKey)
	if exec == nil {
		return nil, &Error{Code: "provider_not_found", Message: "executor not registered for provider: " + providerKey}
	}
	if ctx == nil {
		ctx = req.Context()
	}
	resolvedAuth, errProxy := m.ResolveProxyAuth(ctx, auth)
	if errProxy != nil {
		return nil, errProxy
	}
	auth = resolvedAuth
	runtimeCtx, releaseExecution, active := m.beginCurrentAuthExecution(ctx, auth, exec)
	if !active {
		return nil, runtimeAuthInstanceRetiredError()
	}
	httpReq := req.WithContext(runtimeCtx)
	resp, errRequest := exec.HttpRequest(runtimeCtx, auth, httpReq)
	if errRequest != nil || resp == nil || resp.Body == nil {
		errRequest = m.reportProxyFailure(runtimeCtx, auth, errRequest)
		retiredDuringExecution := releaseExecution()
		if retiredDuringExecution || runtimeAuthInstanceRetiredContext(runtimeCtx) {
			return resp, runtimeAuthInstanceRetiredError()
		}
		return resp, errRequest
	}
	resp.Body = &runtimeExecutionResponseBody{ReadCloser: resp.Body, release: releaseExecution}
	return resp, nil
}

func resolveXAIAPIKeyConfig(cfg *internalconfig.Config, auth *Auth) *internalconfig.XAIKey {
	if cfg == nil {
		return nil
	}
	return resolveAPIKeyConfigExact(cfg.XAIKey, auth)
}
