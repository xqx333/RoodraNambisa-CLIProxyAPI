package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	baseauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth"
)

// PostAuthHook defines a function that is called after an Auth record is created
// but before it is persisted to storage. This allows for modification of the
// Auth record (e.g., injecting metadata) based on external context.
type PostAuthHook func(context.Context, *Auth) error

// AuthStatusHook defines a callback invoked after a management status change
// updates an Auth record in the runtime manager.
type AuthStatusHook func(context.Context, *Auth)

// RequestInfo holds information extracted from the HTTP request.
// It is injected into the context passed to PostAuthHook.
type RequestInfo struct {
	Query   url.Values
	Headers http.Header
}

type requestInfoKey struct{}

const (
	// SourceHashAttributeKey stores a synthesized content fingerprint for file-backed auths.
	SourceHashAttributeKey = "_source_hash"
)

// SourceHashFromBytes returns the stable content hash used to detect auth file replacements.
func SourceHashFromBytes(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// CanonicalSourceHashFromBytes returns the stable JSON metadata hash used by
// file-backed auth records. Non-JSON payloads return an error.
func CanonicalSourceHashFromBytes(data []byte) (string, error) {
	metadata := make(map[string]any)
	if err := json.Unmarshal(data, &metadata); err != nil {
		return "", err
	}
	disabled, _ := metadata["disabled"].(bool)
	metadata["disabled"] = disabled
	canonical, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	return SourceHashFromBytes(canonical), nil
}

// SourceHashMatchesBytes accepts either an exact payload hash or the canonical
// JSON metadata hash. PostgreSQL JSONB normalizes object serialization, while
// file, git, and object stores preserve the original bytes.
func SourceHashMatchesBytes(expectedHash string, data []byte) bool {
	expectedHash = strings.TrimSpace(expectedHash)
	if expectedHash == "" {
		return false
	}
	if SourceHashFromBytes(data) == expectedHash {
		return true
	}
	canonicalHash, err := CanonicalSourceHashFromBytes(data)
	return err == nil && canonicalHash == expectedHash
}

// SetSourceHashAttribute stores a stable file-content hash on the auth attributes.
func SetSourceHashAttribute(auth *Auth, data []byte) {
	if auth == nil {
		return
	}
	hash := SourceHashFromBytes(data)
	if hash == "" {
		return
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes[SourceHashAttributeKey] = hash
}

// CanonicalMetadataBytes returns the canonical serialized metadata used for
// file-backed auth persistence and source hash generation.
func CanonicalMetadataBytes(auth *Auth) ([]byte, error) {
	if auth == nil || auth.Metadata == nil {
		return nil, nil
	}
	metadata := MetadataWithDisabled(auth)
	if metadata == nil {
		return nil, nil
	}
	return json.Marshal(metadata)
}

// MetadataWithDisabled clones runtime metadata and injects the current disabled
// flag so persistence and source hashes use a consistent payload.
func MetadataWithDisabled(auth *Auth) map[string]any {
	if auth == nil || auth.Metadata == nil {
		return nil
	}
	metadata := make(map[string]any, len(auth.Metadata)+1)
	for key, value := range auth.Metadata {
		metadata[key] = value
	}
	metadata["disabled"] = auth.Disabled
	return metadata
}

// SetCanonicalSourceHashAttribute stores a source hash derived from the
// canonical serialized metadata representation.
func SetCanonicalSourceHashAttribute(auth *Auth) error {
	raw, err := CanonicalMetadataBytes(auth)
	if err != nil {
		return err
	}
	SetSourceHashAttribute(auth, raw)
	return nil
}

// SyncPersistedMetadataAndSourceHash updates the runtime auth from a persisted
// auth file payload so metadata-backed comparisons use the same canonical source
// hash as subsequent reloads from disk.
func SyncPersistedMetadataAndSourceHash(auth *Auth, data []byte) error {
	if auth == nil {
		return nil
	}
	metadata := make(map[string]any)
	if err := json.Unmarshal(data, &metadata); err != nil {
		return err
	}
	auth.Metadata = metadata
	if disabled, ok := metadata["disabled"].(bool); ok {
		auth.Disabled = disabled
	}
	return SetCanonicalSourceHashAttribute(auth)
}

// WithRequestInfo returns a new context with the given RequestInfo attached.
func WithRequestInfo(ctx context.Context, info *RequestInfo) context.Context {
	return context.WithValue(ctx, requestInfoKey{}, info)
}

// GetRequestInfo retrieves the RequestInfo from the context, if present.
func GetRequestInfo(ctx context.Context) *RequestInfo {
	if val, ok := ctx.Value(requestInfoKey{}).(*RequestInfo); ok {
		return val
	}
	return nil
}

// Auth encapsulates the runtime state and metadata associated with a single credential.
type Auth struct {
	// ID uniquely identifies the auth record across restarts.
	ID string `json:"id"`
	// Index is a stable runtime identifier derived from auth metadata (not persisted).
	Index string `json:"-"`
	// Provider is the upstream provider key (e.g. "gemini", "claude").
	Provider string `json:"provider"`
	// Prefix optionally namespaces models for routing (e.g., "teamA/gemini-3-pro-preview").
	Prefix string `json:"prefix,omitempty"`
	// FileName stores the relative or absolute path of the backing auth file.
	FileName string `json:"-"`
	// Storage holds the token persistence implementation used during login flows.
	Storage baseauth.TokenStorage `json:"-"`
	// Label is an optional human readable label for logging.
	Label string `json:"label,omitempty"`
	// Status is the lifecycle status managed by the AuthManager.
	Status Status `json:"status"`
	// StatusMessage holds a short description for the current status.
	StatusMessage string `json:"status_message,omitempty"`
	// Disabled indicates the auth is intentionally disabled by operator.
	Disabled bool `json:"disabled"`
	// Unavailable flags transient provider unavailability (e.g. quota exceeded).
	Unavailable bool `json:"unavailable"`
	// ProxyURL overrides the global proxy setting for this auth if provided.
	ProxyURL string `json:"proxy_url,omitempty"`
	// RuntimeProxyURL is a resolved proxy-pool URL used only for the current
	// execution. It never replaces or persists the credential's ProxyURL.
	RuntimeProxyURL string `json:"-"`
	// RuntimeProxyBindingID identifies the current proxy-pool binding so cached
	// transports and long-lived sessions cannot survive a rebind.
	RuntimeProxyBindingID string `json:"-"`
	// RuntimeProxyAuthID identifies the credential that owns a borrowed binding.
	RuntimeProxyAuthID string `json:"-"`
	// runtimeProxyResolved distinguishes an explicit no-proxy decision from a
	// clone that has not gone through request-time proxy resolution yet.
	runtimeProxyResolved bool
	// Attributes stores provider specific metadata needed by executors (immutable configuration).
	Attributes map[string]string `json:"attributes,omitempty"`
	// Metadata stores runtime mutable provider state (e.g. tokens, cookies).
	Metadata map[string]any `json:"metadata,omitempty"`
	// Quota captures recent quota information for load balancers.
	Quota QuotaState `json:"quota"`
	// LastError stores the last failure encountered while executing or refreshing.
	LastError *Error `json:"last_error,omitempty"`
	// CreatedAt is the creation timestamp in UTC.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the last modification timestamp in UTC.
	UpdatedAt time.Time `json:"updated_at"`
	// LastRefreshedAt records the last successful refresh time in UTC.
	LastRefreshedAt time.Time `json:"last_refreshed_at"`
	// NextRefreshAfter is the earliest time a refresh should retrigger.
	NextRefreshAfter time.Time `json:"next_refresh_after"`
	// NextRetryAfter is the earliest time a retry should retrigger.
	NextRetryAfter time.Time `json:"next_retry_after"`
	// CooldownScope records whether auth-level cooldown blocks all models or reflects model aggregation.
	CooldownScope string `json:"cooldown_scope,omitempty"`
	// ModelStates tracks per-model runtime availability data.
	ModelStates map[string]*ModelState `json:"model_states,omitempty"`

	// Runtime carries non-serialisable data used during execution (in-memory only).
	Runtime any `json:"-"`

	indexAssigned  bool   `json:"-"`
	installationID string `json:"-"`
	instanceID     string `json:"-"`
	instanceState  *authInstanceState

	chatGPTWebCredentialGeneration string
	requestRefreshFamilyID         string
	requestScopedErrorRules        *authRequestScopedErrorSnapshot
	codexQuotaObservation          *CodexQuotaObservation
}

type authInstanceState struct {
	mu              sync.Mutex
	retired         atomic.Bool
	executorOwners  []ProviderExecutor
	cleanupDone     chan struct{}
	cleanupComplete bool
	nextLease       uint64
	executions      map[uint64]context.CancelCauseFunc
	executionsIdle  chan struct{}
	maintenance     bool
}

var errRuntimeAuthInstanceRetired = errors.New("runtime auth instance retired")

type runtimeAuthInstanceContextKey struct{}

func (s *authInstanceState) Retired() bool {
	return s != nil && s.retired.Load()
}

func (s *authInstanceState) bindExecutorOwner(executor ProviderExecutor) {
	if s == nil || executor == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retired.Load() {
		return
	}
	for _, owner := range s.executorOwners {
		if sameProviderExecutor(owner, executor) {
			return
		}
	}
	s.executorOwners = append(s.executorOwners, executor)
}

func (s *authInstanceState) owners() []ProviderExecutor {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	owners := append([]ProviderExecutor(nil), s.executorOwners...)
	s.mu.Unlock()
	return owners
}

func (a *Auth) bindExecutorOwner(executor ProviderExecutor) {
	if a == nil || a.instanceState == nil {
		return
	}
	a.instanceState.bindExecutorOwner(executor)
}

func (a *Auth) executorOwners() []ProviderExecutor {
	if a == nil || a.instanceState == nil {
		return nil
	}
	return a.instanceState.owners()
}

func (s *authInstanceState) cleanupDoneSignal() <-chan struct{} {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.cleanupDone == nil {
		s.cleanupDone = make(chan struct{})
		if s.cleanupComplete {
			close(s.cleanupDone)
		}
	}
	done := s.cleanupDone
	s.mu.Unlock()
	return done
}

func (s *authInstanceState) completeCleanup() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.cleanupComplete {
		s.mu.Unlock()
		return
	}
	s.cleanupComplete = true
	if s.cleanupDone == nil {
		s.cleanupDone = make(chan struct{})
	}
	close(s.cleanupDone)
	s.mu.Unlock()
}

func (a *Auth) retireInstance() {
	if a == nil || a.instanceState == nil {
		return
	}
	state := a.instanceState
	state.mu.Lock()
	if state.retired.Load() {
		state.mu.Unlock()
		return
	}
	state.retired.Store(true)
	cancels := make([]context.CancelCauseFunc, 0, len(state.executions))
	for _, cancel := range state.executions {
		cancels = append(cancels, cancel)
	}
	state.executions = nil
	if state.executionsIdle != nil {
		close(state.executionsIdle)
		state.executionsIdle = nil
	}
	state.mu.Unlock()
	for _, cancel := range cancels {
		cancel(errRuntimeAuthInstanceRetired)
	}
}

// RuntimeInstanceRetired reports whether this runtime auth instance has been replaced or removed.
func (a *Auth) RuntimeInstanceRetired() bool {
	return a != nil && a.instanceState != nil && a.instanceState.Retired()
}

// RuntimeInstanceID returns the opaque identity shared by clones of one runtime auth instance.
func (a *Auth) RuntimeInstanceID() string {
	if a == nil {
		return ""
	}
	return a.instanceID
}

// RuntimeInstallationID returns the opaque identity shared by clones of one
// installed auth generation.
func (a *Auth) RuntimeInstallationID() string {
	if a == nil {
		return ""
	}
	return a.installationID
}

// RuntimeInstanceCleanupDone returns a channel that closes after a retired
// runtime auth instance leaves cleanup quarantine. It remains open while the
// instance is active.
func (a *Auth) RuntimeInstanceCleanupDone() <-chan struct{} {
	if a == nil {
		return nil
	}
	return a.instanceState.cleanupDoneSignal()
}

// BeginRuntimeExecution registers a cancellable execution against this auth instance.
// The returned release function must be called when execution finishes.
func (a *Auth) BeginRuntimeExecution(ctx context.Context) (context.Context, func() bool, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.instanceState == nil {
		return ctx, func() bool { return false }, true
	}
	state := a.instanceState
	if existing, _ := ctx.Value(runtimeAuthInstanceContextKey{}).(*authInstanceState); existing == state {
		return ctx, func() bool { return state.retired.Load() }, !state.retired.Load()
	}
	state.mu.Lock()
	if state.retired.Load() || (state.maintenance && ctx.Value(authMaintenanceContextKey{}) != state) {
		state.mu.Unlock()
		return ctx, func() bool { return true }, false
	}
	state.nextLease++
	leaseID := state.nextLease
	execCtx, cancel := context.WithCancelCause(ctx)
	execCtx = context.WithValue(execCtx, runtimeAuthInstanceContextKey{}, state)
	if state.executions == nil {
		state.executions = make(map[uint64]context.CancelCauseFunc)
	}
	if len(state.executions) == 0 {
		state.executionsIdle = make(chan struct{})
	}
	state.executions[leaseID] = cancel
	state.mu.Unlock()

	var once sync.Once
	retiredAtRelease := false
	release := func() bool {
		once.Do(func() {
			state.mu.Lock()
			delete(state.executions, leaseID)
			if len(state.executions) == 0 && state.executionsIdle != nil {
				close(state.executionsIdle)
				state.executionsIdle = nil
			}
			retiredAtRelease = state.retired.Load()
			state.mu.Unlock()
			cancel(nil)
		})
		return retiredAtRelease
	}
	return execCtx, release, true
}

// QuotaState contains limiter tracking data for a credential.
type QuotaState struct {
	// Exceeded indicates the credential recently hit a quota error.
	Exceeded bool `json:"exceeded"`
	// Reason provides an optional provider specific human readable description.
	Reason string `json:"reason,omitempty"`
	// NextRecoverAt is when the credential may become available again.
	NextRecoverAt time.Time `json:"next_recover_at"`
	// BackoffLevel stores the progressive cooldown exponent used for rate limits.
	BackoffLevel int `json:"backoff_level,omitempty"`
	// StrikeCount stores the number of observed 429 responses since the last success.
	StrikeCount int `json:"strike_count,omitempty"`
}

// ModelState captures the execution state for a specific model under an auth entry.
type ModelState struct {
	// Status reflects the lifecycle status for this model.
	Status Status `json:"status"`
	// StatusMessage provides an optional short description of the status.
	StatusMessage string `json:"status_message,omitempty"`
	// Unavailable mirrors whether the model is temporarily blocked for retries.
	Unavailable bool `json:"unavailable"`
	// NextRetryAfter defines the per-model retry time.
	NextRetryAfter time.Time `json:"next_retry_after"`
	// LastError records the latest error observed for this model.
	LastError *Error `json:"last_error,omitempty"`
	// Quota retains quota information if this model hit rate limits.
	Quota QuotaState `json:"quota"`
	// UpdatedAt tracks the last update timestamp for this model state.
	UpdatedAt time.Time `json:"updated_at"`
}

// Clone shallow copies the Auth structure, duplicating maps and errors to avoid accidental mutation.
func (a *Auth) Clone() *Auth {
	if a == nil {
		return nil
	}
	copyAuth := *a
	copyAuth.LastError = cloneError(a.LastError)
	copyAuth.codexQuotaObservation = a.codexQuotaObservation.Clone()
	if len(a.Attributes) > 0 {
		copyAuth.Attributes = make(map[string]string, len(a.Attributes))
		for key, value := range a.Attributes {
			copyAuth.Attributes[key] = value
		}
	}
	if len(a.Metadata) > 0 {
		copyAuth.Metadata = make(map[string]any, len(a.Metadata))
		for key, value := range a.Metadata {
			if key == "request_scoped_errors" || key == "request-scoped-errors" {
				copyAuth.Metadata[key] = cloneRequestScopedRuleMetadata(value)
			} else {
				copyAuth.Metadata[key] = value
			}
		}
	}
	if len(a.ModelStates) > 0 {
		copyAuth.ModelStates = make(map[string]*ModelState, len(a.ModelStates))
		for key, state := range a.ModelStates {
			copyAuth.ModelStates[key] = state.Clone()
		}
	}
	copyAuth.Runtime = a.Runtime
	return &copyAuth
}

// CloneWithoutRuntimeInstance returns a clone without manager-owned runtime
// instance identity or session state.
func (a *Auth) CloneWithoutRuntimeInstance() *Auth {
	clone := a.Clone()
	if clone == nil {
		return nil
	}
	clone.installationID = ""
	clone.instanceID = ""
	clone.instanceState = nil
	clone.RuntimeProxyURL = ""
	clone.RuntimeProxyBindingID = ""
	clone.RuntimeProxyAuthID = ""
	clone.runtimeProxyResolved = false
	clone.chatGPTWebCredentialGeneration = ""
	clone.requestRefreshFamilyID = ""
	clone.codexQuotaObservation = nil
	return clone
}

func stableAuthIndex(seed string) string {
	seed = strings.TrimSpace(seed)
	if seed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:8])
}

func (a *Auth) indexSeed() string {
	if a == nil {
		return ""
	}

	if fileName := strings.TrimSpace(a.FileName); fileName != "" {
		return "file:" + fileName
	}

	providerKey := strings.ToLower(strings.TrimSpace(a.Provider))
	compatName := ""
	baseURL := ""
	apiKey := ""
	source := ""
	if a.Attributes != nil {
		if value := strings.TrimSpace(a.Attributes["provider_key"]); value != "" {
			providerKey = strings.ToLower(value)
		}
		compatName = strings.ToLower(strings.TrimSpace(a.Attributes["compat_name"]))
		baseURL = strings.TrimSpace(a.Attributes["base_url"])
		apiKey = strings.TrimSpace(a.Attributes["api_key"])
		source = strings.TrimSpace(a.Attributes["source"])
	}

	proxyURL := strings.TrimSpace(a.ProxyURL)
	hasCredentialIdentity := compatName != "" || baseURL != "" || proxyURL != "" || apiKey != "" || source != ""
	if providerKey != "" && hasCredentialIdentity {
		parts := []string{"provider=" + providerKey}
		if compatName != "" {
			parts = append(parts, "compat="+compatName)
		}
		if baseURL != "" {
			parts = append(parts, "base="+baseURL)
		}
		if proxyURL != "" {
			parts = append(parts, "proxy="+proxyURL)
		}
		if apiKey != "" {
			parts = append(parts, "api_key="+apiKey)
		}
		if source != "" {
			parts = append(parts, "source="+source)
		}
		return "config:" + strings.Join(parts, "\x00")
	}

	if id := strings.TrimSpace(a.ID); id != "" {
		return "id:" + id
	}

	return ""
}

// EnsureIndex returns a stable index derived from the auth file name or credential identity.
func (a *Auth) EnsureIndex() string {
	if a == nil {
		return ""
	}
	if a.indexAssigned && a.Index != "" {
		return a.Index
	}

	seed := a.indexSeed()
	if seed == "" {
		return ""
	}

	idx := stableAuthIndex(seed)
	a.Index = idx
	a.indexAssigned = true
	return idx
}

// Clone duplicates a model state including nested error details.
func (m *ModelState) Clone() *ModelState {
	if m == nil {
		return nil
	}
	copyState := *m
	copyState.LastError = cloneError(m.LastError)
	return &copyState
}

func (a *Auth) ProxyInfo() string {
	if a == nil {
		return ""
	}
	proxyStr := a.EffectiveProxyURL()
	if proxyStr == "" {
		return ""
	}
	if idx := strings.Index(proxyStr, "://"); idx > 0 {
		return "via " + proxyStr[:idx] + " proxy"
	}
	return "via proxy"
}

// EffectiveProxyURL returns the credential override or its runtime pool
// binding. The persisted credential override always has higher priority.
func (a *Auth) EffectiveProxyURL() string {
	if a == nil {
		return ""
	}
	if proxyURL := strings.TrimSpace(a.ProxyURL); proxyURL != "" {
		return proxyURL
	}
	return strings.TrimSpace(a.RuntimeProxyURL)
}

// EffectiveProxyBindingID returns the runtime proxy-pool binding identity.
func (a *Auth) EffectiveProxyBindingID() string {
	if a == nil || strings.TrimSpace(a.ProxyURL) != "" {
		return ""
	}
	return strings.TrimSpace(a.RuntimeProxyBindingID)
}

// EffectiveProxyAuthID returns the credential that owns the active binding.
func (a *Auth) EffectiveProxyAuthID() string {
	if a == nil {
		return ""
	}
	if owner := strings.TrimSpace(a.RuntimeProxyAuthID); owner != "" {
		return owner
	}
	return strings.TrimSpace(a.ID)
}

// DisableCoolingOverride returns the auth-file scoped disable_cooling override when present.
// The value is read from metadata key "disable_cooling" (or legacy "disable-cooling").
func (a *Auth) DisableCoolingOverride() (bool, bool) {
	if a == nil || a.Metadata == nil {
		return false, false
	}
	if val, ok := a.Metadata["disable_cooling"]; ok {
		if parsed, okParse := parseBoolAny(val); okParse {
			return parsed, true
		}
	}
	if val, ok := a.Metadata["disable-cooling"]; ok {
		if parsed, okParse := parseBoolAny(val); okParse {
			return parsed, true
		}
	}
	return false, false
}

// ToolPrefixDisabled returns whether the proxy_ tool name prefix should be
// skipped for this auth. When true, tool names are sent to Anthropic unchanged.
// The value is read from metadata key "tool_prefix_disabled" (or "tool-prefix-disabled").
func (a *Auth) ToolPrefixDisabled() bool {
	if a == nil || a.Metadata == nil {
		return false
	}
	for _, key := range []string{"tool_prefix_disabled", "tool-prefix-disabled"} {
		if val, ok := a.Metadata[key]; ok {
			if parsed, okParse := parseBoolAny(val); okParse {
				return parsed
			}
		}
	}
	return false
}

// RequestRetryOverride returns the credential-scoped request_retry override when present.
// The value is read from metadata key "request_retry" (or legacy "request-retry").
func (a *Auth) RequestRetryOverride() (int, bool) {
	if a == nil || a.Metadata == nil {
		return 0, false
	}
	if val, ok := a.Metadata["request_retry"]; ok {
		if parsed, okParse := parseIntAny(val); okParse {
			if parsed < 0 {
				parsed = 0
			}
			return parsed, true
		}
	}
	if val, ok := a.Metadata["request-retry"]; ok {
		if parsed, okParse := parseIntAny(val); okParse {
			if parsed < 0 {
				parsed = 0
			}
			return parsed, true
		}
	}
	return 0, false
}

func parseBoolAny(val any) (bool, bool) {
	switch typed := val.(type) {
	case bool:
		return typed, true
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return false, false
		}
		parsed, err := strconv.ParseBool(trimmed)
		if err != nil {
			return false, false
		}
		return parsed, true
	case float64:
		return typed != 0, true
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return false, false
		}
		return parsed != 0, true
	default:
		return false, false
	}
}

func parseIntAny(val any) (int, bool) {
	switch typed := val.(type) {
	case int:
		return typed, true
	case int32:
		return int(typed), true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return int(parsed), true
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, false
		}
		parsed, err := strconv.Atoi(trimmed)
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

func (a *Auth) AccountInfo() (string, string) {
	if a == nil {
		return "", ""
	}
	// Check metadata for email first (OAuth-style auth)
	if a.Metadata != nil {
		if v, ok := a.Metadata["email"].(string); ok {
			email := strings.TrimSpace(v)
			if email != "" {
				return "oauth", email
			}
		}
	}
	// Fall back to API key (API-key auth)
	if a.Attributes != nil {
		if v := a.Attributes["api_key"]; v != "" {
			return "api_key", v
		}
	}
	return "", ""
}

// ExpirationTime attempts to extract the credential expiration timestamp from metadata.
// It inspects common keys such as "expired", "expire", "expires_at", and also
// nested "token" objects to remain compatible with legacy auth file formats.
// Codex OAuth access-token exp claims take precedence over stale metadata.
func (a *Auth) ExpirationTime() (time.Time, bool) {
	if a == nil {
		return time.Time{}, false
	}
	if expires, ok := codexAccessTokenExpiration(a); ok {
		return expires, true
	}
	if ts, ok := expirationFromMap(a.Metadata); ok {
		return ts, true
	}
	return time.Time{}, false
}

var (
	refreshLeadMu        sync.RWMutex
	refreshLeadFactories = make(map[string]func() *time.Duration)
)

func RegisterRefreshLeadProvider(provider string, factory func() *time.Duration) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" || factory == nil {
		return
	}
	refreshLeadMu.Lock()
	refreshLeadFactories[provider] = factory
	refreshLeadMu.Unlock()
}

var expireKeys = [...]string{"expired", "expire", "expires_at", "expiresAt", "expiry", "expires"}

func expirationFromMap(meta map[string]any) (time.Time, bool) {
	if meta == nil {
		return time.Time{}, false
	}
	for _, key := range expireKeys {
		if v, ok := meta[key]; ok {
			if ts, ok1 := parseTimeValue(v); ok1 {
				return ts, true
			}
		}
	}
	for _, nestedKey := range []string{"token", "Token"} {
		if nested, ok := meta[nestedKey]; ok {
			switch val := nested.(type) {
			case map[string]any:
				if ts, ok1 := expirationFromMap(val); ok1 {
					return ts, true
				}
			case map[string]string:
				temp := make(map[string]any, len(val))
				for k, v := range val {
					temp[k] = v
				}
				if ts, ok1 := expirationFromMap(temp); ok1 {
					return ts, true
				}
			}
		}
	}
	return time.Time{}, false
}

func ProviderRefreshLead(provider string, runtime any) *time.Duration {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if runtime != nil {
		if eval, ok := runtime.(interface{ RefreshLead() *time.Duration }); ok {
			if lead := eval.RefreshLead(); lead != nil && *lead > 0 {
				return lead
			}
		}
	}
	refreshLeadMu.RLock()
	factory := refreshLeadFactories[provider]
	refreshLeadMu.RUnlock()
	if factory == nil {
		return nil
	}
	if lead := factory(); lead != nil && *lead > 0 {
		return lead
	}
	return nil
}

func parseTimeValue(v any) (time.Time, bool) {
	switch value := v.(type) {
	case string:
		s := strings.TrimSpace(value)
		if s == "" {
			return time.Time{}, false
		}
		layouts := []string{
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02 15:04:05",
			"2006-01-02 15:04",
			"2006-01-02T15:04:05Z07:00",
		}
		for _, layout := range layouts {
			if ts, err := time.Parse(layout, s); err == nil {
				return ts, true
			}
		}
		if unix, err := strconv.ParseInt(s, 10, 64); err == nil {
			return normaliseUnix(unix), true
		}
	case float64:
		return normaliseUnix(int64(value)), true
	case int64:
		return normaliseUnix(value), true
	case json.Number:
		if i, err := value.Int64(); err == nil {
			return normaliseUnix(i), true
		}
		if f, err := value.Float64(); err == nil {
			return normaliseUnix(int64(f)), true
		}
	}
	return time.Time{}, false
}

func normaliseUnix(raw int64) time.Time {
	if raw <= 0 {
		return time.Time{}
	}
	// Heuristic: treat values with millisecond precision (>1e12) accordingly.
	if raw > 1_000_000_000_000 {
		return time.UnixMilli(raw)
	}
	return time.Unix(raw, 0)
}
