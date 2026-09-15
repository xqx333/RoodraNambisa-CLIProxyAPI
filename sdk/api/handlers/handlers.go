// Package handlers provides core API handler functionality for the CLI Proxy API server.
// It includes common types, client management, load balancing, and error handling
// shared across all API endpoint handlers (OpenAI, Claude, Gemini).
package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/constant"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	executorhelps "github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v6/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	coreusage "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/usage"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
	"golang.org/x/net/context"
)

// ErrorResponse represents a standard error response format for the API.
// It contains a single ErrorDetail field.
type ErrorResponse struct {
	// Error contains detailed information about the error that occurred.
	Error ErrorDetail `json:"error"`
}

// ErrorDetail provides specific information about an error that occurred.
// It includes a human-readable message, an error type, and an optional error code.
type ErrorDetail struct {
	// Message is a human-readable message providing more details about the error.
	Message string `json:"message"`

	// Type is the category of error that occurred (e.g., "invalid_request_error").
	Type string `json:"type"`

	// Code is a short code identifying the error, if applicable.
	Code string `json:"code,omitempty"`
}

const idempotencyKeyMetadataKey = "idempotency_key"

const (
	defaultStreamingKeepAliveSeconds = 0
	defaultStreamingBootstrapRetries = 0
	maxStreamingBootstrapBufferBytes = 64 << 10
)

type pinnedAuthContextKey struct{}
type selectedAuthCallbackContextKey struct{}
type executionSessionContextKey struct{}
type imageGenerationStreamPassthroughContextKey struct{}
type imageGenerationStreamPassthroughStateContextKey struct{}
type imageGenerationMaxResultsContextKey struct{}
type chatGPTWebImageRequestCountContextKey struct{}
type chatGPTWebIgnoreUnsupportedImageParamsContextKey struct{}
type chatGPTWebImageConfigSnapshotContextKey struct{}
type chatGPTWebStrictImageSizeErrorContextKey struct{}
type interactionsAPIMetadataContextKey struct{}

type interactionsAPIMetadata struct {
	version  string
	revision string
}

// WithPinnedAuthID returns a child context that requests execution on a specific auth ID.
func WithPinnedAuthID(ctx context.Context, authID string) context.Context {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, pinnedAuthContextKey{}, authID)
}

// WithImageGenerationStreamPassthrough marks a Responses stream as safe to
// forward image_generation frames without expensive repair/validation passes.
func WithImageGenerationStreamPassthrough(ctx context.Context, enabled bool) context.Context {
	if !enabled {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, imageGenerationStreamPassthroughContextKey{}, true)
}

func imageGenerationStreamPassthrough(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	enabled, _ := ctx.Value(imageGenerationStreamPassthroughContextKey{}).(bool)
	return enabled
}

// WithImageGenerationStreamPassthroughState makes the effective provider-side
// passthrough decision available to the streaming response handler.
func WithImageGenerationStreamPassthroughState(ctx context.Context, state *coreexecutor.ImageGenerationStreamPassthroughState) context.Context {
	if state == nil {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, imageGenerationStreamPassthroughStateContextKey{}, state)
}

func imageGenerationStreamPassthroughState(ctx context.Context) *coreexecutor.ImageGenerationStreamPassthroughState {
	if ctx == nil {
		return nil
	}
	state, _ := ctx.Value(imageGenerationStreamPassthroughStateContextKey{}).(*coreexecutor.ImageGenerationStreamPassthroughState)
	return state
}

// WithImageGenerationMaxResults limits how many generated images a provider
// should materialize for one compatibility endpoint execution.
func WithImageGenerationMaxResults(ctx context.Context, maxResults int) context.Context {
	if maxResults <= 0 {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, imageGenerationMaxResultsContextKey{}, maxResults)
}

func imageGenerationMaxResults(ctx context.Context) int {
	if ctx == nil {
		return 0
	}
	maxResults, _ := ctx.Value(imageGenerationMaxResultsContextKey{}).(int)
	if maxResults < 0 {
		return 0
	}
	return maxResults
}

// WithChatGPTWebImageRequestCount preserves the logical Images API count while
// n aggregation executes one provider request at a time.
func WithChatGPTWebImageRequestCount(ctx context.Context, count int) context.Context {
	if count <= 0 {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, chatGPTWebImageRequestCountContextKey{}, count)
}

func chatGPTWebImageRequestCount(ctx context.Context) int {
	if ctx == nil {
		return 0
	}
	count, _ := ctx.Value(chatGPTWebImageRequestCountContextKey{}).(int)
	if count < 0 {
		return 0
	}
	return count
}

// WithChatGPTWebIgnoreUnsupportedImageParams pins the Images compatibility
// policy for one execution. False is retained so a config reload cannot change
// the policy after provider selection.
func WithChatGPTWebIgnoreUnsupportedImageParams(ctx context.Context, enabled bool) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, chatGPTWebIgnoreUnsupportedImageParamsContextKey{}, enabled)
}

func chatGPTWebIgnoreUnsupportedImageParams(ctx context.Context) (bool, bool) {
	if ctx == nil {
		return false, false
	}
	enabled, ok := ctx.Value(chatGPTWebIgnoreUnsupportedImageParamsContextKey{}).(bool)
	return enabled, ok
}

// WithChatGPTWebImageConfigSnapshot pins Web image adaptation settings for one execution.
func WithChatGPTWebImageConfigSnapshot(ctx context.Context, snapshot coreexecutor.ChatGPTWebImageConfigSnapshot) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, chatGPTWebImageConfigSnapshotContextKey{}, snapshot)
}

func chatGPTWebImageConfigSnapshot(ctx context.Context) (coreexecutor.ChatGPTWebImageConfigSnapshot, bool) {
	if ctx == nil {
		return coreexecutor.ChatGPTWebImageConfigSnapshot{}, false
	}
	snapshot, ok := ctx.Value(chatGPTWebImageConfigSnapshotContextKey{}).(coreexecutor.ChatGPTWebImageConfigSnapshot)
	return snapshot, ok
}

func providersSupportImageStreamPassthrough(providers []string) bool {
	if len(providers) == 0 {
		return false
	}
	for _, provider := range providers {
		switch strings.ToLower(strings.TrimSpace(provider)) {
		case constant.Codex, constant.ChatGPTWeb:
		default:
			return false
		}
	}
	return true
}

func adjustExecutionProvidersForEntryProtocol(entryProtocol string, providers []string) []string {
	entryProtocol = strings.ToLower(strings.TrimSpace(entryProtocol))
	if entryProtocol == constant.Interactions {
		return preferExecutionProvider(providers, constant.GeminiInteractions)
	}
	switch entryProtocol {
	case constant.OpenAI, constant.OpenaiResponse, constant.Claude, constant.Gemini:
		return providers
	default:
		return excludeExecutionProvider(providers, constant.GeminiInteractions)
	}
}

func preferExecutionProvider(providers []string, preferred string) []string {
	preferred = strings.ToLower(strings.TrimSpace(preferred))
	for i := range providers {
		if strings.ToLower(strings.TrimSpace(providers[i])) != preferred || i == 0 {
			continue
		}
		out := make([]string, 0, len(providers))
		out = append(out, providers[i])
		out = append(out, providers[:i]...)
		out = append(out, providers[i+1:]...)
		return out
	}
	return providers
}

func excludeExecutionProvider(providers []string, excluded string) []string {
	excluded = strings.ToLower(strings.TrimSpace(excluded))
	out := make([]string, 0, len(providers))
	for _, provider := range providers {
		if strings.ToLower(strings.TrimSpace(provider)) != excluded {
			out = append(out, provider)
		}
	}
	return out
}

func allowedProviderSetFromGin(c *gin.Context) (map[string]struct{}, bool) {
	if c == nil {
		return nil, false
	}
	rawMetadata, exists := c.Get("accessMetadata")
	if !exists {
		return nil, false
	}
	metadata, ok := rawMetadata.(map[string]string)
	if !ok {
		return nil, false
	}
	rawProviders := strings.TrimSpace(metadata[sdkaccess.MetadataAllowedProviders])
	if rawProviders == "" {
		return nil, false
	}
	allowed := make(map[string]struct{})
	for _, rawProvider := range strings.Split(rawProviders, ",") {
		provider := strings.ToLower(strings.TrimSpace(rawProvider))
		if provider != "" {
			allowed[provider] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return nil, false
	}
	return allowed, true
}

func allowedProviderSetFromContext(ctx context.Context) (map[string]struct{}, bool) {
	if ctx == nil {
		return nil, false
	}
	ginContext, _ := ctx.Value("gin").(*gin.Context)
	return allowedProviderSetFromGin(ginContext)
}

func restrictExecutionProviders(ctx context.Context, providers []string) ([]string, *interfaces.ErrorMessage) {
	allowed, restricted := allowedProviderSetFromContext(ctx)
	if !restricted {
		return providers, nil
	}
	filtered := make([]string, 0, len(providers))
	for _, provider := range providers {
		if _, ok := allowed[strings.ToLower(strings.TrimSpace(provider))]; ok {
			filtered = append(filtered, provider)
		}
	}
	if len(filtered) > 0 {
		return filtered, nil
	}
	return nil, providerNotAllowedError()
}

func (h *BaseAPIHandler) filterChatGPTWebStrictImageSize(
	ctx context.Context,
	providers []string,
	handlerType string,
	rawJSON []byte,
) (context.Context, []string, *interfaces.ErrorMessage) {
	if handlerType != constant.OpenaiResponse || !providersContainChatGPTWeb(providers) {
		return ctx, providers, nil
	}

	snapshot, pinned := chatGPTWebImageConfigSnapshot(ctx)
	if !pinned {
		resolved := config.ChatGPTWebImageConfig{}.Resolved()
		if h != nil && h.Cfg != nil {
			resolved = h.Cfg.Images.ChatGPTWeb.Resolved()
		}
		snapshot = coreexecutor.ChatGPTWebImageConfigSnapshot{
			AutoCleanupLibraryOnFull:     resolved.AutoCleanupLibraryOnFull,
			RemoteImageURLEnabled:        resolved.RemoteImageURLEnabled,
			RemoteImageURLDownloadMode:   resolved.RemoteImageURLDownloadMode,
			NormalizeMismatchedImageMIME: resolved.NormalizeMismatchedImageMIME,
			NormalizeRemoteImageMIME:     resolved.NormalizeRemoteImageMIME,
			AdaptSizeToAspectRatio:       resolved.AdaptSizeToAspectRatio,
			StrictSize:                   resolved.StrictSize,
			AspectRatioMaxErrorPercent:   resolved.AspectRatioMaxErrorPercent,
			MaxResizeEdgePixels:          resolved.MaxResizeEdgePixels,
			ResizeToRequestedSize:        resolved.ResizeToRequestedSize,
			ResizeFilter:                 resolved.ResizeFilter,
			MaxImageResponseBytes:        resolved.MaxImageResponseMegabytes << 20,
			MaxN:                         resolved.MaxN,
		}
		ctx = WithChatGPTWebImageConfigSnapshot(ctx, snapshot)
	}
	size, requestCount, hasImageTool := executorhelps.ChatGPTWebImageControlsFromResponsesPayload(rawJSON)
	if !hasImageTool {
		return ctx, providers, nil
	}
	if count := chatGPTWebImageRequestCount(ctx); count > 0 {
		requestCount = count
	}
	maxN := snapshot.MaxN
	if maxN <= 0 {
		maxN = config.DefaultChatGPTWebMaxN
	}
	var payload []byte
	if requestCount > maxN {
		payload = executorhelps.ChatGPTWebImageNErrorPayload(requestCount, maxN)
	} else if snapshot.StrictSize {
		_, disposition := executorhelps.ResolveChatGPTWebImageSize(size, snapshot.MaxResizeEdgePixels)
		if disposition != executorhelps.ChatGPTWebImageSizeUnspecified && disposition != executorhelps.ChatGPTWebImageSizeMatched {
			payload = executorhelps.ChatGPTWebStrictImageSizeErrorPayload(size, snapshot.MaxResizeEdgePixels)
		}
	}
	if len(payload) == 0 {
		return ctx, providers, nil
	}

	filtered := excludeExecutionProvider(providers, constant.ChatGPTWeb)
	if len(filtered) > 0 {
		return context.WithValue(
			ctx,
			chatGPTWebStrictImageSizeErrorContextKey{},
			payload,
		), filtered, nil
	}
	return ctx, nil, &interfaces.ErrorMessage{
		StatusCode: http.StatusBadRequest,
		Error:      errors.New(string(payload)),
	}
}

func chatGPTWebStrictImageSizeUnavailableError(ctx context.Context, err error) *interfaces.ErrorMessage {
	if ctx == nil || err == nil {
		return nil
	}
	payload, _ := ctx.Value(chatGPTWebStrictImageSizeErrorContextKey{}).([]byte)
	if len(payload) == 0 {
		return nil
	}
	var authErr *coreauth.Error
	if !errors.As(err, &authErr) || authErr == nil {
		return nil
	}
	code := strings.TrimSpace(authErr.Code)
	if code != "auth_not_found" && code != "auth_unavailable" {
		return nil
	}
	return &interfaces.ErrorMessage{
		StatusCode: http.StatusBadRequest,
		Error:      errors.New(string(payload)),
	}
}

// ValidateProviderAccess checks a native endpoint without resolving a Responses model.
func (h *BaseAPIHandler) ValidateProviderAccess(ctx context.Context, provider string) *interfaces.ErrorMessage {
	_, denied := restrictExecutionProviders(ctx, []string{provider})
	return denied
}

// ValidateModelProviderAccess checks a model route without selecting or executing an auth.
func (h *BaseAPIHandler) ValidateModelProviderAccess(ctx context.Context, handlerType, modelName string) *interfaces.ErrorMessage {
	if _, restricted := allowedProviderSetFromContext(ctx); !restricted {
		return nil
	}
	providers, _, errDetails := h.getRequestDetails(modelName)
	if errDetails != nil {
		return errDetails
	}
	providers = adjustExecutionProvidersForEntryProtocol(handlerType, providers)
	_, errRestricted := restrictExecutionProviders(ctx, providers)
	return errRestricted
}

func providerNotAllowedError() *interfaces.ErrorMessage {
	return &interfaces.ErrorMessage{
		StatusCode: http.StatusForbidden,
		Error:      errors.New(`{"error":{"message":"API key is not allowed to use this provider","type":"permission_error","code":"provider_not_allowed"}}`),
	}
}

// ModelsForProviderAccess returns model metadata from the request's allowed
// providers, while keeping the unrestricted catalog behavior unchanged.
func (h *BaseAPIHandler) ModelsForProviderAccess(c *gin.Context, handlerType string) []map[string]any {
	if catalog, restricted := h.RestrictedModelCatalog(c, handlerType); restricted {
		return catalog.Models
	}
	return registry.GetGlobalRegistry().GetAvailableModels(handlerType)
}

// RestrictedModelCatalog captures derived capabilities together with the
// formatted catalog. The boolean is false when the request is unrestricted.
func (h *BaseAPIHandler) RestrictedModelCatalog(c *gin.Context, handlerType string) (registry.ModelCatalogSnapshot, bool) {
	allowed, restricted := allowedProviderSetFromGin(c)
	if !restricted {
		return registry.ModelCatalogSnapshot{}, false
	}
	providers := make([]string, 0, len(allowed))
	for provider := range allowed {
		providers = append(providers, provider)
	}
	return registry.GetGlobalRegistry().GetModelCatalogForProviders(handlerType, providers), true
}

// FilterModelsByProviderAccess removes models that cannot use any provider allowed for the request API key.
func (h *BaseAPIHandler) FilterModelsByProviderAccess(c *gin.Context, models []map[string]any) []map[string]any {
	allowed, restricted := allowedProviderSetFromGin(c)
	if !restricted {
		return models
	}
	filtered := make([]map[string]any, 0, len(models))
	modelRegistry := registry.GetGlobalRegistry()
	for _, model := range models {
		modelID, _ := model["id"].(string)
		if strings.TrimSpace(modelID) == "" {
			modelID, _ = model["name"].(string)
		}
		modelID = strings.TrimPrefix(strings.TrimSpace(modelID), "models/")
		if modelID == "" {
			continue
		}
		for _, provider := range modelRegistry.GetModelProviders(modelID) {
			if _, ok := allowed[strings.ToLower(strings.TrimSpace(provider))]; !ok {
				continue
			}
			filtered = append(filtered, model)
			break
		}
	}
	return filtered
}

// WithSelectedAuthIDCallback returns a child context that receives the selected auth ID.
func WithSelectedAuthIDCallback(ctx context.Context, callback func(string)) context.Context {
	if callback == nil {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, selectedAuthCallbackContextKey{}, callback)
}

// WithExecutionSessionID returns a child context tagged with a long-lived execution session ID.
func WithExecutionSessionID(ctx context.Context, sessionID string) context.Context {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, executionSessionContextKey{}, sessionID)
}

// WithInteractionsAPIMetadata attaches the trusted route version and optional request revision.
func WithInteractionsAPIMetadata(ctx context.Context, version, revision string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, interactionsAPIMetadataContextKey{}, interactionsAPIMetadata{
		version:  strings.TrimSpace(version),
		revision: strings.TrimSpace(revision),
	})
}

// BuildErrorResponseBody builds an OpenAI-compatible JSON error response body.
// If errText is already valid JSON, it is returned as-is to preserve upstream error payloads.
func BuildErrorResponseBody(status int, errText string) []byte {
	if status <= 0 {
		status = http.StatusInternalServerError
	}
	if strings.TrimSpace(errText) == "" {
		errText = http.StatusText(status)
	}

	trimmed := strings.TrimSpace(errText)
	if trimmed != "" && json.Valid([]byte(trimmed)) {
		return []byte(trimmed)
	}

	errType := "invalid_request_error"
	var code string
	switch status {
	case http.StatusUnauthorized:
		errType = "authentication_error"
		code = "invalid_api_key"
	case http.StatusForbidden:
		errType = "permission_error"
		code = "permission_denied"
	case http.StatusTooManyRequests:
		errType = "rate_limit_error"
		code = "rate_limit_exceeded"
	case http.StatusNotFound:
		errType = "invalid_request_error"
		code = "not_found"
		if coreauth.IsModelNotFoundError(&coreauth.Error{HTTPStatus: status, Message: errText}) {
			code = "model_not_found"
		}
	default:
		if status >= http.StatusInternalServerError {
			errType = "server_error"
			code = "internal_server_error"
		}
	}

	payload, err := json.Marshal(ErrorResponse{
		Error: ErrorDetail{
			Message: errText,
			Type:    errType,
			Code:    code,
		},
	})
	if err != nil {
		return []byte(fmt.Sprintf(`{"error":{"message":%q,"type":"server_error","code":"internal_server_error"}}`, errText))
	}
	return payload
}

// StreamingKeepAliveInterval returns the SSE heartbeat and WebSocket Ping interval.
// Returning 0 disables keep-alives (default when unset).
func StreamingKeepAliveInterval(cfg *config.SDKConfig) time.Duration {
	seconds := defaultStreamingKeepAliveSeconds
	if cfg != nil {
		seconds = cfg.Streaming.KeepAliveSeconds
	}
	if seconds <= 0 || int64(seconds) > int64((1<<63-1)/time.Second) {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// NonStreamingKeepAliveInterval returns the keep-alive interval for non-streaming responses.
// Returning 0 disables keep-alives (default when unset).
func NonStreamingKeepAliveInterval(cfg *config.SDKConfig) time.Duration {
	seconds := 0
	if cfg != nil {
		seconds = cfg.NonStreamKeepAliveInterval
	}
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// StreamingBootstrapRetries returns how many times a streaming request may be retried before any bytes are sent.
func StreamingBootstrapRetries(cfg *config.SDKConfig) int {
	retries := defaultStreamingBootstrapRetries
	if cfg != nil {
		retries = cfg.Streaming.BootstrapRetries
	}
	if retries < 0 {
		retries = 0
	}
	return retries
}

// StreamingFlushEnabled returns whether regular streaming responses should batch flushes.
func StreamingFlushEnabled(cfg *config.SDKConfig) bool {
	return cfg != nil && cfg.Streaming.EnableStreamFlush
}

// StreamingFlushInterval returns the regular streaming flush batching interval.
func StreamingFlushInterval(cfg *config.SDKConfig) time.Duration {
	if !StreamingFlushEnabled(cfg) {
		return 0
	}
	ms := 0
	if cfg != nil {
		ms = cfg.Streaming.StreamFlushIntervalMS
	}
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

// StreamingFlushMinBytes returns the regular streaming byte threshold for flush batching.
func StreamingFlushMinBytes(cfg *config.SDKConfig) int {
	if !StreamingFlushEnabled(cfg) || cfg == nil || cfg.Streaming.StreamFlushMinBytes <= 0 {
		return 0
	}
	return cfg.Streaming.StreamFlushMinBytes
}

// StreamingTrustUpstreamSSE returns whether OpenAI Responses SSE should bypass repair/validation.
func StreamingTrustUpstreamSSE(cfg *config.SDKConfig) bool {
	return cfg != nil && cfg.Streaming.TrustUpstreamSSE
}

// PassthroughHeadersEnabled returns whether upstream response headers should be forwarded to clients.
// Default is false.
func PassthroughHeadersEnabled(cfg *config.SDKConfig) bool {
	return cfg != nil && cfg.PassthroughHeaders
}

func requestExecutionMetadata(ctx context.Context) map[string]any {
	// Idempotency-Key is an optional client-supplied header used to correlate retries.
	// Only include it if the client explicitly provides it.
	key := ""
	requestPath := ""
	meta := make(map[string]any)
	if budget := coreexecutor.ImageRequestBudgetFromContext(ctx); budget != nil {
		meta[coreexecutor.ImageRequestBudgetMetadataKey] = budget
	}
	if ctx != nil {
		if ginCtx, ok := ctx.Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
			key = strings.TrimSpace(ginCtx.GetHeader("Idempotency-Key"))
			requestPath = strings.TrimSpace(ginCtx.FullPath())
			if requestPath == "" && ginCtx.Request.URL != nil {
				requestPath = strings.TrimSpace(ginCtx.Request.URL.Path)
			}
			if leases, exists := ginCtx.Get(executorhelps.ChatGPTWebImageMemoryLeaseSetMetadataKey); exists {
				meta[executorhelps.ChatGPTWebImageMemoryLeaseSetMetadataKey] = leases
			}
			if observer, exists := ginCtx.Get(coreexecutor.RequestPhaseObserverMetadataKey); exists {
				meta[coreexecutor.RequestPhaseObserverMetadataKey] = observer
			}
		}
	}

	if key != "" {
		meta[idempotencyKeyMetadataKey] = key
	}
	if requestPath != "" {
		meta[coreexecutor.RequestPathMetadataKey] = requestPath
	}
	if pinnedAuthID := pinnedAuthIDFromContext(ctx); pinnedAuthID != "" {
		meta[coreexecutor.PinnedAuthMetadataKey] = pinnedAuthID
	}
	if selectedCallback := selectedAuthIDCallbackFromContext(ctx); selectedCallback != nil {
		meta[coreexecutor.SelectedAuthCallbackMetadataKey] = selectedCallback
	}
	if sourceTracker := errorResponseSourceTrackerFromContext(ctx); sourceTracker != nil {
		meta[coreexecutor.SelectedAuthSourceCallbackMetadataKey] = func(source coreexecutor.ErrorResponseSourceSnapshot) {
			sourceTracker.store(source)
		}
	}
	if executionSessionID := executionSessionIDFromContext(ctx); executionSessionID != "" {
		meta[coreexecutor.ExecutionSessionMetadataKey] = executionSessionID
	}
	if state := imageGenerationStreamPassthroughState(ctx); state != nil {
		meta[coreexecutor.ImageGenerationStreamPassthroughStateMetadataKey] = state
	}
	if maxResults := imageGenerationMaxResults(ctx); maxResults > 0 {
		meta[coreexecutor.ImageGenerationMaxResultsMetadataKey] = maxResults
	}
	if enabled, ok := chatGPTWebIgnoreUnsupportedImageParams(ctx); ok {
		meta[coreexecutor.ChatGPTWebIgnoreUnsupportedImageParamsMetadataKey] = enabled
	}
	if snapshot, ok := chatGPTWebImageConfigSnapshot(ctx); ok {
		meta[coreexecutor.ChatGPTWebImageConfigSnapshotMetadataKey] = snapshot
	}
	if request := coreexecutor.CodexNativeImageRequestFromContext(ctx); request != nil {
		meta[coreexecutor.CodexNativeImageRequestMetadataKey] = request
	}
	if ctx != nil {
		if interactions, ok := ctx.Value(interactionsAPIMetadataContextKey{}).(interactionsAPIMetadata); ok {
			if interactions.version != "" {
				meta[coreexecutor.InteractionsAPIVersionMetadataKey] = interactions.version
			}
			if interactions.revision != "" {
				meta[coreexecutor.InteractionsAPIRevisionMetadataKey] = interactions.revision
			}
		}
	}
	return meta
}

func (h *BaseAPIHandler) attachRequestBodyRelease(ctx context.Context, rawJSON []byte, meta map[string]any, force bool) (context.Context, *coreexecutor.RequestBodyReleaseController) {
	if h == nil || len(rawJSON) == 0 {
		return ctx, nil
	}
	cfg := config.RequestBodyReleaseConfig{}
	if h.Cfg != nil {
		cfg = config.NormalizeRequestBodyRelease(h.Cfg.RequestBodyRelease)
	}
	if !force && !cfg.Enable {
		return ctx, nil
	}
	size := int64(len(rawJSON))
	if !force && cfg.MinBodyBytes > 0 && size < cfg.MinBodyBytes {
		return ctx, nil
	}
	logOnly := !force && cfg.LogOnly
	placeholder := coreexecutor.RequestBodyReleaseTimerPlaceholder(size, cfg.AfterSeconds, logOnly)
	ctrl := requestBodyReleaseControllerFromContext(ctx)
	// A forced ChatGPT Web controller must not inherit the global release timer.
	if force || ctrl == nil || ctrl.LogOnly() != logOnly {
		ctrl = coreexecutor.NewRequestBodyReleaseControllerWithMode(size, placeholder, logOnly)
	}
	if meta != nil {
		meta[coreexecutor.BodyReleaseControllerMetadataKey] = ctrl
	}
	if ginCtx, ok := ctx.Value("gin").(*gin.Context); ok && ginCtx != nil {
		ginCtx.Set(coreexecutor.BodyReleaseControllerMetadataKey, ctrl)
		if binder, okBinder := ginCtx.Writer.(interface {
			BindRequestBodyReleaseController(*coreexecutor.RequestBodyReleaseController)
		}); okBinder {
			binder.BindRequestBodyReleaseController(ctrl)
		}
	}
	ctx = coreexecutor.WithRequestBodyReleaseController(ctx, ctrl)
	if request := coreexecutor.CodexNativeImageRequestFromContext(ctx); request != nil && !ctrl.LogOnly() {
		ctrl.RegisterReleaseCallback(func([]byte) { request.Release() })
	}
	// ChatGPT Web releases the body itself after its upstream session is
	// committed and its compact billing projection is safe.
	if cfg.AfterSeconds > 0 && !force {
		ctrl.StartTimer(time.Duration(cfg.AfterSeconds)*time.Second, ctx.Done())
	}
	return ctx, ctrl
}

func providersContainChatGPTWeb(providers []string) bool {
	for _, provider := range providers {
		if strings.EqualFold(strings.TrimSpace(provider), "chatgpt-web") {
			return true
		}
	}
	return false
}

func requestBodyReleaseControllerFromContext(ctx context.Context) *coreexecutor.RequestBodyReleaseController {
	if ctrl := coreexecutor.RequestBodyReleaseControllerFromContext(ctx); ctrl != nil {
		return ctrl
	}
	if ctx == nil {
		return nil
	}
	ginCtx, _ := ctx.Value("gin").(*gin.Context)
	if ginCtx == nil {
		return nil
	}
	raw, exists := ginCtx.Get(coreexecutor.BodyReleaseControllerMetadataKey)
	if !exists {
		return nil
	}
	ctrl, _ := raw.(*coreexecutor.RequestBodyReleaseController)
	return ctrl
}

func pinnedAuthIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	raw := ctx.Value(pinnedAuthContextKey{})
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case []byte:
		return strings.TrimSpace(string(v))
	default:
		return ""
	}
}

func selectedAuthIDCallbackFromContext(ctx context.Context) func(string) {
	if ctx == nil {
		return nil
	}
	raw := ctx.Value(selectedAuthCallbackContextKey{})
	if callback, ok := raw.(func(string)); ok && callback != nil {
		return callback
	}
	return nil
}

func executionSessionIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	raw := ctx.Value(executionSessionContextKey{})
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case []byte:
		return strings.TrimSpace(string(v))
	default:
		return ""
	}
}

// BaseAPIHandler contains the handlers for API endpoints.
// It holds a pool of clients to interact with the backend service and manages
// load balancing, client selection, and configuration.
type BaseAPIHandler struct {
	// AuthManager manages auth lifecycle and execution in the new architecture.
	AuthManager *coreauth.Manager

	// Cfg holds the current application configuration. New request snapshots
	// should use ConfigSnapshot when racing with UpdateClients.
	Cfg   *config.SDKConfig
	cfgMu sync.RWMutex
}

// NewBaseAPIHandlers creates a new API handlers instance.
// It takes a slice of clients and configuration as input.
//
// Parameters:
//   - cliClients: A slice of AI service clients
//   - cfg: The application configuration
//
// Returns:
//   - *BaseAPIHandler: A new API handlers instance
func NewBaseAPIHandlers(cfg *config.SDKConfig, authManager *coreauth.Manager) *BaseAPIHandler {
	return &BaseAPIHandler{
		Cfg:         cfg,
		AuthManager: authManager,
	}
}

// UpdateClients updates the handlers' client list and configuration.
// This method is called when the configuration or authentication tokens change.
//
// Parameters:
//   - clients: The new slice of AI service clients
//   - cfg: The new application configuration
func (h *BaseAPIHandler) UpdateClients(cfg *config.SDKConfig) {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	h.Cfg = cfg
}

// ConfigSnapshot returns the immutable configuration installed for new requests.
func (h *BaseAPIHandler) ConfigSnapshot() *config.SDKConfig {
	if h == nil {
		return nil
	}
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	return h.Cfg
}

// GetAlt extracts the 'alt' parameter from the request query string.
// It checks both 'alt' and '$alt' parameters and returns the appropriate value.
//
// Parameters:
//   - c: The Gin context containing the HTTP request
//
// Returns:
//   - string: The alt parameter value, or empty string if it's "sse"
func (h *BaseAPIHandler) GetAlt(c *gin.Context) string {
	var alt string
	var hasAlt bool
	alt, hasAlt = c.GetQuery("alt")
	if !hasAlt {
		alt, _ = c.GetQuery("$alt")
	}
	if alt == "sse" {
		return ""
	}
	return alt
}

// GetContextWithCancel creates a new context with cancellation capabilities.
// It embeds the Gin context and the API handler into the new context for later use.
// The returned cancel function also handles logging the API response if request logging is enabled.
//
// Parameters:
//   - handler: The API handler associated with the request.
//   - c: The Gin context of the current request.
//   - ctx: The parent context (caller values/deadlines are preserved; request context adds cancellation and request ID).
//
// Returns:
//   - context.Context: The new context with cancellation and embedded values.
//   - APIHandlerCancelFunc: A function to cancel the context and log the response.
func (h *BaseAPIHandler) GetContextWithCancel(handler interfaces.APIHandler, c *gin.Context, ctx context.Context) (context.Context, APIHandlerCancelFunc) {
	parentCtx := ctx
	if parentCtx == nil {
		parentCtx = context.Background()
	}

	var requestCtx context.Context
	if c != nil && c.Request != nil {
		requestCtx = c.Request.Context()
	}

	if requestCtx != nil && logging.GetRequestID(parentCtx) == "" {
		if requestID := logging.GetRequestID(requestCtx); requestID != "" {
			parentCtx = logging.WithRequestID(parentCtx, requestID)
		} else if requestID := logging.GetGinRequestID(c); requestID != "" {
			parentCtx = logging.WithRequestID(parentCtx, requestID)
		}
	}
	parentCtx = logging.WithRequestCredentialFrom(parentCtx, requestCtx)
	newCtx, cancel := context.WithCancel(parentCtx)
	cancelCtx := newCtx
	if requestCtx != nil && requestCtx != parentCtx {
		go func() {
			select {
			case <-requestCtx.Done():
				cancel()
			case <-cancelCtx.Done():
			}
		}()
	}
	newCtx = context.WithValue(newCtx, "gin", c)
	if c != nil && c.Request != nil {
		path := c.FullPath()
		if path == "" && c.Request.URL != nil {
			path = c.Request.URL.Path
		}
		identifier := path
		if path != "" && c.Request.Method != "" {
			identifier = c.Request.Method + " " + path
		}
		newCtx = coreusage.WithRequestMetadata(newCtx, coreusage.RequestMetadata{APIIdentifier: identifier, ClientIP: logging.ResolveClientIP(c)})
	}
	newCtx = executorhelps.CaptureCodexMultiAgentPolicyContext(newCtx)
	newCtx = context.WithValue(newCtx, "handler", handler)
	newCtx, _ = ensureErrorResponseSourceTracker(newCtx, c)
	if c != nil {
		if value, exists := c.Get(coreexecutor.ImageBootstrapPolicyMetadataKey); exists {
			if policy, ok := value.(coreexecutor.ImageBootstrapPolicy); ok {
				newCtx = coreexecutor.WithImageBootstrapPolicy(newCtx, policy)
			}
		}
	}
	releaseBudget := func() {}
	if budget := imageRequestBudgetForGin(c); budget != nil {
		newCtx, releaseBudget = budget.Bind(newCtx)
	}
	return newCtx, func(params ...interface{}) {
		defer releaseBudget()
		if h.Cfg.RequestLog && len(params) == 1 {
			if existing, exists := c.Get("API_RESPONSE"); exists {
				if existingBytes, ok := existing.([]byte); ok && len(bytes.TrimSpace(existingBytes)) > 0 {
					switch params[0].(type) {
					case error, string:
						cancel()
						return
					}
				}
			}

			var payload []byte
			switch data := params[0].(type) {
			case []byte:
				payload = data
			case error:
				if data != nil {
					payload = []byte(data.Error())
				}
			case string:
				payload = []byte(data)
			}
			if len(payload) > 0 {
				if existing, exists := c.Get("API_RESPONSE"); exists {
					if existingBytes, ok := existing.([]byte); ok && len(existingBytes) > 0 {
						trimmedPayload := bytes.TrimSpace(payload)
						if len(trimmedPayload) > 0 && bytes.Contains(existingBytes, trimmedPayload) {
							cancel()
							return
						}
					}
				}
				appendAPIResponse(c, payload)
			}
		}

		cancel()
	}
}

// StartNonStreamingKeepAlive emits blank lines every 5 seconds while waiting for a non-streaming response.
// It returns a stop function that must be called before writing the final response.
func (h *BaseAPIHandler) StartNonStreamingKeepAlive(c *gin.Context, ctx context.Context) func() {
	if h == nil || c == nil {
		return func() {}
	}
	interval := NonStreamingKeepAliveInterval(h.Cfg)
	if interval <= 0 {
		return func() {}
	}
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		return func() {}
	}
	if ctx == nil {
		ctx = context.Background()
	}

	stopChan := make(chan struct{})
	var stopOnce sync.Once
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopChan:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = c.Writer.Write([]byte("\n"))
				flusher.Flush()
			}
		}
	}()

	return func() {
		stopOnce.Do(func() {
			close(stopChan)
		})
		wg.Wait()
	}
}

// appendAPIResponse preserves any previously captured API response and appends new data.
func appendAPIResponse(c *gin.Context, data []byte) {
	if c == nil || len(data) == 0 {
		return
	}

	// Capture timestamp on first API response
	if _, exists := c.Get("API_RESPONSE_TIMESTAMP"); !exists {
		c.Set("API_RESPONSE_TIMESTAMP", time.Now())
	}

	if existing, exists := c.Get("API_RESPONSE"); exists {
		if existingBytes, ok := existing.([]byte); ok && len(existingBytes) > 0 {
			combined := make([]byte, 0, len(existingBytes)+len(data)+1)
			combined = append(combined, existingBytes...)
			if existingBytes[len(existingBytes)-1] != '\n' {
				combined = append(combined, '\n')
			}
			combined = append(combined, data...)
			c.Set("API_RESPONSE", combined)
			return
		}
	}

	c.Set("API_RESPONSE", bytes.Clone(data))
}

// ExecuteWithAuthManager executes a non-streaming request via the core auth manager.
// This path is the only supported execution route.
func (h *BaseAPIHandler) ExecuteWithAuthManager(ctx context.Context, handlerType, modelName string, rawJSON []byte, alt string) ([]byte, http.Header, *interfaces.ErrorMessage) {
	ctx, _ = ensureErrorResponseSourceTracker(ctx, nil)
	providers, normalizedModel, errMsg := h.getRequestDetails(modelName)
	if errMsg != nil {
		return nil, nil, errMsg
	}
	providers = adjustExecutionProvidersForEntryProtocol(handlerType, providers)
	providers, errMsg = restrictExecutionProviders(ctx, providers)
	if errMsg != nil {
		return nil, nil, errMsg
	}
	ctx, providers, errMsg = h.filterChatGPTWebStrictImageSize(ctx, providers, handlerType, rawJSON)
	if errMsg != nil {
		return nil, nil, errMsg
	}
	reqMeta := requestExecutionMetadata(ctx)
	setGenerateMetadata(reqMeta, rawJSON)
	reqMeta[coreexecutor.RequestedModelMetadataKey] = normalizedModel
	ctx, _ = h.attachRequestBodyRelease(ctx, rawJSON, reqMeta, providersContainChatGPTWeb(providers))
	payload := rawJSON
	if len(payload) == 0 {
		payload = nil
	}
	req := coreexecutor.Request{
		Model:   normalizedModel,
		Payload: payload,
	}
	opts := coreexecutor.Options{
		Stream:          false,
		Alt:             alt,
		OriginalRequest: rawJSON,
		SourceFormat:    sdktranslator.FromString(handlerType),
	}
	opts.Metadata = reqMeta
	resp, err := h.AuthManager.Execute(ctx, providers, req, opts)
	err = coreexecutor.ImageRequestContextError(ctx, err)
	if err != nil {
		if strictErr := chatGPTWebStrictImageSizeUnavailableError(ctx, err); strictErr != nil {
			return nil, nil, strictErr
		}
		return nil, nil, h.RewriteExecutionErrorResponseForContext(ctx, executionErrorMessage(err, providers, normalizedModel))
	}
	return resp.Payload, ClientUpstreamHeaders(resp.Headers, PassthroughHeadersEnabled(h.Cfg)), nil
}

// ExecuteWithProviders executes a non-streaming request against an explicit provider set.
// It bypasses model-registry provider lookup while preserving request metadata and error formatting.
func (h *BaseAPIHandler) ExecuteWithProviders(ctx context.Context, providers []string, handlerType, modelName string, rawJSON []byte, alt string) ([]byte, http.Header, *interfaces.ErrorMessage) {
	return h.ExecuteWithProvidersAndExecutionModel(ctx, providers, handlerType, modelName, "", rawJSON, alt)
}

// ExecuteWithProvidersAndExecutionModel executes a non-streaming request against an explicit
// provider set while allowing auth selection and upstream execution to use different model IDs.
func (h *BaseAPIHandler) ExecuteWithProvidersAndExecutionModel(ctx context.Context, providers []string, handlerType, routeModelName, executionModelName string, rawJSON []byte, alt string) ([]byte, http.Header, *interfaces.ErrorMessage) {
	ctx, _ = ensureErrorResponseSourceTracker(ctx, nil)
	normalizedRouteModel := strings.TrimSpace(routeModelName)
	if normalizedRouteModel == "" {
		return nil, nil, &interfaces.ErrorMessage{StatusCode: http.StatusBadRequest, Error: fmt.Errorf("model is required")}
	}
	if len(providers) == 0 {
		return nil, nil, &interfaces.ErrorMessage{StatusCode: http.StatusBadGateway, Error: fmt.Errorf("no provider configured for model %s", normalizedRouteModel)}
	}
	providers, errRestricted := restrictExecutionProviders(ctx, providers)
	if errRestricted != nil {
		return nil, nil, errRestricted
	}
	ctx, providers, errRestricted = h.filterChatGPTWebStrictImageSize(ctx, providers, handlerType, rawJSON)
	if errRestricted != nil {
		return nil, nil, errRestricted
	}
	reqMeta := requestExecutionMetadata(ctx)
	setGenerateMetadata(reqMeta, rawJSON)
	reqMeta[coreexecutor.RequestedModelMetadataKey] = normalizedRouteModel
	if normalizedExecutionModel := strings.TrimSpace(executionModelName); normalizedExecutionModel != "" && normalizedExecutionModel != normalizedRouteModel {
		reqMeta[coreexecutor.ExecutionModelOverrideMetadataKey] = normalizedExecutionModel
	}
	imageStreamPassthrough := handlerType == "openai-response" && imageGenerationStreamPassthrough(ctx) && providersSupportImageStreamPassthrough(providers)
	if imageStreamPassthrough {
		reqMeta[coreexecutor.ImageGenerationStreamPassthroughMetadataKey] = true
	}
	ctx, _ = h.attachRequestBodyRelease(ctx, rawJSON, reqMeta, providersContainChatGPTWeb(providers))
	payload := rawJSON
	if len(payload) == 0 {
		payload = nil
	}
	req := coreexecutor.Request{
		Model:   normalizedRouteModel,
		Payload: payload,
	}
	opts := coreexecutor.Options{
		Stream:          false,
		Alt:             alt,
		OriginalRequest: rawJSON,
		SourceFormat:    sdktranslator.FromString(handlerType),
	}
	opts.Metadata = reqMeta
	resp, err := h.AuthManager.Execute(ctx, providers, req, opts)
	err = coreexecutor.ImageRequestContextError(ctx, err)
	if err != nil {
		if strictErr := chatGPTWebStrictImageSizeUnavailableError(ctx, err); strictErr != nil {
			return nil, nil, strictErr
		}
		return nil, nil, h.RewriteExecutionErrorResponseForContext(ctx, executionErrorMessage(err, providers, normalizedRouteModel))
	}
	return resp.Payload, ClientUpstreamHeaders(resp.Headers, PassthroughHeadersEnabled(h.Cfg)), nil
}

// ExecuteStreamWithProviders executes a streaming request against an explicit provider set.
// It bypasses model-registry provider lookup while preserving request metadata and error formatting.
func (h *BaseAPIHandler) ExecuteStreamWithProviders(ctx context.Context, providers []string, handlerType, modelName string, rawJSON []byte, alt string) (<-chan []byte, http.Header, <-chan *interfaces.ErrorMessage) {
	return h.ExecuteStreamWithProvidersAndExecutionModel(ctx, providers, handlerType, modelName, "", rawJSON, alt)
}

// ExecuteStreamWithProvidersAndExecutionModel executes a streaming request against an explicit
// provider set while allowing auth selection and upstream execution to use different model IDs.
func (h *BaseAPIHandler) ExecuteStreamWithProvidersAndExecutionModel(ctx context.Context, providers []string, handlerType, routeModelName, executionModelName string, rawJSON []byte, alt string) (<-chan []byte, http.Header, <-chan *interfaces.ErrorMessage) {
	normalizedRouteModel := strings.TrimSpace(routeModelName)
	if normalizedRouteModel == "" {
		errChan := make(chan *interfaces.ErrorMessage, 1)
		errChan <- &interfaces.ErrorMessage{StatusCode: http.StatusBadRequest, Error: fmt.Errorf("model is required")}
		close(errChan)
		return nil, nil, errChan
	}
	if len(providers) == 0 {
		errChan := make(chan *interfaces.ErrorMessage, 1)
		errChan <- &interfaces.ErrorMessage{StatusCode: http.StatusBadGateway, Error: fmt.Errorf("no provider configured for model %s", normalizedRouteModel)}
		close(errChan)
		return nil, nil, errChan
	}
	return h.executeStreamWithResolvedProviders(ctx, providers, handlerType, normalizedRouteModel, executionModelName, rawJSON, alt)
}

// ExecuteCountWithAuthManager executes a non-streaming request via the core auth manager.
// This path is the only supported execution route.
func (h *BaseAPIHandler) ExecuteCountWithAuthManager(ctx context.Context, handlerType, modelName string, rawJSON []byte, alt string) ([]byte, http.Header, *interfaces.ErrorMessage) {
	ctx, _ = ensureErrorResponseSourceTracker(ctx, nil)
	providers, normalizedModel, errMsg := h.getRequestDetails(modelName)
	if errMsg != nil {
		return nil, nil, errMsg
	}
	providers = adjustExecutionProvidersForEntryProtocol(handlerType, providers)
	providers, errMsg = restrictExecutionProviders(ctx, providers)
	if errMsg != nil {
		return nil, nil, errMsg
	}
	ctx, providers, errMsg = h.filterChatGPTWebStrictImageSize(ctx, providers, handlerType, rawJSON)
	if errMsg != nil {
		return nil, nil, errMsg
	}
	reqMeta := requestExecutionMetadata(ctx)
	setGenerateMetadata(reqMeta, rawJSON)
	reqMeta[coreexecutor.RequestedModelMetadataKey] = normalizedModel
	ctx, _ = h.attachRequestBodyRelease(ctx, rawJSON, reqMeta, providersContainChatGPTWeb(providers))
	payload := rawJSON
	if len(payload) == 0 {
		payload = nil
	}
	req := coreexecutor.Request{
		Model:   normalizedModel,
		Payload: payload,
	}
	opts := coreexecutor.Options{
		Stream:          false,
		Alt:             alt,
		OriginalRequest: rawJSON,
		SourceFormat:    sdktranslator.FromString(handlerType),
	}
	opts.Metadata = reqMeta
	resp, err := h.AuthManager.ExecuteCount(ctx, providers, req, opts)
	if err != nil {
		if strictErr := chatGPTWebStrictImageSizeUnavailableError(ctx, err); strictErr != nil {
			return nil, nil, strictErr
		}
		return nil, nil, h.RewriteExecutionErrorResponseForContext(ctx, executionErrorMessage(err, providers, normalizedModel))
	}
	return resp.Payload, ClientUpstreamHeaders(resp.Headers, PassthroughHeadersEnabled(h.Cfg)), nil
}

// ExecuteStreamWithAuthManager executes a streaming request via the core auth manager.
// This path is the only supported execution route.
// The returned http.Header carries upstream response headers captured before streaming begins.
func (h *BaseAPIHandler) ExecuteStreamWithAuthManager(ctx context.Context, handlerType, modelName string, rawJSON []byte, alt string) (<-chan []byte, http.Header, <-chan *interfaces.ErrorMessage) {
	providers, normalizedModel, errMsg := h.getRequestDetails(modelName)
	if errMsg != nil {
		errChan := make(chan *interfaces.ErrorMessage, 1)
		errChan <- errMsg
		close(errChan)
		return nil, nil, errChan
	}
	providers = adjustExecutionProvidersForEntryProtocol(handlerType, providers)
	return h.executeStreamWithResolvedProviders(ctx, providers, handlerType, normalizedModel, "", rawJSON, alt)
}

func (h *BaseAPIHandler) executeStreamWithResolvedProviders(ctx context.Context, providers []string, handlerType, normalizedRouteModel, executionModelName string, rawJSON []byte, alt string) (<-chan []byte, http.Header, <-chan *interfaces.ErrorMessage) {
	ctx = h.AuthManager.WithRoutingPolicySnapshot(ctx)
	ctx, _ = ensureErrorResponseSourceTracker(ctx, nil)
	var errRestricted *interfaces.ErrorMessage
	providers, errRestricted = restrictExecutionProviders(ctx, providers)
	if errRestricted != nil {
		errChan := make(chan *interfaces.ErrorMessage, 1)
		errChan <- errRestricted
		close(errChan)
		return nil, nil, errChan
	}
	ctx, providers, errRestricted = h.filterChatGPTWebStrictImageSize(ctx, providers, handlerType, rawJSON)
	if errRestricted != nil {
		errChan := make(chan *interfaces.ErrorMessage, 1)
		errChan <- errRestricted
		close(errChan)
		return nil, nil, errChan
	}
	if h != nil && h.AuthManager != nil {
		ctx = h.AuthManager.WithRequestRetryBudgetForProviders(ctx, providers, StreamingBootstrapRetries(h.Cfg))
	}
	reqMeta := requestExecutionMetadata(ctx)
	setGenerateMetadata(reqMeta, rawJSON)
	reqMeta[coreexecutor.RequestedModelMetadataKey] = normalizedRouteModel
	if normalizedExecutionModel := strings.TrimSpace(executionModelName); normalizedExecutionModel != "" && normalizedExecutionModel != normalizedRouteModel {
		reqMeta[coreexecutor.ExecutionModelOverrideMetadataKey] = normalizedExecutionModel
	}
	requestedImageStreamPassthrough := handlerType == "openai-response" && imageGenerationStreamPassthrough(ctx) && providersSupportImageStreamPassthrough(providers)
	if requestedImageStreamPassthrough {
		reqMeta[coreexecutor.ImageGenerationStreamPassthroughMetadataKey] = true
	}
	imageStreamPassthrough := func() bool {
		if !requestedImageStreamPassthrough {
			return false
		}
		state := imageGenerationStreamPassthroughState(ctx)
		return state == nil || state.Enabled()
	}
	trustResponsesSSE := handlerType == "openai-response" && StreamingTrustUpstreamSSE(h.Cfg)
	if trustResponsesSSE {
		reqMeta[coreexecutor.TrustUpstreamSSEMetadataKey] = true
	}
	ctx, _ = h.attachRequestBodyRelease(ctx, rawJSON, reqMeta, providersContainChatGPTWeb(providers))
	payload := rawJSON
	if len(payload) == 0 {
		payload = nil
	}
	req := coreexecutor.Request{
		Model:   normalizedRouteModel,
		Payload: payload,
	}
	opts := coreexecutor.Options{
		Stream:          true,
		Alt:             alt,
		OriginalRequest: rawJSON,
		SourceFormat:    sdktranslator.FromString(handlerType),
	}
	opts.Metadata = reqMeta
	allowRequestErrorRetry := h.AuthManager.SnapshotRequestErrorRetryPolicy(ctx)
	streamResult, err := h.AuthManager.ExecuteStream(ctx, providers, req, opts)
	err = coreexecutor.ImageRequestContextError(ctx, err)
	if err != nil {
		errChan := make(chan *interfaces.ErrorMessage, 1)
		if strictErr := chatGPTWebStrictImageSizeUnavailableError(ctx, err); strictErr != nil {
			errChan <- strictErr
		} else {
			errChan <- h.RewriteExecutionErrorResponseForContext(ctx, executionErrorMessage(err, providers, normalizedRouteModel))
		}
		close(errChan)
		return nil, nil, errChan
	}
	passthroughHeadersEnabled := PassthroughHeadersEnabled(h.Cfg)
	// Bootstrap retries own this map until output is committed. Publish it once
	// so callers can safely read headers before consuming the returned channels.
	upstreamHeaders := cloneHeader(ClientUpstreamHeaders(streamResult.Headers, passthroughHeadersEnabled))
	if upstreamHeaders == nil && (passthroughHeadersEnabled || handlerType == "openai-response") {
		upstreamHeaders = make(http.Header)
	}
	chunks := streamResult.Chunks
	dataChan := make(chan []byte)
	errChan := make(chan *interfaces.ErrorMessage, 1)
	headersReady := make(chan struct{})
	go func() {
		defer close(dataChan)
		defer close(errChan)
		headersPublished := false
		publishHeaders := func() {
			if !headersPublished {
				headersPublished = true
				close(headersReady)
			}
		}
		defer publishHeaders()
		sentPayload := false
		bootstrapRetries := 0
		maxBootstrapRetries := StreamingBootstrapRetries(h.Cfg)
		errorSent := false
		defer func() {
			if msg := h.ImageRequestTimeoutResponse(ctx); msg != nil && !errorSent {
				publishHeaders()
				errChan <- msg
			}
		}()

		sendErr := func(msg *interfaces.ErrorMessage) bool {
			publishHeaders()
			if timeout := h.ImageRequestTimeoutResponse(ctx); timeout != nil {
				errChan <- timeout
				errorSent = true
				return true
			}
			if ctx == nil {
				errChan <- msg
				return true
			}
			select {
			case <-ctx.Done():
				return false
			case errChan <- msg:
				errorSent = true
				return true
			}
		}

		sendData := func(chunk []byte) bool {
			publishHeaders()
			if ctx == nil {
				dataChan <- chunk
				return true
			}
			select {
			case <-ctx.Done():
				return false
			case dataChan <- chunk:
				return true
			}
		}

		bootstrapEligible := func(err error) bool {
			if coreexecutor.IsImageRequestTimeout(err) || coreexecutor.ImageRequestContextError(ctx, nil) != nil {
				return false
			}
			status := statusFromError(err)
			if status == 0 {
				return true
			}
			switch status {
			case http.StatusUnauthorized, http.StatusForbidden, http.StatusPaymentRequired,
				http.StatusRequestTimeout, http.StatusTooManyRequests:
				return true
			default:
				return status >= http.StatusInternalServerError
			}
		}

	outer:
		for {
			var bootstrapDetector SSEBootstrapDetector
			var responsesSSEFramer sseDataJSONFramer
			var bootstrapBuffer bytes.Buffer
			var pendingProtocolProjection *interfaces.ErrorMessage
			flushBootstrapBuffer := func() bool {
				if bootstrapBuffer.Len() == 0 {
					return true
				}
				payload := cloneBytes(bootstrapBuffer.Bytes())
				bootstrapBuffer.Reset()
				return sendData(payload)
			}
			forwardPayload := func(payload []byte, clone, validatedSemantic bool) bool {
				if validatedSemantic || bootstrapDetector.Feed(payload) {
					sentPayload = true
				}
				if clone {
					payload = cloneBytes(payload)
				}
				if !sentPayload && bootstrapBuffer.Len()+len(payload) <= maxStreamingBootstrapBufferBytes {
					_, _ = bootstrapBuffer.Write(payload)
					return true
				}
				if bootstrapBuffer.Len() > 0 {
					if !flushBootstrapBuffer() {
						return false
					}
					sentPayload = true
				}
				sentPayload = true
				return sendData(payload)
			}
			for {
				var chunk coreexecutor.StreamChunk
				var ok bool
				if ctx != nil {
					select {
					case <-ctx.Done():
						return
					case chunk, ok = <-chunks:
					}
				} else {
					chunk, ok = <-chunks
				}
				if !ok {
					if pendingProtocolProjection != nil {
						_ = sendErr(pendingProtocolProjection)
						return
					}
					if handlerType == "openai-response" && !imageStreamPassthrough() && !trustResponsesSSE {
						frames, err := responsesSSEFramer.Finish()
						if err != nil {
							_ = sendErr(h.RewriteExecutionErrorResponseForContext(ctx, &interfaces.ErrorMessage{StatusCode: http.StatusBadGateway, Error: err}))
							return
						}
						for _, frame := range frames {
							if !forwardPayload(frame, false, sseDataJSONFrameHasSemanticData(frame)) {
								return
							}
						}
						if bootstrapBuffer.Len() > 0 && !flushBootstrapBuffer() {
							return
						}
					} else if !sentPayload && handlerType == "openai-response" && !trustResponsesSSE &&
						sseDataJSONCanEmitWithoutDelimiter(bootstrapBuffer.Bytes()) {
						sentPayload = true
						_ = flushBootstrapBuffer()
					} else if handlerType == "openai-response" && trustResponsesSSE && bootstrapBuffer.Len() > 0 {
						sentPayload = true
						_ = flushBootstrapBuffer()
					}
					return
				}
				if chunk.Err != nil {
					streamErr := chunk.Err
					// Safe bootstrap recovery: if the upstream fails before any payload bytes are sent,
					// retry a few times (to allow auth rotation / transient recovery) and then attempt model fallback.
					if !sentPayload && pendingProtocolProjection == nil {
						if bootstrapRetries < maxBootstrapRetries && allowRequestErrorRetry(streamErr) && bootstrapEligible(streamErr) && coreauth.ConsumeRequestRetryBudget(ctx) {
							bootstrapRetries++
							retryResult, retryErr := h.AuthManager.ExecuteStream(ctx, providers, req, opts)
							if retryErr == nil {
								if upstreamHeaders != nil {
									replaceHeader(upstreamHeaders, ClientUpstreamHeaders(retryResult.Headers, passthroughHeadersEnabled))
								}
								chunks = retryResult.Chunks
								continue outer
							}
							streamErr = coreexecutor.PreferUpstreamError(streamErr, enrichAuthSelectionError(retryErr, providers, normalizedRouteModel))
						}
					}

					errMsg := h.RewriteExecutionErrorResponseForContext(ctx, executionErrorMessage(streamErr, providers, normalizedRouteModel))
					if pendingProtocolProjection != nil && !IsErrorResponseRewritten(errMsg) {
						errMsg = pendingProtocolProjection
					}
					_ = sendErr(errMsg)
					return
				}
				if coreexecutor.IsBootstrapCommitStreamChunk(chunk) {
					sentPayload = true
					publishHeaders()
					if !flushBootstrapBuffer() {
						return
					}
					continue
				}
				if len(chunk.Payload) > 0 {
					effectiveImageStreamPassthrough := imageStreamPassthrough()
					if pendingProtocolProjection != nil {
						continue
					}
					if handlerType != "openai-response" {
						protocolPayload := executorhelps.JSONPayload(chunk.Payload)
						if len(protocolPayload) > 0 && executorhelps.IsJSONStreamProtocolError(protocolPayload) {
							protocolProvider := "upstream"
							switch handlerType {
							case constant.Claude:
								protocolProvider = "claude"
							case constant.Gemini:
								protocolProvider = "gemini"
							}
							original := executionErrorMessage(executorhelps.JSONStreamProtocolError(protocolProvider, protocolPayload), providers, normalizedRouteModel)
							projected := h.RewriteExecutionErrorResponseForContext(ctx, original)
							if projected != original {
								pendingProtocolProjection = projected
								continue
							}
						}
					}
					if handlerType == "openai-response" && !effectiveImageStreamPassthrough && !trustResponsesSSE {
						frames, err := responsesSSEFramer.Feed(chunk.Payload)
						if err != nil {
							_ = sendErr(h.RewriteExecutionErrorResponseForContext(ctx, &interfaces.ErrorMessage{StatusCode: http.StatusBadGateway, Error: err}))
							return
						}
						for _, frame := range frames {
							if !forwardPayload(frame, false, sseDataJSONFrameHasSemanticData(frame)) {
								return
							}
						}
						continue
					}
					validatedSemantic := !trustResponsesSSE &&
						sseDataJSONCanEmitWithoutDelimiter(chunk.Payload) &&
						sseDataJSONFrameHasSemanticData(chunk.Payload)
					if !forwardPayload(chunk.Payload, !effectiveImageStreamPassthrough && !trustResponsesSSE, validatedSemantic) {
						return
					}
				}
			}
		}
	}()
	<-headersReady
	return dataChan, upstreamHeaders, errChan
}

func statusFromError(err error) int {
	if err == nil {
		return 0
	}
	var se interface{ StatusCode() int }
	if errors.As(err, &se) && se != nil {
		if code := se.StatusCode(); code > 0 {
			return code
		}
	}
	if errors.Is(err, context.Canceled) {
		return 499
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout
	}
	return 0
}

// ExecutionErrorMessage preserves an execution failure's status, cause, and headers.
func ExecutionErrorMessage(err error) *interfaces.ErrorMessage {
	return executionErrorMessage(err, nil, "")
}

func executionErrorMessage(err error, providers []string, model string) *interfaces.ErrorMessage {
	err = enrichAuthSelectionError(err, providers, model)
	status := http.StatusInternalServerError
	if code := statusFromError(err); code > 0 {
		status = code
	}
	var addon http.Header
	var he interface{ Headers() http.Header }
	if errors.As(err, &he) && he != nil {
		if hdr := he.Headers(); hdr != nil {
			addon = hdr.Clone()
		}
	}
	return &interfaces.ErrorMessage{StatusCode: status, Error: err, Addon: addon}
}

func (h *BaseAPIHandler) getRequestDetails(modelName string) (providers []string, normalizedModel string, err *interfaces.ErrorMessage) {
	resolvedModelName := modelName
	initialSuffix := thinking.ParseSuffix(modelName)
	if initialSuffix.ModelName == "auto" {
		resolvedBase := util.ResolveAutoModel(initialSuffix.ModelName)
		if initialSuffix.HasSuffix {
			resolvedModelName = fmt.Sprintf("%s(%s)", resolvedBase, initialSuffix.RawSuffix)
		} else {
			resolvedModelName = resolvedBase
		}
	} else {
		resolvedModelName = util.ResolveAutoModel(modelName)
	}

	parsed := thinking.ParseSuffix(resolvedModelName)
	baseModel := strings.TrimSpace(parsed.ModelName)

	if h.isConfiguredImageModel(baseModel) {
		return nil, "", &interfaces.ErrorMessage{
			StatusCode: http.StatusServiceUnavailable,
			Error:      fmt.Errorf("model %s is only supported on /v1/images/generations and /v1/images/edits", baseModel),
		}
	}

	providers = util.GetProviderName(baseModel)
	// Fallback: if baseModel has no provider but differs from resolvedModelName,
	// try using the full model name. This handles edge cases where custom models
	// may be registered with their full suffixed name (e.g., "my-model(8192)").
	// Evaluated in Story 11.8: This fallback is intentionally preserved to support
	// custom model registrations that include thinking suffixes.
	if len(providers) == 0 && baseModel != resolvedModelName {
		providers = util.GetProviderName(resolvedModelName)
	}

	if len(providers) == 0 {
		// Preserve gateway status so callers can try another channel for this model.
		return nil, "", &interfaces.ErrorMessage{StatusCode: http.StatusBadGateway, Error: fmt.Errorf("unknown provider for model %s", modelName)}
	}

	// The thinking suffix is preserved in the model name itself, so no
	// metadata-based configuration passing is needed.
	return providers, resolvedModelName, nil
}

func (h *BaseAPIHandler) isConfiguredImageModel(model string) bool {
	var cfg config.ImagesConfig
	if h != nil && h.Cfg != nil {
		cfg = h.Cfg.Images
	}
	models := append(cfg.ResolvedImageModels(), cfg.ResolvedChatGPTWebImageModels()...)
	for _, endpoint := range []config.NativeImageEndpointConfig{cfg.Native.Generations, cfg.Native.Edits} {
		if endpoint.Enabled {
			nativeModels := endpoint.Models
			if len(nativeModels) == 0 {
				nativeModels = config.DefaultCodexImageModels()
			}
			models = append(models, nativeModels...)
		}
	}
	for _, candidate := range models {
		if strings.EqualFold(strings.TrimSpace(candidate), model) {
			return true
		}
	}
	return false
}

func cloneBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func cloneHeader(src http.Header) http.Header {
	if src == nil {
		return nil
	}
	dst := make(http.Header, len(src))
	for key, values := range src {
		dst[key] = append([]string(nil), values...)
	}
	return dst
}

func replaceHeader(dst http.Header, src http.Header) {
	for key := range dst {
		delete(dst, key)
	}
	for key, values := range src {
		dst[key] = append([]string(nil), values...)
	}
}

func enrichAuthSelectionError(err error, providers []string, model string) error {
	if err == nil {
		return nil
	}

	var authErr *coreauth.Error
	if !errors.As(err, &authErr) || authErr == nil {
		return err
	}

	code := strings.TrimSpace(authErr.Code)
	if code != "auth_not_found" && code != "auth_unavailable" {
		return err
	}

	providerText := strings.Join(providers, ",")
	if providerText == "" {
		providerText = "unknown"
	}
	modelText := strings.TrimSpace(model)
	if modelText == "" {
		modelText = "unknown"
	}

	baseMessage := strings.TrimSpace(authErr.Message)
	if baseMessage == "" {
		baseMessage = "no auth available"
	}
	detail := fmt.Sprintf("%s (providers=%s, model=%s)", baseMessage, providerText, modelText)
	storedFailure := coreauth.StoredAuthFailureOf(err)
	if storedFailure != nil && storedFailure.HTTPStatus >= 400 && storedFailure.HTTPStatus <= 599 {
		// Expose only a fixed status summary; stored messages may belong to another request.
		detail += fmt.Sprintf("; previous credential failure: HTTP %d %s", storedFailure.HTTPStatus, http.StatusText(storedFailure.HTTPStatus))
	}

	// Clarify the most common alias confusion between Anthropic route names and internal provider keys.
	if strings.Contains(","+providerText+",", ",claude,") {
		detail += "; check Claude auth/key session and cooldown state via /v0/management/auth-files"
	}

	status := authErr.HTTPStatus
	if status <= 0 {
		status = http.StatusServiceUnavailable
	}

	enriched := *authErr
	enriched.Message = detail
	enriched.HTTPStatus = status
	enriched.Diagnostic = authErr.Diagnostic.Clone()
	result := coreauth.WithStoredAuthFailure(&enriched, storedFailure)
	var headerError interface{ Headers() http.Header }
	if errors.As(err, &headerError) && headerError != nil {
		result = coreauth.WithResponseHeaders(result, headerError.Headers())
	}
	if source, ok := coreexecutor.ErrorResponseSourceOf(err); ok {
		result = coreexecutor.WithErrorResponseSource(result, source)
	}
	return result
}

func shouldForwardErrorAddonHeader(key string, passthroughHeaders bool) bool {
	if isLocalCORSHeader(key) {
		return false
	}
	if passthroughHeaders {
		return true
	}
	return strings.EqualFold(key, "Retry-After")
}

func applyErrorAddonHeaders(dst http.Header, addon http.Header, passthroughHeaders bool) {
	if dst == nil || addon == nil {
		return
	}
	for key, values := range addon {
		if len(values) == 0 || !shouldForwardErrorAddonHeader(key, passthroughHeaders) {
			continue
		}
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// WriteErrorResponse writes an error message to the response writer using the HTTP status embedded in the message.
func (h *BaseAPIHandler) WriteErrorResponse(c *gin.Context, msg *interfaces.ErrorMessage) {
	msg = h.ProjectChatGPTWebImageErrorResponse(c, msg)
	status := http.StatusInternalServerError
	if msg != nil && msg.StatusCode > 0 {
		status = msg.StatusCode
	}
	if IsErrorResponseRewritten(msg) {
		_, bodyRewritten := RewrittenErrorResponseBody(msg)
		for key := range c.Writer.Header() {
			if ShouldRemoveRewrittenErrorHeader(key, status, bodyRewritten) {
				c.Writer.Header().Del(key)
			}
		}
	}
	if msg != nil && msg.Addon != nil {
		applyErrorAddonHeaders(c.Writer.Header(), msg.Addon, PassthroughHeadersEnabled(h.Cfg))
	}

	errText := http.StatusText(status)
	if msg != nil && msg.Error != nil {
		if v := strings.TrimSpace(msg.Error.Error()); v != "" {
			errText = v
		}
	}

	body := BuildErrorResponseBodyForMessage(status, errText, msg)
	logging.RecordResponseError(c, status, body)
	// Append first to preserve upstream response logs, then drop duplicate payloads if already recorded.
	var previous []byte
	if existing, exists := c.Get("API_RESPONSE"); exists {
		if existingBytes, ok := existing.([]byte); ok && len(existingBytes) > 0 {
			previous = existingBytes
		}
	}
	appendAPIResponse(c, body)
	trimmedErrText := strings.TrimSpace(errText)
	trimmedBody := bytes.TrimSpace(body)
	if len(previous) > 0 {
		if (trimmedErrText != "" && bytes.Contains(previous, []byte(trimmedErrText))) ||
			(len(trimmedBody) > 0 && bytes.Contains(previous, trimmedBody)) {
			c.Set("API_RESPONSE", previous)
		}
	}

	if !c.Writer.Written() {
		c.Writer.Header().Set("Content-Type", "application/json")
	}
	c.Status(status)
	_, _ = c.Writer.Write(body)
}

func (h *BaseAPIHandler) recordResponseError(c *gin.Context, msg *interfaces.ErrorMessage) {
	if c == nil || msg == nil || msg.StatusCode == 499 || (msg.StatusCode < 400 && errors.Is(msg.Error, context.Canceled)) {
		return
	}
	body, projected := h.BuildPublicErrorResponseBody(c, msg)
	status := http.StatusInternalServerError
	if projected != nil && projected.StatusCode > 0 {
		status = projected.StatusCode
	}
	logging.RecordResponseError(c, status, body)
}

func (h *BaseAPIHandler) LoggingAPIResponseError(ctx context.Context, err *interfaces.ErrorMessage) {
	if ctx == nil {
		return
	}
	if c, ok := ctx.Value("gin").(*gin.Context); ok {
		h.recordResponseError(c, err)
	}
	if cfg := h.ConfigSnapshot(); cfg != nil && cfg.RequestLog {
		if ginContext, ok := ctx.Value("gin").(*gin.Context); ok && ginContext != nil {
			if redactor := util.PromptCacheLogForGin(ginContext); redactor != nil && err != nil {
				copyError := *err
				if err.Error != nil {
					copyError.Error = errors.New(redactor.Redact(err.Error.Error()))
				}
				copyError.Addon = redactor.Headers(err.Addon)
				err = &copyError
			}
			if apiResponseErrors, isExist := ginContext.Get("API_RESPONSE_ERROR"); isExist {
				if slicesAPIResponseError, isOk := apiResponseErrors.([]*interfaces.ErrorMessage); isOk {
					slicesAPIResponseError = append(slicesAPIResponseError, err)
					ginContext.Set("API_RESPONSE_ERROR", slicesAPIResponseError)
				}
			} else {
				// Create new response data entry
				ginContext.Set("API_RESPONSE_ERROR", []*interfaces.ErrorMessage{err})
			}
		}
	}
}

// APIHandlerCancelFunc is a function type for canceling an API handler's context.
// It can optionally accept parameters, which are used for logging the response.
type APIHandlerCancelFunc func(params ...interface{})
