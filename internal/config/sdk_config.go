// Package config provides configuration management for the CLI Proxy API server.
// It handles loading and parsing YAML configuration files, and provides structured
// access to application settings including server port, authentication directory,
// debug settings, proxy configuration, and API keys.
package config

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// SDKConfig represents the application's configuration, loaded from a YAML file.
type SDKConfig struct {
	// CodexOptimizeMultiAgentV2 is a derived request policy, never a saved SDK field.
	CodexOptimizeMultiAgentV2 bool `yaml:"-" json:"-"`
	// CodexOrphanDelegationCompatibility is a derived Responses handler policy.
	CodexOrphanDelegationCompatibility bool `yaml:"-" json:"-"`
	// ProxyURL is the URL of an optional proxy server to use for outbound requests.
	ProxyURL string `yaml:"proxy-url" json:"proxy-url"`

	// ProxyPools defines reusable structured proxy sources.
	ProxyPools []ProxyPoolConfig `yaml:"proxy-pools" json:"proxy-pools,omitempty"`

	// ProxyRules selects proxy pools by runtime provider and credential priority.
	ProxyRules []ProxyRuleConfig `yaml:"proxy-rules" json:"proxy-rules,omitempty"`

	// ProxyHealthCheck configures shared background and management proxy probes.
	ProxyHealthCheck ProxyHealthCheckConfig `yaml:"proxy-health-check,omitempty" json:"proxy-health-check,omitempty"`

	// EnableGeminiCLIEndpoint is retained for v6 source compatibility and has no effect.
	// Gemini CLI routes and execution support have been removed.
	EnableGeminiCLIEndpoint bool `yaml:"-" json:"-"`

	// ForceModelPrefix requires explicit model prefixes (e.g., "teamA/gemini-3-pro-preview")
	// to target prefixed credentials. When false, unprefixed model requests may use prefixed
	// credentials as well.
	ForceModelPrefix bool `yaml:"force-model-prefix" json:"force-model-prefix"`

	// RequestLog enables or disables detailed request logging functionality.
	RequestLog bool `yaml:"request-log" json:"request-log"`

	// RequestBodyRelease controls timed release of retained request body copies.
	RequestBodyRelease RequestBodyReleaseConfig `yaml:"request-body-release" json:"request-body-release"`

	// APIKeys is a list of keys for authenticating clients to this proxy server.
	APIKeys []string `yaml:"api-keys" json:"api-keys"`

	// APIKeyGroups optionally restricts API keys to selected runtime providers.
	APIKeyGroups []APIKeyGroup `yaml:"api-key-groups" json:"api-key-groups"`

	// PassthroughHeaders controls whether upstream response headers are forwarded to downstream clients.
	// Default is false (disabled).
	PassthroughHeaders bool `yaml:"passthrough-headers" json:"passthrough-headers"`

	// ErrorResponseRewrites changes selected final runtime and local-conversion error responses.
	ErrorResponseRewrites []ErrorResponseRewriteRule `yaml:"error-response-rewrites,omitempty" json:"error-response-rewrites,omitempty"`

	// Streaming configures server-side streaming behavior (keep-alives and safe bootstrap retries).
	Streaming StreamingConfig `yaml:"streaming" json:"streaming"`

	// NonStreamKeepAliveInterval controls how often blank lines are emitted for non-streaming responses.
	// <= 0 disables keep-alives. Value is in seconds.
	NonStreamKeepAliveInterval int `yaml:"nonstream-keepalive-interval,omitempty" json:"nonstream-keepalive-interval,omitempty"`

	// Images configures OpenAI Images compatibility backed by Codex Responses.
	Images ImagesConfig `yaml:"images,omitempty" json:"images,omitempty"`
}

// ProxyPoolConfig defines one named proxy pool.
type ProxyPoolConfig struct {
	Name                 string                 `yaml:"name" json:"name"`
	PlaceholderCharset   string                 `yaml:"placeholder-charset,omitempty" json:"placeholder-charset,omitempty"`
	CheckIntervalSeconds int                    `yaml:"check-interval-seconds,omitempty" json:"check-interval-seconds,omitempty"`
	BindAttempts         int                    `yaml:"bind-attempts,omitempty" json:"bind-attempts,omitempty"`
	SpreadBindings       bool                   `yaml:"spread-bindings,omitempty" json:"spread-bindings,omitempty"`
	Entries              []ProxyPoolEntryConfig `yaml:"entries" json:"entries"`
}

// ProxyPoolEntryConfig defines a URL template and an optional compact port set.
type ProxyPoolEntryConfig struct {
	ID          string `yaml:"id" json:"id"`
	URLTemplate string `yaml:"url-template" json:"url-template"`
	Ports       string `yaml:"ports,omitempty" json:"ports,omitempty"`
}

// ProxyHealthCheckConfig controls process-wide scheduled and management proxy probes.
type ProxyHealthCheckConfig struct {
	Concurrency            int                              `yaml:"concurrency,omitempty" json:"concurrency,omitempty"`
	EndpointTimeoutSeconds int                              `yaml:"endpoint-timeout-seconds,omitempty" json:"endpoint-timeout-seconds,omitempty"`
	FailureThreshold       int                              `yaml:"failure-threshold,omitempty" json:"failure-threshold,omitempty"`
	Endpoints              []ProxyHealthCheckEndpointConfig `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`
}

// ProxyHealthCheckEndpointConfig defines one ordered health-check endpoint.
type ProxyHealthCheckEndpointConfig struct {
	Name string `yaml:"name" json:"name"`
	URL  string `yaml:"url" json:"url"`
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`
}

// ProxyRuleTargetConfig defines one ordered proxy target candidate.
type ProxyRuleTargetConfig struct {
	Pool     string `yaml:"pool,omitempty" json:"pool,omitempty"`
	Direct   bool   `yaml:"direct,omitempty" json:"direct,omitempty"`
	Priority int    `yaml:"priority,omitempty" json:"priority,omitempty"`
}

// ProxyRuleConfig routes matching credentials through one or more targets.
type ProxyRuleConfig struct {
	Name       string                  `yaml:"name" json:"name"`
	Pool       string                  `yaml:"pool,omitempty" json:"pool,omitempty"`
	Targets    []ProxyRuleTargetConfig `yaml:"targets,omitempty" json:"targets,omitempty"`
	Providers  []string                `yaml:"providers,omitempty" json:"providers,omitempty"`
	Priorities []int                   `yaml:"priorities,omitempty" json:"priorities,omitempty"`
}

// APIKeyGroup restricts one configured client key to providers and credential priorities.
type APIKeyGroup struct {
	APIKey string `yaml:"api-key" json:"api-key"`
	// Name is an optional display label and never participates in authorization.
	Name      string   `yaml:"name,omitempty" json:"name,omitempty"`
	Providers []string `yaml:"providers" json:"providers"`
	// Empty allow lists impose no priority restriction; exclusions always win.
	AllowedPriorities  APIKeyPriorityList `yaml:"allowed-priorities,omitempty" json:"allowed-priorities,omitempty"`
	ExcludedPriorities APIKeyPriorityList `yaml:"excluded-priorities,omitempty" json:"excluded-priorities,omitempty"`
}

// ErrorResponseRewriteRule projects a matching final error to a client-facing status or JSON body.
type ErrorResponseRewriteRule struct {
	// Sources optionally restricts the rule to final error provider IDs or local errors.
	Sources []string `yaml:"sources,omitempty" json:"sources,omitempty"`
	// AuthPriorities optionally restricts the rule to final credential priorities.
	AuthPriorities []int `yaml:"auth-priorities,omitempty" json:"auth-priorities,omitempty"`
	// StatusCode optionally restricts the rule to one original HTTP status code.
	StatusCode int `yaml:"status-code,omitempty" json:"status-code,omitempty"`
	// MessageContains optionally matches the original error text case-insensitively.
	MessageContains string `yaml:"message-contains,omitempty" json:"message-contains,omitempty"`
	// ResponseStatusCode optionally replaces the downstream HTTP or event status.
	ResponseStatusCode int `yaml:"response-status-code,omitempty" json:"response-status-code,omitempty"`
	// ResponseBody optionally replaces the downstream JSON object. A non-nil empty map means {}.
	ResponseBody *map[string]any `yaml:"response-body,omitempty" json:"response-body,omitempty"`
}

// StreamingConfig holds server streaming behavior configuration.
type StreamingConfig struct {
	// KeepAliveSeconds controls SSE heartbeats (": keep-alive\n\n") and WebSocket Ping frames.
	// <= 0 or a value overflowing time.Duration disables keep-alives. Default is 0.
	KeepAliveSeconds int `yaml:"keepalive-seconds,omitempty" json:"keepalive-seconds,omitempty"`

	// BootstrapRetries controls how many times the server may retry a streaming request before any bytes are sent,
	// to allow auth rotation / transient recovery.
	// <= 0 disables bootstrap retries. Default is 0.
	BootstrapRetries int `yaml:"bootstrap-retries,omitempty" json:"bootstrap-retries,omitempty"`

	// EnableStreamFlush enables flush batching for regular streaming responses.
	// Default is false to preserve token-by-token latency.
	EnableStreamFlush bool `yaml:"enable-stream-flush,omitempty" json:"enable-stream-flush,omitempty"`

	// StreamFlushIntervalMS batches regular streaming flushes for up to this many milliseconds.
	StreamFlushIntervalMS int `yaml:"stream-flush-interval-ms,omitempty" json:"stream-flush-interval-ms,omitempty"`

	// StreamFlushMinBytes flushes regular streaming output once this many bytes are pending.
	StreamFlushMinBytes int `yaml:"stream-flush-min-bytes,omitempty" json:"stream-flush-min-bytes,omitempty"`

	// TrustUpstreamSSE forwards OpenAI Responses SSE without repair/validation.
	// Default is false for compatibility with split or incomplete upstream SSE frames.
	TrustUpstreamSSE bool `yaml:"trust-upstream-sse,omitempty" json:"trust-upstream-sse,omitempty"`
}

// ImagesConfig holds OpenAI Images compatibility configuration.
type ImagesConfig struct {
	// CodexRequestTimeoutSeconds bounds the logical Codex image request, including tool/native retries.
	CodexRequestTimeoutSeconds int `yaml:"codex-request-timeout-seconds" json:"codex-request-timeout-seconds"`
	// CodexModel is the outer Responses model used to invoke the Codex image_generation tool.
	CodexModel string `yaml:"codex-model,omitempty" json:"codex-model,omitempty"`
	// ImageModel is the default when an Images API request omits its model.
	ImageModel string `yaml:"image-model,omitempty" json:"image-model,omitempty"`
	// ImageModels lists selectable Codex image tool models in addition to the default.
	ImageModels []string `yaml:"image-models,omitempty" json:"image-models,omitempty"`
	// EnableFreePlanImageModel controls whether Codex free-plan auths register the configured image model.
	EnableFreePlanImageModel bool `yaml:"enable-free-plan-image-model,omitempty" json:"enable-free-plan-image-model,omitempty"`
	// EnableNAggregation enables multi-call aggregation for Images API n > 1 requests.
	EnableNAggregation *bool `yaml:"enable-n-aggregation,omitempty" json:"enable-n-aggregation,omitempty"`
	// UnsupportedStatusCode is used for unsupported Images API options.
	UnsupportedStatusCode int `yaml:"unsupported-status-code,omitempty" json:"unsupported-status-code,omitempty"`
	// OverrideUnsupportedParams is a legacy shortcut for enabling all supported option overrides.
	OverrideUnsupportedParams bool `yaml:"override-unsupported-params,omitempty" json:"override-unsupported-params,omitempty"`
	// OverrideResponseFormatURL coerces response_format=url to b64_json when set.
	OverrideResponseFormatURL *bool `yaml:"override-response-format-url,omitempty" json:"override-response-format-url,omitempty"`
	// ResponseFormatURLDataURL returns data: URLs for response_format=url when set.
	ResponseFormatURLDataURL *bool `yaml:"response-format-url-data-url,omitempty" json:"response-format-url-data-url,omitempty"`
	// OverrideTransparentBackground coerces background=transparent to auto when set.
	OverrideTransparentBackground *bool `yaml:"override-transparent-background,omitempty" json:"override-transparent-background,omitempty"`
	// OverrideInputFidelity omits input_fidelity instead of forwarding it when set.
	OverrideInputFidelity *bool `yaml:"override-input-fidelity,omitempty" json:"override-input-fidelity,omitempty"`
	// EnableStreamFlush enables flush batching for image streaming responses. Default is true.
	EnableStreamFlush *bool `yaml:"enable-stream-flush,omitempty" json:"enable-stream-flush,omitempty"`
	// StreamFlushIntervalMS batches image streaming flushes for up to this many milliseconds.
	StreamFlushIntervalMS int `yaml:"stream-flush-interval-ms,omitempty" json:"stream-flush-interval-ms,omitempty"`
	// StreamFlushMinBytes flushes image streaming output once this many bytes are pending.
	StreamFlushMinBytes int `yaml:"stream-flush-min-bytes,omitempty" json:"stream-flush-min-bytes,omitempty"`
	// ChatGPTWeb configures the ChatGPT Web image compatibility path.
	ChatGPTWeb ChatGPTWebImageConfig `yaml:"chatgpt-web,omitempty" json:"chatgpt-web,omitempty"`
	// Native configures direct Codex Images API proxying.
	Native NativeImagesConfig `yaml:"native,omitempty" json:"native,omitempty"`
}

// ChatGPTWebImageConfig controls the ChatGPT Web image compatibility path.
type ChatGPTWebImageConfig struct {
	// RequestTimeoutSeconds bounds one logical Web image request; zero disables the budget.
	RequestTimeoutSeconds int `yaml:"request-timeout-seconds" json:"request-timeout-seconds"`
	// BootstrapTimeoutSeconds bounds one image homepage attempt, including redirects and body reads.
	BootstrapTimeoutSeconds int `yaml:"bootstrap-timeout-seconds" json:"bootstrap-timeout-seconds"`
	// BootstrapRetries counts additional homepage attempts before normal credential failover.
	BootstrapRetries int `yaml:"bootstrap-retries" json:"bootstrap-retries"`
	// ImageModels lists public aliases for the shared Web image capability, not upstream engines.
	ImageModels []string `yaml:"image-models,omitempty" json:"image-models,omitempty"`
	// UpstreamModel is the ChatGPT Web conversation model that invokes picture_v2.
	UpstreamModel string `yaml:"upstream-model,omitempty" json:"upstream-model,omitempty"`
	// RemoteImageURLEnabled allows protected downloads for remote image inputs.
	RemoteImageURLEnabled bool `yaml:"remote-image-url-enabled,omitempty" json:"remote-image-url-enabled,omitempty"`
	// RemoteImageURLDownloadMode selects direct downloads or the selected credential's effective proxy.
	RemoteImageURLDownloadMode string `yaml:"remote-image-url-download-mode,omitempty" json:"remote-image-url-download-mode,omitempty"`
	// IgnoreUnsupportedParams allows Web routing after dropping options that Web cannot express.
	IgnoreUnsupportedParams bool `yaml:"ignore-unsupported-params,omitempty" json:"ignore-unsupported-params,omitempty"`
	// NormalizeMismatchedImageMIME trusts a supported image's decoded format over its declared MIME type.
	NormalizeMismatchedImageMIME bool `yaml:"normalize-mismatched-image-mime,omitempty" json:"normalize-mismatched-image-mime,omitempty"`
	// NormalizeRemoteImageMIME extends MIME normalization to downloaded remote images.
	NormalizeRemoteImageMIME *bool `yaml:"normalize-remote-image-mime,omitempty" json:"normalize-remote-image-mime,omitempty"`
	// SanitizeErrorResponses removes provider and internal implementation details from public image errors.
	SanitizeErrorResponses bool `yaml:"sanitize-error-responses,omitempty" json:"sanitize-error-responses,omitempty"`
	// AutoCleanupLibraryOnFull schedules account maintenance only after a storage rejection and capacity recheck.
	AutoCleanupLibraryOnFull bool `yaml:"auto-cleanup-library-on-full,omitempty" json:"auto-cleanup-library-on-full,omitempty"`
	// AdaptSizeToAspectRatio maps compatible explicit image sizes to an upstream canvas prompt.
	AdaptSizeToAspectRatio bool `yaml:"adapt-size-to-aspect-ratio,omitempty" json:"adapt-size-to-aspect-ratio,omitempty"`
	// StrictSize excludes ChatGPT Web when an explicit image size cannot be adapted.
	StrictSize bool `yaml:"strict-size,omitempty" json:"strict-size,omitempty"`
	// AspectRatioMaxErrorPercent is the maximum relative error accepted for generated output.
	AspectRatioMaxErrorPercent *float64 `yaml:"aspect-ratio-max-error-percent,omitempty" json:"aspect-ratio-max-error-percent,omitempty"`
	// MaxResizeEdgePixels limits explicit size adaptation targets.
	MaxResizeEdgePixels *int `yaml:"max-resize-edge-pixels,omitempty" json:"max-resize-edge-pixels,omitempty"`
	// ResizeToRequestedSize resizes matched Web image results to the explicit target.
	ResizeToRequestedSize bool `yaml:"resize-to-requested-size,omitempty" json:"resize-to-requested-size,omitempty"`
	// ResizeFilter selects the local image resampling filter.
	ResizeFilter string `yaml:"resize-filter,omitempty" json:"resize-filter,omitempty"`
	// MaxImageResponseMegabytes limits final compressed image bytes per request.
	MaxImageResponseMegabytes *int `yaml:"max-image-response-megabytes,omitempty" json:"max-image-response-megabytes,omitempty"`
	// MaxN limits the number of images requested from ChatGPT Web in one logical request.
	MaxN *int `yaml:"max-n,omitempty" json:"max-n,omitempty"`
	// MaxInFlight bounds complete ChatGPT Web image attempts, including sleeping polls.
	MaxInFlight *int `yaml:"max-in-flight,omitempty" json:"max-in-flight,omitempty"`
	// AdmissionQueueSize bounds requests waiting to enter the Web image lifecycle.
	AdmissionQueueSize *int `yaml:"admission-queue-size,omitempty" json:"admission-queue-size,omitempty"`
	// AdmissionWaitMilliseconds limits pre-upstream lifecycle admission waiting.
	AdmissionWaitMilliseconds *int `yaml:"admission-wait-milliseconds,omitempty" json:"admission-wait-milliseconds,omitempty"`
	// MaxFinalizers bounds settled requests admitted to finalizer staging. Heavy
	// memory finalization is controlled independently.
	MaxFinalizers *int `yaml:"max-finalizers,omitempty" json:"max-finalizers,omitempty"`
	// CompletionReserveMegabytes reserves a small per-attempt completion allowance before upstream work.
	CompletionReserveMegabytes *int `yaml:"completion-reserve-megabytes,omitempty" json:"completion-reserve-megabytes,omitempty"`
	// MemoryCapacityMegabytes bounds the shared process-wide ChatGPT Web image working set.
	MemoryCapacityMegabytes *int `yaml:"memory-capacity-megabytes,omitempty" json:"memory-capacity-megabytes,omitempty"`
	// PollConcurrency bounds concurrent ChatGPT Web image poll HTTP requests.
	PollConcurrency *int `yaml:"poll-concurrency,omitempty" json:"poll-concurrency,omitempty"`
	// PollStallBreakerEnabled rejects new image attempts when every poll slot has
	// remained occupied without a completed exchange for the configured interval.
	PollStallBreakerEnabled *bool `yaml:"poll-stall-breaker-enabled,omitempty" json:"poll-stall-breaker-enabled,omitempty"`
	// PollStallSeconds controls how long full poll-slot saturation may make no
	// transport progress before the breaker opens.
	PollStallSeconds *int `yaml:"poll-stall-seconds,omitempty" json:"poll-stall-seconds,omitempty"`
	// MemoryFinalizerConcurrency bounds finalizers that download to disk and
	// reserve their complete in-memory working set before decode or encode work.
	MemoryFinalizerConcurrency *int `yaml:"memory-finalizer-concurrency,omitempty" json:"memory-finalizer-concurrency,omitempty"`
}

const (
	DefaultChatGPTWebAspectRatioMaxErrorPercent  = 1.0
	MaxChatGPTWebAspectRatioMaxErrorPercent      = 10.0
	DefaultChatGPTWebMaxResizeEdgePixels         = 3840
	MaxChatGPTWebMaxResizeEdgePixels             = 3840
	ChatGPTWebResizeFilterCatmullRom             = "catmull-rom"
	ChatGPTWebResizeFilterApproxBiLinear         = "approx-bilinear"
	DefaultChatGPTWebResizeFilter                = ChatGPTWebResizeFilterCatmullRom
	ChatGPTWebRemoteImageDownloadDirect          = "direct"
	ChatGPTWebRemoteImageDownloadCredentialProxy = "credential-proxy"
	DefaultChatGPTWebRemoteImageDownloadMode     = ChatGPTWebRemoteImageDownloadDirect
	DefaultChatGPTWebMaxImageResponseMegabytes   = 128
	MinChatGPTWebMaxImageResponseMegabytes       = 1
	MaxChatGPTWebMaxImageResponseMegabytes       = 256
	DefaultChatGPTWebMaxN                        = 1
	MinChatGPTWebMaxN                            = 1
	MaxChatGPTWebMaxN                            = 10
	DefaultChatGPTWebImageMaxInFlight            = 64
	MinChatGPTWebImageMaxInFlight                = 1
	RecommendedMaxChatGPTWebImageMaxInFlight     = 4096
	// Deprecated: this advisory alias is not a validation limit. Use RecommendedMaxChatGPTWebImageMaxInFlight.
	MaxChatGPTWebImageMaxInFlight                   = RecommendedMaxChatGPTWebImageMaxInFlight
	DefaultChatGPTWebImageAdmissionQueueSize        = 64
	MinChatGPTWebImageAdmissionQueueSize            = 0
	RecommendedMaxChatGPTWebImageAdmissionQueueSize = 4096
	// Deprecated: this advisory alias is not a validation limit. Use RecommendedMaxChatGPTWebImageAdmissionQueueSize.
	MaxChatGPTWebImageAdmissionQueueSize         = RecommendedMaxChatGPTWebImageAdmissionQueueSize
	DefaultChatGPTWebImageAdmissionWaitMS        = 1000
	MinChatGPTWebImageAdmissionWaitMS            = 0
	RecommendedMaxChatGPTWebImageAdmissionWaitMS = 30000
	// Deprecated: this advisory alias is not a validation limit. Use RecommendedMaxChatGPTWebImageAdmissionWaitMS.
	MaxChatGPTWebImageAdmissionWaitMS          = RecommendedMaxChatGPTWebImageAdmissionWaitMS
	DefaultChatGPTWebImageMaxFinalizers        = 8
	MinChatGPTWebImageMaxFinalizers            = 1
	RecommendedMaxChatGPTWebImageMaxFinalizers = 64
	// Deprecated: this advisory alias is not a validation limit. Use RecommendedMaxChatGPTWebImageMaxFinalizers.
	MaxChatGPTWebImageMaxFinalizers                  = RecommendedMaxChatGPTWebImageMaxFinalizers
	DefaultChatGPTWebImageCompletionReserveMB        = 1
	MinChatGPTWebImageCompletionReserveMB            = 0
	RecommendedMaxChatGPTWebImageCompletionReserveMB = 32
	// Deprecated: this advisory alias is not a validation limit. Use RecommendedMaxChatGPTWebImageCompletionReserveMB.
	MaxChatGPTWebImageCompletionReserveMB         = RecommendedMaxChatGPTWebImageCompletionReserveMB
	DefaultChatGPTWebImageMemoryCapacityMB        = 512
	MinChatGPTWebImageMemoryCapacityMB            = 1
	RecommendedMinChatGPTWebImageMemoryCapacityMB = 64
	RecommendedMaxChatGPTWebImageMemoryCapacityMB = 8192
	// Deprecated: this advisory alias is not a validation limit. Use RecommendedMaxChatGPTWebImageMemoryCapacityMB.
	MaxChatGPTWebImageMemoryCapacityMB = RecommendedMaxChatGPTWebImageMemoryCapacityMB
)

const (
	DefaultChatGPTWebImagePollConcurrency        = 64
	MinChatGPTWebImagePollConcurrency            = 1
	RecommendedMaxChatGPTWebImagePollConcurrency = 512
	// Deprecated: this advisory alias is not a validation limit. Use RecommendedMaxChatGPTWebImagePollConcurrency.
	MaxChatGPTWebImagePollConcurrency                       = RecommendedMaxChatGPTWebImagePollConcurrency
	DefaultChatGPTWebImagePollStallBreakerEnabled           = true
	DefaultChatGPTWebImagePollStallSeconds                  = 120
	MinChatGPTWebImagePollStallSeconds                      = 30
	MaxChatGPTWebImagePollStallSeconds                      = 3600
	DefaultChatGPTWebImageMemoryFinalizerConcurrency        = 1
	MinChatGPTWebImageMemoryFinalizerConcurrency            = 1
	RecommendedMaxChatGPTWebImageMemoryFinalizerConcurrency = 64
	// Deprecated: this advisory alias is not a validation limit. Use RecommendedMaxChatGPTWebImageMemoryFinalizerConcurrency.
	MaxChatGPTWebImageMemoryFinalizerConcurrency = RecommendedMaxChatGPTWebImageMemoryFinalizerConcurrency
)

const chatGPTWebImageBytesPerMegabyte int64 = 1 << 20

// ChatGPTWebImageMegabytesToBytes converts a configured image budget without
// allowing the platform representation to wrap.
func ChatGPTWebImageMegabytesToBytes(megabytes int) (int64, error) {
	if megabytes < 0 || int64(megabytes) > math.MaxInt64/chatGPTWebImageBytesPerMegabyte {
		return 0, fmt.Errorf("image memory value cannot be represented as bytes on this platform")
	}
	return int64(megabytes) * chatGPTWebImageBytesPerMegabyte, nil
}

// ChatGPTWebImageAdmissionWaitDuration converts a configured admission wait
// without allowing time.Duration to wrap.
func ChatGPTWebImageAdmissionWaitDuration(milliseconds int) (time.Duration, error) {
	if milliseconds < 0 || int64(milliseconds) > math.MaxInt64/int64(time.Millisecond) {
		return 0, fmt.Errorf("image admission wait cannot be represented on this platform")
	}
	return time.Duration(milliseconds) * time.Millisecond, nil
}

// ResolvedChatGPTWebImageConfig contains effective ChatGPT Web image compatibility values.
type ResolvedChatGPTWebImageConfig struct {
	UpstreamModel                string
	RemoteImageURLEnabled        bool
	RemoteImageURLDownloadMode   string
	IgnoreUnsupportedParams      bool
	NormalizeMismatchedImageMIME bool
	NormalizeRemoteImageMIME     bool
	SanitizeErrorResponses       bool
	AutoCleanupLibraryOnFull     bool
	AdaptSizeToAspectRatio       bool
	StrictSize                   bool
	AspectRatioMaxErrorPercent   float64
	MaxResizeEdgePixels          int
	ResizeToRequestedSize        bool
	ResizeFilter                 string
	MaxImageResponseMegabytes    int
	MaxN                         int
	MaxInFlight                  int
	AdmissionQueueSize           int
	AdmissionWaitMilliseconds    int
	MaxFinalizers                int
	CompletionReserveMegabytes   int
	MemoryCapacityMegabytes      int
	PollConcurrency              int
	PollStallBreakerEnabled      bool
	PollStallSeconds             int
	MemoryFinalizerConcurrency   int
}

// ResolvedUpstreamModel returns the effective ChatGPT Web image conversation model.
func (cfg ChatGPTWebImageConfig) ResolvedUpstreamModel() string {
	if model := strings.TrimSpace(cfg.UpstreamModel); model != "" {
		return model
	}
	return DefaultChatGPTWebImageUpstreamModel
}

// Resolved returns the effective ChatGPT Web image compatibility configuration.
func (cfg ChatGPTWebImageConfig) Resolved() ResolvedChatGPTWebImageConfig {
	resolved := ResolvedChatGPTWebImageConfig{
		UpstreamModel:                cfg.ResolvedUpstreamModel(),
		RemoteImageURLEnabled:        cfg.RemoteImageURLEnabled,
		RemoteImageURLDownloadMode:   DefaultChatGPTWebRemoteImageDownloadMode,
		IgnoreUnsupportedParams:      cfg.IgnoreUnsupportedParams,
		NormalizeMismatchedImageMIME: cfg.NormalizeMismatchedImageMIME,
		NormalizeRemoteImageMIME:     true,
		SanitizeErrorResponses:       cfg.SanitizeErrorResponses,
		AutoCleanupLibraryOnFull:     cfg.AutoCleanupLibraryOnFull,
		AdaptSizeToAspectRatio:       cfg.AdaptSizeToAspectRatio,
		StrictSize:                   cfg.StrictSize,
		AspectRatioMaxErrorPercent:   DefaultChatGPTWebAspectRatioMaxErrorPercent,
		MaxResizeEdgePixels:          DefaultChatGPTWebMaxResizeEdgePixels,
		ResizeToRequestedSize:        cfg.ResizeToRequestedSize,
		ResizeFilter:                 DefaultChatGPTWebResizeFilter,
		MaxImageResponseMegabytes:    DefaultChatGPTWebMaxImageResponseMegabytes,
		MaxN:                         DefaultChatGPTWebMaxN,
		MaxInFlight:                  DefaultChatGPTWebImageMaxInFlight,
		AdmissionQueueSize:           DefaultChatGPTWebImageAdmissionQueueSize,
		AdmissionWaitMilliseconds:    DefaultChatGPTWebImageAdmissionWaitMS,
		MaxFinalizers:                DefaultChatGPTWebImageMaxFinalizers,
		CompletionReserveMegabytes:   DefaultChatGPTWebImageCompletionReserveMB,
		MemoryCapacityMegabytes:      DefaultChatGPTWebImageMemoryCapacityMB,
		PollConcurrency:              DefaultChatGPTWebImagePollConcurrency,
		PollStallBreakerEnabled:      DefaultChatGPTWebImagePollStallBreakerEnabled,
		PollStallSeconds:             DefaultChatGPTWebImagePollStallSeconds,
		MemoryFinalizerConcurrency:   DefaultChatGPTWebImageMemoryFinalizerConcurrency,
	}
	if mode := strings.ToLower(strings.TrimSpace(cfg.RemoteImageURLDownloadMode)); mode != "" {
		resolved.RemoteImageURLDownloadMode = mode
	}
	if cfg.NormalizeRemoteImageMIME != nil {
		resolved.NormalizeRemoteImageMIME = *cfg.NormalizeRemoteImageMIME
	}
	if cfg.AspectRatioMaxErrorPercent != nil {
		resolved.AspectRatioMaxErrorPercent = *cfg.AspectRatioMaxErrorPercent
	}
	if cfg.MaxResizeEdgePixels != nil {
		resolved.MaxResizeEdgePixels = *cfg.MaxResizeEdgePixels
	}
	if filter := strings.ToLower(strings.TrimSpace(cfg.ResizeFilter)); filter != "" {
		resolved.ResizeFilter = filter
	}
	if cfg.MaxImageResponseMegabytes != nil {
		resolved.MaxImageResponseMegabytes = *cfg.MaxImageResponseMegabytes
	}
	if cfg.MaxN != nil {
		resolved.MaxN = *cfg.MaxN
	}
	if cfg.MaxInFlight != nil {
		resolved.MaxInFlight = *cfg.MaxInFlight
	}
	if cfg.AdmissionQueueSize != nil {
		resolved.AdmissionQueueSize = *cfg.AdmissionQueueSize
	}
	if cfg.AdmissionWaitMilliseconds != nil {
		resolved.AdmissionWaitMilliseconds = *cfg.AdmissionWaitMilliseconds
	}
	if cfg.MaxFinalizers != nil {
		resolved.MaxFinalizers = *cfg.MaxFinalizers
	}
	if cfg.CompletionReserveMegabytes != nil {
		resolved.CompletionReserveMegabytes = *cfg.CompletionReserveMegabytes
	}
	if cfg.MemoryCapacityMegabytes != nil {
		resolved.MemoryCapacityMegabytes = *cfg.MemoryCapacityMegabytes
	}
	if cfg.PollConcurrency != nil {
		resolved.PollConcurrency = *cfg.PollConcurrency
	}
	if cfg.PollStallBreakerEnabled != nil {
		resolved.PollStallBreakerEnabled = *cfg.PollStallBreakerEnabled
	}
	if cfg.PollStallSeconds != nil {
		resolved.PollStallSeconds = *cfg.PollStallSeconds
	}
	if cfg.MemoryFinalizerConcurrency != nil {
		resolved.MemoryFinalizerConcurrency = *cfg.MemoryFinalizerConcurrency
	}
	return resolved
}

// Validate rejects invalid ChatGPT Web image compatibility settings.
func (cfg ChatGPTWebImageConfig) Validate() error {
	if err := cfg.ValidateBootstrap(); err != nil {
		return err
	}
	if cfg.RequestTimeoutSeconds < 0 || cfg.RequestTimeoutSeconds > MaxImageRequestTimeoutSeconds {
		return fmt.Errorf("images.chatgpt-web.request-timeout-seconds must be between 0 and %d", MaxImageRequestTimeoutSeconds)
	}
	resolved := cfg.Resolved()
	if math.IsNaN(resolved.AspectRatioMaxErrorPercent) || math.IsInf(resolved.AspectRatioMaxErrorPercent, 0) ||
		resolved.AspectRatioMaxErrorPercent < 0 ||
		resolved.AspectRatioMaxErrorPercent > MaxChatGPTWebAspectRatioMaxErrorPercent {
		return fmt.Errorf("images.chatgpt-web.aspect-ratio-max-error-percent must be between 0 and %.0f", MaxChatGPTWebAspectRatioMaxErrorPercent)
	}
	if resolved.MaxResizeEdgePixels < 1 || resolved.MaxResizeEdgePixels > MaxChatGPTWebMaxResizeEdgePixels {
		return fmt.Errorf("images.chatgpt-web.max-resize-edge-pixels must be between 1 and %d", MaxChatGPTWebMaxResizeEdgePixels)
	}
	if resolved.ResizeToRequestedSize && !resolved.AdaptSizeToAspectRatio {
		return fmt.Errorf("images.chatgpt-web.resize-to-requested-size requires adapt-size-to-aspect-ratio")
	}
	if resolved.StrictSize && !resolved.AdaptSizeToAspectRatio {
		return fmt.Errorf("images.chatgpt-web.strict-size requires adapt-size-to-aspect-ratio")
	}
	if resolved.ResizeFilter != ChatGPTWebResizeFilterCatmullRom && resolved.ResizeFilter != ChatGPTWebResizeFilterApproxBiLinear {
		return fmt.Errorf("images.chatgpt-web.resize-filter must be %s or %s", ChatGPTWebResizeFilterCatmullRom, ChatGPTWebResizeFilterApproxBiLinear)
	}
	if resolved.RemoteImageURLDownloadMode != ChatGPTWebRemoteImageDownloadDirect &&
		resolved.RemoteImageURLDownloadMode != ChatGPTWebRemoteImageDownloadCredentialProxy {
		return fmt.Errorf("images.chatgpt-web.remote-image-url-download-mode must be %s or %s", ChatGPTWebRemoteImageDownloadDirect, ChatGPTWebRemoteImageDownloadCredentialProxy)
	}
	if resolved.MaxImageResponseMegabytes < MinChatGPTWebMaxImageResponseMegabytes ||
		resolved.MaxImageResponseMegabytes > MaxChatGPTWebMaxImageResponseMegabytes {
		return fmt.Errorf("images.chatgpt-web.max-image-response-megabytes must be between %d and %d", MinChatGPTWebMaxImageResponseMegabytes, MaxChatGPTWebMaxImageResponseMegabytes)
	}
	if resolved.MaxN < MinChatGPTWebMaxN || resolved.MaxN > MaxChatGPTWebMaxN {
		return fmt.Errorf("images.chatgpt-web.max-n must be between %d and %d", MinChatGPTWebMaxN, MaxChatGPTWebMaxN)
	}
	if resolved.MaxInFlight < MinChatGPTWebImageMaxInFlight {
		return fmt.Errorf("images.chatgpt-web.max-in-flight must be at least %d", MinChatGPTWebImageMaxInFlight)
	}
	if resolved.MaxInFlight > math.MaxInt/2 {
		return fmt.Errorf("images.chatgpt-web.max-in-flight cannot be represented safely when deriving the poll queue on this platform")
	}
	if resolved.AdmissionQueueSize < MinChatGPTWebImageAdmissionQueueSize {
		return fmt.Errorf("images.chatgpt-web.admission-queue-size must be at least %d", MinChatGPTWebImageAdmissionQueueSize)
	}
	if resolved.AdmissionWaitMilliseconds < MinChatGPTWebImageAdmissionWaitMS {
		return fmt.Errorf("images.chatgpt-web.admission-wait-milliseconds must be at least %d", MinChatGPTWebImageAdmissionWaitMS)
	}
	if _, errDuration := ChatGPTWebImageAdmissionWaitDuration(resolved.AdmissionWaitMilliseconds); errDuration != nil {
		return fmt.Errorf("images.chatgpt-web.admission-wait-milliseconds: %w", errDuration)
	}
	if resolved.MaxFinalizers < MinChatGPTWebImageMaxFinalizers {
		return fmt.Errorf("images.chatgpt-web.max-finalizers must be at least %d", MinChatGPTWebImageMaxFinalizers)
	}
	if resolved.CompletionReserveMegabytes < MinChatGPTWebImageCompletionReserveMB {
		return fmt.Errorf("images.chatgpt-web.completion-reserve-megabytes must be at least %d", MinChatGPTWebImageCompletionReserveMB)
	}
	if _, errBytes := ChatGPTWebImageMegabytesToBytes(resolved.CompletionReserveMegabytes); errBytes != nil {
		return fmt.Errorf("images.chatgpt-web.completion-reserve-megabytes: %w", errBytes)
	}
	if resolved.MemoryCapacityMegabytes < MinChatGPTWebImageMemoryCapacityMB {
		return fmt.Errorf("images.chatgpt-web.memory-capacity-megabytes must be at least %d", MinChatGPTWebImageMemoryCapacityMB)
	}
	if _, errBytes := ChatGPTWebImageMegabytesToBytes(resolved.MemoryCapacityMegabytes); errBytes != nil {
		return fmt.Errorf("images.chatgpt-web.memory-capacity-megabytes: %w", errBytes)
	}
	if resolved.PollConcurrency < MinChatGPTWebImagePollConcurrency {
		return fmt.Errorf("images.chatgpt-web.poll-concurrency must be at least %d", MinChatGPTWebImagePollConcurrency)
	}
	if resolved.PollStallSeconds < MinChatGPTWebImagePollStallSeconds || resolved.PollStallSeconds > MaxChatGPTWebImagePollStallSeconds {
		return fmt.Errorf("images.chatgpt-web.poll-stall-seconds must be between %d and %d", MinChatGPTWebImagePollStallSeconds, MaxChatGPTWebImagePollStallSeconds)
	}
	if resolved.MemoryFinalizerConcurrency < MinChatGPTWebImageMemoryFinalizerConcurrency {
		return fmt.Errorf("images.chatgpt-web.memory-finalizer-concurrency must be at least %d", MinChatGPTWebImageMemoryFinalizerConcurrency)
	}
	return nil
}

// NativeImagesConfig holds direct Codex Images API configuration.
type NativeImagesConfig struct {
	// Generations configures POST /v1/images/generations native proxying.
	Generations NativeImageEndpointConfig `yaml:"generations,omitempty" json:"generations,omitempty"`
	// Edits configures POST /v1/images/edits native proxying.
	Edits NativeImageEndpointConfig `yaml:"edits,omitempty" json:"edits,omitempty"`
}

// NativeImageEndpointConfig holds per-endpoint native Images API options.
type NativeImageEndpointConfig struct {
	// Enabled controls whether this endpoint uses the native Images API path.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Models lists image models allowed on the native path.
	Models []string `yaml:"models,omitempty" json:"models,omitempty"`
	// ParamRules deletes or overrides request parameters before forwarding.
	ParamRules []string `yaml:"param-rules,omitempty" json:"param-rules,omitempty"`
	// UnsupportedModelStatusCode is returned when native is enabled but the model is not allowed.
	UnsupportedModelStatusCode int `yaml:"unsupported-model-status-code,omitempty" json:"unsupported-model-status-code,omitempty"`
	// UnsupportedModelMessage is returned when native is enabled but the model is not allowed.
	UnsupportedModelMessage string `yaml:"unsupported-model-message,omitempty" json:"unsupported-model-message,omitempty"`
}
