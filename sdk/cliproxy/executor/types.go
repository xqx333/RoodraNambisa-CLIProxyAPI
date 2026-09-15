package executor

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
)

const providerPreparedRequestsMetadataKey = "provider_prepared_requests"

// RequestOperation identifies the Manager entrypoint preparing a provider request.
type RequestOperation uint8

const (
	RequestOperationExecute RequestOperation = iota
	RequestOperationCount
	RequestOperationStream
)

// ProviderRequestPreparationScope describes whether a deterministic preflight
// failure applies to the whole client request or only to one provider.
type ProviderRequestPreparationScope string

const (
	ProviderRequestPreparationGlobalInvalid        ProviderRequestPreparationScope = "global_invalid"
	ProviderRequestPreparationProviderIncompatible ProviderRequestPreparationScope = "provider_incompatible"
)

type providerRequestPreparationError struct {
	scope ProviderRequestPreparationScope
	cause error
}

func (e *providerRequestPreparationError) Error() string {
	if e == nil || e.cause == nil {
		return "provider request preparation failed"
	}
	return e.cause.Error()
}

func (e *providerRequestPreparationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *providerRequestPreparationError) ProviderRequestPreparationScope() ProviderRequestPreparationScope {
	if e == nil {
		return ProviderRequestPreparationGlobalInvalid
	}
	return e.scope
}

// NewGlobalProviderRequestPreparationError marks an error as applying to the
// entire client request. Manager must not silently try another provider.
func NewGlobalProviderRequestPreparationError(err error) error {
	if err == nil {
		return nil
	}
	return &providerRequestPreparationError{scope: ProviderRequestPreparationGlobalInvalid, cause: err}
}

// NewProviderIncompatibleRequestPreparationError marks an otherwise valid
// request as unsupported by one provider, allowing provider-level fallback.
func NewProviderIncompatibleRequestPreparationError(err error) error {
	if err == nil {
		return nil
	}
	return &providerRequestPreparationError{scope: ProviderRequestPreparationProviderIncompatible, cause: err}
}

// ProviderRequestPreparationScopeOf returns the explicit preflight scope.
// Unclassified errors are global failures by default.
func ProviderRequestPreparationScopeOf(err error) ProviderRequestPreparationScope {
	var classified interface {
		ProviderRequestPreparationScope() ProviderRequestPreparationScope
	}
	if errors.As(err, &classified) && classified != nil {
		return classified.ProviderRequestPreparationScope()
	}
	return ProviderRequestPreparationGlobalInvalid
}

// WithProviderPreparedRequest returns an Options copy carrying one immutable,
// provider-owned preflight result. The nested maps are copied so one request
// cannot mutate another provider's prepared state.
func WithProviderPreparedRequest(opts Options, provider string, prepared any) Options {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" || prepared == nil {
		return opts
	}
	metadata := make(map[string]any, len(opts.Metadata)+1)
	for key, value := range opts.Metadata {
		metadata[key] = value
	}
	preparedByProvider := make(map[string]any)
	if existing, ok := metadata[providerPreparedRequestsMetadataKey].(map[string]any); ok {
		preparedByProvider = make(map[string]any, len(existing)+1)
		for key, value := range existing {
			preparedByProvider[key] = value
		}
	}
	preparedByProvider[provider] = prepared
	metadata[providerPreparedRequestsMetadataKey] = preparedByProvider
	opts.Metadata = metadata
	return opts
}

// ProviderPreparedRequest returns the immutable preflight result for provider.
func ProviderPreparedRequest(opts Options, provider string) (any, bool) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" || opts.Metadata == nil {
		return nil, false
	}
	preparedByProvider, ok := opts.Metadata[providerPreparedRequestsMetadataKey].(map[string]any)
	if !ok {
		return nil, false
	}
	prepared, ok := preparedByProvider[provider]
	return prepared, ok && prepared != nil
}

// RequestedModelMetadataKey stores the client-requested model name in Options.Metadata.
const RequestedModelMetadataKey = "requested_model"

// GenerateMetadataKey records explicit client generation intent for usage sinks.
const GenerateMetadataKey = "generate"

// RequestPathMetadataKey stores the inbound HTTP request path in Options.Metadata.
const RequestPathMetadataKey = "request_path"

// ExecutionModelOverrideMetadataKey overrides the upstream execution model while
// keeping auth selection bound to Request.Model.
const ExecutionModelOverrideMetadataKey = "execution_model_override"

// InteractionsAPIVersionMetadataKey stores the trusted Interactions route version.
const InteractionsAPIVersionMetadataKey = "interactions_api_version"

// InteractionsAPIRevisionMetadataKey stores the client-supplied Interactions revision.
const InteractionsAPIRevisionMetadataKey = "interactions_api_revision"

const (
	// StreamBufferSize bounds per-stream buffering between executor layers.
	StreamBufferSize = 16

	// PinnedAuthMetadataKey locks execution to a specific auth ID.
	PinnedAuthMetadataKey = "pinned_auth_id"
	// ImageGenerationStreamPassthroughMetadataKey requests low-overhead passthrough for
	// streaming Responses image_generation events.
	ImageGenerationStreamPassthroughMetadataKey = "image_generation_stream_passthrough"
	// ImageGenerationStreamPassthroughStateMetadataKey carries the effective passthrough
	// state after provider policy has transformed the request.
	ImageGenerationStreamPassthroughStateMetadataKey = "image_generation_stream_passthrough_state"
	// ImageGenerationMaxResultsMetadataKey limits provider-side image result
	// materialization for compatibility image endpoints.
	ImageGenerationMaxResultsMetadataKey = "image_generation_max_results"
	// ChatGPTWebIgnoreUnsupportedImageParamsMetadataKey pins the compatibility
	// endpoint's unsupported image parameter policy for one execution.
	ChatGPTWebIgnoreUnsupportedImageParamsMetadataKey = "chatgpt_web_ignore_unsupported_image_params"
	// ChatGPTWebImageConfigSnapshotMetadataKey pins Web image adaptation settings
	// after compatibility routing has accepted a request.
	ChatGPTWebImageConfigSnapshotMetadataKey = "chatgpt_web_image_config_snapshot"
	// ImageGenerationResultStateMetadataKey carries provider-confirmed image
	// generation success back to the auth result recorder.
	ImageGenerationResultStateMetadataKey = "image_generation_result_state"
	// TrustUpstreamSSEMetadataKey requests direct forwarding of trusted upstream SSE frames.
	TrustUpstreamSSEMetadataKey = "trust_upstream_sse"
	// SelectionAttemptMetadataKey stores the outer retry attempt index for auth selection.
	SelectionAttemptMetadataKey = "selection_attempt"
	// SelectedAuthMetadataKey stores the auth ID selected by the scheduler.
	SelectedAuthMetadataKey = "selected_auth_id"
	// SelectedAuthInstanceMetadataKey stores the immutable runtime instance selected by the scheduler.
	SelectedAuthInstanceMetadataKey = "selected_auth_instance_id"
	// SelectedAuthInstanceRetirementMetadataKey carries the selected instance retirement state.
	SelectedAuthInstanceRetirementMetadataKey = "selected_auth_instance_retirement"
	// StreamTerminalMarkerMetadataKey asks compatible executors to emit an internal
	// zero-payload completion marker before closing a successful stream.
	StreamTerminalMarkerMetadataKey = "stream_terminal_marker"
	// SelectedAuthCallbackMetadataKey carries an optional callback invoked with the selected auth ID.
	SelectedAuthCallbackMetadataKey = "selected_auth_callback"
	// SelectedAuthSourceCallbackMetadataKey carries an optional callback invoked with the selected provider and priority.
	SelectedAuthSourceCallbackMetadataKey = "selected_auth_source_callback"
	// ExecutionSessionMetadataKey identifies a long-lived downstream execution session.
	ExecutionSessionMetadataKey = "execution_session_id"
	// CallerScopeMetadataKey is supplied only by trusted SDK integrations and must
	// include both caller identity and its authorization scope. Never populate it
	// from an unverified client header or body field.
	CallerScopeMetadataKey = "caller_scope"
)

// ChatGPTWebImageConfigSnapshot contains request-scoped Web image adaptation settings.
type ChatGPTWebImageConfigSnapshot struct {
	AutoCleanupLibraryOnFull     bool
	RemoteImageURLEnabled        bool
	RemoteImageURLDownloadMode   string
	NormalizeMismatchedImageMIME bool
	NormalizeRemoteImageMIME     bool
	AdaptSizeToAspectRatio       bool
	StrictSize                   bool
	AspectRatioMaxErrorPercent   float64
	MaxResizeEdgePixels          int
	ResizeToRequestedSize        bool
	ResizeFilter                 string
	MaxImageResponseBytes        int
	MaxN                         int
}

// ImageGenerationStreamPassthroughState reports whether the selected upstream request
// still contains an image generation tool after provider policy is applied.
type ImageGenerationStreamPassthroughState struct {
	enabled atomic.Bool
}

// SetEnabled updates the effective image stream passthrough state.
func (s *ImageGenerationStreamPassthroughState) SetEnabled(enabled bool) {
	if s != nil {
		s.enabled.Store(enabled)
	}
}

// Enabled returns the effective image stream passthrough state.
func (s *ImageGenerationStreamPassthroughState) Enabled() bool {
	return s != nil && s.enabled.Load()
}

// ImageGenerationResultState records how many completed images an upstream
// provider returned. Merely accepting a request with an image tool is not success.
type ImageGenerationResultState struct {
	succeededCount atomic.Int64
	producedCount  atomic.Int64
}

// MarkSucceeded records provider-confirmed image output.
func (s *ImageGenerationResultState) MarkSucceeded() {
	s.AddSucceeded(1)
}

// AddSucceeded records provider-confirmed image output.
func (s *ImageGenerationResultState) AddSucceeded(count int) {
	if s != nil && count > 0 {
		s.succeededCount.Add(int64(count))
	}
}

// Succeeded reports whether provider-confirmed image output was produced.
func (s *ImageGenerationResultState) Succeeded() bool {
	return s.SucceededCount() > 0
}

// SucceededCount returns the number of provider-confirmed image outputs.
func (s *ImageGenerationResultState) SucceededCount() int64 {
	if s == nil {
		return 0
	}
	return s.succeededCount.Load()
}

// AddProduced records images that were generated and downloaded even if local
// post-processing later prevents them from reaching the client.
func (s *ImageGenerationResultState) AddProduced(count int) {
	if s != nil && count > 0 {
		s.producedCount.Add(int64(count))
	}
}

// ProducedCount returns the number of generated and downloaded images.
func (s *ImageGenerationResultState) ProducedCount() int64 {
	if s == nil {
		return 0
	}
	return s.producedCount.Load()
}

// TakeProducedCount atomically consumes generated images for quota projection.
func (s *ImageGenerationResultState) TakeProducedCount() int64 {
	if s == nil {
		return 0
	}
	return s.producedCount.Swap(0)
}

// AuthInstanceRetirement reports whether a selected runtime auth instance was retired.
type AuthInstanceRetirement interface {
	Retired() bool
}

// AuthRequestReservation represents one per-auth request-limit reservation.
// Implementations must make Commit and Release idempotent and concurrency-safe.
type AuthRequestReservation interface {
	Commit() bool
	Release() bool
	Reserved() bool
	Committed() bool
	Consumed() bool
}

// RequestExecutionDiagnostics records request ownership and upstream commit
// boundaries without attaching provider secrets to usage records.
type RequestExecutionDiagnostics struct {
	mu            sync.RWMutex
	failureStage  string
	errorCode     string
	selected      atomic.Bool
	committed     atomic.Bool
	slotConsumed  atomic.Bool
	attemptCommit atomic.Bool
}

// ClearFailure removes attempt-local failure metadata before the next
// credential attempt while preserving request-level selection and commit
// ownership flags.
func (d *RequestExecutionDiagnostics) ClearFailure() {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.failureStage = ""
	d.errorCode = ""
	d.mu.Unlock()
}

// RequestExecutionDiagnosticsSnapshot is the immutable public view persisted
// with one request usage detail.
type RequestExecutionDiagnosticsSnapshot struct {
	FailureStage            string
	ErrorCode               string
	CredentialSelected      bool
	UpstreamCommitted       bool
	AuthRequestSlotConsumed bool
}

// RequestExecutionMetricsSnapshot is a monotonic process-local view of
// request preflight, selection, and upstream commit boundaries.
type RequestExecutionMetricsSnapshot struct {
	PreflightRejected       uint64 `json:"preflight_rejected"`
	AuthSlotReserved        uint64 `json:"auth_slot_reserved"`
	AuthSlotReleased        uint64 `json:"auth_slot_released"`
	UpstreamCommitted       uint64 `json:"upstream_committed"`
	AuthRequestLimited      uint64 `json:"auth_request_limited"`
	SelectedButNotCommitted uint64 `json:"selected_but_not_committed"`
}

// RequestExecutionMetrics owns process-local counters shared by all attempts
// of user model requests. Lifecycle and maintenance traffic must not use it.
type RequestExecutionMetrics struct {
	preflightRejected       atomic.Uint64
	authSlotReserved        atomic.Uint64
	authSlotReleased        atomic.Uint64
	upstreamCommitted       atomic.Uint64
	authRequestLimited      atomic.Uint64
	selectedButNotCommitted atomic.Uint64
}

// RecordPreflightRejected records one request rejected before credential
// selection.
func (m *RequestExecutionMetrics) RecordPreflightRejected() {
	if m != nil {
		m.preflightRejected.Add(1)
	}
}

// RecordAuthRequestLimited records one final request-limit rejection.
func (m *RequestExecutionMetrics) RecordAuthRequestLimited() {
	if m != nil {
		m.authRequestLimited.Add(1)
	}
}

// Snapshot returns the current monotonic counters.
func (m *RequestExecutionMetrics) Snapshot() RequestExecutionMetricsSnapshot {
	if m == nil {
		return RequestExecutionMetricsSnapshot{}
	}
	return RequestExecutionMetricsSnapshot{
		PreflightRejected:       m.preflightRejected.Load(),
		AuthSlotReserved:        m.authSlotReserved.Load(),
		AuthSlotReleased:        m.authSlotReleased.Load(),
		UpstreamCommitted:       m.upstreamCommitted.Load(),
		AuthRequestLimited:      m.authRequestLimited.Load(),
		SelectedButNotCommitted: m.selectedButNotCommitted.Load(),
	}
}

// SetFailure stores the final safe failure classification for the request.
func (d *RequestExecutionDiagnostics) SetFailure(stage, code string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.failureStage = strings.TrimSpace(stage)
	d.errorCode = strings.TrimSpace(code)
	d.mu.Unlock()
}

func (d *RequestExecutionDiagnostics) markCredentialSelected() {
	if d != nil {
		d.selected.Store(true)
	}
}

func (d *RequestExecutionDiagnostics) markUpstreamCommitted(slotConsumed bool) {
	if d == nil {
		return
	}
	d.committed.Store(true)
	d.attemptCommit.Store(true)
	if slotConsumed {
		d.slotConsumed.Store(true)
	}
}

// CurrentAttemptCommitted reports whether the currently bound credential
// attempt crossed its upstream commit boundary.
func (d *RequestExecutionDiagnostics) CurrentAttemptCommitted() bool {
	return d != nil && d.attemptCommit.Load()
}

// Snapshot returns a concurrency-safe copy of the current diagnostics.
func (d *RequestExecutionDiagnostics) Snapshot() RequestExecutionDiagnosticsSnapshot {
	if d == nil {
		return RequestExecutionDiagnosticsSnapshot{}
	}
	d.mu.RLock()
	snapshot := RequestExecutionDiagnosticsSnapshot{
		FailureStage: d.failureStage,
		ErrorCode:    d.errorCode,
	}
	d.mu.RUnlock()
	snapshot.CredentialSelected = d.selected.Load()
	snapshot.UpstreamCommitted = d.committed.Load()
	snapshot.AuthRequestSlotConsumed = d.slotConsumed.Load()
	return snapshot
}

// AuthRequestSlot carries an attempt-local request-limit reservation from auth
// selection to the executor that owns the upstream commit boundary.
type AuthRequestSlot struct {
	mu                       sync.RWMutex
	reservation              AuthRequestReservation
	diagnostics              *RequestExecutionDiagnostics
	metrics                  *RequestExecutionMetrics
	reservationDurationNanos atomic.Uint64
}

// SetDiagnostics binds request-scoped diagnostics before auth selection.
func (s *AuthRequestSlot) SetDiagnostics(diagnostics *RequestExecutionDiagnostics) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.diagnostics = diagnostics
	s.mu.Unlock()
}

// SetMetrics attaches the model-request metrics sink used by this slot.
func (s *AuthRequestSlot) SetMetrics(metrics *RequestExecutionMetrics) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.metrics = metrics
	s.mu.Unlock()
}

// RecordReservationDuration accumulates time spent reserving fixed-window
// request capacity while the scheduler selects a credential.
func (s *AuthRequestSlot) RecordReservationDuration(duration time.Duration) {
	if s == nil || duration <= 0 {
		return
	}
	s.reservationDurationNanos.Add(uint64(duration.Nanoseconds()))
}

// ReservationDurationNanos returns the cumulative request-capacity
// reservation duration for the current downstream request.
func (s *AuthRequestSlot) ReservationDurationNanos() uint64 {
	if s == nil {
		return 0
	}
	return s.reservationDurationNanos.Load()
}

// Bind replaces the previous attempt's reservation with the next one. A still
// pending reservation is released before replacement so retries do not retain
// capacity that never reached an upstream request.
func (s *AuthRequestSlot) Bind(reservation AuthRequestReservation) {
	if s == nil || reservation == nil {
		return
	}
	s.mu.Lock()
	previous := s.reservation
	s.reservation = reservation
	diagnostics := s.diagnostics
	metrics := s.metrics
	s.mu.Unlock()
	diagnostics.ClearFailure()
	if diagnostics != nil {
		diagnostics.attemptCommit.Store(false)
	}
	diagnostics.markCredentialSelected()
	if metrics != nil && reservation.Consumed() {
		metrics.authSlotReserved.Add(1)
	}
	if previous != nil && previous.Reserved() {
		settleReleasedReservation(previous, metrics)
	}
}

func settleReleasedReservation(reservation AuthRequestReservation, metrics *RequestExecutionMetrics) bool {
	if reservation == nil || !reservation.Release() {
		return false
	}
	if metrics != nil {
		metrics.selectedButNotCommitted.Add(1)
		if reservation.Consumed() {
			metrics.authSlotReleased.Add(1)
		}
	}
	return true
}

const (
	requestUsageOutcomeOpen uint8 = iota
	requestUsageOutcomeStreamAccepted
	requestUsageOutcomeSucceeded
	requestUsageOutcomeFailed
)

// RequestUsageOutcome coordinates attempt-local usage reporters so an
// internal credential retry cannot publish multiple primary failures for one
// downstream request.
type RequestUsageOutcome struct {
	mu              sync.Mutex
	state           uint8
	acceptedAttempt *RequestUsageAttempt
	pendingFailure  requestUsageFailure
}

type requestUsageOutcomeContextKey struct{}
type requestUsageAttemptContextKey struct{}

// RequestUsageAttempt identifies one provider stream attempt within a
// downstream request. Pointer identity is intentionally request-local.
type RequestUsageAttempt struct {
	marker byte
}

type requestUsageFailure struct {
	attempt *RequestUsageAttempt
	publish func()
}

// WithRequestUsageOutcome returns a context that shares one primary usage
// outcome across every provider attempt belonging to the same request.
func WithRequestUsageOutcome(ctx context.Context, outcome *RequestUsageOutcome) context.Context {
	if ctx == nil || outcome == nil {
		return ctx
	}
	return context.WithValue(ctx, requestUsageOutcomeContextKey{}, outcome)
}

// RequestUsageOutcomeFromContext returns the request-scoped primary usage
// outcome installed by Manager.
func RequestUsageOutcomeFromContext(ctx context.Context) *RequestUsageOutcome {
	if ctx == nil {
		return nil
	}
	outcome, _ := ctx.Value(requestUsageOutcomeContextKey{}).(*RequestUsageOutcome)
	return outcome
}

// WithRequestUsageAttempt returns a child context and an opaque attempt token
// used to distinguish an accepted stream from superseded provider attempts.
func WithRequestUsageAttempt(ctx context.Context) (context.Context, *RequestUsageAttempt) {
	attempt := &RequestUsageAttempt{marker: 1}
	if ctx == nil {
		return ctx, attempt
	}
	return context.WithValue(ctx, requestUsageAttemptContextKey{}, attempt), attempt
}

// RequestUsageAttemptFromContext returns the current provider stream attempt.
func RequestUsageAttemptFromContext(ctx context.Context) *RequestUsageAttempt {
	if ctx == nil {
		return nil
	}
	attempt, _ := ctx.Value(requestUsageAttemptContextKey{}).(*RequestUsageAttempt)
	return attempt
}

// StageFailure keeps only the latest internal attempt failure until routing
// decides that the overall request has failed. After a stream is accepted,
// asynchronous failures are already final and are published immediately.
func (o *RequestUsageOutcome) StageFailure(publish func()) {
	o.StageFailureForAttempt(nil, publish)
}

// StageFailureForAttempt freezes the latest failed provider attempt until
// routing decides whether it was superseded or was the accepted stream.
func (o *RequestUsageOutcome) StageFailureForAttempt(attempt *RequestUsageAttempt, publish func()) {
	if o == nil || publish == nil {
		return
	}
	o.mu.Lock()
	switch o.state {
	case requestUsageOutcomeOpen:
		o.pendingFailure = requestUsageFailure{attempt: attempt, publish: publish}
		o.mu.Unlock()
	case requestUsageOutcomeStreamAccepted:
		if o.acceptedAttempt != attempt {
			o.mu.Unlock()
			return
		}
		o.state = requestUsageOutcomeFailed
		o.pendingFailure = requestUsageFailure{}
		o.mu.Unlock()
		publish()
	default:
		o.mu.Unlock()
	}
}

// PublishSuccess clears any superseded attempt failure and publishes the
// successful primary record exactly once.
func (o *RequestUsageOutcome) PublishSuccess(publish func()) {
	o.PublishSuccessForAttempt(nil, publish)
}

// PublishSuccessForAttempt publishes a successful primary record only when
// it belongs to the accepted stream attempt, or before a stream is selected.
func (o *RequestUsageOutcome) PublishSuccessForAttempt(attempt *RequestUsageAttempt, publish func()) {
	if publish == nil {
		return
	}
	if o == nil {
		publish()
		return
	}
	o.mu.Lock()
	if o.state == requestUsageOutcomeSucceeded || o.state == requestUsageOutcomeFailed {
		o.mu.Unlock()
		return
	}
	if o.state == requestUsageOutcomeStreamAccepted && o.acceptedAttempt != attempt {
		o.mu.Unlock()
		return
	}
	o.state = requestUsageOutcomeSucceeded
	o.acceptedAttempt = attempt
	o.pendingFailure = requestUsageFailure{}
	o.mu.Unlock()
	publish()
}

// FinalizeFailure publishes the last staged attempt failure when routing has
// exhausted all candidates and request rounds.
func (o *RequestUsageOutcome) FinalizeFailure() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if o.state != requestUsageOutcomeOpen {
		o.mu.Unlock()
		return
	}
	o.state = requestUsageOutcomeFailed
	publish := o.pendingFailure.publish
	o.pendingFailure = requestUsageFailure{}
	o.mu.Unlock()
	if publish != nil {
		publish()
	}
}

// FinalizeSuccess discards failures from internal attempts when another
// provider or credential ultimately succeeds.
func (o *RequestUsageOutcome) FinalizeSuccess() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if o.state == requestUsageOutcomeOpen {
		o.state = requestUsageOutcomeSucceeded
		o.acceptedAttempt = nil
		o.pendingFailure = requestUsageFailure{}
	}
	o.mu.Unlock()
}

// AcceptStream marks a returned stream as the final selected attempt. Any
// later consume, settle, download, or downstream cancellation failure is no
// longer eligible for credential fallback.
func (o *RequestUsageOutcome) AcceptStream() {
	o.AcceptStreamAttempt(nil)
}

// AcceptStreamAttempt marks one returned stream as final. If that same stream
// already failed asynchronously before ExecuteStream returned, its frozen
// failure is published instead of being mistaken for a superseded attempt.
func (o *RequestUsageOutcome) AcceptStreamAttempt(attempt *RequestUsageAttempt) {
	if o == nil {
		return
	}
	o.mu.Lock()
	if o.state != requestUsageOutcomeOpen {
		o.mu.Unlock()
		return
	}
	pending := o.pendingFailure
	if attempt != nil && pending.attempt == attempt && pending.publish != nil {
		o.state = requestUsageOutcomeFailed
		o.acceptedAttempt = attempt
		o.pendingFailure = requestUsageFailure{}
		o.mu.Unlock()
		pending.publish()
		return
	}
	o.state = requestUsageOutcomeStreamAccepted
	o.acceptedAttempt = attempt
	o.pendingFailure = requestUsageFailure{}
	o.mu.Unlock()
}

func (s *AuthRequestSlot) current() AuthRequestReservation {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	reservation := s.reservation
	s.mu.RUnlock()
	return reservation
}

// Commit keeps the reserved capacity until its original request window ends.
func (s *AuthRequestSlot) Commit() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	reservation := s.reservation
	diagnostics := s.diagnostics
	metrics := s.metrics
	s.mu.RUnlock()
	if reservation == nil {
		return false
	}
	committed := reservation.Commit()
	if committed && metrics != nil {
		metrics.upstreamCommitted.Add(1)
	}
	if committed || reservation.Committed() {
		diagnostics.markUpstreamCommitted(reservation.Consumed())
	}
	return committed
}

// Release returns capacity only when the attached reservation is still pending.
func (s *AuthRequestSlot) Release() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	reservation := s.reservation
	metrics := s.metrics
	s.mu.RUnlock()
	return settleReleasedReservation(reservation, metrics)
}

// Bound reports whether selection attached a reservation to this slot.
func (s *AuthRequestSlot) Bound() bool {
	return s.current() != nil
}

// Reserved reports whether the attached reservation still awaits settlement.
func (s *AuthRequestSlot) Reserved() bool {
	reservation := s.current()
	return reservation != nil && reservation.Reserved()
}

// Committed reports whether an upstream request consumed the attached slot.
func (s *AuthRequestSlot) Committed() bool {
	reservation := s.current()
	return reservation != nil && reservation.Committed()
}

// Consumed reports whether the attached policy reserves real capacity.
func (s *AuthRequestSlot) Consumed() bool {
	reservation := s.current()
	return reservation != nil && reservation.Consumed()
}

// Request encapsulates the translated payload that will be sent to a provider executor.
type Request struct {
	// Model is the upstream model identifier after translation.
	Model string
	// Payload is the provider specific JSON payload.
	Payload []byte
	// Format represents the provider payload schema.
	Format sdktranslator.Format
	// Metadata carries optional provider specific execution hints.
	Metadata map[string]any
}

// Options controls execution behavior for both streaming and non-streaming calls.
type Options struct {
	// Stream toggles streaming mode.
	Stream bool
	// Alt carries optional alternate format hint (e.g. SSE JSON key).
	Alt string
	// Headers are forwarded to the provider request builder.
	Headers http.Header
	// Query contains optional query string parameters.
	Query url.Values
	// OriginalRequest preserves the inbound request bytes prior to translation.
	OriginalRequest []byte
	// SourceFormat identifies the inbound schema.
	SourceFormat sdktranslator.Format
	// ResponseFormat identifies the downstream response schema. Empty preserves
	// the historical behavior of using SourceFormat.
	ResponseFormat sdktranslator.Format
	// Metadata carries extra execution hints shared across selection and executors.
	Metadata map[string]any
	// AuthRequestSlot carries the attempt-local per-auth request-limit reservation.
	AuthRequestSlot *AuthRequestSlot
	// ExecutionDiagnostics records selection, commit, and safe failure metadata.
	ExecutionDiagnostics *RequestExecutionDiagnostics
	// UsageOutcome coordinates primary usage publication across internal retries.
	UsageOutcome *RequestUsageOutcome
	// ExecutionMetrics records process-local preflight and commit counters.
	ExecutionMetrics *RequestExecutionMetrics
}

// ResponseFormatOrSource returns the explicit downstream format when present.
func ResponseFormatOrSource(opts Options) sdktranslator.Format {
	if opts.ResponseFormat != "" {
		return opts.ResponseFormat
	}
	return opts.SourceFormat
}

// Response wraps either a full provider response or metadata for streaming flows.
type Response struct {
	// StatusCode preserves native HTTP endpoint status. Zero keeps the caller's default.
	StatusCode int
	// Payload is the provider response in the executor format.
	Payload []byte
	// Metadata exposes optional structured data for translators.
	Metadata map[string]any
	// Headers carries upstream HTTP response headers for passthrough to clients.
	Headers http.Header
}

// StreamChunk represents a single streaming payload unit emitted by provider executors.
type StreamChunk struct {
	// Payload is the raw provider chunk payload.
	Payload []byte
	// Err reports any terminal error encountered while producing chunks.
	Err error
}

// StreamResult wraps the streaming response, providing both the chunk channel
// and the upstream HTTP response headers captured before streaming begins.
type StreamResult struct {
	// Headers carries upstream HTTP response headers from the initial connection.
	Headers http.Header
	// Chunks is the channel of streaming payload units.
	Chunks <-chan StreamChunk
}

// StatusError represents an error that carries an HTTP-like status code.
// Provider executors should implement this when possible to enable
// better auth state updates on failures (e.g., 401/402/429).
type StatusError interface {
	error
	StatusCode() int
}
