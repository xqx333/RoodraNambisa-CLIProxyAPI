package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	stddraw "image/draw"
	_ "image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	imagewebp "github.com/gen2brain/webp"
	"github.com/google/uuid"
	chatgptwebauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/chatgptweb"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
	xdraw "golang.org/x/image/draw"
	_ "golang.org/x/image/webp"
)

const (
	chatGPTWebMaxImageBytes             = helps.ChatGPTWebMaxImageBytes
	chatGPTWebMaxImageRequestBytes      = helps.ChatGPTWebMaxImageRequestBytes
	chatGPTWebMaxImageResponseBytes     = config.DefaultChatGPTWebMaxImageResponseMegabytes << 20
	chatGPTWebMaxImageEditDecodedBytes  = 96 << 20
	chatGPTWebDecodedImageBytesPerPixel = 8
	chatGPTWebImageEditBytesPerPixel    = 16
	chatGPTWebMaxImagePixels            = chatGPTWebMaxImageEditDecodedBytes / chatGPTWebDecodedImageBytesPerPixel
	chatGPTWebMaxOutputImagePixels      = config.MaxChatGPTWebMaxResizeEdgePixels * config.MaxChatGPTWebMaxResizeEdgePixels
	chatGPTWebImageDownloadAccept       = "image/png,image/jpeg,image/gif,image/webp,application/octet-stream;q=0.8"
	chatGPTWebMaxAssetRedirects         = 5
	chatGPTWebAssetSettleAttempts       = 4
	chatGPTWebImageMaxPollAttempts      = 180
	chatGPTWebImageStreamMaxBytes       = 128 << 20
	chatGPTWebImageStreamMaxEvents      = 65_536
	chatGPTWebPollResponseMaxBytes      = 128 << 20
	chatGPTWebImageTaskMaxPages         = 8
	chatGPTWebImageResponseJSONOverhead = 8 << 20
	chatGPTWebImageRateLimitClientBody  = `{"error":{"message":"Rate limit reached for requests. Please try again later.","type":"rate_limit_error","code":"rate_limit_exceeded"}}`
	chatGPTWebImageNoOutputMessage      = "chatgpt web image generation completed without an image"
)

var chatGPTWebAssetHostSuffixes = []string{
	"blob.core.windows.net",
	"chatgpt.com",
	"oaiusercontent.com",
	"oaistatic.com",
	"openai.com",
}

var chatGPTWebImagePollMetrics struct {
	attempts atomic.Uint64
	acquired atomic.Uint64
}

var chatGPTWebImageProtocolMetrics struct {
	taskIDsObserved                  atomic.Uint64
	exactStreamsStarted              atomic.Uint64
	exactStreamsCompleted            atomic.Uint64
	exactStreamFallbacks             atomic.Uint64
	finalMessagesCaptured            atomic.Uint64
	taskPagesFetched                 atomic.Uint64
	hiddenOutputsIgnored             atomic.Uint64
	incompletePointersObserved       atomic.Uint64
	allSourcesExhaustedWithoutOutput atomic.Uint64
	taskPagesEmpty                   atomic.Uint64
	taskPagesUnrecognized            atomic.Uint64
	taskPageParseErrors              atomic.Uint64
	taskRecords                      atomic.Uint64
	taskInvalidRecords               atomic.Uint64
	taskImageRecords                 atomic.Uint64
	taskMatchedRecords               atomic.Uint64
	taskOtherConversationRecords     atomic.Uint64
	taskIdentityMismatchRecords      atomic.Uint64
	taskMissingIDRecords             atomic.Uint64
	taskMissingResponseIDRecords     atomic.Uint64
}

// ChatGPTWebImagePollRuntimeSnapshot contains only aggregate poll-slot data.
type ChatGPTWebImagePollRuntimeSnapshot struct {
	Limit            int    `json:"limit"`
	QueueLimit       int    `json:"queue_limit"`
	Active           int64  `json:"active"`
	Queued           int64  `json:"queued"`
	PeakActive       int64  `json:"peak_active"`
	PeakQueued       int64  `json:"peak_queued"`
	Shrinking        bool   `json:"shrinking"`
	AcquireAttempts  uint64 `json:"acquire_attempts"`
	Acquired         uint64 `json:"acquired"`
	ImmediateRejects uint64 `json:"immediate_rejects"`
	QueueRejects     uint64 `json:"queue_rejects"`
	TimedOut         uint64 `json:"timed_out"`
	Canceled         uint64 `json:"canceled"`
	TotalWaitNanos   uint64 `json:"total_wait_nanos"`
	MaxWaitNanos     uint64 `json:"max_wait_nanos"`
}

// ChatGPTWebImagePollSnapshot returns process-wide poll-slot metrics.
func ChatGPTWebImagePollSnapshot() ChatGPTWebImagePollRuntimeSnapshot {
	admission := cliproxyexecutor.ChatGPTWebImagePollAdmissionSnapshot()
	return ChatGPTWebImagePollRuntimeSnapshot{
		Limit:            admission.Limit,
		QueueLimit:       admission.QueueLimit,
		Active:           int64(admission.Active),
		Queued:           int64(admission.Queued),
		PeakActive:       int64(admission.PeakActive),
		PeakQueued:       int64(admission.PeakQueued),
		Shrinking:        admission.Shrinking,
		AcquireAttempts:  chatGPTWebImagePollMetrics.attempts.Load(),
		Acquired:         chatGPTWebImagePollMetrics.acquired.Load(),
		ImmediateRejects: admission.ImmediateRejects,
		QueueRejects:     admission.QueueRejects,
		TimedOut:         admission.TimedOut,
		Canceled:         admission.Canceled,
		TotalWaitNanos:   uint64(max(admission.TotalWait.Nanoseconds(), int64(0))),
		MaxWaitNanos:     uint64(max(admission.MaxWait.Nanoseconds(), int64(0))),
	}
}

// ChatGPTWebImageProtocolRuntimeSnapshot contains only aggregate image
// convergence counters. It never contains task, conversation, or asset IDs.
type ChatGPTWebImageProtocolRuntimeSnapshot struct {
	TaskIDsObserved                  uint64                                 `json:"task_ids_observed"`
	ExactStreamsStarted              uint64                                 `json:"exact_streams_started"`
	ExactStreamsCompleted            uint64                                 `json:"exact_streams_completed"`
	ExactStreamFallbacks             uint64                                 `json:"exact_stream_fallbacks"`
	FinalMessagesCaptured            uint64                                 `json:"final_messages_captured"`
	TaskPagesFetched                 uint64                                 `json:"task_pages_fetched"`
	HiddenOutputsIgnored             uint64                                 `json:"hidden_outputs_ignored"`
	IncompletePointersObserved       uint64                                 `json:"incomplete_pointers_observed"`
	AllSourcesExhaustedWithoutOutput uint64                                 `json:"all_sources_exhausted_without_output"`
	TaskDiagnostics                  ChatGPTWebImageTaskDiagnosticsSnapshot `json:"task_diagnostics"`
}

// ChatGPTWebImageTaskDiagnosticsSnapshot distinguishes empty responses from
// unrecognized shapes and records excluded by the current-turn identity checks.
type ChatGPTWebImageTaskDiagnosticsSnapshot struct {
	EmptyPages               uint64 `json:"empty_pages"`
	UnrecognizedPages        uint64 `json:"unrecognized_pages"`
	ParseErrors              uint64 `json:"parse_errors"`
	Records                  uint64 `json:"records"`
	InvalidRecords           uint64 `json:"invalid_records"`
	ImageRecords             uint64 `json:"image_records"`
	MatchedRecords           uint64 `json:"matched_records"`
	OtherConversationRecords uint64 `json:"other_conversation_records"`
	IdentityMismatchRecords  uint64 `json:"identity_mismatch_records"`
	MissingTaskIDRecords     uint64 `json:"missing_task_id_records"`
	MissingResponseIDRecords uint64 `json:"missing_response_id_records"`
}

// ChatGPTWebImageProtocolSnapshot returns process-wide image convergence
// counters without exposing upstream identities or response contents.
func ChatGPTWebImageProtocolSnapshot() ChatGPTWebImageProtocolRuntimeSnapshot {
	return ChatGPTWebImageProtocolRuntimeSnapshot{
		TaskIDsObserved:                  chatGPTWebImageProtocolMetrics.taskIDsObserved.Load(),
		ExactStreamsStarted:              chatGPTWebImageProtocolMetrics.exactStreamsStarted.Load(),
		ExactStreamsCompleted:            chatGPTWebImageProtocolMetrics.exactStreamsCompleted.Load(),
		ExactStreamFallbacks:             chatGPTWebImageProtocolMetrics.exactStreamFallbacks.Load(),
		FinalMessagesCaptured:            chatGPTWebImageProtocolMetrics.finalMessagesCaptured.Load(),
		TaskPagesFetched:                 chatGPTWebImageProtocolMetrics.taskPagesFetched.Load(),
		HiddenOutputsIgnored:             chatGPTWebImageProtocolMetrics.hiddenOutputsIgnored.Load(),
		IncompletePointersObserved:       chatGPTWebImageProtocolMetrics.incompletePointersObserved.Load(),
		AllSourcesExhaustedWithoutOutput: chatGPTWebImageProtocolMetrics.allSourcesExhaustedWithoutOutput.Load(),
		TaskDiagnostics: ChatGPTWebImageTaskDiagnosticsSnapshot{
			EmptyPages:               chatGPTWebImageProtocolMetrics.taskPagesEmpty.Load(),
			UnrecognizedPages:        chatGPTWebImageProtocolMetrics.taskPagesUnrecognized.Load(),
			ParseErrors:              chatGPTWebImageProtocolMetrics.taskPageParseErrors.Load(),
			Records:                  chatGPTWebImageProtocolMetrics.taskRecords.Load(),
			InvalidRecords:           chatGPTWebImageProtocolMetrics.taskInvalidRecords.Load(),
			ImageRecords:             chatGPTWebImageProtocolMetrics.taskImageRecords.Load(),
			MatchedRecords:           chatGPTWebImageProtocolMetrics.taskMatchedRecords.Load(),
			OtherConversationRecords: chatGPTWebImageProtocolMetrics.taskOtherConversationRecords.Load(),
			IdentityMismatchRecords:  chatGPTWebImageProtocolMetrics.taskIdentityMismatchRecords.Load(),
			MissingTaskIDRecords:     chatGPTWebImageProtocolMetrics.taskMissingIDRecords.Load(),
			MissingResponseIDRecords: chatGPTWebImageProtocolMetrics.taskMissingResponseIDRecords.Load(),
		},
	}
}

func observeChatGPTWebImageTaskPage(state helps.ChatGPTWebImageTaskState, err error) {
	if err != nil {
		chatGPTWebImageProtocolMetrics.taskPageParseErrors.Add(1)
		return
	}
	diagnostics := state.Diagnostics
	if !diagnostics.Recognized {
		chatGPTWebImageProtocolMetrics.taskPagesUnrecognized.Add(1)
		return
	}
	if diagnostics.Records == 0 {
		chatGPTWebImageProtocolMetrics.taskPagesEmpty.Add(1)
	}
	chatGPTWebImageProtocolMetrics.taskRecords.Add(uint64(diagnostics.Records))
	chatGPTWebImageProtocolMetrics.taskInvalidRecords.Add(uint64(diagnostics.InvalidRecords))
	chatGPTWebImageProtocolMetrics.taskImageRecords.Add(uint64(diagnostics.ImageRecords))
	chatGPTWebImageProtocolMetrics.taskMatchedRecords.Add(uint64(diagnostics.MatchedRecords))
	chatGPTWebImageProtocolMetrics.taskOtherConversationRecords.Add(uint64(diagnostics.OtherConversationRecords))
	chatGPTWebImageProtocolMetrics.taskIdentityMismatchRecords.Add(uint64(diagnostics.IdentityMismatchRecords))
	chatGPTWebImageProtocolMetrics.taskMissingIDRecords.Add(uint64(diagnostics.MissingTaskIDRecords))
	chatGPTWebImageProtocolMetrics.taskMissingResponseIDRecords.Add(uint64(diagnostics.MissingResponseIDRecords))
}

func observeChatGPTWebImageProtocolAccumulator(accumulator *helps.ChatGPTWebImageAccumulator) {
	if accumulator == nil {
		return
	}
	if accumulator.FinalMessageSeen {
		chatGPTWebImageProtocolMetrics.finalMessagesCaptured.Add(1)
	}
	if accumulator.HiddenOutputSeen {
		chatGPTWebImageProtocolMetrics.hiddenOutputsIgnored.Add(1)
	}
	if accumulator.IncompleteOutputSeen {
		chatGPTWebImageProtocolMetrics.incompletePointersObserved.Add(1)
	}
}

type chatGPTWebUploadedImage struct {
	FileID   string
	FileName string
	MIMEType string
	Size     int
	Width    int
	Height   int
}

type chatGPTWebSpooledImage struct {
	path        string
	size        int
	contentType string
	format      string
	width       int
	height      int
	tracker     *helps.ChatGPTWebImageSpoolFile
}

func (image *chatGPTWebSpooledImage) remove() error {
	if image == nil || image.path == "" {
		return nil
	}
	err := os.Remove(image.path)
	image.path = ""
	image.tracker.FinishCleanup(err)
	return err
}

func removeChatGPTWebSpooledImages(images []*chatGPTWebSpooledImage) {
	for _, image := range images {
		if err := image.remove(); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.WithError(err).Warn("chatgpt web image: remove completion spool")
		}
	}
}

type chatGPTWebAssetTransportError struct {
	statusErr
	cause      error
	diagnostic *cliproxyauth.ErrorDiagnostic
}

type chatGPTWebImageBodyLimitError struct {
	maxBytes int
}

type chatGPTWebImageMemoryCapacityError struct {
	stage string
}

func (err *chatGPTWebImageMemoryCapacityError) Error() string {
	stage := "download"
	if err != nil && strings.TrimSpace(err.stage) != "" {
		stage = strings.TrimSpace(err.stage)
	}
	payload, _ := json.Marshal(map[string]any{"error": map[string]any{
		"message":       "image request memory capacity is temporarily exhausted",
		"type":          "server_error",
		"code":          "image_memory_capacity",
		"failure_stage": stage,
	}})
	return string(payload)
}

func (*chatGPTWebImageMemoryCapacityError) StatusCode() int { return http.StatusServiceUnavailable }

func (*chatGPTWebImageMemoryCapacityError) SkipAuthResult() bool { return true }

func (*chatGPTWebImageMemoryCapacityError) RetryOtherAuth() bool { return false }

func (*chatGPTWebImageMemoryCapacityError) ExecutionResultErrorCode() string {
	return "image_memory_capacity"
}

func (err *chatGPTWebImageMemoryCapacityError) ChatGPTWebFailureStage() string {
	if err == nil || strings.TrimSpace(err.stage) == "" {
		return "download"
	}
	return strings.TrimSpace(err.stage)
}

func (err *chatGPTWebImageBodyLimitError) Error() string {
	return fmt.Sprintf("chatgpt web image exceeds %d bytes", err.maxBytes)
}

func (e chatGPTWebAssetTransportError) Unwrap() error { return e.cause }

func (e chatGPTWebAssetTransportError) AuthErrorDiagnostic() *cliproxyauth.ErrorDiagnostic {
	return e.diagnostic.Clone()
}

type chatGPTWebImageSettleError struct {
	statusErr
	cause   error
	headers http.Header
}

type chatGPTWebImageSettleStatusError struct {
	statusErr
	errorCode string
}

type chatGPTWebImageQuotaResultError struct {
	cause     error
	committed bool
}

type chatGPTWebImageRateLimitResultError struct {
	cause     error
	committed bool
}

type chatGPTWebImageNoOutputResultError struct {
	statusErr
}

const (
	chatGPTWebImageErrorUpstreamFailed  = "chatgpt_web_image_upstream_failed"
	chatGPTWebImageErrorNoOutput        = "chatgpt_web_image_no_output"
	chatGPTWebImageErrorMissingTerminal = "chatgpt_web_image_missing_terminal"
	chatGPTWebImageErrorPollUnsettled   = "chatgpt_web_image_poll_not_converged"
	chatGPTWebImageErrorPollFailed      = "chatgpt_web_image_poll_failed"
)

func (e chatGPTWebImageSettleStatusError) ExecutionResultErrorCode() string {
	return strings.TrimSpace(e.errorCode)
}

func (chatGPTWebImageNoOutputResultError) ExecutionResultErrorCode() string {
	return chatGPTWebImageErrorNoOutput
}

func (e chatGPTWebImageSettleError) ExecutionResultErrorCode() string {
	var provider interface{ ExecutionResultErrorCode() string }
	if errors.As(e.cause, &provider) && provider != nil {
		if code := strings.TrimSpace(provider.ExecutionResultErrorCode()); code != "" {
			return code
		}
	}
	return chatGPTWebImageErrorPollFailed
}

func chatGPTWebImageResultStatusCode(err error) int {
	var provider interface{ StatusCode() int }
	if errors.As(err, &provider) && provider != nil {
		return provider.StatusCode()
	}
	return 0
}

func chatGPTWebImageResultHeaders(err error) http.Header {
	var provider interface{ Headers() http.Header }
	if !errors.As(err, &provider) || provider == nil {
		return nil
	}
	headers := provider.Headers()
	if headers == nil {
		return nil
	}
	return headers.Clone()
}

func chatGPTWebImageResultRetryAfter(err error) *time.Duration {
	var provider interface{ RetryAfter() *time.Duration }
	if !errors.As(err, &provider) || provider == nil {
		return nil
	}
	retryAfter := provider.RetryAfter()
	if retryAfter == nil {
		return nil
	}
	value := *retryAfter
	return &value
}

func chatGPTWebImageResultSkipAuthResult(err error) bool {
	var provider interface{ SkipAuthResult() bool }
	return errors.As(err, &provider) && provider != nil && provider.SkipAuthResult()
}

func chatGPTWebImageResultRetryOtherAuth(err error) bool {
	var provider interface{ RetryOtherAuth() bool }
	return errors.As(err, &provider) && provider != nil && provider.RetryOtherAuth()
}

func (e *chatGPTWebImageRateLimitResultError) Error() string {
	return chatGPTWebImageRateLimitClientBody
}

func (e *chatGPTWebImageRateLimitResultError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (*chatGPTWebImageRateLimitResultError) ExecutionResultModel() string {
	return chatgptwebauth.ImageModel
}

func (e *chatGPTWebImageRateLimitResultError) RequestCommitted() bool {
	return e != nil && e.committed
}

func (e *chatGPTWebImageRateLimitResultError) StatusCode() int {
	if e == nil {
		return 0
	}
	return chatGPTWebImageResultStatusCode(e.cause)
}

func (e *chatGPTWebImageRateLimitResultError) Headers() http.Header {
	if e == nil {
		return nil
	}
	return chatGPTWebImageResultHeaders(e.cause)
}

func (e *chatGPTWebImageRateLimitResultError) RetryAfter() *time.Duration {
	if e == nil {
		return nil
	}
	return chatGPTWebImageResultRetryAfter(e.cause)
}

func (e *chatGPTWebImageRateLimitResultError) SkipAuthResult() bool {
	return e != nil && chatGPTWebImageResultSkipAuthResult(e.cause)
}

func (e *chatGPTWebImageRateLimitResultError) RetryOtherAuth() bool {
	return e != nil && chatGPTWebImageResultRetryOtherAuth(e.cause)
}

func (e *chatGPTWebImageQuotaResultError) Error() string {
	return chatGPTWebImageRateLimitClientBody
}

func (e *chatGPTWebImageQuotaResultError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (*chatGPTWebImageQuotaResultError) ExecutionResultModel() string {
	return chatgptwebauth.ImageModel
}

func (*chatGPTWebImageQuotaResultError) ExecutionResultErrorCode() string {
	return "chatgpt_web_image_quota"
}

func (e *chatGPTWebImageQuotaResultError) RequestCommitted() bool {
	return e != nil && e.committed
}

func (e *chatGPTWebImageQuotaResultError) StatusCode() int {
	if e == nil {
		return 0
	}
	return chatGPTWebImageResultStatusCode(e.cause)
}

func (e *chatGPTWebImageQuotaResultError) Headers() http.Header {
	if e == nil {
		return nil
	}
	return chatGPTWebImageResultHeaders(e.cause)
}

func (e *chatGPTWebImageQuotaResultError) RetryAfter() *time.Duration {
	if e == nil {
		return nil
	}
	return chatGPTWebImageResultRetryAfter(e.cause)
}

func (e *chatGPTWebImageQuotaResultError) SkipAuthResult() bool {
	return false
}

func (e *chatGPTWebImageQuotaResultError) RetryOtherAuth() bool {
	return e != nil && chatGPTWebImageResultRetryOtherAuth(e.cause)
}

func chatGPTWebImageRequestError(err error) (projectedError error) {
	if err == nil {
		return nil
	}
	defer func() {
		projectedError = preserveChatGPTWebFailureStage(err, projectedError)
	}()
	var projected *chatGPTWebImageQuotaResultError
	if errors.As(err, &projected) {
		return err
	}
	var rateLimited *chatGPTWebImageRateLimitResultError
	if errors.As(err, &rateLimited) {
		return err
	}
	var status interface{ StatusCode() int }
	if !errors.As(err, &status) || status == nil || status.StatusCode() != http.StatusTooManyRequests {
		return err
	}
	if !chatGPTWebImageQuotaErrorEvidence(err) {
		return &chatGPTWebImageRateLimitResultError{cause: err}
	}
	return &chatGPTWebImageQuotaResultError{cause: err}
}

func chatGPTWebImageRequestErrorWithRefresh(err error, triggerRefresh func(force bool)) error {
	projected := chatGPTWebImageRequestError(err)
	var rateLimited *chatGPTWebImageRateLimitResultError
	var quotaExhausted *chatGPTWebImageQuotaResultError
	if triggerRefresh != nil {
		switch {
		case errors.As(projected, &quotaExhausted):
			triggerRefresh(true)
		case errors.As(projected, &rateLimited):
			triggerRefresh(false)
		}
	}
	return projected
}

func (e *ChatGPTWebExecutor) handleChatGPTWebImageRequestError(authID string, err error) error {
	projected := chatGPTWebImageRequestErrorWithRefresh(err, func(force bool) {
		if force {
			e.triggerImageQuotaEvidenceAccountInfoRefresh(authID)
			return
		}
		e.TriggerAutomaticAccountInfoRefresh(authID)
	})
	var noOutput *chatGPTWebImageNoOutputResultError
	if errors.As(projected, &noOutput) {
		e.triggerAmbiguousImageAccountInfoRefresh(authID)
	}
	return projected
}

func newChatGPTWebImageNoOutputResultError() error {
	return &chatGPTWebImageNoOutputResultError{statusErr: statusErr{
		code:           http.StatusBadGateway,
		msg:            chatGPTWebImageNoOutputMessage,
		skipAuthResult: true,
		retryOtherAuth: true,
	}}
}

func newChatGPTWebImageModerationResultError() error {
	return helps.NewOpenAIImageModerationError()
}

func chatGPTWebImageQuotaErrorEvidence(err error) bool {
	var upstream chatGPTWebHTTPError
	if errors.As(err, &upstream) {
		if !chatGPTWebImageConversationPath(upstream.path) {
			return false
		}
		return chatGPTWebImageQuotaTextEvidence(upstream.statusErr.msg)
	}
	return chatGPTWebImageQuotaTextEvidence(err.Error())
}

func chatGPTWebImageQuotaTextEvidence(value string) bool {
	body := strings.ToLower(strings.TrimSpace(value))
	if body == "" {
		return false
	}
	for _, marker := range []string{
		"image_quota_exhausted",
		"image_generation_quota_exhausted",
		"image_generation_limit_reached",
		"image_gen_limit_reached",
		"you've hit your limit",
		"you’ve hit your limit",
	} {
		if strings.Contains(body, marker) {
			return true
		}
	}
	exhausted := false
	for _, marker := range []string{"exhausted", "depleted", "reached", "no remaining", `"remaining":0`} {
		if strings.Contains(body, marker) {
			exhausted = true
			break
		}
	}
	if !exhausted {
		return false
	}
	for _, marker := range []string{
		"image quota",
		"image credit",
		"image generation limit",
		"image-generation limit",
		"image_gen limit",
		"limit for creating images",
	} {
		if strings.Contains(body, marker) {
			return true
		}
	}
	return false
}

func chatGPTWebImageConversationPath(path string) bool {
	path = strings.TrimSpace(path)
	return path == "/backend-api/conversation" ||
		strings.HasPrefix(path, "/backend-api/conversation/") ||
		path == "/backend-api/f/conversation" ||
		strings.HasPrefix(path, "/backend-api/f/conversation/")
}

func newChatGPTWebImageSettleError(cause error) chatGPTWebImageSettleError {
	err := chatGPTWebImageSettleError{
		statusErr: statusErr{
			code:           http.StatusBadGateway,
			msg:            "chatgpt web image conversation did not settle: " + cause.Error(),
			skipAuthResult: true,
			retryOtherAuth: true,
		},
		cause: cause,
	}
	var retryAfter interface{ RetryAfter() *time.Duration }
	if errors.As(cause, &retryAfter) {
		err.statusErr.retryAfter = retryAfter.RetryAfter()
	}
	var responseHeaders interface{ Headers() http.Header }
	if errors.As(cause, &responseHeaders) {
		err.headers = responseHeaders.Headers().Clone()
	}
	return err
}

func newChatGPTWebImageSettleStatusError(code, message string) error {
	return chatGPTWebImageSettleStatusError{
		statusErr: statusErr{
			code:           http.StatusBadGateway,
			msg:            strings.TrimSpace(message),
			skipAuthResult: true,
			retryOtherAuth: true,
		},
		errorCode: strings.TrimSpace(code),
	}
}

func (e chatGPTWebImageSettleError) Unwrap() error { return e.cause }

func (e chatGPTWebImageSettleError) Headers() http.Header {
	if len(e.headers) == 0 {
		return nil
	}
	return e.headers.Clone()
}

type chatGPTWebImageExecution struct {
	response *fhttp.Response
	headers  http.Header
	inputIDs map[string]struct{}
	turn     helps.ChatGPTWebImageTurn
}

type chatGPTWebPollResponseBudget struct {
	mu               sync.Mutex
	maxResponseBytes int
	remainingBytes   int
}

func newChatGPTWebPollResponseBudget(maxBytes int) *chatGPTWebPollResponseBudget {
	return &chatGPTWebPollResponseBudget{
		maxResponseBytes: maxBytes,
		remainingBytes:   maxBytes,
	}
}

func newChatGPTWebPollResponseLimit(maxBytes int) *chatGPTWebPollResponseBudget {
	return &chatGPTWebPollResponseBudget{
		maxResponseBytes: maxBytes,
		remainingBytes:   -1,
	}
}

func (budget *chatGPTWebPollResponseBudget) consume(size int) error {
	if budget == nil || size <= 0 {
		return nil
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.maxResponseBytes < 1 || size > budget.maxResponseBytes {
		return &helps.ChatGPTWebResponseLimitError{
			Message: fmt.Sprintf("chatgpt web polling response exceeds %d bytes", budget.maxResponseBytes),
		}
	}
	if budget.remainingBytes >= 0 {
		if size > budget.remainingBytes {
			return &helps.ChatGPTWebResponseLimitError{
				Message: fmt.Sprintf("chatgpt web polling responses exceed %d total bytes", budget.maxResponseBytes),
			}
		}
		budget.remainingBytes -= size
	}
	return nil
}

func chatGPTWebSharedPollResponseBudget(budgets []*chatGPTWebPollResponseBudget) *chatGPTWebPollResponseBudget {
	for _, budget := range budgets {
		if budget != nil {
			return budget
		}
	}
	return newChatGPTWebPollResponseBudget(chatGPTWebPollResponseMaxBytes)
}

func (e *ChatGPTWebExecutor) buildChatGPTWebConversationMessages(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, messages []helps.ChatGPTWebMessage, projections ...*helps.ChatGPTWebUsageProjection) ([]map[string]any, error) {
	var projection *helps.ChatGPTWebUsageProjection
	if len(projections) > 0 {
		projection = projections[0]
	}
	output := make([]map[string]any, 0, len(messages))
	for index := range messages {
		message := &messages[index]
		if strings.TrimSpace(message.ID) == "" {
			message.ID = uuid.NewString()
		}
		parts := make([]any, 0, len(message.Parts))
		uploads := make([]chatGPTWebUploadedImage, 0, len(message.Parts))
		for index, part := range message.Parts {
			if part.Text != "" {
				parts = append(parts, part.Text)
			}
			if strings.TrimSpace(part.ImageURL) == "" {
				continue
			}
			uploaded, err := e.uploadChatGPTWebImage(ctx, client, credential, part.ImageURL, fmt.Sprintf("image_%d.png", index+1))
			if err != nil {
				return nil, err
			}
			uploads = append(uploads, uploaded)
			projection.AddImage(helps.ChatGPTWebUsageImage{
				Model: messageUsageModel(projection), Detail: part.ImageDetail, Use: "input",
				Width: uploaded.Width, Height: uploaded.Height,
			})
			parts = append(parts, map[string]any{
				"content_type":  "image_asset_pointer",
				"asset_pointer": "file-service://" + uploaded.FileID,
				"width":         uploaded.Width,
				"height":        uploaded.Height,
				"size_bytes":    uploaded.Size,
			})
		}
		item := map[string]any{
			"id":     message.ID,
			"author": map[string]any{"role": message.Role},
		}
		if len(uploads) == 0 {
			item["content"] = map[string]any{
				"content_type": "text",
				"parts":        []string{chatGPTWebTextParts(parts)},
			}
		} else {
			attachments := make([]any, 0, len(uploads))
			for _, uploaded := range uploads {
				attachments = append(attachments, chatGPTWebAttachment(uploaded))
			}
			item["content"] = map[string]any{"content_type": "multimodal_text", "parts": parts}
			item["metadata"] = map[string]any{"attachments": attachments}
		}
		output = append(output, item)
	}
	return output, nil
}

func messageUsageModel(projection *helps.ChatGPTWebUsageProjection) string {
	if projection == nil {
		return ""
	}
	return projection.Model()
}

func chatGPTWebTextParts(parts []any) string {
	var text strings.Builder
	for _, part := range parts {
		if value, ok := part.(string); ok {
			text.WriteString(value)
		}
	}
	return text.String()
}

func (e *ChatGPTWebExecutor) executeChatGPTWebImage(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, prepared *chatGPTWebPreparedRequest) ([]byte, http.Header, error) {
	execution, err := e.beginChatGPTWebImage(ctx, client, credential, prepared)
	if err != nil {
		return nil, nil, err
	}
	completed, err := e.finishChatGPTWebImage(ctx, client, credential, prepared, execution)
	return completed, execution.headers, chatGPTWebCommittedRequestError(ctx, chatGPTWebImageRequestError(err))
}

func (e *ChatGPTWebExecutor) beginChatGPTWebImage(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, prepared *chatGPTWebPreparedRequest) (*chatGPTWebImageExecution, error) {
	imageRequest := prepared.request.Image
	if imageRequest == nil {
		return nil, errors.New("chatgpt web image request is nil")
	}
	upstreamPrompt := chatGPTWebImageUpstreamPrompt(imageRequest.Prompt, imageRequest.Action, prepared.imageSizeMatch)
	imageInputs := append([]string(nil), imageRequest.Images...)
	uploads := make([]chatGPTWebUploadedImage, 0, len(imageInputs))
	inputIDs := make(map[string]struct{}, len(imageInputs))
	uploadStarted := time.Now()
	setChatGPTWebImageTaskStage(ctx, "uploading_inputs")
	var uploadObserved sync.Once
	finishUploadObservation := func() {
		uploadObserved.Do(func() {
			cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseInputUpload, uploadStarted)
		})
	}
	defer finishUploadObservation()
	for index, imageURL := range imageInputs {
		uploaded, err := e.uploadChatGPTWebImage(ctx, client, credential, imageURL, fmt.Sprintf("image_%d.png", index+1))
		if err != nil {
			return nil, err
		}
		uploads = append(uploads, uploaded)
		prepared.usageProjection.AddImage(helps.ChatGPTWebUsageImage{
			Model: chatgptwebauth.ImageModel, Detail: "high", Use: "image_generation_input",
			Width: uploaded.Width, Height: uploaded.Height,
		})
		inputIDs[uploaded.FileID] = struct{}{}
	}
	finishUploadObservation()

	requirementsStarted := time.Now()
	setChatGPTWebImageTaskStage(ctx, "fetching_requirements")
	bootstrapCtx := cliproxyexecutor.WithImageBootstrapPolicy(ctx, prepared.bootstrapPolicy)
	requirements, err := e.chatGPTWebRequirements(chatgptwebauth.WithSentinelComputeScope(bootstrapCtx, "images"), client, credential, prepared.sentinelPolicy)
	cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseRequirements, requirementsStarted)
	if err != nil {
		return nil, err
	}
	upstreamModel := e.chatGPTWebImageUpstreamModel()
	prepareStarted := time.Now()
	setChatGPTWebImageTaskStage(ctx, "preparing_conversation")
	conduit, err := e.prepareChatGPTWebImageConversation(ctx, client, credential, requirements, upstreamModel, upstreamPrompt)
	cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseConversationPrepare, prepareStarted)
	if err != nil {
		return nil, err
	}
	upstreamStarted := time.Now()
	setChatGPTWebImageTaskStage(ctx, "starting_generation")
	response, turn, err := e.openChatGPTWebImageConversation(ctx, client, credential, requirements, upstreamModel, conduit, upstreamPrompt, uploads)
	cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseUpstreamInitial, upstreamStarted)
	if err != nil {
		return nil, err
	}
	prepared.releaseRequestBody()
	return &chatGPTWebImageExecution{
		response: response,
		headers:  cloneChatGPTWebHeaders(response.Header),
		inputIDs: inputIDs,
		turn:     turn,
	}, nil
}

func chatGPTWebImageUpstreamPrompt(prompt, action string, match *helps.ChatGPTWebImageSizeMatch) string {
	prompt = strings.TrimSpace(prompt)
	if match == nil || strings.TrimSpace(match.Ratio) == "" {
		return prompt
	}
	if strings.EqualFold(strings.TrimSpace(action), "edit") {
		return prompt + "\n\n" + fmt.Sprintf(
			"Recompose, crop, or extend the edited image so the final canvas is exactly %d×%d pixels (width × height), with an aspect ratio of %s. Preserve the subject's natural proportions; do not stretch or distort the subject. If exact pixel dimensions are unavailable, preserve the %s aspect ratio exactly.",
			match.Width, match.Height, match.Ratio, match.Ratio,
		)
	}
	return prompt + "\n\n" + fmt.Sprintf(
		"Set the final image canvas to exactly %d×%d pixels (width × height), with an aspect ratio of %s. If exact pixel dimensions are unavailable, preserve the %s aspect ratio exactly.",
		match.Width, match.Height, match.Ratio, match.Ratio,
	)
}

func (e *ChatGPTWebExecutor) finishChatGPTWebImage(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, prepared *chatGPTWebPreparedRequest, execution *chatGPTWebImageExecution) (payload []byte, err error) {
	ctx, _ = withChatGPTWebImageExactStreamRegistry(ctx)
	failureStage := "settle"
	settleStarted := time.Now()
	settleObserved := false
	defer func() {
		if !settleObserved {
			cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseStreamSettle, settleStarted)
		}
		if err != nil {
			err = withChatGPTWebFailureStage(failureStage, err)
		}
	}()
	if execution == nil || execution.response == nil {
		return nil, errors.New("chatgpt web image execution is nil")
	}
	imageRequest := prepared.request.Image
	response := execution.response
	setChatGPTWebImageTaskStage(ctx, "settling_stream")
	pollBudget := newChatGPTWebPollResponseBudget(chatGPTWebPollResponseMaxBytes)
	accumulator, errStream := e.consumeChatGPTWebImageStreamWithTaskPollingForTurn(ctx, client, credential, response, execution.turn, pollBudget)
	if errClose := response.Body.Close(); errClose != nil {
		log.Errorf("chatgpt web executor: close image response body: %v", errClose)
	}
	streamIncomplete := errors.Is(errStream, errChatGPTWebImageIncompleteStream)
	if errStream != nil && (!streamIncomplete || strings.TrimSpace(accumulator.ConversationID) == "") {
		return nil, errStream
	}
	filterChatGPTWebInputImageIDs(accumulator, execution.inputIDs)
	hasStreamOutput := len(accumulator.FileIDs) > 0 || len(accumulator.SedimentIDs) > 0
	if accumulator.FailureStatus != "" {
		return nil, chatGPTWebImageFailureError(accumulator.FailureStatus)
	}
	if !hasStreamOutput && accumulator.HasTerminalAssistantText() && strings.TrimSpace(accumulator.ConversationID) == "" {
		chatGPTWebImageProtocolMetrics.allSourcesExhaustedWithoutOutput.Add(1)
		return nil, newChatGPTWebImageModerationResultError()
	}
	hasTerminal := accumulator.Terminal
	hasDownloadableSediment := strings.TrimSpace(accumulator.ConversationID) != "" && len(accumulator.SedimentIDs) > 0
	if strings.TrimSpace(accumulator.ConversationID) == "" {
		if !hasTerminal {
			return nil, newChatGPTWebImageSettleStatusError(
				chatGPTWebImageErrorMissingTerminal,
				"chatgpt web image stream ended without an explicit terminal state or conversation ID",
			)
		}
		if !hasStreamOutput {
			chatGPTWebImageProtocolMetrics.allSourcesExhaustedWithoutOutput.Add(1)
			return nil, newChatGPTWebImageNoOutputResultError()
		}
	} else if streamIncomplete || !hasTerminal || !hasStreamOutput {
		if err := e.pollChatGPTWebImageConversation(ctx, client, credential, accumulator, execution.inputIDs, hasStreamOutput, pollBudget); err != nil {
			var memoryErr *chatGPTWebImageMemoryCapacityError
			if errors.As(err, &memoryErr) {
				return nil, err
			}
			var noOutputErr *chatGPTWebImageNoOutputResultError
			if errors.As(err, &noOutputErr) {
				chatGPTWebImageProtocolMetrics.allSourcesExhaustedWithoutOutput.Add(1)
				if accumulator.HasTerminalAssistantText() {
					return nil, newChatGPTWebImageModerationResultError()
				}
			}
			var moderationErr *helps.OpenAIImageModerationError
			if errors.As(err, &moderationErr) {
				return nil, err
			}
			if chatGPTWebImagePollAuthenticationError(err) {
				return nil, err
			}
			if hasStreamOutput {
				return nil, newChatGPTWebImageSettleError(err)
			}
			return nil, err
		}
	}
	hasDownloadableSediment = strings.TrimSpace(accumulator.ConversationID) != "" && len(accumulator.SedimentIDs) > 0
	if accumulator.FailureStatus != "" {
		return nil, chatGPTWebImageFailureError(accumulator.FailureStatus)
	}
	if chatGPTWebImageOutputCount(accumulator) == 0 && accumulator.HasTerminalAssistantText() {
		chatGPTWebImageProtocolMetrics.allSourcesExhaustedWithoutOutput.Add(1)
		return nil, newChatGPTWebImageModerationResultError()
	}
	if !accumulator.Terminal && !hasDownloadableSediment {
		return nil, newChatGPTWebImageSettleStatusError(
			chatGPTWebImageErrorMissingTerminal,
			"chatgpt web image conversation ended without an explicit terminal state",
		)
	}
	cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseStreamSettle, settleStarted)
	settleObserved = true
	finalizerStarted := time.Now()
	setChatGPTWebImageTaskStage(ctx, "waiting_finalizer")
	releaseFinalizer, errFinalizer := cliproxyexecutor.AcquireChatGPTWebImageFinalizer(ctx)
	if errFinalizer != nil {
		cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseFinalizerWait, finalizerStarted)
		return nil, errFinalizer
	}
	defer releaseFinalizer()
	releaseMemoryFinalizer, errMemoryFinalizer := cliproxyexecutor.AcquireChatGPTWebImageMemoryFinalizer(ctx)
	if errMemoryFinalizer != nil {
		cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseFinalizerWait, finalizerStarted)
		return nil, errMemoryFinalizer
	}
	defer releaseMemoryFinalizer()
	failureStage = "download"
	setChatGPTWebImageTaskStage(ctx, "downloading")
	parallelMemoryFinalization := cliproxyexecutor.ChatGPTWebImageMemoryFinalizerAdmissionSnapshot().Limit > 1
	if prepared.imageMemoryLeases != nil && !parallelMemoryFinalization {
		releaseCompletionTurn, errFinalization := prepared.imageMemoryLeases.BeginFinalization(ctx)
		if errFinalization != nil {
			cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseFinalizerWait, finalizerStarted)
			return nil, errFinalization
		}
		defer releaseCompletionTurn()
	}
	cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseFinalizerWait, finalizerStarted)
	responseByteLimit := chatGPTWebImageResponseByteLimit(prepared.imageConfigSnapshot)
	downloadStarted := time.Now()
	var images [][]byte
	if parallelMemoryFinalization && prepared.imageMemoryLeases != nil {
		images, ctx, err = e.downloadChatGPTWebImagesWithWholeFinalization(
			ctx,
			client,
			credential,
			accumulator,
			prepared.maxImageResults,
			responseByteLimit,
			imageRequest,
			prepared.imageSizeMatch,
			prepared.imageConfigSnapshot,
			prepared.imageMemoryLeases,
		)
	} else {
		images, err = e.downloadChatGPTWebImagesLimitedWithBudget(ctx, client, credential, accumulator, prepared.maxImageResults, responseByteLimit)
	}
	cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseDownload, downloadStarted)
	if prepared.imageResultState != nil && len(images) > 0 {
		prepared.imageResultState.AddProduced(len(images))
	}
	if err != nil {
		return nil, err
	}
	if len(images) == 0 {
		return nil, statusErr{code: http.StatusBadGateway, msg: "chatgpt web did not return image output"}
	}
	outputCompression := imageRequest.OutputCompression
	if normalizeChatGPTWebImageOutputFormat(imageRequest.OutputFormat) == "png" && outputCompression == 0 {
		outputCompression = 100
	}
	encodeStarted := time.Now()
	setChatGPTWebImageTaskStage(ctx, "encoding")
	// Public Web aliases do not select an image engine. Retain the existing
	// usage estimate while reporting the requested alias separately.
	outputImages, err := prepareChatGPTWebImageOutputsWithContextAndCompression(
		ctx,
		imageRequest.OutputFormat,
		outputCompression,
		chatgptwebauth.ImageModel,
		imageRequest.Quality,
		images,
		prepared.imageSizeMatch,
		prepared.imageConfigSnapshot,
	)
	if err != nil {
		return nil, err
	}
	usage := e.completeChatGPTWebUpstreamImageUsage(prepared, accumulator.ToolUsage)
	if usage == nil {
		usage = e.completeChatGPTWebUsage(prepared, "", outputImages)
	}
	completed, err := buildPreparedChatGPTWebImageCompletedEvent(prepared.routeModel, imageRequest.OutputFormat, images, outputImages, usage)
	cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseWebResponseEncode, encodeStarted)
	if err != nil {
		return nil, err
	}
	if prepared.imageResultState != nil {
		prepared.imageResultState.AddSucceeded(len(outputImages))
	}
	return completed, nil
}

func prepareChatGPTWebImageOutputs(requestedFormat, model, quality string, images [][]byte) ([]helps.ChatGPTWebUsageImage, error) {
	return prepareChatGPTWebImageOutputsWithConfig(
		requestedFormat,
		model,
		quality,
		images,
		nil,
		cliproxyexecutor.ChatGPTWebImageConfigSnapshot{MaxImageResponseBytes: chatGPTWebMaxImageResponseBytes},
	)
}

func prepareChatGPTWebImageOutputsWithConfig(
	requestedFormat, model, quality string,
	images [][]byte,
	imageSizeMatch *helps.ChatGPTWebImageSizeMatch,
	imageConfig cliproxyexecutor.ChatGPTWebImageConfigSnapshot,
) ([]helps.ChatGPTWebUsageImage, error) {
	return prepareChatGPTWebImageOutputsWithConfigAndCompression(
		requestedFormat,
		100,
		model,
		quality,
		images,
		imageSizeMatch,
		imageConfig,
	)
}

func prepareChatGPTWebImageOutputsWithConfigAndCompression(
	requestedFormat string,
	outputCompression int,
	model, quality string,
	images [][]byte,
	imageSizeMatch *helps.ChatGPTWebImageSizeMatch,
	imageConfig cliproxyexecutor.ChatGPTWebImageConfigSnapshot,
) ([]helps.ChatGPTWebUsageImage, error) {
	return prepareChatGPTWebImageOutputsWithContextAndCompression(
		context.Background(),
		requestedFormat,
		outputCompression,
		model,
		quality,
		images,
		imageSizeMatch,
		imageConfig,
	)
}

func prepareChatGPTWebImageOutputsWithContextAndCompression(
	ctx context.Context,
	requestedFormat string,
	outputCompression int,
	model, quality string,
	images [][]byte,
	imageSizeMatch *helps.ChatGPTWebImageSizeMatch,
	imageConfig cliproxyexecutor.ChatGPTWebImageConfigSnapshot,
) ([]helps.ChatGPTWebUsageImage, error) {
	requestedFormat = normalizeChatGPTWebImageOutputFormat(requestedFormat)
	if requestedFormat != "png" && requestedFormat != "jpeg" && requestedFormat != "webp" {
		return nil, statusErr{code: http.StatusBadRequest, msg: "chatgpt web does not support the requested image output format", skipAuthResult: true, retryOtherAuth: true}
	}
	if outputCompression < 0 || outputCompression > 100 || (requestedFormat == "png" && outputCompression != 100) {
		return nil, statusErr{code: http.StatusBadRequest, msg: "chatgpt web does not support the requested image output compression", skipAuthResult: true, retryOtherAuth: true}
	}
	responseByteLimit := chatGPTWebImageResponseByteLimit(imageConfig)
	originalOutputs := make([]helps.ChatGPTWebUsageImage, 0, len(images))
	originalTotalBytes := 0
	for _, imageData := range images {
		if len(imageData) > responseByteLimit-originalTotalBytes {
			return nil, chatGPTWebImageResponseLimitError(responseByteLimit)
		}
		outputFormat := chatGPTWebImageOutputFormat(imageData)
		if outputFormat == "" {
			return nil, statusErr{code: http.StatusBadGateway, msg: "chatgpt web returned an unrecognized image format", skipAuthResult: true, retryOtherAuth: true}
		}
		decodedConfig, _, errConfig := image.DecodeConfig(bytes.NewReader(imageData))
		if errConfig != nil {
			return nil, statusErr{code: http.StatusBadGateway, msg: "chatgpt web returned an invalid image", skipAuthResult: true, retryOtherAuth: true}
		}
		originalOutputs = append(originalOutputs, helps.ChatGPTWebUsageImage{
			Model: model, Use: "image_generation_output", Width: decodedConfig.Width, Height: decodedConfig.Height, Quality: quality,
		})
		originalTotalBytes += len(imageData)
	}

	resizeEnabled := imageConfig.ResizeToRequestedSize && imageSizeMatch != nil
	if resizeEnabled {
		for _, output := range originalOutputs {
			if !helps.ChatGPTWebImageRatioMatches(
				output.Width,
				output.Height,
				imageSizeMatch.RatioWidth,
				imageSizeMatch.RatioHeight,
				imageConfig.AspectRatioMaxErrorPercent,
			) {
				if imageConfig.StrictSize {
					return nil, chatGPTWebImageSizeMismatchError()
				}
				return originalOutputs, nil
			}
		}
	}

	candidates := make([][]byte, len(images))
	candidateOutputs := make([]helps.ChatGPTWebUsageImage, 0, len(images))
	candidateTotalBytes := 0
	changed := false
	for index, imageData := range images {
		originalFormat := chatGPTWebImageOutputFormat(imageData)
		needsResize := resizeEnabled &&
			(originalOutputs[index].Width != imageSizeMatch.Width || originalOutputs[index].Height != imageSizeMatch.Height)
		needsEncoding := originalFormat != requestedFormat || requestedFormat == "jpeg" || requestedFormat == "webp"
		if !needsResize && !needsEncoding {
			if len(imageData) > responseByteLimit-candidateTotalBytes {
				if imageConfig.StrictSize {
					return nil, chatGPTWebImagePostProcessingBudgetError()
				}
				return originalOutputs, nil
			}
			candidates[index] = imageData
			candidateOutputs = append(candidateOutputs, originalOutputs[index])
			candidateTotalBytes += len(imageData)
			continue
		}

		encoded, processedWidth, processedHeight, errEncode := processChatGPTWebOutputImage(
			ctx,
			imageData,
			originalFormat,
			requestedFormat,
			outputCompression,
			responseByteLimit-candidateTotalBytes,
			originalOutputs[index].Width,
			originalOutputs[index].Height,
			needsResize,
			imageSizeMatch,
			imageConfig,
		)
		if errors.Is(errEncode, errChatGPTWebImageResponseBudgetExceeded) {
			if imageConfig.StrictSize {
				return nil, chatGPTWebImagePostProcessingBudgetError()
			}
			return originalOutputs, nil
		}
		if errEncode != nil {
			return nil, fmt.Errorf("encode chatgpt web image as %s: %w", requestedFormat, errEncode)
		}
		if len(encoded) > responseByteLimit-candidateTotalBytes {
			if imageConfig.StrictSize {
				return nil, chatGPTWebImagePostProcessingBudgetError()
			}
			return originalOutputs, nil
		}
		candidates[index] = encoded
		candidateTotalBytes += len(encoded)
		candidateOutputs = append(candidateOutputs, helps.ChatGPTWebUsageImage{
			Model: model, Use: "image_generation_output", Width: processedWidth, Height: processedHeight, Quality: quality,
		})
		changed = true
	}
	if changed {
		copy(images, candidates)
	}
	return candidateOutputs, nil
}

func processChatGPTWebOutputImage(
	ctx context.Context,
	imageData []byte,
	originalFormat string,
	requestedFormat string,
	outputCompression int,
	maxBytes int,
	sourceWidth int,
	sourceHeight int,
	needsResize bool,
	imageSizeMatch *helps.ChatGPTWebImageSizeMatch,
	imageConfig cliproxyexecutor.ChatGPTWebImageConfigSnapshot,
) ([]byte, int, int, error) {
	targetWidth, targetHeight := sourceWidth, sourceHeight
	if needsResize && imageSizeMatch != nil {
		targetWidth, targetHeight = imageSizeMatch.Width, imageSizeMatch.Height
	}
	estimatedBytes := estimateChatGPTWebImagePostProcessingBytes(
		sourceWidth,
		sourceHeight,
		targetWidth,
		targetHeight,
		needsResize,
		requestedFormat,
	)
	releaseMemory, errAcquire := acquireChatGPTWebTransientImageMemory(ctx, estimatedBytes)
	if errAcquire != nil {
		return nil, 0, 0, fmt.Errorf("wait for chatgpt web image post-processing memory: %w", errAcquire)
	}
	defer releaseMemory()

	decoded, _, errDecode := decodeAndValidateChatGPTWebOutputImage(imageData, "image/"+originalFormat)
	if errDecode != nil {
		return nil, 0, 0, fmt.Errorf("decode chatgpt web %s image for post-processing: %w", originalFormat, errDecode)
	}
	processed := image.Image(decoded)
	if needsResize {
		crop := chatGPTWebImageCenterCrop(decoded.Bounds(), targetWidth, targetHeight)
		if crop.Empty() {
			return nil, 0, 0, errors.New("computed chatgpt web image crop is empty")
		}
		destination := image.NewRGBA(image.Rect(0, 0, targetWidth, targetHeight))
		scaler := xdraw.Scaler(xdraw.CatmullRom)
		if strings.EqualFold(strings.TrimSpace(imageConfig.ResizeFilter), config.ChatGPTWebResizeFilterApproxBiLinear) {
			scaler = xdraw.ApproxBiLinear
		}
		scaler.Scale(destination, destination.Bounds(), decoded, crop, xdraw.Src, nil)
		processed = destination
	}

	encoded, errEncode := encodeChatGPTWebOutputImage(
		processed,
		requestedFormat,
		outputCompression,
		maxBytes,
	)
	return encoded, processed.Bounds().Dx(), processed.Bounds().Dy(), errEncode
}

func estimateChatGPTWebImagePostProcessingBytes(
	sourceWidth int,
	sourceHeight int,
	targetWidth int,
	targetHeight int,
	needsResize bool,
	requestedFormat string,
) int64 {
	sourcePixels := saturatingChatGPTWebImagePixels(sourceWidth, sourceHeight)
	targetPixels := sourcePixels
	if needsResize {
		targetPixels = saturatingChatGPTWebImagePixels(targetWidth, targetHeight)
	}
	estimatedBytes := saturatingChatGPTWebImageMultiply(sourcePixels, chatGPTWebDecodedImageBytesPerPixel)
	if needsResize {
		estimatedBytes = saturatingChatGPTWebImageAdd(
			estimatedBytes,
			saturatingChatGPTWebImageMultiply(targetPixels, 4),
		)
	}
	if requestedFormat == "jpeg" || requestedFormat == "webp" {
		estimatedBytes = saturatingChatGPTWebImageAdd(
			estimatedBytes,
			saturatingChatGPTWebImageMultiply(targetPixels, 4),
		)
	}
	// Reserve a conservative encoded-output allowance. The bounded encoder may
	// stop earlier, but keeping this memory in the admission estimate prevents
	// several large output buffers from growing concurrently without accounting.
	estimatedBytes = saturatingChatGPTWebImageAdd(
		estimatedBytes,
		saturatingChatGPTWebImageMultiply(targetPixels, 4),
	)
	return max(estimatedBytes, int64(1))
}

func saturatingChatGPTWebImagePixels(width, height int) int64 {
	if width <= 0 || height <= 0 || int64(width) > int64(^uint64(0)>>1)/int64(height) {
		return int64(^uint64(0) >> 1)
	}
	return int64(width) * int64(height)
}

func saturatingChatGPTWebImageMultiply(value int64, factor int) int64 {
	maxInt64 := int64(^uint64(0) >> 1)
	if value <= 0 || factor <= 0 {
		return 0
	}
	if value > maxInt64/int64(factor) {
		return maxInt64
	}
	return value * int64(factor)
}

func saturatingChatGPTWebImageAdd(left, right int64) int64 {
	maxInt64 := int64(^uint64(0) >> 1)
	if left >= maxInt64-right {
		return maxInt64
	}
	return left + right
}

var errChatGPTWebImageResponseBudgetExceeded = errors.New("chatgpt web image response budget exceeded")

type chatGPTWebBoundedBuffer struct {
	bytes.Buffer
	maxBytes int
}

func (buffer *chatGPTWebBoundedBuffer) Write(data []byte) (int, error) {
	if buffer == nil || len(data) > buffer.maxBytes-buffer.Len() {
		return 0, errChatGPTWebImageResponseBudgetExceeded
	}
	return buffer.Buffer.Write(data)
}

func encodeChatGPTWebOutputImage(source image.Image, outputFormat string, outputCompression, maxBytes int) ([]byte, error) {
	if source == nil {
		return nil, errors.New("chatgpt web image to encode is nil")
	}
	output := &chatGPTWebBoundedBuffer{maxBytes: maxBytes}
	var err error
	switch outputFormat {
	case "png":
		err = png.Encode(output, source)
	case "jpeg":
		// The standard JPEG encoder accepts qualities from 1 through 100, so map
		// the API's lowest quality value to its lowest effective encoder value.
		jpegQuality := max(outputCompression, 1)
		err = jpeg.Encode(output, flattenChatGPTWebImageOnWhite(source), &jpeg.Options{Quality: jpegQuality})
	case "webp":
		// The encoder treats zero as an omitted quality, so map the API's lowest
		// quality value to its lowest effective encoder value instead.
		webPQuality := max(outputCompression, 1)
		err = imagewebp.Encode(output, source, imagewebp.Options{Quality: webPQuality, Exact: true})
	default:
		return nil, fmt.Errorf("unsupported chatgpt web image output format %q", outputFormat)
	}
	if err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func flattenChatGPTWebImageOnWhite(source image.Image) image.Image {
	bounds := source.Bounds()
	destination := image.NewRGBA(image.Rect(0, 0, bounds.Dx(), bounds.Dy()))
	stddraw.Draw(destination, destination.Bounds(), &image.Uniform{C: color.White}, image.Point{}, stddraw.Src)
	stddraw.Draw(destination, destination.Bounds(), source, bounds.Min, stddraw.Over)
	return destination
}

func chatGPTWebImageResponseByteLimit(snapshot cliproxyexecutor.ChatGPTWebImageConfigSnapshot) int {
	maxBytes := config.MaxChatGPTWebMaxImageResponseMegabytes << 20
	if snapshot.MaxImageResponseBytes <= 0 || snapshot.MaxImageResponseBytes > maxBytes {
		return chatGPTWebMaxImageResponseBytes
	}
	return snapshot.MaxImageResponseBytes
}

func chatGPTWebImageResponseLimitError(limit int) error {
	return statusErr{
		code:           http.StatusBadGateway,
		msg:            fmt.Sprintf("chatgpt web image response exceeds %d bytes", limit),
		skipAuthResult: true,
	}
}

func chatGPTWebImageSizeMismatchError() error {
	return statusErr{
		code:           http.StatusBadGateway,
		msg:            `{"error":{"message":"chatgpt web image aspect ratio exceeds the configured tolerance for the requested size.","type":"server_error","code":"image_size_mismatch"}}`,
		skipAuthResult: true,
	}
}

func chatGPTWebImagePostProcessingBudgetError() error {
	return statusErr{
		code:           http.StatusBadGateway,
		msg:            `{"error":{"message":"chatgpt web image post-processing exceeds the configured response budget.","type":"server_error","code":"image_response_budget_exceeded"}}`,
		skipAuthResult: true,
	}
}

func resizeChatGPTWebImageToPNG(
	data []byte,
	match *helps.ChatGPTWebImageSizeMatch,
	snapshot cliproxyexecutor.ChatGPTWebImageConfigSnapshot,
	maxBytes int,
) ([]byte, bool, error) {
	if match == nil || match.Width <= 0 || match.Height <= 0 ||
		match.Width > config.MaxChatGPTWebMaxResizeEdgePixels || match.Height > config.MaxChatGPTWebMaxResizeEdgePixels {
		return nil, false, nil
	}
	imageConfig, err := chatGPTWebOutputImageConfig(data, "image/"+chatGPTWebImageOutputFormat(data))
	if err != nil {
		return nil, false, err
	}
	if !helps.ChatGPTWebImageRatioMatches(
		imageConfig.Width,
		imageConfig.Height,
		match.RatioWidth,
		match.RatioHeight,
		snapshot.AspectRatioMaxErrorPercent,
	) {
		return nil, false, nil
	}
	if imageConfig.Width == match.Width && imageConfig.Height == match.Height && chatGPTWebImageOutputFormat(data) == "png" {
		return nil, false, nil
	}
	decoded, _, err := decodeAndValidateChatGPTWebOutputImage(data, "image/"+chatGPTWebImageOutputFormat(data))
	if err != nil {
		return nil, false, err
	}
	crop := chatGPTWebImageCenterCrop(decoded.Bounds(), match.Width, match.Height)
	if crop.Empty() {
		return nil, false, errors.New("computed image crop is empty")
	}
	destination := image.NewRGBA(image.Rect(0, 0, match.Width, match.Height))
	scaler := xdraw.Scaler(xdraw.CatmullRom)
	if strings.EqualFold(strings.TrimSpace(snapshot.ResizeFilter), config.ChatGPTWebResizeFilterApproxBiLinear) {
		scaler = xdraw.ApproxBiLinear
	}
	scaler.Scale(destination, destination.Bounds(), decoded, crop, xdraw.Src, nil)
	output := &chatGPTWebBoundedBuffer{maxBytes: maxBytes}
	if err = png.Encode(output, destination); err != nil {
		if errors.Is(err, errChatGPTWebImageResponseBudgetExceeded) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return output.Bytes(), true, nil
}

func chatGPTWebImageCenterCrop(bounds image.Rectangle, targetWidth, targetHeight int) image.Rectangle {
	sourceWidth := bounds.Dx()
	sourceHeight := bounds.Dy()
	if sourceWidth <= 0 || sourceHeight <= 0 || targetWidth <= 0 || targetHeight <= 0 {
		return image.Rectangle{}
	}
	cropWidth := sourceWidth
	cropHeight := sourceHeight
	left := int64(sourceWidth) * int64(targetHeight)
	right := int64(sourceHeight) * int64(targetWidth)
	if left > right {
		cropWidth = int((int64(sourceHeight)*int64(targetWidth) + int64(targetHeight)/2) / int64(targetHeight))
	} else if left < right {
		cropHeight = int((int64(sourceWidth)*int64(targetHeight) + int64(targetWidth)/2) / int64(targetWidth))
	}
	cropWidth = min(max(cropWidth, 1), sourceWidth)
	cropHeight = min(max(cropHeight, 1), sourceHeight)
	minX := bounds.Min.X + (sourceWidth-cropWidth)/2
	minY := bounds.Min.Y + (sourceHeight-cropHeight)/2
	return image.Rect(minX, minY, minX+cropWidth, minY+cropHeight)
}

func chatGPTWebImageFailureError(status string) error {
	if chatGPTWebImageModerationFailure(status) {
		return newChatGPTWebImageModerationResultError()
	}
	if chatGPTWebImageQuotaTextEvidence(status) {
		return statusErr{
			code:           http.StatusTooManyRequests,
			msg:            "chatgpt web image quota exhausted: " + strings.TrimSpace(status),
			skipAuthResult: true,
		}
	}
	return newChatGPTWebImageSettleStatusError(
		chatGPTWebImageErrorUpstreamFailed,
		"chatgpt web image generation failed: "+strings.TrimSpace(status),
	)
}

func chatGPTWebImageModerationFailure(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "blocked", "content_filter", "moderation_blocked":
		return true
	default:
		return false
	}
}

func buildChatGPTWebImageCompletedEvent(routeModel, requestedFormat string, images [][]byte, usage map[string]any) ([]byte, error) {
	outputImages, err := prepareChatGPTWebImageOutputs(requestedFormat, routeModel, "", images)
	if err != nil {
		return nil, err
	}
	return buildPreparedChatGPTWebImageCompletedEvent(routeModel, requestedFormat, images, outputImages, usage)
}

func buildPreparedChatGPTWebImageCompletedEvent(routeModel, requestedFormat string, images [][]byte, outputImages []helps.ChatGPTWebUsageImage, usage map[string]any) ([]byte, error) {
	requestedFormat = normalizeChatGPTWebImageOutputFormat(requestedFormat)
	totalBytes := 0
	for _, imageData := range images {
		totalBytes += len(imageData)
	}
	var output bytes.Buffer
	output.Grow(base64.StdEncoding.EncodedLen(totalBytes) + 1024*len(images) + 256)
	output.WriteString(`{"type":"response.completed","response":{"id":`)
	writeChatGPTWebJSONString(&output, "resp_"+strings.ReplaceAll(uuid.NewString(), "-", ""))
	output.WriteString(`,"object":"response","created_at":`)
	_, _ = fmt.Fprintf(&output, "%d", time.Now().Unix())
	output.WriteString(`,"status":"completed","model":`)
	writeChatGPTWebJSONString(&output, routeModel)
	output.WriteString(`,"output":[`)

	for index, imageData := range images {
		outputFormat := chatGPTWebImageOutputFormat(imageData)
		if index > 0 {
			output.WriteByte(',')
		}
		output.WriteString(`{"type":"image_generation_call","id":`)
		writeChatGPTWebJSONString(&output, "ig_"+strings.ReplaceAll(uuid.NewString(), "-", ""))
		output.WriteString(`,"status":"completed","result":"`)
		encoder := base64.NewEncoder(base64.StdEncoding, &output)
		if _, err := encoder.Write(imageData); err != nil {
			return nil, fmt.Errorf("encode chatgpt web image result: %w", err)
		}
		if err := encoder.Close(); err != nil {
			return nil, fmt.Errorf("finish chatgpt web image result: %w", err)
		}
		images[index] = nil
		output.WriteString(`","output_format":`)
		writeChatGPTWebJSONString(&output, outputFormat)
		if index < len(outputImages) {
			imageOutput := outputImages[index]
			if imageOutput.Width > 0 && imageOutput.Height > 0 {
				output.WriteString(`,"size":`)
				writeChatGPTWebJSONString(&output, fmt.Sprintf("%dx%d", imageOutput.Width, imageOutput.Height))
			}
			quality := strings.ToLower(strings.TrimSpace(imageOutput.Quality))
			if quality != "" && quality != "auto" {
				output.WriteString(`,"quality":`)
				writeChatGPTWebJSONString(&output, quality)
			}
		}
		output.WriteByte('}')
	}
	responseUsage := chatGPTWebUsageOrZero(usage)
	toolUsage := responseUsage["tool_usage"]
	if toolUsage != nil {
		responseUsage = cloneChatGPTWebUsage(responseUsage)
		delete(responseUsage, "tool_usage")
	}
	usageJSON, err := json.Marshal(responseUsage)
	if err != nil {
		return nil, fmt.Errorf("encode chatgpt web image usage: %w", err)
	}
	output.WriteString(`],"usage":`)
	_, _ = output.Write(usageJSON)
	if toolUsage != nil {
		toolUsageJSON, errToolUsage := json.Marshal(toolUsage)
		if errToolUsage != nil {
			return nil, fmt.Errorf("encode chatgpt web image tool usage: %w", errToolUsage)
		}
		output.WriteString(`,"tool_usage":`)
		_, _ = output.Write(toolUsageJSON)
	}
	output.WriteString(`}}`)
	return output.Bytes(), nil
}

func cloneChatGPTWebUsage(usage map[string]any) map[string]any {
	cloned := make(map[string]any, len(usage))
	for key, value := range usage {
		cloned[key] = value
	}
	return cloned
}

func convertChatGPTWebImageToPNG(data []byte, outputFormat string) ([]byte, error) {
	return convertChatGPTWebImageToPNGWithLimit(data, outputFormat, chatGPTWebMaxImageResponseBytes)
}

func convertChatGPTWebImageToPNGWithLimit(data []byte, outputFormat string, maxBytes int) ([]byte, error) {
	mimeType := "image/" + strings.TrimSpace(outputFormat)
	if outputFormat == "jpeg" {
		mimeType = "image/jpeg"
	}
	decoded, _, err := decodeAndValidateChatGPTWebOutputImage(data, mimeType)
	if err != nil {
		return nil, err
	}
	output := &chatGPTWebBoundedBuffer{maxBytes: maxBytes}
	if err = png.Encode(output, decoded); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeChatGPTWebJSONString(output *bytes.Buffer, value string) {
	encoded, _ := json.Marshal(value)
	_, _ = output.Write(encoded)
}

func (e *ChatGPTWebExecutor) prepareChatGPTWebImageConversation(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, requirements chatGPTWebRequirements, upstreamModel, prompt string) (string, error) {
	path := "/backend-api/f/conversation/prepare"
	prepareRequirements := requirements
	prepareRequirements.SOToken = ""
	headers := chatGPTWebRequirementsHeaders(e.chatGPTWebHeaders(credential, path, nil), prepareRequirements)
	headers["accept"] = "*/*"
	headers["content-type"] = "application/json"
	timezone := e.chatGPTWebTimezone()
	body := map[string]any{
		"action":                 "next",
		"fork_from_shared_post":  false,
		"parent_message_id":      uuid.NewString(),
		"model":                  upstreamModel,
		"client_prepare_state":   "success",
		"timezone_offset_min":    timezone.OffsetMinutes,
		"timezone":               timezone.Timezone,
		"conversation_mode":      map[string]any{"kind": "primary_assistant"},
		"system_hints":           []string{"picture_v2"},
		"partial_query":          chatGPTWebUserTextMessage(prompt),
		"supports_buffering":     true,
		"supported_encodings":    []string{"v1"},
		"client_contextual_info": map[string]any{"app_name": "chatgpt.com"},
	}
	_, data, err := e.doChatGPTWebJSONWithHeaders(ctx, client, credential, path, headers, body)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(gjsonString(data, "conduit_token"))
	if token == "" {
		return "", chatGPTWebLocalProtocolError(
			http.StatusBadGateway,
			"chatgpt web image prepare response is missing conduit token",
		)
	}
	return token, nil
}

func (e *ChatGPTWebExecutor) openChatGPTWebImageConversation(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, requirements chatGPTWebRequirements, upstreamModel, conduit, prompt string, uploads []chatGPTWebUploadedImage) (*fhttp.Response, helps.ChatGPTWebImageTurn, error) {
	path := "/backend-api/f/conversation"
	headers := chatGPTWebRequirementsHeaders(e.chatGPTWebHeaders(credential, path, nil), requirements)
	headers["accept"] = "text/event-stream"
	headers["content-type"] = "application/json"
	headers["x-conduit-token"] = conduit
	headers["x-oai-turn-trace-id"] = uuid.NewString()
	parts := make([]any, 0, len(uploads)+1)
	attachments := make([]any, 0, len(uploads))
	for _, uploaded := range uploads {
		parts = append(parts, map[string]any{
			"content_type":  "image_asset_pointer",
			"asset_pointer": "file-service://" + uploaded.FileID,
			"width":         uploaded.Width,
			"height":        uploaded.Height,
			"size_bytes":    uploaded.Size,
		})
		attachments = append(attachments, chatGPTWebAttachment(uploaded))
	}
	parts = append(parts, prompt)
	content := map[string]any{"content_type": "text", "parts": []string{prompt}}
	if len(uploads) > 0 {
		content = map[string]any{"content_type": "multimodal_text", "parts": parts}
	}
	metadata := map[string]any{
		"developer_mode_connector_ids": []any{},
		"selected_github_repos":        []any{},
		"selected_all_github_repos":    false,
		"system_hints":                 []string{"picture_v2"},
		"serialization_metadata":       map[string]any{"custom_symbol_offsets": []any{}},
	}
	if len(attachments) > 0 {
		metadata["attachments"] = attachments
	}
	turn := helps.ChatGPTWebImageTurn{
		MessageID: uuid.NewString(),
		CreatedAt: float64(time.Now().UnixNano()) / 1e9,
	}
	timezone := e.chatGPTWebTimezone()
	body := map[string]any{
		"action": "next",
		"messages": []any{map[string]any{
			"id": turn.MessageID, "author": map[string]any{"role": "user"}, "create_time": turn.CreatedAt,
			"content": content, "metadata": metadata,
		}},
		"parent_message_id":                    uuid.NewString(),
		"model":                                upstreamModel,
		"client_prepare_state":                 "sent",
		"timezone_offset_min":                  timezone.OffsetMinutes,
		"timezone":                             timezone.Timezone,
		"conversation_mode":                    map[string]any{"kind": "primary_assistant"},
		"enable_message_followups":             true,
		"system_hints":                         []string{"picture_v2"},
		"supports_buffering":                   true,
		"supported_encodings":                  []string{"v1"},
		"client_contextual_info":               chatGPTWebClientContext(),
		"paragen_cot_summary_display_override": "allow",
		"force_parallel_switch":                "auto",
	}
	response, err := e.doChatGPTWebJSONStream(ctx, client, credential, path, headers, body)
	return response, turn, err
}

func (e *ChatGPTWebExecutor) uploadChatGPTWebImage(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, imageURL, fileName string) (chatGPTWebUploadedImage, error) {
	data, mimeType, err := decodeChatGPTWebImageReference(imageURL)
	if err != nil {
		return chatGPTWebUploadedImage{}, statusErr{code: http.StatusBadRequest, msg: err.Error(), skipAuthResult: true}
	}
	config, err := chatGPTWebReferenceImageConfig(data, mimeType)
	if err != nil {
		return chatGPTWebUploadedImage{}, statusErr{code: http.StatusBadRequest, msg: "decode image: " + err.Error(), skipAuthResult: true}
	}
	if extension := extensionForChatGPTWebMIME(mimeType); extension != "" {
		fileName = strings.TrimSuffix(fileName, filepath.Ext(fileName)) + extension
	}
	path := "/backend-api/files"
	_, metadataData, err := e.doChatGPTWebJSON(ctx, client, credential, path, map[string]any{
		"file_name":                 fileName,
		"file_size":                 len(data),
		"use_case":                  "multimodal",
		"width":                     config.Width,
		"height":                    config.Height,
		"mime_type":                 mimeType,
		"client_resolved_mime_type": mimeType,
		"timezone_offset_min":       e.chatGPTWebTimezone().OffsetMinutes,
		"store_in_library":          false,
	})
	if err != nil {
		return chatGPTWebUploadedImage{}, chatGPTWebAssetNetworkError(ctx, "signing", chatGPTWebLibraryUploadSize(err, len(data)))
	}
	var metadata map[string]any
	if err := json.Unmarshal(metadataData, &metadata); err != nil {
		return chatGPTWebUploadedImage{}, chatGPTWebLocalProtocolError(
			http.StatusBadGateway,
			"decode chatgpt web upload metadata: "+err.Error(),
		)
	}
	fileID := strings.TrimSpace(fmt.Sprint(metadata["file_id"]))
	uploadURL := strings.TrimSpace(fmt.Sprint(metadata["upload_url"]))
	if fileID == "" || fileID == "<nil>" || uploadURL == "" || uploadURL == "<nil>" {
		return chatGPTWebUploadedImage{}, chatGPTWebLocalProtocolError(
			http.StatusBadGateway,
			"chatgpt web upload response is incomplete",
		)
	}
	uploadHeaders := map[string]string{
		"content-type":    mimeType,
		"x-ms-blob-type":  "BlockBlob",
		"x-ms-version":    "2020-04-08",
		"origin":          e.chatGPTWebBaseURL(),
		"referer":         e.chatGPTWebBaseURL() + "/",
		"accept":          "application/json, text/plain, */*",
		"accept-language": credential.Persona.AcceptLanguage,
	}
	response, finalUploadURL, err := e.doChatGPTWebAssetRequest(ctx, client, credential, http.MethodPut, uploadURL, uploadHeaders, data, true)
	if err != nil {
		sanitizedErr := newChatGPTWebAssetTransportError(ctx, "upload", err)
		helps.RecordAPIResponseError(ctx, e.configSnapshot(), sanitizedErr)
		return chatGPTWebUploadedImage{}, sanitizedErr
	}
	payload, errRead := readChatGPTWebErrorBody(response.Body)
	errClose := response.Body.Close()
	if errRead != nil || errClose != nil {
		cause := errRead
		if cause == nil {
			cause = errClose
		}
		sanitizedErr := newChatGPTWebAssetTransportError(ctx, "upload response", cause)
		helps.RecordAPIResponseError(ctx, e.configSnapshot(), sanitizedErr)
		return chatGPTWebUploadedImage{}, sanitizedErr
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return chatGPTWebUploadedImage{}, newChatGPTWebAssetStatusError(response.StatusCode, finalUploadURL, payload, response.Header, "file_upload")
	}
	if err := e.confirmChatGPTWebImageUpload(ctx, client, credential, fileID, fileName); err != nil {
		return chatGPTWebUploadedImage{}, chatGPTWebAssetNetworkError(ctx, "confirmation", chatGPTWebLibraryUploadSize(err, len(data)))
	}
	return chatGPTWebUploadedImage{
		FileID: fileID, FileName: fileName, MIMEType: mimeType, Size: len(data), Width: config.Width, Height: config.Height,
	}, nil
}

func (e *ChatGPTWebExecutor) confirmChatGPTWebImageUpload(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, fileID, fileName string) error {
	const path = "/backend-api/files/process_upload_stream"
	headers := e.chatGPTWebHeaders(credential, path, map[string]string{"accept": "text/event-stream", "content-type": "application/json"})
	body := map[string]any{
		"file_id": fileID, "file_name": fileName, "use_case": "multimodal", "index_for_retrieval": false,
		"metadata": map[string]any{"store_in_library": false},
	}
	payload, _ := json.Marshal(body)
	e.recordChatGPTWebRequest(ctx, credential, http.MethodPost, path, headers, payload)
	response, err := client.DoJSONStream(ctx, http.MethodPost, e.chatGPTWebBaseURL()+path, headers, body)
	if err != nil {
		return chatGPTWebTransportDiagnosticError(err, path)
	}
	helps.RecordAPIResponseMetadata(ctx, e.configSnapshot(), response.StatusCode, chatGPTWebResponseLogHeaders(response.Header))
	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusMethodNotAllowed {
		_ = readAndCloseChatGPTWebErrorBody(response.Body)
		if err := ctx.Err(); err != nil {
			return err
		}
		// Only a definitive unsupported endpoint can use legacy confirmation.
		// Never repeat the binary upload or fall back after an ambiguous stream.
		legacyPath := "/backend-api/files/" + url.PathEscape(fileID) + "/uploaded"
		_, _, err := e.doChatGPTWebJSON(ctx, client, credential, legacyPath, map[string]any{})
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data := readAndCloseChatGPTWebErrorBody(response.Body)
		return newChatGPTWebStatusError(response.StatusCode, path, data, response.Header)
	}
	defer func() {
		if errClose := response.Body.Close(); errClose != nil {
			log.Debug("chatgpt web upload processing response close failed")
		}
	}()
	wrapChatGPTWebChallengeInspectingBody(response, path)
	if err := helps.ConsumeChatGPTWebUploadProcessing(ctx, response.Body, fileID); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var processing *helps.UploadProcessingError
		if errors.As(err, &processing) && processing.StorageRejected {
			return chatGPTWebHTTPError{statusErr: chatGPTWebLocalProtocolError(http.StatusBadGateway, err.Error()), path: path, libraryStorageRejected: true}
		}
		return chatGPTWebLocalProtocolError(http.StatusBadGateway, "image upload processing did not complete: "+err.Error())
	}
	return nil
}

func (e *ChatGPTWebExecutor) doChatGPTWebAssetRequest(
	ctx context.Context,
	client *chatgptwebauth.Client,
	credential *chatgptwebauth.Credential,
	method string,
	targetURL string,
	headers map[string]string,
	data []byte,
	signedUpload bool,
) (*fhttp.Response, string, error) {
	if client == nil {
		return nil, "", errors.New("chatgpt web asset client is nil")
	}
	currentURL, err := e.validateChatGPTWebAssetURL(targetURL)
	if err != nil {
		return nil, "", err
	}
	for redirects := 0; ; redirects++ {
		var body io.Reader
		if len(data) > 0 {
			body = bytes.NewReader(data)
		}
		requestHeaders := e.chatGPTWebAssetRequestHeaders(credential, method, currentURL, headers, signedUpload)
		e.recordChatGPTWebRequest(ctx, credential, method, currentURL.String(), requestHeaders, nil)
		response, errRequest := client.DoNoRedirectStream(ctx, method, currentURL.String(), requestHeaders, body)
		if errRequest != nil {
			return nil, currentURL.String(), errRequest
		}
		helps.RecordAPIResponseMetadata(ctx, e.configSnapshot(), response.StatusCode, chatGPTWebResponseLogHeaders(response.Header))
		if !chatGPTWebAssetRedirectStatus(method, response.StatusCode, signedUpload) {
			return response, currentURL.String(), nil
		}
		if redirects >= chatGPTWebMaxAssetRedirects {
			_ = response.Body.Close()
			return nil, currentURL.String(), errors.New("chatgpt web asset redirect limit exceeded")
		}
		location := strings.TrimSpace(response.Header.Get("Location"))
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, chatGPTWebMaxErrorBodyBytes))
		if errClose := response.Body.Close(); errClose != nil {
			return nil, currentURL.String(), fmt.Errorf("close chatgpt web asset redirect response: %w", errClose)
		}
		if location == "" {
			return nil, currentURL.String(), errors.New("chatgpt web asset redirect is missing location")
		}
		locationURL, errLocation := url.Parse(location)
		if errLocation != nil {
			return nil, currentURL.String(), errors.New("chatgpt web asset redirect is invalid")
		}
		nextURL, errValidate := e.validateChatGPTWebAssetURL(currentURL.ResolveReference(locationURL).String())
		if errValidate != nil {
			return nil, currentURL.String(), errValidate
		}
		if signedUpload {
			if errRedirect := validateChatGPTWebSignedUploadRedirect(currentURL, nextURL); errRedirect != nil {
				return nil, currentURL.String(), errRedirect
			}
		}
		currentURL = nextURL
	}
}

func (e *ChatGPTWebExecutor) chatGPTWebAssetRequestHeaders(credential *chatgptwebauth.Credential, method string, targetURL *url.URL, headers map[string]string, signedUpload bool) map[string]string {
	requestHeaders := make(map[string]string, len(headers)+16)
	if !signedUpload && strings.EqualFold(strings.TrimSpace(method), http.MethodGet) {
		baseURL, _ := url.Parse(e.chatGPTWebBaseURL())
		if sameChatGPTWebAssetOrigin(baseURL, targetURL) {
			path := targetURL.EscapedPath()
			if path == "" {
				path = "/"
			}
			requestHeaders = e.chatGPTWebHeaders(credential, path, nil)
		}
	}
	for key, value := range headers {
		requestHeaders[key] = value
	}
	return requestHeaders
}

func chatGPTWebAssetRedirectStatus(method string, status int, signedUpload bool) bool {
	if signedUpload || !strings.EqualFold(strings.TrimSpace(method), http.MethodGet) {
		return status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect
	}
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func (e *ChatGPTWebExecutor) validateChatGPTWebAssetURL(rawURL string) (*url.URL, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errors.New("chatgpt web asset URL is invalid")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed == nil {
		return nil, errors.New("chatgpt web asset URL is invalid")
	}
	baseURL, _ := url.Parse(e.chatGPTWebBaseURL())
	if parsed.Host == "" {
		parsed = baseURL.ResolveReference(parsed)
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return nil, errors.New("chatgpt web asset URL is invalid")
	}
	if parsed.User != nil {
		return nil, errors.New("chatgpt web asset URL credentials are not allowed")
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme != "http" && scheme != "https" {
		return nil, errors.New("chatgpt web asset URL scheme is invalid")
	}
	if sameChatGPTWebAssetOrigin(baseURL, parsed) {
		return parsed, nil
	}
	if scheme != "https" {
		return nil, errors.New("chatgpt web asset URL must use HTTPS")
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return nil, errors.New("chatgpt web asset URL port is not allowed")
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parsed.Hostname()), "."))
	if net.ParseIP(host) != nil || !chatGPTWebAssetHostAllowed(host) {
		return nil, errors.New("chatgpt web asset URL host is not allowed")
	}
	return parsed, nil
}

func sameChatGPTWebAssetOrigin(left, right *url.URL) bool {
	if left == nil || right == nil {
		return false
	}
	leftScheme := strings.ToLower(strings.TrimSpace(left.Scheme))
	rightScheme := strings.ToLower(strings.TrimSpace(right.Scheme))
	return leftScheme == rightScheme &&
		strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(left.Hostname()), "."), strings.TrimSuffix(strings.TrimSpace(right.Hostname()), ".")) &&
		chatGPTWebEffectivePort(leftScheme, left.Port()) == chatGPTWebEffectivePort(rightScheme, right.Port())
}

func chatGPTWebEffectivePort(scheme, port string) string {
	if port != "" {
		return port
	}
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func chatGPTWebAssetHostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, suffix := range chatGPTWebAssetHostSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func validateChatGPTWebSignedUploadRedirect(currentURL, nextURL *url.URL) error {
	if currentURL == nil || nextURL == nil {
		return errors.New("chatgpt web upload redirect is invalid")
	}
	nextScheme := strings.ToLower(strings.TrimSpace(nextURL.Scheme))
	if nextScheme != "http" && nextScheme != "https" {
		return errors.New("chatgpt web upload redirect scheme is invalid")
	}
	currentScheme := strings.ToLower(strings.TrimSpace(currentURL.Scheme))
	if currentScheme == "https" && nextScheme != "https" {
		return errors.New("chatgpt web upload redirect HTTPS downgrade is not allowed")
	}
	if !strings.EqualFold(strings.TrimSpace(currentURL.Host), strings.TrimSpace(nextURL.Host)) {
		return errors.New("chatgpt web upload redirect host is not allowed")
	}
	return nil
}

func chatGPTWebImageConfig(data []byte, mimeType string) (image.Config, error) {
	imageConfig, err := decodeChatGPTWebImageConfig(data, mimeType)
	if err != nil {
		return image.Config{}, err
	}
	return imageConfig, validateChatGPTWebImageConfig(imageConfig)
}

func chatGPTWebReferenceImageConfig(data []byte, mimeType string) (image.Config, error) {
	imageConfig, err := decodeChatGPTWebImageConfig(data, mimeType)
	if err != nil {
		return image.Config{}, err
	}
	if imageConfig.Width <= 0 || imageConfig.Height <= 0 {
		return image.Config{}, errors.New("image dimensions must be positive")
	}
	return imageConfig, nil
}

func chatGPTWebOutputImageConfig(data []byte, mimeType string) (image.Config, error) {
	imageConfig, err := decodeChatGPTWebImageConfig(data, mimeType)
	if err != nil {
		return image.Config{}, err
	}
	return imageConfig, validateChatGPTWebOutputImageConfig(imageConfig)
}

func decodeChatGPTWebImageConfig(data []byte, mimeType string) (image.Config, error) {
	imageConfig, detected, err := helps.DetectChatGPTWebImageMIME(bytes.NewReader(data))
	if err == nil {
		declared := helps.CanonicalChatGPTWebImageMIME(mimeType)
		if declared != detected {
			if declared == "" {
				declared = strings.ToLower(strings.TrimSpace(mimeType))
			}
			return image.Config{}, &helps.ChatGPTWebImageMIMEMismatchError{Declared: declared, Detected: detected}
		}
		return imageConfig, nil
	}
	if !strings.EqualFold(strings.TrimSpace(mimeType), "image/webp") {
		return image.Config{}, err
	}
	width, height, ok := chatGPTWebWebPDimensions(data)
	if !ok {
		return image.Config{}, err
	}
	return image.Config{Width: width, Height: height}, nil
}

func decodeAndValidateChatGPTWebOutputImage(data []byte, mimeType string) (image.Image, image.Config, error) {
	return decodeAndValidateChatGPTWebImageWithConfig(data, mimeType, chatGPTWebOutputImageConfig)
}

func decodeAndValidateChatGPTWebImageWithConfig(
	data []byte,
	mimeType string,
	decodeConfig func([]byte, string) (image.Config, error),
) (image.Image, image.Config, error) {
	imageConfig, err := decodeConfig(data, mimeType)
	if err != nil {
		return nil, image.Config{}, err
	}
	decoded, err := decodeAndValidateChatGPTWebImageAgainstConfig(data, imageConfig)
	if err != nil {
		return nil, image.Config{}, err
	}
	return decoded, imageConfig, nil
}

func decodeAndValidateChatGPTWebImageAgainstConfig(data []byte, imageConfig image.Config) (image.Image, error) {
	decoded, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	bounds := decoded.Bounds()
	if bounds.Dx() != imageConfig.Width || bounds.Dy() != imageConfig.Height {
		return nil, errors.New("decoded image dimensions do not match its header")
	}
	return decoded, nil
}

func validateChatGPTWebImageConfig(imageConfig image.Config) error {
	if imageConfig.Width <= 0 || imageConfig.Height <= 0 {
		return errors.New("image dimensions must be positive")
	}
	pixels := int64(imageConfig.Width) * int64(imageConfig.Height)
	if pixels > chatGPTWebMaxImagePixels {
		return fmt.Errorf("image dimensions exceed %d pixels", chatGPTWebMaxImagePixels)
	}
	return nil
}

func validateChatGPTWebOutputImageConfig(imageConfig image.Config) error {
	if imageConfig.Width <= 0 || imageConfig.Height <= 0 {
		return errors.New("image dimensions must be positive")
	}
	if imageConfig.Width > config.MaxChatGPTWebMaxResizeEdgePixels || imageConfig.Height > config.MaxChatGPTWebMaxResizeEdgePixels {
		return fmt.Errorf("image dimensions exceed %d pixels per edge", config.MaxChatGPTWebMaxResizeEdgePixels)
	}
	pixels := int64(imageConfig.Width) * int64(imageConfig.Height)
	if pixels > chatGPTWebMaxOutputImagePixels {
		return fmt.Errorf("image dimensions exceed %d pixels", chatGPTWebMaxOutputImagePixels)
	}
	return nil
}

func chatGPTWebWebPDimensions(data []byte) (int, int, bool) {
	if len(data) < 30 || string(data[:4]) != "RIFF" || string(data[8:12]) != "WEBP" {
		return 0, 0, false
	}
	switch string(data[12:16]) {
	case "VP8X":
		width := 1 + int(data[24]) + int(data[25])<<8 + int(data[26])<<16
		height := 1 + int(data[27]) + int(data[28])<<8 + int(data[29])<<16
		return width, height, width > 0 && height > 0
	case "VP8L":
		if len(data) < 25 || data[20] != 0x2f {
			return 0, 0, false
		}
		width := 1 + int(data[21]) + int(data[22]&0x3f)<<8
		height := 1 + int(data[22]>>6) + int(data[23])<<2 + int(data[24]&0x0f)<<10
		return width, height, width > 0 && height > 0
	case "VP8 ":
		for index := 20; index+9 < len(data); index++ {
			if data[index] == 0x9d && data[index+1] == 0x01 && data[index+2] == 0x2a {
				width := int(binary.LittleEndian.Uint16(data[index+3:index+5]) & 0x3fff)
				height := int(binary.LittleEndian.Uint16(data[index+5:index+7]) & 0x3fff)
				return width, height, width > 0 && height > 0
			}
		}
	}
	return 0, 0, false
}

func consumeChatGPTWebImageStream(ctx context.Context, body io.Reader, accumulator *helps.ChatGPTWebImageAccumulator) error {
	return consumeChatGPTWebImageStreamWithLimitsAndProgress(
		ctx,
		body,
		accumulator,
		chatGPTWebImageStreamMaxBytes,
		chatGPTWebImageStreamMaxEvents,
		nil,
	)
}

func consumeChatGPTWebImageStreamWithLimits(ctx context.Context, body io.Reader, accumulator *helps.ChatGPTWebImageAccumulator, maxBytes, maxEvents int) error {
	return consumeChatGPTWebImageStreamWithLimitsAndProgress(ctx, body, accumulator, maxBytes, maxEvents, nil)
}

func consumeChatGPTWebImageStreamWithLimitsAndProgress(ctx context.Context, body io.Reader, accumulator *helps.ChatGPTWebImageAccumulator, maxBytes, maxEvents int, onProgress func()) error {
	decoder := helps.NewChatGPTWebSSEDecoder(chatGPTWebSSEMaxFrameBytes)
	buffer := make([]byte, 32<<10)
	totalBytes := 0
	eventCount := 0
	applyPayloads := func(payloads [][]byte) (bool, error) {
		for _, payload := range payloads {
			eventCount++
			if maxEvents > 0 && eventCount > maxEvents {
				return false, &helps.ChatGPTWebResponseLimitError{
					Message: "chatgpt web image stream exceeds the event limit",
				}
			}
			done, err := accumulator.Apply(payload)
			if err != nil {
				return false, err
			}
			if onProgress != nil {
				onProgress()
			}
			if done {
				return true, nil
			}
		}
		return false, nil
	}
	for {
		count, errRead := body.Read(buffer)
		if count > 0 {
			if maxBytes > 0 && count > maxBytes-totalBytes {
				return &helps.ChatGPTWebResponseLimitError{
					Message: "chatgpt web image stream exceeds the response limit",
				}
			}
			totalBytes += count
			payloads, err := decoder.Feed(buffer[:count], false)
			if err != nil {
				return err
			}
			done, errConsume := applyPayloads(payloads)
			if errConsume != nil {
				return errConsume
			}
			if done {
				return nil
			}
		}
		if errRead != nil {
			if !errors.Is(errRead, io.EOF) {
				return errRead
			}
			payloads, err := decoder.Feed(nil, true)
			if err != nil {
				return err
			}
			done, errConsume := applyPayloads(payloads)
			if errConsume != nil {
				return errConsume
			}
			if done {
				return nil
			}
			if accumulator.StreamTerminal || accumulator.FailureStatus != "" {
				return nil
			}
			if ctx != nil && ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("%w: %v", errChatGPTWebImageIncompleteStream, helps.IncompleteStreamError("chatgpt web image"))
		}
	}
}

type chatGPTWebImageTaskWatchResult struct {
	accumulator *helps.ChatGPTWebImageAccumulator
	err         error
}

type chatGPTWebImageTaskPollResult struct {
	accumulator   *helps.ChatGPTWebImageAccumulator
	state         helps.ChatGPTWebImageTaskState
	err           error
	protocolError bool
}

type chatGPTWebImageExactStreamRegistry struct {
	mu             sync.Mutex
	observed       map[string]struct{}
	attempted      map[string]struct{}
	completed      map[string]*helps.ChatGPTWebImageAccumulator
	primaryTaskIDs []string
}

type chatGPTWebImageExactStreamContextKey struct{}

func withChatGPTWebImageExactStreamRegistry(ctx context.Context) (context.Context, *chatGPTWebImageExactStreamRegistry) {
	if ctx == nil {
		ctx = context.Background()
	}
	if registry, _ := ctx.Value(chatGPTWebImageExactStreamContextKey{}).(*chatGPTWebImageExactStreamRegistry); registry != nil {
		return ctx, registry
	}
	registry := &chatGPTWebImageExactStreamRegistry{}
	return context.WithValue(ctx, chatGPTWebImageExactStreamContextKey{}, registry), registry
}

func (registry *chatGPTWebImageExactStreamRegistry) observePrimary(taskIDs []string) {
	registry.mu.Lock()
	// The primary accumulator is append-only and already bounds these IDs.
	previous := len(registry.primaryTaskIDs)
	if len(taskIDs) <= previous {
		registry.mu.Unlock()
		return
	}
	registry.primaryTaskIDs = append([]string(nil), taskIDs...)
	registry.mu.Unlock()
	registry.observe(taskIDs[previous:]...)
}

func (registry *chatGPTWebImageExactStreamRegistry) seed(source *helps.ChatGPTWebImageAccumulator) *helps.ChatGPTWebImageAccumulator {
	seed := chatGPTWebImageTaskSeed(source)
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if len(registry.primaryTaskIDs) > 0 {
		seed.TaskIDs = append([]string(nil), registry.primaryTaskIDs...)
	}
	return seed
}

func (registry *chatGPTWebImageExactStreamRegistry) observe(taskIDs ...string) {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.observed == nil {
		registry.observed = make(map[string]struct{})
	}
	for _, taskID := range taskIDs {
		taskID = strings.TrimSpace(taskID)
		if taskID == "" {
			continue
		}
		if _, exists := registry.observed[taskID]; exists {
			continue
		}
		registry.observed[taskID] = struct{}{}
		chatGPTWebImageProtocolMetrics.taskIDsObserved.Add(1)
	}
}

func (registry *chatGPTWebImageExactStreamRegistry) claim(taskID string) bool {
	if registry == nil {
		return false
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return false
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.attempted == nil {
		registry.attempted = make(map[string]struct{})
	}
	if _, exists := registry.attempted[taskID]; exists {
		return false
	}
	registry.attempted[taskID] = struct{}{}
	return true
}

func (registry *chatGPTWebImageExactStreamRegistry) store(taskID string, accumulator *helps.ChatGPTWebImageAccumulator) {
	if registry == nil || accumulator == nil {
		return
	}
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.completed == nil {
		registry.completed = make(map[string]*helps.ChatGPTWebImageAccumulator)
	}
	registry.completed[taskID] = accumulator
}

func (registry *chatGPTWebImageExactStreamRegistry) load(taskID string) *helps.ChatGPTWebImageAccumulator {
	if registry == nil {
		return nil
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return registry.completed[strings.TrimSpace(taskID)]
}

type chatGPTWebImageConversationPollResult struct {
	accumulator   *helps.ChatGPTWebImageAccumulator
	err           error
	protocolError bool
}

var (
	errChatGPTWebImageStreamClosedByWatcher = errors.New("chatgpt web image stream closed by task watcher")
	errChatGPTWebImageIncompleteStream      = errors.New("chatgpt web image incomplete stream")
)

type chatGPTWebImageWatchBody struct {
	io.ReadCloser
	closedByWatcher atomic.Bool
}

func (e *ChatGPTWebExecutor) startChatGPTWebImageTaskPoll(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, conversationID string, budget *chatGPTWebPollResponseBudget) <-chan chatGPTWebImageTaskPollResult {
	return e.startChatGPTWebImageTaskPollForTurn(ctx, client, credential, conversationID, helps.ChatGPTWebImageTurn{}, budget)
}

func (e *ChatGPTWebExecutor) startChatGPTWebImageTaskPollForTurn(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, conversationID string, turn helps.ChatGPTWebImageTurn, budget *chatGPTWebPollResponseBudget) <-chan chatGPTWebImageTaskPollResult {
	seed := &helps.ChatGPTWebImageAccumulator{ConversationID: conversationID, Turn: turn}
	return e.startChatGPTWebImageTaskPollForAccumulator(ctx, client, credential, seed, budget, nil)
}

func (e *ChatGPTWebExecutor) startChatGPTWebImageTaskPollForAccumulator(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, seed *helps.ChatGPTWebImageAccumulator, budget *chatGPTWebPollResponseBudget, exactStreams *chatGPTWebImageExactStreamRegistry) <-chan chatGPTWebImageTaskPollResult {
	result := make(chan chatGPTWebImageTaskPollResult, 1)
	go func() {
		defer close(result)
		pollResult := e.fetchChatGPTWebImageTaskPages(ctx, client, credential, seed, budget, exactStreams)
		select {
		case result <- pollResult:
		case <-ctx.Done():
		}
	}()
	return result
}

func chatGPTWebImageTaskSeed(source *helps.ChatGPTWebImageAccumulator) *helps.ChatGPTWebImageAccumulator {
	if source == nil {
		return &helps.ChatGPTWebImageAccumulator{}
	}
	return &helps.ChatGPTWebImageAccumulator{
		ConversationID:     source.ConversationID,
		Turn:               source.Turn,
		TaskIDs:            append([]string(nil), source.TaskIDs...),
		ResponseMessageIDs: append([]string(nil), source.ResponseMessageIDs...),
	}
}

func (e *ChatGPTWebExecutor) fetchChatGPTWebImageTaskPages(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, seed *helps.ChatGPTWebImageAccumulator, budget *chatGPTWebPollResponseBudget, exactStreams *chatGPTWebImageExactStreamRegistry) chatGPTWebImageTaskPollResult {
	if seed == nil {
		seed = &helps.ChatGPTWebImageAccumulator{}
	}
	accumulator, errClone := helps.MergeChatGPTWebImageAccumulators(nil, seed)
	if errClone != nil {
		return chatGPTWebImageTaskPollResult{accumulator: accumulator, err: errClone, protocolError: true}
	}
	conversationID := strings.TrimSpace(accumulator.ConversationID)
	result := chatGPTWebImageTaskPollResult{accumulator: accumulator}
	knownTaskIDs := append([]string(nil), accumulator.TaskIDs...)
	exactStreams.observe(knownTaskIDs...)
	seenCursors := make(map[string]struct{}, chatGPTWebImageTaskMaxPages)
	cursor := ""
	for page := 0; page < chatGPTWebImageTaskMaxPages; page++ {
		path := "/backend-api/tasks"
		if cursor != "" {
			path += "?cursor=" + url.QueryEscape(cursor)
		}
		_, payload, releaseMemory, err := e.doChatGPTWebPollGET(ctx, client, credential, path, nil, budget)
		if releaseMemory != nil {
			releaseMemory()
		}
		if err != nil {
			result.err = err
			return result
		}
		chatGPTWebImageProtocolMetrics.taskPagesFetched.Add(1)
		pageAccumulator := &helps.ChatGPTWebImageAccumulator{
			ConversationID: conversationID,
			Turn:           accumulator.Turn,
			TaskIDs:        append([]string(nil), knownTaskIDs...),
		}
		pageState, errCapture := helps.CaptureChatGPTWebImageTasks(payload, conversationID, pageAccumulator)
		observeChatGPTWebImageTaskPage(pageState, errCapture)
		if errCapture != nil {
			result.err = errCapture
			result.protocolError = true
			return result
		}
		observeChatGPTWebImageProtocolAccumulator(pageAccumulator)
		for _, target := range pageState.Targets {
			exactStreams.observe(target.TaskID)
		}
		mergedAccumulator, errMerge := helps.MergeChatGPTWebImageAccumulators(accumulator, pageAccumulator)
		if errMerge != nil {
			result.err = errMerge
			result.protocolError = true
			return result
		}
		accumulator = mergedAccumulator
		result.accumulator = accumulator
		mergeChatGPTWebImageTaskState(&result.state, pageState)

		nextCursor, hasCursor, errCursor := helps.ChatGPTWebImageTasksNextCursor(payload)
		if errCursor != nil {
			result.err = errCursor
			result.protocolError = true
			return result
		}
		if chatGPTWebImageTaskIDsFound(knownTaskIDs, result.state.Targets) ||
			(pageState.Matched > 0 && pageState.AllTerminal()) || !hasCursor {
			break
		}
		if nextCursor == cursor {
			break
		}
		if _, duplicate := seenCursors[nextCursor]; duplicate {
			break
		}
		seenCursors[nextCursor] = struct{}{}
		cursor = nextCursor
	}

	for index := range result.state.Targets {
		target := &result.state.Targets[index]
		if strings.TrimSpace(target.ResponseMessageID) == "" || exactStreams == nil {
			continue
		}
		if target.Terminal && (chatGPTWebImageOutputCount(result.accumulator) > 0 || result.accumulator.FailureStatus != "") {
			continue
		}
		exactAccumulator := exactStreams.load(target.TaskID)
		var errExact error
		if exactAccumulator == nil {
			if !exactStreams.claim(target.TaskID) {
				continue
			}
			exactAccumulator, errExact = e.consumeChatGPTWebExactImageTaskStream(ctx, client, credential, conversationID, *target, budget)
		}
		if errExact != nil {
			if ctx != nil && ctx.Err() != nil {
				// A completed primary SSE cancels its watcher. The subsequent
				// poll phase must be able to resume an interrupted exact stream.
				exactStreams.mu.Lock()
				delete(exactStreams.attempted, target.TaskID)
				exactStreams.mu.Unlock()
				result.err = ctx.Err()
				return result
			}
			var limitErr *helps.ChatGPTWebResponseLimitError
			if errors.As(errExact, &limitErr) {
				result.err = errExact
				return result
			}
			if chatGPTWebImagePollAuthenticationError(errExact) {
				result.err = errExact
				return result
			}
			chatGPTWebImageProtocolMetrics.exactStreamFallbacks.Add(1)
			continue
		}
		exactStreams.store(target.TaskID, exactAccumulator)
		merged, errMerge := helps.MergeChatGPTWebImageAccumulators(result.accumulator, exactAccumulator)
		if errMerge != nil {
			result.err = errMerge
			result.protocolError = true
			return result
		}
		result.accumulator = merged
		if exactAccumulator.Terminal || exactAccumulator.FailureStatus != "" || exactAccumulator.StreamTerminal {
			if !target.Terminal {
				target.Terminal = true
				result.state.Terminal++
			}
		}
	}
	result.accumulator.Terminal = result.state.AllTerminal()
	return result
}

func mergeChatGPTWebImageTaskState(target *helps.ChatGPTWebImageTaskState, source helps.ChatGPTWebImageTaskState) {
	if target == nil {
		return
	}
	terminalTargets := 0
	for _, candidate := range source.Targets {
		if candidate.Terminal {
			terminalTargets++
		}
	}
	target.Matched += max(source.Matched-len(source.Targets), 0)
	target.Terminal += max(source.Terminal-terminalTargets, 0)
	for _, candidate := range source.Targets {
		found := false
		for index := range target.Targets {
			if target.Targets[index].TaskID != candidate.TaskID {
				continue
			}
			found = true
			if target.Targets[index].ResponseMessageID == "" {
				target.Targets[index].ResponseMessageID = candidate.ResponseMessageID
			}
			if candidate.Terminal && !target.Targets[index].Terminal {
				target.Targets[index].Terminal = true
				target.Terminal++
			}
			break
		}
		if !found {
			target.Targets = append(target.Targets, candidate)
			target.Matched++
			if candidate.Terminal {
				target.Terminal++
			}
		}
	}
}

func chatGPTWebImageTaskIDsFound(known []string, targets []helps.ChatGPTWebImageTaskTarget) bool {
	if len(known) == 0 {
		return false
	}
	for _, taskID := range known {
		found := false
		for _, target := range targets {
			if strings.TrimSpace(target.TaskID) == strings.TrimSpace(taskID) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (e *ChatGPTWebExecutor) consumeChatGPTWebExactImageTaskStream(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, conversationID string, target helps.ChatGPTWebImageTaskTarget, budget *chatGPTWebPollResponseBudget) (_ *helps.ChatGPTWebImageAccumulator, err error) {
	conversationID = strings.TrimSpace(conversationID)
	taskID := strings.TrimSpace(target.TaskID)
	messageID := strings.TrimSpace(target.ResponseMessageID)
	if conversationID == "" || taskID == "" || messageID == "" {
		return nil, errors.New("chatgpt web exact image task stream identity is incomplete")
	}
	releasePoll, errPoll := acquireChatGPTWebImagePollSlot(ctx)
	if errPoll != nil {
		return nil, errPoll
	}
	defer releasePoll()
	finishTaskPoll := beginChatGPTWebImageTaskPoll(ctx)
	defer func() {
		canceled := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		if ctx != nil && ctx.Err() != nil {
			canceled = true
		}
		finishTaskPoll(canceled)
		cliproxyexecutor.ObserveChatGPTWebImagePollCompletion(canceled)
	}()

	query := url.Values{}
	query.Set("parent_conversation_id", conversationID)
	query.Set("message_id", messageID)
	path := "/backend-api/tasks/" + url.PathEscape(taskID) + "/stream?" + query.Encode()
	safePath := "/backend-api/tasks/{task_id}/stream"
	headers := e.chatGPTWebHeaders(credential, safePath, map[string]string{"accept": "text/event-stream"})
	e.recordChatGPTWebRequest(ctx, credential, http.MethodGet, safePath, headers, nil)
	chatGPTWebImageProtocolMetrics.exactStreamsStarted.Add(1)
	started := time.Now()
	response, errRequest := client.DoPollNoRedirectStream(ctx, http.MethodGet, e.chatGPTWebBaseURL()+path, headers, nil)
	if errRequest != nil {
		cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhasePollRequest, started)
		helps.RecordAPIResponseError(ctx, e.configSnapshot(), errRequest)
		return nil, chatGPTWebTransportDiagnosticError(errRequest, safePath)
	}
	defer func() { _ = response.Body.Close() }()
	helps.RecordAPIResponseMetadata(ctx, e.configSnapshot(), response.StatusCode, chatGPTWebResponseLogHeaders(response.Header))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		payload, releaseMemory, errRead := readChatGPTWebPollResponseBody(ctx, response, chatGPTWebMaxErrorBodyBytes)
		cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhasePollRequest, started)
		if releaseMemory != nil {
			defer releaseMemory()
		}
		if errRead != nil {
			return nil, errRead
		}
		if errBudget := budget.consume(len(payload)); errBudget != nil {
			return nil, errBudget
		}
		if challengeErr := newChatGPTWebChallengeResponseError(response.StatusCode, safePath, payload, response.Header); challengeErr != nil {
			return nil, challengeErr
		}
		return nil, newChatGPTWebStatusError(response.StatusCode, safePath, payload, response.Header)
	}
	contentType := strings.TrimSpace(response.Header.Get("Content-Type"))
	if parsed, _, errParse := mime.ParseMediaType(contentType); errParse == nil {
		contentType = parsed
	}
	if !strings.EqualFold(contentType, "text/event-stream") {
		cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhasePollRequest, started)
		return nil, errors.New("chatgpt web exact image task stream did not return SSE")
	}

	accumulator := &helps.ChatGPTWebImageAccumulator{
		ConversationID: conversationID,
		Turn:           helps.ChatGPTWebImageTurn{MessageID: messageID},
		TaskIDs:        []string{taskID},
	}
	streamReader := &chatGPTWebImageBudgetReader{reader: response.Body, budget: budget}
	errStream := consumeChatGPTWebImageStreamWithLimits(ctx, streamReader, accumulator, chatGPTWebImageStreamMaxBytes, chatGPTWebImageStreamMaxEvents)
	observeChatGPTWebImageProtocolAccumulator(accumulator)
	cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhasePollRequest, started)
	helps.AppendAPIResponseChunk(ctx, e.configSnapshot(), []byte("<chatgpt web exact task stream body omitted>"))
	if errors.Is(errStream, errChatGPTWebImageIncompleteStream) && (accumulator.Terminal || accumulator.StreamTerminal || accumulator.FailureStatus != "") {
		errStream = nil
	}
	if errStream != nil {
		return accumulator, errStream
	}
	if !accumulator.Terminal && !accumulator.StreamTerminal && accumulator.FailureStatus == "" {
		return accumulator, errors.New("chatgpt web exact image task stream ended without a terminal event")
	}
	chatGPTWebImageProtocolMetrics.exactStreamsCompleted.Add(1)
	return accumulator, nil
}

type chatGPTWebImageBudgetReader struct {
	reader io.Reader
	budget *chatGPTWebPollResponseBudget
}

func (reader *chatGPTWebImageBudgetReader) Read(buffer []byte) (int, error) {
	if reader == nil || reader.reader == nil {
		return 0, io.EOF
	}
	count, errRead := reader.reader.Read(buffer)
	if count > 0 {
		if errBudget := reader.budget.consume(count); errBudget != nil {
			return 0, errBudget
		}
	}
	return count, errRead
}

func (e *ChatGPTWebExecutor) startChatGPTWebImageConversationPoll(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, conversationID string, budget *chatGPTWebPollResponseBudget) <-chan chatGPTWebImageConversationPollResult {
	return e.startChatGPTWebImageConversationPollForTurn(ctx, client, credential, conversationID, helps.ChatGPTWebImageTurn{}, budget)
}

func (e *ChatGPTWebExecutor) startChatGPTWebImageConversationPollForTurn(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, conversationID string, turn helps.ChatGPTWebImageTurn, budget *chatGPTWebPollResponseBudget) <-chan chatGPTWebImageConversationPollResult {
	result := make(chan chatGPTWebImageConversationPollResult, 1)
	go func() {
		defer close(result)
		pollResult := chatGPTWebImageConversationPollResult{
			accumulator: &helps.ChatGPTWebImageAccumulator{ConversationID: conversationID, Turn: turn},
		}
		path := "/backend-api/conversation/" + url.PathEscape(conversationID)
		_, payload, releaseMemory, err := e.doChatGPTWebPollGET(ctx, client, credential, path, nil, budget)
		if releaseMemory != nil {
			defer releaseMemory()
		}
		if err != nil {
			pollResult.err = err
		} else {
			pollResult.err = helps.CaptureChatGPTWebImageConversation(payload, pollResult.accumulator)
			pollResult.protocolError = pollResult.err != nil
			observeChatGPTWebImageProtocolAccumulator(pollResult.accumulator)
			if ctx != nil {
				if registry, _ := ctx.Value(chatGPTWebImageExactStreamContextKey{}).(*chatGPTWebImageExactStreamRegistry); registry != nil {
					registry.observe(pollResult.accumulator.TaskIDs...)
				}
			}
		}
		select {
		case result <- pollResult:
		case <-ctx.Done():
		}
	}()
	return result
}

func chatGPTWebNextImagePollAt(now time.Time, times ...time.Time) (time.Time, bool) {
	var next time.Time
	for _, candidate := range times {
		if candidate.IsZero() || !candidate.After(now) {
			continue
		}
		if next.IsZero() || candidate.Before(next) {
			next = candidate
		}
	}
	return next, !next.IsZero()
}

func (body *chatGPTWebImageWatchBody) Read(buffer []byte) (int, error) {
	count, err := body.ReadCloser.Read(buffer)
	if err != nil && body.closedByWatcher.Load() {
		return count, fmt.Errorf("%w: %v", errChatGPTWebImageStreamClosedByWatcher, err)
	}
	return count, err
}

func (body *chatGPTWebImageWatchBody) closeByWatcher() error {
	body.closedByWatcher.Store(true)
	return body.ReadCloser.Close()
}

// chatGPTWebImageTaskPollContext keeps cancellation and deadlines without
// attaching concurrent image-poll responses to the primary upstream request log.
type chatGPTWebImageTaskPollContext struct {
	context.Context
}

func (chatGPTWebImageTaskPollContext) Value(any) any { return nil }

func newChatGPTWebImageTaskPollContext(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	taskHandle := chatGPTWebImageTaskHandleFromContext(ctx)
	base := context.Context(chatGPTWebImageTaskPollContext{Context: ctx})
	base = cliproxyexecutor.WithRequestPhaseObserver(base, cliproxyexecutor.RequestPhaseObserverFromContext(ctx))
	base = helps.WithChatGPTWebImageMemoryLeaseSet(base, helps.ChatGPTWebImageMemoryLeaseSetFromContext(ctx))
	base = withChatGPTWebImageTaskHandle(base, taskHandle)
	if registry, _ := ctx.Value(chatGPTWebImageExactStreamContextKey{}).(*chatGPTWebImageExactStreamRegistry); registry != nil {
		base = context.WithValue(base, chatGPTWebImageExactStreamContextKey{}, registry)
	}
	return base
}

func (e *ChatGPTWebExecutor) consumeChatGPTWebImageStreamWithTaskPolling(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, response *fhttp.Response, budgets ...*chatGPTWebPollResponseBudget) (*helps.ChatGPTWebImageAccumulator, error) {
	return e.consumeChatGPTWebImageStreamWithTaskPollingForTurn(ctx, client, credential, response, helps.ChatGPTWebImageTurn{}, budgets...)
}

func (e *ChatGPTWebExecutor) consumeChatGPTWebImageStreamWithTaskPollingForTurn(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, response *fhttp.Response, turn helps.ChatGPTWebImageTurn, budgets ...*chatGPTWebPollResponseBudget) (*helps.ChatGPTWebImageAccumulator, error) {
	ctx, exactStreams := withChatGPTWebImageExactStreamRegistry(ctx)
	accumulator := &helps.ChatGPTWebImageAccumulator{Turn: turn}
	streamBody := &chatGPTWebImageWatchBody{ReadCloser: response.Body}
	stopContextRead := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = streamBody.Close()
		case <-stopContextRead:
		}
	}()
	defer close(stopContextRead)
	watchCtx, cancelWatch := context.WithCancel(newChatGPTWebImageTaskPollContext(ctx))
	defer cancelWatch()
	result := make(chan chatGPTWebImageTaskWatchResult, 1)
	watchDone := make(chan struct{})
	watchProgress := make(chan struct{}, 1)
	var lastStreamProgress atomic.Int64
	pollBudget := chatGPTWebSharedPollResponseBudget(budgets)
	watchStarted := false
	onProgress := func() {
		exactStreams.observePrimary(accumulator.TaskIDs)
		conversationID := strings.TrimSpace(accumulator.ConversationID)
		if conversationID == "" {
			return
		}
		wasStarted := watchStarted
		if !wasStarted {
			watchStarted = true
			go func() {
				defer close(watchDone)
				e.watchChatGPTWebImageTasks(watchCtx, client, credential, conversationID, turn, streamBody, result, watchProgress, &lastStreamProgress, pollBudget)
			}()
		}
		if wasStarted {
			lastStreamProgress.Store(time.Now().UnixNano())
		}
		select {
		case watchProgress <- struct{}{}:
		default:
		}
	}
	errStream := consumeChatGPTWebImageStreamWithLimitsAndProgress(
		ctx,
		streamBody,
		accumulator,
		chatGPTWebImageStreamMaxBytes,
		chatGPTWebImageStreamMaxEvents,
		onProgress,
	)
	observeChatGPTWebImageProtocolAccumulator(accumulator)
	exactStreams.observePrimary(accumulator.TaskIDs)
	cancelWatch()
	if watchStarted {
		<-watchDone
	}
	if err := ctx.Err(); err != nil {
		return accumulator, err
	}
	if challengeErr := chatGPTWebStreamChallengeError(response); challengeErr != nil {
		return accumulator, challengeErr
	}
	if errStream != nil && !errors.Is(errStream, errChatGPTWebImageStreamClosedByWatcher) {
		return accumulator, errStream
	}
	select {
	case taskResult := <-result:
		if taskResult.err != nil {
			return accumulator, taskResult.err
		}
		if taskResult.accumulator != nil {
			merged, errMerge := helps.MergeChatGPTWebImageAccumulators(taskResult.accumulator, accumulator)
			if errMerge != nil {
				return accumulator, errMerge
			}
			return merged, nil
		}
	default:
	}
	return accumulator, errStream
}

func (e *ChatGPTWebExecutor) watchChatGPTWebImageTasks(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, conversationID string, turn helps.ChatGPTWebImageTurn, streamBody *chatGPTWebImageWatchBody, result chan<- chatGPTWebImageTaskWatchResult, progress <-chan struct{}, lastStreamProgress *atomic.Int64, pollBudget *chatGPTWebPollResponseBudget) {
	ctx, exactStreams := withChatGPTWebImageExactStreamRegistry(ctx)
	if err := waitForChatGPTWebImageIdle(ctx, e.imageInitialWait, progress); err != nil {
		return
	}
	pollBudget = chatGPTWebSharedPollResponseBudget([]*chatGPTWebPollResponseBudget{pollBudget})
	tasksEnabled := true
	conversationEnabled := true
	pollContext, cancelPolls := context.WithCancel(newChatGPTWebImageTaskPollContext(ctx))
	var taskPoll <-chan chatGPTWebImageTaskPollResult
	var conversationPoll <-chan chatGPTWebImageConversationPollResult
	defer func() {
		cancelPolls()
		if taskPoll != nil {
			<-taskPoll
		}
		if conversationPoll != nil {
			<-conversationPoll
		}
	}()
	var taskSnapshot *helps.ChatGPTWebImageAccumulator
	var conversationSnapshot *helps.ChatGPTWebImageAccumulator
	taskState := helps.ChatGPTWebImageTaskState{}
	conversationTerminal := false
	lastTaskFailure := ""
	nextTaskPollAt := time.Time{}
	nextConversationPollAt := time.Time{}
	maxPolls := e.imageMaxPolls
	if maxPolls <= 0 {
		maxPolls = chatGPTWebImageMaxPollAttempts
	}
	taskPolls := 0
	conversationPolls := 0
	lastTaskTerminalSignature := ""
	stableTaskSnapshots := 0
	taskFallbackAt := time.Time{}
	taskFallbackNeedsConversationRefresh := false
	taskFallbackConversationRefreshed := false
	lastConversationTerminalSignature := ""
	stableConversationTerminalSnapshots := 0
	conversationSettleAt := time.Time{}
	streamProgressSettleAt := func() time.Time {
		if lastStreamProgress == nil {
			return time.Time{}
		}
		progressAt := lastStreamProgress.Load()
		if progressAt <= 0 {
			return time.Time{}
		}
		return time.Unix(0, progressAt).Add(e.imageSettleWait)
	}
	streamProgressSettled := func(now time.Time) bool {
		settleAt := streamProgressSettleAt()
		return settleAt.IsZero() || !now.Before(settleAt)
	}
	conversationSettled := func(now time.Time) bool {
		if !conversationTerminal || stableConversationTerminalSnapshots < 2 ||
			(!conversationSettleAt.IsZero() && now.Before(conversationSettleAt)) {
			return false
		}
		return streamProgressSettled(now)
	}

	buildCandidate := func() *helps.ChatGPTWebImageAccumulator {
		candidate := &helps.ChatGPTWebImageAccumulator{ConversationID: conversationID, Turn: turn}
		if taskSnapshot != nil {
			if merged, errMerge := helps.MergeChatGPTWebImageAccumulators(candidate, taskSnapshot); errMerge == nil {
				candidate = merged
			} else {
				tasksEnabled = false
				taskSnapshot = nil
				taskState = helps.ChatGPTWebImageTaskState{}
			}
		}
		if conversationSnapshot != nil {
			if merged, errMerge := helps.MergeChatGPTWebImageAccumulators(candidate, conversationSnapshot); errMerge == nil {
				candidate = merged
			} else {
				conversationEnabled = false
				conversationSnapshot = nil
				conversationTerminal = false
				conversationSettleAt = time.Time{}
			}
		}
		return candidate
	}

	for {
		now := time.Now()
		if !taskFallbackAt.IsZero() && !now.Before(taskFallbackAt) {
			if streamSettleAt := streamProgressSettleAt(); !streamSettleAt.IsZero() && now.Before(streamSettleAt) {
				taskFallbackAt = streamSettleAt
			} else {
				canRefreshConversation := !taskFallbackConversationRefreshed && conversationEnabled && conversationPoll == nil && conversationPolls < maxPolls
				if canRefreshConversation {
					taskFallbackAt = time.Time{}
					taskFallbackNeedsConversationRefresh = true
					if conversationPoll == nil {
						nextConversationPollAt = time.Time{}
					}
				} else {
					candidate := buildCandidate()
					taskStable := taskState.AllTerminal() && stableTaskSnapshots >= 2 && streamProgressSettled(now)
					outputCount := chatGPTWebImageOutputCount(candidate)
					if taskStable && (outputCount > 0 || lastTaskFailure != "") &&
						!chatGPTWebImageHasUniqueReferences(conversationSnapshot, taskSnapshot) {
						if outputCount == 0 {
							candidate.FailureStatus = lastTaskFailure
						}
						candidate.Terminal = true
						e.publishChatGPTWebImageTaskWatchResult(ctx, streamBody, result, chatGPTWebImageTaskWatchResult{accumulator: candidate})
						return
					}
					taskFallbackAt = time.Time{}
					taskFallbackConversationRefreshed = false
				}
			}
		}
		if tasksEnabled && taskPoll == nil && taskPolls < maxPolls && !now.Before(nextTaskPollAt) {
			seed := exactStreams.seed(taskSnapshot)
			if len(seed.TaskIDs) == 0 && conversationSnapshot != nil {
				seed.TaskIDs = append([]string(nil), conversationSnapshot.TaskIDs...)
			}
			seed.ConversationID = conversationID
			seed.Turn = turn
			taskPoll = e.startChatGPTWebImageTaskPollForAccumulator(pollContext, client, credential, seed, pollBudget, exactStreams)
			taskPolls++
		}
		if conversationEnabled && conversationPoll == nil && conversationPolls < maxPolls && !now.Before(nextConversationPollAt) {
			conversationPoll = e.startChatGPTWebImageConversationPollForTurn(pollContext, client, credential, conversationID, turn, pollBudget)
			conversationPolls++
		}

		tasksExhausted := !tasksEnabled || (taskPoll == nil && taskPolls >= maxPolls)
		conversationExhausted := !conversationEnabled || (conversationPoll == nil && conversationPolls >= maxPolls)
		if tasksExhausted && conversationExhausted {
			candidate := buildCandidate()
			conversationStable := conversationSettled(now)
			taskStable := taskState.AllTerminal() && stableTaskSnapshots >= 2 && streamProgressSettled(now)
			if (conversationStable || taskStable) && (chatGPTWebImageOutputCount(candidate) > 0 || lastTaskFailure != "") {
				if chatGPTWebImageOutputCount(candidate) == 0 {
					candidate.FailureStatus = lastTaskFailure
				}
				candidate.Terminal = true
				e.publishChatGPTWebImageTaskWatchResult(ctx, streamBody, result, chatGPTWebImageTaskWatchResult{accumulator: candidate})
			}
			return
		}

		var timer *time.Timer
		var timerChannel <-chan time.Time
		var pendingTimes []time.Time
		if tasksEnabled && taskPoll == nil && taskPolls < maxPolls {
			pendingTimes = append(pendingTimes, nextTaskPollAt)
		}
		if conversationEnabled && conversationPoll == nil && conversationPolls < maxPolls {
			pendingTimes = append(pendingTimes, nextConversationPollAt)
		}
		if !taskFallbackAt.IsZero() {
			pendingTimes = append(pendingTimes, taskFallbackAt)
		}
		if next, ok := chatGPTWebNextImagePollAt(now, pendingTimes...); ok {
			timer = time.NewTimer(time.Until(next))
			timerChannel = timer.C
		}

		var taskResult chatGPTWebImageTaskPollResult
		var conversationResult chatGPTWebImageConversationPollResult
		var taskReady bool
		var conversationReady bool
		var timerFired bool
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-timerChannel:
			timerFired = true
		case value, ok := <-taskPoll:
			if ok {
				taskResult = value
				taskReady = true
			}
			taskPoll = nil
		case value, ok := <-conversationPoll:
			if ok {
				conversationResult = value
				conversationReady = true
			}
			conversationPoll = nil
		}
		if timer != nil {
			timer.Stop()
		}
		if timerFired {
			continue
		}
		if taskReady && conversationPoll != nil {
			select {
			case value, ok := <-conversationPoll:
				conversationPoll = nil
				if ok {
					conversationResult = value
					conversationReady = true
				}
			default:
			}
		}
		if conversationReady && taskPoll != nil {
			select {
			case value, ok := <-taskPoll:
				taskPoll = nil
				if ok {
					taskResult = value
					taskReady = true
				}
			default:
			}
		}
		now = time.Now()

		if taskReady {
			var memoryErr *chatGPTWebImageMemoryCapacityError
			if errors.As(taskResult.err, &memoryErr) {
				e.publishChatGPTWebImageTaskWatchResult(ctx, streamBody, result, chatGPTWebImageTaskWatchResult{err: taskResult.err})
				return
			}
			var limitErr *helps.ChatGPTWebResponseLimitError
			if errors.As(taskResult.err, &limitErr) {
				// The primary SSE remains authoritative while it is healthy. If it
				// later ends incomplete, the synchronous fallback will surface the
				// exhausted shared polling budget.
				return
			}
			if chatGPTWebImagePollAuthenticationError(taskResult.err) {
				e.publishChatGPTWebImageTaskWatchResult(ctx, streamBody, result, chatGPTWebImageTaskWatchResult{err: taskResult.err})
				return
			}
			if taskResult.err == nil {
				taskSnapshot = taskResult.accumulator
				taskState = taskResult.state
				nextTaskPollAt = now.Add(e.imagePollInterval)
				outputCount := chatGPTWebImageOutputCount(taskSnapshot)
				if taskState.AllTerminal() && outputCount == 0 && taskSnapshot.FailureStatus != "" {
					lastTaskFailure = taskSnapshot.FailureStatus
				} else if taskState.AllTerminal() && outputCount > 0 {
					lastTaskFailure = ""
				}
				taskSnapshot.FailureStatus = ""
				if taskState.AllTerminal() && (outputCount > 0 || lastTaskFailure != "") {
					signature := "failure:" + lastTaskFailure
					if outputCount > 0 {
						signature = "output:" + chatGPTWebImageReferenceSignature(taskSnapshot)
					}
					if signature == lastTaskTerminalSignature {
						stableTaskSnapshots++
					} else {
						lastTaskTerminalSignature = signature
						stableTaskSnapshots = 0
						taskFallbackAt = time.Time{}
						taskFallbackNeedsConversationRefresh = false
						taskFallbackConversationRefreshed = false
					}
				} else {
					lastTaskTerminalSignature = ""
					stableTaskSnapshots = 0
					taskFallbackAt = time.Time{}
					taskFallbackNeedsConversationRefresh = false
					taskFallbackConversationRefreshed = false
				}
			} else if taskResult.protocolError || chatGPTWebImageTaskQueryFatal(ctx, taskResult.err) {
				tasksEnabled = false
				taskSnapshot = nil
				taskState = helps.ChatGPTWebImageTaskState{}
				lastTaskTerminalSignature = ""
				stableTaskSnapshots = 0
				taskFallbackAt = time.Time{}
				taskFallbackNeedsConversationRefresh = false
				taskFallbackConversationRefreshed = false
			} else if delay, retryable := chatGPTWebPollRetryDelay(taskResult.err, e.imagePollInterval); retryable {
				taskSnapshot = nil
				taskState = helps.ChatGPTWebImageTaskState{}
				lastTaskTerminalSignature = ""
				stableTaskSnapshots = 0
				taskFallbackAt = time.Time{}
				taskFallbackNeedsConversationRefresh = false
				taskFallbackConversationRefreshed = false
				nextTaskPollAt = now.Add(delay)
			} else {
				tasksEnabled = false
				taskSnapshot = nil
				taskState = helps.ChatGPTWebImageTaskState{}
				lastTaskTerminalSignature = ""
				stableTaskSnapshots = 0
				taskFallbackAt = time.Time{}
				taskFallbackNeedsConversationRefresh = false
				taskFallbackConversationRefreshed = false
			}
		}

		if conversationReady {
			var memoryErr *chatGPTWebImageMemoryCapacityError
			if errors.As(conversationResult.err, &memoryErr) {
				e.publishChatGPTWebImageTaskWatchResult(ctx, streamBody, result, chatGPTWebImageTaskWatchResult{err: conversationResult.err})
				return
			}
			var limitErr *helps.ChatGPTWebResponseLimitError
			if errors.As(conversationResult.err, &limitErr) {
				// Do not replace a still-running primary SSE with an auxiliary
				// polling limit error.
				return
			}
			if chatGPTWebImagePollAuthenticationError(conversationResult.err) {
				e.publishChatGPTWebImageTaskWatchResult(ctx, streamBody, result, chatGPTWebImageTaskWatchResult{err: conversationResult.err})
				return
			}
			if conversationResult.err == nil {
				conversationSnapshot = conversationResult.accumulator
				conversationTerminal = conversationSnapshot.Terminal
				nextConversationPollAt = now.Add(e.imagePollInterval)
				if conversationTerminal {
					if failure := strings.TrimSpace(conversationSnapshot.FailureStatus); failure != "" {
						e.publishChatGPTWebImageTaskWatchResult(ctx, streamBody, result, chatGPTWebImageTaskWatchResult{
							err: chatGPTWebImageFailureError(failure),
						})
						return
					}
					signature := chatGPTWebImageReferenceSignature(conversationSnapshot)
					if signature == lastConversationTerminalSignature {
						stableConversationTerminalSnapshots++
					} else {
						lastConversationTerminalSignature = signature
						stableConversationTerminalSnapshots = 1
						conversationSettleAt = now.Add(e.imageSettleWait)
					}
					if conversationSettleAt.After(nextConversationPollAt) {
						nextConversationPollAt = conversationSettleAt
					}
					if lastStreamProgress != nil {
						progressAt := lastStreamProgress.Load()
						if progressAt > 0 {
							streamSettleAt := time.Unix(0, progressAt).Add(e.imageSettleWait)
							if streamSettleAt.After(nextConversationPollAt) {
								nextConversationPollAt = streamSettleAt
							}
						}
					}
				} else {
					lastConversationTerminalSignature = ""
					stableConversationTerminalSnapshots = 0
					conversationSettleAt = time.Time{}
				}
				if taskFallbackNeedsConversationRefresh {
					taskFallbackNeedsConversationRefresh = false
					taskFallbackConversationRefreshed = true
					taskFallbackAt = now
				}
			} else if conversationResult.protocolError {
				nextConversationPollAt = now.Add(e.imagePollInterval)
			} else if chatGPTWebImageTaskQueryFatal(ctx, conversationResult.err) {
				conversationEnabled = false
				if taskFallbackNeedsConversationRefresh {
					taskFallbackNeedsConversationRefresh = false
					taskFallbackConversationRefreshed = true
					taskFallbackAt = now
				}
			} else if delay, retryable := chatGPTWebPollRetryDelay(conversationResult.err, e.imagePollInterval); retryable {
				nextConversationPollAt = now.Add(delay)
			} else {
				conversationEnabled = false
				if taskFallbackNeedsConversationRefresh {
					taskFallbackNeedsConversationRefresh = false
					taskFallbackConversationRefreshed = true
					taskFallbackAt = now
				}
			}
		}

		candidate := buildCandidate()
		outputCount := chatGPTWebImageOutputCount(candidate)
		if conversationSettled(now) {
			if outputCount == 0 && candidate.FailureStatus == "" && lastTaskFailure != "" {
				candidate.FailureStatus = lastTaskFailure
			}
			candidate.Terminal = true
			e.publishChatGPTWebImageTaskWatchResult(ctx, streamBody, result, chatGPTWebImageTaskWatchResult{accumulator: candidate})
			return
		}
		if stableTaskSnapshots >= 2 && !taskFallbackNeedsConversationRefresh && taskFallbackAt.IsZero() {
			conversationStable := !conversationTerminal || conversationSettled(now)
			if conversationStable && !chatGPTWebImageHasUniqueReferences(conversationSnapshot, taskSnapshot) {
				taskFallbackConversationRefreshed = false
				taskFallbackAt = now.Add(e.imageSettleWait)
			}
		}
	}
}

func waitForChatGPTWebImageIdle(ctx context.Context, delay time.Duration, _ <-chan struct{}) error {
	return waitForChatGPTWebPoll(ctx, delay)
}

func (e *ChatGPTWebExecutor) publishChatGPTWebImageTaskWatchResult(ctx context.Context, streamBody *chatGPTWebImageWatchBody, result chan<- chatGPTWebImageTaskWatchResult, value chatGPTWebImageTaskWatchResult) {
	select {
	case <-ctx.Done():
		return
	default:
	}
	streamBody.closedByWatcher.Store(true)
	result <- value
	if err := streamBody.closeByWatcher(); err != nil {
		log.Debugf("chatgpt web executor: close completed image stream: %v", err)
	}
}

func (e *ChatGPTWebExecutor) pollChatGPTWebImageConversation(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, accumulator *helps.ChatGPTWebImageAccumulator, inputIDs map[string]struct{}, hasInitialOutput bool, budgets ...*chatGPTWebPollResponseBudget) error {
	ctx, exactStreams := withChatGPTWebImageExactStreamRegistry(ctx)
	if hasInitialOutput {
		if err := waitForChatGPTWebPoll(ctx, e.imageSettleWait); err != nil {
			return err
		}
	} else if err := waitForChatGPTWebPoll(ctx, e.imageInitialWait); err != nil {
		return err
	}
	maxPolls := e.imageMaxPolls
	if maxPolls <= 0 {
		maxPolls = chatGPTWebImageMaxPollAttempts
	}
	pollBudget := chatGPTWebSharedPollResponseBudget(budgets)
	tasksEnabled := true
	conversationEnabled := true
	pollContext, cancelPolls := context.WithCancel(newChatGPTWebImageTaskPollContext(ctx))
	var taskPoll <-chan chatGPTWebImageTaskPollResult
	var conversationPoll <-chan chatGPTWebImageConversationPollResult
	defer func() {
		cancelPolls()
		if taskPoll != nil {
			<-taskPoll
		}
		if conversationPoll != nil {
			<-conversationPoll
		}
	}()
	taskState := helps.ChatGPTWebImageTaskState{}
	taskStateKnown := false
	nextTaskPollAt := time.Time{}
	nextConversationPollAt := time.Time{}
	taskPolls := 0
	conversationPolls := 0
	lastTaskTerminalSignature := ""
	stableTaskSnapshots := 0
	taskFallbackAt := time.Time{}
	taskFallbackNeedsConversationRefresh := false
	taskFallbackConversationRefreshed := false
	lastStableSignature := chatGPTWebImageReferenceSignature(accumulator)
	stableSnapshots := 0
	lastTaskFailure := ""
	var lastConversationErr error
	conversationTerminal := false
	baseAccumulator, errClone := helps.MergeChatGPTWebImageAccumulators(nil, accumulator)
	if errClone != nil {
		return errClone
	}
	var taskSnapshot *helps.ChatGPTWebImageAccumulator
	var conversationSnapshot *helps.ChatGPTWebImageAccumulator
	rebuildAccumulator := func() error {
		merged, errMerge := helps.MergeChatGPTWebImageAccumulators(baseAccumulator, taskSnapshot)
		if errMerge != nil {
			return errMerge
		}
		merged, errMerge = helps.MergeChatGPTWebImageAccumulators(merged, conversationSnapshot)
		if errMerge != nil {
			return errMerge
		}
		*accumulator = *merged
		filterChatGPTWebInputImageIDs(accumulator, inputIDs)
		return nil
	}

	for {
		now := time.Now()
		if !taskFallbackAt.IsZero() && !now.Before(taskFallbackAt) {
			canRefreshConversation := !taskFallbackConversationRefreshed && conversationEnabled && conversationPoll == nil && conversationPolls < maxPolls
			if canRefreshConversation {
				taskFallbackAt = time.Time{}
				taskFallbackNeedsConversationRefresh = true
				if conversationPoll == nil {
					nextConversationPollAt = time.Time{}
				}
			} else {
				taskStable := taskStateKnown && taskState.AllTerminal() && stableTaskSnapshots >= 2
				outputCount := chatGPTWebImageOutputCount(accumulator)
				if taskStable && (outputCount > 0 || lastTaskFailure != "") &&
					!chatGPTWebImageHasUniqueReferences(conversationSnapshot, taskSnapshot) {
					if outputCount == 0 {
						return chatGPTWebImageFailureError(lastTaskFailure)
					}
					accumulator.Terminal = true
					return nil
				}
				taskFallbackAt = time.Time{}
				taskFallbackConversationRefreshed = false
			}
		}
		if tasksEnabled && taskPoll == nil && taskPolls < maxPolls && !now.Before(nextTaskPollAt) {
			taskPoll = e.startChatGPTWebImageTaskPollForAccumulator(pollContext, client, credential, chatGPTWebImageTaskSeed(accumulator), pollBudget, exactStreams)
			taskPolls++
		}
		if conversationEnabled && conversationPoll == nil && conversationPolls < maxPolls && !now.Before(nextConversationPollAt) {
			conversationPoll = e.startChatGPTWebImageConversationPollForTurn(pollContext, client, credential, accumulator.ConversationID, accumulator.Turn, pollBudget)
			conversationPolls++
		}

		tasksExhausted := !tasksEnabled || (taskPoll == nil && taskPolls >= maxPolls)
		conversationExhausted := !conversationEnabled || (conversationPoll == nil && conversationPolls >= maxPolls)
		if tasksExhausted && conversationExhausted {
			outputCount := chatGPTWebImageOutputCount(accumulator)
			taskStable := taskStateKnown && taskState.AllTerminal() && stableTaskSnapshots >= 2
			if outputCount > 0 && (conversationTerminal || taskStable) {
				accumulator.Terminal = true
				return nil
			}
			if taskStable && lastTaskFailure != "" {
				return chatGPTWebImageFailureError(lastTaskFailure)
			}
			if lastConversationErr != nil {
				return lastConversationErr
			}
			if lastTaskFailure != "" {
				return chatGPTWebImageFailureError(lastTaskFailure)
			}
			break
		}

		var timer *time.Timer
		var timerChannel <-chan time.Time
		var pendingTimes []time.Time
		if tasksEnabled && taskPoll == nil && taskPolls < maxPolls {
			pendingTimes = append(pendingTimes, nextTaskPollAt)
		}
		if conversationEnabled && conversationPoll == nil && conversationPolls < maxPolls {
			pendingTimes = append(pendingTimes, nextConversationPollAt)
		}
		if !taskFallbackAt.IsZero() {
			pendingTimes = append(pendingTimes, taskFallbackAt)
		}
		if next, ok := chatGPTWebNextImagePollAt(now, pendingTimes...); ok {
			timer = time.NewTimer(time.Until(next))
			timerChannel = timer.C
		}

		var taskResult chatGPTWebImageTaskPollResult
		var conversationResult chatGPTWebImageConversationPollResult
		var taskReady bool
		var conversationReady bool
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return ctx.Err()
		case <-timerChannel:
			// A delayed endpoint is ready to be started on the next pass.
		case value, ok := <-taskPoll:
			if ok {
				taskResult = value
				taskReady = true
			}
			taskPoll = nil
		case value, ok := <-conversationPoll:
			if ok {
				conversationResult = value
				conversationReady = true
			}
			conversationPoll = nil
		}
		if timer != nil {
			timer.Stop()
		}
		if taskReady && conversationPoll != nil {
			select {
			case value, ok := <-conversationPoll:
				conversationPoll = nil
				if ok {
					conversationResult = value
					conversationReady = true
				}
			default:
			}
		}
		if conversationReady && taskPoll != nil {
			select {
			case value, ok := <-taskPoll:
				taskPoll = nil
				if ok {
					taskResult = value
					taskReady = true
				}
			default:
			}
		}
		now = time.Now()

		if taskReady {
			var memoryErr *chatGPTWebImageMemoryCapacityError
			if errors.As(taskResult.err, &memoryErr) {
				return taskResult.err
			}
			var limitErr *helps.ChatGPTWebResponseLimitError
			if errors.As(taskResult.err, &limitErr) {
				return taskResult.err
			}
			if chatGPTWebImagePollAuthenticationError(taskResult.err) {
				return taskResult.err
			}
			if taskResult.err == nil {
				taskState = taskResult.state
				taskStateKnown = true
				nextTaskPollAt = now.Add(e.imagePollInterval)
				taskSnapshot = taskResult.accumulator
				if errRebuild := rebuildAccumulator(); errRebuild != nil {
					return errRebuild
				}
				taskOutputCount := chatGPTWebImageOutputCount(taskResult.accumulator)
				if taskResult.accumulator.FailureStatus != "" && taskState.AllTerminal() && taskOutputCount == 0 {
					lastTaskFailure = taskResult.accumulator.FailureStatus
				} else if taskState.AllTerminal() && taskOutputCount > 0 {
					lastTaskFailure = ""
				}
				taskSnapshot.FailureStatus = ""
				if taskState.AllTerminal() && (taskOutputCount > 0 || lastTaskFailure != "") {
					taskSignature := "failure:" + lastTaskFailure
					if taskOutputCount > 0 {
						taskSignature = "output:" + chatGPTWebImageReferenceSignature(taskResult.accumulator)
					}
					if taskSignature == lastTaskTerminalSignature {
						stableTaskSnapshots++
					} else {
						lastTaskTerminalSignature = taskSignature
						stableTaskSnapshots = 0
						taskFallbackAt = time.Time{}
						taskFallbackNeedsConversationRefresh = false
						taskFallbackConversationRefreshed = false
					}
				} else {
					lastTaskTerminalSignature = ""
					stableTaskSnapshots = 0
					taskFallbackAt = time.Time{}
					taskFallbackNeedsConversationRefresh = false
					taskFallbackConversationRefreshed = false
				}
			} else if taskResult.protocolError || chatGPTWebImageTaskQueryFatal(ctx, taskResult.err) {
				tasksEnabled = false
				taskSnapshot = nil
				if errRebuild := rebuildAccumulator(); errRebuild != nil {
					return errRebuild
				}
				taskState = helps.ChatGPTWebImageTaskState{}
				taskStateKnown = false
				lastTaskTerminalSignature = ""
				stableTaskSnapshots = 0
				taskFallbackAt = time.Time{}
				taskFallbackNeedsConversationRefresh = false
				taskFallbackConversationRefreshed = false
			} else if delay, retryable := chatGPTWebPollRetryDelay(taskResult.err, e.imagePollInterval); retryable {
				taskSnapshot = nil
				if errRebuild := rebuildAccumulator(); errRebuild != nil {
					return errRebuild
				}
				taskState = helps.ChatGPTWebImageTaskState{}
				taskStateKnown = false
				lastTaskTerminalSignature = ""
				stableTaskSnapshots = 0
				taskFallbackAt = time.Time{}
				taskFallbackNeedsConversationRefresh = false
				taskFallbackConversationRefreshed = false
				nextTaskPollAt = now.Add(delay)
			} else {
				tasksEnabled = false
				taskSnapshot = nil
				if errRebuild := rebuildAccumulator(); errRebuild != nil {
					return errRebuild
				}
				taskState = helps.ChatGPTWebImageTaskState{}
				taskStateKnown = false
				lastTaskTerminalSignature = ""
				stableTaskSnapshots = 0
				taskFallbackAt = time.Time{}
				taskFallbackNeedsConversationRefresh = false
				taskFallbackConversationRefreshed = false
			}
		}

		if conversationReady {
			var memoryErr *chatGPTWebImageMemoryCapacityError
			if errors.As(conversationResult.err, &memoryErr) {
				return conversationResult.err
			}
			if chatGPTWebImagePollAuthenticationError(conversationResult.err) {
				return conversationResult.err
			}
			if conversationResult.err == nil {
				lastConversationErr = nil
				conversationAccumulator := conversationResult.accumulator
				conversationTerminal = conversationAccumulator.Terminal
				conversationFailure := conversationAccumulator.FailureStatus
				conversationSnapshot = conversationAccumulator
				if errRebuild := rebuildAccumulator(); errRebuild != nil {
					return errRebuild
				}
				conversationOutputCount := chatGPTWebImageOutputCount(conversationAccumulator)
				outputCount := chatGPTWebImageOutputCount(accumulator)
				if conversationFailure != "" && conversationTerminal {
					return chatGPTWebImageFailureError(conversationFailure)
				}
				if outputCount > 0 {
					if taskStateKnown && taskState.HasPending() && !conversationTerminal {
						lastStableSignature = ""
						stableSnapshots = 0
					} else {
						signature := chatGPTWebImageReferenceSignature(accumulator)
						if signature != "" && signature == lastStableSignature {
							stableSnapshots++
						} else {
							lastStableSignature = signature
							stableSnapshots = 0
						}
					}
					if conversationTerminal && stableSnapshots >= 1 {
						return nil
					}
					if len(accumulator.SedimentIDs) > 0 && (!taskStateKnown || !taskState.HasPending()) && stableSnapshots >= 1 {
						return nil
					}
					delay := e.imagePollInterval
					if conversationOutputCount > 0 && e.imageSettleWait > delay {
						delay = e.imageSettleWait
					}
					nextConversationPollAt = now.Add(delay)
				} else {
					nextConversationPollAt = now.Add(e.imagePollInterval)
					if conversationTerminal && (!taskStateKnown || !taskState.HasPending()) {
						if lastTaskFailure != "" {
							return chatGPTWebImageFailureError(lastTaskFailure)
						}
						return newChatGPTWebImageNoOutputResultError()
					}
				}
				if taskFallbackNeedsConversationRefresh {
					taskFallbackNeedsConversationRefresh = false
					taskFallbackConversationRefreshed = true
					taskFallbackAt = now
				}
			} else {
				lastConversationErr = conversationResult.err
				var limitErr *helps.ChatGPTWebResponseLimitError
				if errors.As(conversationResult.err, &limitErr) {
					return conversationResult.err
				}
				if conversationResult.protocolError {
					nextConversationPollAt = now.Add(e.imagePollInterval)
				} else if chatGPTWebImageTaskQueryFatal(ctx, conversationResult.err) {
					conversationEnabled = false
					if taskFallbackNeedsConversationRefresh {
						taskFallbackNeedsConversationRefresh = false
						taskFallbackConversationRefreshed = true
						taskFallbackAt = now
					}
				} else if delay, retryable := chatGPTWebPollRetryDelay(conversationResult.err, e.imagePollInterval); retryable {
					nextConversationPollAt = now.Add(delay)
				} else {
					conversationEnabled = false
					if taskFallbackNeedsConversationRefresh {
						taskFallbackNeedsConversationRefresh = false
						taskFallbackConversationRefreshed = true
						taskFallbackAt = now
					}
				}
			}
		}

		conversationStable := !conversationTerminal || stableSnapshots >= 1
		if stableTaskSnapshots >= 2 && conversationStable && !taskFallbackNeedsConversationRefresh &&
			!chatGPTWebImageHasUniqueReferences(conversationSnapshot, taskSnapshot) && taskFallbackAt.IsZero() {
			taskFallbackConversationRefreshed = false
			taskFallbackAt = now.Add(e.imageSettleWait)
		}
	}
	chatGPTWebImageProtocolMetrics.allSourcesExhaustedWithoutOutput.Add(1)
	return newChatGPTWebImageSettleStatusError(
		chatGPTWebImageErrorPollUnsettled,
		fmt.Sprintf("chatgpt web image generation remained incomplete after %d polls", maxPolls),
	)
}

func chatGPTWebImageOutputCount(accumulator *helps.ChatGPTWebImageAccumulator) int {
	if accumulator == nil {
		return 0
	}
	if len(accumulator.References) > 0 {
		count := 0
		for _, reference := range accumulator.References {
			if reference.Kind == "file" && reference.ID == "file_upload" {
				continue
			}
			count++
		}
		return count
	}
	count := len(accumulator.SedimentIDs)
	for _, fileID := range accumulator.FileIDs {
		if fileID != "file_upload" {
			count++
		}
	}
	return count
}

func chatGPTWebImageReferenceSignature(accumulator *helps.ChatGPTWebImageAccumulator) string {
	if accumulator == nil {
		return ""
	}
	var signature strings.Builder
	appendReference := func(kind, id string) {
		if kind == "file" && id == "file_upload" {
			return
		}
		signature.WriteString(kind)
		signature.WriteByte(':')
		signature.WriteString(id)
		signature.WriteByte('\n')
	}
	if len(accumulator.References) > 0 {
		for _, reference := range accumulator.References {
			appendReference(reference.Kind, reference.ID)
		}
		return signature.String()
	}
	for _, fileID := range accumulator.FileIDs {
		appendReference("file", fileID)
	}
	for _, sedimentID := range accumulator.SedimentIDs {
		appendReference("sediment", sedimentID)
	}
	return signature.String()
}

func chatGPTWebImageHasUniqueReferences(accumulator, baseline *helps.ChatGPTWebImageAccumulator) bool {
	if chatGPTWebImageOutputCount(accumulator) == 0 {
		return false
	}
	baselineReferences := make(map[string]struct{}, chatGPTWebImageOutputCount(baseline))
	visitChatGPTWebImageReferences(baseline, func(kind, id string) bool {
		baselineReferences[kind+"\x00"+id] = struct{}{}
		return true
	})
	hasUnique := false
	visitChatGPTWebImageReferences(accumulator, func(kind, id string) bool {
		_, exists := baselineReferences[kind+"\x00"+id]
		hasUnique = !exists
		return exists
	})
	return hasUnique
}

func visitChatGPTWebImageReferences(accumulator *helps.ChatGPTWebImageAccumulator, visit func(kind, id string) bool) {
	if accumulator == nil || visit == nil {
		return
	}
	visitReference := func(kind, id string) bool {
		if kind == "file" && id == "file_upload" {
			return true
		}
		return visit(kind, id)
	}
	if len(accumulator.References) > 0 {
		for _, reference := range accumulator.References {
			if !visitReference(reference.Kind, reference.ID) {
				return
			}
		}
		return
	}
	for _, fileID := range accumulator.FileIDs {
		if !visitReference("file", fileID) {
			return
		}
	}
	for _, sedimentID := range accumulator.SedimentIDs {
		if !visitReference("sediment", sedimentID) {
			return
		}
	}
}

func chatGPTWebImageTaskQueryFatal(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return true
	}
	var memoryErr *chatGPTWebImageMemoryCapacityError
	if errors.As(err, &memoryErr) {
		return true
	}
	var limitErr *helps.ChatGPTWebResponseLimitError
	if errors.As(err, &limitErr) {
		return true
	}
	statusCode := statusCodeFromError(err)
	return statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden
}

func chatGPTWebImagePollAuthenticationError(err error) bool {
	statusCode := statusCodeFromError(err)
	if statusCode == http.StatusUnauthorized {
		return true
	}
	if statusCode != http.StatusForbidden {
		return false
	}
	return chatGPTWebLifecycleError(err) != nil
}

func chatGPTWebPollRetryDelay(err error, fallback time.Duration) (time.Duration, bool) {
	var memoryErr *chatGPTWebImageMemoryCapacityError
	if errors.As(err, &memoryErr) {
		return 0, false
	}
	var limitErr *helps.ChatGPTWebResponseLimitError
	if errors.As(err, &limitErr) {
		return 0, false
	}
	statusCode := statusCodeFromError(err)
	retryable := statusCode == 0 || statusCode == http.StatusNotFound || statusCode == http.StatusConflict ||
		statusCode == http.StatusLocked || statusCode == http.StatusTooManyRequests ||
		(statusCode >= http.StatusInternalServerError && statusCode <= 599)
	if !retryable {
		return 0, false
	}
	var retryAfter interface{ RetryAfter() *time.Duration }
	if errors.As(err, &retryAfter) {
		if delay := retryAfter.RetryAfter(); delay != nil && *delay >= 0 {
			return *delay, true
		}
	}
	if fallback < 0 {
		fallback = 0
	}
	return fallback, true
}

func waitForChatGPTWebPoll(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		if ctx != nil {
			return ctx.Err()
		}
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	if ctx == nil {
		<-timer.C
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (e *ChatGPTWebExecutor) downloadChatGPTWebImages(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, accumulator *helps.ChatGPTWebImageAccumulator) ([][]byte, error) {
	return e.downloadChatGPTWebImagesLimited(ctx, client, credential, accumulator, 0)
}

func (e *ChatGPTWebExecutor) downloadChatGPTWebImagesLimited(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, accumulator *helps.ChatGPTWebImageAccumulator, maxResults int) ([][]byte, error) {
	return e.downloadChatGPTWebImagesLimitedWithBudget(ctx, client, credential, accumulator, maxResults, chatGPTWebMaxImageResponseBytes)
}

func (e *ChatGPTWebExecutor) downloadChatGPTWebImagesLimitedWithBudget(
	ctx context.Context,
	client *chatgptwebauth.Client,
	credential *chatgptwebauth.Credential,
	accumulator *helps.ChatGPTWebImageAccumulator,
	maxResults int,
	responseByteLimit int,
) ([][]byte, error) {
	if responseByteLimit <= 0 {
		responseByteLimit = chatGPTWebMaxImageResponseBytes
	}
	urls, errURLs := e.chatGPTWebImageDownloadURLs(ctx, client, credential, accumulator, maxResults)
	if errURLs != nil {
		return nil, errURLs
	}
	images := make([][]byte, 0, len(urls))
	totalBytes := 0
	for _, downloadURL := range urls {
		remainingBytes := responseByteLimit - totalBytes
		if remainingBytes <= 0 {
			return images, chatGPTWebImageResponseLimitError(responseByteLimit)
		}
		payload, err := e.downloadChatGPTWebImageAsset(ctx, client, credential, downloadURL, remainingBytes)
		if err != nil {
			var limitErr *chatGPTWebImageBodyLimitError
			if errors.As(err, &limitErr) {
				return images, chatGPTWebImageResponseLimitError(responseByteLimit)
			}
			return images, err
		}
		if totalBytes > responseByteLimit-len(payload) {
			return images, chatGPTWebImageResponseLimitError(responseByteLimit)
		}
		totalBytes += len(payload)
		images = append(images, payload)
	}
	return images, nil
}

func (e *ChatGPTWebExecutor) chatGPTWebImageDownloadURLs(
	ctx context.Context,
	client *chatgptwebauth.Client,
	credential *chatgptwebauth.Credential,
	accumulator *helps.ChatGPTWebImageAccumulator,
	maxResults int,
) ([]string, error) {
	references := accumulator.References
	if len(references) == 0 {
		references = make([]helps.ChatGPTWebImageReference, 0, len(accumulator.FileIDs)+len(accumulator.SedimentIDs))
		for _, fileID := range accumulator.FileIDs {
			references = append(references, helps.ChatGPTWebImageReference{Kind: "file", ID: fileID})
		}
		for _, sedimentID := range accumulator.SedimentIDs {
			references = append(references, helps.ChatGPTWebImageReference{Kind: "sediment", ID: sedimentID})
		}
	}
	urls := make([]string, 0, len(references))
	for _, reference := range references {
		if maxResults > 0 && len(urls) >= maxResults {
			break
		}
		var path string
		switch reference.Kind {
		case "file":
			if reference.ID == "file_upload" {
				continue
			}
			path = "/backend-api/files/" + reference.ID + "/download"
		case "sediment":
			if strings.TrimSpace(accumulator.ConversationID) == "" {
				return nil, chatGPTWebImageOutputProtocolError("chatgpt web sediment image output is missing a conversation ID")
			}
			path = "/backend-api/conversation/" + accumulator.ConversationID + "/attachment/" + reference.ID + "/download"
		default:
			continue
		}
		downloadURL, err := e.resolveChatGPTWebImageDownloadURL(ctx, client, credential, path)
		if err != nil {
			return nil, err
		}
		urls = append(urls, downloadURL)
	}
	return urls, nil
}

func (e *ChatGPTWebExecutor) downloadChatGPTWebImagesWithWholeFinalization(
	ctx context.Context,
	client *chatgptwebauth.Client,
	credential *chatgptwebauth.Credential,
	accumulator *helps.ChatGPTWebImageAccumulator,
	maxResults int,
	responseByteLimit int,
	request *helps.ChatGPTWebImageRequest,
	imageSizeMatch *helps.ChatGPTWebImageSizeMatch,
	imageConfig cliproxyexecutor.ChatGPTWebImageConfigSnapshot,
	leases *helps.ChatGPTWebImageMemoryLeaseSet,
) ([][]byte, context.Context, error) {
	if leases == nil {
		return nil, ctx, errors.New("chatgpt web image finalization memory lease is unavailable")
	}
	if responseByteLimit <= 0 {
		responseByteLimit = chatGPTWebMaxImageResponseBytes
	}
	urls, errURLs := e.chatGPTWebImageDownloadURLs(ctx, client, credential, accumulator, maxResults)
	if errURLs != nil {
		return nil, ctx, errURLs
	}
	spooled := make([]*chatGPTWebSpooledImage, 0, len(urls))
	defer func() { removeChatGPTWebSpooledImages(spooled) }()
	totalBytes := 0
	for _, downloadURL := range urls {
		remainingBytes := responseByteLimit - totalBytes
		if remainingBytes <= 0 {
			return nil, ctx, chatGPTWebImageResponseLimitError(responseByteLimit)
		}
		image, errDownload := e.downloadChatGPTWebImageAssetToSpool(ctx, client, credential, downloadURL, remainingBytes)
		if errDownload != nil {
			var limitErr *chatGPTWebImageBodyLimitError
			if errors.As(errDownload, &limitErr) {
				return nil, ctx, chatGPTWebImageResponseLimitError(responseByteLimit)
			}
			return nil, ctx, errDownload
		}
		if totalBytes > responseByteLimit-image.size {
			_ = image.remove()
			return nil, ctx, chatGPTWebImageResponseLimitError(responseByteLimit)
		}
		totalBytes += image.size
		spooled = append(spooled, image)
	}
	workspaceBytes, errEstimate := estimateChatGPTWebWholeFinalizationBytes(
		spooled,
		request,
		imageSizeMatch,
		imageConfig,
		responseByteLimit,
	)
	if errEstimate != nil {
		return nil, ctx, errEstimate
	}
	if capacity := helps.ChatGPTWebImageMemorySnapshot().CapacityBytes; capacity < 1 || workspaceBytes > capacity {
		return nil, ctx, &chatGPTWebImageMemoryCapacityError{stage: "download"}
	}
	releaseTurn, errBegin := leases.BeginFinalization(ctx)
	if errBegin != nil {
		return nil, ctx, errBegin
	}
	turnReleased := false
	defer func() {
		if !turnReleased {
			releaseTurn()
		}
	}()
	if errAcquire := leases.AcquireExact(ctx, workspaceBytes); errAcquire != nil {
		return nil, ctx, chatGPTWebWholeFinalizationMemoryError(errAcquire)
	}
	releaseTurn()
	turnReleased = true
	workspaceContext := helps.WithChatGPTWebImageWholeFinalization(ctx)
	images := make([][]byte, 0, len(spooled))
	for _, image := range spooled {
		payload, errRead := os.ReadFile(image.path)
		if errRead != nil {
			return nil, workspaceContext, fmt.Errorf("read chatgpt web image completion spool: %w", errRead)
		}
		if len(payload) != image.size {
			return nil, workspaceContext, errors.New("chatgpt web image completion spool size changed")
		}
		if errValidate := validateChatGPTWebDownloadedImageWithAdmission(
			workspaceContext,
			payload,
			image.contentType,
			helps.AcquireChatGPTWebImageMemory,
		); errValidate != nil {
			return nil, workspaceContext, chatGPTWebImageOutputProtocolError("chatgpt web image download is invalid: " + errValidate.Error())
		}
		images = append(images, payload)
	}
	return images, workspaceContext, nil
}

func chatGPTWebWholeFinalizationMemoryError(err error) error {
	if errors.Is(err, helps.ErrChatGPTWebImageMemoryQueueFull) || errors.Is(err, helps.ErrChatGPTWebImageMemoryWorkingSetTooLarge) {
		return &chatGPTWebImageMemoryCapacityError{stage: "download"}
	}
	return err
}

func (e *ChatGPTWebExecutor) downloadChatGPTWebImageAssetToSpool(
	ctx context.Context,
	client *chatgptwebauth.Client,
	credential *chatgptwebauth.Credential,
	downloadURL string,
	maxBytes int,
) (*chatGPTWebSpooledImage, error) {
	var lastErr error
	for attempt := 0; attempt < chatGPTWebAssetSettleAttempts; attempt++ {
		image, err, retryable := e.downloadChatGPTWebImageAssetToSpoolOnce(ctx, client, credential, downloadURL, maxBytes)
		if err == nil {
			return image, nil
		}
		lastErr = err
		if !retryable {
			return nil, err
		}
		if attempt+1 >= chatGPTWebAssetSettleAttempts {
			return nil, chatGPTWebFinalAssetError(err)
		}
		delay, _ := chatGPTWebAssetRetryDelay(err, e.imageSettleWait)
		if errWait := waitForChatGPTWebPoll(ctx, delay); errWait != nil {
			return nil, errWait
		}
	}
	return nil, chatGPTWebFinalAssetError(lastErr)
}

func (e *ChatGPTWebExecutor) downloadChatGPTWebImageAssetToSpoolOnce(
	ctx context.Context,
	client *chatgptwebauth.Client,
	credential *chatgptwebauth.Credential,
	downloadURL string,
	maxBytes int,
) (*chatGPTWebSpooledImage, error, bool) {
	downloadHeaders := map[string]string{"accept": chatGPTWebImageDownloadAccept}
	response, finalDownloadURL, errRequest := e.doChatGPTWebAssetRequest(ctx, client, credential, http.MethodGet, downloadURL, downloadHeaders, nil, false)
	if errRequest != nil {
		sanitizedErr := newChatGPTWebAssetTransportError(ctx, "download", errRequest)
		helps.RecordAPIResponseError(ctx, e.configSnapshot(), sanitizedErr)
		return nil, sanitizedErr, true
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		payload := readAndCloseChatGPTWebErrorBody(response.Body)
		statusErr := newChatGPTWebAssetStatusError(response.StatusCode, finalDownloadURL, payload, response.Header, "image_download")
		return nil, statusErr, chatGPTWebAssetSettleStatusRetryable(response.StatusCode)
	}
	contentType := response.Header.Get("Content-Type")
	temporary, errCreate := os.CreateTemp("", "cliproxy-web-image-completion-*")
	if errCreate != nil {
		_ = response.Body.Close()
		return nil, fmt.Errorf("create chatgpt web image completion spool: %w", errCreate), false
	}
	spooled := &chatGPTWebSpooledImage{
		path:        temporary.Name(),
		contentType: contentType,
		tracker:     helps.BeginChatGPTWebImageSpool(),
	}
	keep := false
	defer func() {
		if !keep {
			_ = temporary.Close()
			_ = spooled.remove()
		}
	}()
	copied, errCopy := io.Copy(temporary, io.LimitReader(response.Body, int64(maxBytes)+1))
	spooled.tracker.SetBytes(copied)
	errCloseBody := response.Body.Close()
	if errCopy != nil {
		return nil, newChatGPTWebAssetTransportError(ctx, "download response", errCopy), false
	}
	if errCloseBody != nil {
		return nil, newChatGPTWebAssetTransportError(ctx, "download response", errCloseBody), false
	}
	if copied > int64(maxBytes) {
		return nil, &chatGPTWebImageBodyLimitError{maxBytes: maxBytes}, false
	}
	if copied == 0 {
		return nil, chatGPTWebImageOutputProtocolError("chatgpt web image download is empty"), true
	}
	if _, errSeek := temporary.Seek(0, io.SeekStart); errSeek != nil {
		return nil, fmt.Errorf("rewind chatgpt web image completion spool: %w", errSeek), false
	}
	decodedConfig, format, errConfig := image.DecodeConfig(temporary)
	if errConfig != nil {
		return nil, chatGPTWebImageOutputProtocolError("chatgpt web image download is invalid: " + errConfig.Error()), true
	}
	if errClose := temporary.Close(); errClose != nil {
		return nil, fmt.Errorf("close chatgpt web image completion spool: %w", errClose), false
	}
	spooled.size = int(copied)
	spooled.format = normalizeChatGPTWebImageOutputFormat(format)
	spooled.width = decodedConfig.Width
	spooled.height = decodedConfig.Height
	keep = true
	return spooled, nil, false
}

func estimateChatGPTWebWholeFinalizationBytes(
	images []*chatGPTWebSpooledImage,
	request *helps.ChatGPTWebImageRequest,
	imageSizeMatch *helps.ChatGPTWebImageSizeMatch,
	imageConfig cliproxyexecutor.ChatGPTWebImageConfigSnapshot,
	responseByteLimit int,
) (int64, error) {
	if request == nil {
		return 0, errors.New("chatgpt web image request is unavailable during finalization")
	}
	requestedFormat := normalizeChatGPTWebImageOutputFormat(request.OutputFormat)
	if requestedFormat != "png" && requestedFormat != "jpeg" && requestedFormat != "webp" {
		return 0, statusErr{code: http.StatusBadRequest, msg: "chatgpt web does not support the requested image output format", skipAuthResult: true, retryOtherAuth: true}
	}
	resizeEnabled := imageConfig.ResizeToRequestedSize && imageSizeMatch != nil
	inputBytes := int64(0)
	outputBytes := int64(0)
	transientPeak := int64(1)
	changed := false
	for _, image := range images {
		if image == nil || image.size <= 0 || image.width <= 0 || image.height <= 0 {
			return 0, errors.New("chatgpt web image completion spool metadata is invalid")
		}
		inputBytes = saturatingChatGPTWebImageAdd(inputBytes, int64(image.size))
		validationBytes := saturatingChatGPTWebImageMultiply(
			saturatingChatGPTWebImagePixels(image.width, image.height),
			chatGPTWebDecodedImageBytesPerPixel,
		)
		if validationBytes > transientPeak {
			transientPeak = validationBytes
		}
		needsResize := resizeEnabled && (image.width != imageSizeMatch.Width || image.height != imageSizeMatch.Height)
		needsEncoding := image.format != requestedFormat || requestedFormat == "jpeg" || requestedFormat == "webp"
		if !needsResize && !needsEncoding {
			outputBytes = saturatingChatGPTWebImageAdd(outputBytes, int64(image.size))
			continue
		}
		changed = true
		targetWidth, targetHeight := image.width, image.height
		if needsResize {
			targetWidth, targetHeight = imageSizeMatch.Width, imageSizeMatch.Height
		}
		processingBytes := estimateChatGPTWebImagePostProcessingBytes(
			image.width,
			image.height,
			targetWidth,
			targetHeight,
			needsResize,
			requestedFormat,
		)
		if processingBytes > transientPeak {
			transientPeak = processingBytes
		}
		encodedUpperBound := chatGPTWebImageEncodedOutputUpperBound(targetWidth, targetHeight)
		outputBytes = saturatingChatGPTWebImageAdd(outputBytes, encodedUpperBound)
	}
	if outputBytes > int64(responseByteLimit) {
		outputBytes = int64(responseByteLimit)
	}
	base64Bytes := saturatingChatGPTWebImageMultiply(saturatingChatGPTWebImageAdd(outputBytes, 2)/3, 4)
	workspaceBytes := saturatingChatGPTWebImageAdd(inputBytes, transientPeak)
	if changed {
		workspaceBytes = saturatingChatGPTWebImageAdd(workspaceBytes, outputBytes)
	}
	workspaceBytes = saturatingChatGPTWebImageAdd(workspaceBytes, saturatingChatGPTWebImageMultiply(base64Bytes, 2))
	workspaceBytes = saturatingChatGPTWebImageAdd(workspaceBytes, chatGPTWebImageResponseJSONOverhead)
	return max(workspaceBytes, int64(1)), nil
}

func chatGPTWebImageEncodedOutputUpperBound(width, height int) int64 {
	// All supported encoders receive at most four bytes of source color data per
	// pixel. Twice that raw size plus one MiB covers PNG scanline/DEFLATE and
	// container overhead as well as the JPEG/WebP encoder output buffers. The
	// response byte limit remains the final hard cap across all images.
	return saturatingChatGPTWebImageAdd(
		saturatingChatGPTWebImageMultiply(saturatingChatGPTWebImagePixels(width, height), 8),
		1<<20,
	)
}

func (e *ChatGPTWebExecutor) resolveChatGPTWebImageDownloadURL(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, path string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < chatGPTWebAssetSettleAttempts; attempt++ {
		_, payload, releaseMemory, err := e.doChatGPTWebGET(ctx, client, credential, path, nil)
		if err == nil {
			downloadURL := firstChatGPTWebURL(payload)
			if releaseMemory != nil {
				releaseMemory()
			}
			if downloadURL != "" {
				return downloadURL, nil
			}
			err = chatGPTWebImageOutputProtocolError("chatgpt web image output metadata is missing a download URL")
		} else {
			var memoryErr *chatGPTWebImageMemoryCapacityError
			if errors.As(err, &memoryErr) {
				return "", err
			}
			err = chatGPTWebAssetNetworkError(ctx, "download URL", err)
		}
		lastErr = err
		delay, retryable := chatGPTWebAssetRetryDelay(err, e.imageSettleWait)
		if !retryable {
			return "", err
		}
		if attempt+1 >= chatGPTWebAssetSettleAttempts {
			return "", chatGPTWebFinalAssetError(err)
		}
		if errWait := waitForChatGPTWebPoll(ctx, delay); errWait != nil {
			return "", errWait
		}
	}
	return "", chatGPTWebFinalAssetError(lastErr)
}

func (e *ChatGPTWebExecutor) downloadChatGPTWebImageAsset(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, downloadURL string, maxBytes int) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < chatGPTWebAssetSettleAttempts; attempt++ {
		payload, err, retryable := e.downloadChatGPTWebImageAssetOnce(ctx, client, credential, downloadURL, maxBytes)
		if err == nil {
			return payload, nil
		}
		lastErr = err
		if !retryable {
			return nil, err
		}
		if attempt+1 >= chatGPTWebAssetSettleAttempts {
			return nil, chatGPTWebFinalAssetError(err)
		}
		delay, _ := chatGPTWebAssetRetryDelay(err, e.imageSettleWait)
		if errWait := waitForChatGPTWebPoll(ctx, delay); errWait != nil {
			return nil, errWait
		}
	}
	return nil, chatGPTWebFinalAssetError(lastErr)
}

func (e *ChatGPTWebExecutor) downloadChatGPTWebImageAssetOnce(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, downloadURL string, maxBytes int) ([]byte, error, bool) {
	downloadHeaders := map[string]string{"accept": chatGPTWebImageDownloadAccept}
	response, finalDownloadURL, err := e.doChatGPTWebAssetRequest(ctx, client, credential, http.MethodGet, downloadURL, downloadHeaders, nil, false)
	if err != nil {
		sanitizedErr := newChatGPTWebAssetTransportError(ctx, "download", err)
		helps.RecordAPIResponseError(ctx, e.configSnapshot(), sanitizedErr)
		return nil, sanitizedErr, true
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		payload := readAndCloseChatGPTWebErrorBody(response.Body)
		statusErr := newChatGPTWebAssetStatusError(response.StatusCode, finalDownloadURL, payload, response.Header, "image_download")
		return nil, statusErr, chatGPTWebAssetSettleStatusRetryable(response.StatusCode)
	}
	contentType := response.Header.Get("Content-Type")
	payload, errRead := readChatGPTWebImageDownloadBody(ctx, response.Body, response.ContentLength, maxBytes)
	errClose := response.Body.Close()
	if errRead != nil {
		var memoryErr *chatGPTWebImageMemoryCapacityError
		if errors.As(errRead, &memoryErr) {
			return nil, errRead, false
		}
		return nil, newChatGPTWebAssetTransportError(ctx, "download response", errRead), false
	}
	if errClose != nil {
		return nil, newChatGPTWebAssetTransportError(ctx, "download response", errClose), false
	}
	if len(payload) == 0 {
		return nil, chatGPTWebImageOutputProtocolError("chatgpt web image download is empty"), true
	}
	if errValidate := validateChatGPTWebDownloadedImageWithAdmission(ctx, payload, contentType, helps.AcquireChatGPTWebImageMemory); errValidate != nil {
		if errors.Is(errValidate, context.Canceled) || errors.Is(errValidate, context.DeadlineExceeded) {
			return nil, errValidate, false
		}
		var memoryErr *chatGPTWebImageMemoryCapacityError
		if errors.As(errValidate, &memoryErr) {
			return nil, errValidate, false
		}
		return nil, chatGPTWebImageOutputProtocolError("chatgpt web image download is invalid: " + errValidate.Error()), true
	}
	return payload, nil, false
}

func readChatGPTWebImageDownloadBody(ctx context.Context, body io.Reader, contentLength int64, maxBytes int) ([]byte, error) {
	leases := helps.ChatGPTWebImageMemoryLeaseSetFromContext(ctx)
	if leases == nil {
		return readChatGPTWebBoundedBody(body, maxBytes)
	}
	return readChatGPTWebBoundedBodyWithAdmission(body, contentLength, maxBytes, func(size int64) (func(), error) {
		base64Bytes := saturatingChatGPTWebImageMultiply(saturatingChatGPTWebImageAdd(size, 2)/3, 4)
		estimatedBytes := saturatingChatGPTWebImageAdd(size, saturatingChatGPTWebImageMultiply(base64Bytes, 2))
		if errAcquire := leases.Acquire(ctx, max(estimatedBytes, int64(1))); errAcquire != nil {
			if errors.Is(errAcquire, context.Canceled) || errors.Is(errAcquire, context.DeadlineExceeded) {
				return nil, errAcquire
			}
			return nil, &chatGPTWebImageMemoryCapacityError{stage: "download"}
		}
		return func() {}, nil
	})
}

func chatGPTWebAssetRetryDelay(err error, fallback time.Duration) (time.Duration, bool) {
	statusCode := statusCodeFromError(err)
	if statusCode != 0 && !chatGPTWebAssetSettleStatusRetryable(statusCode) {
		return 0, false
	}
	var retryAfter interface{ RetryAfter() *time.Duration }
	if errors.As(err, &retryAfter) {
		if delay := retryAfter.RetryAfter(); delay != nil && *delay >= 0 {
			return *delay, true
		}
	}
	if fallback < 0 {
		fallback = 0
	}
	return fallback, true
}

func chatGPTWebAssetSettleStatusRetryable(code int) bool {
	switch code {
	case http.StatusNotFound, http.StatusRequestTimeout, http.StatusConflict,
		http.StatusLocked, http.StatusTooEarly, http.StatusTooManyRequests:
		return true
	default:
		return code >= http.StatusInternalServerError
	}
}

func chatGPTWebFinalAssetError(err error) error {
	if err == nil {
		return statusErr{
			code:           http.StatusBadGateway,
			msg:            "chatgpt web image asset did not become available",
			skipAuthResult: true,
		}
	}
	var transportErr chatGPTWebAssetTransportError
	if errors.As(err, &transportErr) {
		transportErr.skipAuthResult = true
		transportErr.retryOtherAuth = false
		return transportErr
	}
	var httpErr chatGPTWebHTTPError
	if errors.As(err, &httpErr) {
		httpErr.statusErr.skipAuthResult = true
		httpErr.statusErr.retryOtherAuth = false
		return httpErr
	}
	var localErr statusErr
	if errors.As(err, &localErr) {
		localErr.skipAuthResult = true
		localErr.retryOtherAuth = false
		return localErr
	}
	diagnostic := helps.ClassifyChatGPTWebTransportDiagnostic(err, "/")
	diagnostic.Stage = "image_download"
	diagnostic.TargetHost = ""
	diagnostic.TargetPath = ""
	return chatGPTWebAssetTransportError{
		statusErr: statusErr{
			code:           http.StatusBadGateway,
			msg:            "chatgpt web image asset request failed",
			skipAuthResult: true,
		},
		cause:      sanitizeChatGPTWebAssetTransportCause(err),
		diagnostic: diagnostic,
	}
}

func chatGPTWebCommittedRequestError(ctx context.Context, err error) (committedError error) {
	if err == nil {
		return nil
	}
	defer func() {
		committedError = preserveChatGPTWebFailureStage(err, committedError)
	}()
	if ctx != nil && errors.Is(context.Cause(ctx), errChatGPTWebImageTaskCanceledByAdmin) {
		return normalizeChatGPTWebImageTaskCancellation(ctx, err)
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	var imageQuotaErr *chatGPTWebImageQuotaResultError
	if errors.As(err, &imageQuotaErr) {
		return &chatGPTWebImageQuotaResultError{cause: imageQuotaErr.cause, committed: true}
	}
	var imageRateLimitErr *chatGPTWebImageRateLimitResultError
	if errors.As(err, &imageRateLimitErr) {
		return &chatGPTWebImageRateLimitResultError{cause: imageRateLimitErr.cause, committed: true}
	}
	var moderationErr *helps.OpenAIImageModerationError
	if errors.As(err, &moderationErr) {
		return moderationErr
	}
	var settleErr chatGPTWebImageSettleError
	if errors.As(err, &settleErr) {
		settleErr.skipAuthResult = true
		settleErr.retryOtherAuth = false
		return settleErr
	}
	var settleStatusErr chatGPTWebImageSettleStatusError
	if errors.As(err, &settleStatusErr) {
		settleStatusErr.skipAuthResult = true
		settleStatusErr.retryOtherAuth = false
		return settleStatusErr
	}
	var noOutputErr *chatGPTWebImageNoOutputResultError
	if errors.As(err, &noOutputErr) && noOutputErr != nil {
		projected := *noOutputErr
		projected.skipAuthResult = true
		projected.retryOtherAuth = false
		return &projected
	}
	var transportErr chatGPTWebAssetTransportError
	if errors.As(err, &transportErr) {
		transportErr.skipAuthResult = true
		transportErr.retryOtherAuth = false
		return transportErr
	}
	var httpErr chatGPTWebHTTPError
	if errors.As(err, &httpErr) {
		httpErr.statusErr.skipAuthResult = true
		httpErr.statusErr.retryOtherAuth = false
		return httpErr
	}
	var localErr statusErr
	if errors.As(err, &localErr) {
		localErr.skipAuthResult = true
		localErr.retryOtherAuth = false
		return localErr
	}
	var limitErr *helps.ChatGPTWebResponseLimitError
	if errors.As(err, &limitErr) {
		return err
	}
	var memoryErr *chatGPTWebImageMemoryCapacityError
	if errors.As(err, &memoryErr) {
		return err
	}
	code := statusCodeFromError(err)
	if code == 0 {
		code = http.StatusBadGateway
	}
	return statusErr{
		code:           code,
		msg:            err.Error(),
		skipAuthResult: true,
	}
}

func validateChatGPTWebDownloadedImage(data []byte, contentType string) error {
	return validateChatGPTWebDownloadedImageWithAdmission(
		context.Background(),
		data,
		contentType,
		helps.AcquireChatGPTWebImageMemory,
	)
}

func validateChatGPTWebDownloadedImageWithAdmission(
	ctx context.Context,
	data []byte,
	contentType string,
	acquire func(context.Context, int64) (func(), error),
) error {
	mimeType := strings.TrimSpace(contentType)
	if parsed, _, err := mime.ParseMediaType(mimeType); err == nil {
		mimeType = parsed
	}
	imageConfig, errConfig := chatGPTWebOutputImageConfig(data, mimeType)
	if errConfig != nil {
		return errConfig
	}
	estimatedBytes := saturatingChatGPTWebImageMultiply(
		saturatingChatGPTWebImagePixels(imageConfig.Width, imageConfig.Height),
		chatGPTWebDecodedImageBytesPerPixel,
	)
	var releaseMemory func()
	var errAcquire error
	if helps.ChatGPTWebImageMemoryLeaseSetFromContext(ctx) != nil {
		releaseMemory, errAcquire = acquireChatGPTWebTransientImageMemory(ctx, max(estimatedBytes, int64(1)))
	} else {
		releaseMemory, errAcquire = acquire(ctx, max(estimatedBytes, int64(1)))
	}
	if errAcquire != nil {
		return fmt.Errorf("wait for chatgpt web image validation memory: %w", errAcquire)
	}
	defer releaseMemory()

	_, errDecode := decodeAndValidateChatGPTWebImageAgainstConfig(data, imageConfig)
	return errDecode
}

func acquireChatGPTWebTransientImageMemory(ctx context.Context, estimatedBytes int64) (func(), error) {
	if helps.ChatGPTWebImageWholeFinalizationFromContext(ctx) {
		return func() {}, nil
	}
	leases := helps.ChatGPTWebImageMemoryLeaseSetFromContext(ctx)
	if leases == nil {
		return helps.AcquireChatGPTWebImageMemory(ctx, estimatedBytes)
	}
	release, err := leases.AcquireTransient(ctx, estimatedBytes)
	if errors.Is(err, helps.ErrChatGPTWebImageMemoryQueueFull) || errors.Is(err, helps.ErrChatGPTWebImageMemoryWorkingSetTooLarge) {
		return nil, &chatGPTWebImageMemoryCapacityError{}
	}
	return release, err
}

func chatGPTWebImageOutputProtocolError(message string) error {
	return statusErr{
		code:           http.StatusBadGateway,
		msg:            message,
		skipAuthResult: true,
		retryOtherAuth: true,
	}
}

func readChatGPTWebBoundedBody(body io.Reader, maxBytes int) ([]byte, error) {
	if body == nil {
		return nil, errors.New("chatgpt web response body is nil")
	}
	if maxBytes < 1 {
		return nil, errors.New("chatgpt web response body limit is invalid")
	}
	payload, err := io.ReadAll(io.LimitReader(body, int64(maxBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("read chatgpt web response body: %w", err)
	}
	if len(payload) > maxBytes {
		return nil, &chatGPTWebImageBodyLimitError{maxBytes: maxBytes}
	}
	return payload, nil
}

func readChatGPTWebBoundedBodyWithAdmission(
	body io.Reader,
	contentLength int64,
	maxBytes int,
	acquire func(int64) (func(), error),
) ([]byte, error) {
	if body == nil {
		return nil, errors.New("chatgpt web response body is nil")
	}
	if maxBytes < 1 {
		return nil, errors.New("chatgpt web response body limit is invalid")
	}
	if contentLength > int64(maxBytes) {
		return nil, &chatGPTWebImageBodyLimitError{maxBytes: maxBytes}
	}
	if contentLength > 0 {
		release, errAcquire := acquire(contentLength)
		if errAcquire != nil {
			return nil, errAcquire
		}
		if release != nil {
			defer release()
		}
		return readChatGPTWebBoundedBody(body, maxBytes)
	}

	temporary, errCreate := os.CreateTemp("", "cliproxy-chatgpt-web-image-*")
	if errCreate != nil {
		return nil, fmt.Errorf("create bounded image spool: %w", errCreate)
	}
	path := temporary.Name()
	spoolTracker := helps.BeginChatGPTWebImageSpool()
	defer func() {
		errRemove := os.Remove(path)
		spoolTracker.FinishCleanup(errRemove)
	}()
	defer func() { _ = temporary.Close() }()
	copied, errCopy := io.Copy(temporary, io.LimitReader(body, int64(maxBytes)+1))
	spoolTracker.SetBytes(copied)
	if errCopy != nil {
		return nil, fmt.Errorf("spool chatgpt web response body: %w", errCopy)
	}
	if copied > int64(maxBytes) {
		return nil, &chatGPTWebImageBodyLimitError{maxBytes: maxBytes}
	}
	release, errAcquire := acquire(copied)
	if errAcquire != nil {
		return nil, errAcquire
	}
	if release != nil {
		defer release()
	}
	if _, errSeek := temporary.Seek(0, io.SeekStart); errSeek != nil {
		return nil, fmt.Errorf("rewind bounded image spool: %w", errSeek)
	}
	payload := make([]byte, copied)
	if _, errRead := io.ReadFull(temporary, payload); errRead != nil {
		return nil, fmt.Errorf("read bounded image spool: %w", errRead)
	}
	return payload, nil
}

func (e *ChatGPTWebExecutor) doChatGPTWebGET(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, path string, extra map[string]string) (*fhttp.Response, []byte, func(), error) {
	return e.doChatGPTWebGETWithBudget(ctx, client, credential, path, extra, nil, true, false)
}

func (e *ChatGPTWebExecutor) doChatGPTWebPollGET(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, path string, extra map[string]string, budget *chatGPTWebPollResponseBudget) (*fhttp.Response, []byte, func(), error) {
	setChatGPTWebImageTaskStage(ctx, "poll_slot_wait")
	releasePoll, errPoll := acquireChatGPTWebImagePollSlot(ctx)
	if errPoll != nil {
		return nil, nil, nil, errPoll
	}
	defer releasePoll()
	finishTaskPoll := beginChatGPTWebImageTaskPoll(ctx)
	started := time.Now()
	response, payload, release, err := e.doChatGPTWebGETWithBudget(ctx, client, credential, path, extra, budget, false, true)
	canceled := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	if ctx != nil && ctx.Err() != nil {
		canceled = true
	}
	finishTaskPoll(canceled)
	cliproxyexecutor.ObserveChatGPTWebImagePollCompletion(canceled)
	cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhasePollRequest, started)
	return response, payload, release, err
}

func acquireChatGPTWebImagePollSlot(ctx context.Context) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	started := time.Now()
	chatGPTWebImagePollMetrics.attempts.Add(1)
	release, err := cliproxyexecutor.AcquireChatGPTWebImagePoll(ctx)
	cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhasePollSlotWait, started)
	if err != nil {
		return nil, err
	}
	chatGPTWebImagePollMetrics.acquired.Add(1)
	return release, nil
}

func readChatGPTWebPollResponseBody(ctx context.Context, response *fhttp.Response, maxBytes int) ([]byte, func(), error) {
	if response == nil {
		return nil, nil, errors.New("chatgpt web response is nil")
	}
	estimatedBytes := response.ContentLength
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		estimatedBytes = chatGPTWebMaxErrorBodyBytes
	} else if estimatedBytes <= 0 || estimatedBytes > int64(maxBytes) {
		estimatedBytes = int64(maxBytes)
	}
	estimatedBytes = saturatingChatGPTWebImageMultiply(estimatedBytes, 2)
	var release func()
	var errAcquire error
	if leases := helps.ChatGPTWebImageMemoryLeaseSetFromContext(ctx); leases != nil {
		release, errAcquire = leases.AcquireTransient(ctx, max(estimatedBytes, int64(1)))
	} else {
		var acquired bool
		release, acquired = helps.TryAcquireChatGPTWebImageMemory(max(estimatedBytes, int64(1)))
		if !acquired {
			errAcquire = helps.ErrChatGPTWebImageMemoryQueueFull
		}
	}
	if errAcquire != nil {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		if errors.Is(errAcquire, context.Canceled) || errors.Is(errAcquire, context.DeadlineExceeded) {
			return nil, nil, errAcquire
		}
		return nil, nil, &chatGPTWebImageMemoryCapacityError{stage: "settle"}
	}
	data, err := readChatGPTWebResponseBody(response, maxBytes)
	if err != nil {
		release()
		return nil, nil, err
	}
	return data, release, nil
}

func (e *ChatGPTWebExecutor) doChatGPTWebGETWithBudget(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, path string, extra map[string]string, budget *chatGPTWebPollResponseBudget, logBody, usePollTransport bool) (*fhttp.Response, []byte, func(), error) {
	headers := e.chatGPTWebHeaders(credential, path, extra)
	logPath := chatGPTWebRequestLogPath(path)
	e.recordChatGPTWebRequest(ctx, credential, http.MethodGet, logPath, headers, nil)
	var response *fhttp.Response
	var err error
	if usePollTransport {
		response, err = client.DoPollNoRedirectStream(ctx, http.MethodGet, e.chatGPTWebBaseURL()+path, headers, nil)
	} else {
		response, err = client.DoNoRedirectStream(ctx, http.MethodGet, e.chatGPTWebBaseURL()+path, headers, nil)
	}
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.configSnapshot(), err)
		return nil, nil, nil, chatGPTWebTransportDiagnosticError(err, logPath)
	}
	helps.RecordAPIResponseMetadata(ctx, e.configSnapshot(), response.StatusCode, chatGPTWebResponseLogHeaders(response.Header))
	data, releaseMemory, err := readChatGPTWebPollResponseBody(ctx, response, chatGPTWebMaxJSONBodyBytes)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.configSnapshot(), err)
		var memoryErr *chatGPTWebImageMemoryCapacityError
		if errors.As(err, &memoryErr) {
			return response, nil, nil, err
		}
		return response, nil, nil, chatGPTWebTransportDiagnosticError(err, logPath)
	}
	if err = budget.consume(len(data)); err != nil {
		releaseMemory()
		helps.RecordAPIResponseError(ctx, e.configSnapshot(), err)
		return response, nil, nil, err
	}
	sanitizedData := chatGPTWebResponseLogBody(logPath, data)
	if logBody {
		helps.AppendAPIResponseChunk(ctx, e.configSnapshot(), sanitizedData)
	} else {
		helps.AppendAPIResponseChunk(ctx, e.configSnapshot(), []byte("<chatgpt web polling response body omitted>"))
	}
	if challengeErr := newChatGPTWebChallengeResponseError(response.StatusCode, logPath, data, response.Header); challengeErr != nil {
		releaseMemory()
		return response, nil, nil, challengeErr
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		statusErr := newChatGPTWebStatusError(response.StatusCode, logPath, data, response.Header)
		releaseMemory()
		return response, nil, nil, statusErr
	}
	return response, data, releaseMemory, nil
}

func chatGPTWebRequestLogPath(path string) string {
	parsed, err := url.Parse(strings.TrimSpace(path))
	if err != nil || parsed == nil || strings.TrimSpace(parsed.Path) == "" {
		return "/"
	}
	return parsed.EscapedPath()
}

func chatGPTWebAssetNetworkError(ctx context.Context, action string, err error) error {
	if err == nil || statusCodeFromError(err) != 0 {
		return err
	}
	return newChatGPTWebAssetTransportError(ctx, action, err)
}

func newChatGPTWebAssetTransportError(ctx context.Context, action string, cause error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	diagnostic := helps.ClassifyChatGPTWebTransportDiagnostic(cause, "/")
	diagnostic.TargetHost = ""
	diagnostic.TargetPath = ""
	if strings.HasPrefix(strings.TrimSpace(action), "download") {
		diagnostic.Stage = "image_download"
	} else {
		diagnostic.Stage = "file_upload"
	}
	return chatGPTWebAssetTransportError{
		statusErr: statusErr{
			code:           http.StatusBadGateway,
			msg:            "chatgpt web image asset " + strings.TrimSpace(action) + " failed",
			skipAuthResult: true,
			retryOtherAuth: true,
		},
		cause:      sanitizeChatGPTWebAssetTransportCause(cause),
		diagnostic: diagnostic,
	}
}

func sanitizeChatGPTWebAssetTransportCause(cause error) error {
	var urlError *url.Error
	if !errors.As(cause, &urlError) {
		return cause
	}
	return &url.Error{
		Op:  urlError.Op,
		URL: "<redacted>",
		Err: sanitizeChatGPTWebAssetTransportCause(urlError.Err),
	}
}

func newChatGPTWebAssetStatusError(code int, targetURL string, body []byte, headers fhttp.Header, stage string) chatGPTWebHTTPError {
	err := newChatGPTWebStatusError(code, chatGPTWebAssetErrorPath(targetURL), body, headers)
	err.statusErr.skipAuthResult = true
	err.statusErr.retryOtherAuth = chatGPTWebAssetStatusRetryable(code)
	err.diagnostic = helps.ClassifyChatGPTWebHTTPDiagnostic(code, targetURL, body, headers)
	err.diagnostic.Stage = stage
	return err
}

func chatGPTWebAssetErrorPath(rawURL string) string {
	parsed, errParse := url.Parse(strings.TrimSpace(rawURL))
	if errParse != nil || strings.TrimSpace(parsed.Path) == "" {
		return "/"
	}
	return parsed.EscapedPath()
}

func chatGPTWebAssetStatusRetryable(code int) bool {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusRequestTimeout, http.StatusConflict, http.StatusLocked,
		http.StatusTooEarly, http.StatusTooManyRequests:
		return true
	default:
		return code >= http.StatusInternalServerError
	}
}

func chatGPTWebRequirementsHeaders(headers map[string]string, requirements chatGPTWebRequirements) map[string]string {
	headers["openai-sentinel-chat-requirements-token"] = requirements.Token
	if requirements.ProofToken != "" {
		headers["openai-sentinel-proof-token"] = requirements.ProofToken
	}
	if requirements.TurnstileToken != "" {
		headers["openai-sentinel-turnstile-token"] = requirements.TurnstileToken
	}
	if requirements.SOToken != "" {
		headers["openai-sentinel-so-token"] = requirements.SOToken
	}
	return headers
}

func chatGPTWebUserTextMessage(prompt string) map[string]any {
	return map[string]any{
		"id": uuid.NewString(), "author": map[string]any{"role": "user"},
		"content": map[string]any{"content_type": "text", "parts": []string{prompt}},
	}
}

func chatGPTWebAttachment(uploaded chatGPTWebUploadedImage) map[string]any {
	return map[string]any{
		"id": uploaded.FileID, "mimeType": uploaded.MIMEType, "name": uploaded.FileName,
		"size": uploaded.Size, "width": uploaded.Width, "height": uploaded.Height,
	}
}

func decodeChatGPTWebImageReference(value string) ([]byte, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, "", errors.New("image reference is empty")
	}
	mimeType := "image/png"
	payload := value
	if strings.HasPrefix(strings.ToLower(value), "data:") {
		comma := strings.IndexByte(value, ',')
		if comma < 0 {
			return nil, "", errors.New("invalid image data URL")
		}
		metadata := value[5:comma]
		payload = value[comma+1:]
		if semicolon := strings.IndexByte(metadata, ';'); semicolon >= 0 {
			mimeType = strings.TrimSpace(metadata[:semicolon])
		} else if strings.TrimSpace(metadata) != "" {
			mimeType = strings.TrimSpace(metadata)
		}
		if !strings.Contains(strings.ToLower(metadata), ";base64") {
			return nil, "", errors.New("image data URL must use base64 encoding")
		}
	}
	if _, err := chatGPTWebEncodedImageSize(payload, chatGPTWebMaxImageBytes); err != nil {
		return nil, "", err
	}
	data, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, "", fmt.Errorf("decode image base64: %w", err)
	}
	if !strings.HasPrefix(strings.ToLower(mimeType), "image/") {
		return nil, "", fmt.Errorf("unsupported image MIME type %q", mimeType)
	}
	return data, strings.ToLower(mimeType), nil
}

func validateChatGPTWebImageRequest(request *helps.ChatGPTWebImageRequest, remoteEnabled ...bool) error {
	if request == nil {
		return nil
	}
	size := strings.ToLower(strings.TrimSpace(request.Size))
	defaultSize := size == "" || size == "auto" ||
		(size == "1024x1024" && strings.EqualFold(strings.TrimSpace(request.Action), "edit"))
	if !defaultSize {
		return statusErr{
			code:           http.StatusBadRequest,
			msg:            "chatgpt web does not support an exact image size",
			skipAuthResult: true,
			retryOtherAuth: true,
		}
	}
	if quality := strings.TrimSpace(request.Quality); quality != "" && !strings.EqualFold(quality, "auto") {
		return statusErr{
			code:           http.StatusBadRequest,
			msg:            "chatgpt web does not support an exact image quality",
			skipAuthResult: true,
			retryOtherAuth: true,
		}
	}
	outputFormat := normalizeChatGPTWebImageOutputFormat(request.OutputFormat)
	if outputFormat != "png" && outputFormat != "jpeg" && outputFormat != "webp" {
		return statusErr{
			code:           http.StatusBadRequest,
			msg:            "chatgpt web does not support the requested image output format",
			skipAuthResult: true,
			retryOtherAuth: true,
		}
	}
	if request.OutputCompression < 0 || request.OutputCompression > 100 ||
		(outputFormat == "png" && request.OutputCompression != 100) {
		return statusErr{
			code:           http.StatusBadRequest,
			msg:            "chatgpt web does not support the requested image output compression",
			skipAuthResult: true,
			retryOtherAuth: true,
		}
	}
	references := append([]string(nil), request.Images...)
	if mask := strings.TrimSpace(request.MaskURL); mask != "" {
		references = append(references, mask)
	}
	allowRemote := len(remoteEnabled) > 0 && remoteEnabled[0]
	if err := validateChatGPTWebImageReferences(references, allowRemote); err != nil {
		return err
	}
	return nil
}

func prepareChatGPTWebImageMask(request *helps.ChatGPTWebImageRequest) error {
	return prepareChatGPTWebImageMaskWithLimits(request, chatGPTWebMaxImageBytes, chatGPTWebMaxImageRequestBytes)
}

func prepareChatGPTWebImageMaskWithLimits(request *helps.ChatGPTWebImageRequest, maxImageBytes, maxTotalBytes int) error {
	if request == nil || strings.TrimSpace(request.MaskURL) == "" {
		return nil
	}
	if len(request.Images) == 0 {
		return statusErr{code: http.StatusBadRequest, msg: "image mask requires an input image", skipAuthResult: true}
	}
	maskImageIndex := request.MaskImageIndex
	if maskImageIndex < 0 || maskImageIndex >= len(request.Images) {
		return statusErr{code: http.StatusBadRequest, msg: "image mask target is invalid", skipAuthResult: true}
	}
	composited, err := compositeChatGPTWebMask(request.Images[maskImageIndex], request.MaskURL)
	if err != nil {
		var unsupportedTool *helps.ChatGPTWebUnsupportedToolError
		return statusErr{
			code:           http.StatusBadRequest,
			msg:            err.Error(),
			skipAuthResult: true,
			retryOtherAuth: errors.As(err, &unsupportedTool),
		}
	}
	request.Images = append([]string(nil), request.Images...)
	request.Images[maskImageIndex] = composited
	request.MaskURL = ""
	if err := helps.ValidateChatGPTWebImageReferences(request.Images, maxImageBytes, maxTotalBytes); err != nil {
		return statusErr{
			code:           http.StatusRequestEntityTooLarge,
			msg:            err.Error(),
			skipAuthResult: true,
		}
	}
	return nil
}

func ignoreUnsupportedChatGPTWebImageParams(request *helps.ChatGPTWebImageRequest) {
	if request == nil {
		return
	}
	request.Size = ""
	if quality := strings.TrimSpace(request.Quality); quality != "" && !strings.EqualFold(quality, "auto") {
		request.Quality = "auto"
	}
	if outputFormat := normalizeChatGPTWebImageOutputFormat(request.OutputFormat); outputFormat != "png" && outputFormat != "jpeg" && outputFormat != "webp" {
		request.OutputFormat = "png"
		request.OutputCompression = 100
	} else if outputFormat == "png" && request.OutputCompression != 100 {
		request.OutputCompression = 100
	}
}

func (e *ChatGPTWebExecutor) chatGPTWebImageUpstreamModel() string {
	if cfg := e.configSnapshot(); cfg != nil {
		return cfg.Images.ChatGPTWeb.ResolvedUpstreamModel()
	}
	return config.DefaultChatGPTWebImageUpstreamModel
}

func chatGPTWebEncodedImageSize(value string, maxBytes int) (int, error) {
	return helps.ChatGPTWebEncodedImageSize(value, maxBytes)
}

func compositeChatGPTWebMask(imageURL, maskURL string) (string, error) {
	imageData, imageMIME, err := decodeChatGPTWebImageReference(imageURL)
	if err != nil {
		return "", err
	}
	maskData, maskMIME, err := decodeChatGPTWebImageReference(maskURL)
	if err != nil {
		return "", err
	}
	if imageMIME == "image/webp" || maskMIME == "image/webp" {
		return "", &helps.ChatGPTWebUnsupportedToolError{
			Message: "WebP mask compositing is not supported for ChatGPT Web; use PNG, JPEG, or GIF",
		}
	}
	sourceConfig, err := chatGPTWebImageConfig(imageData, imageMIME)
	if err != nil {
		return "", fmt.Errorf("decode input image dimensions: %w", err)
	}
	maskConfig, err := chatGPTWebImageConfig(maskData, maskMIME)
	if err != nil {
		return "", fmt.Errorf("decode image mask dimensions: %w", err)
	}
	if sourceConfig.Width != maskConfig.Width || sourceConfig.Height != maskConfig.Height {
		return "", errors.New("image mask dimensions must match the input image")
	}
	if err := validateChatGPTWebImageEditMemory(sourceConfig); err != nil {
		return "", err
	}
	source, _, err := image.Decode(bytes.NewReader(imageData))
	if err != nil {
		return "", fmt.Errorf("decode input image: %w", err)
	}
	mask, _, err := image.Decode(bytes.NewReader(maskData))
	if err != nil {
		return "", fmt.Errorf("decode image mask: %w", err)
	}
	bounds := source.Bounds()
	if mask.Bounds().Dx() != bounds.Dx() || mask.Bounds().Dy() != bounds.Dy() {
		return "", errors.New("image mask dimensions must match the input image")
	}
	result := &chatGPTWebMaskedImage{
		source: source,
		mask:   mask,
		bounds: image.Rect(0, 0, bounds.Dx(), bounds.Dy()),
	}
	var output strings.Builder
	output.WriteString("data:image/png;base64,")
	encoder := base64.NewEncoder(base64.StdEncoding, &output)
	if err := png.Encode(encoder, result); err != nil {
		return "", fmt.Errorf("encode masked image: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return "", fmt.Errorf("finish masked image encoding: %w", err)
	}
	return output.String(), nil
}

func validateChatGPTWebImageEditMemory(config image.Config) error {
	pixels := int64(config.Width) * int64(config.Height)
	if pixels > int64(chatGPTWebMaxImageEditDecodedBytes/chatGPTWebImageEditBytesPerPixel) {
		return fmt.Errorf("image edit decoded data exceeds %d bytes", chatGPTWebMaxImageEditDecodedBytes)
	}
	return nil
}

type chatGPTWebMaskedImage struct {
	source image.Image
	mask   image.Image
	bounds image.Rectangle
}

func (*chatGPTWebMaskedImage) ColorModel() color.Model {
	return color.NRGBAModel
}

func (masked *chatGPTWebMaskedImage) Bounds() image.Rectangle {
	return masked.bounds
}

func (masked *chatGPTWebMaskedImage) At(x, y int) color.Color {
	sourceBounds := masked.source.Bounds()
	maskBounds := masked.mask.Bounds()
	sourceColor := color.NRGBAModel.Convert(masked.source.At(
		sourceBounds.Min.X+x-masked.bounds.Min.X,
		sourceBounds.Min.Y+y-masked.bounds.Min.Y,
	)).(color.NRGBA)
	_, _, _, maskAlpha := masked.mask.At(
		maskBounds.Min.X+x-masked.bounds.Min.X,
		maskBounds.Min.Y+y-masked.bounds.Min.Y,
	).RGBA()
	sourceColor.A = uint8((uint32(sourceColor.A)*maskAlpha + 0x7fff) / 0xffff)
	return sourceColor
}

func filterChatGPTWebInputImageIDs(accumulator *helps.ChatGPTWebImageAccumulator, inputIDs map[string]struct{}) {
	filtered := accumulator.FileIDs[:0]
	for _, fileID := range accumulator.FileIDs {
		if _, input := inputIDs[fileID]; input {
			continue
		}
		filtered = append(filtered, fileID)
	}
	accumulator.FileIDs = filtered
	filteredReferences := accumulator.References[:0]
	for _, reference := range accumulator.References {
		if reference.Kind == "file" {
			if _, input := inputIDs[reference.ID]; input {
				continue
			}
		}
		filteredReferences = append(filteredReferences, reference)
	}
	accumulator.References = filteredReferences
}

func normalizeChatGPTWebImageOutputFormat(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "png"
	case "jpg", "jpeg":
		return "jpeg"
	case "png", "gif", "webp":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func chatGPTWebImageOutputFormat(data []byte) string {
	if len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP" {
		return "webp"
	}
	switch http.DetectContentType(data) {
	case "image/png":
		return "png"
	case "image/jpeg":
		return "jpeg"
	case "image/gif":
		return "gif"
	case "image/webp":
		return "webp"
	default:
		return ""
	}
}

func extensionForChatGPTWebMIME(mimeType string) string {
	switch strings.ToLower(strings.TrimSpace(mimeType)) {
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	default:
		extensions, _ := mime.ExtensionsByType(mimeType)
		if len(extensions) > 0 {
			return extensions[0]
		}
		return ""
	}
}

func firstChatGPTWebURL(payload []byte) string {
	var root map[string]any
	if err := json.Unmarshal(payload, &root); err != nil {
		return ""
	}
	for _, key := range []string{"download_url", "url"} {
		if value := strings.TrimSpace(fmt.Sprint(root[key])); value != "" && value != "<nil>" {
			return value
		}
	}
	return ""
}

func gjsonString(payload []byte, path string) string {
	var root map[string]any
	if err := json.Unmarshal(payload, &root); err != nil {
		return ""
	}
	value := root[path]
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func statusCodeFromError(err error) int {
	var status interface{ StatusCode() int }
	if errors.As(err, &status) && status != nil {
		return status.StatusCode()
	}
	return 0
}
