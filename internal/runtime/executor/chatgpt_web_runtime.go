package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	fhttp "github.com/bogdanfinn/fhttp"
	fhttptrace "github.com/bogdanfinn/fhttp/httptrace"
	"github.com/google/uuid"
	chatgptwebauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/chatgptweb"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/sentinelcompat"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/thinking"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	chatGPTWebClientVersion         = "prod-a194cd50d4416d3c0b47c740f206b12ce60f5887"
	chatGPTWebClientBuildNumber     = "6708908"
	chatGPTWebSearchModel           = "gpt-5-5"
	chatGPTWebSSEMaxFrameBytes      = 50 << 20
	chatGPTWebMaxErrorBodyBytes     = 1 << 20
	chatGPTWebMaxJSONBodyBytes      = 32 << 20
	chatGPTWebMaxHTMLBodyBytes      = 16 << 20
	chatGPTWebMaxBootstrapRedirects = 5
	chatGPTWebChallengeInspectBytes = 64 << 10
)

type chatGPTWebChallengeInspectingBody struct {
	io.ReadCloser
	status  int
	path    string
	headers fhttp.Header
	prefix  []byte
}

func (body *chatGPTWebChallengeInspectingBody) Read(payload []byte) (int, error) {
	read, errRead := body.ReadCloser.Read(payload)
	if read > 0 && len(body.prefix) < chatGPTWebChallengeInspectBytes {
		remaining := chatGPTWebChallengeInspectBytes - len(body.prefix)
		if read < remaining {
			remaining = read
		}
		body.prefix = append(body.prefix, payload[:remaining]...)
	}
	return read, errRead
}

func (body *chatGPTWebChallengeInspectingBody) challengeError() error {
	if body == nil {
		return nil
	}
	return newChatGPTWebChallengeResponseError(body.status, body.path, body.prefix, body.headers)
}

type chatGPTWebPreparedRequest struct {
	sentinelPolicy         *sentinelcompat.Policy
	bootstrapPolicy        cliproxyexecutor.ImageBootstrapPolicy
	baseModel              string
	routeModel             string
	responseFormat         sdktranslator.Format
	originalPayload        []byte
	canonicalBody          []byte
	request                helps.ChatGPTWebRequest
	terminalMarker         bool
	trustUpstreamSSE       bool
	maxImageResults        int
	usageProjection        *helps.ChatGPTWebUsageProjection
	usageProjectionOn      bool
	usageProjectionOpts    helps.ChatGPTWebUsageCacheOptions
	imageFallbackUsage     config.ResolvedChatGPTWebImageFallbackUsageConfig
	imageConfigSnapshot    cliproxyexecutor.ChatGPTWebImageConfigSnapshot
	imageSizeMatch         *helps.ChatGPTWebImageSizeMatch
	bodyRelease            *cliproxyexecutor.RequestBodyReleaseController
	imageResultState       *cliproxyexecutor.ImageGenerationResultState
	executionDiagnostics   *cliproxyexecutor.RequestExecutionDiagnostics
	requestUsageOutcome    *cliproxyexecutor.RequestUsageOutcome
	imageMemoryLeases      *helps.ChatGPTWebImageMemoryLeaseSet
	imageMemoryLeasesOwned bool
	phaseObserver          cliproxyexecutor.RequestPhaseObserver
}

type chatGPTWebRequirements struct {
	Token          string
	ProofToken     string
	TurnstileToken string
	SOToken        string
}

type chatGPTWebTextResult struct {
	Text    string
	Query   string
	Sources []chatGPTWebSearchSource
	Search  bool
	Usage   map[string]any
}

type chatGPTWebSearchSource struct {
	Title string `json:"title,omitempty"`
	URL   string `json:"url"`
}

func commitChatGPTWebAuthRequestSlot(opts cliproxyexecutor.Options) {
	if opts.AuthRequestSlot != nil {
		opts.AuthRequestSlot.Commit()
	}
}

func (e *ChatGPTWebExecutor) currentChatGPTWebImageConfig() config.ResolvedChatGPTWebImageConfig {
	if cfg := e.configSnapshot(); cfg != nil {
		return cfg.Images.ChatGPTWeb.Resolved()
	}
	return config.ChatGPTWebImageConfig{}.Resolved()
}

func (e *ChatGPTWebExecutor) acquireChatGPTWebImageLifecycle(ctx context.Context, prepared *chatGPTWebPreparedRequest) (func(), error) {
	resolved := e.currentChatGPTWebImageConfig()
	admissionWait, errWait := config.ChatGPTWebImageAdmissionWaitDuration(resolved.AdmissionWaitMilliseconds)
	if errWait != nil {
		return nil, cliproxyexecutor.NewImageExecutionCapacityError("invalid_admission_wait")
	}
	started := time.Now()
	releaseExecution, err := cliproxyexecutor.AcquireChatGPTWebImageExecution(
		ctx,
		admissionWait,
	)
	cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseExecutionAdmission, started)
	if err != nil {
		return nil, err
	}
	reserveBytes, errReserve := config.ChatGPTWebImageMegabytesToBytes(resolved.CompletionReserveMegabytes)
	if errReserve != nil {
		releaseExecution()
		return nil, cliproxyexecutor.NewImageExecutionCapacityError("invalid_completion_reserve")
	}
	if prepared != nil && prepared.imageMemoryLeases != nil && !prepared.imageMemoryLeases.TryReserveCompletion(reserveBytes) {
		releaseExecution()
		return nil, cliproxyexecutor.NewImageExecutionCapacityError("completion_memory")
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			if prepared != nil && prepared.imageMemoryLeasesOwned && prepared.imageMemoryLeases != nil {
				prepared.imageMemoryLeases.Release()
			}
			releaseExecution()
		})
	}, nil
}

type chatGPTWebFailureStageProvider interface {
	ChatGPTWebFailureStage() string
}

type chatGPTWebFailureStageError struct {
	stage string
	cause error
}

func (e *chatGPTWebFailureStageError) Error() string {
	if e == nil || e.cause == nil {
		return ""
	}
	return e.cause.Error()
}

func (e *chatGPTWebFailureStageError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *chatGPTWebFailureStageError) ChatGPTWebFailureStage() string {
	if e == nil {
		return ""
	}
	return e.stage
}

func withChatGPTWebFailureStage(stage string, err error) error {
	if err == nil {
		return nil
	}
	var existing chatGPTWebFailureStageProvider
	if errors.As(err, &existing) && strings.TrimSpace(existing.ChatGPTWebFailureStage()) != "" {
		return err
	}
	return &chatGPTWebFailureStageError{stage: strings.TrimSpace(stage), cause: err}
}

func preserveChatGPTWebFailureStage(original, normalized error) error {
	if normalized == nil {
		return nil
	}
	var originalStage chatGPTWebFailureStageProvider
	if !errors.As(original, &originalStage) {
		return normalized
	}
	stage := strings.TrimSpace(originalStage.ChatGPTWebFailureStage())
	if stage == "" {
		return normalized
	}
	var normalizedStage chatGPTWebFailureStageProvider
	if errors.As(normalized, &normalizedStage) && strings.TrimSpace(normalizedStage.ChatGPTWebFailureStage()) == stage {
		return normalized
	}
	return &chatGPTWebFailureStageError{stage: stage, cause: normalized}
}

func recordChatGPTWebExecutionFailure(diagnostics *cliproxyexecutor.RequestExecutionDiagnostics, err error) {
	if diagnostics == nil || err == nil {
		return
	}
	stage := "selection"
	if diagnostics.CurrentAttemptCommitted() {
		stage = "upstream"
	} else if !diagnostics.Snapshot().CredentialSelected {
		stage = "preflight"
	}
	var stageProvider chatGPTWebFailureStageProvider
	if errors.As(err, &stageProvider) {
		if value := strings.TrimSpace(stageProvider.ChatGPTWebFailureStage()); value != "" {
			stage = value
		}
	}
	code := "chatgpt_web_request_failed"
	var authError *chatgptwebauth.AuthError
	if errors.As(err, &authError) && authError != nil {
		// Authentication lifecycle stages are provider-internal diagnostics.
		// Usage exposes only the request contract stages selected above, while an
		// explicit outer image stage must take precedence over the wrapped error.
		safeCode := authError.DiagnosticCode
		if strings.TrimSpace(safeCode) == "" {
			safeCode = authError.Code
		}
		if value := strings.TrimSpace(chatgptwebauth.SafeDiagnosticCode(safeCode)); value != "" {
			code = value
		}
	} else {
		var coded interface{ ExecutionResultErrorCode() string }
		if errors.As(err, &coded) && coded != nil && strings.TrimSpace(coded.ExecutionResultErrorCode()) != "" {
			code = strings.TrimSpace(coded.ExecutionResultErrorCode())
			diagnostics.SetFailure(stage, code)
			return
		}
		var status interface{ StatusCode() int }
		if errors.As(err, &status) {
			code = fmt.Sprintf("http_%d", status.StatusCode())
		}
	}
	diagnostics.SetFailure(stage, code)
}

func publishChatGPTWebStreamFailure(ctx context.Context, reporter *helps.UsageReporter, diagnostics *cliproxyexecutor.RequestExecutionDiagnostics, err error) {
	if reporter == nil || err == nil {
		return
	}
	recordChatGPTWebExecutionFailure(diagnostics, err)
	reporter.PublishFailure(ctx, err)
}

func chatGPTWebStreamDeliveryError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("chatgpt web downstream stream closed")
}

func (e *ChatGPTWebExecutor) executeRuntime(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	var outcomePersona chatgptwebauth.Persona
	var reporter *helps.UsageReporter
	defer func() {
		recordChatGPTWebExecutionFailure(opts.ExecutionDiagnostics, err)
		if reporter != nil && err != nil {
			reporter.PublishFailure(ctx, err)
		}
		logChatGPTWebSafeDiagnostic(ctx, auth, err)
		e.recordPersonaOutcome(auth, outcomePersona, err)
	}()
	if selectedAuthInstanceRetired(opts) {
		return resp, errXAIWebsocketSessionTerminated
	}
	prepared, err := e.prepareRuntimeRequest(ctx, auth, req, opts, false)
	if err != nil {
		return resp, err
	}
	defer prepared.discardUsageProjection()
	hasRemoteImages := chatGPTWebPreparedRequestHasRemoteImages(prepared)
	if (prepared.request.Image != nil || hasRemoteImages) && prepared.imageMemoryLeases == nil {
		prepared.imageMemoryLeases = helps.NewChatGPTWebImageMemoryLeaseSet()
		prepared.imageMemoryLeasesOwned = true
	}
	if prepared.request.Image == nil && prepared.imageMemoryLeasesOwned && prepared.imageMemoryLeases != nil {
		defer prepared.imageMemoryLeases.Release()
	}
	ctx = helps.WithChatGPTWebImageMemoryLeaseSet(ctx, prepared.imageMemoryLeases)
	ctx = cliproxyexecutor.WithRequestPhaseObserver(ctx, prepared.phaseObserver)
	reporter = helps.NewExecutorUsageReporter(ctx, e, prepared.routeModel, auth)
	reporter.SetExecutionDiagnostics(opts.ExecutionDiagnostics)
	reporter.SetRequestUsageOutcome(opts.UsageOutcome)
	reporter.SetTranslatedReasoningEffort(prepared.canonicalBody, e.Identifier())
	var releaseImageLifecycle func()
	var imageTask *chatGPTWebImageTaskHandle
	if prepared.request.Image != nil {
		releaseImageLifecycle, err = e.acquireChatGPTWebImageLifecycle(ctx, prepared)
		if err != nil {
			return resp, err
		}
		defer releaseImageLifecycle()
		ctx, imageTask = beginChatGPTWebImageTask(ctx, auth.ID)
		defer imageTask.finish()
		defer func() { err = normalizeChatGPTWebImageTaskCancellation(ctx, err) }()
	}
	if hasRemoteImages {
		setChatGPTWebImageTaskStage(ctx, "materializing_inputs")
		if err = e.materializeChatGPTWebRemoteImages(ctx, auth, prepared); err != nil {
			return resp, err
		}
	}

	setChatGPTWebImageTaskStage(ctx, "creating_client")
	client, credential, err := e.newRuntimeClientForRequest(ctx, auth)
	if err != nil {
		return resp, err
	}
	client.SetBeforeRequestHook(func() {
		cliproxyexecutor.MarkUpstreamAttempt(ctx)
		commitChatGPTWebAuthRequestSlot(opts)
	})
	outcomePersona = credential.Persona
	defer e.finishChatGPTWebRuntimeClient(ctx, auth, credential, client)

	if prepared.request.Image != nil {
		completed, headers, errImage := e.executeChatGPTWebImage(ctx, client, credential, prepared)
		if errImage != nil {
			e.scheduleChatGPTWebLibraryCleanup(ctx, auth, prepared, errImage)
			return resp, e.handleChatGPTWebImageRequestError(auth.ID, errImage)
		}
		publishChatGPTWebTerminalUsage(ctx, reporter, prepared, completed)
		var param any
		out := sdktranslator.TranslateNonStream(ctx, sdktranslator.FormatCodex, prepared.responseFormat, prepared.routeModel,
			prepared.originalPayload, prepared.canonicalBody, completed, &param)
		return cliproxyexecutor.Response{Payload: out, Headers: headers}, nil
	}

	result, headers, errText := e.executeChatGPTWebText(ctx, client, credential, prepared)
	if errText != nil {
		return resp, errText
	}
	result.Usage = e.completeChatGPTWebUsage(prepared, result.Text, nil)
	completed := buildChatGPTWebCompletedEvent(prepared.routeModel, result)
	publishChatGPTWebTerminalUsage(ctx, reporter, prepared, completed)
	var param any
	out := sdktranslator.TranslateNonStream(ctx, sdktranslator.FormatCodex, prepared.responseFormat, prepared.routeModel,
		prepared.originalPayload, prepared.canonicalBody, completed, &param)
	return cliproxyexecutor.Response{Payload: out, Headers: headers}, nil
}

func (e *ChatGPTWebExecutor) executeRuntimeStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	var outcomePersona chatgptwebauth.Persona
	defer func() {
		logChatGPTWebSafeDiagnostic(ctx, auth, err)
		e.recordPersonaOutcome(auth, outcomePersona, err)
	}()
	if selectedAuthInstanceRetired(opts) {
		return nil, errXAIWebsocketSessionTerminated
	}
	prepared, err := e.prepareRuntimeRequest(ctx, auth, req, opts, true)
	if err != nil {
		return nil, err
	}
	hasRemoteImages := chatGPTWebPreparedRequestHasRemoteImages(prepared)
	if (prepared.request.Image != nil || hasRemoteImages) && prepared.imageMemoryLeases == nil {
		prepared.imageMemoryLeases = helps.NewChatGPTWebImageMemoryLeaseSet()
		prepared.imageMemoryLeasesOwned = true
	}
	if prepared.request.Image == nil && prepared.imageMemoryLeasesOwned && prepared.imageMemoryLeases != nil {
		defer prepared.imageMemoryLeases.Release()
	}
	ctx = helps.WithChatGPTWebImageMemoryLeaseSet(ctx, prepared.imageMemoryLeases)
	ctx = cliproxyexecutor.WithRequestPhaseObserver(ctx, prepared.phaseObserver)
	reporter := helps.NewExecutorUsageReporter(ctx, e, prepared.routeModel, auth)
	reporter.SetExecutionDiagnostics(opts.ExecutionDiagnostics)
	reporter.SetRequestUsageOutcome(opts.UsageOutcome)
	reporter.SetTranslatedReasoningEffort(prepared.canonicalBody, e.Identifier())
	defer func() {
		if err != nil {
			recordChatGPTWebExecutionFailure(opts.ExecutionDiagnostics, err)
			reporter.PublishFailure(ctx, err)
		}
	}()
	passthroughState, _ := opts.Metadata[cliproxyexecutor.ImageGenerationStreamPassthroughStateMetadataKey].(*cliproxyexecutor.ImageGenerationStreamPassthroughState)
	if passthroughState != nil {
		passthroughState.SetEnabled(false)
	}
	var releaseImageLifecycle func()
	var releaseImageWork func()
	if prepared.request.Image != nil {
		releaseImageLifecycle, err = e.acquireChatGPTWebImageLifecycle(ctx, prepared)
		if err != nil {
			prepared.discardUsageProjection()
			return nil, err
		}
		var imageTask *chatGPTWebImageTaskHandle
		ctx, imageTask = beginChatGPTWebImageTask(ctx, auth.ID)
		defer func() { err = normalizeChatGPTWebImageTaskCancellation(ctx, err) }()
		var cleanupOnce sync.Once
		releaseImageWork = func() {
			cleanupOnce.Do(func() {
				imageTask.finish()
				releaseImageLifecycle()
			})
		}
	}
	if hasRemoteImages {
		setChatGPTWebImageTaskStage(ctx, "materializing_inputs")
		if err = e.materializeChatGPTWebRemoteImages(ctx, auth, prepared); err != nil {
			if releaseImageWork != nil {
				releaseImageWork()
			}
			prepared.discardUsageProjection()
			return nil, err
		}
	}
	setChatGPTWebImageTaskStage(ctx, "creating_client")
	client, credential, err := e.newRuntimeClientForRequest(ctx, auth)
	if err != nil {
		if releaseImageWork != nil {
			releaseImageWork()
		}
		prepared.discardUsageProjection()
		return nil, err
	}
	client.SetBeforeRequestHook(func() {
		cliproxyexecutor.MarkUpstreamAttempt(ctx)
		commitChatGPTWebAuthRequestSlot(opts)
	})
	outcomePersona = credential.Persona

	if prepared.request.Image != nil {
		imageStreamPassthrough := metadataBool(opts.Metadata, cliproxyexecutor.ImageGenerationStreamPassthroughMetadataKey)
		execution, errImage := e.beginChatGPTWebImage(ctx, client, credential, prepared)
		if errImage != nil {
			e.scheduleChatGPTWebLibraryCleanup(ctx, auth, prepared, errImage)
			releaseImageWork()
			prepared.discardUsageProjection()
			e.finishChatGPTWebRuntimeClient(ctx, auth, credential, client)
			return nil, e.handleChatGPTWebImageRequestError(auth.ID, errImage)
		}
		return e.streamDeferredChatGPTWebResponse(ctx, auth, credential, prepared, client, reporter, execution.headers, passthroughState, imageStreamPassthrough, releaseImageWork, func() ([]byte, error) {
			completed, errFinish := e.finishChatGPTWebImage(ctx, client, credential, prepared, execution)
			errFinish = normalizeChatGPTWebImageTaskCancellation(ctx, errFinish)
			return completed, chatGPTWebCommittedRequestError(ctx, e.handleChatGPTWebImageRequestError(auth.ID, errFinish))
		}), nil
	}

	if chatGPTWebRequestUsesSearch(prepared) {
		execution, errSearch := e.beginChatGPTWebSearch(ctx, client, credential, prepared)
		if errSearch != nil {
			prepared.discardUsageProjection()
			e.finishChatGPTWebRuntimeClient(ctx, auth, credential, client)
			return nil, errSearch
		}
		return e.streamDeferredChatGPTWebResponse(ctx, auth, credential, prepared, client, reporter, execution.headers, nil, false, nil, func() ([]byte, error) {
			result, errFinish := e.finishChatGPTWebSearch(ctx, client, credential, execution)
			if errFinish != nil {
				return nil, chatGPTWebCommittedRequestError(ctx, errFinish)
			}
			result.Usage = e.completeChatGPTWebUsage(prepared, result.Text, nil)
			return buildChatGPTWebCompletedEvent(prepared.routeModel, result), nil
		}), nil
	}

	response, accumulator, errOpen := e.openChatGPTWebConversation(ctx, client, credential, prepared)
	if errOpen != nil {
		prepared.discardUsageProjection()
		e.finishChatGPTWebRuntimeClient(ctx, auth, credential, client)
		return nil, errOpen
	}
	headers := cloneChatGPTWebHeaders(response.Header)
	if opts.UsageOutcome != nil {
		opts.UsageOutcome.AcceptStreamAttempt(cliproxyexecutor.RequestUsageAttemptFromContext(ctx))
	}
	out := make(chan cliproxyexecutor.StreamChunk, cliproxyexecutor.StreamBufferSize)
	go func() {
		defer close(out)
		defer prepared.discardUsageProjection()
		defer e.finishChatGPTWebRuntimeClient(ctx, auth, credential, client)
		defer func() {
			if errClose := response.Body.Close(); errClose != nil {
				log.Errorf("chatgpt web executor: close response body: %v", errClose)
			}
		}()
		if !sendChatGPTWebStreamChunk(ctx, out, cliproxyexecutor.BootstrapCommitStreamChunk()) {
			publishChatGPTWebStreamFailure(ctx, reporter, opts.ExecutionDiagnostics, chatGPTWebStreamDeliveryError(ctx))
			return
		}
		responseID := "resp_" + strings.ReplaceAll(uuid.NewString(), "-", "")
		messageID := "msg_" + strings.ReplaceAll(uuid.NewString(), "-", "")
		sequencer := &chatGPTWebEventSequencer{}
		var param any
		emit := func(event []byte) bool {
			event = sequencer.Next(event)
			chunks := sdktranslator.TranslateStream(ctx, sdktranslator.FormatCodex, prepared.responseFormat, prepared.routeModel,
				prepared.originalPayload, prepared.canonicalBody, append([]byte("data: "), event...), &param)
			for _, chunk := range chunks {
				chunk = chatGPTWebTrustedSSEFrame(chunk, prepared.trustUpstreamSSE)
				if !sendChatGPTWebStreamChunk(ctx, out, cliproxyexecutor.StreamChunk{Payload: chunk}) {
					return false
				}
			}
			return true
		}
		started := false
		emitStart := func() bool {
			if started {
				return true
			}
			if !emit(buildChatGPTWebCreatedEvent(responseID, prepared.routeModel)) {
				return false
			}
			if !emit(buildChatGPTWebInProgressEvent(responseID, prepared.routeModel)) {
				return false
			}
			for _, event := range buildChatGPTWebMessageAddedEvents(responseID, messageID, 0) {
				if !emit(event) {
					return false
				}
			}
			started = true
			return true
		}

		deltaCh := make(chan string)
		resultCh := make(chan error, 1)
		go func() {
			errConsume := consumeChatGPTWebConversation(ctx, response.Body, accumulator, func(delta string) bool {
				if ctx == nil {
					deltaCh <- delta
					return true
				}
				select {
				case deltaCh <- delta:
					return true
				case <-ctx.Done():
					return false
				}
			})
			resultCh <- errConsume
		}()

		initialWait := e.streamInitialWait
		if initialWait < 0 {
			initialWait = 0
		}
		initialTimer := time.NewTimer(initialWait)
		defer initialTimer.Stop()
		var heartbeatTicker *time.Ticker
		var heartbeat <-chan time.Time
		var contextDone <-chan struct{}
		if ctx != nil {
			contextDone = ctx.Done()
		}
		defer func() {
			if heartbeatTicker != nil {
				heartbeatTicker.Stop()
			}
		}()
		sendHeartbeat := func() bool {
			return sendChatGPTWebStreamChunk(ctx, out, cliproxyexecutor.StreamChunk{Payload: chatGPTWebDeferredHeartbeat(prepared, "", 0)})
		}

		for {
			select {
			case delta := <-deltaCh:
				if !emitStart() || !emit(buildChatGPTWebTextDeltaEvent(responseID, messageID, 0, delta)) {
					publishChatGPTWebStreamFailure(ctx, reporter, opts.ExecutionDiagnostics, chatGPTWebStreamDeliveryError(ctx))
					return
				}
			case errConsume := <-resultCh:
				if challengeErr := chatGPTWebStreamChallengeError(response); challengeErr != nil {
					errConsume = challengeErr
				}
				if errConsume != nil {
					errConsume = chatGPTWebCommittedRequestError(ctx, chatGPTWebUpstreamProtocolError(ctx, errConsume))
					errConsume = e.handleChatGPTWebRuntimeLifecycleError(ctx, auth, errConsume)
					logChatGPTWebSafeDiagnostic(ctx, auth, errConsume)
					publishChatGPTWebStreamFailure(ctx, reporter, opts.ExecutionDiagnostics, errConsume)
					_ = sendChatGPTWebStreamChunk(ctx, out, cliproxyexecutor.StreamChunk{Err: errConsume})
					return
				}
				if !emitStart() {
					publishChatGPTWebStreamFailure(ctx, reporter, opts.ExecutionDiagnostics, chatGPTWebStreamDeliveryError(ctx))
					return
				}
				text := accumulator.Text()
				usage := e.completeChatGPTWebUsage(prepared, text, nil)
				terminalEvents := buildChatGPTWebTerminalEvents(responseID, messageID, prepared.routeModel, text, nil, "", false, usage)
				for _, event := range terminalEvents {
					if !emit(event) {
						publishChatGPTWebStreamFailure(ctx, reporter, opts.ExecutionDiagnostics, chatGPTWebStreamDeliveryError(ctx))
						return
					}
				}
				publishChatGPTWebTerminalUsage(ctx, reporter, prepared, terminalEvents[len(terminalEvents)-1])
				if metadataBool(opts.Metadata, cliproxyexecutor.StreamTerminalMarkerMetadataKey) {
					_ = sendChatGPTWebStreamChunk(ctx, out, cliproxyexecutor.SuccessfulStreamTerminalChunk())
				}
				return
			case <-initialTimer.C:
				if !sendHeartbeat() {
					publishChatGPTWebStreamFailure(ctx, reporter, opts.ExecutionDiagnostics, chatGPTWebStreamDeliveryError(ctx))
					return
				}
				if e.streamHeartbeat > 0 {
					heartbeatTicker = time.NewTicker(e.streamHeartbeat)
					heartbeat = heartbeatTicker.C
				}
			case <-heartbeat:
				if !sendHeartbeat() {
					publishChatGPTWebStreamFailure(ctx, reporter, opts.ExecutionDiagnostics, chatGPTWebStreamDeliveryError(ctx))
					return
				}
			case <-contextDone:
				publishChatGPTWebStreamFailure(ctx, reporter, opts.ExecutionDiagnostics, chatGPTWebStreamDeliveryError(ctx))
				return
			}
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: headers, Chunks: out}, nil
}

func (e *ChatGPTWebExecutor) prepareRuntimeRequest(ctx context.Context, _ *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, stream bool) (*chatGPTWebPreparedRequest, error) {
	if opaque, ok := cliproxyexecutor.ProviderPreparedRequest(opts, e.Identifier()); ok {
		if template, okTemplate := opaque.(*chatGPTWebPreparedRequest); okTemplate {
			effectiveModel := strings.TrimSpace(thinking.ParseSuffix(req.Model).ModelName)
			if template.baseModel == effectiveModel {
				return e.instantiateRuntimeRequest(template, opts)
			}
		}
	}
	template, err := e.prepareRuntimeRequestTemplate(ctx, req, opts, stream)
	if err != nil {
		return nil, err
	}
	return e.instantiateRuntimeRequest(template, opts)
}

func (e *ChatGPTWebExecutor) prepareRuntimeRequestTemplate(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, stream bool) (*chatGPTWebPreparedRequest, error) {
	baseModel := strings.TrimSpace(thinking.ParseSuffix(req.Model).ModelName)
	routeModel := strings.TrimSpace(helps.PayloadRequestedModel(opts, req.Model))
	if routeModel == "" {
		routeModel = baseModel
	}
	originalSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalSource = opts.OriginalRequest
	}
	rawRequestBytes := max(len(req.Payload), len(originalSource))
	if rawRequestBytes > helps.ChatGPTWebMaxRequestBytes {
		return nil, statusErr{
			code:           http.StatusRequestEntityTooLarge,
			msg:            fmt.Sprintf("chatgpt web request exceeds %d bytes", helps.ChatGPTWebMaxRequestBytes),
			skipAuthResult: true,
		}
	}
	if rawRequestBytes > helps.ChatGPTWebMaxTextRequestBytes &&
		!chatGPTWebRawRequestHasImageInputs(req.Payload, opts.SourceFormat) &&
		!chatGPTWebRawRequestHasImageInputs(originalSource, opts.SourceFormat) {
		return nil, statusErr{
			code:           http.StatusRequestEntityTooLarge,
			msg:            fmt.Sprintf("chatgpt web text request exceeds %d bytes", helps.ChatGPTWebMaxTextRequestBytes),
			skipAuthResult: true,
		}
	}
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
	canonicalBody, err := sdktranslator.TranslateRequestChecked(opts.SourceFormat, sdktranslator.FormatCodex, baseModel, req.Payload, stream)
	if err != nil {
		return nil, err
	}
	canonicalBody, err = thinking.ApplyThinking(canonicalBody, req.Model, opts.SourceFormat.String(), e.Identifier(), e.Identifier())
	if err != nil {
		return nil, err
	}
	cfg := e.configSnapshot()
	sentinelPolicy := chatGPTWebSentinelPolicy(cfg)
	bootstrapPolicy, bootstrapPinned := cliproxyexecutor.ImageBootstrapPolicyFromContext(ctx)
	if !bootstrapPinned && cfg != nil {
		bootstrapPolicy = cliproxyexecutor.ImageBootstrapPolicy{Timeout: time.Duration(cfg.Images.ChatGPTWeb.BootstrapTimeoutSeconds) * time.Second, Retries: cfg.Images.ChatGPTWeb.BootstrapRetries}
	}
	if opaque, ok := cliproxyexecutor.ProviderPreparedRequest(opts, e.Identifier()); ok {
		if previous, ok := opaque.(*chatGPTWebPreparedRequest); ok {
			sentinelPolicy = previous.sentinelPolicy
			bootstrapPolicy = previous.bootstrapPolicy
		}
	}
	resolvedImageConfig := config.ChatGPTWebImageConfig{}.Resolved()
	if cfg != nil {
		resolvedImageConfig = cfg.Images.ChatGPTWeb.Resolved()
	}
	imageConfigSnapshot := cliproxyexecutor.ChatGPTWebImageConfigSnapshot{
		AutoCleanupLibraryOnFull:     resolvedImageConfig.AutoCleanupLibraryOnFull,
		RemoteImageURLEnabled:        resolvedImageConfig.RemoteImageURLEnabled,
		RemoteImageURLDownloadMode:   resolvedImageConfig.RemoteImageURLDownloadMode,
		NormalizeMismatchedImageMIME: resolvedImageConfig.NormalizeMismatchedImageMIME,
		NormalizeRemoteImageMIME:     resolvedImageConfig.NormalizeRemoteImageMIME,
		AdaptSizeToAspectRatio:       resolvedImageConfig.AdaptSizeToAspectRatio,
		StrictSize:                   resolvedImageConfig.StrictSize,
		AspectRatioMaxErrorPercent:   resolvedImageConfig.AspectRatioMaxErrorPercent,
		MaxResizeEdgePixels:          resolvedImageConfig.MaxResizeEdgePixels,
		ResizeToRequestedSize:        resolvedImageConfig.ResizeToRequestedSize,
		ResizeFilter:                 resolvedImageConfig.ResizeFilter,
		MaxImageResponseBytes:        resolvedImageConfig.MaxImageResponseMegabytes << 20,
		MaxN:                         resolvedImageConfig.MaxN,
	}
	if pinned, ok := opts.Metadata[cliproxyexecutor.ChatGPTWebImageConfigSnapshotMetadataKey].(cliproxyexecutor.ChatGPTWebImageConfigSnapshot); ok {
		imageConfigSnapshot = pinned
	}
	canonicalBody = helps.ApplyPayloadConfigWithRequest(cfg, baseModel, sdktranslator.FormatCodex.String(), opts.SourceFormat.String(), "",
		canonicalBody, originalSource, routeModel, helps.PayloadRequestPath(opts), opts.Headers)
	forcedTool := ""
	if chatGPTWebSearchAlias(routeModel) || chatGPTWebOriginalRequestUsesSearch(opts.OriginalRequest) {
		forcedTool = "search"
	}
	ignoreUnsupportedImageParams := cfg != nil && cfg.Images.ChatGPTWeb.IgnoreUnsupportedParams
	if pinned, ok := opts.Metadata[cliproxyexecutor.ChatGPTWebIgnoreUnsupportedImageParamsMetadataKey].(bool); ok {
		ignoreUnsupportedImageParams = pinned
	}
	parsed, err := helps.ParseChatGPTWebRequestWithOptions(canonicalBody, helps.ChatGPTWebParseOptions{
		ForcedTool:                   forcedTool,
		IgnoreUnsupportedImageParams: ignoreUnsupportedImageParams,
	})
	if err != nil {
		return nil, statusErr{
			code:           http.StatusBadRequest,
			msg:            err.Error(),
			skipAuthResult: true,
			retryOtherAuth: helps.IsChatGPTWebProviderUnsupported(err),
		}
	}
	if imageConfigSnapshot.NormalizeMismatchedImageMIME {
		if err = normalizeChatGPTWebRequestImageMIME(&parsed); err != nil {
			return nil, statusErr{code: http.StatusBadRequest, msg: err.Error(), skipAuthResult: true}
		}
	}
	if parsed.Model == "" {
		parsed.Model = baseModel
	}
	if rawRequestBytes > helps.ChatGPTWebMaxTextRequestBytes && !chatGPTWebRequestHasImageInputs(parsed) {
		return nil, statusErr{
			code:           http.StatusRequestEntityTooLarge,
			msg:            fmt.Sprintf("chatgpt web text request exceeds %d bytes", helps.ChatGPTWebMaxTextRequestBytes),
			skipAuthResult: true,
		}
	}
	if parsed.WebSearch && parsed.Image != nil {
		return nil, statusErr{
			code:           http.StatusBadRequest,
			msg:            "chatgpt web cannot combine web search and image generation in one request",
			skipAuthResult: true,
			retryOtherAuth: true,
		}
	}
	var imageSizeMatch *helps.ChatGPTWebImageSizeMatch
	if parsed.Image != nil && imageConfigSnapshot.AdaptSizeToAspectRatio {
		match, disposition := helps.ResolveChatGPTWebImageSize(parsed.Image.Size, imageConfigSnapshot.MaxResizeEdgePixels)
		switch disposition {
		case helps.ChatGPTWebImageSizeMatched:
			imageSizeMatch = &match
			parsed.Image.Size = ""
		case helps.ChatGPTWebImageSizeUnspecified:
			parsed.Image.Size = ""
		case helps.ChatGPTWebImageSizeIgnored, helps.ChatGPTWebImageSizeInvalid:
			if imageConfigSnapshot.StrictSize {
				return nil, statusErr{
					code:           http.StatusBadRequest,
					msg:            string(helps.ChatGPTWebStrictImageSizeErrorPayload(parsed.Image.Size, imageConfigSnapshot.MaxResizeEdgePixels)),
					skipAuthResult: true,
				}
			}
			if disposition == helps.ChatGPTWebImageSizeIgnored {
				parsed.Image.Size = ""
			}
		}
	}
	if parsed.Image != nil {
		requestedCount := parsed.Image.N
		if maxResults := chatGPTWebMaxImageResults(opts.Metadata); maxResults > requestedCount {
			requestedCount = maxResults
		}
		maxN := imageConfigSnapshot.MaxN
		if maxN <= 0 {
			maxN = config.DefaultChatGPTWebMaxN
		}
		if requestedCount > maxN {
			return nil, statusErr{
				code:           http.StatusBadRequest,
				msg:            string(helps.ChatGPTWebImageNErrorPayload(requestedCount, maxN)),
				skipAuthResult: true,
			}
		}
	}
	if ignoreUnsupportedImageParams {
		ignoreUnsupportedChatGPTWebImageParams(parsed.Image)
	}
	if err = validateChatGPTWebImageRequest(parsed.Image, imageConfigSnapshot.RemoteImageURLEnabled); err != nil {
		return nil, err
	}
	if !chatGPTWebImageRequestHasRemoteReference(parsed.Image) {
		if err = prepareChatGPTWebImageMask(parsed.Image); err != nil {
			return nil, err
		}
	}
	if parsed.Image == nil {
		if err = validateChatGPTWebMessageImageInputs(parsed.Messages, imageConfigSnapshot.RemoteImageURLEnabled); err != nil {
			return nil, err
		}
	}
	var usageProjectionOn bool
	var usageProjectionOpts helps.ChatGPTWebUsageCacheOptions
	fallbackUsage := config.ChatGPTWebImageFallbackUsageConfig{}.Resolved()
	if cfg != nil {
		fallbackUsage = cfg.ChatGPTWeb.ImageUsage.FallbackUsage.Resolved()
	}
	if cfg == nil || cfg.ChatGPTWeb.TokenUsageEstimationEnabled() {
		usageProjectionOn = true
		resolvedCache := config.ResolvedChatGPTWebUsageCacheConfig{
			DiskThresholdMB:          config.DefaultChatGPTWebUsageCacheThresholdMB,
			MaxDiskSizeMB:            config.DefaultChatGPTWebUsageCacheMaxDiskSizeMB,
			ResourceGuardEnabled:     true,
			MinAvailableDiskMB:       config.DefaultChatGPTWebUsageCacheMinAvailableMB,
			MaxFilesystemUsedPercent: config.DefaultChatGPTWebUsageCacheMaxUsedPercent,
		}
		autoOutputQuality := config.DefaultChatGPTWebAutoOutputQuality
		if cfg != nil {
			resolvedCache = cfg.ChatGPTWeb.UsageCache.Resolved()
			autoOutputQuality = cfg.ChatGPTWeb.ImageUsage.ResolvedAutoOutputQuality()
		}
		usageProjectionOpts = helps.ChatGPTWebUsageCacheOptions{
			Enabled:                  resolvedCache.Enabled,
			DiskThresholdBytes:       chatGPTWebUsageCacheMegabytesToBytes(resolvedCache.DiskThresholdMB),
			MaxDiskBytes:             chatGPTWebUsageCacheMegabytesToBytes(resolvedCache.MaxDiskSizeMB),
			ResourceGuardEnabled:     resolvedCache.ResourceGuardEnabled,
			MinAvailableDiskBytes:    chatGPTWebUsageCacheMegabytesToBytes(resolvedCache.MinAvailableDiskMB),
			MaxFilesystemUsedPercent: resolvedCache.MaxFilesystemUsedPercent,
			Path:                     resolvedCache.Path,
			OrphanRetention:          time.Duration(resolvedCache.OrphanRetentionMinutes) * time.Minute,
			AutoOutputQuality:        autoOutputQuality,
		}
	}
	originalPayload := helps.SlimRequestBodyForTranslation(originalSource)
	canonicalBody = helps.SlimRequestBodyForTranslation(canonicalBody)
	return &chatGPTWebPreparedRequest{
		sentinelPolicy:  sentinelPolicy,
		bootstrapPolicy: bootstrapPolicy,
		baseModel:       baseModel,
		routeModel:      routeModel,
		responseFormat:  responseFormat,
		originalPayload: originalPayload,
		canonicalBody:   canonicalBody,
		request:         parsed,
		terminalMarker:  metadataBool(opts.Metadata, cliproxyexecutor.StreamTerminalMarkerMetadataKey),
		trustUpstreamSSE: metadataBool(opts.Metadata, cliproxyexecutor.TrustUpstreamSSEMetadataKey) &&
			responseFormat == sdktranslator.FormatOpenAIResponse,
		maxImageResults:     chatGPTWebMaxImageResults(opts.Metadata),
		usageProjectionOn:   usageProjectionOn,
		usageProjectionOpts: usageProjectionOpts,
		imageFallbackUsage:  fallbackUsage,
		imageConfigSnapshot: imageConfigSnapshot,
		imageSizeMatch:      imageSizeMatch,
	}, nil
}

func normalizeChatGPTWebRequestImageMIME(request *helps.ChatGPTWebRequest) error {
	if request == nil {
		return nil
	}
	for messageIndex := range request.Messages {
		for partIndex := range request.Messages[messageIndex].Parts {
			part := &request.Messages[messageIndex].Parts[partIndex]
			if strings.TrimSpace(part.ImageURL) == "" {
				continue
			}
			normalized, err := helps.NormalizeChatGPTWebImageDataURLMIME(part.ImageURL, chatGPTWebMaxImageBytes)
			if err != nil {
				return fmt.Errorf("decode message image: %w", err)
			}
			part.ImageURL = normalized
		}
	}
	if request.Image == nil {
		return nil
	}
	for index := range request.Image.Images {
		normalized, err := helps.NormalizeChatGPTWebImageDataURLMIME(request.Image.Images[index], chatGPTWebMaxImageBytes)
		if err != nil {
			return fmt.Errorf("decode image input %d: %w", index, err)
		}
		request.Image.Images[index] = normalized
	}
	if strings.TrimSpace(request.Image.MaskURL) != "" {
		normalized, err := helps.NormalizeChatGPTWebImageDataURLMIME(request.Image.MaskURL, chatGPTWebMaxImageBytes)
		if err != nil {
			return fmt.Errorf("decode image mask: %w", err)
		}
		request.Image.MaskURL = normalized
	}
	return nil
}

func (e *ChatGPTWebExecutor) instantiateRuntimeRequest(template *chatGPTWebPreparedRequest, opts cliproxyexecutor.Options) (*chatGPTWebPreparedRequest, error) {
	prepared := cloneChatGPTWebPreparedRequest(template)
	if prepared == nil {
		return nil, statusErr{code: http.StatusInternalServerError, msg: "chatgpt web prepared request is unavailable", skipAuthResult: true}
	}
	prepared.bodyRelease = cliproxyexecutor.RequestBodyReleaseControllerFromOptions(opts)
	prepared.executionDiagnostics = opts.ExecutionDiagnostics
	prepared.requestUsageOutcome = opts.UsageOutcome
	prepared.imageMemoryLeases = helps.ChatGPTWebImageMemoryLeaseSetFromMetadata(opts.Metadata)
	prepared.imageMemoryLeasesOwned = false
	prepared.phaseObserver = cliproxyexecutor.RequestPhaseObserverFromMetadata(opts.Metadata)
	prepared.imageResultState, _ = opts.Metadata[cliproxyexecutor.ImageGenerationResultStateMetadataKey].(*cliproxyexecutor.ImageGenerationResultState)
	if prepared.usageProjectionOn {
		projection, err := e.usageCache.NewProjection(prepared.routeModel, prepared.request, prepared.usageProjectionOpts)
		if err != nil {
			return nil, chatGPTWebUsageCacheStatusError(err)
		}
		prepared.usageProjection = projection
	}
	return prepared, nil
}

func cloneChatGPTWebPreparedRequest(template *chatGPTWebPreparedRequest) *chatGPTWebPreparedRequest {
	if template == nil {
		return nil
	}
	prepared := *template
	prepared.originalPayload = append([]byte(nil), template.originalPayload...)
	prepared.canonicalBody = append([]byte(nil), template.canonicalBody...)
	prepared.usageProjection = nil
	prepared.bodyRelease = nil
	prepared.imageResultState = nil
	prepared.executionDiagnostics = nil
	prepared.requestUsageOutcome = nil
	prepared.imageMemoryLeases = nil
	prepared.imageMemoryLeasesOwned = false
	prepared.phaseObserver = nil
	prepared.request.Messages = make([]helps.ChatGPTWebMessage, len(template.request.Messages))
	for index := range template.request.Messages {
		prepared.request.Messages[index] = template.request.Messages[index]
		prepared.request.Messages[index].Parts = append([]helps.ChatGPTWebContentPart(nil), template.request.Messages[index].Parts...)
	}
	if template.request.Image != nil {
		imageRequest := *template.request.Image
		imageRequest.Images = append([]string(nil), template.request.Image.Images...)
		prepared.request.Image = &imageRequest
	}
	if template.imageSizeMatch != nil {
		imageSizeMatch := *template.imageSizeMatch
		prepared.imageSizeMatch = &imageSizeMatch
	}
	return &prepared
}

func chatGPTWebUsageCacheMegabytesToBytes(megabytes int64) int64 {
	if megabytes <= 0 {
		return 0
	}
	if megabytes > config.MaxChatGPTWebUsageCacheMegabytes {
		return 1<<63 - 1
	}
	return megabytes << 20
}

func chatGPTWebUsageCacheStatusError(_ error) error {
	payload, _ := json.Marshal(map[string]any{"error": map[string]any{
		"message": "server resource capacity is temporarily exhausted",
		"type":    "server_error",
		"code":    "resource_exhausted",
	}})
	return statusErr{code: http.StatusServiceUnavailable, msg: string(payload), skipAuthResult: true}
}

func (prepared *chatGPTWebPreparedRequest) releaseRequestBody() {
	if prepared == nil {
		return
	}
	if prepared.usageProjection != nil {
		for _, estimateErr := range prepared.usageProjection.PrecomputeInput() {
			log.WithError(estimateErr).Warn("chatgpt web input usage precomputation was incomplete")
		}
	}
	if prepared.bodyRelease != nil {
		prepared.bodyRelease.ReleaseWithPlaceholder(cliproxyexecutor.RequestBodyReleaseStreamPlaceholder(
			prepared.bodyRelease.OriginalSize(), prepared.bodyRelease.LogOnly(),
		))
	}
	if prepared.imageMemoryLeases != nil {
		prepared.imageMemoryLeases.ReleaseInput()
	}
	prepared.request.Messages = nil
	if prepared.request.Image != nil {
		prepared.request.Image.Prompt = ""
		prepared.request.Image.Images = nil
		prepared.request.Image.MaskURL = ""
	}
}

func (prepared *chatGPTWebPreparedRequest) discardUsageProjection() {
	if prepared == nil || prepared.usageProjection == nil {
		return
	}
	prepared.usageProjection.Discard()
	prepared.usageProjection = nil
}

func (e *ChatGPTWebExecutor) completeChatGPTWebUsage(prepared *chatGPTWebPreparedRequest, outputText string, outputImages []helps.ChatGPTWebUsageImage) map[string]any {
	if prepared == nil {
		return nil
	}
	if prepared.usageProjection == nil {
		if prepared.request.Image == nil {
			return nil
		}
		imageUsage := helps.ChatGPTWebImageUsageMap(0, 0, 0, 0)
		fallback := prepared.imageFallbackUsage
		if fallback.Enabled {
			outputCount := int64(len(outputImages))
			imageUsage = helps.ChatGPTWebImageUsageMap(
				fallback.InputTextTokens,
				fallback.InputImageTokens,
				multiplyChatGPTWebUsageTokens(fallback.OutputTextTokens, outputCount),
				multiplyChatGPTWebUsageTokens(fallback.OutputImageTokens, outputCount),
			)
		}
		usage := chatGPTWebUsageOrZero(nil)
		usage["tool_usage"] = map[string]any{"image_gen": imageUsage}
		return usage
	}
	usage, estimateErrors := prepared.usageProjection.Estimate(outputText, outputImages)
	for _, estimateErr := range estimateErrors {
		log.WithError(estimateErr).Warn("chatgpt web usage estimation was incomplete")
	}
	prepared.usageProjection.Complete()
	prepared.usageProjection = nil
	return usage
}

func multiplyChatGPTWebUsageTokens(tokens, count int64) int64 {
	if tokens <= 0 || count <= 0 {
		return 0
	}
	const maxInt64 = int64(^uint64(0) >> 1)
	if tokens > maxInt64/count {
		return maxInt64
	}
	return tokens * count
}

func (e *ChatGPTWebExecutor) completeChatGPTWebUpstreamImageUsage(prepared *chatGPTWebPreparedRequest, toolUsage map[string]any) map[string]any {
	if len(toolUsage) == 0 {
		return nil
	}
	usage := chatGPTWebUsageOrZero(nil)
	if prepared != nil && prepared.usageProjection != nil {
		var estimateErrors []error
		usage, estimateErrors = prepared.usageProjection.Estimate("", nil)
		for _, estimateErr := range estimateErrors {
			log.WithError(estimateErr).Warn("chatgpt web usage estimation was incomplete")
		}
		prepared.usageProjection.Complete()
		prepared.usageProjection = nil
	}
	usage["tool_usage"] = map[string]any{"image_gen": toolUsage}
	return usage
}

func publishChatGPTWebTerminalUsage(ctx context.Context, reporter *helps.UsageReporter, prepared *chatGPTWebPreparedRequest, completed []byte) {
	if reporter == nil {
		return
	}
	if detail, ok := helps.ParseCodexUsage(completed); ok {
		reporter.Publish(ctx, detail)
	} else {
		reporter.EnsurePublished(ctx)
	}
	if prepared == nil || prepared.request.Image == nil {
		return
	}
	if detail, ok := helps.ParseCodexImageToolUsage(completed); ok {
		reporter.PublishAdditionalModel(ctx, prepared.request.Image.Model, detail)
	}
}

func chatGPTWebRequestHasImageInputs(request helps.ChatGPTWebRequest) bool {
	if request.Image != nil && (len(request.Image.Images) > 0 || strings.TrimSpace(request.Image.MaskURL) != "") {
		return true
	}
	for _, message := range request.Messages {
		for _, part := range message.Parts {
			if strings.TrimSpace(part.ImageURL) != "" {
				return true
			}
		}
	}
	return false
}

func chatGPTWebRawRequestHasImageInputs(payload []byte, format sdktranslator.Format) bool {
	if len(payload) == 0 {
		return false
	}
	root := gjson.ParseBytes(payload)
	if !root.IsObject() {
		return false
	}
	if chatGPTWebJSONValuePresent(root.Get("image")) ||
		chatGPTWebJSONValuePresent(root.Get("images")) ||
		chatGPTWebJSONValuePresent(root.Get("mask")) {
		return true
	}
	switch format {
	case sdktranslator.FormatOpenAI:
		return chatGPTWebJSONArrayAny(root.Get("messages"), func(message gjson.Result) bool {
			return chatGPTWebOpenAIContentHasImage(message.Get("content"))
		})
	case sdktranslator.FormatOpenAIResponse, sdktranslator.FormatCodex, sdktranslator.FormatInteractions:
		return chatGPTWebOpenAIResponseInputHasImage(root.Get("input"))
	case sdktranslator.FormatClaude:
		return chatGPTWebJSONArrayAny(root.Get("messages"), func(message gjson.Result) bool {
			return chatGPTWebClaudeContentHasImage(message.Get("content"))
		})
	case sdktranslator.FormatGemini, sdktranslator.FormatAntigravity:
		return chatGPTWebJSONArrayAny(root.Get("contents"), func(content gjson.Result) bool {
			return chatGPTWebJSONArrayAny(content.Get("parts"), func(part gjson.Result) bool {
				return chatGPTWebJSONValuePresent(part.Get("inline_data")) ||
					chatGPTWebJSONValuePresent(part.Get("inlineData")) ||
					chatGPTWebJSONValuePresent(part.Get("file_data")) ||
					chatGPTWebJSONValuePresent(part.Get("fileData"))
			})
		})
	default:
		return false
	}
}

func chatGPTWebJSONValuePresent(result gjson.Result) bool {
	if !result.Exists() || result.Type == gjson.Null {
		return false
	}
	if result.IsArray() {
		present := false
		result.ForEach(func(_, value gjson.Result) bool {
			present = chatGPTWebJSONValuePresent(value)
			return !present
		})
		return present
	}
	raw := strings.TrimSpace(result.Raw)
	return raw != "" && raw != `""` && raw != "{}"
}

func chatGPTWebJSONArrayAny(result gjson.Result, predicate func(gjson.Result) bool) bool {
	if predicate == nil {
		return false
	}
	if !result.IsArray() {
		return predicate(result)
	}
	matched := false
	result.ForEach(func(_, value gjson.Result) bool {
		matched = predicate(value)
		return !matched
	})
	return matched
}

func chatGPTWebOpenAIResponseInputHasImage(input gjson.Result) bool {
	return chatGPTWebJSONArrayAny(input, func(item gjson.Result) bool {
		switch strings.ToLower(strings.TrimSpace(item.Get("type").String())) {
		case "image", "image_url", "input_image":
			return true
		}
		return chatGPTWebOpenAIContentHasImage(item.Get("content"))
	})
}

func chatGPTWebOpenAIContentHasImage(content gjson.Result) bool {
	return chatGPTWebJSONArrayAny(content, func(part gjson.Result) bool {
		switch strings.ToLower(strings.TrimSpace(part.Get("type").String())) {
		case "image", "image_url", "input_image":
			return true
		}
		return chatGPTWebJSONValuePresent(part.Get("image_url")) ||
			chatGPTWebJSONValuePresent(part.Get("image"))
	})
}

func chatGPTWebClaudeContentHasImage(content gjson.Result) bool {
	return chatGPTWebJSONArrayAny(content, func(part gjson.Result) bool {
		return strings.EqualFold(strings.TrimSpace(part.Get("type").String()), "image") ||
			chatGPTWebJSONValuePresent(part.Get("source.data"))
	})
}

func validateChatGPTWebMessageImageInputs(messages []helps.ChatGPTWebMessage, remoteEnabled ...bool) error {
	var references []string
	for _, message := range messages {
		for _, part := range message.Parts {
			if imageURL := strings.TrimSpace(part.ImageURL); imageURL != "" {
				references = append(references, imageURL)
			}
		}
	}
	if len(references) == 0 {
		return nil
	}
	allowRemote := len(remoteEnabled) > 0 && remoteEnabled[0]
	return validateChatGPTWebImageReferences(references, allowRemote)
}

func chatGPTWebMaxImageResults(metadata map[string]any) int {
	if metadata == nil {
		return 0
	}
	maxResults, _ := metadata[cliproxyexecutor.ImageGenerationMaxResultsMetadataKey].(int)
	if maxResults < 0 {
		return 0
	}
	return maxResults
}

func (e *ChatGPTWebExecutor) newRuntimeClient(auth *cliproxyauth.Auth) (*chatgptwebauth.Client, *chatgptwebauth.Credential, error) {
	return e.newRuntimeClientForAcquisition(auth, false)
}

func (e *ChatGPTWebExecutor) newRuntimeClientForRequest(ctx context.Context, auth *cliproxyauth.Auth) (*chatgptwebauth.Client, *chatgptwebauth.Credential, error) {
	if cliproxyexecutor.ImageRequestBudgetFromContext(ctx).Limit("chatgpt-web") > 0 {
		return e.newRuntimeClientForAcquisition(auth, false, ctx)
	}
	return e.newRuntimeClient(auth)
}

func (e *ChatGPTWebExecutor) newRuntimeClientForAcquisition(auth *cliproxyauth.Auth, acquisition bool, requestContexts ...context.Context) (*chatgptwebauth.Client, *chatgptwebauth.Credential, error) {
	if auth == nil {
		return nil, nil, errors.New("chatgpt web credential is nil")
	}
	credential, err := chatgptwebauth.ParseCredential(auth.Metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("parse chatgpt web credential: %w", err)
	}
	chatgptwebauth.ResolveCredentialPersona(credential, auth.ID)
	if strings.TrimSpace(credential.AccessToken) == "" {
		return nil, nil, statusErr{code: http.StatusUnauthorized, msg: "chatgpt web access token is empty"}
	}
	if err = chatgptwebauth.EnsureCredentialRuntimeIDsForURL(credential, chatgptwebauth.CredentialRuntimeIdentityReader(auth.ID, credential), e.chatGPTWebBaseURL()); err != nil {
		return nil, nil, fmt.Errorf("initialize chatgpt web browser identity: %w", err)
	}
	var client *chatgptwebauth.Client
	if len(requestContexts) > 0 {
		client, err = chatgptwebauth.NewRequestClient(requestContexts[0], credential.Persona,
			e.proxyURLForTarget(auth, e.chatGPTWebBaseURL()), credential.Cookies, false)
	} else if acquisition {
		client, err = chatgptwebauth.NewAccessTokenAcquisitionClient(
			credential.Persona,
			e.proxyURLForTarget(auth, e.chatGPTWebBaseURL()),
			credential.Cookies,
			e.accountInfoTimeout,
		)
	} else {
		client, err = chatgptwebauth.NewAccessTokenClient(
			credential.Persona,
			e.proxyURLForTarget(auth, e.chatGPTWebBaseURL()),
			credential.Cookies,
		)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("create chatgpt web browser client: %w", err)
	}
	baseURL := e.chatGPTWebBaseURL()
	deviceID := strings.TrimSpace(credential.DeviceID)
	if err = client.SetCookie(baseURL, "oai-did", deviceID); err != nil {
		client.CloseIdleConnections()
		return nil, nil, err
	}
	return client, credential, nil
}

func (e *ChatGPTWebExecutor) finishChatGPTWebRuntimeClient(ctx context.Context, auth *cliproxyauth.Auth, credential *chatgptwebauth.Credential, client *chatgptwebauth.Client) {
	if client == nil {
		return
	}
	defer client.CloseIdleConnections()
	if e == nil || e.manager == nil || auth == nil || credential == nil {
		return
	}
	cookies := client.ExportCookies()
	persona := client.Persona()
	if reflect.DeepEqual(credential.Cookies, cookies) &&
		reflect.DeepEqual(credential.Persona, persona) &&
		chatGPTWebMetadataString(auth.Metadata, "device_id") == credential.DeviceID &&
		chatGPTWebMetadataString(auth.Metadata, "session_id") == credential.SessionID {
		return
	}
	persistCtx := context.Background()
	if ctx != nil {
		persistCtx = context.WithoutCancel(ctx)
	}
	baselineCookies := append([]chatgptwebauth.Cookie(nil), credential.Cookies...)
	_, _, errUpdate := e.manager.MutateRuntimeMetadataIfCurrent(persistCtx, auth, func(current *cliproxyauth.Auth) {
		currentCookies := baselineCookies
		if currentCredential, errParse := chatgptwebauth.ParseCredential(current.Metadata); errParse == nil {
			currentCookies = currentCredential.Cookies
		}
		if current.Metadata == nil {
			current.Metadata = make(map[string]any)
		}
		current.Metadata["cookies"] = mergeChatGPTWebCookieDelta(currentCookies, baselineCookies, cookies)
		current.Metadata["persona"] = persona
		current.Metadata["device_id"] = credential.DeviceID
		current.Metadata["session_id"] = credential.SessionID
	})
	if errUpdate != nil {
		log.WithField("auth_id", auth.ID).Warnf("chatgpt web executor: persist runtime session: %v", errUpdate)
	}
}

func mergeChatGPTWebCookieDelta(current, baseline, next []chatgptwebauth.Cookie) []chatgptwebauth.Cookie {
	return chatgptwebauth.MergeCookieDelta(current, baseline, next)
}

func chatGPTWebMetadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

// FetchModels refreshes the authenticated ChatGPT Web model catalog.
func (e *ChatGPTWebExecutor) FetchModels(ctx context.Context, auth *cliproxyauth.Auth) ([]chatgptwebauth.CatalogModel, error) {
	client, credential, err := e.newRuntimeClient(auth)
	if err != nil {
		return nil, err
	}
	defer e.finishChatGPTWebRuntimeClient(ctx, auth, credential, client)
	bootstrapPath := "/"
	bootstrapHeaders := e.chatGPTWebHeaders(credential, bootstrapPath, map[string]string{
		"accept":         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"sec-fetch-dest": "document",
		"sec-fetch-mode": "navigate",
		"sec-fetch-site": "none",
	})
	response, err := e.doChatGPTWebBootstrapRequest(
		ctx,
		client,
		credential,
		e.chatGPTWebBaseURL()+bootstrapPath,
		bootstrapHeaders,
	)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.configSnapshot(), err)
		return nil, err
	}
	bootstrap, err := readChatGPTWebResponseBody(response, chatGPTWebMaxHTMLBodyBytes)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.configSnapshot(), err)
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, newChatGPTWebStatusError(response.StatusCode, bootstrapPath, bootstrap, response.Header)
	}
	path := "/backend-api/models?history_and_training_disabled=false"
	headers := e.chatGPTWebHeaders(credential, path, map[string]string{
		"x-openai-target-path":  "/backend-api/models",
		"x-openai-target-route": "/backend-api/models",
	})
	response, err = e.doChatGPTWebBootstrapRequest(
		ctx,
		client,
		credential,
		e.chatGPTWebBaseURL()+path,
		headers,
	)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.configSnapshot(), err)
		return nil, err
	}
	payload, err := readChatGPTWebResponseBody(response, chatGPTWebMaxJSONBodyBytes)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.configSnapshot(), err)
		return nil, err
	}
	sanitizedPayload := chatGPTWebResponseLogBody(path, payload)
	helps.AppendAPIResponseChunk(ctx, e.configSnapshot(), sanitizedPayload)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, newChatGPTWebStatusError(response.StatusCode, path, payload, response.Header)
	}
	return chatgptwebauth.DecodeCatalog(payload)
}

func (e *ChatGPTWebExecutor) executeChatGPTWebText(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, prepared *chatGPTWebPreparedRequest) (chatGPTWebTextResult, http.Header, error) {
	if chatGPTWebRequestUsesSearch(prepared) {
		return e.executeChatGPTWebSearch(ctx, client, credential, prepared)
	}
	response, accumulator, err := e.openChatGPTWebConversation(ctx, client, credential, prepared)
	if err != nil {
		return chatGPTWebTextResult{}, nil, err
	}
	defer func() {
		if errClose := response.Body.Close(); errClose != nil {
			log.Errorf("chatgpt web executor: close response body: %v", errClose)
		}
	}()
	err = consumeChatGPTWebConversation(ctx, response.Body, accumulator, nil)
	if challengeErr := chatGPTWebStreamChallengeError(response); challengeErr != nil {
		return chatGPTWebTextResult{}, nil, challengeErr
	}
	if err != nil {
		return chatGPTWebTextResult{}, nil, chatGPTWebCommittedRequestError(ctx, chatGPTWebUpstreamProtocolError(ctx, err))
	}
	return chatGPTWebTextResult{Text: accumulator.Text()}, cloneChatGPTWebHeaders(response.Header), nil
}

func (e *ChatGPTWebExecutor) openChatGPTWebConversation(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, prepared *chatGPTWebPreparedRequest) (*fhttp.Response, *helps.ChatGPTWebConversationAccumulator, error) {
	requirements, err := e.chatGPTWebRequirements(ctx, client, credential, prepared.sentinelPolicy)
	if err != nil {
		return nil, nil, err
	}
	messages, err := e.buildChatGPTWebConversationMessages(ctx, client, credential, prepared.request.Messages, prepared.usageProjection)
	if err != nil {
		return nil, nil, err
	}
	path := "/backend-api/conversation"
	timezone := e.chatGPTWebTimezone()
	body := map[string]any{
		"action":                        "next",
		"messages":                      messages,
		"model":                         prepared.request.Model,
		"parent_message_id":             uuid.NewString(),
		"conversation_mode":             map[string]any{"kind": "primary_assistant"},
		"conversation_origin":           nil,
		"force_paragen":                 false,
		"force_paragen_model_slug":      "",
		"force_rate_limit":              false,
		"force_use_sse":                 true,
		"history_and_training_disabled": true,
		"reset_rate_limits":             false,
		"suggestions":                   []any{},
		"supported_encodings":           []any{},
		"system_hints":                  []any{},
		"timezone":                      timezone.Timezone,
		"timezone_offset_min":           timezone.OffsetMinutes,
		"variant_purpose":               "comparison_implicit",
		"websocket_request_id":          uuid.NewString(),
		"client_contextual_info":        chatGPTWebClientContext(),
	}
	if effort := normalizeChatGPTWebThinkingEffort(prepared.request.ReasoningEffort); effort != "" {
		body["thinking_effort"] = effort
	}
	headers := e.chatGPTWebHeaders(credential, path, map[string]string{
		"accept":       "text/event-stream",
		"content-type": "application/json",
		"openai-sentinel-chat-requirements-token": requirements.Token,
		"openai-sentinel-proof-token":             requirements.ProofToken,
		"openai-sentinel-turnstile-token":         requirements.TurnstileToken,
		"openai-sentinel-so-token":                requirements.SOToken,
	})
	response, err := e.doChatGPTWebJSONStream(ctx, client, credential, path, headers, body)
	if err != nil {
		return nil, nil, err
	}
	accumulator := helps.NewChatGPTWebConversationAccumulator(prepared.request.Messages)
	prepared.releaseRequestBody()
	return response, accumulator, nil
}

func chatGPTWebSentinelPolicy(cfg *config.Config) *sentinelcompat.Policy {
	if cfg == nil {
		return nil
	}
	return cfg.ChatGPTWeb.Sentinel.GoVMPolicy
}

func (e *ChatGPTWebExecutor) chatGPTWebRequirements(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, policies ...*sentinelcompat.Policy) (chatGPTWebRequirements, error) {
	policy := chatGPTWebSentinelPolicy(e.configSnapshot())
	if len(policies) > 0 {
		policy = policies[0]
	}
	// Observe on transitions and return so errors and cancellation are included.
	// These child phases are already included in the image requirements total.
	phase := ""
	phaseStarted := time.Now()
	setPhase := func(name string) {
		if phase != "" {
			cliproxyexecutor.ObserveRequestPhaseContext(ctx, phase, phaseStarted)
		}
		phase = name
		phaseStarted = time.Now()
		setChatGPTWebImageTaskStage(ctx, name)
	}
	defer func() { cliproxyexecutor.ObserveRequestPhaseContext(ctx, phase, phaseStarted) }()
	setPhase(cliproxyexecutor.ImagePhaseRequirementsBootstrap)
	baseURL := e.chatGPTWebBaseURL()
	bootstrapPath := "/"
	bootstrapHeaders := e.chatGPTWebHeaders(credential, bootstrapPath, map[string]string{
		"accept":         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"sec-fetch-dest": "document",
		"sec-fetch-mode": "navigate",
		"sec-fetch-site": "none",
	})
	var response *fhttp.Response
	var bootstrap []byte
	var err error
	if chatgptwebauth.SentinelComputeScope(ctx) == "images" {
		response, bootstrap, err = e.fetchChatGPTWebImageBootstrap(ctx, client, credential, baseURL+bootstrapPath, bootstrapHeaders)
	} else {
		response, err = e.doChatGPTWebBootstrapRequest(ctx, client, credential, baseURL+bootstrapPath, bootstrapHeaders)
		if err == nil {
			bootstrap, err = readChatGPTWebResponseBody(response, chatGPTWebMaxHTMLBodyBytes)
		}
	}
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.configSnapshot(), err)
		return chatGPTWebRequirements{}, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return chatGPTWebRequirements{}, newChatGPTWebStatusError(response.StatusCode, bootstrapPath, bootstrap, response.Header)
	}
	setPhase(cliproxyexecutor.ImagePhaseRequirementsLocal)
	sources, dataBuild := chatgptwebauth.ParseConversationPoWResources(bootstrap)
	sdkResource := chatgptwebauth.ParseConversationSentinelSDKResource(bootstrap)
	if sdkResource.URL == "" {
		sdkResource = chatgptwebauth.DefaultConversationSentinelSDKResource()
	}
	sentinelEnvironment := chatgptwebauth.ConversationTurnstileEnvironment{
		Compatibility:      policy,
		Persona:            credential.Persona,
		BrowserEnvironment: chatgptwebauth.ResolveCredentialBrowserEnvironment(credential, ""),
		DeviceID:           credential.DeviceID,
		PageStartedAt:      e.now(),
		ScriptSources:      sources,
		Location:           strings.TrimRight(baseURL, "/") + "/",
	}
	var remoteCompute *chatgptwebauth.SentinelComputeSession
	var pToken string
	computeScope := chatgptwebauth.SentinelComputeScope(ctx)
	if e.sentinelCompute.Enabled(computeScope) {
		computeFetcher := e.chatGPTWebSentinelSDKFetcher(client, credential)
		if e.sentinelSDKFetcherFactory != nil {
			computeFetcher = e.sentinelSDKFetcherFactory(client, credential)
		}
		remoteCompute, err = e.sentinelCompute.Begin(ctx, computeScope, chatgptwebauth.SentinelComputeInput{
			Format: "conversation", Environment: chatgptwebauth.ComputeEnvironment(sentinelEnvironment), DataBuild: dataBuild,
			Flow: "conversation", Clock: e.now(), SDKURL: sdkResource.URL, SDKSHA256: sdkResource.SHA256, SDKIntegrityRequired: sdkResource.IntegrityRequired,
		}, chatgptwebauth.SentinelComputeHooks{Reader: e.runtimeRand, Now: e.now, Fetcher: computeFetcher})
		if err != nil {
			return chatGPTWebRequirements{}, err
		}
		defer remoteCompute.Close()
		pToken = remoteCompute.RequirementsToken()
	} else {
		pToken, err = chatgptwebauth.BuildConversationRequirementsTokenWithEnvironment(sentinelEnvironment, sources, dataBuild, e.runtimeRand, e.now)
	}
	if err != nil {
		return chatGPTWebRequirements{}, chatGPTWebLocalProtocolError(
			http.StatusBadGateway,
			"build chatgpt web requirements token: "+err.Error(),
		)
	}
	preparePath := "/backend-api/sentinel/chat-requirements/prepare"
	setPhase(cliproxyexecutor.ImagePhaseRequirementsPrepare)
	_, prepareData, err := e.doChatGPTWebJSON(ctx, client, credential, preparePath, map[string]any{"p": pToken})
	if err != nil {
		return chatGPTWebRequirements{}, err
	}
	setPhase(cliproxyexecutor.ImagePhaseRequirementsParse)
	var prepare map[string]any
	if err := json.Unmarshal(prepareData, &prepare); err != nil {
		return chatGPTWebRequirements{}, chatGPTWebLocalProtocolError(
			http.StatusBadGateway,
			"decode chatgpt web requirements prepare: "+err.Error(),
		)
	}
	if requiredJSONFlag(prepare, "arkose", "required") {
		return chatGPTWebRequirements{}, chatGPTWebLocalProtocolError(
			http.StatusForbidden,
			"chatgpt web requires an unsupported Arkose challenge",
		)
	}
	sdkFetcher := e.chatGPTWebSentinelSDKFetcher(client, credential)
	if e.sentinelSDKFetcherFactory != nil {
		sdkFetcher = e.sentinelSDKFetcherFactory(client, credential)
	}
	sdkRequest := chatgptwebauth.SentinelSDKRequest{
		BaseURL:           baseURL,
		SDKURL:            sdkResource.URL,
		ScriptSources:     sources,
		ExpectedSHA256:    sdkResource.SHA256,
		IntegrityRequired: sdkResource.IntegrityRequired,
		TransportKey:      chatGPTWebSentinelTransportKey(client),
		Challenge:         prepare,
		RequirementsToken: pToken,
		Environment:       sentinelEnvironment,
		DeviceID:          credential.DeviceID,
		Flow:              "conversation",
		Fetcher:           sdkFetcher,
	}
	var observer helps.ChatGPTWebSentinelObserver
	var observerErr error
	soRequired := requiredJSONFlag(prepare, "so", "required")
	proofToken := ""
	turnstileToken := ""
	if remoteCompute != nil {
		setPhase(cliproxyexecutor.ImagePhaseRequirementsObserver)
		computed, computeErr := remoteCompute.Solve(ctx, chatgptwebauth.ComputeChallenge(prepare, true))
		if computeErr != nil {
			return chatGPTWebRequirements{}, computeErr
		}
		proofToken, turnstileToken = computed.ProofToken, computed.TurnstileToken
		observer = remoteCompute
	} else {
		if e.sentinelRuntime != nil {
			setPhase(cliproxyexecutor.ImagePhaseRequirementsObserver)
			observer, err = e.sentinelRuntime.BeginObserver(ctx, sdkRequest)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || (ctx != nil && ctx.Err() != nil) {
					return chatGPTWebRequirements{}, err
				}
				observerErr = err
			}
		}
		if observer != nil {
			defer func() {
				setPhase(cliproxyexecutor.ImagePhaseRequirementsCleanup)
				observer.Close()
			}()
		}
		if requiredJSONFlag(prepare, "proofofwork", "required") {
			setPhase(cliproxyexecutor.ImagePhaseRequirementsProof)
			proof, _ := prepare["proofofwork"].(map[string]any)
			proofToken, err = chatgptwebauth.BuildConversationProofTokenWithEnvironment(
				ctx,
				chatGPTWebAnyString(proof["seed"]),
				chatGPTWebAnyString(proof["difficulty"]),
				sentinelEnvironment, sources, dataBuild, e.runtimeRand, e.now,
			)
			if err != nil {
				if ctx != nil && ctx.Err() != nil {
					return chatGPTWebRequirements{}, ctx.Err()
				}
				return chatGPTWebRequirements{}, chatGPTWebLocalProtocolError(
					http.StatusBadGateway,
					"build chatgpt web proof token: "+err.Error(),
				)
			}
		}
		if requiredJSONFlag(prepare, "turnstile", "required") {
			setPhase(cliproxyexecutor.ImagePhaseRequirementsTurnstile)
			turnstile, _ := prepare["turnstile"].(map[string]any)
			dx := chatGPTWebAnyString(turnstile["dx"])
			if dx == "" {
				return chatGPTWebRequirements{}, chatGPTWebTurnstileProtocolError(
					"ChatGPT Web Turnstile challenge is missing dx",
				)
			}
			goRequest := chatgptwebauth.ConversationTurnstileSolveRequest{
				DX:                dx,
				RequirementsToken: pToken,
				Environment:       sentinelEnvironment,
				Reader:            e.runtimeRand,
				Now:               e.now,
			}
			if e.sentinelRuntime == nil {
				turnstileToken, err = chatgptwebauth.BuildConversationTurnstileTokenWithEnvironment(
					ctx, dx, pToken, sentinelEnvironment, e.runtimeRand, e.now,
				)
			} else {
				turnstileToken, err = e.sentinelRuntime.SolveTurnstile(ctx, goRequest, sdkRequest, observer)
			}
			if err != nil {
				if ctx != nil && ctx.Err() != nil {
					return chatGPTWebRequirements{}, ctx.Err()
				}
				var runtimeErr *chatgptwebauth.SentinelRuntimeError
				if errors.As(err, &runtimeErr) {
					return chatGPTWebRequirements{}, chatGPTWebSentinelRuntimeProtocolError(runtimeErr)
				}
				log.Warn("chatgpt web executor: Turnstile challenge solve failed")
				return chatGPTWebRequirements{}, chatGPTWebTurnstileProtocolError(
					"ChatGPT Web Turnstile challenge could not be solved",
				)
			}
		}
	}
	finalizePath := "/backend-api/sentinel/chat-requirements/finalize"
	setPhase(cliproxyexecutor.ImagePhaseRequirementsFinalize)
	_, finalizeData, err := e.doChatGPTWebJSON(ctx, client, credential, finalizePath, map[string]any{
		"prepare_token":   chatGPTWebAnyString(prepare["prepare_token"]),
		"proof_token":     proofToken,
		"turnstile_token": turnstileToken,
	})
	if err != nil {
		if turnstileToken != "" && chatGPTWebTurnstileFinalizeRejection(err) {
			log.WithError(err).Warn("chatgpt web executor: upstream rejected Turnstile token")
			return chatGPTWebRequirements{}, chatGPTWebTurnstileProtocolError(
				"ChatGPT Web rejected the generated Turnstile token",
			)
		}
		if soRequired && chatGPTWebSentinelFinalizeRejection(err) {
			log.WithError(err).Warn("chatgpt web executor: upstream rejected Session Observer token")
			return chatGPTWebRequirements{}, chatGPTWebSentinelObserverProtocolError(
				errors.New("ChatGPT Web rejected the generated Session Observer token"),
			)
		}
		return chatGPTWebRequirements{}, err
	}
	setPhase(cliproxyexecutor.ImagePhaseRequirementsParse)
	var finalize map[string]any
	if err := json.Unmarshal(finalizeData, &finalize); err != nil {
		return chatGPTWebRequirements{}, chatGPTWebLocalProtocolError(
			http.StatusBadGateway,
			"decode chatgpt web requirements finalize: "+err.Error(),
		)
	}
	token, _ := finalize["token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		return chatGPTWebRequirements{}, chatGPTWebLocalProtocolError(
			http.StatusBadGateway,
			"chatgpt web requirements response is missing token",
		)
	}
	finalizedTurnstileToken := ""
	if value, ok := finalize["turnstile_token"].(string); ok {
		finalizedTurnstileToken = strings.TrimSpace(value)
	}
	if finalizedTurnstileToken == "" {
		finalizedTurnstileToken = turnstileToken
	}
	soToken, _ := finalize["so_token"].(string)
	soToken = strings.TrimSpace(soToken)
	if soToken == "" && soRequired {
		if observer == nil {
			if observerErr != nil {
				return chatGPTWebRequirements{}, chatGPTWebSentinelObserverProtocolError(observerErr)
			}
			return chatGPTWebRequirements{}, chatGPTWebSentinelObserverProtocolError(&chatgptwebauth.SentinelRuntimeError{
				Code: "sentinel_session_observer_unavailable",
				Err:  errors.New("Sentinel Session Observer is unavailable"),
			})
		}
		setPhase(cliproxyexecutor.ImagePhaseRequirementsSnapshot)
		soToken, err = observer.Snapshot(ctx)
		if err != nil {
			if ctx != nil && ctx.Err() != nil {
				return chatGPTWebRequirements{}, ctx.Err()
			}
			return chatGPTWebRequirements{}, chatGPTWebSentinelObserverProtocolError(err)
		}
	}
	return chatGPTWebRequirements{
		Token:          token,
		ProofToken:     proofToken,
		TurnstileToken: finalizedTurnstileToken,
		SOToken:        soToken,
	}, nil
}

func chatGPTWebSentinelTransportKey(client *chatgptwebauth.Client) string {
	if client == nil {
		return "default"
	}
	persona, _ := json.Marshal(client.Persona())
	digest := sha256.Sum256([]byte(client.ProxyURL() + "\x00" + string(persona)))
	return fmt.Sprintf("%x", digest[:])
}

func (e *ChatGPTWebExecutor) chatGPTWebSentinelSDKFetcher(client *chatgptwebauth.Client, credential *chatgptwebauth.Credential) chatgptwebauth.SentinelSDKFetcher {
	return func(ctx context.Context, targetURL string, maxBytes int64) ([]byte, string, string, error) {
		if client == nil {
			return nil, "", "", errors.New("chatgpt web SDK client is nil")
		}
		// Source fetches can outlive an individual waiter but must stop when their
		// own shared-fetch context is cancelled.
		var sdkClient *chatgptwebauth.Client
		var errClient error
		if client.RequestScoped() {
			sdkClient, errClient = chatgptwebauth.NewRequestClient(ctx, client.Persona(), client.ProxyURL(), nil, true)
		} else {
			sdkClient, errClient = chatgptwebauth.NewClient(client.Persona(), client.ProxyURL(), nil)
		}
		if errClient != nil {
			return nil, "", "", fmt.Errorf("create cookie-free Sentinel SDK client: %w", errClient)
		}
		defer sdkClient.CloseIdleConnections()
		headers := map[string]string{
			"accept":         "text/javascript,application/javascript;q=0.9,*/*;q=0.1",
			"referer":        e.chatGPTWebBaseURL() + "/",
			"sec-fetch-dest": "script",
			"sec-fetch-mode": "no-cors",
			"sec-fetch-site": "cross-site",
		}
		response, err := e.doChatGPTWebBootstrapRequest(ctx, sdkClient, nil, targetURL, headers)
		if err != nil {
			return nil, "", "", err
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			body := readAndCloseChatGPTWebErrorBody(response.Body)
			return nil, "", "", newChatGPTWebStatusError(response.StatusCode, "/sentinel/sdk.js", body, response.Header)
		}
		if maxBytes < 1 || maxBytes > int64(^uint(0)>>1) {
			_ = response.Body.Close()
			return nil, "", "", errors.New("Sentinel SDK response limit is invalid")
		}
		data, err := readChatGPTWebSuccessBody(response.Body, int(maxBytes))
		contentType := response.Header.Get("Content-Type")
		finalURL := targetURL
		if response.Request != nil && response.Request.URL != nil {
			finalURL = response.Request.URL.String()
		}
		if errClose := response.Body.Close(); err == nil && errClose != nil {
			err = errClose
		}
		return data, contentType, finalURL, err
	}
}

func chatGPTWebSentinelRuntimeProtocolError(err error) statusErr {
	code := "sentinel_sdk_unavailable"
	statusCode := http.StatusServiceUnavailable
	message := "ChatGPT Web Sentinel SDK is temporarily unavailable"
	var runtimeErr *chatgptwebauth.SentinelRuntimeError
	var retryAfter *time.Duration
	if errors.As(err, &runtimeErr) {
		if strings.TrimSpace(runtimeErr.Code) != "" {
			code = strings.TrimSpace(runtimeErr.Code)
		}
		if runtimeErr.RetryAfter > 0 {
			value := runtimeErr.RetryAfter
			retryAfter = &value
		}
	}
	if code == "sentinel_session_observer_unavailable" {
		statusCode = http.StatusBadGateway
		message = "ChatGPT Web Sentinel Session Observer is temporarily unavailable"
	}
	payload, marshalErr := json.Marshal(map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    "upstream_protocol_error",
			"code":    code,
		},
	})
	if marshalErr != nil {
		payload = []byte(code)
	}
	return statusErr{
		code:           statusCode,
		msg:            string(payload),
		retryAfter:     retryAfter,
		skipAuthResult: true,
	}
}

func chatGPTWebSentinelObserverProtocolError(err error) statusErr {
	var runtimeErr *chatgptwebauth.SentinelRuntimeError
	if errors.As(err, &runtimeErr) && strings.TrimSpace(runtimeErr.Code) == "sentinel_sdk_busy" {
		return chatGPTWebSentinelRuntimeProtocolError(err)
	}
	retryAfter := time.Duration(0)
	if runtimeErr != nil {
		retryAfter = runtimeErr.RetryAfter
	}
	return chatGPTWebSentinelRuntimeProtocolError(&chatgptwebauth.SentinelRuntimeError{
		Code:       "sentinel_session_observer_unavailable",
		RetryAfter: retryAfter,
		Err:        err,
	})
}

func chatGPTWebTurnstileFinalizeRejection(err error) bool {
	var upstreamErr chatGPTWebHTTPError
	if errors.As(err, &upstreamErr) && upstreamErr.turnstileFinalizeRejection {
		return true
	}
	var status interface{ StatusCode() int }
	if !errors.As(err, &status) {
		return false
	}
	if status.StatusCode() != http.StatusBadRequest && status.StatusCode() != http.StatusForbidden {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "turnstile")
}

func chatGPTWebSentinelFinalizeRejection(err error) bool {
	var upstreamErr chatGPTWebHTTPError
	if errors.As(err, &upstreamErr) && upstreamErr.sentinelFinalizeRejection {
		return true
	}
	var status interface{ StatusCode() int }
	if !errors.As(err, &status) {
		return false
	}
	if status.StatusCode() != http.StatusBadRequest && status.StatusCode() != http.StatusForbidden {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "sentinel") || strings.Contains(lower, "session observer") ||
		strings.Contains(lower, "so_token") || strings.Contains(lower, "so-token")
}

func (e *ChatGPTWebExecutor) fetchChatGPTWebImageBootstrap(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, target string, headers map[string]string) (*fhttp.Response, []byte, error) {
	policy, _ := cliproxyexecutor.ImageBootstrapPolicyFromContext(ctx)
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			return nil, nil, cliproxyexecutor.ImageRequestContextError(ctx, context.Cause(ctx))
		}
		if attempt > 0 {
			setChatGPTWebImageTaskStage(ctx, cliproxyexecutor.ImagePhaseBootstrapRetryWait)
			started := time.Now()
			timer := time.NewTimer(helps.ChatGPTWebBootstrapRetryDelay(attempt))
			select {
			case <-ctx.Done():
				timer.Stop()
				cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseBootstrapRetryWait, started)
				return nil, nil, cliproxyexecutor.ImageRequestContextError(ctx, context.Cause(ctx))
			case <-timer.C:
			}
			cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseBootstrapRetryWait, started)
		}
		if ctx.Err() != nil {
			return nil, nil, cliproxyexecutor.ImageRequestContextError(ctx, context.Cause(ctx))
		}
		cliproxyexecutor.ObserveImageBootstrapAttempt(attempt > 0)
		if handle := chatGPTWebImageTaskHandleFromContext(ctx); handle != nil {
			handle.setBootstrapAttempt(attempt+1, policy.Retries+1)
		}
		response, body, err, timedOut := func() (*fhttp.Response, []byte, error, bool) {
			attemptCtx := ctx
			cancel := func() {}
			if policy.Timeout > 0 {
				attemptCtx, cancel = context.WithTimeout(ctx, policy.Timeout)
			}
			defer cancel()
			attemptClient := client
			if policy.Enabled() {
				var errClient error
				attemptClient, errClient = client.NewBootstrapAttempt(attemptCtx)
				if errClient != nil {
					return nil, nil, errClient, false
				}
				defer func() { attemptClient.CloseActiveAcquisitionConnections(); attemptClient.CloseIdleConnections() }()
			}
			response, errRequest := e.doChatGPTWebBootstrapRequest(attemptCtx, attemptClient, credential, target, headers, true)
			var body []byte
			if errRequest == nil {
				setChatGPTWebImageTaskStage(ctx, cliproxyexecutor.ImagePhaseBootstrapBody)
				started := time.Now()
				body, errRequest = readChatGPTWebResponseBody(response, chatGPTWebMaxHTMLBodyBytes)
				cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseBootstrapBody, started)
			}
			timedOut := policy.Timeout > 0 && errors.Is(attemptCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil
			if timedOut {
				cliproxyexecutor.ObserveImageBootstrapTimeout()
			}
			// A received HTTP rejection keeps its existing classification, even if
			// its error body could not be read before the phase deadline.
			if response != nil && (response.StatusCode < 200 || response.StatusCode >= 300) {
				return response, body, errRequest, false
			}
			if timedOut {
				errRequest = errors.Join(context.DeadlineExceeded, errRequest)
			}
			return response, body, errRequest, timedOut
		}()
		if ctx.Err() != nil {
			return nil, nil, cliproxyexecutor.ImageRequestContextError(ctx, context.Cause(ctx))
		}
		if err == nil {
			if attempt > 0 && response.StatusCode >= 200 && response.StatusCode < 300 {
				cliproxyexecutor.ObserveImageBootstrapRetrySuccess()
			}
			return response, body, nil
		}
		if !policy.Enabled() || !helps.ChatGPTWebBootstrapRetryable(err) {
			return response, body, err
		}
		if attempt >= policy.Retries {
			return nil, nil, &cliproxyexecutor.ImageBootstrapError{Cause: chatGPTWebTransportDiagnosticError(err, target), Timeout: timedOut}
		}
	}
}

func (e *ChatGPTWebExecutor) doChatGPTWebBootstrapRequest(
	ctx context.Context,
	client *chatgptwebauth.Client,
	credential *chatgptwebauth.Credential,
	targetURL string,
	headers map[string]string,
	observeBootstrap ...bool,
) (*fhttp.Response, error) {
	if client == nil {
		return nil, errors.New("chatgpt web bootstrap client is nil")
	}
	originalURL, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || originalURL == nil || originalURL.Scheme == "" || originalURL.Host == "" {
		return nil, errors.New("chatgpt web bootstrap URL is invalid")
	}
	currentURL := originalURL
	observe := len(observeBootstrap) > 0 && observeBootstrap[0]
	for redirects := 0; ; redirects++ {
		started := time.Now()
		if observe {
			setChatGPTWebImageTaskStage(ctx, cliproxyexecutor.ImagePhaseBootstrapHTTP)
		}
		e.recordChatGPTWebRequest(ctx, credential, http.MethodGet, currentURL.String(), headers, nil)
		response, errRequest := client.DoNoRedirectStream(ctx, http.MethodGet, currentURL.String(), headers, nil)
		if observe {
			cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseBootstrapHTTP, started)
		}
		if errRequest != nil {
			return nil, chatGPTWebTransportDiagnosticError(errRequest, currentURL.String())
		}
		helps.RecordAPIResponseMetadata(ctx, e.configSnapshot(), response.StatusCode, chatGPTWebResponseLogHeaders(response.Header))
		if !chatGPTWebBootstrapRedirectStatus(response.StatusCode) {
			return response, nil
		}
		location := strings.TrimSpace(response.Header.Get("Location"))
		if location == "" {
			return response, nil
		}
		nextURL, errLocation := currentURL.Parse(location)
		if errLocation != nil || !sameChatGPTWebAssetOrigin(originalURL, nextURL) {
			return response, nil
		}
		if redirects >= chatGPTWebMaxBootstrapRedirects {
			_ = response.Body.Close()
			return nil, fmt.Errorf("chatgpt web redirect chain exceeds %d hops", chatGPTWebMaxBootstrapRedirects)
		}
		started = time.Now()
		if observe {
			setChatGPTWebImageTaskStage(ctx, cliproxyexecutor.ImagePhaseBootstrapBody)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, chatGPTWebMaxErrorBodyBytes))
		if observe {
			cliproxyexecutor.ObserveRequestPhaseContext(ctx, cliproxyexecutor.ImagePhaseBootstrapBody, started)
		}
		if errClose := response.Body.Close(); errClose != nil {
			return nil, fmt.Errorf("close chatgpt web bootstrap redirect response: %w", errClose)
		}
		currentURL = nextURL
	}
}

func chatGPTWebBootstrapRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func (e *ChatGPTWebExecutor) doChatGPTWebJSON(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, path string, body any) (*fhttp.Response, []byte, error) {
	return e.doChatGPTWebJSONWithMaxBody(ctx, client, credential, path, body, chatGPTWebMaxJSONBodyBytes)
}

func (e *ChatGPTWebExecutor) doChatGPTWebJSONWithMaxBody(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, path string, body any, maxBodyBytes int) (*fhttp.Response, []byte, error) {
	headers := e.chatGPTWebHeaders(credential, path, map[string]string{
		"accept":       "application/json",
		"content-type": "application/json",
	})
	return e.doChatGPTWebJSONWithHeadersAndMaxBody(ctx, client, credential, path, headers, body, maxBodyBytes)
}

func (e *ChatGPTWebExecutor) doChatGPTWebJSONWithHeaders(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, path string, headers map[string]string, body any) (*fhttp.Response, []byte, error) {
	return e.doChatGPTWebJSONWithHeadersAndMaxBody(ctx, client, credential, path, headers, body, chatGPTWebMaxJSONBodyBytes)
}

func (e *ChatGPTWebExecutor) doChatGPTWebJSONWithHeadersAndMaxBody(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, path string, headers map[string]string, body any, maxBodyBytes int) (*fhttp.Response, []byte, error) {
	payload, _ := json.Marshal(body)
	e.recordChatGPTWebRequest(ctx, credential, http.MethodPost, path, headers, payload)
	response, err := client.DoJSONStream(ctx, http.MethodPost, e.chatGPTWebBaseURL()+path, headers, body)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.configSnapshot(), err)
		return nil, nil, chatGPTWebTransportDiagnosticError(err, path)
	}
	helps.RecordAPIResponseMetadata(ctx, e.configSnapshot(), response.StatusCode, chatGPTWebResponseLogHeaders(response.Header))
	data, err := readChatGPTWebResponseBody(response, maxBodyBytes)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.configSnapshot(), err)
		return response, nil, chatGPTWebTransportDiagnosticError(err, path)
	}
	sanitizedData := chatGPTWebResponseLogBody(path, data)
	helps.AppendAPIResponseChunk(ctx, e.configSnapshot(), sanitizedData)
	if challengeErr := newChatGPTWebChallengeResponseError(response.StatusCode, path, data, response.Header); challengeErr != nil {
		return response, data, challengeErr
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response, data, newChatGPTWebStatusError(response.StatusCode, path, data, response.Header)
	}
	return response, data, nil
}

func (e *ChatGPTWebExecutor) doChatGPTWebJSONStream(ctx context.Context, client *chatgptwebauth.Client, credential *chatgptwebauth.Credential, path string, headers map[string]string, body any) (*fhttp.Response, error) {
	payload, _ := json.Marshal(body)
	e.recordChatGPTWebRequest(ctx, credential, http.MethodPost, path, headers, payload)
	traceCtx := ctx
	if traceCtx == nil {
		traceCtx = context.Background()
	}
	var requestWritten atomic.Bool
	traceCtx = fhttptrace.WithClientTrace(traceCtx, &fhttptrace.ClientTrace{
		WroteRequest: func(fhttptrace.WroteRequestInfo) {
			requestWritten.Store(true)
		},
	})
	response, err := client.DoJSONStream(traceCtx, http.MethodPost, e.chatGPTWebBaseURL()+path, headers, body)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.configSnapshot(), err)
		if requestWritten.Load() {
			err = chatGPTWebCommittedRequestError(ctx, err)
		}
		return nil, chatGPTWebTransportDiagnosticError(err, path)
	}
	helps.RecordAPIResponseMetadata(ctx, e.configSnapshot(), response.StatusCode, chatGPTWebResponseLogHeaders(response.Header))
	if challengeErr := newChatGPTWebChallengeResponseError(response.StatusCode, path, nil, response.Header); challengeErr != nil {
		data := readAndCloseChatGPTWebErrorBody(response.Body)
		challengeErr = newChatGPTWebChallengeResponseError(response.StatusCode, path, data, response.Header)
		return nil, challengeErr
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data := readAndCloseChatGPTWebErrorBody(response.Body)
		sanitizedData := chatGPTWebResponseLogBody(path, data)
		helps.AppendAPIResponseChunk(ctx, e.configSnapshot(), sanitizedData)
		return nil, newChatGPTWebStatusError(response.StatusCode, path, data, response.Header)
	}
	wrapChatGPTWebChallengeInspectingBody(response, path)
	return response, nil
}

func wrapChatGPTWebChallengeInspectingBody(response *fhttp.Response, path string) {
	if response == nil || response.Body == nil || response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return
	}
	contentType := strings.ToLower(strings.TrimSpace(response.Header.Get("Content-Type")))
	cfMitigated := strings.ToLower(strings.TrimSpace(response.Header.Get("cf-mitigated")))
	if !strings.Contains(contentType, "text/html") && (cfMitigated == "" || cfMitigated == "none") {
		return
	}
	response.Body = &chatGPTWebChallengeInspectingBody{
		ReadCloser: response.Body,
		status:     response.StatusCode,
		path:       path,
		headers:    response.Header,
	}
}

func chatGPTWebStreamChallengeError(response *fhttp.Response) error {
	if response == nil {
		return nil
	}
	body, ok := response.Body.(*chatGPTWebChallengeInspectingBody)
	if !ok {
		return nil
	}
	return body.challengeError()
}

func readChatGPTWebResponseBody(response *fhttp.Response, maxSuccessBytes int) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, errors.New("chatgpt web response body is nil")
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 &&
		response.ContentLength > int64(maxSuccessBytes) {
		_ = response.Body.Close()
		return nil, chatGPTWebResponseBodyLimitError(maxSuccessBytes)
	}
	var (
		payload []byte
		errRead error
	)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return readAndCloseChatGPTWebErrorBody(response.Body), nil
	} else {
		payload, errRead = readChatGPTWebSuccessBody(response.Body, maxSuccessBytes)
	}
	errClose := response.Body.Close()
	if errRead != nil {
		return nil, errRead
	}
	if errClose != nil {
		return nil, fmt.Errorf("close chatgpt web response body: %w", errClose)
	}
	return payload, nil
}

func readAndCloseChatGPTWebErrorBody(body io.ReadCloser) []byte {
	if body == nil {
		return []byte("<upstream-error-body-unavailable>")
	}
	payload, errRead := readChatGPTWebErrorBody(body)
	_ = body.Close()
	if errRead != nil {
		return []byte("<upstream-error-body-unavailable>")
	}
	return payload
}

func readChatGPTWebSuccessBody(body io.Reader, maxBytes int) ([]byte, error) {
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
		return nil, chatGPTWebResponseBodyLimitError(maxBytes)
	}
	return payload, nil
}

func chatGPTWebResponseBodyLimitError(maxBytes int) error {
	return statusErr{
		code:           http.StatusBadGateway,
		msg:            fmt.Sprintf("chatgpt web response body exceeds %d bytes", maxBytes),
		skipAuthResult: true,
	}
}

func readChatGPTWebErrorBody(body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, errors.New("chatgpt web response body is nil")
	}
	payload, err := io.ReadAll(io.LimitReader(body, chatGPTWebMaxErrorBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read chatgpt web error body: %w", err)
	}
	if len(payload) > chatGPTWebMaxErrorBodyBytes {
		return []byte("<upstream-error-body-truncated>"), nil
	}
	return payload, nil
}

func consumeChatGPTWebConversation(ctx context.Context, body io.Reader, accumulator *helps.ChatGPTWebConversationAccumulator, onDelta func(string) bool) error {
	decoder := helps.NewChatGPTWebSSEDecoder(chatGPTWebSSEMaxFrameBytes)
	buffer := make([]byte, 32<<10)
	applyPayload := func(payload []byte) (bool, error) {
		eventType := normalizeChatGPTWebErrorClassification(gjson.GetBytes(payload, "type").String())
		eventCode := normalizeChatGPTWebErrorClassification(gjson.GetBytes(payload, "code").String())
		if gjson.GetBytes(payload, "error").Exists() || eventType == "error" ||
			eventCode == "account_deleted" || eventCode == "account_deactivated" {
			if authError := chatgptwebauth.ClassifyPermanentAccountResponse(http.StatusForbidden, payload); authError != nil {
				return false, newChatGPTWebStatusError(http.StatusForbidden, "/backend-api/conversation", payload, nil)
			}
		}
		delta, done, err := accumulator.Apply(payload)
		if err != nil {
			return false, err
		}
		if delta != "" && onDelta != nil && !onDelta(delta) {
			if ctx != nil && ctx.Err() != nil {
				return false, ctx.Err()
			}
			return false, context.Canceled
		}
		return done, nil
	}
	for {
		count, errRead := body.Read(buffer)
		if count > 0 {
			payloads, err := decoder.Feed(buffer[:count], false)
			if err != nil {
				return err
			}
			for _, payload := range payloads {
				done, err := applyPayload(payload)
				if err != nil {
					return err
				}
				if done {
					return nil
				}
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
			for _, payload := range payloads {
				done, errApply := applyPayload(payload)
				if errApply != nil {
					return errApply
				}
				if done {
					return nil
				}
			}
			return helps.IncompleteStreamError("chatgpt web")
		}
	}
}

func chatGPTWebUpstreamProtocolError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	var status interface{ StatusCode() int }
	if errors.As(err, &status) {
		return err
	}
	return statusErr{
		code:           http.StatusBadGateway,
		msg:            err.Error(),
		skipAuthResult: true,
		retryOtherAuth: true,
	}
}

func (e *ChatGPTWebExecutor) chatGPTWebHeaders(credential *chatgptwebauth.Credential, path string, extra map[string]string) map[string]string {
	headers := map[string]string{
		"authorization":           "Bearer " + strings.TrimSpace(credential.AccessToken),
		"origin":                  e.chatGPTWebBaseURL(),
		"referer":                 e.chatGPTWebBaseURL() + "/",
		"oai-device-id":           strings.TrimSpace(credential.DeviceID),
		"oai-session-id":          strings.TrimSpace(credential.SessionID),
		"oai-language":            credential.Persona.Language,
		"oai-client-version":      chatGPTWebClientVersion,
		"oai-client-build-number": chatGPTWebClientBuildNumber,
		"x-openai-target-path":    path,
		"x-openai-target-route":   path,
		"priority":                "u=1, i",
		"pragma":                  "no-cache",
		"sec-fetch-dest":          "empty",
		"sec-fetch-mode":          "cors",
		"sec-fetch-site":          "same-origin",
	}
	for key, value := range extra {
		if strings.TrimSpace(value) != "" {
			headers[key] = value
		}
	}
	return headers
}

func (e *ChatGPTWebExecutor) chatGPTWebBaseURL() string {
	if e != nil && strings.TrimSpace(e.runtimeBaseURL) != "" {
		return strings.TrimRight(strings.TrimSpace(e.runtimeBaseURL), "/")
	}
	return "https://chatgpt.com"
}

func (e *ChatGPTWebExecutor) recordChatGPTWebRequest(ctx context.Context, credential *chatgptwebauth.Credential, method, path string, headers map[string]string, body []byte) {
	httpHeaders := chatGPTWebRequestLogHeaders(headers)
	authValue := ""
	if credential != nil {
		authValue = chatGPTWebLogEmail(credential.Email)
	}
	requestURL := path
	if !strings.HasPrefix(requestURL, "http://") && !strings.HasPrefix(requestURL, "https://") {
		requestURL = e.chatGPTWebBaseURL() + path
	}
	requestURL = chatGPTWebRequestLogURL(requestURL)
	helps.RecordAPIRequest(ctx, e.configSnapshot(), helps.UpstreamRequestLog{
		URL:       requestURL,
		Method:    method,
		Headers:   httpHeaders,
		Body:      chatGPTWebRequestLogBody(path, body),
		Provider:  e.Identifier(),
		AuthType:  "email",
		AuthValue: authValue,
	})
}

func chatGPTWebRequestLogHeaders(headers map[string]string) http.Header {
	httpHeaders := make(http.Header, len(headers))
	for key, value := range headers {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "authorization",
			"oai-device-id",
			"oai-session-id",
			"openai-sentinel-chat-requirements-token",
			"openai-sentinel-proof-token",
			"openai-sentinel-turnstile-token",
			"openai-sentinel-so-token",
			"x-conduit-token":
			value = "<redacted>"
		}
		httpHeaders.Set(key, value)
	}
	return httpHeaders
}

func chatGPTWebLogEmail(value string) string {
	value = strings.TrimSpace(value)
	local, domain, found := strings.Cut(value, "@")
	if !found || local == "" || domain == "" {
		return "<redacted-email>"
	}
	prefix := local[:1]
	if len(local) > 1 {
		prefix = local[:2]
	}
	return prefix + "***@" + domain
}

func chatGPTWebRequestLogBody(path string, body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return []byte("<redacted-non-json-body>")
	}
	redactPreparePayload := strings.Contains(strings.ToLower(path), "/chat-requirements/prepare")
	var redact func(any)
	redact = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, item := range typed {
				normalized := strings.ToLower(strings.TrimSpace(key))
				switch normalized {
				case "access_token", "refresh_token", "id_token", "session_token",
					"prepare_token", "proof_token", "turnstile_token", "so_token",
					"conduit_token", "token", "password", "totp_secret", "cookie", "cookies":
					typed[key] = "<redacted>"
					continue
				case "email", "login_hint":
					typed[key] = chatGPTWebLogEmail(chatGPTWebAnyString(item))
					continue
				case "p":
					if redactPreparePayload {
						typed[key] = "<redacted>"
						continue
					}
				}
				if redacted, ok := chatGPTWebRedactSignedURL(item); ok {
					typed[key] = redacted
					continue
				}
				redact(item)
			}
		case []any:
			for index, item := range typed {
				if redacted, ok := chatGPTWebRedactSignedURL(item); ok {
					typed[index] = redacted
					continue
				}
				redact(item)
			}
		}
	}
	if redacted, ok := chatGPTWebRedactSignedURL(root); ok {
		root = redacted
	} else {
		redact(root)
	}
	sanitized, err := json.Marshal(root)
	if err != nil {
		return []byte("<redacted-json-body>")
	}
	return sanitized
}

func chatGPTWebRequestLogURL(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "<redacted-invalid-url>"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed.String()
}

func chatGPTWebResponseLogBody(path string, body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	if bytes.Equal(body, []byte("<upstream-error-body-truncated>")) {
		return body
	}
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return []byte("<redacted-non-json-response-body>")
	}
	redactGenericURL := strings.Contains(strings.ToLower(path), "/download")
	redactPreparePayload := strings.Contains(strings.ToLower(path), "/chat-requirements/prepare")
	var redact func(any, bool)
	redact = func(value any, insideSentinelChallenge bool) {
		switch typed := value.(type) {
		case map[string]any:
			for key, item := range typed {
				normalized := strings.ToLower(strings.TrimSpace(key))
				switch normalized {
				case "access_token", "refresh_token", "id_token", "session_token",
					"prepare_token", "proof_token", "turnstile_token", "so_token",
					"conduit_token", "token", "password", "totp_secret", "cookie", "cookies":
					typed[key] = "<redacted>"
					continue
				}
				if insideSentinelChallenge && (normalized == "collector_dx" || normalized == "snapshot_dx" || redactPreparePayload && normalized == "dx") {
					typed[key] = "<redacted>"
					continue
				}
				if normalized == "upload_url" || normalized == "download_url" || (redactGenericURL && normalized == "url") {
					typed[key] = "<redacted-signed-url>"
					continue
				}
				if redacted, ok := chatGPTWebRedactSignedURL(item); ok {
					typed[key] = redacted
					continue
				}
				redact(item, insideSentinelChallenge || normalized == "turnstile" || normalized == "so")
			}
		case []any:
			for index, item := range typed {
				if redacted, ok := chatGPTWebRedactSignedURL(item); ok {
					typed[index] = redacted
					continue
				}
				redact(item, insideSentinelChallenge)
			}
		}
	}
	if redacted, ok := chatGPTWebRedactSignedURL(root); ok {
		root = redacted
	} else {
		redact(root, false)
	}
	sanitized, err := json.Marshal(root)
	if err != nil {
		return []byte("<redacted-json-response-body>")
	}
	return sanitized
}

func chatGPTWebRedactSignedURL(value any) (string, bool) {
	rawURL, ok := value.(string)
	if !ok {
		return "", false
	}
	trimmed := strings.TrimSpace(rawURL)
	if (strings.Contains(trimmed, "https://") || strings.Contains(trimmed, "http://")) &&
		strings.Contains(trimmed, "?") {
		return "<redacted-signed-url>", true
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", false
	}
	if parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" {
		return "", false
	}
	return "<redacted-signed-url>", true
}

func chatGPTWebStatusErrorBody(path string, body []byte) []byte {
	if bytes.Equal(body, []byte("<upstream-error-body-truncated>")) {
		return body
	}
	if len(body) == 0 || json.Valid(body) {
		return chatGPTWebResponseLogBody(path, body)
	}
	return []byte("<redacted-non-json-response-body>")
}

type chatGPTWebHTTPError struct {
	statusErr
	headers                    http.Header
	path                       string
	lifecycleError             *chatgptwebauth.AuthError
	turnstileFinalizeRejection bool
	sentinelFinalizeRejection  bool
	libraryStorageRejected     bool
	libraryUploadBytes         int64
	diagnostic                 *cliproxyauth.ErrorDiagnostic
}

type chatGPTWebDiagnosticError struct {
	cause      error
	diagnostic *cliproxyauth.ErrorDiagnostic
}

func (e chatGPTWebDiagnosticError) Error() string {
	if e.cause == nil {
		return "chatgpt web upstream request failed"
	}
	return e.cause.Error()
}

func (e chatGPTWebDiagnosticError) Unwrap() error { return e.cause }

func (e chatGPTWebDiagnosticError) AuthErrorDiagnostic() *cliproxyauth.ErrorDiagnostic {
	return e.diagnostic.Clone()
}

func chatGPTWebTransportDiagnosticError(err error, path string) error {
	if err == nil {
		return nil
	}
	type diagnosticProvider interface {
		AuthErrorDiagnostic() *cliproxyauth.ErrorDiagnostic
	}
	var existing diagnosticProvider
	if errors.As(err, &existing) && existing != nil {
		return err
	}
	return chatGPTWebDiagnosticError{
		cause:      err,
		diagnostic: helps.ClassifyChatGPTWebTransportDiagnostic(err, path),
	}
}

// AuthErrorDiagnostic returns a redacted diagnostic safe for management views.
func (e chatGPTWebHTTPError) AuthErrorDiagnostic() *cliproxyauth.ErrorDiagnostic {
	return e.diagnostic.Clone()
}

func (e chatGPTWebHTTPError) Headers() http.Header {
	if len(e.headers) == 0 {
		return nil
	}
	return e.headers.Clone()
}

// ChatGPTWebRequestPath identifies the upstream stage that returned the error.
func (e chatGPTWebHTTPError) ChatGPTWebRequestPath() string {
	return e.path
}

// ChatGPTWebLifecycleError returns a structured lifecycle transition carried by
// the upstream response.
func (e chatGPTWebHTTPError) ChatGPTWebLifecycleError() *chatgptwebauth.AuthError {
	if e.lifecycleError == nil {
		return nil
	}
	result := *e.lifecycleError
	return &result
}

func newChatGPTWebStatusError(code int, path string, body []byte, headers fhttp.Header) chatGPTWebHTTPError {
	sanitizedBody := chatGPTWebStatusErrorBody(path, body)
	lifecycleError := chatgptwebauth.ClassifyPermanentAccountResponse(code, body)
	turnstileFinalizeRejection := false
	sentinelFinalizeRejection := false
	if path == "/backend-api/sentinel/chat-requirements/finalize" &&
		(code == http.StatusBadRequest || code == http.StatusForbidden) {
		lowerBody := bytes.ToLower(body)
		turnstileFinalizeRejection = bytes.Contains(lowerBody, []byte("turnstile"))
		sentinelFinalizeRejection = turnstileFinalizeRejection ||
			bytes.Contains(lowerBody, []byte("sentinel")) ||
			bytes.Contains(lowerBody, []byte("session observer")) ||
			bytes.Contains(lowerBody, []byte("so_token")) ||
			bytes.Contains(lowerBody, []byte("so-token"))
	}
	err := chatGPTWebHTTPError{
		statusErr:                  statusErr{code: code, msg: strings.TrimSpace(string(sanitizedBody))},
		path:                       path,
		lifecycleError:             lifecycleError,
		turnstileFinalizeRejection: turnstileFinalizeRejection,
		sentinelFinalizeRejection:  sentinelFinalizeRejection,
		diagnostic:                 helps.ClassifyChatGPTWebHTTPDiagnostic(code, path, body, headers),
		libraryStorageRejected:     (path == "/backend-api/files" || path == "/backend-api/files/process_upload_stream" || strings.HasSuffix(path, "/uploaded")) && chatgptwebauth.LibraryStorageRejection(body),
	}
	switch code {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed,
		http.StatusConflict, http.StatusRequestEntityTooLarge,
		http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity:
		err.statusErr.skipAuthResult = true
	}
	if lifecycleError != nil {
		err.statusErr.skipAuthResult = true
		err.statusErr.retryOtherAuth = true
	} else {
		if code == http.StatusForbidden && chatGPTWebRequestScopedForbidden(path, body) {
			err.statusErr.skipAuthResult = true
			err.statusErr.retryOtherAuth = false
		}
		if sentinelFinalizeRejection {
			err.statusErr.skipAuthResult = true
			err.statusErr.retryOtherAuth = false
		}
	}
	if code == http.StatusNotFound {
		err.statusErr.retryOtherAuth = true
	}
	retryAfter := ""
	if headers != nil {
		retryAfter = headers.Get("Retry-After")
	}
	if strings.TrimSpace(retryAfter) != "" {
		err.statusErr.retryAfter = parseXAIRetryAfterHeader(retryAfter, time.Now())
		err.headers = http.Header{"Retry-After": []string{retryAfter}}
	}
	return err
}

func newChatGPTWebChallengeResponseError(status int, path string, body []byte, headers fhttp.Header) error {
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return nil
	}
	diagnostic := helps.ClassifyChatGPTWebHTTPDiagnostic(status, path, body, headers)
	if diagnostic == nil || !diagnostic.Cloudflare {
		return nil
	}
	err := newChatGPTWebStatusError(http.StatusBadGateway, path, body, headers)
	err.statusErr.msg = "chatgpt web upstream returned a Cloudflare challenge"
	err.statusErr.skipAuthResult = true
	err.statusErr.retryOtherAuth = true
	err.diagnostic = diagnostic
	return err
}

func logChatGPTWebSafeDiagnostic(ctx context.Context, auth *cliproxyauth.Auth, err error) {
	if err == nil {
		return
	}
	type diagnosticProvider interface {
		AuthErrorDiagnostic() *cliproxyauth.ErrorDiagnostic
	}
	var provider diagnosticProvider
	if !errors.As(err, &provider) || provider == nil {
		return
	}
	diagnostic := provider.AuthErrorDiagnostic()
	if diagnostic == nil {
		return
	}
	if auth != nil {
		diagnostic.AuthIndex = auth.EnsureIndex()
		if credential, errCredential := chatgptwebauth.ParseCredential(auth.Metadata); errCredential == nil && credential != nil {
			chatgptwebauth.ResolveCredentialPersona(credential, auth.ID)
			browserEnvironment := chatgptwebauth.ResolveCredentialBrowserEnvironment(credential, auth.ID)
			diagnostic.Persona = strings.TrimSpace(credential.Persona.Profile)
			diagnostic.CatalogVersion = strings.TrimSpace(credential.Persona.CatalogVersion)
			diagnostic.CatalogID = strings.TrimSpace(credential.Persona.CatalogID)
			diagnostic.TransportPersonaID = strings.TrimSpace(credential.Persona.CatalogID)
			diagnostic.BrowserEnvironmentID = strings.TrimSpace(browserEnvironment.CatalogID)
			diagnostic.TLSProfile = strings.TrimSpace(credential.Persona.Profile)
			diagnostic.Platform = strings.TrimSpace(credential.Persona.Platform)
			diagnostic.UAMajor = chatGPTWebUserAgentMajor(credential.Persona.UserAgent)
		}
	}
	fields := helps.ChatGPTWebDiagnosticLogFields(diagnostic)
	helps.LogWithRequestID(ctx).WithFields(log.Fields(fields)).Warn("chatgpt web upstream request failed")
}

func chatGPTWebUserAgentMajor(userAgent string) string {
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

func chatGPTWebRequestScopedForbidden(path string, body []byte) bool {
	classifications := chatGPTWebStructuredErrorClassifications(body)
	for _, classification := range classifications {
		switch classification {
		case "access_denied", "account_restricted", "account_suspended", "account_inactive",
			"account_unavailable", "insufficient_quota", "permission_error", "unauthorized":
			return false
		}
	}
	if strings.HasPrefix(path, "/backend-api/sentinel/") || path == "/sentinel/sdk.js" {
		return true
	}
	if chatGPTWebSentinelConversationRejection(path, body) {
		return true
	}
	for _, classification := range classifications {
		switch classification {
		case "bad_request", "content_policy_violation", "invalid_prompt", "invalid_request",
			"invalid_request_error", "invalid_value", "moderation_blocked", "unsupported_parameter",
			"unsupported_value", "validation_error":
			return true
		}
	}
	return false
}

func chatGPTWebSentinelConversationRejection(path string, body []byte) bool {
	if path != "/backend-api/conversation" && path != "/backend-api/f/conversation" {
		return false
	}
	for _, classification := range chatGPTWebStructuredErrorClassifications(body) {
		if chatGPTWebSentinelErrorClassification(classification) {
			return true
		}
	}
	return false
}

func chatGPTWebStructuredErrorClassifications(body []byte) []string {
	paths := [...]string{
		"error",
		"error.code",
		"error.type",
		"code",
		"type",
		"detail.code",
		"detail.type",
		"page.payload.code",
		"page.payload.type",
		"page.payload.error",
		"page.payload.error.code",
		"page.payload.error.type",
	}
	values := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		result := gjson.GetBytes(body, path)
		if result.Type != gjson.String {
			continue
		}
		normalized := normalizeChatGPTWebErrorClassification(result.String())
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		values = append(values, normalized)
	}
	return values
}

func normalizeChatGPTWebErrorClassification(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.NewReplacer("-", "_", " ", "_", ".", "_").Replace(value)
	return strings.Trim(value, "_")
}

func chatGPTWebSentinelErrorClassification(value string) bool {
	switch value {
	case "chat_requirements", "chat_requirements_failed", "invalid_proof_token",
		"invalid_so_token", "proof_token", "session_observer", "session_observer_failed",
		"so_token", "turnstile", "turnstile_required":
		return true
	}
	return strings.HasPrefix(value, "sentinel_") ||
		strings.HasPrefix(value, "invalid_sentinel_") ||
		strings.HasPrefix(value, "turnstile_") ||
		strings.HasPrefix(value, "invalid_turnstile_")
}

func chatGPTWebLocalProtocolError(code int, message string) statusErr {
	return statusErr{
		code:           code,
		msg:            strings.TrimSpace(message),
		skipAuthResult: true,
	}
}

func chatGPTWebTurnstileProtocolError(message string) statusErr {
	payload, err := json.Marshal(map[string]any{
		"error": map[string]any{
			"message": strings.TrimSpace(message),
			"type":    "upstream_protocol_error",
			"code":    "turnstile_required",
		},
	})
	if err != nil {
		return chatGPTWebLocalProtocolError(http.StatusBadGateway, message)
	}
	return chatGPTWebLocalProtocolError(http.StatusBadGateway, string(payload))
}

func cloneChatGPTWebHeaders(headers fhttp.Header) http.Header {
	if headers == nil {
		return nil
	}
	cloned := make(http.Header, len(headers))
	for key, values := range headers {
		if strings.HasPrefix(key, ":") ||
			strings.EqualFold(key, "Set-Cookie") ||
			strings.EqualFold(key, "Set-Cookie2") {
			continue
		}
		cloned[key] = append([]string(nil), values...)
	}
	return cloned
}

func chatGPTWebResponseLogHeaders(headers fhttp.Header) http.Header {
	cloned := cloneChatGPTWebHeaders(headers)
	if cloned == nil {
		return nil
	}
	cloned.Del("Cookie")
	cloned.Del("Set-Cookie")
	cloned.Del("Set-Cookie2")
	if cloned.Get("Location") != "" {
		cloned.Set("Location", "<redacted-location>")
	}
	return cloned
}

func requiredJSONFlag(root map[string]any, key, field string) bool {
	value, _ := root[key].(map[string]any)
	required, _ := value[field].(bool)
	return required
}

func normalizeChatGPTWebThinkingEffort(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low", "medium", "high":
		return strings.ToLower(strings.TrimSpace(value))
	case "xhigh", "extended":
		return "extended"
	default:
		return ""
	}
}

func chatGPTWebClientContext() map[string]any {
	return map[string]any{
		"is_dark_mode":      false,
		"time_since_loaded": 120,
		"page_height":       900,
		"page_width":        1400,
		"pixel_ratio":       2,
		"screen_height":     1440,
		"screen_width":      2560,
		"app_name":          "chatgpt.com",
	}
}

func chatGPTWebRequestUsesSearch(prepared *chatGPTWebPreparedRequest) bool {
	return prepared != nil && (prepared.request.WebSearch || chatGPTWebSearchAlias(prepared.routeModel))
}

func chatGPTWebSearchAlias(model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	return strings.HasPrefix(model, "gpt-4o-search-preview") ||
		strings.HasPrefix(model, "gpt-4o-mini-search-preview") ||
		strings.HasPrefix(model, "gpt-5-search-api")
}

func chatGPTWebOriginalRequestUsesSearch(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	return gjson.GetBytes(payload, "web_search_options").Exists()
}

func sendChatGPTWebStreamChunk(ctx context.Context, out chan<- cliproxyexecutor.StreamChunk, chunk cliproxyexecutor.StreamChunk) bool {
	if ctx == nil {
		out <- chunk
		return true
	}
	select {
	case out <- chunk:
		return true
	case <-ctx.Done():
		return false
	}
}

func (e *ChatGPTWebExecutor) streamDeferredChatGPTWebResponse(
	ctx context.Context,
	auth *cliproxyauth.Auth,
	credential *chatgptwebauth.Credential,
	prepared *chatGPTWebPreparedRequest,
	client *chatgptwebauth.Client,
	reporter *helps.UsageReporter,
	headers http.Header,
	passthroughState *cliproxyexecutor.ImageGenerationStreamPassthroughState,
	enablePassthrough bool,
	cleanup func(),
	work func() ([]byte, error),
) *cliproxyexecutor.StreamResult {
	var cleanupOnce sync.Once
	finishCleanup := func() {
		cleanupOnce.Do(func() {
			if cleanup != nil {
				cleanup()
			}
		})
	}
	out := make(chan cliproxyexecutor.StreamChunk)
	if prepared.requestUsageOutcome != nil {
		prepared.requestUsageOutcome.AcceptStreamAttempt(cliproxyexecutor.RequestUsageAttemptFromContext(ctx))
	}
	go func() {
		defer close(out)
		defer prepared.discardUsageProjection()
		if !sendChatGPTWebStreamChunk(ctx, out, cliproxyexecutor.BootstrapCommitStreamChunk()) {
			publishChatGPTWebStreamFailure(ctx, reporter, prepared.executionDiagnostics, chatGPTWebStreamDeliveryError(ctx))
			e.finishChatGPTWebRuntimeClient(ctx, auth, credential, client)
			finishCleanup()
			return
		}
		var cleanupParts atomic.Int32
		cleanupParts.Store(2)
		finishCleanupPart := func() {
			if cleanupParts.Add(-1) == 0 {
				finishCleanup()
			}
		}
		defer finishCleanupPart()
		type deferredResult struct {
			completed []byte
			err       error
		}
		resultCh := make(chan deferredResult, 1)
		go func() {
			defer e.finishChatGPTWebRuntimeClient(ctx, auth, credential, client)
			defer finishCleanupPart()
			completed, err := work()
			resultCh <- deferredResult{completed: completed, err: err}
		}()

		initialWait := e.streamInitialWait
		if initialWait < 0 {
			initialWait = 0
		}
		initialTimer := time.NewTimer(initialWait)
		defer initialTimer.Stop()
		var heartbeatTicker *time.Ticker
		var heartbeat <-chan time.Time
		var contextDone <-chan struct{}
		if ctx != nil {
			contextDone = ctx.Done()
		}
		defer func() {
			if heartbeatTicker != nil {
				heartbeatTicker.Stop()
			}
		}()

		var completed []byte
		sendPayload := func(payload []byte) bool {
			if enablePassthrough && passthroughState != nil && chatGPTWebStreamHasSemanticPayload(payload) {
				passthroughState.SetEnabled(true)
			}
			payload = chatGPTWebTrustedSSEFrame(payload, prepared.trustUpstreamSSE)
			return sendChatGPTWebStreamChunk(ctx, out, cliproxyexecutor.StreamChunk{Payload: payload})
		}
		sendHeartbeat := func() bool {
			payload := chatGPTWebDeferredHeartbeat(prepared, "", 0)
			return sendChatGPTWebStreamChunk(ctx, out, cliproxyexecutor.StreamChunk{Payload: payload})
		}
		for completed == nil {
			select {
			case result := <-resultCh:
				if result.err != nil {
					result.err = e.handleChatGPTWebRuntimeLifecycleError(ctx, auth, result.err)
					logChatGPTWebSafeDiagnostic(ctx, auth, result.err)
					publishChatGPTWebStreamFailure(ctx, reporter, prepared.executionDiagnostics, result.err)
					_ = sendChatGPTWebStreamChunk(ctx, out, cliproxyexecutor.StreamChunk{Err: result.err})
					return
				}
				if len(result.completed) == 0 {
					errEmpty := errors.New("chatgpt web deferred stream completed without a response")
					publishChatGPTWebStreamFailure(ctx, reporter, prepared.executionDiagnostics, errEmpty)
					_ = sendChatGPTWebStreamChunk(ctx, out, cliproxyexecutor.StreamChunk{Err: errEmpty})
					return
				}
				completed = result.completed
			case <-initialTimer.C:
				if !sendHeartbeat() {
					publishChatGPTWebStreamFailure(ctx, reporter, prepared.executionDiagnostics, chatGPTWebStreamDeliveryError(ctx))
					return
				}
				if e.streamHeartbeat > 0 {
					heartbeatTicker = time.NewTicker(e.streamHeartbeat)
					heartbeat = heartbeatTicker.C
				}
			case <-heartbeat:
				if !sendHeartbeat() {
					publishChatGPTWebStreamFailure(ctx, reporter, prepared.executionDiagnostics, chatGPTWebStreamDeliveryError(ctx))
					return
				}
			case <-contextDone:
				publishChatGPTWebStreamFailure(ctx, reporter, prepared.executionDiagnostics, chatGPTWebStreamDeliveryError(ctx))
				return
			}
		}

		var param any
		response := gjson.GetBytes(completed, "response")
		responseID := response.Get("id").String()
		model := response.Get("model").String()
		if model == "" {
			model = prepared.routeModel
		}
		emitEvent := func(event []byte) bool {
			chunks := sdktranslator.TranslateStream(ctx, sdktranslator.FormatCodex, prepared.responseFormat, prepared.routeModel,
				prepared.originalPayload, prepared.canonicalBody, append([]byte("data: "), event...), &param)
			for _, chunk := range chunks {
				if !sendPayload(chunk) {
					return false
				}
			}
			return true
		}
		if !emitChatGPTWebEventsFromCompleted(responseID, model, response, emitEvent) {
			publishChatGPTWebStreamFailure(ctx, reporter, prepared.executionDiagnostics, chatGPTWebStreamDeliveryError(ctx))
			return
		}
		publishChatGPTWebTerminalUsage(ctx, reporter, prepared, completed)
		if prepared.terminalMarker {
			_ = sendChatGPTWebStreamChunk(ctx, out, cliproxyexecutor.SuccessfulStreamTerminalChunk())
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: headers, Chunks: out}
}

func chatGPTWebTrustedSSEFrame(payload []byte, enabled bool) []byte {
	if !enabled || len(payload) == 0 || bytes.HasSuffix(payload, []byte("\n\n")) || bytes.HasSuffix(payload, []byte("\r\n\r\n")) {
		return payload
	}
	framed := make([]byte, 0, len(payload)+2)
	framed = append(framed, payload...)
	if bytes.HasSuffix(payload, []byte{'\n'}) {
		return append(framed, '\n')
	}
	return append(framed, '\n', '\n')
}

func chatGPTWebStreamHasSemanticPayload(payload []byte) bool {
	for _, line := range bytes.Split(payload, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == ':' {
			continue
		}
		return true
	}
	return false
}

func chatGPTWebDeferredHeartbeat(prepared *chatGPTWebPreparedRequest, responseID string, createdAt int64) []byte {
	_ = prepared
	_ = responseID
	_ = createdAt
	return []byte(": chatgpt-web upstream pending\n\n")
}

func buildChatGPTWebCompletedEvent(model string, result chatGPTWebTextResult) []byte {
	responseID := "resp_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	messageID := "msg_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	output := make([]any, 0, 2)
	if result.Search {
		searchItem := map[string]any{
			"type":   "web_search_call",
			"id":     "ws_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
			"status": "completed",
			"action": chatGPTWebSearchAction(result.Query, result.Sources),
		}
		output = append(output, searchItem)
	}
	output = append(output, map[string]any{
		"type":   "message",
		"id":     messageID,
		"role":   "assistant",
		"status": "completed",
		"content": []any{map[string]any{
			"type":        "output_text",
			"text":        result.Text,
			"annotations": chatGPTWebSourceAnnotations(result.Text, result.Sources),
		}},
	})
	return marshalChatGPTWebEvent(map[string]any{
		"type": "response.completed",
		"response": map[string]any{
			"id":         responseID,
			"object":     "response",
			"created_at": time.Now().Unix(),
			"status":     "completed",
			"model":      model,
			"output":     output,
			"usage":      chatGPTWebUsageOrZero(result.Usage),
		},
	})
}

func buildChatGPTWebCreatedEvent(responseID, model string) []byte {
	return marshalChatGPTWebEvent(map[string]any{
		"type": "response.created",
		"response": map[string]any{
			"id":         responseID,
			"object":     "response",
			"created_at": time.Now().Unix(),
			"status":     "in_progress",
			"model":      model,
			"output":     []any{},
		},
	})
}

func buildChatGPTWebInProgressEvent(responseID, model string) []byte {
	return marshalChatGPTWebEvent(map[string]any{
		"type": "response.in_progress",
		"response": map[string]any{
			"id":         responseID,
			"object":     "response",
			"created_at": time.Now().Unix(),
			"status":     "in_progress",
			"model":      model,
			"output":     []any{},
		},
	})
}

func buildChatGPTWebMessageAddedEvents(responseID, messageID string, outputIndex int) [][]byte {
	return [][]byte{
		marshalChatGPTWebEvent(map[string]any{
			"type":         "response.output_item.added",
			"response_id":  responseID,
			"output_index": outputIndex,
			"item": map[string]any{
				"type": "message", "id": messageID, "role": "assistant", "status": "in_progress", "content": []any{},
			},
		}),
		marshalChatGPTWebEvent(map[string]any{
			"type":          "response.content_part.added",
			"response_id":   responseID,
			"item_id":       messageID,
			"output_index":  outputIndex,
			"content_index": 0,
			"part": map[string]any{
				"type": "output_text", "text": "", "annotations": []any{},
			},
		}),
	}
}

func buildChatGPTWebTextDeltaEvent(responseID, messageID string, outputIndex int, delta string) []byte {
	return marshalChatGPTWebEvent(map[string]any{
		"type":          "response.output_text.delta",
		"response_id":   responseID,
		"item_id":       messageID,
		"output_index":  outputIndex,
		"content_index": 0,
		"delta":         delta,
	})
}

func buildChatGPTWebMessageTerminalEvents(responseID, messageID string, outputIndex int, text string, annotations []any) [][]byte {
	message := map[string]any{
		"type":   "message",
		"id":     messageID,
		"role":   "assistant",
		"status": "completed",
		"content": []any{map[string]any{
			"type":        "output_text",
			"text":        text,
			"annotations": annotations,
		}},
	}
	return [][]byte{
		marshalChatGPTWebEvent(map[string]any{
			"type": "response.output_text.done", "response_id": responseID, "item_id": messageID,
			"output_index": outputIndex, "content_index": 0, "text": text,
		}),
		marshalChatGPTWebEvent(map[string]any{
			"type": "response.content_part.done", "response_id": responseID, "item_id": messageID,
			"output_index": outputIndex, "content_index": 0,
			"part": map[string]any{"type": "output_text", "text": text, "annotations": annotations},
		}),
		marshalChatGPTWebEvent(map[string]any{
			"type": "response.output_item.done", "response_id": responseID, "output_index": outputIndex, "item": message,
		}),
	}
}

func buildChatGPTWebTerminalEvents(responseID, messageID, model, text string, sources []chatGPTWebSearchSource, query string, search bool, usage map[string]any) [][]byte {
	annotations := chatGPTWebSourceAnnotations(text, sources)
	events := buildChatGPTWebMessageTerminalEvents(responseID, messageID, 0, text, annotations)
	message := map[string]any{
		"type":   "message",
		"id":     messageID,
		"role":   "assistant",
		"status": "completed",
		"content": []any{map[string]any{
			"type":        "output_text",
			"text":        text,
			"annotations": annotations,
		}},
	}
	output := []any{message}
	if search {
		output = append([]any{map[string]any{
			"type": "web_search_call", "id": "ws_" + strings.ReplaceAll(uuid.NewString(), "-", ""), "status": "completed",
			"action": chatGPTWebSearchAction(query, sources),
		}}, output...)
	}
	events = append(events, marshalChatGPTWebEvent(map[string]any{
		"type": "response.completed",
		"response": map[string]any{
			"id": responseID, "object": "response", "created_at": time.Now().Unix(), "status": "completed",
			"model": model, "output": output, "usage": chatGPTWebUsageOrZero(usage),
		},
	}))
	return events
}

func chatGPTWebUsageOrZero(usage map[string]any) map[string]any {
	if usage != nil {
		return usage
	}
	return map[string]any{
		"input_tokens":  0,
		"output_tokens": 0,
		"total_tokens":  0,
		"input_tokens_details": map[string]any{
			"cached_tokens": 0,
			"text_tokens":   0,
			"image_tokens":  0,
		},
		"output_tokens_details": map[string]any{
			"reasoning_tokens": 0,
			"text_tokens":      0,
			"image_tokens":     0,
		},
	}
}

func chatGPTWebSearchAction(query string, sources []chatGPTWebSearchSource) map[string]any {
	actionSources := make([]any, 0, len(sources))
	for _, source := range sources {
		if sourceURL := strings.TrimSpace(source.URL); sourceURL != "" {
			actionSources = append(actionSources, map[string]any{"type": "url", "url": sourceURL})
		}
	}
	action := map[string]any{
		"type":    "search",
		"sources": actionSources,
	}
	if query = strings.TrimSpace(query); query != "" {
		action["query"] = query
		action["queries"] = []string{query}
	}
	return action
}

func buildChatGPTWebGenericOutputAddedEvent(responseID string, outputIndex int, item gjson.Result) []byte {
	var added map[string]any
	if item.Get("type").String() == "image_generation_call" {
		added = map[string]any{
			"type": item.Get("type").String(),
			"id":   item.Get("id").String(),
		}
	} else if err := json.Unmarshal([]byte(item.Raw), &added); err != nil {
		added = map[string]any{"type": item.Get("type").String()}
	}
	added["status"] = "in_progress"
	return marshalChatGPTWebEvent(map[string]any{
		"type":         "response.output_item.added",
		"response_id":  responseID,
		"output_index": outputIndex,
		"item":         added,
	})
}

func emitChatGPTWebEventsFromCompleted(responseID, model string, response gjson.Result, emit func([]byte) bool) bool {
	if emit == nil {
		return false
	}
	sequencer := &chatGPTWebEventSequencer{}
	emitNext := func(event []byte) bool {
		return emit(sequencer.Next(event))
	}
	if !emitNext(buildChatGPTWebCreatedEvent(responseID, model)) ||
		!emitNext(buildChatGPTWebInProgressEvent(responseID, model)) {
		return false
	}
	for outputIndex, item := range response.Get("output").Array() {
		itemID := item.Get("id").String()
		if item.Get("type").String() == "message" {
			for _, event := range buildChatGPTWebMessageAddedEvents(responseID, itemID, outputIndex) {
				if !emitNext(event) {
					return false
				}
			}
			text := item.Get("content.0.text").String()
			if text != "" && !emitNext(buildChatGPTWebTextDeltaEvent(responseID, itemID, outputIndex, text)) {
				return false
			}
			annotations := make([]any, 0)
			for _, annotation := range item.Get("content.0.annotations").Array() {
				annotations = append(annotations, json.RawMessage(annotation.Raw))
			}
			for _, event := range buildChatGPTWebMessageTerminalEvents(responseID, itemID, outputIndex, text, annotations) {
				if !emitNext(event) {
					return false
				}
			}
			continue
		}
		if !emitNext(buildChatGPTWebGenericOutputAddedEvent(responseID, outputIndex, item)) ||
			!emitNext(marshalChatGPTWebEvent(map[string]any{
				"type": "response.output_item.done", "response_id": responseID, "output_index": outputIndex,
				"item": json.RawMessage(item.Raw),
			})) {
			return false
		}
	}
	return emitNext(marshalChatGPTWebEvent(map[string]any{
		"type": "response.completed", "response": json.RawMessage(response.Raw),
	}))
}

type chatGPTWebEventSequencer struct {
	next int64
}

func (sequencer *chatGPTWebEventSequencer) Next(event []byte) []byte {
	if sequencer == nil {
		return event
	}
	sequence := sequencer.next
	sequencer.next++
	withSequence, err := sjson.SetBytes(event, "sequence_number", sequence)
	if err != nil {
		return event
	}
	return withSequence
}

func chatGPTWebSourceAnnotations(text string, sources []chatGPTWebSearchSource) []any {
	annotations := make([]any, 0, len(sources))
	sourceSection := strings.LastIndex(text, "\n\nSources:")
	searchOffset := 0
	if sourceSection >= 0 {
		searchOffset = sourceSection
	}
	for _, source := range sources {
		sourceURL := strings.TrimSpace(source.URL)
		if sourceURL == "" || searchOffset >= len(text) {
			continue
		}
		relativeIndex := strings.Index(text[searchOffset:], sourceURL)
		if relativeIndex < 0 {
			continue
		}
		startByte := searchOffset + relativeIndex
		endByte := startByte + len(sourceURL)
		annotations = append(annotations, map[string]any{
			"type":        "url_citation",
			"url":         sourceURL,
			"title":       source.Title,
			"start_index": utf8.RuneCountInString(text[:startByte]),
			"end_index":   utf8.RuneCountInString(text[:endByte]),
		})
		searchOffset = endByte
	}
	return annotations
}

func marshalChatGPTWebEvent(value any) []byte {
	payload, _ := json.Marshal(value)
	return payload
}

func chatGPTWebAnyString(value any) string {
	if value == nil {
		return ""
	}
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "<nil>" {
		return ""
	}
	return text
}
