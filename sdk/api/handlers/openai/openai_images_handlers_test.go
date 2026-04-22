package openai

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
	"github.com/tidwall/gjson"
)

type imageCaptureExecutor struct {
	calls        int
	streamCalls  int
	model        string
	payload      []byte
	stream       bool
	sourceFormat string
	response     []byte
	streamChunks []coreexecutor.StreamChunk
}

func (e *imageCaptureExecutor) Identifier() string { return "codex" }

func (e *imageCaptureExecutor) Execute(ctx context.Context, auth *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
	e.calls++
	e.model = req.Model
	e.payload = append([]byte(nil), req.Payload...)
	e.stream = opts.Stream
	e.sourceFormat = opts.SourceFormat.String()
	if len(e.response) == 0 {
		e.response = []byte(`{"created_at":1700000000,"output":[{"type":"image_generation_call","result":"aGVsbG8=","revised_prompt":"rev"}],"usage":{"total_tokens":3}}`)
	}
	return coreexecutor.Response{Payload: e.response}, nil
}

func (e *imageCaptureExecutor) ExecuteStream(_ context.Context, _ *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	e.streamCalls++
	e.model = req.Model
	e.payload = append([]byte(nil), req.Payload...)
	e.stream = opts.Stream
	e.sourceFormat = opts.SourceFormat.String()
	ch := make(chan coreexecutor.StreamChunk, len(e.streamChunks))
	for _, chunk := range e.streamChunks {
		ch <- chunk
	}
	close(ch)
	return &coreexecutor.StreamResult{Chunks: ch}, nil
}

func (e *imageCaptureExecutor) Refresh(ctx context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	return auth, nil
}

func (e *imageCaptureExecutor) CountTokens(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, errors.New("not implemented")
}

func (e *imageCaptureExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("not implemented")
}

func newImagesTestHandler(t *testing.T, executor *imageCaptureExecutor) *OpenAIImagesAPIHandler {
	t.Helper()
	manager := coreauth.NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	auth := &coreauth.Auth{ID: "codex-auth", Provider: executor.Identifier(), Status: coreauth.StatusActive}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register auth: %v", err)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "gpt-5.4-mini"}})
	t.Cleanup(func() {
		registry.GetGlobalRegistry().UnregisterClient(auth.ID)
	})
	base := handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{
		Images: sdkconfig.ImagesConfig{CodexModel: "gpt-5.4-mini"},
	}, manager)
	return NewOpenAIImagesAPIHandler(base)
}

func TestOpenAIImagesGenerationsNonStreamingUsesCodexImageTool(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &imageCaptureExecutor{}
	h := newImagesTestHandler(t, executor)
	router := gin.New()
	router.POST("/v1/images/generations", h.Generations)

	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"gpt-image-2","prompt":"draw a cat","size":"1024x1024","quality":"high","output_format":"png","n":1}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", resp.Code, http.StatusOK, resp.Body.String())
	}
	if executor.calls != 1 {
		t.Fatalf("executor calls = %d, want 1", executor.calls)
	}
	if executor.model != "gpt-5.4-mini" {
		t.Fatalf("executor model = %q, want gpt-5.4-mini", executor.model)
	}
	if executor.sourceFormat != "openai-response" {
		t.Fatalf("source format = %q, want openai-response", executor.sourceFormat)
	}
	if got := gjson.GetBytes(executor.payload, "model").String(); got != "gpt-5.4-mini" {
		t.Fatalf("payload model = %q", got)
	}
	if store := gjson.GetBytes(executor.payload, "store"); !store.Exists() || store.Bool() {
		t.Fatalf("payload store = %v, exists=%v, want false", store.Bool(), store.Exists())
	}
	if instructions := gjson.GetBytes(executor.payload, "instructions"); !instructions.Exists() || instructions.String() != "" {
		t.Fatalf("payload instructions = %q, exists=%v, want empty", instructions.String(), instructions.Exists())
	}
	if stream := gjson.GetBytes(executor.payload, "stream"); !stream.Exists() || !stream.Bool() {
		t.Fatalf("payload stream = %v, exists=%v, want true", stream.Bool(), stream.Exists())
	}
	if got := gjson.GetBytes(executor.payload, "tools.0.type").String(); got != "image_generation" {
		t.Fatalf("tool type = %q", got)
	}
	if got := gjson.GetBytes(executor.payload, "tools.0.model").String(); got != "gpt-image-2" {
		t.Fatalf("tool model = %q", got)
	}
	if got := gjson.GetBytes(executor.payload, "tools.0.action").String(); got != "generate" {
		t.Fatalf("tool action = %q", got)
	}
	if got := gjson.Get(resp.Body.String(), "data.0.b64_json").String(); got != "aGVsbG8=" {
		t.Fatalf("b64_json = %q", got)
	}
	if got := gjson.Get(resp.Body.String(), "data.0.revised_prompt").String(); got != "rev" {
		t.Fatalf("revised_prompt = %q", got)
	}
	if got := gjson.Get(resp.Body.String(), "usage.total_tokens").Int(); got != 3 {
		t.Fatalf("usage.total_tokens = %d", got)
	}
}

func TestOpenAIImagesGenerationsUsesConfiguredImageModel(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &imageCaptureExecutor{}
	h := newImagesTestHandler(t, executor)
	h.Cfg.Images.ImageModel = "gpt-image-custom"
	router := gin.New()
	router.POST("/v1/images/generations", h.Generations)

	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"gpt-image-custom","prompt":"draw a cat"}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", resp.Code, http.StatusOK, resp.Body.String())
	}
	if got := gjson.GetBytes(executor.payload, "tools.0.model").String(); got != "gpt-image-custom" {
		t.Fatalf("tool model = %q", got)
	}
	models := h.Models()
	if got := models[0]["id"]; got != "gpt-image-custom" {
		t.Fatalf("model id = %v", got)
	}
}

func TestOpenAIImagesGenerationsAggregatesMultipleNonStreamingImages(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &imageCaptureExecutor{
		response: []byte(`{"created_at":1700000000,"output":[{"type":"image_generation_call","result":"aGVsbG8=","revised_prompt":"rev"}],"usage":{"input_tokens":1,"output_tokens":2,"output_tokens_details":{"image_tokens":2},"total_tokens":3}}`),
	}
	h := newImagesTestHandler(t, executor)
	enableNAggregation := true
	h.Cfg.Images.EnableNAggregation = &enableNAggregation
	router := gin.New()
	router.POST("/v1/images/generations", h.Generations)

	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"gpt-image-2","prompt":"draw","n":2}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", resp.Code, http.StatusOK, resp.Body.String())
	}
	if executor.calls != 2 {
		t.Fatalf("executor calls = %d, want 2", executor.calls)
	}
	if n := gjson.GetBytes(executor.payload, "tools.0.n"); n.Exists() {
		t.Fatalf("tool n exists = %s, want absent", n.Raw)
	}
	if count := len(gjson.Get(resp.Body.String(), "data").Array()); count != 2 {
		t.Fatalf("data count = %d, want 2: %s", count, resp.Body.String())
	}
	if got := gjson.Get(resp.Body.String(), "usage.total_tokens").Int(); got != 6 {
		t.Fatalf("usage.total_tokens = %d, want 6", got)
	}
	if got := gjson.Get(resp.Body.String(), "usage.output_tokens").Int(); got != 4 {
		t.Fatalf("usage.output_tokens = %d, want 4", got)
	}
	if got := gjson.Get(resp.Body.String(), "usage.output_tokens_details.image_tokens").Int(); got != 4 {
		t.Fatalf("usage.output_tokens_details.image_tokens = %d, want 4", got)
	}
}

func TestOpenAIImagesGenerationsRejectsMultipleImagesByDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &imageCaptureExecutor{}
	h := newImagesTestHandler(t, executor)
	h.Cfg.Images.UnsupportedStatusCode = http.StatusConflict
	router := gin.New()
	router.POST("/v1/images/generations", h.Generations)

	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"gpt-image-2","prompt":"draw","n":2}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d, body=%s", resp.Code, http.StatusConflict, resp.Body.String())
	}
	if executor.calls != 0 && executor.streamCalls != 0 {
		t.Fatalf("executor calls = %d streamCalls = %d, want none", executor.calls, executor.streamCalls)
	}
}

func TestOpenAIImagesUnsupportedOptionsUseConfiguredStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &imageCaptureExecutor{}
	h := newImagesTestHandler(t, executor)
	h.Cfg.Images.UnsupportedStatusCode = http.StatusUnprocessableEntity
	router := gin.New()
	router.POST("/v1/images/generations", h.Generations)

	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"gpt-image-2","prompt":"draw","response_format":"url"}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d, body=%s", resp.Code, http.StatusUnprocessableEntity, resp.Body.String())
	}
	if executor.calls != 0 && executor.streamCalls != 0 {
		t.Fatalf("executor calls = %d streamCalls = %d, want none", executor.calls, executor.streamCalls)
	}
}

func TestOpenAIImagesCanOverrideUnsupportedOptions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &imageCaptureExecutor{}
	h := newImagesTestHandler(t, executor)
	overrideResponseFormatURL := true
	overrideTransparentBackground := true
	h.Cfg.Images.OverrideResponseFormatURL = &overrideResponseFormatURL
	h.Cfg.Images.OverrideTransparentBackground = &overrideTransparentBackground
	router := gin.New()
	router.POST("/v1/images/generations", h.Generations)

	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"gpt-image-2","prompt":"draw","response_format":"url","background":"transparent"}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", resp.Code, http.StatusOK, resp.Body.String())
	}
	if executor.calls != 1 {
		t.Fatalf("executor calls = %d, want 1", executor.calls)
	}
	if got := gjson.GetBytes(executor.payload, "tools.0.background").String(); got != "auto" {
		t.Fatalf("tool background = %q, want auto", got)
	}
	if got := gjson.Get(resp.Body.String(), "data.0.b64_json").String(); got != "aGVsbG8=" {
		t.Fatalf("b64_json = %q", got)
	}
}

func TestOpenAIImagesOverrideOptionsAreSeparate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	overrideResponseFormatURL := true
	overrideTransparentBackground := false
	executor := &imageCaptureExecutor{}
	h := newImagesTestHandler(t, executor)
	h.Cfg.Images.OverrideResponseFormatURL = &overrideResponseFormatURL
	h.Cfg.Images.OverrideTransparentBackground = &overrideTransparentBackground
	router := gin.New()
	router.POST("/v1/images/generations", h.Generations)

	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"gpt-image-2","prompt":"draw","response_format":"url","background":"transparent"}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", resp.Code, http.StatusBadRequest, resp.Body.String())
	}
	if executor.calls != 0 && executor.streamCalls != 0 {
		t.Fatalf("executor calls = %d streamCalls = %d, want none", executor.calls, executor.streamCalls)
	}
}

func TestOpenAIImagesLegacyOverrideEnablesBothOptions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &imageCaptureExecutor{}
	h := newImagesTestHandler(t, executor)
	h.Cfg.Images.OverrideUnsupportedParams = true
	router := gin.New()
	router.POST("/v1/images/generations", h.Generations)

	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"gpt-image-2","prompt":"draw","response_format":"url","background":"transparent"}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", resp.Code, http.StatusOK, resp.Body.String())
	}
	if executor.calls != 1 {
		t.Fatalf("executor calls = %d, want 1", executor.calls)
	}
}

func TestOpenAIImagesOverrideKeepsUnknownResponseFormatUnsupported(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &imageCaptureExecutor{}
	h := newImagesTestHandler(t, executor)
	overrideResponseFormatURL := true
	h.Cfg.Images.OverrideResponseFormatURL = &overrideResponseFormatURL
	router := gin.New()
	router.POST("/v1/images/generations", h.Generations)

	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"gpt-image-2","prompt":"draw","response_format":"json"}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", resp.Code, http.StatusBadRequest, resp.Body.String())
	}
	if executor.calls != 0 && executor.streamCalls != 0 {
		t.Fatalf("executor calls = %d streamCalls = %d, want none", executor.calls, executor.streamCalls)
	}
}

func TestOpenAIImagesEditsMultipartBuildsDataURLsAndMask(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &imageCaptureExecutor{}
	h := newImagesTestHandler(t, executor)
	router := gin.New()
	router.POST("/v1/images/edits", h.Edits)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("model", "gpt-image-2"); err != nil {
		t.Fatalf("WriteField model: %v", err)
	}
	if err := writer.WriteField("prompt", "edit this"); err != nil {
		t.Fatalf("WriteField prompt: %v", err)
	}
	imagePart, err := writer.CreateFormFile("image[]", "image.png")
	if err != nil {
		t.Fatalf("CreateFormFile image: %v", err)
	}
	_, _ = imagePart.Write([]byte("\x89PNG\r\n\x1a\nimage-data"))
	maskPart, err := writer.CreateFormFile("mask", "mask.png")
	if err != nil {
		t.Fatalf("CreateFormFile mask: %v", err)
	}
	_, _ = maskPart.Write([]byte("\x89PNG\r\n\x1a\nmask-data"))
	if err := writer.Close(); err != nil {
		t.Fatalf("Close writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/images/edits", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", resp.Code, http.StatusOK, resp.Body.String())
	}
	if got := gjson.GetBytes(executor.payload, "tools.0.action").String(); got != "edit" {
		t.Fatalf("tool action = %q", got)
	}
	imageURL := gjson.GetBytes(executor.payload, "input.0.content.1.image_url").String()
	if !strings.HasPrefix(imageURL, "data:image/png;base64,") {
		t.Fatalf("image_url = %q", imageURL)
	}
	maskURL := gjson.GetBytes(executor.payload, "tools.0.input_image_mask.image_url").String()
	if !strings.HasPrefix(maskURL, "data:image/png;base64,") {
		t.Fatalf("mask image_url = %q", maskURL)
	}
}

func TestConvertResponsesToImagesResponse(t *testing.T) {
	raw := []byte(`{"created_at":1700000000,"output":[{"type":"message"},{"type":"image_generation_call","result":"ZmluYWw=","revised_prompt":"better"}],"usage":{"total_tokens":9}}`)
	out, err := convertResponsesToImagesResponse(raw, 1)
	if err != nil {
		t.Fatalf("convertResponsesToImagesResponse: %v", err)
	}
	if got := gjson.GetBytes(out, "created").Int(); got != 1700000000 {
		t.Fatalf("created = %d", got)
	}
	if got := gjson.GetBytes(out, "data.0.b64_json").String(); got != "ZmluYWw=" {
		t.Fatalf("b64_json = %q", got)
	}
	if got := gjson.GetBytes(out, "data.0.revised_prompt").String(); got != "better" {
		t.Fatalf("revised_prompt = %q", got)
	}
	if got := gjson.GetBytes(out, "usage.total_tokens").Int(); got != 9 {
		t.Fatalf("usage.total_tokens = %d", got)
	}
}

func TestOpenAIImagesStreamingMapsPartialAndCompletedEvents(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &imageCaptureExecutor{
		streamChunks: []coreexecutor.StreamChunk{
			{Payload: []byte(`data: {"type":"response.image_generation_call.partial_image","partial_image_b64":"cGFydA==","partial_image_index":0}`)},
			{Payload: []byte(`data: {"type":"response.completed","response":{"created_at":1700000000,"output":[{"type":"image_generation_call","result":"ZmluYWw=","revised_prompt":"rev"}],"usage":{"total_tokens":7}}}`)},
		},
	}
	h := newImagesTestHandler(t, executor)
	router := gin.New()
	router.POST("/v1/images/generations", h.Generations)

	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"gpt-image-2","prompt":"draw","stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", resp.Code, http.StatusOK, resp.Body.String())
	}
	body := resp.Body.String()
	if !strings.Contains(body, "event: image_generation.partial_image") || !strings.Contains(body, `"b64_json":"cGFydA=="`) {
		t.Fatalf("partial event missing: %s", body)
	}
	if !strings.Contains(body, "event: image_generation.completed") || !strings.Contains(body, `"b64_json":"ZmluYWw="`) {
		t.Fatalf("completed event missing: %s", body)
	}
	if !strings.Contains(body, `"total_tokens":7`) {
		t.Fatalf("usage missing: %s", body)
	}
}

func TestOpenAIImagesStreamingSupportsMultipleCompletedImages(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &imageCaptureExecutor{
		streamChunks: []coreexecutor.StreamChunk{
			{Payload: []byte(`data: {"type":"response.completed","response":{"created_at":1700000000,"output":[{"type":"image_generation_call","result":"Zmlyc3Q="}],"usage":{"total_tokens":11}}}`)},
		},
	}
	h := newImagesTestHandler(t, executor)
	enableNAggregation := true
	h.Cfg.Images.EnableNAggregation = &enableNAggregation
	router := gin.New()
	router.POST("/v1/images/generations", h.Generations)

	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"gpt-image-2","prompt":"draw","stream":true,"n":2}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", resp.Code, http.StatusOK, resp.Body.String())
	}
	if executor.streamCalls != 2 {
		t.Fatalf("stream calls = %d, want 2", executor.streamCalls)
	}
	if n := gjson.GetBytes(executor.payload, "tools.0.n"); n.Exists() {
		t.Fatalf("tool n exists = %s, want absent", n.Raw)
	}
	body := resp.Body.String()
	if count := strings.Count(body, "event: image_generation.completed"); count != 2 {
		t.Fatalf("completed event count = %d, want 2: %s", count, body)
	}
	if strings.Count(body, `"b64_json":"Zmlyc3Q="`) != 2 {
		t.Fatalf("completed image payloads missing: %s", body)
	}
}
