package openai

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	. "github.com/router-for-me/CLIProxyAPI/v6/internal/constant"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/api/handlers"
)

const (
	defaultImagesCodexModel = "gpt-5.4"
	defaultImagesImageModel = "gpt-image-2"
	maxImageUploadBytes     = 50 << 20
	maxImageMultipartBytes  = 220 << 20
)

type imageOperation struct {
	action         string
	partialEvent   string
	completedEvent string
}

var (
	imageGenerationOperation = imageOperation{
		action:         "generate",
		partialEvent:   "image_generation.partial_image",
		completedEvent: "image_generation.completed",
	}
	imageEditOperation = imageOperation{
		action:         "edit",
		partialEvent:   "image_edit.partial_image",
		completedEvent: "image_edit.completed",
	}
)

// OpenAIImagesAPIHandler adapts OpenAI Images requests to Codex Responses image tools.
type OpenAIImagesAPIHandler struct {
	*handlers.BaseAPIHandler
}

// NewOpenAIImagesAPIHandler creates a new OpenAI Images compatibility handler.
func NewOpenAIImagesAPIHandler(apiHandlers *handlers.BaseAPIHandler) *OpenAIImagesAPIHandler {
	return &OpenAIImagesAPIHandler{
		BaseAPIHandler: apiHandlers,
	}
}

// HandlerType returns the upstream schema used for the Codex-backed request.
func (h *OpenAIImagesAPIHandler) HandlerType() string {
	return OpenaiResponse
}

// Models returns the image model exposed by this compatibility layer.
func (h *OpenAIImagesAPIHandler) Models() []map[string]any {
	return []map[string]any{{
		"id":       h.imagesImageModel(),
		"object":   "model",
		"created":  0,
		"owned_by": "openai",
	}}
}

type openAIImageRequest struct {
	Model             string           `json:"model"`
	Prompt            string           `json:"prompt"`
	N                 *int             `json:"n"`
	Size              string           `json:"size"`
	Quality           string           `json:"quality"`
	Background        string           `json:"background"`
	OutputFormat      string           `json:"output_format"`
	OutputCompression *int             `json:"output_compression"`
	InputFidelity     string           `json:"input_fidelity"`
	Moderation        string           `json:"moderation"`
	Stream            bool             `json:"stream"`
	PartialImages     *int             `json:"partial_images"`
	ResponseFormat    string           `json:"response_format"`
	Images            []imageReference `json:"images,omitempty"`
	Mask              *imageReference  `json:"mask,omitempty"`
}

type imageReference struct {
	ImageURL any    `json:"image_url,omitempty"`
	FileID   string `json:"file_id,omitempty"`
}

type imageOutputItem struct {
	Type          string          `json:"type"`
	Result        string          `json:"result"`
	RevisedPrompt string          `json:"revised_prompt,omitempty"`
	OutputFormat  string          `json:"output_format,omitempty"`
	Size          string          `json:"size,omitempty"`
	Background    string          `json:"background,omitempty"`
	Quality       string          `json:"quality,omitempty"`
	Usage         json.RawMessage `json:"usage,omitempty"`
	InputTokens   json.RawMessage `json:"input_tokens,omitempty"`
	OutputTokens  json.RawMessage `json:"output_tokens,omitempty"`
	TotalTokens   json.RawMessage `json:"total_tokens,omitempty"`

	InputTokensDetails  json.RawMessage `json:"input_tokens_details,omitempty"`
	OutputTokensDetails json.RawMessage `json:"output_tokens_details,omitempty"`
}

type imageResult struct {
	B64JSON       string `json:"b64_json,omitempty"`
	URL           string `json:"url,omitempty"`
	RevisedPrompt string `json:"revised_prompt,omitempty"`
	OutputFormat  string `json:"-"`
	Size          string `json:"-"`
	Background    string `json:"-"`
	Quality       string `json:"-"`
}

type imagesResponse struct {
	Created      int64           `json:"created"`
	Data         []imageResult   `json:"data"`
	Usage        json.RawMessage `json:"usage,omitempty"`
	Background   string          `json:"background,omitempty"`
	OutputFormat string          `json:"output_format,omitempty"`
	Quality      string          `json:"quality,omitempty"`
	Size         string          `json:"size,omitempty"`
}

type responsesImageObject struct {
	CreatedAt int64                      `json:"created_at"`
	Output    []imageOutputItem          `json:"output"`
	Usage     json.RawMessage            `json:"usage,omitempty"`
	ToolUsage map[string]json.RawMessage `json:"tool_usage,omitempty"`
}

type responseCompletedEvent struct {
	Type     string               `json:"type"`
	Response responsesImageObject `json:"response"`
}

type responseOutputItemDoneEvent struct {
	Type string          `json:"type"`
	Item imageOutputItem `json:"item"`
}

type responsePartialImageEvent struct {
	Type              string `json:"type"`
	PartialImageB64   string `json:"partial_image_b64"`
	PartialImageIndex *int   `json:"partial_image_index,omitempty"`
	OutputFormat      string `json:"output_format,omitempty"`
}

type imageStreamEvent struct {
	Type              string          `json:"type"`
	B64JSON           string          `json:"b64_json,omitempty"`
	URL               string          `json:"url,omitempty"`
	RevisedPrompt     string          `json:"revised_prompt,omitempty"`
	PartialImageIndex *int            `json:"partial_image_index,omitempty"`
	Usage             json.RawMessage `json:"usage,omitempty"`
}

type imageUnsupportedError struct {
	err error
}

func (e imageUnsupportedError) Error() string {
	return e.err.Error()
}

func (e imageUnsupportedError) Unwrap() error {
	return e.err
}

// Generations handles POST /v1/images/generations.
func (h *OpenAIImagesAPIHandler) Generations(c *gin.Context) {
	req, err := parseImageGenerationRequest(c)
	if err != nil {
		h.writeImagesRequestError(c, err)
		return
	}
	if err := h.validateImageRequest(&req, imageGenerationOperation); err != nil {
		h.writeImagesRequestError(c, err)
		return
	}
	h.handleImagesRequest(c, req, imageGenerationOperation)
}

// Edits handles POST /v1/images/edits.
func (h *OpenAIImagesAPIHandler) Edits(c *gin.Context) {
	req, err := parseImageEditRequest(c)
	if err != nil {
		h.writeImagesRequestError(c, err)
		return
	}
	if err := h.validateImageRequest(&req, imageEditOperation); err != nil {
		h.writeImagesRequestError(c, err)
		return
	}
	h.handleImagesRequest(c, req, imageEditOperation)
}

func (h *OpenAIImagesAPIHandler) handleImagesRequest(c *gin.Context, req openAIImageRequest, op imageOperation) {
	codexModel := h.imagesCodexModel()
	payload, err := buildCodexImageResponsesPayload(req, op, codexModel, h.imagesImageModel(), h.imagesOverrideInputFidelityEnabled())
	if err != nil {
		h.writeImagesError(c, http.StatusBadRequest, err)
		return
	}
	rawJSON, err := json.Marshal(payload)
	if err != nil {
		h.writeImagesError(c, http.StatusInternalServerError, err)
		return
	}
	count := imageRequestCount(req)
	if count > 1 && !h.imagesNAggregationEnabled() {
		h.writeImagesRequestError(c, unsupportedImageErrorf("n > 1 is not supported"))
		return
	}
	responseFormat := strings.ToLower(strings.TrimSpace(req.ResponseFormat))
	if req.Stream {
		h.handleStreamingImagesResponse(c, rawJSON, codexModel, op, count, responseFormat)
		return
	}
	h.handleNonStreamingImagesResponse(c, rawJSON, codexModel, count, responseFormat)
}

func (h *OpenAIImagesAPIHandler) handleNonStreamingImagesResponse(c *gin.Context, rawJSON []byte, codexModel string, count int, responseFormat string) {
	c.Header("Content-Type", "application/json")
	var combined imagesResponse
	var upstreamHeaders http.Header
	if count < 1 {
		count = 1
	}
	for i := 0; i < count; i++ {
		cliCtx, cliCancel := h.GetContextWithCancel(h, c, context.Background())
		stopKeepAlive := h.StartNonStreamingKeepAlive(c, cliCtx)
		resp, headers, errMsg := h.ExecuteWithProviders(cliCtx, []string{Codex}, h.HandlerType(), codexModel, rawJSON, "")
		stopKeepAlive()
		if errMsg != nil {
			h.WriteErrorResponse(c, errMsg)
			cliCancel(errMsg.Error)
			return
		}
		parsed, err := parseResponsesToImagesResponse(resp, time.Now().Unix())
		if err != nil {
			h.writeImagesError(c, http.StatusBadGateway, err)
			cliCancel(err)
			return
		}
		if combined.Created == 0 {
			combined.Created = parsed.Created
			combined.Background = parsed.Background
			combined.OutputFormat = parsed.OutputFormat
			combined.Quality = parsed.Quality
			combined.Size = parsed.Size
			upstreamHeaders = headers
		}
		combined.Data = append(combined.Data, parsed.Data...)
		combined.Usage = mergeImageUsageForNAggregation(combined.Usage, parsed.Usage)
		cliCancel(resp)
	}
	applyImageResponseFormat(&combined, responseFormat)
	imagesPayload, err := json.Marshal(combined)
	if err != nil {
		h.writeImagesError(c, http.StatusInternalServerError, err)
		return
	}
	handlers.WriteUpstreamHeaders(c.Writer.Header(), upstreamHeaders)
	_, _ = c.Writer.Write(imagesPayload)
}

func (h *OpenAIImagesAPIHandler) handleStreamingImagesResponse(c *gin.Context, rawJSON []byte, codexModel string, op imageOperation, count int, responseFormat string) {
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		h.writeImagesError(c, http.StatusInternalServerError, errors.New("streaming not supported"))
		return
	}
	if count > 1 {
		h.handleMultiStreamingImagesResponse(c, flusher, rawJSON, codexModel, op, count, responseFormat)
		return
	}
	cliCtx, cliCancel := h.GetContextWithCancel(h, c, context.Background())
	dataChan, upstreamHeaders, errChan := h.ExecuteStreamWithProviders(cliCtx, []string{Codex}, h.HandlerType(), codexModel, rawJSON, "")

	setSSEHeaders := func() {
		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")
		c.Header("Access-Control-Allow-Origin", "*")
	}

	mapper := &imageStreamMapper{operation: op, responseFormat: responseFormat}
	for {
		select {
		case <-c.Request.Context().Done():
			cliCancel(c.Request.Context().Err())
			return
		case errMsg, ok := <-errChan:
			if !ok {
				errChan = nil
				continue
			}
			h.WriteErrorResponse(c, errMsg)
			if errMsg != nil {
				cliCancel(errMsg.Error)
			} else {
				cliCancel(nil)
			}
			return
		case chunk, ok := <-dataChan:
			if !ok {
				select {
				case errMsg, okErr := <-errChan:
					if okErr && errMsg != nil {
						h.WriteErrorResponse(c, errMsg)
						cliCancel(errMsg.Error)
						return
					}
				default:
				}
				setSSEHeaders()
				handlers.WriteUpstreamHeaders(c.Writer.Header(), upstreamHeaders)
				mapper.flush(c.Writer)
				_, _ = c.Writer.Write([]byte("\n"))
				flusher.Flush()
				cliCancel(nil)
				return
			}
			setSSEHeaders()
			handlers.WriteUpstreamHeaders(c.Writer.Header(), upstreamHeaders)
			mapper.writeChunk(c.Writer, chunk)
			flusher.Flush()
			h.forwardImagesStream(c, flusher, func(err error) { cliCancel(err) }, dataChan, errChan, mapper)
			return
		}
	}
}

func (h *OpenAIImagesAPIHandler) handleMultiStreamingImagesResponse(c *gin.Context, flusher http.Flusher, rawJSON []byte, codexModel string, op imageOperation, count int, responseFormat string) {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Access-Control-Allow-Origin", "*")
	for i := 0; i < count; i++ {
		cliCtx, cliCancel := h.GetContextWithCancel(h, c, context.Background())
		dataChan, upstreamHeaders, errChan := h.ExecuteStreamWithProviders(cliCtx, []string{Codex}, h.HandlerType(), codexModel, rawJSON, "")
		if i == 0 {
			handlers.WriteUpstreamHeaders(c.Writer.Header(), upstreamHeaders)
		}
		mapper := &imageStreamMapper{operation: op, omitInputUsage: i > 0, responseFormat: responseFormat}
		var streamErr error
		h.ForwardStream(c, flusher, func(err error) {
			streamErr = err
			cliCancel(err)
		}, dataChan, errChan, handlers.StreamForwardOptions{
			WriteChunk: func(chunk []byte) {
				mapper.writeChunk(c.Writer, chunk)
			},
			WriteTerminalError: func(errMsg *interfaces.ErrorMessage) {
				if errMsg == nil {
					return
				}
				status := http.StatusInternalServerError
				if errMsg.StatusCode > 0 {
					status = errMsg.StatusCode
				}
				errText := http.StatusText(status)
				if errMsg.Error != nil && strings.TrimSpace(errMsg.Error.Error()) != "" {
					errText = errMsg.Error.Error()
				}
				body := handlers.BuildErrorResponseBody(status, errText)
				_, _ = fmt.Fprintf(c.Writer, "\nevent: error\ndata: %s\n\n", string(body))
			},
			WriteDone: func() {
				mapper.flush(c.Writer)
			},
		})
		if streamErr != nil {
			return
		}
	}
	_, _ = c.Writer.Write([]byte("\n"))
	flusher.Flush()
}

func (h *OpenAIImagesAPIHandler) forwardImagesStream(c *gin.Context, flusher http.Flusher, cancel func(error), data <-chan []byte, errs <-chan *interfaces.ErrorMessage, mapper *imageStreamMapper) {
	if mapper == nil {
		mapper = &imageStreamMapper{operation: imageGenerationOperation}
	}
	h.ForwardStream(c, flusher, cancel, data, errs, handlers.StreamForwardOptions{
		WriteChunk: func(chunk []byte) {
			mapper.writeChunk(c.Writer, chunk)
		},
		WriteTerminalError: func(errMsg *interfaces.ErrorMessage) {
			if errMsg == nil {
				return
			}
			status := http.StatusInternalServerError
			if errMsg.StatusCode > 0 {
				status = errMsg.StatusCode
			}
			errText := http.StatusText(status)
			if errMsg.Error != nil && strings.TrimSpace(errMsg.Error.Error()) != "" {
				errText = errMsg.Error.Error()
			}
			body := handlers.BuildErrorResponseBody(status, errText)
			_, _ = fmt.Fprintf(c.Writer, "\nevent: error\ndata: %s\n\n", string(body))
		},
		WriteDone: func() {
			mapper.flush(c.Writer)
			_, _ = c.Writer.Write([]byte("\n"))
		},
	})
}

func parseImageGenerationRequest(c *gin.Context) (openAIImageRequest, error) {
	var req openAIImageRequest
	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil {
		return req, fmt.Errorf("invalid request: %w", err)
	}
	return req, nil
}

func parseImageEditRequest(c *gin.Context) (openAIImageRequest, error) {
	contentType := c.GetHeader("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err == nil && strings.EqualFold(mediaType, "multipart/form-data") {
		return parseMultipartImageEditRequest(c)
	}
	var req openAIImageRequest
	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil {
		return req, fmt.Errorf("invalid request: %w", err)
	}
	for i := range req.Images {
		if strings.TrimSpace(req.Images[i].FileID) != "" {
			return req, unsupportedImageErrorf("JSON image file_id is not supported")
		}
		imageURL, err := imageURLFromReference(req.Images[i])
		if err != nil {
			return req, fmt.Errorf("invalid images[%d]: %w", i, err)
		}
		req.Images[i].ImageURL = imageURL
	}
	if req.Mask != nil {
		if strings.TrimSpace(req.Mask.FileID) != "" {
			return req, unsupportedImageErrorf("JSON mask file_id is not supported")
		}
		maskURL, err := imageURLFromReference(*req.Mask)
		if err != nil {
			return req, fmt.Errorf("invalid mask: %w", err)
		}
		req.Mask.ImageURL = maskURL
	}
	return req, nil
}

func parseMultipartImageEditRequest(c *gin.Context) (openAIImageRequest, error) {
	var req openAIImageRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxImageMultipartBytes)
	if err := c.Request.ParseMultipartForm(maxImageUploadBytes); err != nil {
		return req, fmt.Errorf("invalid multipart request: %w", err)
	}
	form := c.Request.MultipartForm
	req.Model = multipartValue(form, "model")
	req.Prompt = multipartValue(form, "prompt")
	req.Size = multipartValue(form, "size")
	req.Quality = multipartValue(form, "quality")
	req.Background = multipartValue(form, "background")
	req.OutputFormat = multipartValue(form, "output_format")
	req.InputFidelity = multipartValue(form, "input_fidelity")
	req.Moderation = multipartValue(form, "moderation")
	req.ResponseFormat = multipartValue(form, "response_format")
	req.Stream = parseBoolValue(multipartValue(form, "stream"))
	if n, ok, err := parseOptionalInt(multipartValue(form, "n")); err != nil {
		return req, err
	} else if ok {
		req.N = &n
	}
	if compression, ok, err := parseOptionalInt(multipartValue(form, "output_compression")); err != nil {
		return req, err
	} else if ok {
		req.OutputCompression = &compression
	}
	if partialImages, ok, err := parseOptionalInt(multipartValue(form, "partial_images")); err != nil {
		return req, err
	} else if ok {
		req.PartialImages = &partialImages
	}

	files := append([]*multipart.FileHeader(nil), multipartFiles(form, "image")...)
	files = append(files, multipartFiles(form, "image[]")...)
	for _, fh := range files {
		dataURL, err := dataURLFromFileHeader(fh)
		if err != nil {
			return req, err
		}
		req.Images = append(req.Images, imageReference{ImageURL: dataURL})
	}
	if masks := multipartFiles(form, "mask"); len(masks) > 0 {
		if len(masks) > 1 {
			return req, errors.New("only one mask file is supported")
		}
		maskURL, err := dataURLFromFileHeader(masks[0])
		if err != nil {
			return req, err
		}
		req.Mask = &imageReference{ImageURL: maskURL}
	}
	return req, nil
}

func (h *OpenAIImagesAPIHandler) validateImageRequest(req *openAIImageRequest, op imageOperation) error {
	if req == nil {
		return errors.New("request is required")
	}
	imageModel := h.imagesImageModel()
	imageModel = strings.TrimSpace(imageModel)
	if imageModel == "" {
		imageModel = defaultImagesImageModel
	}
	model := strings.TrimSpace(req.Model)
	if model == "" {
		model = imageModel
	}
	if model != imageModel {
		return unsupportedImageErrorf("unsupported image model %q; configured image model is %s", req.Model, imageModel)
	}
	if strings.TrimSpace(req.Prompt) == "" {
		return errors.New("prompt is required")
	}
	if strings.EqualFold(strings.TrimSpace(req.ResponseFormat), "url") {
		if h.imagesResponseFormatURLDataURLEnabled() {
			req.ResponseFormat = "url"
		} else if h.imagesOverrideResponseFormatURLEnabled() {
			req.ResponseFormat = "b64_json"
		} else {
			return unsupportedImageErrorf("response_format=url is not supported; use b64_json")
		}
	}
	if rf := strings.TrimSpace(req.ResponseFormat); rf != "" && rf != "b64_json" && rf != "url" {
		return unsupportedImageErrorf("unsupported response_format %q", rf)
	}
	if strings.EqualFold(strings.TrimSpace(req.Background), "transparent") && h.imagesOverrideTransparentBackgroundEnabled() {
		req.Background = "auto"
	}
	n := 1
	if req.N != nil {
		n = *req.N
	}
	if n < 1 {
		return errors.New("n must be at least 1")
	}
	if req.OutputCompression != nil && (*req.OutputCompression < 0 || *req.OutputCompression > 100) {
		return errors.New("output_compression must be between 0 and 100")
	}
	if req.PartialImages != nil && (*req.PartialImages < 0 || *req.PartialImages > 3) {
		return errors.New("partial_images must be between 0 and 3")
	}
	if op.action == imageEditOperation.action && len(req.Images) == 0 {
		return errors.New("at least one image is required")
	}
	return nil
}

func buildCodexImageResponsesPayload(req openAIImageRequest, op imageOperation, codexModel, imageModel string, overrideInputFidelity bool) (map[string]any, error) {
	imageModel = strings.TrimSpace(imageModel)
	if imageModel == "" {
		imageModel = defaultImagesImageModel
	}
	content := []map[string]any{{
		"type": "input_text",
		"text": req.Prompt,
	}}
	for i := range req.Images {
		imageURL, err := imageURLFromReference(req.Images[i])
		if err != nil {
			return nil, fmt.Errorf("invalid image reference: %w", err)
		}
		content = append(content, map[string]any{
			"type":      "input_image",
			"image_url": imageURL,
		})
	}

	tool := map[string]any{
		"type":   "image_generation",
		"model":  imageModel,
		"action": op.action,
	}
	setOptionalString(tool, "size", req.Size)
	setOptionalString(tool, "quality", req.Quality)
	setOptionalString(tool, "background", req.Background)
	setOptionalString(tool, "output_format", req.OutputFormat)
	if shouldForwardInputFidelity(overrideInputFidelity) {
		setOptionalString(tool, "input_fidelity", req.InputFidelity)
	}
	setOptionalString(tool, "moderation", req.Moderation)
	if req.OutputCompression != nil {
		tool["output_compression"] = *req.OutputCompression
	}
	if req.Stream && req.PartialImages != nil {
		tool["partial_images"] = *req.PartialImages
	}
	if req.Mask != nil {
		maskURL, err := imageURLFromReference(*req.Mask)
		if err != nil {
			return nil, fmt.Errorf("invalid mask reference: %w", err)
		}
		tool["input_image_mask"] = map[string]any{"image_url": maskURL}
	}

	return map[string]any{
		"model":        codexModel,
		"instructions": "",
		"store":        false,
		"stream":       true,
		"input": []map[string]any{{
			"type":    "message",
			"role":    "user",
			"content": content,
		}},
		"tools":       []map[string]any{tool},
		"tool_choice": map[string]any{"type": "image_generation"},
	}, nil
}

func shouldForwardInputFidelity(overrideInputFidelity bool) bool {
	return !overrideInputFidelity
}

func imageRequestCount(req openAIImageRequest) int {
	if req.N == nil || *req.N < 1 {
		return 1
	}
	return *req.N
}

func mimeTypeFromOutputFormat(outputFormat string) string {
	outputFormat = strings.ToLower(strings.TrimSpace(outputFormat))
	if outputFormat == "" {
		return "image/png"
	}
	if strings.Contains(outputFormat, "/") {
		return outputFormat
	}
	switch outputFormat {
	case "png":
		return "image/png"
	case "jpg", "jpeg":
		return "image/jpeg"
	case "webp":
		return "image/webp"
	default:
		return "image/png"
	}
}

func imageDataURL(b64JSON, outputFormat string) string {
	return "data:" + mimeTypeFromOutputFormat(outputFormat) + ";base64," + b64JSON
}

func imageResponseFormatIsURL(responseFormat string) bool {
	return strings.EqualFold(strings.TrimSpace(responseFormat), "url")
}

func applyImageResponseFormat(out *imagesResponse, responseFormat string) {
	if out == nil || !imageResponseFormatIsURL(responseFormat) {
		return
	}
	for i := range out.Data {
		if strings.TrimSpace(out.Data[i].B64JSON) == "" {
			continue
		}
		out.Data[i].URL = imageDataURL(out.Data[i].B64JSON, out.Data[i].OutputFormat)
		out.Data[i].B64JSON = ""
	}
}

func convertResponsesToImagesResponse(raw []byte, fallbackCreated int64) ([]byte, error) {
	out, err := parseResponsesToImagesResponse(raw, fallbackCreated)
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

func parseResponsesToImagesResponse(raw []byte, fallbackCreated int64) (imagesResponse, error) {
	respObj, err := parseResponsesImageObject(raw)
	if err != nil {
		return imagesResponse{}, err
	}
	created := respObj.CreatedAt
	if created == 0 {
		created = fallbackCreated
	}
	out := imagesResponse{
		Created: created,
		Data:    imageResultsFromOutput(respObj.Output),
	}
	if len(out.Data) == 0 {
		return imagesResponse{}, errors.New("upstream did not return image output")
	}
	out.applyMetadataFromFirstImage()
	if usage := imageUsageFromToolUsage(respObj.ToolUsage); len(bytes.TrimSpace(usage)) > 0 && string(bytes.TrimSpace(usage)) != "null" {
		out.Usage = usage
	} else if usage := imageUsageFromOutput(respObj.Output); len(bytes.TrimSpace(usage)) > 0 && string(bytes.TrimSpace(usage)) != "null" {
		out.Usage = usage
	} else if usage := respObj.Usage; len(bytes.TrimSpace(usage)) > 0 && string(bytes.TrimSpace(usage)) != "null" {
		out.Usage = usage
	}
	return out, nil
}

func parseResponsesImageObject(raw []byte) (responsesImageObject, error) {
	var obj responsesImageObject
	if err := json.Unmarshal(raw, &obj); err != nil {
		return obj, fmt.Errorf("invalid Codex response: %w", err)
	}
	if len(obj.Output) > 0 || obj.CreatedAt != 0 || len(obj.Usage) > 0 || len(obj.ToolUsage) > 0 {
		return obj, nil
	}
	var completed responseCompletedEvent
	if err := json.Unmarshal(raw, &completed); err == nil && completed.Response.Output != nil {
		return completed.Response, nil
	}
	return obj, nil
}

func imageResultsFromOutput(items []imageOutputItem) []imageResult {
	results := make([]imageResult, 0, len(items))
	for i := range items {
		if items[i].Type != "image_generation_call" || strings.TrimSpace(items[i].Result) == "" {
			continue
		}
		results = append(results, imageResult{
			B64JSON:       items[i].Result,
			RevisedPrompt: items[i].RevisedPrompt,
			OutputFormat:  items[i].OutputFormat,
			Size:          items[i].Size,
			Background:    items[i].Background,
			Quality:       items[i].Quality,
		})
	}
	return results
}

func (r *imagesResponse) applyMetadataFromFirstImage() {
	if r == nil || len(r.Data) == 0 {
		return
	}
	first := r.Data[0]
	r.Background = first.Background
	r.OutputFormat = first.OutputFormat
	r.Quality = first.Quality
	r.Size = first.Size
}

func imageUsageFromToolUsage(toolUsage map[string]json.RawMessage) json.RawMessage {
	for _, key := range []string{"image_gen", "image_generation"} {
		if usage := toolUsage[key]; len(bytes.TrimSpace(usage)) > 0 && string(bytes.TrimSpace(usage)) != "null" {
			return usage
		}
	}
	return nil
}

func imageUsageFromOutput(items []imageOutputItem) json.RawMessage {
	var combined json.RawMessage
	for i := range items {
		if items[i].Type != "image_generation_call" {
			continue
		}
		combined = mergeImageUsage(combined, imageUsageRawFromOutputItem(items[i]))
	}
	return combined
}

func imageUsageRawFromOutputItem(item imageOutputItem) json.RawMessage {
	if len(bytes.TrimSpace(item.Usage)) > 0 && string(bytes.TrimSpace(item.Usage)) != "null" {
		return item.Usage
	}
	fields := map[string]json.RawMessage{}
	setRawUsageField(fields, "input_tokens", item.InputTokens)
	setRawUsageField(fields, "output_tokens", item.OutputTokens)
	setRawUsageField(fields, "total_tokens", item.TotalTokens)
	setRawUsageField(fields, "input_tokens_details", item.InputTokensDetails)
	setRawUsageField(fields, "output_tokens_details", item.OutputTokensDetails)
	if len(fields) == 0 {
		return nil
	}
	data, err := json.Marshal(fields)
	if err != nil {
		return nil
	}
	return data
}

func setRawUsageField(dst map[string]json.RawMessage, key string, value json.RawMessage) {
	if len(bytes.TrimSpace(value)) == 0 || string(bytes.TrimSpace(value)) == "null" {
		return
	}
	dst[key] = value
}

func mergeImageUsage(current, next json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(next)) == 0 || string(bytes.TrimSpace(next)) == "null" {
		return current
	}
	if len(bytes.TrimSpace(current)) == 0 || string(bytes.TrimSpace(current)) == "null" {
		return next
	}
	var currentMap map[string]any
	var nextMap map[string]any
	if err := json.Unmarshal(current, &currentMap); err != nil {
		return next
	}
	if err := json.Unmarshal(next, &nextMap); err != nil {
		return current
	}
	merged := mergeImageUsageMaps(currentMap, nextMap)
	data, err := json.Marshal(merged)
	if err != nil {
		return current
	}
	return data
}

func mergeImageUsageForNAggregation(current, next json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(next)) == 0 || string(bytes.TrimSpace(next)) == "null" {
		return current
	}
	if len(bytes.TrimSpace(current)) == 0 || string(bytes.TrimSpace(current)) == "null" {
		return next
	}
	var currentMap map[string]any
	var nextMap map[string]any
	if err := json.Unmarshal(current, &currentMap); err != nil {
		return next
	}
	if err := json.Unmarshal(next, &nextMap); err != nil {
		return current
	}
	merged := mergeImageUsageMapsForNAggregation(currentMap, nextMap)
	recomputeImageUsageTotal(merged)
	data, err := json.Marshal(merged)
	if err != nil {
		return current
	}
	return data
}

func mergeImageUsageMapsForNAggregation(current, next map[string]any) map[string]any {
	out := make(map[string]any, len(current)+len(next))
	for key, value := range current {
		out[key] = value
	}
	for key, value := range next {
		switch key {
		case "output_tokens", "output_tokens_details":
			if existing, ok := out[key]; ok {
				out[key] = mergeImageUsageValue(existing, value)
			} else {
				out[key] = value
			}
		case "input_tokens", "input_tokens_details":
			if _, ok := out[key]; !ok {
				out[key] = value
			}
		case "total_tokens":
			if _, ok := out[key]; !ok {
				out[key] = value
			}
		default:
			if existing, ok := out[key]; ok {
				out[key] = mergeImageUsageValue(existing, value)
			} else {
				out[key] = value
			}
		}
	}
	return out
}

func recomputeImageUsageTotal(usage map[string]any) {
	input, inputOK := usageNumber(usage["input_tokens"])
	output, outputOK := usageNumber(usage["output_tokens"])
	if !inputOK || !outputOK {
		return
	}
	usage["total_tokens"] = input + output
}

func omitInputImageUsage(raw json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return raw
	}
	var usage map[string]any
	if err := json.Unmarshal(raw, &usage); err != nil {
		return raw
	}
	delete(usage, "input_tokens")
	delete(usage, "input_tokens_details")
	if output, ok := usageNumber(usage["output_tokens"]); ok {
		usage["total_tokens"] = output
	}
	data, err := json.Marshal(usage)
	if err != nil {
		return raw
	}
	return data
}

func usageNumber(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func mergeImageUsageMaps(current, next map[string]any) map[string]any {
	out := make(map[string]any, len(current)+len(next))
	for key, value := range current {
		out[key] = value
	}
	for key, value := range next {
		if existing, ok := out[key]; ok {
			out[key] = mergeImageUsageValue(existing, value)
			continue
		}
		out[key] = value
	}
	return out
}

func mergeImageUsageValue(current, next any) any {
	currentMap, currentMapOK := current.(map[string]any)
	nextMap, nextMapOK := next.(map[string]any)
	if currentMapOK && nextMapOK {
		return mergeImageUsageMaps(currentMap, nextMap)
	}
	currentNumber, currentOK := current.(float64)
	nextNumber, nextOK := next.(float64)
	if currentOK && nextOK {
		return currentNumber + nextNumber
	}
	return next
}

type imageStreamMapper struct {
	operation      imageOperation
	parser         imageSSEParser
	finals         []imageResult
	finalUsage     json.RawMessage
	omitInputUsage bool
	responseFormat string
	completed      bool
}

func (m *imageStreamMapper) writeChunk(w io.Writer, chunk []byte) {
	for _, payload := range m.parser.Push(chunk) {
		m.writePayload(w, payload)
	}
}

func (m *imageStreamMapper) flush(w io.Writer) {
	for _, payload := range m.parser.Flush() {
		m.writePayload(w, payload)
	}
	if !m.completed && len(m.finals) > 0 {
		m.writeCompletedSet(w, m.finals, m.finalUsage)
	}
}

func (m *imageStreamMapper) writePayload(w io.Writer, payload []byte) {
	eventType := responseEventType(payload)
	switch eventType {
	case "response.image_generation_call.partial_image":
		var event responsePartialImageEvent
		if err := json.Unmarshal(payload, &event); err != nil || strings.TrimSpace(event.PartialImageB64) == "" {
			return
		}
		streamEvent := imageStreamEvent{
			Type:              m.operation.partialEvent,
			B64JSON:           event.PartialImageB64,
			PartialImageIndex: event.PartialImageIndex,
		}
		m.applyStreamImageFormat(&streamEvent, event.OutputFormat)
		m.writeSSE(w, m.operation.partialEvent, streamEvent)
	case "response.output_item.done":
		var event responseOutputItemDoneEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return
		}
		results := imageResultsFromOutput([]imageOutputItem{event.Item})
		if len(results) == 0 {
			return
		}
		m.finals = append(m.finals, results...)
		m.finalUsage = mergeImageUsage(m.finalUsage, imageUsageRawFromOutputItem(event.Item))
	case "response.completed":
		var event responseCompletedEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return
		}
		results := imageResultsFromOutput(event.Response.Output)
		usage := imageUsageFromToolUsage(event.Response.ToolUsage)
		if len(bytes.TrimSpace(usage)) == 0 || string(bytes.TrimSpace(usage)) == "null" {
			usage = imageUsageFromOutput(event.Response.Output)
		}
		if len(bytes.TrimSpace(usage)) == 0 || string(bytes.TrimSpace(usage)) == "null" {
			usage = event.Response.Usage
		}
		if len(results) > 0 {
			m.writeCompletedSet(w, results, usage)
			return
		}
		if len(m.finals) > 0 {
			m.writeCompletedSet(w, m.finals, mergeImageUsage(m.finalUsage, usage))
			return
		}
		m.writeError(w, http.StatusBadGateway, "upstream did not return image output")
	}
}

func (m *imageStreamMapper) writeCompletedSet(w io.Writer, results []imageResult, usage json.RawMessage) {
	m.completed = true
	for i := range results {
		m.writeCompleted(w, results[i], usage)
	}
}

func (m *imageStreamMapper) writeCompleted(w io.Writer, result imageResult, usage json.RawMessage) {
	event := imageStreamEvent{
		Type:          m.operation.completedEvent,
		B64JSON:       result.B64JSON,
		RevisedPrompt: result.RevisedPrompt,
	}
	m.applyStreamImageFormat(&event, result.OutputFormat)
	if len(bytes.TrimSpace(usage)) > 0 && string(bytes.TrimSpace(usage)) != "null" {
		if m.omitInputUsage {
			usage = omitInputImageUsage(usage)
		}
		event.Usage = usage
	}
	m.writeSSE(w, m.operation.completedEvent, event)
}

func (m *imageStreamMapper) applyStreamImageFormat(event *imageStreamEvent, outputFormat string) {
	if event == nil || !imageResponseFormatIsURL(m.responseFormat) || strings.TrimSpace(event.B64JSON) == "" {
		return
	}
	event.URL = imageDataURL(event.B64JSON, outputFormat)
	event.B64JSON = ""
}

func (m *imageStreamMapper) writeSSE(w io.Writer, eventName string, payload imageStreamEvent) {
	if w == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventName, string(data))
}

func (m *imageStreamMapper) writeError(w io.Writer, status int, message string) {
	if w == nil {
		return
	}
	m.completed = true
	if status <= 0 {
		status = http.StatusInternalServerError
	}
	if strings.TrimSpace(message) == "" {
		message = http.StatusText(status)
	}
	body := handlers.BuildErrorResponseBody(status, message)
	_, _ = fmt.Fprintf(w, "event: error\ndata: %s\n\n", string(body))
}

type imageSSEParser struct {
	pending []byte
}

func (p *imageSSEParser) Push(chunk []byte) [][]byte {
	if len(chunk) == 0 {
		return nil
	}
	if responsesSSENeedsLineBreak(p.pending, chunk) {
		p.pending = append(p.pending, '\n')
	}
	p.pending = append(p.pending, chunk...)
	var payloads [][]byte
	for {
		frameLen := responsesSSEFrameLen(p.pending)
		if frameLen == 0 {
			break
		}
		payloads = append(payloads, extractImageSSEPayloads(p.pending[:frameLen])...)
		copy(p.pending, p.pending[frameLen:])
		p.pending = p.pending[:len(p.pending)-frameLen]
	}
	if responsesSSECanEmitWithoutDelimiter(p.pending) || json.Valid(bytes.TrimSpace(p.pending)) {
		payloads = append(payloads, extractImageSSEPayloads(p.pending)...)
		p.pending = p.pending[:0]
	}
	return payloads
}

func (p *imageSSEParser) Flush() [][]byte {
	if len(bytes.TrimSpace(p.pending)) == 0 {
		p.pending = p.pending[:0]
		return nil
	}
	payloads := extractImageSSEPayloads(p.pending)
	p.pending = p.pending[:0]
	return payloads
}

func extractImageSSEPayloads(frame []byte) [][]byte {
	trimmed := bytes.TrimSpace(frame)
	if len(trimmed) == 0 {
		return nil
	}
	if json.Valid(trimmed) {
		return [][]byte{bytes.Clone(trimmed)}
	}
	var payloads [][]byte
	for _, line := range bytes.Split(trimmed, []byte("\n")) {
		line = bytes.TrimSpace(bytes.TrimSuffix(line, []byte("\r")))
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		data := bytes.TrimSpace(line[len("data:"):])
		if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) || !json.Valid(data) {
			continue
		}
		payloads = append(payloads, bytes.Clone(data))
	}
	return payloads
}

func responseEventType(payload []byte) string {
	var event struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return ""
	}
	return event.Type
}

func (h *OpenAIImagesAPIHandler) imagesCodexModel() string {
	if h != nil && h.Cfg != nil {
		if model := strings.TrimSpace(h.Cfg.Images.CodexModel); model != "" {
			return model
		}
	}
	return defaultImagesCodexModel
}

func (h *OpenAIImagesAPIHandler) imagesImageModel() string {
	if h != nil && h.Cfg != nil {
		if model := strings.TrimSpace(h.Cfg.Images.ImageModel); model != "" {
			return model
		}
	}
	return defaultImagesImageModel
}

func (h *OpenAIImagesAPIHandler) imagesNAggregationEnabled() bool {
	if h != nil && h.Cfg != nil && h.Cfg.Images.EnableNAggregation != nil {
		return *h.Cfg.Images.EnableNAggregation
	}
	return false
}

func (h *OpenAIImagesAPIHandler) imagesOverrideResponseFormatURLEnabled() bool {
	if h != nil && h.Cfg != nil {
		if h.Cfg.Images.OverrideResponseFormatURL != nil {
			return *h.Cfg.Images.OverrideResponseFormatURL
		}
		return h.Cfg.Images.OverrideUnsupportedParams
	}
	return false
}

func (h *OpenAIImagesAPIHandler) imagesResponseFormatURLDataURLEnabled() bool {
	if h != nil && h.Cfg != nil && h.Cfg.Images.ResponseFormatURLDataURL != nil {
		return *h.Cfg.Images.ResponseFormatURLDataURL
	}
	return false
}

func (h *OpenAIImagesAPIHandler) imagesOverrideTransparentBackgroundEnabled() bool {
	if h != nil && h.Cfg != nil {
		if h.Cfg.Images.OverrideTransparentBackground != nil {
			return *h.Cfg.Images.OverrideTransparentBackground
		}
		return h.Cfg.Images.OverrideUnsupportedParams
	}
	return false
}

func (h *OpenAIImagesAPIHandler) imagesOverrideInputFidelityEnabled() bool {
	if h != nil && h.Cfg != nil {
		if h.Cfg.Images.OverrideInputFidelity != nil {
			return *h.Cfg.Images.OverrideInputFidelity
		}
		return h.Cfg.Images.OverrideUnsupportedParams
	}
	return false
}

func (h *OpenAIImagesAPIHandler) imagesUnsupportedStatusCode() int {
	if h != nil && h.Cfg != nil {
		if code := h.Cfg.Images.UnsupportedStatusCode; code >= http.StatusBadRequest && code <= 599 {
			return code
		}
	}
	return http.StatusBadRequest
}

func (h *OpenAIImagesAPIHandler) writeImagesRequestError(c *gin.Context, err error) {
	var unsupported imageUnsupportedError
	if errors.As(err, &unsupported) {
		h.writeImagesError(c, h.imagesUnsupportedStatusCode(), err)
		return
	}
	h.writeImagesError(c, http.StatusBadRequest, err)
}

func (h *OpenAIImagesAPIHandler) writeImagesError(c *gin.Context, status int, err error) {
	h.WriteErrorResponse(c, &interfaces.ErrorMessage{StatusCode: status, Error: err})
}

func unsupportedImageErrorf(format string, args ...any) error {
	return imageUnsupportedError{err: fmt.Errorf(format, args...)}
}

func setOptionalString(dst map[string]any, key, value string) {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		dst[key] = trimmed
	}
}

func imageURLFromReference(ref imageReference) (string, error) {
	switch v := ref.ImageURL.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return "", errors.New("image_url is empty")
		}
		return strings.TrimSpace(v), nil
	case map[string]any:
		raw, ok := v["url"]
		if !ok {
			return "", errors.New("image_url.url is required")
		}
		url, ok := raw.(string)
		if !ok || strings.TrimSpace(url) == "" {
			return "", errors.New("image_url.url must be a non-empty string")
		}
		return strings.TrimSpace(url), nil
	default:
		return "", errors.New("image_url is required")
	}
}

func dataURLFromFileHeader(fh *multipart.FileHeader) (string, error) {
	if fh == nil {
		return "", errors.New("image file is required")
	}
	file, err := fh.Open()
	if err != nil {
		return "", fmt.Errorf("open image file: %w", err)
	}
	defer func() { _ = file.Close() }()
	limited := io.LimitReader(file, maxImageUploadBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", fmt.Errorf("read image file: %w", err)
	}
	if len(data) == 0 {
		return "", errors.New("image file is empty")
	}
	if len(data) > maxImageUploadBytes {
		return "", fmt.Errorf("image file %q exceeds %d bytes", fh.Filename, maxImageUploadBytes)
	}
	mimeType := strings.TrimSpace(fh.Header.Get("Content-Type"))
	if mimeType == "" || mimeType == "application/octet-stream" {
		mimeType = http.DetectContentType(data)
	}
	return "data:" + mimeType + ";base64," + base64.StdEncoding.EncodeToString(data), nil
}

func multipartValue(form *multipart.Form, key string) string {
	if form == nil || form.Value == nil {
		return ""
	}
	values := form.Value[key]
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func multipartFiles(form *multipart.Form, key string) []*multipart.FileHeader {
	if form == nil || form.File == nil {
		return nil
	}
	return form.File[key]
}

func parseOptionalInt(value string) (int, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, false, fmt.Errorf("invalid integer value %q", value)
	}
	return parsed, true, nil
}

func parseBoolValue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "t", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}
