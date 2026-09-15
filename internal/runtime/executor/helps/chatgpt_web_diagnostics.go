package helps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	chatgptwebauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/chatgptweb"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/managementdiag"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

const (
	maxChatGPTWebDiagnosticValueBytes        = 128
	maxChatGPTWebDiagnosticResponseBodyBytes = 4096
)

var chatGPTWebDiagnosticCodePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

// ChatGPTWebHeaderGetter is implemented by standard and fingerprinted HTTP headers.
type ChatGPTWebHeaderGetter interface {
	Get(string) string
}

// ClassifyChatGPTWebTransportDiagnostic extracts a safe transport failure class without retaining the error text.
func ClassifyChatGPTWebTransportDiagnostic(err error, path string) *cliproxyauth.ErrorDiagnostic {
	code := "network_error"
	retryable := true
	switch {
	case err == nil:
		code = "network_error"
	case errors.Is(err, context.Canceled):
		code = "request_canceled"
		retryable = false
	case errors.Is(err, context.DeadlineExceeded):
		code = "network_timeout"
	default:
		var dnsError *net.DNSError
		var networkError net.Error
		lower := strings.ToLower(err.Error())
		switch {
		case errors.As(err, &dnsError):
			code = "dns_error"
		case errors.As(err, &networkError) && networkError.Timeout():
			code = "network_timeout"
		case strings.Contains(lower, "tls") || strings.Contains(lower, "x509") || strings.Contains(lower, "certificate"):
			code = "tls_error"
		case strings.Contains(lower, "proxyconnect") || strings.Contains(lower, "proxy connection"):
			code = "proxy_error"
		}
	}
	targetHost, targetPath := chatGPTWebDiagnosticTarget(path)
	return &cliproxyauth.ErrorDiagnostic{
		Provider:   "chatgpt-web",
		Stage:      ChatGPTWebDiagnosticStage(targetPath),
		Code:       code,
		TargetHost: targetHost,
		TargetPath: targetPath,
		Retryable:  retryable,
	}
}

// ClassifyChatGPTWebHTTPDiagnostic extracts bounded troubleshooting details from an upstream response.
func ClassifyChatGPTWebHTTPDiagnostic(status int, path string, body []byte, headers ChatGPTWebHeaderGetter) *cliproxyauth.ErrorDiagnostic {
	contentType := ""
	cfRay := ""
	cfMitigated := ""
	server := ""
	if headers != nil {
		contentType = normalizeChatGPTWebDiagnosticContentType(headers.Get("Content-Type"))
		cfRay = safeChatGPTWebDiagnosticValue(headers.Get("cf-ray"))
		cfMitigated = strings.ToLower(strings.TrimSpace(headers.Get("cf-mitigated")))
		server = strings.ToLower(strings.TrimSpace(headers.Get("server")))
	}
	responseType := chatGPTWebDiagnosticResponseType(contentType, body)
	responseBody, responseBodyTruncated := chatGPTWebDiagnosticResponseBody(body, responseType)
	cloudflare := chatGPTWebDiagnosticCloudflare(status, cfMitigated, server, responseType, body)
	code := chatGPTWebDiagnosticErrorCode(status, responseType, cloudflare, body)
	retryable := cloudflare || status == http.StatusRequestTimeout || status == http.StatusTooEarly ||
		status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
	return &cliproxyauth.ErrorDiagnostic{
		Provider:              "chatgpt-web",
		Stage:                 ChatGPTWebDiagnosticStage(path),
		Code:                  code,
		ResponseType:          responseType,
		ContentType:           contentType,
		CFRay:                 cfRay,
		TargetHost:            chatGPTWebDiagnosticHost(path),
		TargetPath:            safeChatGPTWebDiagnosticPath(path),
		ResponseBytes:         int64(len(body)),
		ResponseBody:          responseBody,
		ResponseBodyTruncated: responseBodyTruncated,
		HTTPStatus:            status,
		Cloudflare:            cloudflare,
		Retryable:             retryable,
	}
}

func chatGPTWebDiagnosticResponseBody(body []byte, responseType string) (string, bool) {
	if len(body) == 0 || responseType == "binary" {
		return "", false
	}
	return managementdiag.ProcessResponseBody(
		string(body),
		managementdiag.DetailLevelFull,
		maxChatGPTWebDiagnosticResponseBodyBytes,
	)
}

// ChatGPTWebDiagnosticStage maps trusted upstream paths to a stable troubleshooting stage.
func ChatGPTWebDiagnosticStage(path string) string {
	path = strings.ToLower(safeChatGPTWebDiagnosticPath(path))
	if queryIndex := strings.IndexByte(path, '?'); queryIndex >= 0 {
		path = path[:queryIndex]
	}
	switch {
	case strings.Contains(path, "/passkey/verify"):
		return "passkey_verify"
	case strings.Contains(path, "/api/auth/session"):
		return "session"
	case strings.Contains(path, "/chat-requirements/prepare"):
		return "sentinel_prepare"
	case strings.Contains(path, "/chat-requirements/finalize"):
		return "sentinel_finalize"
	case strings.Contains(path, "/sentinel/sdk"):
		return "sentinel_sdk"
	case strings.HasSuffix(path, "/backend-api/files"):
		return "file_sign"
	case strings.HasSuffix(path, "/backend-api/files/process_upload_stream"):
		return "file_confirm"
	case strings.Contains(path, "/backend-api/files/") && strings.HasSuffix(path, "/uploaded"):
		return "file_confirm"
	case strings.Contains(path, "/backend-api/files/") && strings.HasSuffix(path, "/download"):
		return "image_download"
	case strings.Contains(path, "/backend-api/models"):
		return "models"
	case strings.Contains(path, "/accounts/check") || strings.Contains(path, "/limits"):
		return "quota_refresh"
	case strings.Contains(path, "/conversation"):
		return "conversation"
	default:
		return "upstream_request"
	}
}

func chatGPTWebDiagnosticErrorCode(status int, responseType string, cloudflare bool, body []byte) string {
	if cloudflare {
		return "cloudflare_challenge"
	}
	if upstreamCode := chatGPTWebStructuredDiagnosticCode(body); upstreamCode != "" {
		return upstreamCode
	}
	switch status {
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusTooManyRequests:
		return "rate_limited"
	}
	if responseType != "json" && status >= http.StatusBadRequest {
		return "upstream_non_json"
	}
	if status >= http.StatusInternalServerError {
		return "upstream_server_error"
	}
	if status >= http.StatusBadRequest {
		return "upstream_request_error"
	}
	return "upstream_challenge"
}

func chatGPTWebStructuredDiagnosticCode(body []byte) string {
	if !json.Valid(body) {
		return ""
	}
	for _, path := range []string{
		"error.code", "error.type", "code", "type", "detail.code", "detail.type",
		"page.payload.error.code", "page.payload.error.type", "page.payload.code", "page.payload.type",
	} {
		value := strings.TrimSpace(gjson.GetBytes(body, path).String())
		if chatGPTWebDiagnosticCodePattern.MatchString(value) {
			return chatgptwebauth.SafeDiagnosticCode(value)
		}
	}
	return ""
}

func chatGPTWebDiagnosticResponseType(contentType string, body []byte) string {
	if len(body) == 0 {
		return "empty"
	}
	if json.Valid(body) {
		return "json"
	}
	lower := bytes.ToLower(bytes.TrimSpace(body))
	if contentType == "text/html" || bytes.HasPrefix(lower, []byte("<!doctype html")) || bytes.HasPrefix(lower, []byte("<html")) {
		return "html"
	}
	if strings.HasPrefix(contentType, "text/") || utf8.Valid(body) {
		return "text"
	}
	return "binary"
}

func chatGPTWebDiagnosticCloudflare(status int, cfMitigated, server, responseType string, body []byte) bool {
	if cfMitigated != "" && cfMitigated != "none" {
		return true
	}
	lower := bytes.ToLower(body)
	bodyChallenge := bytes.Contains(lower, []byte("/cdn-cgi/challenge-platform")) ||
		bytes.Contains(lower, []byte("cf-chl-")) ||
		bytes.Contains(lower, []byte("challenge-platform")) ||
		bytes.Contains(lower, []byte("just a moment")) ||
		bytes.Contains(lower, []byte("attention required! | cloudflare"))
	serverChallenge := responseType == "html" && strings.Contains(server, "cloudflare") &&
		(status == http.StatusForbidden || status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable)
	return bodyChallenge || serverChallenge
}

func normalizeChatGPTWebDiagnosticContentType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	mediaType, _, errParse := mime.ParseMediaType(value)
	if errParse != nil {
		if index := strings.IndexByte(value, ';'); index >= 0 {
			value = value[:index]
		}
		return safeChatGPTWebDiagnosticValue(strings.ToLower(strings.TrimSpace(value)))
	}
	return safeChatGPTWebDiagnosticValue(strings.ToLower(mediaType))
}

func safeChatGPTWebDiagnosticValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > maxChatGPTWebDiagnosticValueBytes {
		value = value[:maxChatGPTWebDiagnosticValueBytes]
	}
	return value
}

func safeChatGPTWebDiagnosticPath(path string) string {
	_, safePath := chatGPTWebDiagnosticTarget(path)
	return safePath
}

func chatGPTWebDiagnosticHost(path string) string {
	host, _ := chatGPTWebDiagnosticTarget(path)
	return host
}

func chatGPTWebDiagnosticTarget(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if parsed, errParse := url.Parse(raw); errParse == nil && parsed.IsAbs() {
		host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
		if !trustedChatGPTWebDiagnosticHost(host) {
			host = "external_asset"
		}
		processed := managementdiag.ProcessURL(raw, managementdiag.DetailLevelFull)
		processedURL, errProcessed := url.Parse(processed)
		if errProcessed != nil {
			processedURL = parsed
			processedURL.RawQuery = ""
		}
		path := processedURL.EscapedPath()
		if path == "" {
			path = "/"
		}
		if processedURL.RawQuery != "" {
			path += "?" + processedURL.RawQuery
		}
		return host, safeChatGPTWebDiagnosticValue(path)
	}
	if strings.HasPrefix(raw, "/") {
		processed := managementdiag.ProcessURL("https://management.invalid"+raw, managementdiag.DetailLevelFull)
		raw = strings.TrimPrefix(processed, "https://management.invalid")
	}
	if raw == "" || raw[0] != '/' {
		raw = "/"
	}
	host := "chatgpt.com"
	if strings.Contains(strings.ToLower(raw), "/passkey/") {
		host = "auth.openai.com"
	}
	return host, safeChatGPTWebDiagnosticValue(raw)
}

func trustedChatGPTWebDiagnosticHost(host string) bool {
	for _, suffix := range []string{"chatgpt.com", "openai.com", "oaiusercontent.com", "oaistatic.com", "blob.core.windows.net"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// ChatGPTWebDiagnosticLogFields returns the structured log whitelist for one diagnostic.
func ChatGPTWebDiagnosticLogFields(diagnostic *cliproxyauth.ErrorDiagnostic) map[string]any {
	if diagnostic == nil {
		return nil
	}
	fields := map[string]any{
		"provider":    diagnostic.Provider,
		"auth_index":  diagnostic.AuthIndex,
		"stage":       diagnostic.Stage,
		"code":        diagnostic.Code,
		"status":      diagnostic.HTTPStatus,
		"retryable":   diagnostic.Retryable,
		"target_host": diagnostic.TargetHost,
		"target_path": managementdiag.NewManagementOnlyValueWithFallback(
			diagnostic.TargetPath,
			strings.SplitN(diagnostic.TargetPath, "?", 2)[0],
		),
		"persona":                diagnostic.Persona,
		"catalog_version":        diagnostic.CatalogVersion,
		"catalog_id":             diagnostic.CatalogID,
		"transport_persona_id":   diagnostic.TransportPersonaID,
		"browser_environment_id": diagnostic.BrowserEnvironmentID,
		"tls_profile":            diagnostic.TLSProfile,
		"ua_major":               diagnostic.UAMajor,
		"platform":               diagnostic.Platform,
		"response_type":          diagnostic.ResponseType,
		"content_type":           diagnostic.ContentType,
		"response_bytes":         diagnostic.ResponseBytes,
		"attempts":               diagnostic.Attempts,
		"cloudflare":             diagnostic.Cloudflare,
	}
	if diagnostic.ResponseBody != "" {
		fileLogBody, _ := managementdiag.ProcessResponseBody(
			diagnostic.ResponseBody,
			managementdiag.DetailLevelFull,
			maxChatGPTWebDiagnosticResponseBodyBytes,
		)
		fields["response_body"] = managementdiag.NewManagementOnlyValueWithFallback(diagnostic.ResponseBody, fileLogBody)
		fields["response_body_truncated"] = diagnostic.ResponseBodyTruncated
	}
	if diagnostic.CFRay != "" {
		fields["cf_ray"] = diagnostic.CFRay
	}
	return fields
}
