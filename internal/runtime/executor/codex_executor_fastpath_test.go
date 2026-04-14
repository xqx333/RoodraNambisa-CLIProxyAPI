package executor

import (
	"bytes"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
)

func TestTranslateCodexRequestBodies_ReusesTranslationWhenOriginalMatchesPayload(t *testing.T) {
	from := sdktranslator.FromString("codex")
	to := sdktranslator.FromString("codex")
	payload := []byte(`{"model":"gpt-5","input":"hello"}`)

	originalPayload, originalTranslated, body := translateCodexRequestBodies(
		from,
		to,
		"gpt-5",
		cliproxyexecutor.Request{Payload: payload},
		cliproxyexecutor.Options{},
		true,
	)

	if !bytes.Equal(originalPayload, payload) {
		t.Fatalf("original payload = %s, want %s", string(originalPayload), string(payload))
	}
	if !bytes.Equal(originalTranslated, body) {
		t.Fatalf("original translation = %s, want body %s", string(originalTranslated), string(body))
	}
	if len(body) > 0 && len(originalTranslated) > 0 && &originalTranslated[0] != &body[0] {
		t.Fatalf("expected helper to reuse translated body when original payload matches request payload")
	}
}

func TestTranslateCodexRequestBodies_SeparatesTranslationWhenOriginalRequestDiffers(t *testing.T) {
	from := sdktranslator.FromString("codex")
	to := sdktranslator.FromString("codex")
	currentPayload := []byte(`{"model":"gpt-5","input":"updated"}`)
	originalRequest := []byte(`{"model":"gpt-5","input":"original"}`)

	_, originalTranslated, body := translateCodexRequestBodies(
		from,
		to,
		"gpt-5",
		cliproxyexecutor.Request{Payload: currentPayload},
		cliproxyexecutor.Options{OriginalRequest: originalRequest},
		true,
	)

	if bytes.Equal(originalTranslated, body) {
		t.Fatalf("expected original translation to differ when original request payload changes")
	}
	if len(body) > 0 && len(originalTranslated) > 0 && &originalTranslated[0] == &body[0] {
		t.Fatalf("expected separate translated buffers when original request differs")
	}
}
