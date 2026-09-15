package executor

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

func TestChatGPTWebLibraryAutoCleanupTriggerGuards(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		enabled, image, canceled, storage bool
		path                              string
		want                              bool
	}{
		{"disabled", false, true, false, true, "/backend-api/files", false},
		{"chat", true, false, false, true, "/backend-api/files", false},
		{"canceled", true, true, true, true, "/backend-api/files", false},
		{"ordinary429", true, true, false, false, "/backend-api/files", false},
		{"generationQuota", true, true, false, true, "/backend-api/conversation", false},
		{"sign", true, true, false, true, "/backend-api/files", true},
		{"confirm", true, true, false, true, "/backend-api/files/process_upload_stream", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := coreauth.NewManager(nil, nil, nil)
			a, err := m.Register(t.Context(), &coreauth.Auth{ID: tc.name, Provider: "chatgpt-web"})
			if err != nil {
				t.Fatal(err)
			}
			_, release, _ := a.BeginRuntimeExecution(t.Context())
			defer release()
			e := NewChatGPTWebExecutor(&config.Config{}, m)
			defer func() { release(); _ = m.LibraryCleanup().Shutdown(context.Background()); _ = e.Close() }()
			p := &chatGPTWebPreparedRequest{imageConfigSnapshot: coreexecutor.ChatGPTWebImageConfigSnapshot{AutoCleanupLibraryOnFull: tc.enabled}}
			if tc.image {
				p.request.Image = &helps.ChatGPTWebImageRequest{}
			}
			payload := []byte(`{"detail":{}}`)
			if tc.storage {
				payload = []byte(`{"detail":{"code":"library_storage_limit_exceeded"}}`)
			}
			original := newChatGPTWebStatusError(http.StatusTooManyRequests, tc.path, payload, nil)
			tagged := chatGPTWebLibraryUploadSize(original, 100)
			var httpError chatGPTWebHTTPError
			if !errors.As(tagged, &httpError) || httpError.StatusCode() != original.StatusCode() || tagged.Error() != original.Error() {
				t.Fatal("original public error changed")
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			e.scheduleChatGPTWebLibraryCleanup(ctx, a, p, tagged)
			if (m.LibraryCleanup().Snapshot() != nil) != tc.want {
				t.Fatal("wrong automatic trigger")
			}
		})
	}
}
