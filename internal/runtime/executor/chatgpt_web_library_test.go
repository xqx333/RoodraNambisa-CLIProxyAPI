package executor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestChatGPTWebLibraryCancellationClosesOwnedBody(t *testing.T) {
	reading, disconnected := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/backend-api/files/library/storage/usage" || r.Method != http.MethodGet {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("missing authentication")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{"))
		w.(http.Flusher).Flush()
		close(reading)
		<-r.Context().Done()
		close(disconnected)
	}))
	defer server.Close()
	executor := NewChatGPTWebExecutor(nil, nil)
	executor.runtimeBaseURL = server.URL
	defer func() { _ = executor.Close() }()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := executor.CleanupLibrary(ctx, chatGPTWebRuntimeAuth(), nil); done <- err }()
	select {
	case <-reading:
	case <-time.After(3 * time.Second):
		t.Fatal("body read did not start")
	}
	cancel()
	select {
	case <-disconnected:
	case <-time.After(3 * time.Second):
		t.Fatal("owned connection was not closed")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled operation succeeded")
		}
		if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
			t.Fatal("missing cancellation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("body reader did not exit")
	}
}
