package executor

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestChatGPTWebUploadConfirmationProtocol(t *testing.T) {
	for _, test := range []struct {
		name      string
		status    int
		body      string
		legacy    int
		wantError bool
	}{
		{"ndjson", 200, "{\"event\":\"file.processing.file_ready\",\"file_id\":\"file_test\"}\n{\"event\":\"file.processing.completed\",\"file_id\":\"file_test\"}\n", 0, false},
		{"legacy404", 404, `not found`, 1, false},
		{"legacy405", 405, `not allowed`, 1, false},
		{"auth", 401, `{"detail":"unauthorized"}`, 0, true},
		{"restricted", 451, `{"detail":{}}`, 0, true},
		{"ambiguous", 200, "{\"event\":\"file.processing.file_ready\",\"file_id\":\"file_test\"}\n", 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			modern, legacy := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/backend-api/files/process_upload_stream":
					modern++
					var payload struct {
						FileID   string `json:"file_id"`
						Metadata struct {
							Store bool `json:"store_in_library"`
						} `json:"metadata"`
					}
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Error(err)
					}
					if payload.FileID != "file_test" || payload.Metadata.Store {
						t.Errorf("unexpected payload %+v", payload)
					}
					w.Header().Set("Content-Type", "text/event-stream")
					w.WriteHeader(test.status)
					_, _ = io.WriteString(w, test.body)
				case "/backend-api/files/file_test/uploaded":
					legacy++
					_, _ = io.WriteString(w, `{"ok":true}`)
				default:
					t.Errorf("unexpected replay %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			executor := NewChatGPTWebExecutor(nil, nil)
			executor.runtimeBaseURL = server.URL
			client, credential, err := executor.newRuntimeClient(chatGPTWebRuntimeAuth())
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			err = executor.confirmChatGPTWebImageUpload(t.Context(), client, credential, "file_test", "input.png")
			if (err != nil) != test.wantError || modern != 1 || legacy != test.legacy {
				t.Fatalf("modern=%d legacy=%d err=%v", modern, legacy, err)
			}
		})
	}
}
