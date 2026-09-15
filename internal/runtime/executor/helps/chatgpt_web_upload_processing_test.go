package helps

import (
	"context"
	"strings"
	"testing"
)

func TestChatGPTWebUploadProcessing(t *testing.T) {
	completed := `{"file_id":"file_test","event":"file.processing.completed"}`
	for _, test := range []struct {
		name, input string
		wantError   bool
	}{
		{"ndjson", `{"file_id":"file_test","event":"file.processing.started"}` + "\n" + completed + "\n", false},
		{"sse", ": heartbeat\n\nevent: file.processing.completed\ndata: {\"file_id\":\"file_test\"}\n\n", false},
		{"sse EOF", "data: " + completed, false},
		{"ready is not completed", `{"file_id":"file_test","event":"file.processing.file_ready"}`, true},
		{"failure", `{"file_id":"file_test","event":"file.processing.error","message":"secret"}`, true},
		{"wrong file", `{"file_id":"other","event":"file.processing.completed"}`, true},
		{"empty", "", true}, {"invalid", "<html>bad gateway</html>", true},
		{"oversized", strings.Repeat("x", 256<<10), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ConsumeChatGPTWebUploadProcessing(t.Context(), strings.NewReader(test.input), "file_test")
			if (err != nil) != test.wantError {
				t.Fatalf("error=%v", err)
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Fatal("upstream content leaked")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := ConsumeChatGPTWebUploadProcessing(ctx, strings.NewReader(completed), "file_test"); err != context.Canceled {
		t.Fatal(err)
	}
}
