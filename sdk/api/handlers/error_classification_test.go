package handlers

import (
	"encoding/json"
	"testing"
)

func TestGenericErrorClassificationDoesNotInventCause(t *testing.T) {
	for _, test := range []struct {
		status        int
		message, code string
	}{
		{404, "status 404", "not_found"},
		{404, "upload endpoint not found", "not_found"},
		{404, "The model missing does not exist", "model_not_found"},
		{403, "Forbidden", "permission_denied"},
		{403, `{"error":{"message":"quota","code":"insufficient_quota"}}`, "insufficient_quota"},
		{404, `{"error":{"message":"missing","code":"model_not_found"}}`, "model_not_found"},
	} {
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(BuildErrorResponseBody(test.status, test.message), &body); err != nil {
			t.Fatal(err)
		}
		if body.Error.Code != test.code {
			t.Errorf("HTTP %d %q: code=%s, want %s", test.status, test.message, body.Error.Code, test.code)
		}
		var event struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(BuildOpenAIResponsesStreamErrorChunk(test.status, test.message, 0), &event); err != nil {
			t.Fatal(err)
		}
		if event.Code != test.code {
			t.Errorf("SSE %d %q: code=%s, want %s", test.status, test.message, event.Code, test.code)
		}
	}
}
