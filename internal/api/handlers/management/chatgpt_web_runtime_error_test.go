package management

import (
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestChatGPTWebRuntimeErrorsDoNotInventAuthenticationFailure(t *testing.T) {
	for _, test := range []struct {
		status int
		code   string
	}{
		{401, "authentication_failed"}, {403, "permission_denied"}, {404, "not_found"},
		{429, "rate_limited"}, {451, "access_restricted"}, {502, "upstream_error"}, {400, "request_rejected"}, {0, "request_failed"},
	} {
		err := &coreauth.Error{HTTPStatus: test.status, Code: "unrecognized_private_reason"}
		if got := chatGPTWebRequestErrorCategory(err); got != test.code {
			t.Errorf("status %d: %s, want %s", test.status, got, test.code)
		}
	}
	if got := chatGPTWebRequestErrorCategory(&coreauth.Error{HTTPStatus: 403, Code: "account_deleted"}); got != "account_deleted" {
		t.Fatal(got)
	}
	if got := chatGPTWebRequestErrorCategory(&coreauth.Error{Diagnostic: &coreauth.ErrorDiagnostic{Code: "network_timeout"}}); got != "network_timeout" {
		t.Fatal(got)
	}
}
