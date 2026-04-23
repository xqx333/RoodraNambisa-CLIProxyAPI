package management

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
)

func TestManagementCallbackURLIncludesAccessPath(t *testing.T) {
	h := NewHandler(&config.Config{
		Port: 8317,
		RemoteManagement: config.RemoteManagement{
			AccessPath: "secret-token",
		},
	}, "", nil)

	got, err := h.managementCallbackURL("/codex/callback")
	if err != nil {
		t.Fatalf("managementCallbackURL returned error: %v", err)
	}
	want := "http://127.0.0.1:8317/secret-token/codex/callback"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
