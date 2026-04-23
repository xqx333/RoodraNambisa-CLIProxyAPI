package config

import (
	"os"
	"testing"
)

func TestNormalizeManagementAccessPath(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      string
		wantError bool
	}{
		{name: "empty", input: "", want: ""},
		{name: "trim spaces and slashes", input: " /secret-token/ ", want: "secret-token"},
		{name: "allows safe characters", input: "abc.DEF_123-xyz", want: "abc.DEF_123-xyz"},
		{name: "rejects slash", input: "a/b", wantError: true},
		{name: "rejects query", input: "abc?x=1", wantError: true},
		{name: "rejects dot segment", input: "..", wantError: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeManagementAccessPath(tt.input)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadConfigOptionalRejectsInvalidManagementAccessPath(t *testing.T) {
	path := writeTempConfig(t, "remote-management:\n  access-path: bad/path\n")
	if _, err := LoadConfigOptional(path, false); err == nil {
		t.Fatalf("expected invalid access path error")
	}
}

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()

	path := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	return path
}
