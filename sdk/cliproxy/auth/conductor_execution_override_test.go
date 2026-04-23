package auth

import (
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

func TestPreparedExecutionModels_UsesExecutionModelOverride(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:       "codex-image-auth",
		Provider: "codex",
		Status:   StatusActive,
	}
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{
			cliproxyexecutor.ExecutionModelOverrideMetadataKey: "gpt-5.4-mini",
		},
	}

	models, pooled := manager.preparedExecutionModels(auth, "gpt-image-2", opts)
	if pooled {
		t.Fatal("expected non-pooled execution model list")
	}
	if len(models) != 1 || models[0] != "gpt-5.4-mini" {
		t.Fatalf("preparedExecutionModels() = %v, want [gpt-5.4-mini]", models)
	}
	if got := manager.stateModelForExecution(auth, "gpt-image-2", models[0], pooled); got != "gpt-image-2" {
		t.Fatalf("stateModelForExecution() = %q, want gpt-image-2", got)
	}
}
