package cliproxy

import (
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

func TestRegisterModelsForAuth_UsesPreMergedExcludedModelsAttribute(t *testing.T) {
	service := &Service{
		cfg: &config.Config{
			OAuthExcludedModels: map[string][]string{
				"gemini-cli": {"gemini-2.5-pro"},
			},
		},
	}
	auth := &coreauth.Auth{
		ID:       "auth-gemini-cli",
		Provider: "gemini-cli",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"auth_kind":       "oauth",
			"excluded_models": "gemini-2.5-flash",
		},
	}

	registry := GlobalModelRegistry()
	registry.UnregisterClient(auth.ID)
	t.Cleanup(func() {
		registry.UnregisterClient(auth.ID)
	})

	service.registerModelsForAuth(auth)

	models := registry.GetAvailableModelsByProvider("gemini-cli")
	if len(models) == 0 {
		t.Fatal("expected gemini-cli models to be registered")
	}

	for _, model := range models {
		if model == nil {
			continue
		}
		modelID := strings.TrimSpace(model.ID)
		if strings.EqualFold(modelID, "gemini-2.5-flash") {
			t.Fatalf("expected model %q to be excluded by auth attribute", modelID)
		}
	}

	seenGlobalExcluded := false
	for _, model := range models {
		if model == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(model.ID), "gemini-2.5-pro") {
			seenGlobalExcluded = true
			break
		}
	}
	if !seenGlobalExcluded {
		t.Fatal("expected global excluded model to be present when attribute override is set")
	}
}

func TestRegisterModelsForAuth_CodexImageModelFollowsPlanType(t *testing.T) {
	testCases := []struct {
		name            string
		planType        string
		enableFreeImage bool
		want            bool
	}{
		{name: "free disabled", planType: "free", want: false},
		{name: "free enabled", planType: "free", enableFreeImage: true, want: true},
		{name: "plus", planType: "plus", want: true},
		{name: "pro", planType: "pro", want: true},
		{name: "team", planType: "team", want: true},
		{name: "business", planType: "business", want: true},
		{name: "go", planType: "go", want: true},
		{name: "missing plan", planType: "", want: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service := &Service{
				cfg: &config.Config{
					SDKConfig: config.SDKConfig{
						Images: config.ImagesConfig{
							ImageModel:               "gpt-image-custom",
							EnableFreePlanImageModel: tc.enableFreeImage,
						},
					},
				},
			}
			auth := &coreauth.Auth{
				ID:       "auth-codex-" + strings.ReplaceAll(tc.name, " ", "-"),
				Provider: "codex",
				Status:   coreauth.StatusActive,
				Attributes: map[string]string{
					"plan_type": tc.planType,
				},
			}
			reg := GlobalModelRegistry()
			reg.UnregisterClient(auth.ID)
			t.Cleanup(func() {
				reg.UnregisterClient(auth.ID)
			})

			service.registerModelsForAuth(auth)

			models := registry.GetGlobalRegistry().GetModelsForClient(auth.ID)
			hasImage := false
			for _, model := range models {
				if model != nil && strings.EqualFold(strings.TrimSpace(model.ID), "gpt-image-custom") {
					hasImage = true
					break
				}
			}
			if hasImage != tc.want {
				t.Fatalf("image model presence = %v, want %v", hasImage, tc.want)
			}
		})
	}
}

func TestRegisterModelsForAuth_CodexImageModelRespectsExcludedModels(t *testing.T) {
	service := &Service{
		cfg: &config.Config{
			SDKConfig: config.SDKConfig{
				Images: config.ImagesConfig{ImageModel: "gpt-image-custom"},
			},
		},
	}
	auth := &coreauth.Auth{
		ID:       "auth-codex-image-excluded",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"plan_type":       "plus",
			"excluded_models": "gpt-image-custom",
		},
	}

	reg := GlobalModelRegistry()
	reg.UnregisterClient(auth.ID)
	t.Cleanup(func() {
		reg.UnregisterClient(auth.ID)
	})

	service.registerModelsForAuth(auth)

	for _, model := range registry.GetGlobalRegistry().GetModelsForClient(auth.ID) {
		if model != nil && strings.EqualFold(strings.TrimSpace(model.ID), "gpt-image-custom") {
			t.Fatalf("expected excluded image model to be absent, got %q", model.ID)
		}
	}
}

func TestRegisterModelsForAuth_CodexCustomModelsFollowPlanGroups(t *testing.T) {
	testCases := []struct {
		name     string
		planType string
		want     bool
	}{
		{name: "free excluded by groups", planType: "free", want: false},
		{name: "plus", planType: "plus", want: true},
		{name: "pro", planType: "pro", want: true},
		{name: "team", planType: "team", want: true},
		{name: "business", planType: "business", want: true},
		{name: "go", planType: "go", want: true},
		{name: "missing plan defaults to pro", planType: "", want: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service := &Service{
				cfg: &config.Config{
					CodexCustomModels: []config.CodexCustomModel{
						{ID: "gpt-5.5-codex", DisplayName: "GPT 5.5 Codex", Groups: []string{"plus", "pro", "team", "business", "go"}},
					},
				},
			}
			auth := &coreauth.Auth{
				ID:       "auth-codex-custom-" + strings.ReplaceAll(tc.name, " ", "-"),
				Provider: "codex",
				Status:   coreauth.StatusActive,
				Attributes: map[string]string{
					"plan_type": tc.planType,
				},
			}
			reg := GlobalModelRegistry()
			reg.UnregisterClient(auth.ID)
			t.Cleanup(func() {
				reg.UnregisterClient(auth.ID)
			})

			service.registerModelsForAuth(auth)

			hasCustom := containsRegisteredModel(registry.GetGlobalRegistry().GetModelsForClient(auth.ID), "gpt-5.5-codex")
			if hasCustom != tc.want {
				t.Fatalf("custom model presence = %v, want %v", hasCustom, tc.want)
			}
		})
	}
}

func TestRegisterModelsForAuth_CodexCustomModelsCanIncludeFree(t *testing.T) {
	service := &Service{
		cfg: &config.Config{
			CodexCustomModels: []config.CodexCustomModel{
				{ID: "gpt-5.5-codex", Groups: []string{"free"}},
			},
		},
	}
	auth := &coreauth.Auth{
		ID:       "auth-codex-custom-free",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"plan_type": "free",
		},
	}
	reg := GlobalModelRegistry()
	reg.UnregisterClient(auth.ID)
	t.Cleanup(func() {
		reg.UnregisterClient(auth.ID)
	})

	service.registerModelsForAuth(auth)

	if !containsRegisteredModel(registry.GetGlobalRegistry().GetModelsForClient(auth.ID), "gpt-5.5-codex") {
		t.Fatal("expected free custom model to be registered when free is listed in groups")
	}
}

func TestRegisterModelsForAuth_CodexCustomModelsOverrideBuiltInGroups(t *testing.T) {
	testCases := []struct {
		name     string
		groups   []string
		planType string
		want     bool
	}{
		{name: "pro only removes plus built in", groups: []string{"pro"}, planType: "plus", want: false},
		{name: "pro only keeps pro", groups: []string{"pro"}, planType: "pro", want: true},
		{name: "plus only keeps plus", groups: []string{"plus"}, planType: "plus", want: true},
		{name: "plus only removes pro built in", groups: []string{"plus"}, planType: "pro", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service := &Service{
				cfg: &config.Config{
					CodexCustomModels: []config.CodexCustomModel{
						{ID: "gpt-5.4-mini", DisplayName: "Custom GPT 5.4 Mini", Groups: tc.groups},
					},
				},
			}
			auth := &coreauth.Auth{
				ID:       "auth-codex-custom-override-" + strings.ReplaceAll(tc.name, " ", "-"),
				Provider: "codex",
				Status:   coreauth.StatusActive,
				Attributes: map[string]string{
					"plan_type": tc.planType,
				},
			}
			reg := GlobalModelRegistry()
			reg.UnregisterClient(auth.ID)
			t.Cleanup(func() {
				reg.UnregisterClient(auth.ID)
			})

			service.registerModelsForAuth(auth)

			hasModel := containsRegisteredModel(registry.GetGlobalRegistry().GetModelsForClient(auth.ID), "gpt-5.4-mini")
			if hasModel != tc.want {
				t.Fatalf("gpt-5.4-mini presence = %v, want %v", hasModel, tc.want)
			}
		})
	}
}

func TestRegisterModelsForAuth_CodexCustomModelsRespectExcludedModels(t *testing.T) {
	service := &Service{
		cfg: &config.Config{
			CodexCustomModels: []config.CodexCustomModel{
				{ID: "gpt-5.5-codex", Groups: []string{"plus"}},
			},
		},
	}
	auth := &coreauth.Auth{
		ID:       "auth-codex-custom-excluded",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"plan_type":       "plus",
			"excluded_models": "gpt-5.5-codex",
		},
	}
	reg := GlobalModelRegistry()
	reg.UnregisterClient(auth.ID)
	t.Cleanup(func() {
		reg.UnregisterClient(auth.ID)
	})

	service.registerModelsForAuth(auth)

	if containsRegisteredModel(registry.GetGlobalRegistry().GetModelsForClient(auth.ID), "gpt-5.5-codex") {
		t.Fatal("expected custom model to be removed by excluded_models")
	}
}

func TestRegisterModelsForAuth_CodexCustomModelsApplyOAuthAlias(t *testing.T) {
	service := &Service{
		cfg: &config.Config{
			CodexCustomModels: []config.CodexCustomModel{
				{ID: "gpt-5.5-codex", Groups: []string{"plus"}},
			},
			OAuthModelAlias: map[string][]config.OAuthModelAlias{
				"codex": {
					{Name: "gpt-5.5-codex", Alias: "codex-latest", Fork: true},
				},
			},
		},
	}
	auth := &coreauth.Auth{
		ID:       "auth-codex-custom-alias",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"plan_type": "plus",
		},
	}
	reg := GlobalModelRegistry()
	reg.UnregisterClient(auth.ID)
	t.Cleanup(func() {
		reg.UnregisterClient(auth.ID)
	})

	service.registerModelsForAuth(auth)

	models := registry.GetGlobalRegistry().GetModelsForClient(auth.ID)
	if !containsRegisteredModel(models, "gpt-5.5-codex") {
		t.Fatal("expected original custom model to remain with fork alias")
	}
	if !containsRegisteredModel(models, "codex-latest") {
		t.Fatal("expected alias for custom model to be registered")
	}
}
