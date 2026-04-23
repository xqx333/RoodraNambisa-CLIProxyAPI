package registry

import "testing"

func assertCodexModelsDoNotContain(t *testing.T, models []*ModelInfo, modelID string) {
	t.Helper()
	for _, model := range models {
		if model == nil {
			continue
		}
		if model.ID == modelID {
			t.Fatalf("expected codex models to exclude %q", modelID)
		}
	}
}

func TestGetCodexFreeModels_NoLongerIncludesBuiltInImageModel(t *testing.T) {
	assertCodexModelsDoNotContain(t, GetCodexFreeModels(), "gpt-image-2")
}

func TestGetCodexTeamModels_NoLongerIncludesBuiltInImageModel(t *testing.T) {
	assertCodexModelsDoNotContain(t, GetCodexTeamModels(), "gpt-image-2")
}

func TestGetCodexPlusModels_NoLongerIncludesBuiltInImageModel(t *testing.T) {
	assertCodexModelsDoNotContain(t, GetCodexPlusModels(), "gpt-image-2")
}

func TestGetCodexProModels_StillIncludesSpark(t *testing.T) {
	models := GetCodexProModels()
	for _, model := range models {
		if model == nil {
			continue
		}
		if model.ID == codexSparkModelID {
			return
		}
	}
	t.Fatalf("expected codex pro models to include %q", codexSparkModelID)
}

func TestGetCodexProModels_NoLongerIncludesBuiltInImageModel(t *testing.T) {
	assertCodexModelsDoNotContain(t, GetCodexProModels(), "gpt-image-2")
}

func TestGetCodexPlusModels_ExcludesSpark(t *testing.T) {
	models := GetCodexPlusModels()
	if len(models) == 0 {
		t.Fatal("expected codex plus models to be non-empty")
	}
	for _, model := range models {
		if model == nil {
			continue
		}
		if model.ID == codexSparkModelID {
			t.Fatalf("expected codex plus models to exclude %q", codexSparkModelID)
		}
	}
}
