package registry

import "testing"

func TestGetCodexProModels_ExcludesSpark(t *testing.T) {
	models := GetCodexProModels()
	if len(models) == 0 {
		t.Fatal("expected codex pro models to be non-empty")
	}
	for _, model := range models {
		if model == nil {
			continue
		}
		if model.ID == codexSparkModelID {
			t.Fatalf("expected codex pro models to exclude %q", codexSparkModelID)
		}
	}
}

func TestGetCodexPlusModels_StillIncludesSpark(t *testing.T) {
	models := GetCodexPlusModels()
	for _, model := range models {
		if model == nil {
			continue
		}
		if model.ID == codexSparkModelID {
			return
		}
	}
	t.Fatalf("expected codex plus models to include %q", codexSparkModelID)
}
