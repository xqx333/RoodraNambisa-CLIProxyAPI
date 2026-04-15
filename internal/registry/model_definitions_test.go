package registry

import "testing"

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
