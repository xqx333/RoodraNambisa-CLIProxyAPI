package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestImageLibraryCleanupConfigStrictOptIn(t *testing.T) {
	for _, tt := range []struct {
		source         string
		valid, enabled bool
	}{{"{}", true, false}, {"auto-cleanup-library-on-full: true", true, true}, {"auto-cleanup-library-on-full: false", true, false}, {"auto-cleanup-library-on-full: null", false, false}, {"auto-cleanup-library-on-full: 1", false, false}, {"auto-cleanup-library-on-full: 'true'", false, false}} {
		var cfg ChatGPTWebImageConfig
		err := yaml.Unmarshal([]byte(tt.source), &cfg)
		if (err == nil) != tt.valid || cfg.Resolved().AutoCleanupLibraryOnFull != tt.enabled {
			t.Fatalf("%s err=%v cfg=%+v", tt.source, err, cfg)
		}
	}
}
