package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
)

func (cfg ChatGPTWebImageConfig) ValidateBootstrap() error {
	if cfg.BootstrapTimeoutSeconds < 0 || cfg.BootstrapTimeoutSeconds > 3600 {
		return fmt.Errorf("images.chatgpt-web.bootstrap-timeout-seconds must be an integer between 0 and 3600")
	}
	if cfg.BootstrapRetries < 0 || cfg.BootstrapRetries > 5 {
		return fmt.Errorf("images.chatgpt-web.bootstrap-retries must be an integer between 0 and 5")
	}
	return nil
}

func (cfg *ChatGPTWebImageConfig) UnmarshalYAML(node *yaml.Node) error {
	// yaml.v3 otherwise truncates floating-point scalars when decoding integers.
	var fields map[string]any
	if err := node.Decode(&fields); err != nil {
		return err
	}
	if value, present := fields["auto-cleanup-library-on-full"]; present {
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("images.chatgpt-web.auto-cleanup-library-on-full must be a boolean")
		}
	}
	for _, key := range []string{"bootstrap-timeout-seconds", "bootstrap-retries"} {
		if value, present := fields[key]; present {
			switch value.(type) {
			case int, int64, uint64:
			default:
				return fmt.Errorf("images.chatgpt-web.%s must be an integer", key)
			}
		}
	}
	type plain ChatGPTWebImageConfig
	decoded := plain(*cfg)
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	if err := ChatGPTWebImageConfig(decoded).ValidateBootstrap(); err != nil {
		return err
	}
	*cfg = ChatGPTWebImageConfig(decoded)
	return nil
}
