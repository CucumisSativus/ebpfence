package daemon

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config represents the JSON configuration file structure
type Config struct {
	Patterns  []string `json:"patterns"`
	Threshold uint32   `json:"threshold"`
	TargetPID uint32   `json:"target_pid,omitempty"`
}

// LoadConfig loads the configuration from a JSON file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if len(config.Patterns) == 0 {
		return nil, fmt.Errorf("config file must contain at least one pattern")
	}

	if config.Threshold == 0 {
		return nil, fmt.Errorf("threshold must be greater than 0")
	}

	return &config, nil
}
