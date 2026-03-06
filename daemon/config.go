package daemon

import (
	"encoding/json"
	"fmt"
	"os"
)

// BlockStrategy defines what gets blocked when a PID exceeds the violation threshold.
type BlockStrategy string

const (
	// BlockFiles blocks the process from opening any further files (default).
	BlockFiles BlockStrategy = "block_files"
	// BlockNetwork blocks the process from making any socket connections.
	BlockNetwork BlockStrategy = "block_network"
	// BlockBoth blocks both file opens and socket connections.
	BlockBoth BlockStrategy = "block_both"
)

// Config represents the JSON configuration file structure
type Config struct {
	Patterns  []string      `json:"patterns"`
	Threshold uint32        `json:"threshold"`
	TargetPID uint32        `json:"target_pid,omitempty"`
	Strategy  BlockStrategy `json:"strategy,omitempty"`
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

	// Default strategy to block_files for backward compatibility
	if config.Strategy == "" {
		config.Strategy = BlockFiles
	}

	switch config.Strategy {
	case BlockFiles, BlockNetwork, BlockBoth:
		// valid
	default:
		return nil, fmt.Errorf("invalid strategy %q, must be one of: %q, %q, %q",
			config.Strategy, BlockFiles, BlockNetwork, BlockBoth)
	}

	return &config, nil
}
