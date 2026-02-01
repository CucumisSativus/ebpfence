package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		wantErr       bool
		wantPatterns  []string
		wantThreshold uint32
		wantTargetPID uint32
	}{
		{
			name:          "valid config with multiple patterns",
			content:       `{"patterns": ["/etc/passwd", "/etc/shadow", "/var/log/*.log"], "threshold": 3}`,
			wantErr:       false,
			wantPatterns:  []string{"/etc/passwd", "/etc/shadow", "/var/log/*.log"},
			wantThreshold: 3,
			wantTargetPID: 0,
		},
		{
			name:          "valid config with single pattern and target PID",
			content:       `{"patterns": ["/etc/passwd"], "threshold": 1, "target_pid": 12345}`,
			wantErr:       false,
			wantPatterns:  []string{"/etc/passwd"},
			wantThreshold: 1,
			wantTargetPID: 12345,
		},
		{
			name:    "empty patterns array",
			content: `{"patterns": [], "threshold": 2}`,
			wantErr: true,
		},
		{
			name:    "missing patterns field",
			content: `{"threshold": 2}`,
			wantErr: true,
		},
		{
			name:    "missing threshold",
			content: `{"patterns": ["/etc/passwd"]}`,
			wantErr: true,
		},
		{
			name:    "zero threshold",
			content: `{"patterns": ["/etc/passwd"], "threshold": 0}`,
			wantErr: true,
		},
		{
			name:    "invalid json",
			content: `{invalid}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.json")
			if err := os.WriteFile(configPath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("failed to write temp config: %v", err)
			}

			config, err := LoadConfig(configPath)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(config.Patterns) != len(tt.wantPatterns) {
				t.Errorf("got %d patterns, want %d", len(config.Patterns), len(tt.wantPatterns))
			}

			for i, p := range config.Patterns {
				if p != tt.wantPatterns[i] {
					t.Errorf("pattern[%d] = %q, want %q", i, p, tt.wantPatterns[i])
				}
			}

			if config.Threshold != tt.wantThreshold {
				t.Errorf("threshold = %d, want %d", config.Threshold, tt.wantThreshold)
			}

			if config.TargetPID != tt.wantTargetPID {
				t.Errorf("target_pid = %d, want %d", config.TargetPID, tt.wantTargetPID)
			}
		})
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
