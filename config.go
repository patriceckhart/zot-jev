package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Config is persisted to config.json next to the extension and edited
// through the /jev panel.
type Config struct {
	// GuardEnabled gates bash/edit/write tool calls through Jev.
	GuardEnabled bool `json:"guard_enabled"`
	// GuardBlockThreshold: block when P(destructive) >= this.
	GuardBlockThreshold float64 `json:"guard_block_threshold"`
	// GuardWarnThreshold: notify (but allow) when P(destructive) >= this.
	GuardWarnThreshold float64 `json:"guard_warn_threshold"`
	// SecretsBlockThreshold: block when P(touches credentials) >= this.
	SecretsBlockThreshold float64 `json:"secrets_block_threshold"`
	// ReviewEnabled runs the final assistant message through Jev.
	ReviewEnabled bool `json:"review_enabled"`
	// ReviewSecretThreshold: redact the message when P(leaks secret) >= this.
	ReviewSecretThreshold float64 `json:"review_secret_threshold"`
	// FailOpen allows tool calls and replies when Jev is unreachable.
	// When false, tool calls are blocked and replies are withheld.
	FailOpen bool `json:"fail_open"`
	// GuardTools lists tool names the guard inspects.
	GuardTools []string `json:"guard_tools"`
}

func defaultConfig() Config {
	return Config{
		GuardEnabled:          true,
		GuardBlockThreshold:   0.70,
		GuardWarnThreshold:    0.40,
		SecretsBlockThreshold: 0.80,
		ReviewEnabled:         true,
		ReviewSecretThreshold: 0.85,
		FailOpen:              true,
		GuardTools:            []string{"bash", "write", "edit"},
	}
}

type configStore struct {
	mu   sync.RWMutex
	path string
	cfg  Config
}

func newConfigStore(dir string) *configStore {
	s := &configStore{path: filepath.Join(dir, "config.json"), cfg: defaultConfig()}
	s.load()
	return s
}

func (s *configStore) load() {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	cfg := defaultConfig()
	if json.Unmarshal(data, &cfg) != nil {
		return
	}
	if len(cfg.GuardTools) == 0 {
		cfg.GuardTools = defaultConfig().GuardTools
	}
	s.cfg = cfg
}

func (s *configStore) save() {
	s.mu.RLock()
	data, _ := json.MarshalIndent(s.cfg, "", "  ")
	s.mu.RUnlock()
	_ = os.WriteFile(s.path, data, 0o644)
}

func (s *configStore) get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg
	c.GuardTools = append([]string(nil), s.cfg.GuardTools...)
	return c
}

func (s *configStore) update(fn func(*Config)) {
	s.mu.Lock()
	fn(&s.cfg)
	s.mu.Unlock()
	s.save()
}

func (c Config) guards(tool string) bool {
	for _, t := range c.GuardTools {
		if t == tool {
			return true
		}
	}
	return false
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
