// Package background stores user opt-in settings. It never stores a key.
package background

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type State struct {
	AllowArtifacts bool   `json:"allow_plain_artifacts,omitempty"`
	Enabled        bool   `json:"enabled"`
	Database       string `json:"database"`
	AllowPlain     bool   `json:"allow_plain_development,omitempty"`
}

func Dir() string         { h, _ := os.UserHomeDir(); return filepath.Join(h, ".pentrail") }
func AgentSocket() string { return filepath.Join(Dir(), "run", "key-agent.sock") }
func Load() (State, error) {
	var s State
	b, err := os.ReadFile(filepath.Join(Dir(), "state.json"))
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(b, &s)
	return s, err
}
func Save(s State) error {
	if err := os.MkdirAll(Dir(), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(Dir(), "state-*.json")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(Dir(), "state.json"))
}
