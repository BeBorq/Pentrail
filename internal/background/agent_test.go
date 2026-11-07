//go:build linux

package background

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKeyAgentMemoryAndStop(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := os.MkdirAll(filepath.Dir(AgentSocket()), 0700); err != nil {
		t.Fatal(err)
	}
	key := []byte("synthetic-key-never-in-state")
	done := make(chan error, 1)
	go func() { done <- ServeAgent(AgentSocket(), key) }()
	defer func() { _, _ = AgentRequest('L') }()
	until := time.Now().Add(time.Second)
	for !AgentReady() {
		if time.Now().After(until) {
			t.Fatal("agent did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	b, err := AgentRequest('K')
	if err != nil || !bytes.Equal(b, key) {
		t.Fatalf("get key: %q %v", b, err)
	}
	if err := Save(State{Enabled: true, Database: "/tmp/test.db"}); err != nil {
		t.Fatal(err)
	}
	state, err := os.ReadFile(filepath.Join(Dir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(state, key) {
		t.Fatal("state contains passphrase")
	}
	if _, err := AgentRequest('L'); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("agent did not stop")
	}
	for _, b := range key {
		if b != 0 {
			t.Fatal("agent did not clear owned key")
		}
	}
}

func TestDisabledStateIsPersistent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := Save(State{Enabled: true, Database: "/tmp/synthetic.db"}); err != nil {
		t.Fatal(err)
	}
	s, err := Load()
	if err != nil || !s.Enabled {
		t.Fatal(s, err)
	}
	s.Enabled = false
	if err = Save(s); err != nil {
		t.Fatal(err)
	}
	s, err = Load()
	if err != nil || s.Enabled {
		t.Fatal(s, err)
	}
}
