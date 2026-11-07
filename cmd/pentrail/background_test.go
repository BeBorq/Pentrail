//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BeBorq/Pentrail/internal/background"
)

func TestSetupIsOptInAndIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PENTRAIL_DB", "")
	rc := filepath.Join(home, ".bashrc")
	original := "alias ll='ls -la'\n"
	if err := os.WriteFile(rc, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := cmdSetup([]string{"bash", "--allow-plain"}); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(rc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(b), blockStart) != 1 || !strings.Contains(string(b), original) || !strings.HasPrefix(string(b), "\n"+blockStart) {
		t.Fatal("invalid startup integration")
	}
	s, err := background.Load()
	if err != nil || s.Enabled {
		t.Fatal("setup silently enabled recording", s, err)
	}
	if _, err := os.Stat(filepath.Join(home, ".local/bin/pentrail")); err != nil {
		t.Fatal(err)
	}
	backups, _ := filepath.Glob(rc + ".pentrail-backup-*")
	if len(backups) != 2 {
		t.Fatal("missing rc backups")
	}
}
