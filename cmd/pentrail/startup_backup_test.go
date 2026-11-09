package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// freezeBackupClock makes every backup in the test get the same timestamp, as
// a coarse wall clock does for two setups in quick succession.
func freezeBackupClock(t *testing.T) {
	t.Helper()
	old := backupNow
	at := time.Unix(1_700_000_000, 123_456_789)
	backupNow = func() time.Time { return at }
	t.Cleanup(func() { backupNow = old })
}

func TestStartupBackupNeverReplacesAnExistingBackup(t *testing.T) {
	freezeBackupClock(t)
	path := filepath.Join(t.TempDir(), "profile")
	taken := path + ".pentrail-backup-1700000000123456789"
	if err := os.WriteFile(taken, []byte("earlier backup"), 0600); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{taken: "earlier backup"}
	for _, data := range []string{"first", "second", ""} {
		name, err := writeStartupBackup(path, []byte(data))
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := want[name]; dup {
			t.Fatalf("backup name %s reused", name)
		}
		want[name] = data
	}
	got, _ := filepath.Glob(path + ".pentrail-backup-*")
	if len(got) != len(want) {
		t.Fatalf("backups %v, want %d", got, len(want))
	}
	for name, data := range want {
		b, err := os.ReadFile(name)
		if err != nil || string(b) != data {
			t.Fatalf("%s: %q %v, want %q", name, b, err, data)
		}
		if runtime.GOOS != "windows" {
			if fi, err := os.Stat(name); err != nil || fi.Mode().Perm() != 0600 {
				t.Fatalf("%s mode %v %v", name, fi.Mode(), err)
			}
		}
	}
}

func TestStartupBackupReportsAnUnwritableDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "profile")
	if _, err := writeStartupBackup(path, []byte("x")); err == nil {
		t.Fatal("a backup into a missing directory reported success")
	}
}
