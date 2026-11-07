//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

func TestWindowsSetupPreservesUTF16ProfileAndBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profil.ps1")
	original := "$global:Polish = 'żółć'\r\n"
	u := utf16.Encode([]rune(original))
	b := []byte{255, 254}
	for _, v := range u {
		b = binary.LittleEndian.AppendUint16(b, v)
	}
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if e := setupPSProfile(path, `C:\Users\test name\pentrail.exe`, `C:\Windows\powershell.exe`, true); e != nil {
			t.Fatal(e)
		}
	}
	after, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.HasPrefix(after, []byte{239, 187, 191}) || !bytes.Contains(after, []byte(original)) || bytes.Count(after, []byte(blockStart)) != 1 {
		t.Fatal("profile changed or block duplicated")
	}
	backups, _ := filepath.Glob(path + ".pentrail-backup-*")
	if len(backups) != 2 {
		t.Fatal("missing backups")
	}
	first, _ := os.ReadFile(backups[0])
	if !bytes.Equal(first, b) {
		t.Fatal("original UTF-16 backup changed")
	}
}

func TestWindowsProfileLocationQuery(t *testing.T) {
	for _, name := range []string{"powershell.exe", "pwsh.exe"} {
		shell, e := exec.LookPath(name)
		if e != nil {
			t.Skipf("%s unavailable", name)
		}
		path, e := queryPSProfile(shell)
		if e != nil || !utf8.ValidString(path) || !strings.HasSuffix(strings.ToLower(path), "profile.ps1") {
			t.Fatalf("%s profile %q: %v", name, path, e)
		}
	}
}
