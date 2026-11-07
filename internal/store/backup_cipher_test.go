//go:build sqlcipher

package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEncryptedBackupIncludesWALAndRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "live.db")
	key := []byte("synthetic-backup-key")
	st, e := Open(source, key)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	id, _ := st.StartSession("sh", "test", "test")
	st.WriteRaw(id, 0, 0, []byte("PUBLIC_MARKER\nPASSWORD=backupHidden\n"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if e = st.Sync(ctx); e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(dir, "snap.db")
	digest, e := BackupFile(source, dest, key)
	if e != nil {
		t.Fatal(e)
	}
	if len(digest) != 64 {
		t.Fatal(digest)
	}
	disk, _ := os.ReadFile(dest)
	if bytes.HasPrefix(disk, []byte("SQLite format")) || bytes.Contains(disk, []byte("PUBLIC_MARKER")) {
		t.Fatal("plaintext backup")
	}
	if e = VerifyFile(dest, []byte("wrong")); e == nil {
		t.Fatal("wrong key accepted")
	}
	copy, e := Open(dest, key)
	if e != nil {
		t.Fatal(e)
	}
	data, missing, e := copy.ReadRange(id, 0, int64(len("PUBLIC_MARKER\nPASSWORD=backupHidden\n")))
	copy.Close()
	if e != nil || missing != 0 || !bytes.Contains(data, []byte("PUBLIC_MARKER")) || bytes.Contains(data, []byte("backupHidden")) {
		t.Fatal(string(data), missing, e)
	}
	before, _ := os.ReadFile(dest)
	if _, e = BackupFile(source, dest, key); e == nil {
		t.Fatal("overwrite accepted")
	}
	after, _ := os.ReadFile(dest)
	if !bytes.Equal(before, after) {
		t.Fatal("existing backup modified")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".pentrail-private-*")); len(leftovers) != 0 {
		t.Fatal(leftovers)
	}
}

func TestQuotedPassphraseIsLiteralAndNotSQL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quotes.db")
	key := []byte(`quote"; PRAGMA user_version=12345; --'żółć`)
	st, e := Open(path, key)
	if e != nil {
		t.Fatal(e)
	}
	var version int
	if e = st.DB().QueryRow("PRAGMA user_version").Scan(&version); e != nil || version != 0 {
		t.Fatal("key interpreted as SQL", version, e)
	}
	st.Close()
	if e = VerifyFile(path, key); e != nil {
		t.Fatal(e)
	}
	if e = VerifyFile(path, []byte("quote")); e == nil {
		t.Fatal("key was truncated")
	}
	if _, e = Open(filepath.Join(t.TempDir(), "nul.db"), []byte("valid\x00truncated")); e == nil {
		t.Fatal("NUL accepted")
	}
}
