package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Codex 04E: where does a durable capture write spend its time? Runs on any
// OS; meaningful with -tags sqlcipher (the production build). Production
// settings only, except the clearly labelled diagnostic variants at the end
// (never used by the program). Synthetic data in this test's TempDir.
//
//	PENTRAIL_STORE_PROFILE=300 go test -tags sqlcipher -run TestStoreCommitProfile -v ./internal/store
//
// Without the variable a short run (20 writes) checks the instrumentation.
func TestStoreCommitProfile(t *testing.T) {
	n := 20
	if v, err := strconv.Atoi(os.Getenv("PENTRAIL_STORE_PROFILE")); err == nil && v > 0 {
		n = v
	}
	dir := t.TempDir()
	// ConPTY-like output: rows of 120 characters with CRLF
	row := strings.Repeat("abcdefghij", 12) + "\r\n"
	payload := func(size int) []byte {
		var b []byte
		for len(b) < size {
			b = append(b, row...)
		}
		return b[:size]
	}

	// 1) plain file write + fsync in the same folder: the disk's flush cost
	f, err := os.Create(filepath.Join(dir, "fsync.bin"))
	if err != nil {
		t.Fatal(err)
	}
	var fs time.Duration
	for i := 0; i < n; i++ {
		t0 := time.Now()
		f.Write(payload(4096))
		f.Sync()
		fs += time.Since(t0)
	}
	f.Close()
	t.Logf("STORE_PROFILE file write+fsync 4KiB: avg %v over %d", (fs / time.Duration(n)).Round(time.Microsecond), n)

	// 2) open (key derivation, schema) of a new database and a reopen
	db := filepath.Join(dir, "profile.db")
	t0 := time.Now()
	st, err := Open(db, []byte("synthetic-profile-key"))
	if err != nil {
		t.Fatal(err)
	}
	openNew := time.Since(t0)
	st.Close()
	t0 = time.Now()
	st, err = Open(db, []byte("synthetic-profile-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	t.Logf("STORE_PROFILE open new %v, reopen %v, encrypted=%v", openNew.Round(time.Millisecond), time.Since(t0).Round(time.Millisecond), Encrypted())

	// 3) the production write path, per chunk size
	id, err := st.StartSession("cmd.exe", "profile", "test")
	if err != nil {
		t.Fatal(err)
	}
	var off, seq int64
	run := func(label string, size int) {
		var prof []CommitProfile
		SetCommitProfileHook(func(p CommitProfile) { prof = append(prof, p) })
		defer SetCommitProfileHook(nil)
		t0 := time.Now()
		for i := 0; i < n; i++ {
			b := payload(size)
			if err := st.WriteRaw(id, seq, off, b); err != nil {
				t.Fatal(err)
			}
			seq++
			off += int64(len(b))
		}
		total := time.Since(t0)
		if !Encrypted() {
			t.Logf("STORE_PROFILE %s: %d writes of %d B in %v (plain build: asynchronous, no per-write commit)", label, n, size, total.Round(time.Millisecond))
			return
		}
		var sum, mx [6]time.Duration
		retries := 0
		for _, p := range prof {
			retries += p.Retries
			for i, d := range p.Stage {
				sum[i] += d
				mx[i] = max(mx[i], d)
			}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "STORE_PROFILE %s: %d writes of %d B in %v (avg %v/write, %.2f MiB/s), retries %d;", label, n, size,
			total.Round(time.Millisecond), (total / time.Duration(n)).Round(time.Microsecond), float64(n*size)/(1<<20)/total.Seconds(), retries)
		for i, name := range CommitStages {
			fmt.Fprintf(&b, " %s avg %v max %v;", name, (sum[i] / time.Duration(max(1, len(prof)))).Round(time.Microsecond), mx[i].Round(time.Microsecond))
		}
		t.Log(b.String())
		if len(prof) != n {
			t.Fatalf("%d profiles for %d writes", len(prof), n)
		}
	}
	run("production 4KiB", 4096)
	run("production 64KiB", 64<<10)
	if !Encrypted() {
		return
	}
	// 4) DIAGNOSTIC ONLY (never the program's settings): which SQLCipher
	// feature costs what. secure_delete and memory security stay ON in
	// production.
	if _, err := st.db.Exec("PRAGMA secure_delete=OFF"); err == nil {
		run("diagnostic secure_delete=OFF 4KiB", 4096)
		st.db.Exec("PRAGMA secure_delete=ON")
	}
	if _, err := st.db.Exec("PRAGMA cipher_memory_security=OFF"); err == nil {
		run("diagnostic cipher_memory_security=OFF 4KiB", 4096)
	}
}
