//go:build sqlcipher

package store

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const crashKey = "synthetic-crash-only-key"
const crashPrefix = "PUBLIC żółć 日本語\n"
const crashPending = "PASSWORD=NeverExposeCrashSecret"

func TestRecoveryCrashChild(t *testing.T) {
	path := os.Getenv("PENTRAIL_CRASH_CHILD_DB")
	if path == "" {
		t.Skip("subprocess helper")
	}
	st, err := Open(path, []byte(crashKey))
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.StartSession("test", "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	st.WriteCommand(Command{SessionID: id, Index: 0, Command: "synthetic command żółć", StartedAt: 1, ExitCode: -1})
	if err = st.WriteRaw(id, 0, 0, []byte(crashPrefix+crashPending)); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".ready", []byte(fmt.Sprint(id)), 0600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestRecoveryAfterForcedProcessKill(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crash.db")
	child := exec.Command(os.Args[0], "-test.run=^TestRecoveryCrashChild$", "-test.v")
	child.Env = append(os.Environ(), "PENTRAIL_CRASH_CHILD_DB="+path)
	var log bytes.Buffer
	child.Stdout = &log
	child.Stderr = &log
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	deadline := time.Now().Add(40 * time.Second)
	for {
		if _, err := os.Stat(path + ".ready"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not commit checkpoint")
		}
		time.Sleep(20 * time.Millisecond)
	}
	active, err := Open(path, []byte(crashKey))
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err = active.DB().QueryRow("SELECT count(*) FROM capture_checkpoints").Scan(&n); err != nil || n != 1 {
		t.Fatal("active checkpoint", n, err)
	}
	if err = active.DB().QueryRow("SELECT count(*) FROM capture_recoveries").Scan(&n); err != nil || n != 0 {
		t.Fatal("recovered a living owner", n, err)
	}
	raw, missing, err := active.ReadRange(1, 0, int64(len(crashPrefix)))
	if err != nil || missing != 0 || string(raw) != crashPrefix {
		t.Fatal("ready bytes not committed", string(raw), missing, err)
	}
	active.Close()
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	st, err := Open(path, []byte(crashKey))
	if err != nil {
		t.Fatal(err)
	}
	expected := crashPrefix + "PASSWORD=" + string(bytes.Repeat([]byte("*"), len("NeverExposeCrashSecret")))
	raw, missing, err = st.ReadRange(1, 0, int64(len(expected)))
	if err != nil || missing != 0 || string(raw) != expected {
		t.Fatalf("recovery mismatch %q missing=%d err=%v", raw, missing, err)
	}
	if err = st.DB().QueryRow("SELECT count(*) FROM capture_checkpoints").Scan(&n); err != nil || n != 0 {
		t.Fatal("checkpoint retained", n, err)
	}
	if err = st.DB().QueryRow("SELECT count(*) FROM capture_recoveries").Scan(&n); err != nil || n != 1 {
		t.Fatal("recovery audit", n, err)
	}
	cmds, err := st.ListCommands(1)
	if err != nil || len(cmds) != 1 || cmds[0].Command != "synthetic command żółć" || cmds[0].OutEndOff != int64(len(expected)) || cmds[0].Complete {
		t.Fatal("running command recovery", cmds, err)
	}
	st.Close()
	st, err = Open(path, []byte(crashKey))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	raw, missing, err = st.ReadRange(1, 0, int64(len(expected)))
	if err != nil || missing != 0 || string(raw) != expected {
		t.Fatal("recovery duplicated or lost data")
	}
	if err = st.DB().QueryRow("SELECT count(*) FROM capture_recoveries").Scan(&n); err != nil || n != 1 {
		t.Fatal("recovery not idempotent", n, err)
	}
	t.Logf("FORCED_KILL recovered_bytes=%d exact_unicode=PASS secret_masking=PASS command_saved=PASS active_owner_isolation=PASS idempotence=PASS missing=0", len(raw))
}

func TestCheckpointTransactionRollbackAndPause(t *testing.T) {
	st := openTemp(t)
	id, err := st.StartSession("test", "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err = st.WriteRaw(id, 0, 0, []byte("PUBLIC\n")); err != nil {
		t.Fatal(err)
	}
	if err = st.PauseCapture(id); err != nil {
		t.Fatal(err)
	}
	st.ObservePaused(id, []byte("PAUSED_PRIVATE_BYTES"))
	st.ResumeCapture(id)
	if err = st.WriteRaw(id, 1, 7, []byte("RESUMED\n")); err != nil {
		t.Fatal(err)
	}
	var state []byte
	if err = st.DB().QueryRow("SELECT state FROM capture_checkpoints WHERE session_id=?", id).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(state, []byte("PAUSED_PRIVATE_BYTES")) || bytes.Contains(state, []byte("UEFVU0VEX1BSSVZBVEVfQllURVM=")) {
		t.Fatal("paused data entered checkpoint")
	}
	if _, err = st.DB().Exec("CREATE TRIGGER fail_checkpoint BEFORE INSERT ON capture_checkpoints BEGIN SELECT RAISE(ABORT,'injected checkpoint failure'); END"); err != nil {
		t.Fatal(err)
	}
	if err = st.WriteRaw(id, 2, 15, []byte("MUST_ROLL_BACK\n")); err == nil {
		t.Fatal("checkpoint failure ignored")
	}
	var n int
	if err = st.DB().QueryRow("SELECT count(*) FROM raw_chunks WHERE CAST(data AS TEXT) LIKE '%MUST_ROLL_BACK%'").Scan(&n); err != nil || n != 0 {
		t.Fatal("raw committed without checkpoint", n, err)
	}
	t.Log("CHECKPOINT rollback=PASS pause_exclusion=PASS errors_propagated=PASS")
}

func TestBackupExcludesOriginalCheckpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "live.db")
	key := []byte(crashKey)
	st, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, err := st.StartSession("test", "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err = st.WriteRaw(id, 0, 0, []byte(crashPrefix+crashPending)); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "backup.db")
	if _, err = BackupFile(path, dest, key); err != nil {
		t.Fatal(err)
	}
	backup, err := Open(dest, key)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	var n int
	if err = backup.DB().QueryRow("SELECT count(*) FROM capture_checkpoints").Scan(&n); err != nil || n != 0 {
		t.Fatal("original checkpoint exported", n, err)
	}
	if err = st.DB().QueryRow("SELECT count(*) FROM capture_checkpoints").Scan(&n); err != nil || n != 1 {
		t.Fatal("source checkpoint modified", n, err)
	}
	data, missing, err := backup.ReadRange(id, 0, int64(len(crashPrefix+crashPending)))
	if err != nil || missing != 0 || !bytes.HasPrefix(data, []byte(crashPrefix)) || bytes.Contains(data, []byte("NeverExposeCrashSecret")) {
		t.Fatal("backup pending bytes not safely materialized", string(data), missing, err)
	}
	t.Log("BACKUP original_checkpoint_excluded=PASS source_untouched=PASS")
}
