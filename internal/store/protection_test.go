package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecognizedSecretsNeverEnterRawOrCommandRows(t *testing.T) {
	dir := t.TempDir()
	st, e := Open(filepath.Join(dir, "data.db"), []byte("synthetic-test-key"))
	if e != nil {
		t.Fatal(e)
	}
	id, e := st.StartSession("sh", "test", "test")
	if e != nil {
		t.Fatal(e)
	}
	command := "tool --password rawHunter"
	raw := "PASSWORD=rawHunter\nAuthorization: Bearer rawBearer\n\x1b]697;test;CMD;" + base64.StdEncoding.EncodeToString([]byte(command)) + "\a\n"
	for i := range []byte(raw) {
		st.WriteRaw(id, int64(i), int64(i), []byte{raw[i]})
	}
	st.WriteCommand(Command{SessionID: id, Index: 0, Command: command})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if e = st.Sync(ctx); e != nil {
		t.Fatal(e)
	}
	rows, e := st.DB().Query("SELECT data FROM raw_chunks WHERE session_id=? ORDER BY byte_offset", id)
	if e != nil {
		t.Fatal(e)
	}
	var stored bytes.Buffer
	for rows.Next() {
		var b []byte
		rows.Scan(&b)
		stored.Write(b)
	}
	rows.Close()
	if stored.Len() != len(raw) || bytes.Contains(stored.Bytes(), []byte("rawHunter")) || bytes.Contains(stored.Bytes(), []byte("rawBearer")) || bytes.Contains(stored.Bytes(), []byte(base64.StdEncoding.EncodeToString([]byte(command)))) {
		t.Fatalf("secret in DB: %q", stored.String())
	}
	var saved string
	if e = st.DB().QueryRow("SELECT command FROM commands WHERE session_id=?", id).Scan(&saved); e != nil || strings.Contains(saved, "rawHunter") {
		t.Fatal(saved, e)
	}
	var changed int64
	st.DB().QueryRow("SELECT sum(redacted_bytes) FROM raw_chunks WHERE session_id=?", id).Scan(&changed)
	if changed == 0 {
		t.Fatal("no masking audit counter")
	}
	st.Close()
}
func TestLegacyRangeCannotRevealQuotedURLOrPEMContinuation(t *testing.T) {
	for _, raw := range []string{"{\"password\":\"hiddenLegacy\"}\n", "https://user:hiddenLegacy@host/\n", "-----BEGIN PRIVATE KEY-----\nAAAAhiddenLegacyBBBB\n-----END PRIVATE KEY-----\n"} {
		st, e := Open(filepath.Join(t.TempDir(), "old.db"), []byte("legacy-key"))
		if e != nil {
			t.Fatal(e)
		}
		id, _ := st.StartSession("sh", "test", "test")
		st.DB().Exec("UPDATE sessions SET privacy_version='' WHERE id=?", id)
		mid := strings.Index(raw, "hiddenLegacy") + 4
		for i := 0; i < len(raw); i += 3 {
			end := min(i+3, len(raw))
			st.DB().Exec("INSERT INTO raw_chunks(session_id,seq,ts,byte_offset,data) VALUES(?,?,1,?,?)", id, i, i, []byte(raw[i:end]))
		}
		b, missing, e := st.ReadSafeRange(id, int64(mid), int64(mid+3))
		if e != nil || missing != 0 || bytes.ContainsAny(b, "denLegacy") {
			t.Fatalf("legacy leaked from %q: %q missing=%d err=%v", raw, b, missing, e)
		}
		if len(b) != 3 {
			t.Fatal(len(b))
		}
		st.Close()
	}
}
func TestPrivacyBoundaryAndPartialTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boundary.db")
	st, e := Open(path, []byte("key"))
	if e != nil {
		t.Fatal(e)
	}
	id, _ := st.StartSession("sh", "test", "test")
	prefix := "PASSWORD=first"
	st.WriteRaw(id, 0, 0, []byte(prefix))
	st.MaskPendingRaw(id)
	st.WriteRaw(id, 1, int64(len(prefix)), []byte("second\npublic\n"))
	if e = st.FinishSession(id); e != nil {
		t.Fatal(e)
	}
	st, e = Open(path, []byte("key"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	b, missing, e := st.ReadRange(id, 0, int64(len(prefix)+len("second\npublic\n")))
	if e != nil || missing != 0 || bytes.Contains(b, []byte("first")) || bytes.Contains(b, []byte("second")) || !bytes.Contains(b, []byte("public")) {
		t.Fatal(string(b), missing, e)
	}
}

func TestPausedContextDoesNotMaskResumedPublicOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pause.db")
	st, e := Open(path, []byte("key"))
	if e != nil {
		t.Fatal(e)
	}
	id, _ := st.StartSession("cmd.exe", "test", "test")
	st.WriteRaw(id, 0, 0, []byte("PASSWORD=hidden\n"))
	st.PauseCapture(id)
	st.ObservePaused(id, []byte("PRIVATE_OUTPUT\nnormal prompt> "))
	st.ResumeCapture(id)
	st.WriteRaw(id, 1, int64(len("PASSWORD=hidden\n")), []byte("RESUMED_PUBLIC\n"))
	st.FinishSession(id)
	st, e = Open(path, []byte("key"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	b, _, e := st.ReadRange(id, 0, int64(len("PASSWORD=hidden\nRESUMED_PUBLIC\n")))
	if e != nil || !bytes.Contains(b, []byte("RESUMED_PUBLIC")) || bytes.Contains(b, []byte("PRIVATE_OUTPUT")) || bytes.Contains(b, []byte("hidden")) {
		t.Fatal(string(b), e)
	}
}

func TestArtifactContentIsMaskedBeforeStorage(t *testing.T) {
	dir := t.TempDir()
	st, e := Open(filepath.Join(dir, "art.db"), []byte("key"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	id, _ := st.StartSession("sh", "test", "test")
	path := filepath.Join(dir, "tool.json")
	os.WriteFile(path, []byte(`{"password":"artifactSecret","results":[]}`), 0600)
	_, e = st.DB().Exec("INSERT INTO command_artifacts(session_id,cmd_index,tool,path,finalized) VALUES(?,0,'ffuf',?,1)", id, path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = st.IngestArtifacts(id); e != nil {
		t.Fatal(e)
	}
	var content []byte
	if e = st.DB().QueryRow("SELECT content FROM command_artifacts WHERE session_id=?", id).Scan(&content); e != nil || bytes.Contains(content, []byte("artifactSecret")) {
		t.Fatal(string(content), e)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("plaintext artifact not removed")
	}
}

func TestIdlePromptAndMetadataPreserveFirstOutputLine(t *testing.T) {
	dir := t.TempDir()
	st, e := Open(filepath.Join(dir, "idle.db"), []byte("test-key"))
	if e != nil {
		t.Fatal(e)
	}
	id, _ := st.StartSession("bash", "test", "test")
	st.WriteRaw(id, 0, 0, []byte("prompt> "))
	time.Sleep(400 * time.Millisecond)
	st.WriteRaw(id, 1, 0, []byte("command\r\n\x1b]697;abc123;C\a"))
	time.Sleep(400 * time.Millisecond)
	st.WriteRaw(id, 2, 0, []byte("PUBLIC_FIRST\nPASSWORD=split"))
	time.Sleep(400 * time.Millisecond)
	st.WriteRaw(id, 3, 0, []byte("Secret\n"))
	if e = st.FinishSession(id); e != nil {
		t.Fatal(e)
	}
	st, e = Open(filepath.Join(dir, "idle.db"), []byte("test-key"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	raw, _, e := st.ReadRange(id, 0, 1000)
	if e != nil || !bytes.Contains(raw, []byte("PUBLIC_FIRST")) || bytes.Contains(raw, []byte("splitSecret")) {
		t.Fatal(string(raw), e)
	}
}

func TestLegacyV1WrappedSecretUsesUpdatedProtection(t *testing.T) {
	st := openTemp(t)
	id, e := st.StartSession("cmd.exe", "test", "0.4")
	if e != nil {
		t.Fatal(e)
	}
	raw := []byte("PASSWORD\r\n\x1b[29;120HD='LegacyWrappedSecret'\r\nPUBLIC\n")
	if _, e = st.DB().Exec("UPDATE sessions SET privacy_version='masked-v1' WHERE id=?", id); e != nil {
		t.Fatal(e)
	}
	if _, e = st.DB().Exec("INSERT INTO raw_chunks(session_id,seq,byte_offset,ts,data) VALUES(?,0,0,0,?)", id, raw); e != nil {
		t.Fatal(e)
	}
	safe, missing, e := st.ReadSafeRange(id, 0, int64(len(raw)))
	if e != nil || missing != 0 || bytes.Contains(safe, []byte("LegacyWrappedSecret")) || !bytes.Contains(safe, []byte("PUBLIC")) {
		t.Fatalf("unsafe old output %q %d %v", safe, missing, e)
	}
	spans, e := st.ReadSpans(id, 0, int64(len(raw)))
	if e != nil {
		t.Fatal(e)
	}
	for _, span := range spans {
		if bytes.Contains(span.Data, []byte("LegacyWrappedSecret")) {
			t.Fatal("unsafe old extraction span")
		}
	}
}
