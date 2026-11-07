package store

import (
	"bytes"
	"context"
	"testing"
	"time"
)

const oscSecret = "SyntheticOSCSecret"

// Codex audit: ESC]697;<token>;CWD;C:/password=SyntheticOSCSecret BEL LF was
// stored verbatim in raw_chunks and returned by ReadSafeRange.
func TestMarkerArgumentsNotStored(t *testing.T) {
	st := openTemp(t)
	id, err := st.StartSession("cmd.exe", "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	in := []byte("dir\r\n\x1b]697;audit-token;CWD;C:/password=" + oscSecret + "\x07\n\x1b]697;audit-token;FIN;/x/token=FinLeak9\x07ok\r\n")
	// arbitrary read boundaries, as a PTY delivers them
	off := int64(0)
	for i, part := range [][]byte{in[:9], in[9:30], in[30:]} {
		if e := st.WriteRaw(id, int64(i), off, part); e != nil {
			t.Fatal(e)
		}
		off += int64(len(part))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := st.Sync(ctx); e != nil {
		t.Fatal(e)
	}
	stored, missing, err := st.ReadRange(id, 0, int64(len(in)))
	if err != nil || missing != 0 || len(stored) != len(in) {
		t.Fatalf("stored %d/%d missing=%d err=%v", len(stored), len(in), missing, err)
	}
	for _, leak := range []string{oscSecret, "FinLeak9", "audit-token"} {
		if bytes.Contains(stored, []byte(leak)) {
			t.Fatalf("%s written to raw_chunks: %q", leak, stored)
		}
	}
	safe, _, err := st.ReadSafeRange(id, 0, int64(len(in)))
	if err != nil || bytes.Contains(safe, []byte(oscSecret)) {
		t.Fatalf("ReadSafeRange leaked: %q %v", safe, err)
	}
}

// masked-v2 sessions already on disk keep their bytes (no destructive rewrite)
// but every read path applies the current marker rules.
func TestLegacyV2MarkerArgumentsProtectedOnRead(t *testing.T) {
	st := openTemp(t)
	id, err := st.StartSession("bash", "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	legacy := []byte("echo a\r\na\r\n\x1b]697;********;CWD;C:/password=" + oscSecret + "\x07\x1b]697;********;CWD;/home/zażółć\x07prompt$ \r\n")
	db := st.DB()
	if _, e := db.Exec("UPDATE sessions SET privacy_version='masked-v2' WHERE id=?", id); e != nil {
		t.Fatal(e)
	}
	// split the old record across chunks, with the marker crossing a boundary
	cut := bytes.Index(legacy, []byte("password"))
	db.Exec("INSERT INTO raw_chunks(session_id,seq,ts,byte_offset,data) VALUES(?,0,1,0,?)", id, legacy[:cut])
	db.Exec("INSERT INTO raw_chunks(session_id,seq,ts,byte_offset,data) VALUES(?,1,1,?,?)", id, cut, legacy[cut:])
	db.Exec("INSERT INTO commands(session_id,cmd_index,command,out_start_off,out_end_off,complete) VALUES(?,0,'echo a',0,?,1)", id, len(legacy))

	n := int64(len(legacy))
	for _, r := range [][2]int64{{0, n}, {int64(cut), int64(cut) + 5}, {int64(cut) + 9, n}} {
		got, missing, err := st.ReadSafeRange(id, r[0], r[1])
		if err != nil || missing != 0 || int64(len(got)) != r[1]-r[0] {
			t.Fatalf("range %v: len=%d missing=%d err=%v", r, len(got), missing, err)
		}
		if bytes.Contains(got, []byte("Synthetic")) || bytes.Contains(got, []byte("OSCSecret")) {
			t.Fatalf("range %v leaked legacy secret: %q", r, got)
		}
	}
	all, _, _ := st.ReadSafeRange(id, 0, n)
	if !bytes.Contains(all, []byte("/home/zażółć")) || !bytes.Contains(all, []byte("echo a\r\na\r\n")) {
		t.Fatalf("ordinary legacy content damaged: %q", all)
	}
	spans, err := st.ReadSpans(id, 0, n)
	if err != nil {
		t.Fatal(err)
	}
	for _, sp := range spans {
		if bytes.Contains(sp.Data, []byte(oscSecret)) {
			t.Fatalf("ReadSpans leaked: %q", sp.Data)
		}
	}
	// history is not rewritten
	raw, _, _ := st.ReadRange(id, 0, n)
	if !bytes.Equal(raw, legacy) {
		t.Fatal("stored legacy bytes were modified")
	}
	var v string
	db.QueryRow("SELECT privacy_version FROM sessions WHERE id=?", id).Scan(&v)
	if v != "masked-v2" {
		t.Fatalf("legacy version label changed to %q", v)
	}
}
