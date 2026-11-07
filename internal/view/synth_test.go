package view

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/store"
)

// Synthetic databases for the viewer tests and the preview (Codex 04J):
// invented commands, changes and artifact rows only — no real targets, no
// real secrets; every database has a fixed synthetic key.

const synthKey = "synthetic-view-key"

type synthArtifact struct {
	cmd                 int
	tool, path, state   string
	finalized, ingested int
	partial             int
	detail              string
}

// synthDB opens (creating if needed) a synthetic database at path. If it is
// new it gets one session (id 1) with: commands, cleanup changes
// (same session/command/category in every synthetic database: exactly the
// case where checklist ticks must not leak between databases) and the
// given artifact rows.
func synthDB(t testing.TB, path string, arts []synthArtifact) *store.Store {
	t.Helper()
	st, err := store.Open(path, []byte(synthKey))
	if err != nil {
		t.Fatal(err)
	}
	ss, err := st.ListSessions()
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if len(ss) > 0 {
		return st
	}
	addSynthSession(t, st, arts)
	return st
}

// addSynthSession adds one synthetic session (see synthDB).
func addSynthSession(t testing.TB, st *store.Store, arts []synthArtifact) {
	t.Helper()
	id, err := st.StartSession("cmd.exe", "synthetic-host", "test")
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	now := time.Now().UnixNano()
	db := st.DB()
	exec := func(q string, args ...any) {
		if _, err := db.Exec(q, args...); err != nil {
			st.Close()
			t.Fatalf("%s: %v", q, err)
		}
	}
	out := "synthetic output\r\n"
	exec(`INSERT INTO raw_chunks(session_id,seq,ts,byte_offset,data) VALUES(?,0,?,0,?)`, id, now, []byte(out+out+out))
	cmds := []string{"net user synth_user /add", "schtasks /create /tn synth_task /tr x.exe", "nmap -oX scan.xml 192.0.2.10"}
	for i, c := range cmds {
		exec(`INSERT INTO commands(session_id,cmd_index,command,cwd,started_at,ended_at,exit_code,out_start_off,out_end_off,complete) VALUES(?,?,?,?,?,?,0,?,?,1)`,
			id, i, c, `C:\synthetic`, now+int64(i)*1e9, now+int64(i)*1e9+5e8, i*len(out), (i+1)*len(out))
	}
	for _, ch := range []struct {
		cmd       int
		cat, desc string
	}{{0, "account", "account created: synth_user"}, {1, "service", "scheduled task: synth_task"}} {
		exec(`INSERT INTO changes(session_id,cmd_index,command,cwd,category,description,detected_at,source_offset) VALUES(?,?,?,?,?,?,?,?)`,
			id, ch.cmd, cmds[ch.cmd], `C:\synthetic`, ch.cat, ch.desc, now, ch.cmd*len(out))
	}
	for _, a := range arts {
		exec(`INSERT INTO command_artifacts(session_id,cmd_index,tool,path,created_at,finalized,ingested,state,state_detail,partial) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			id, a.cmd, a.tool, a.path, now, a.finalized, a.ingested, a.state, a.detail, a.partial)
	}
}

// previewDB: the preview's database A — sessions 1..5, see TestSyntheticPreview.
func previewDB(t testing.TB, path string) *store.Store {
	t.Helper()
	mixed := []synthArtifact{
		{cmd: 2, tool: "nmap", path: `C:\synthetic\scan-a.xml`, state: "imported", finalized: 1, ingested: 1},
		{cmd: 2, tool: "Nuclei", path: `C:\synthetic\findings.jsonl`, state: "imported", finalized: 1, ingested: 1},
		{cmd: 2, tool: "ffuf", path: `C:\synthetic\ffuf.json`, finalized: 0},               // the tool still runs
		{cmd: 2, tool: "NMAP", path: `C:\synthetic\scan-b.xml`, finalized: 1, ingested: 0}, // waits for import
		{cmd: 2, tool: "nmap", path: `C:\synthetic\scan-c.xml`, state: "imported_partial", finalized: 1, ingested: 1, partial: 1, detail: "file truncated (synthetic)"},
	}
	complete := []synthArtifact{
		{cmd: 2, tool: "nmap", path: `C:\synthetic\scan.xml`, state: "imported", finalized: 1, ingested: 1},
		{cmd: 2, tool: "nuclei", path: `C:\synthetic\n.jsonl`, state: "imported", finalized: 1, ingested: 1},
	}
	st := synthDB(t, path, mixed)
	ss, err := st.ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	for len(ss) < 5 {
		addSynthSession(t, st, complete) // 2: all complete; 3, 4, 5: the list the faults stand in front of
		if ss, err = st.ListSessions(); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

// serveSynth serves st with the real viewer routes (Server.handler) on a
// loopback httptest server with a fixed test token.
func serveSynth(t testing.TB, st *store.Store, token string) *httptest.Server {
	t.Helper()
	s := New(st)
	s.token = token
	ts := httptest.NewServer(s.handler())
	t.Cleanup(ts.Close)
	return ts
}

func serveHandler(t testing.TB, h http.Handler) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

func synthPath(dir, name string) string { return filepath.Join(dir, name) }
