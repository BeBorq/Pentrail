package store

import "testing"

// P2: ReadRange must report missing bytes instead of silently splicing a gap
// into plausible-looking output. (The exact case from the review: ABC@0, GHI@6,
// requesting 0..9 => 3 missing bytes.)
func TestReadRangeReportsGap(t *testing.T) {
	st := openTemp(t)
	db := st.DB()
	db.Exec(`INSERT OR IGNORE INTO sessions(id, started_at) VALUES(1,1)`)
	db.Exec(`INSERT INTO raw_chunks(session_id,seq,ts,byte_offset,data) VALUES(1,0,1,0,?)`, []byte("ABC"))
	db.Exec(`INSERT INTO raw_chunks(session_id,seq,ts,byte_offset,data) VALUES(1,1,1,6,?)`, []byte("GHI"))

	data, missing, err := st.ReadRange(1, 0, 9)
	if err != nil {
		t.Fatal(err)
	}
	if missing != 3 {
		t.Fatalf("missing = %d, want 3", missing)
	}
	if string(data) != "ABCGHI" {
		t.Fatalf("data = %q", data)
	}
}

// insertEntity writes a derived entity directly, for graph tests.
func insertEntity(t *testing.T, st *Store, typ, value, conf, details, obs string, cmdIndex int64) {
	t.Helper()
	db := st.DB()
	db.Exec(`INSERT OR IGNORE INTO sessions(id, started_at) VALUES(1,1)`)
	db.Exec(`INSERT OR IGNORE INTO commands(session_id, cmd_index, command, complete) VALUES(1,?,?,1)`, cmdIndex, "cmd")
	var cid int64
	db.QueryRow(`SELECT id FROM commands WHERE session_id=1 AND cmd_index=?`, cmdIndex).Scan(&cid)
	if _, err := db.Exec(`INSERT INTO entities(session_id,type,value,confidence,source_command_id,tool,extractor,details,obs_key)
	    VALUES(1,?,?,?,?,?,?,?,?)`, typ, value, conf, cid, "t", "parser:t", nullStr(details), obs); err != nil {
		t.Fatal(err)
	}
}

// P2: edges must form regardless of the order entities are processed. Here a
// port is inserted before its host; the "on" edge must still appear.
func TestGraphEdgesOrderIndependent(t *testing.T) {
	st := openTemp(t)
	// port first, host second
	insertEntity(t, st, "port", "10.0.0.1:22/tcp", "high", `{"host":"10.0.0.1","port":"22","proto":"tcp","service":"ssh"}`, "o1", 0)
	insertEntity(t, st, "host", "10.0.0.1", "high", `{"state":"up"}`, "o2", 0)

	g, err := st.BuildGraph(1)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range g.Edges {
		if e.Source == "port:10.0.0.1:22/tcp" && e.Target == "host:10.0.0.1" && e.Type == "on" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing port->host edge regardless of order; edges=%+v", g.Edges)
	}
}

// P1.5 (graph): two findings with the same name but different targets must be
// two distinct nodes, not merged.
func TestGraphFindingsDistinct(t *testing.T) {
	st := openTemp(t)
	insertEntity(t, st, "finding", "Example RCE", "high", `{"template":"CVE-X","host":"a.test","matched":"http://a.test/x"}`, "f1", 0)
	insertEntity(t, st, "finding", "Example RCE", "high", `{"template":"CVE-X","host":"b.test","matched":"http://b.test/x"}`, "f2", 1)

	g, err := st.BuildGraph(1)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, nd := range g.Nodes {
		if nd.Type == "finding" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("finding nodes: got %d, want 2 (same name, different target must not merge)", n)
	}
}
