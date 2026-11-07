package store

import (
	"path/filepath"
	"testing"
)

func TestReviewEntityOffsetAfterRawGap(t *testing.T) {
	st, e := Open(filepath.Join(t.TempDir(), "gap.db"), []byte("synthetic-review-key"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	id, e := st.StartSession("sh", "test", "test")
	if e != nil {
		t.Fatal(e)
	}
	_, e = st.DB().Exec("INSERT INTO commands(session_id,cmd_index,command,out_start_off,out_end_off,complete) VALUES(?,0,'echo',0,27,1)", id)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range []struct {
		seq, off int
		data     string
	}{{0, 0, "hello "}, {2, 16, "10.77.88.99"}} {
		_, e = st.DB().Exec("INSERT INTO raw_chunks(session_id,seq,ts,byte_offset,data) VALUES(?,?,1,?,?)", id, c.seq, c.off, []byte(c.data))
		if e != nil {
			t.Fatal(e)
		}
	}
	_, e = st.ExtractRegex(id)
	if e != nil {
		t.Fatal(e)
	}
	var offset int64
	e = st.DB().QueryRow("SELECT source_offset FROM entities WHERE session_id=? AND value='10.77.88.99'", id).Scan(&offset)
	if e != nil {
		t.Fatal(e)
	}
	if offset != 16 {
		t.Fatalf("entity points to raw offset %d, actual IP starts at 16", offset)
	}
}
