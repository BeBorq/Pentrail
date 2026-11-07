package view

import (
	"github.com/BeBorq/Pentrail/internal/store"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestRawPagingAuthorizationBoundsAndGaps(t *testing.T) {
	st, e := store.Open(filepath.Join(t.TempDir(), "raw.db"), []byte("synthetic-view-key"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	id, e := st.StartSession("cmd.exe", "test", "test")
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range []struct {
		seq, off int
		data     string
	}{{0, 0, "ABC"}, {1, 5, "FG"}} {
		_, e = st.DB().Exec("INSERT INTO raw_chunks(session_id,seq,ts,byte_offset,data) VALUES(?,?,1,?,?)", id, c.seq, c.off, []byte(c.data))
		if e != nil {
			t.Fatal(e)
		}
	}
	s := New(st)
	s.token = "test-token"
	handler := s.guard(s.handleRaw)
	for _, tc := range []struct {
		query               string
		code                int
		body, missing, next string
	}{{"?session=1", 401, "", "", ""}, {"?session=1&t=test-token", 200, "ABCFG", "2", "7"}, {"?session=1&t=test-token&start=5&limit=1", 200, "F", "0", "6"}, {"?session=1&t=test-token&limit=4194305", 400, "", "", ""}, {"?session=1&t=test-token&start=-1", 400, "", "", ""}, {"?session=1&t=test-token&start=9223372036854775807", 400, "", "", ""}} {
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/raw"+tc.query, nil)
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != tc.code {
			t.Fatalf("%s: %d %s", tc.query, w.Code, w.Body.String())
		}
		if tc.code == 200 && (w.Body.String() != tc.body || w.Header().Get("X-Missing-Bytes") != tc.missing || w.Header().Get("X-Next-Offset") != tc.next) {
			t.Fatalf("%s: %q %v", tc.query, w.Body.String(), w.Header())
		}
	}
}

// Command output is plaintext evidence: it must never be stored in the
// browser's disk cache, and must not be MIME-sniffed.
func TestOutputIsNotCached(t *testing.T) {
	st, e := store.Open(filepath.Join(t.TempDir(), "out.db"), []byte("synthetic-view-key"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	id, _ := st.StartSession("bash", "test", "test")
	st.DB().Exec("INSERT INTO raw_chunks(session_id,seq,ts,byte_offset,data) VALUES(?,0,1,0,?)", id, []byte("secret output"))
	s := New(st)
	s.token = "test-token"
	h := s.guard(s.handleOutput)
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/output?session=1&start=0&end=13&t=test-token", nil)
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("code=%d headers=%v", w.Code, w.Header())
	}
	r = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/output?session=1&start=10&end=2&t=test-token", nil)
	w = httptest.NewRecorder()
	h(w, r)
	if w.Code != 400 {
		t.Fatalf("inverted range accepted: %d", w.Code)
	}
}

func TestArtifactStatusAPI(t *testing.T) {
	st, e := store.Open(filepath.Join(t.TempDir(), "art.db"), []byte("synthetic-view-key"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	id, _ := st.StartSession("bash", "test", "test")
	st.DB().Exec(`INSERT INTO command_artifacts(session_id,cmd_index,tool,path,finalized,state,state_detail) VALUES(?,0,'ffuf','/x/f.json',1,'rejected_invalid','invalid document')`, id)
	s := New(st)
	s.token = "test-token"
	w := httptest.NewRecorder()
	s.guard(s.handleArtifacts)(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/artifacts?session=1&t=test-token", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"rejected_invalid"`) || !strings.Contains(w.Body.String(), "invalid document") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
