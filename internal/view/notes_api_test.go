package view

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/BeBorq/Pentrail/internal/store"
)

// The notes API on the real viewer routes over a synthetic database: reads
// are token-guarded; every change needs POST/PUT, an exact same-origin Origin,
// JSON, the write token and a bounded body. No CORS. Notes never change what
// the evidence endpoints return.
func TestNotesAPISecurityAndBehaviour(t *testing.T) {
	st := synthDB(t, synthPath(t.TempDir(), "notes.db"), nil)
	defer st.Close()
	ss, err := st.ListSessions()
	if err != nil || len(ss) == 0 {
		t.Fatal(err)
	}
	sid := ss[0].ID
	other, err := st.StartSession("bash", "synthetic-host", "test")
	if err != nil {
		t.Fatal(err)
	}
	const tok = "synthetic-notes-token"
	srv := serveSynth(t, st, tok)
	client := &http.Client{}
	type resp struct {
		code int
		body []byte
		h    http.Header
	}
	do := func(method, path string, body []byte, hdr map[string]string) resp {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get("Access-Control-Allow-Origin") != "" || r.Header.Get("Access-Control-Allow-Credentials") != "" {
			t.Fatalf("%s %s sent CORS headers", method, path)
		}
		return resp{r.StatusCode, b, r.Header}
	}
	auth := map[string]string{"Cookie": "pt=" + tok}
	with := func(base map[string]string, kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			if kv[i+1] == "" {
				delete(m, kv[i])
			} else {
				m[kv[i]] = kv[i+1]
			}
		}
		return m
	}

	// token endpoint
	if r := do("GET", "/api/notes/token", nil, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("token without the session token: %d", r.code)
	}
	r := do("GET", "/api/notes/token", nil, auth)
	var wt struct {
		WriteToken string `json:"write_token"`
	}
	if r.code != 200 || json.Unmarshal(r.body, &wt) != nil || len(wt.WriteToken) != 64 || r.h.Get("Cache-Control") != "no-store" {
		t.Fatalf("token: %d %s %v", r.code, r.body, r.h)
	}
	if strings.Contains(wt.WriteToken, tok) {
		t.Fatal("the write token contains the session token")
	}
	if r := do("POST", "/api/notes/token", nil, auth); r.code != http.StatusMethodNotAllowed {
		t.Fatalf("POST token: %d", r.code)
	}
	write := with(auth, "Origin", srv.URL, "Content-Type", "application/json", "X-Pentrail-Write", wt.WriteToken, "Sec-Fetch-Site", "same-origin")

	// evidence before any note
	evidence := func() string {
		var b strings.Builder
		for _, p := range []string{"/api/sessions", "/api/commands?session=", "/api/entities?session=", "/api/graph?session=", "/api/changes?session=", "/api/capture-events?session=", "/api/artifacts?session=", "/api/raw?session="} {
			if strings.HasSuffix(p, "=") {
				p += strconv.FormatInt(sid, 10)
			}
			rr := do("GET", p, nil, auth)
			b.WriteString(p + "\n" + strconv.Itoa(rr.code) + "\n" + string(rr.body) + "\n")
		}
		return b.String()
	}
	before := evidence()

	js := func(v any) []byte { b, _ := json.Marshal(v); return b }
	create := map[string]any{"session": sid, "anchor": map[string]any{"kind": "command", "cmd_index": 2}, "title": "<script>alert(1)</script> Zażółć", "body": "multi\nline **md** password=SyntheticPw123\n"}

	// rejected changes
	cases := []struct {
		name   string
		method string
		path   string
		body   []byte
		hdr    map[string]string
		want   int
	}{
		{"no session token", "POST", "/api/notes", js(create), with(write, "Cookie", ""), 401},
		{"no Origin", "POST", "/api/notes", js(create), with(write, "Origin", ""), 403},
		{"foreign Origin", "POST", "/api/notes", js(create), with(write, "Origin", "http://evil.example"), 403},
		{"another local port", "POST", "/api/notes", js(create), with(write, "Origin", "http://127.0.0.1:1"), 403},
		{"Origin null", "POST", "/api/notes", js(create), with(write, "Origin", "null"), 403},
		{"same-site, not same-origin", "POST", "/api/notes", js(create), with(write, "Sec-Fetch-Site", "same-site"), 403},
		{"cross-site fetch", "POST", "/api/notes", js(create), with(write, "Sec-Fetch-Site", "cross-site"), 403},
		{"no write token", "POST", "/api/notes", js(create), with(write, "X-Pentrail-Write", ""), 403},
		{"wrong write token", "POST", "/api/notes", js(create), with(write, "X-Pentrail-Write", strings.Repeat("0", 64)), 403},
		{"session token as write token", "POST", "/api/notes", js(create), with(write, "X-Pentrail-Write", tok), 403},
		{"form content type", "POST", "/api/notes", js(create), with(write, "Content-Type", "application/x-www-form-urlencoded"), 415},
		{"text/plain", "POST", "/api/notes", js(create), with(write, "Content-Type", "text/plain"), 415},
		{"no content type", "POST", "/api/notes", js(create), with(write, "Content-Type", ""), 415},
		{"GET write", "GET", "/api/notes/" + strings.Repeat("a", 32), nil, write, 405},
		{"DELETE", "DELETE", "/api/notes/" + strings.Repeat("a", 32), nil, write, 405},
		{"PUT collection", "PUT", "/api/notes", js(create), write, 405},
		{"preflight", "OPTIONS", "/api/notes", nil, with(write, "Access-Control-Request-Method", "POST"), 405},
		{"GET archive", "GET", "/api/notes/" + strings.Repeat("a", 32) + "/archive", nil, write, 405},
		{"bad id", "PUT", "/api/notes/xyz", js(create), write, 404},
		{"unknown action", "POST", "/api/notes/" + strings.Repeat("a", 32) + "/delete", []byte(`{}`), write, 404},
		{"unknown field", "POST", "/api/notes", []byte(`{"session":1,"title":"t","body":"b","extra":1}`), write, 400},
		{"two documents", "POST", "/api/notes", []byte(`{"session":1,"title":"t","body":"b"}{}`), write, 400},
		{"not JSON", "POST", "/api/notes", []byte(`title=t`), write, 400},
		{"too large", "POST", "/api/notes", js(map[string]any{"session": sid, "title": "t", "body": strings.Repeat("x", noteRequestMax)}), write, 413},
		{"body over the note limit", "POST", "/api/notes", js(map[string]any{"session": sid, "title": "t", "body": strings.Repeat("x", store.NoteBodyMax+1)}), write, 400},
		{"missing session", "POST", "/api/notes", js(map[string]any{"session": 9999, "title": "t", "body": "b"}), write, 400},
		{"command of another session", "POST", "/api/notes", js(map[string]any{"session": other, "anchor": map[string]any{"kind": "command", "cmd_index": 2}, "title": "t", "body": "b"}), write, 400},
		{"unknown element", "POST", "/api/notes", js(map[string]any{"session": sid, "anchor": map[string]any{"kind": "node", "node_id": "host:203.0.113.99"}, "title": "t", "body": "b"}), write, 400},
	}
	for _, c := range cases {
		if r := do(c.method, c.path, c.body, c.hdr); r.code != c.want {
			t.Errorf("%s: %d, want %d (%s)", c.name, r.code, c.want, bytes.TrimSpace(r.body))
		}
	}
	var count int
	st.DB().QueryRow(`SELECT count(*) FROM notes`).Scan(&count)
	if count != 0 {
		t.Fatalf("rejected requests stored %d notes", count)
	}

	// create, read, update, conflict, archive, restore
	r = do("POST", "/api/notes", js(create), write)
	var n store.Note
	if r.code != http.StatusCreated || json.Unmarshal(r.body, &n) != nil {
		t.Fatalf("create: %d %s", r.code, r.body)
	}
	if !strings.HasPrefix(r.h.Get("Content-Type"), "application/json") || r.h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("create headers: %v", r.h)
	}
	if n.Title != create["title"] || strings.Contains(n.Body, "SyntheticPw123") || n.MaskedBytes == 0 || n.Revision != 1 || !strings.HasPrefix(n.AnchorLabel, "command #2: ") {
		t.Fatalf("created: %+v", n)
	}
	if bytes.Contains(r.body, []byte("<script>")) {
		t.Fatal("markup is not escaped in the JSON reply") // encoding/json escapes < > as < >
	}
	r = do("GET", "/api/notes?session="+strconv.FormatInt(sid, 10), nil, auth)
	var list []store.Note
	if r.code != 200 || json.Unmarshal(r.body, &list) != nil || len(list) != 1 || list[0].ID != n.ID || list[0].Title != n.Title {
		t.Fatalf("list: %d %s", r.code, r.body)
	}
	if r := do("GET", "/api/notes?session="+strconv.FormatInt(other, 10), nil, auth); string(bytes.TrimSpace(r.body)) != "[]" {
		t.Fatalf("other session lists: %s", r.body)
	}
	if r := do("GET", "/api/notes?session="+strconv.FormatInt(sid, 10), nil, nil); r.code != 401 {
		t.Fatalf("list without the token: %d", r.code)
	}
	if r := do("GET", "/api/notes?session=x", nil, auth); r.code != 400 {
		t.Fatalf("bad session: %d", r.code)
	}
	put := func(rev int64, body string, session int64) resp {
		return do("PUT", "/api/notes/"+n.ID, js(map[string]any{"session": session, "revision": rev, "title": "t", "body": body}), write)
	}
	if r := put(1, "second", other); r.code != 404 {
		t.Fatalf("update through another session: %d", r.code)
	}
	if r := put(1, "second", sid); r.code != 200 {
		t.Fatalf("update: %d %s", r.code, r.body)
	}
	r = put(1, "stale tab", sid)
	var conflict struct {
		Error   string     `json:"error"`
		Current store.Note `json:"current"`
	}
	if r.code != 409 || json.Unmarshal(r.body, &conflict) != nil || conflict.Current.Revision != 2 || conflict.Current.Body != "second" {
		t.Fatalf("stale update: %d %s", r.code, r.body)
	}
	arch := func(rev int64, a bool) resp {
		return do("POST", "/api/notes/"+n.ID+"/archive", js(map[string]any{"session": sid, "revision": rev, "archived": a}), write)
	}
	if r := arch(1, true); r.code != 409 {
		t.Fatalf("stale archive: %d", r.code)
	}
	if r := arch(2, true); r.code != 200 || !bytes.Contains(r.body, []byte(`"archived":true`)) {
		t.Fatalf("archive: %d %s", r.code, r.body)
	}
	if r := put(3, "edit archived", sid); r.code != 409 {
		t.Fatalf("edit of an archived note: %d", r.code)
	}
	if r := arch(3, false); r.code != 200 || !bytes.Contains(r.body, []byte(`"revision":4`)) {
		t.Fatalf("restore: %d %s", r.code, r.body)
	}

	if after := evidence(); after != before {
		t.Fatal("note changes altered what the evidence endpoints return")
	}
	// The page carries the honest label and loads notes.js.
	page := string(indexHTML)
	for _, want := range []string{"evidence read-only · operator notes editable", `<script src="/notes.js"></script>`, `data-view="notes"`, "not captured evidence"} {
		if !strings.Contains(page, want) {
			t.Fatalf("index.html lacks %q", want)
		}
	}
	if strings.Contains(page, ">read-only · localhost<") {
		t.Fatal("the misleading global read-only label is still there")
	}
}

// notes.test.cjs: the real notes.js (autosave, conflicts, archive, unload).
func TestNotesClientModule(t *testing.T) {
	if len(notesJS) == 0 {
		t.Fatal("notes.js not embedded")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed: notes.test.cjs not run")
	}
	if _, err := os.Stat("notes.test.cjs"); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, "notes.test.cjs").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "PASS notes 24") {
		t.Fatalf("notes.test.cjs: %v\n%s", err, out)
	}
	t.Log(strings.TrimSpace(string(out)))
}
