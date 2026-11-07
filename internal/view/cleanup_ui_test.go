package view

import (
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Codex 04J: checklist ticks belong to ONE database. Two synthetic databases
// with the same session/command/category are served by the real viewer
// routes; cleanup.js (the file the page loads) runs in node against them:
// a tick in A is not shown in B, survives a restart of A's viewer (store
// reopened, new server), legacy keys mark nothing, and a failing
// /api/identity leaves the ticks unknown (hidden and locked).
func TestCleanupTicksPerDatabase(t *testing.T) {
	page := string(indexHTML)
	for _, want := range []string{`<script src="/cleanup.js"></script>`, "pentrailCleanup.namespace(fetch)", "pentrailCleanup.state(cleanStorage(),nsr,sid)", "pentrailCleanup.headText("} {
		if !strings.Contains(page, want) {
			t.Fatalf("index.html lacks %q", want)
		}
	}
	if strings.Contains(page, "cleanKey") || strings.Contains(page, "pentrail:clean:${") {
		t.Fatal("index.html still builds the old session-only key")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed: cleanup.test.cjs not run")
	}
	if exec.Command(node, "-e", "process.exit(typeof fetch==='function'?0:3)").Run() != nil {
		t.Skip("node without fetch (needs node 18+): cleanup.test.cjs not run")
	}
	dir := t.TempDir()
	const tok = "test-token-cleanup"
	pathA, pathB := synthPath(dir, "a.db"), synthPath(dir, "b.db")
	stA := synthDB(t, pathA, nil)
	stB := synthDB(t, pathB, nil)
	defer stB.Close()
	srvA, srvB := serveSynth(t, stA, tok), serveSynth(t, stB, tok)
	// a viewer whose /api/identity fails (everything else real)
	real := New(stB)
	real.token = tok
	bad := serveHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/identity" {
			http.Error(w, "synthetic failure", http.StatusInternalServerError)
			return
		}
		real.handler().ServeHTTP(w, r)
	}))
	storage := filepath.Join(dir, "storage.json")
	run := func(phase, a string) {
		t.Helper()
		out, err := exec.Command(node, "cleanup.test.cjs", phase, storage, tok, a, srvB.URL, bad.URL).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "PASS cleanup phase "+phase) {
			t.Fatalf("cleanup.test.cjs phase %s: %v\n%s", phase, err, out)
		}
		t.Log(strings.TrimSpace(string(out)))
	}
	run("1", srvA.URL)
	// restart A's viewer: close server and store, reopen the same file
	srvA.Close()
	if err := stA.Close(); err != nil {
		t.Fatal(err)
	}
	stA2 := synthDB(t, pathA, nil)
	defer stA2.Close()
	srvA2 := serveSynth(t, stA2, tok)
	run("2", srvA2.URL)
}
