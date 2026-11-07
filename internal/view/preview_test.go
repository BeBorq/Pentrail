package view

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Codex 04J: a repeatable SYNTHETIC preview of the real viewer page for an
// independent visual check of the artifact list (unknown state on server
// error and timeout, retry, mixed counts) and of the cleanup checklist
// (ticks per database, unknown state). It is a test, not a product route:
// nothing here is compiled into pentrail. Run (any OS, plain or sqlcipher
// build):
//
//	PENTRAIL_PREVIEW=1 go test ./internal/view -run TestSyntheticPreview -v -timeout 0
//
// Optional: PENTRAIL_PREVIEW_MINUTES (default 30), PENTRAIL_PREVIEW_ADDR
// (loopback only, default 127.0.0.1:0). It prints a loopback link (random
// token), a switch between the two databases on that SAME address, and a
// table of what each session shows, serves
// the real handler (Server.handler) over synthetic databases in a temporary
// folder, and stops after the time limit or Ctrl-C. Failures are injected
// only by this test's wrapper, in front of the real routes.
func TestSyntheticPreview(t *testing.T) {
	if os.Getenv("PENTRAIL_PREVIEW") != "1" {
		t.Skip("synthetic preview: set PENTRAIL_PREVIEW=1 (see the comment)")
	}
	minutes := 30
	if v, err := strconv.Atoi(os.Getenv("PENTRAIL_PREVIEW_MINUTES")); err == nil && v > 0 {
		minutes = v
	}
	dir := t.TempDir()
	main := previewDB(t, filepath.Join(dir, "preview-a.db"))
	other := synthDB(t, filepath.Join(dir, "preview-b.db"), nil)
	defer main.Close()
	defer other.Close()

	// ONE origin for both databases, as in real use (`pentrail serve` on its
	// port, whichever database it opens): the browser's per-origin storage
	// is shared, so only the per-database namespace keeps the ticks apart.
	tok, err := randToken()
	if err != nil {
		t.Fatal(err)
	}
	a, b := New(main), New(other)
	a.token, b.token = tok, tok
	inj := &previewFaults{seen: map[string]int{}}
	hA, hB := inj.wrap(a.handler(), false), inj.wrap(b.handler(), true)
	var mu sync.Mutex
	cur := hA
	base := previewServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__preview/use" { // this test's switch, not a product route
			if r.URL.Query().Get("t") != tok || !hostIsLocal(r.Host) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			mu.Lock()
			if r.URL.Query().Get("db") == "b" {
				cur = hB
			} else {
				cur = hA
			}
			mu.Unlock()
			http.Redirect(w, r, "/?t="+tok, http.StatusFound)
			return
		}
		mu.Lock()
		h := cur
		mu.Unlock()
		h.ServeHTTP(w, r)
	}))

	fmt.Printf(`
SYNTHETIC PREVIEW (data invented; no real targets, no real secrets)

Open (database A):      %[1]s/?t=%[2]s
Switch to database B:   %[1]s/__preview/use?db=b&t=%[2]s
Back to database A:     %[1]s/__preview/use?db=a&t=%[2]s

Database A
   session 1  tool output files: mixed — 2 complete, 1 tool running, 1 waiting for import, 1 partial (needs attention)
   session 2  tool output files: all complete
   session 3  tool output files: first 2 reads — server error, then the list (check “Try again”)
   session 4  tool output files: first read unanswered for 15 s (the page waits 10 s), then the list
   session 5  tool output files: always a server error (the unknown state stays)
   Cleanup (session 1): tick an item; after reloading the page it stays ticked.
Database B — the same address (the same browser storage), another database, the same session 1 with the
   same commands and categories: ticks from A must NOT appear here. The first 2 identity reads of
   database B fail: Cleanup shows “Tick state: unknown” with locked check boxes;
   “Try again” after 2 attempts restores the checklist (without the ticks from A). Back in A,
   the ticks of A are in place.

Runs for %[3]d min or until Ctrl-C.
`, base, tok, minutes)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	defer signal.Stop(stop)
	select {
	case <-stop:
	case <-time.After(time.Duration(minutes) * time.Minute):
	}
	t.Logf("preview stopped; requests seen: %v", inj.counts())
}

// previewFaults: per-session behaviour of /api/artifacts on server A, and a
// failing /api/identity (first 2 requests) on server B.
type previewFaults struct {
	mu   sync.Mutex
	seen map[string]int
}

func (f *previewFaults) next(k string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen[k]++
	return f.seen[k]
}

func (f *previewFaults) counts() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int{}
	for k, v := range f.seen {
		out[k] = v
	}
	return out
}

func (f *previewFaults) wrap(real http.Handler, identityFails bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case identityFails && r.URL.Path == "/api/identity":
			if f.next("B identity") <= 2 {
				http.Error(w, "synthetic failure", http.StatusInternalServerError)
				return
			}
		case !identityFails && r.URL.Path == "/api/artifacts":
			s := r.URL.Query().Get("session")
			n := f.next("A artifacts session " + s)
			switch {
			case s == "3" && n <= 2, s == "5":
				http.Error(w, "synthetic failure", http.StatusInternalServerError)
				return
			case s == "4" && n == 1:
				select { // longer than the page's 10 s timeout
				case <-time.After(15 * time.Second):
				case <-r.Context().Done():
				}
				return
			}
		}
		real.ServeHTTP(w, r)
	})
}

func previewServe(t *testing.T, h http.Handler) string {
	t.Helper()
	addr := os.Getenv("PENTRAIL_PREVIEW_ADDR")
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	if !addrIsLoopback(addr) {
		t.Fatalf("PENTRAIL_PREVIEW_ADDR=%q is not a loopback address", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "http://" + ln.Addr().String()
}
