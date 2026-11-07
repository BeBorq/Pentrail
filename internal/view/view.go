// Package view is Layer 4: a local viewer that never changes evidence. It serves a
// timeline of what capture already stored and, on demand, the exact output
// bytes of a command sliced from the raw log (the provenance view). It never
// captures and never parses. It binds to loopback only — nothing leaves the
// machine. The only thing it writes is operator notes (notes.go), which are
// kept apart from the evidence.
package view

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/BeBorq/Pentrail/internal/redact"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/BeBorq/Pentrail/internal/store"
)

//go:embed index.html
var indexHTML []byte

//go:embed graph.js
var graphJS []byte

//go:embed artifacts.js
var artifactsJS []byte

//go:embed cleanup.js
var cleanupJS []byte

//go:embed xref.js
var xrefJS []byte

//go:embed notes.js
var notesJS []byte

type Server struct {
	st    *store.Store
	token string
}

func New(st *store.Store) *Server { return &Server{st: st} }

// Serve blocks, serving the viewer on addr (e.g. 127.0.0.1:7878).
//
// Security (P1.8): it refuses a non-loopback bind unless allowRemote is set; it
// mints a random session token that must be in the URL; and every request is
// checked for a loopback Host and same-origin Origin (defending against DNS
// rebinding and cross-site reads). Evidence is read-only; operator notes are
// the only writes, with additional checks (notes.go).
func (s *Server) Serve(addr string, allowRemote bool) error {
	if !allowRemote && !addrIsLoopback(addr) {
		return fmt.Errorf("refusing to bind non-loopback address %q (session data would be exposed); pass --allow-remote to override deliberately", addr)
	}
	tok, err := randToken()
	if err != nil {
		return err
	}
	s.token = tok

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	warn := ""
	if allowRemote && !addrIsLoopback(addr) {
		warn = "  !! NON-LOOPBACK BIND — session data is reachable from the network"
	}
	ln, e := net.Listen("tcp", addr)
	if e != nil {
		return e
	}
	// Functional output (the access link with its token) goes to stdout and
	// is never masked; stderr carries diagnostics, which background
	// processes mask before they reach their plain .log file.
	fmt.Fprintf(os.Stdout, "pentrail: open  http://%s/?t=%s   (evidence read-only, operator notes editable; Ctrl-C to stop)%s\n", ln.Addr().String(), s.token, warn)
	return srv.Serve(ln)
}

// handler: every route of the viewer, each behind guard (s.token must be
// set). Tests serve it with httptest and their own token.
func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	// database_id: the path-derived identity the background `open` uses to
	// find a viewer of the right database. view_namespace (Codex 04J): the
	// random per-database name the page uses for its per-browser state.
	mux.HandleFunc("/api/identity", s.guard(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"database_id": s.st.Identity(), "view_namespace": s.st.ViewNamespace()})
	}))
	mux.HandleFunc("/", s.guard(s.handleIndex))
	mux.HandleFunc("/api/sessions", s.guard(s.handleSessions))
	mux.HandleFunc("/api/commands", s.guard(s.handleCommands))
	mux.HandleFunc("/api/raw", s.guard(s.handleRaw))
	mux.HandleFunc("/api/output", s.guard(s.handleOutput))
	mux.HandleFunc("/api/entities", s.guard(s.handleEntities))
	mux.HandleFunc("/api/graph", s.guard(s.handleGraph))
	mux.HandleFunc("/api/changes", s.guard(s.handleChanges))
	mux.HandleFunc("/api/capture-events", s.guard(s.handleCaptureEvents))
	mux.HandleFunc("/api/artifacts", s.guard(s.handleArtifacts))
	mux.HandleFunc("/graph.js", s.guard(s.handleGraphJS))
	mux.HandleFunc("/artifacts.js", s.guard(s.handleArtifactsJS))
	mux.HandleFunc("/cleanup.js", s.guard(s.handleCleanupJS))
	mux.HandleFunc("/xref.js", s.guard(s.handleXrefJS))
	mux.HandleFunc("/notes.js", s.guard(s.handleNotesJS))
	mux.HandleFunc("/api/notes/token", s.guard(s.handleNotesToken))
	mux.HandleFunc("/api/notes", s.guard(s.handleNotes))
	mux.HandleFunc("/api/notes/", s.guard(s.handleNote))
	return mux
}

func randToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("secure RNG unavailable: %w", err) // never serve with a guessable token
	}
	return hex.EncodeToString(b), nil
}

func addrIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return false // ":7878" binds all interfaces
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func hostIsLocal(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// guard enforces loopback Host, same-origin Origin, and the session token.
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !hostIsLocal(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && o != "null" {
			if u, err := url.Parse(o); err != nil || !hostIsLocal(u.Host) {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
		}
		tok := ""
		if c, err := r.Cookie("pt"); err == nil {
			tok = c.Value
		}
		if q := r.URL.Query().Get("t"); q != "" {
			tok = q
			if tokenOK(tok, s.token) && r.URL.Path == "/" {
				http.SetCookie(w, &http.Cookie{Name: "pt", Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			}
		}
		if !tokenOK(tok, s.token) {
			http.Error(w, "unauthorized — open the link printed by 'pentrail serve'", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func tokenOK(got, want string) bool {
	return len(got) == len(want) && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(indexHTML)
}

func writeJSON(w http.ResponseWriter, v interface{}) { writeJSONCode(w, http.StatusOK, v) }

// writeJSONCode: the reply passes the recognized-secret masking (redact.JSON)
// like every viewer reply.
func writeJSONCode(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Cache-Control", "no-store")
	b, e := json.Marshal(v)
	if e != nil {
		http.Error(w, "data serialization failed", 500)
		return
	}
	b, e = redact.JSON(b)
	if e != nil {
		http.Error(w, "data protection failed", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.st.ListSessions()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if sessions == nil {
		sessions = []store.SessionInfo{}
	}
	writeJSON(w, sessions)
}

func (s *Server) handleCommands(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("session"), 10, 64)
	if err != nil {
		http.Error(w, "bad session", 400)
		return
	}
	cmds, err := s.st.ListCommands(id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if cmds == nil {
		cmds = []store.CommandInfo{}
	}
	writeJSON(w, cmds)
}

func (s *Server) handleGraphJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Write(graphJS)
}

func (s *Server) handleArtifactsJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Write(artifactsJS)
}

func (s *Server) handleCleanupJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Write(cleanupJS)
}

func (s *Server) handleNotesJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Write(notesJS)
}

func (s *Server) handleXrefJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Write(xrefJS)
}

func (s *Server) handleChanges(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("session"), 10, 64)
	if err != nil {
		http.Error(w, "bad session", 400)
		return
	}
	items, err := s.st.ListChanges(id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if items == nil {
		items = []store.ChangeRow{}
	}
	writeJSON(w, items)
}

func (s *Server) handleCaptureEvents(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("session"), 10, 64)
	if err != nil {
		http.Error(w, "bad session", 400)
		return
	}
	events, err := s.st.ListCaptureEvents(id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if events == nil {
		events = []store.CaptureEvent{}
	}
	writeJSON(w, events)
}

// handleArtifacts lists every tool output file with its persisted import
// outcome (imported, partial, rejected, skipped and why, cleanup pending).
func (s *Server) handleArtifacts(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("session"), 10, 64)
	if err != nil {
		http.Error(w, "bad session", 400)
		return
	}
	items, err := s.st.ListArtifacts(id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if items == nil {
		items = []store.ArtifactInfo{}
	}
	writeJSON(w, items)
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("session"), 10, 64)
	if err != nil {
		http.Error(w, "bad session", 400)
		return
	}
	g, err := s.st.BuildGraph(id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, g)
}

func (s *Server) handleEntities(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("session"), 10, 64)
	if err != nil {
		http.Error(w, "bad session", 400)
		return
	}
	ents, err := s.st.ListEntityRows(id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if ents == nil {
		ents = []store.EntityRow{}
	}
	writeJSON(w, ents)
}

func (s *Server) handleOutput(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id, e1 := strconv.ParseInt(q.Get("session"), 10, 64)
	start, e2 := strconv.ParseInt(q.Get("start"), 10, 64)
	end, e3 := strconv.ParseInt(q.Get("end"), 10, 64)
	if e1 != nil || e2 != nil || e3 != nil {
		http.Error(w, "bad params", 400)
		return
	}
	// Cap the requested span so a crafted request cannot ask the server to
	// buffer an unbounded range into memory.
	const maxSpan = 8 << 20 // 8 MiB
	if start < 0 || end < start {
		http.Error(w, "bad range", 400)
		return
	}
	if end-start > maxSpan {
		http.Error(w, "range too large", 413)
		return
	}
	data, missing, err := s.st.ReadSafeRange(id, start, end)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// Session output is the most sensitive thing the viewer serves: it must not
	// land in the browser's on-disk HTTP cache (outside the encrypted DB), and
	// target-controlled bytes must never be sniffed as HTML.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Raw-Bytes", fmt.Sprintf("%d", len(data)))
	w.Header().Set("X-Missing-Bytes", fmt.Sprintf("%d", missing)) // >0 => range not contiguous
	w.Write(data)
}

// Bounded paging of the full recorded stream, including unsegmented commands.
func (s *Server) handleRaw(w http.ResponseWriter, r *http.Request) {
	id, e := strconv.ParseInt(r.URL.Query().Get("session"), 10, 64)
	if e != nil || id <= 0 {
		http.Error(w, "bad session", 400)
		return
	}
	start := int64(0)
	if v := r.URL.Query().Get("start"); v != "" {
		start, e = strconv.ParseInt(v, 10, 64)
		if e != nil || start < 0 {
			http.Error(w, "bad offset", 400)
			return
		}
	}
	limit := int64(1 << 20)
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, e = strconv.ParseInt(v, 10, 64)
		if e != nil || limit <= 0 || limit > 4<<20 {
			http.Error(w, "limit must be 1..4194304", 400)
			return
		}
	}
	sessions, e := s.st.ListSessions()
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	total := int64(-1)
	for _, session := range sessions {
		if session.ID == id {
			total = session.RawBytes
			break
		}
	}
	if total < 0 {
		http.NotFound(w, r)
		return
	}
	total, e = s.st.RawExtent(id)
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	if start > total {
		http.Error(w, "offset beyond recorded data", 400)
		return
	}
	end := total
	if total-start > limit {
		end = start + limit
	}
	b, missing, e := s.st.ReadSafeRange(id, start, end)
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Missing-Bytes", strconv.FormatInt(missing, 10))
	w.Header().Set("X-Next-Offset", strconv.FormatInt(end, 10))
	w.Header().Set("X-Raw-Total", strconv.FormatInt(total, 10))
	w.Write(b)
}
