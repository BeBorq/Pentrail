// Command pentrail — Krok 1 prototype: capture + store.
//
//	pentrail start            run your shell, capturing everything to the db
//	pentrail hook bash|zsh     print the shell-integration snippet
//	pentrail inspect [--db p]  dump what's in the database
package main

import (
	"bufio"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BeBorq/Pentrail/internal/background"
	"github.com/BeBorq/Pentrail/internal/capture"
	"github.com/BeBorq/Pentrail/internal/hooks"
	"github.com/BeBorq/Pentrail/internal/privatefs"
	"github.com/BeBorq/Pentrail/internal/redact"
	"github.com/BeBorq/Pentrail/internal/report"
	"github.com/BeBorq/Pentrail/internal/store"
	"github.com/BeBorq/Pentrail/internal/view"
)

const version = "0.6.29-durable"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	flushDiag := func() {}
	switch os.Args[1] {
	case "__key-agent", "__viewer", "__session-server":
		// stderr of these background processes is a plain .log file
		flushDiag = maskStderr()
	}
	exit := func(code int) { flushDiag(); os.Exit(code) }
	defer flushDiag()
	switch os.Args[1] {
	case "flush":
		err = cmdFlush(os.Args[2:])
	case "backup":
		err = cmdBackup(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "setup":
		err = cmdSetup(os.Args[2:])
	case "on":
		err = cmdOn(os.Args[2:])
	case "off":
		err = cmdOff()
	case "status":
		err = cmdStatus()
	case "open":
		err = cmdOpen(os.Args[2:])
	case "__key-agent":
		err = cmdKeyAgent()
	case "__viewer":
		err = cmdViewer(os.Args[2:])
	case "__same-console":
		if !inheritedRecording() {
			os.Exit(1)
		}
		return
	case "__cmd-check":
		if !cmdAutoCheck() {
			os.Exit(1)
		}
		return
	case "__auto-check":
		if !shouldAutoStart() {
			os.Exit(1)
		}
		return
	case "__artifact-check":
		s, e := userState()
		if e != nil || !s.AllowArtifacts || !captureEnabled() {
			os.Exit(1)
		}
		return
	case "__capture-check":
		if !captureEnabled() {
			os.Exit(1)
		}
		return
	case "start":
		err = cmdStart(os.Args[2:])
	case "attach":
		err = cmdAttach(os.Args[2:])
	case "__session-server": // internal: the detached session server
		err = cmdSessionServer(os.Args[2:])
	case "hook":
		err = cmdHook(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "extract":
		err = cmdExtract(os.Args[2:])
	case "parse":
		err = cmdParse(os.Args[2:])
	case "cleanup":
		err = cmdCleanup(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	case "export":
		err = cmdExport(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "pentrail: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pentrail:", err)
		exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `pentrail `+version+`

usage:
  pentrail setup bash|zsh|windows|powershell|pwsh|cmd [--db PATH]        opt-in automatic capture in new terminals
  pentrail flush [--db PATH]                  commit active recording queues to disk
  pentrail backup [--out PATH]               create and verify an encrypted backup
  pentrail verify [--file PATH]               verify encrypted database integrity
  pentrail on                               unlock once and enable recording
  pentrail off                              pause all sessions; keep shells alive
  pentrail status                            show enabled/unlocked/session state
  pentrail open [--no-browser]               open the local viewer on demand
  pentrail start [--db PATH] [--shell PATH]   start a captured shell session (detachable)
  pentrail attach [--db PATH] [--sock PATH]   re-attach to a running session (Ctrl-\ to detach)
  pentrail hook  bash|zsh                      print the shell hook
  pentrail inspect [--db PATH]                 show sessions, commands, raw stats
  pentrail serve   [--db PATH] [--addr A] [--allow-remote]   local viewer: evidence read-only, operator notes editable (token-gated)
  pentrail extract [--db PATH] [--session N]   run regex extraction (IP/domain/URL/email)
  pentrail parse   [--db PATH] [--session N]   parse structured output (nmap/ffuf/nuclei)
  pentrail cleanup [--db PATH] [--session N]   checklist of state changes to undo
  pentrail report  [--db PATH] [--session N] [--out F] [--include-notes] --confirm-plaintext   masked plaintext HTML report
  pentrail export  [--db PATH] [--session N] [--format json|csv] [--out F] [--include-notes] --confirm-plaintext
                   (operator notes are private: included only with --include-notes; not in CSV)

env:
  PENTRAIL_DB          database path (default ~/.pentrail/pentrail.db)
  PENTRAIL_PASSPHRASE  passphrase (non-interactive; otherwise prompted on encrypted builds)
`)
	if store.Encrypted() {
		fmt.Fprintln(os.Stderr, "\nbuild: SQLCipher (database encrypted at rest)")
	} else {
		fmt.Fprintln(os.Stderr, "\nbuild: plain SQLite (NOT encrypted — dev/test build)")
	}
}

func defaultDBPath() string {
	if v := os.Getenv("PENTRAIL_DB"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".pentrail", "pentrail.db")
}

// flagValue pulls "--name value" out of args; returns value and the rest.
func flagValue(args []string, name, def string) (string, []string) {
	out := def
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == name && i+1 < len(args) {
			out = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	return out, rest
}

// flagBool removes a boolean "--name" flag from args; returns whether present.
func flagBool(args []string, name string) (bool, []string) {
	found := false
	rest := make([]string, 0, len(args))
	for _, a := range args {
		if a == name {
			found = true
			continue
		}
		rest = append(rest, a)
	}
	return found, rest
}

func getPassphrase() ([]byte, error) {
	if v := os.Getenv("PENTRAIL_PASSPHRASE"); v != "" {
		// Remove it from our environment immediately so the captured shell and
		// every tool it runs do NOT inherit the database key via os.Environ().
		os.Unsetenv("PENTRAIL_PASSPHRASE")
		return []byte(v), nil
	}
	if store.Encrypted() {
		if key, err := background.AgentRequest('K'); err == nil && len(key) > 0 {
			return key, nil
		}
		return capture.ReadPassphrase("pentrail passphrase: ")
	}
	return nil, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// newToken returns a random per-session token. It FAILS rather than returning a
// predictable value if the system RNG is unavailable — a guessable marker token
// would defeat the whole point.
func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("secure RNG unavailable: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func cmdHook(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: pentrail hook bash|zsh")
	}
	h, ok := hooks.For(args[0])
	if !ok {
		return fmt.Errorf("no hook for shell %q (have: bash, zsh, powershell, pwsh)", args[0])
	}
	fmt.Print(h)
	return nil
}

func cmdInspect(args []string) error {
	dbPath, _ := flagValue(args, "--db", defaultDBPath())
	pass, err := getPassphrase()
	if err != nil {
		return err
	}
	st, err := store.Open(dbPath, pass)
	zero(pass)
	if err != nil {
		return err
	}
	defer st.Close()
	db := st.DB()

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	// Read all sessions first and close the cursor before issuing nested
	// queries: the store uses a single connection, so a still-open cursor
	// would deadlock the per-session queries below.
	type sess struct {
		id               int64
		shell, host, ver string
	}
	var sessions []sess
	rows, err := db.Query(`SELECT id, shell, hostname, version FROM sessions ORDER BY id`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var s sess
		if err := rows.Scan(&s.id, &s.shell, &s.host, &s.ver); err != nil {
			rows.Close()
			return err
		}
		sessions = append(sessions, s)
	}
	rows.Close()

	for _, s := range sessions {
		id := s.id
		fmt.Fprintf(w, "session %d  shell=%s host=%s ver=%s\n", id, s.shell, s.host, s.ver)

		var chunks, bytes sql.NullInt64
		db.QueryRow(`SELECT count(*), COALESCE(sum(length(data)),0) FROM raw_chunks WHERE session_id=?`, id).
			Scan(&chunks, &bytes)
		fmt.Fprintf(w, "  raw: %d chunks, %d bytes (source of truth)\n", chunks.Int64, bytes.Int64)

		crows, err := db.Query(`
            SELECT cmd_index, COALESCE(command,''), COALESCE(cwd,''), COALESCE(exit_code,0),
                   COALESCE(out_start_off,0), COALESCE(out_end_off,0), complete
            FROM commands WHERE session_id=? ORDER BY cmd_index`, id)
		if err != nil {
			return err
		}
		for crows.Next() {
			var idx, exit, so, eo, comp int64
			var cmd, cwd string
			if err := crows.Scan(&idx, &cmd, &cwd, &exit, &so, &eo, &comp); err != nil {
				crows.Close()
				return err
			}
			cmd = redact.String(cmd)
			cwd = redact.String(cwd)
			status := "…"
			if comp == 1 {
				status = fmt.Sprintf("exit=%d", exit)
			}
			fmt.Fprintf(w, "  [%d] %s  (%s)  bytes %d..%d  cwd=%s\n",
				idx, truncate(cmd, 60), status, so, eo, cwd)
		}
		crows.Close()
	}
	return nil
}

func cmdServe(args []string) error {
	dbPath, args := flagValue(args, "--db", defaultDBPath())
	addr, args := flagValue(args, "--addr", "127.0.0.1:7878")
	noExtract, args := flagBool(args, "--no-extract")
	allowRemote, _ := flagBool(args, "--allow-remote")

	pass, err := getPassphrase()
	if err != nil {
		return err
	}
	st, err := store.Open(dbPath, pass)
	zero(pass)
	if err != nil {
		return err
	}
	defer st.Close()

	// Refresh derived entities so the timeline shows them. Idempotent and fast;
	// this is the Layer-3 pass, kept out of the live terminal. --no-extract skips.
	if !noExtract {
		if sessions, err := st.ListSessions(); err != nil {
			return err
		} else {
			regexN, parserN, files := 0, 0, 0
			for _, s := range sessions {
				if _, e := st.IngestArtifacts(s.ID); e != nil {
					return e
				}
				if n, err := st.ExtractRegex(s.ID); err == nil {
					regexN += n
				} else {
					return err
				}
				if n, f, err := st.ParseArtifacts(s.ID); err == nil {
					parserN += n
					files += f
				} else {
					return err
				}
				if _, e := st.DetectChanges(s.ID); e != nil {
					return e
				}
			}
			fmt.Fprintf(os.Stderr, "pentrail: %d regex + %d parsed (from %d files) indicators across %d session(s)\n",
				regexN, parserN, files, len(sessions))
		}
	}

	return view.New(st).Serve(addr, allowRemote)
}

func cmdExtract(args []string) error {
	dbPath, args := flagValue(args, "--db", defaultDBPath())
	sessStr, _ := flagValue(args, "--session", "")

	pass, err := getPassphrase()
	if err != nil {
		return err
	}
	st, err := store.Open(dbPath, pass)
	zero(pass)
	if err != nil {
		return err
	}
	defer st.Close()

	var sessions []int64
	if sessStr != "" {
		id, perr := strconv.ParseInt(sessStr, 10, 64)
		if perr != nil {
			return fmt.Errorf("bad --session: %w", perr)
		}
		sessions = []int64{id}
	} else {
		all, err := st.ListSessions()
		if err != nil {
			return err
		}
		for _, s := range all {
			sessions = append(sessions, s.ID)
		}
	}

	for _, id := range sessions {
		n, err := st.ExtractRegex(id)
		if err != nil {
			return err
		}
		fmt.Printf("session %d: %d indicators extracted\n", id, n)
	}
	return nil
}

func cmdParse(args []string) error {
	dbPath, args := flagValue(args, "--db", defaultDBPath())
	sessStr, _ := flagValue(args, "--session", "")

	pass, err := getPassphrase()
	if err != nil {
		return err
	}
	st, err := store.Open(dbPath, pass)
	zero(pass)
	if err != nil {
		return err
	}
	defer st.Close()

	var sessions []int64
	if sessStr != "" {
		id, perr := strconv.ParseInt(sessStr, 10, 64)
		if perr != nil {
			return fmt.Errorf("bad --session: %w", perr)
		}
		sessions = []int64{id}
	} else {
		all, err := st.ListSessions()
		if err != nil {
			return err
		}
		for _, s := range all {
			sessions = append(sessions, s.ID)
		}
	}

	for _, id := range sessions {
		if _, e := st.IngestArtifacts(id); e != nil {
			return e
		}
		n, files, err := st.ParseArtifacts(id)
		if err != nil {
			return err
		}
		fmt.Printf("session %d: %d high-confidence entities from %d structured artifact(s)\n", id, n, files)
	}
	return nil
}

func cmdCleanup(args []string) error {
	dbPath, args := flagValue(args, "--db", defaultDBPath())
	sessStr, _ := flagValue(args, "--session", "")

	pass, err := getPassphrase()
	if err != nil {
		return err
	}
	st, err := store.Open(dbPath, pass)
	zero(pass)
	if err != nil {
		return err
	}
	defer st.Close()

	var sessions []int64
	if sessStr != "" {
		id, perr := strconv.ParseInt(sessStr, 10, 64)
		if perr != nil {
			return fmt.Errorf("bad --session: %w", perr)
		}
		sessions = []int64{id}
	} else {
		all, err := st.ListSessions()
		if err != nil {
			return err
		}
		for _, s := range all {
			sessions = append(sessions, s.ID)
		}
	}

	for _, id := range sessions {
		if _, err := st.DetectChanges(id); err != nil {
			return err
		}
		items, err := st.ListChanges(id)
		if err != nil {
			return err
		}
		fmt.Printf("session %d: %d state change(s) to review for cleanup\n", id, len(items))
		for _, it := range items {
			fmt.Printf("  [%s] #%d  %s\n        %s\n", it.Category, it.CmdIndex, redact.String(it.Description), truncate(redact.String(it.Command), 100))
		}
	}
	return nil
}

// assembleBundle refreshes derived data (idempotent) and gathers everything a
// report/export needs for one session.
func assembleBundle(st *store.Store, id int64) (report.Bundle, error) {
	if e := refreshDerived(st, id); e != nil {
		return report.Bundle{}, e
	}

	sessions, err := st.ListSessions()
	if err != nil {
		return report.Bundle{}, err
	}
	var si store.SessionInfo
	found := false
	for _, s := range sessions {
		if s.ID == id {
			si = s
			found = true
			break
		}
	}
	if !found {
		return report.Bundle{}, fmt.Errorf("session %d not found", id)
	}
	cmds, err := st.ListCommands(id)
	if err != nil {
		return report.Bundle{}, err
	}
	ents, err := st.ListEntityRows(id)
	if err != nil {
		return report.Bundle{}, err
	}
	changes, err := st.ListChanges(id)
	if err != nil {
		return report.Bundle{}, err
	}
	graph, err := st.BuildGraph(id)
	if err != nil {
		return report.Bundle{}, err
	}
	events, err := st.ListCaptureEvents(id)
	if err != nil {
		return report.Bundle{}, err
	}
	artifacts, err := st.ListArtifacts(id)
	if err != nil {
		return report.Bundle{}, err
	}
	return report.Bundle{
		Version: version, Encrypted: store.Encrypted(), Session: si, Commands: cmds,
		Entities: ents, Changes: changes, Graph: graph, CaptureEvents: events, Artifacts: artifacts, OutputMapping: capture.OutputMapping(si.Shell),
	}, nil
}

// resolveSession picks the session id from --session, or the most recent one.
func resolveSession(st *store.Store, sessStr string) (int64, error) {
	if sessStr != "" {
		return strconv.ParseInt(sessStr, 10, 64)
	}
	sessions, err := st.ListSessions()
	if err != nil {
		return 0, err
	}
	if len(sessions) == 0 {
		return 0, fmt.Errorf("no sessions in database")
	}
	return sessions[0].ID, nil // newest first
}

func cmdReport(args []string) error {
	confirmed, args := flagBool(args, "--confirm-plaintext")
	if !confirmed {
		return fmt.Errorf("HTML is an unencrypted export; add --confirm-plaintext to create a masked report")
	}
	includeNotes, args := flagBool(args, "--include-notes")
	dbPath, args := flagValue(args, "--db", defaultDBPath())
	sessStr, args := flagValue(args, "--session", "")
	out, _ := flagValue(args, "--out", "")

	pass, err := getPassphrase()
	if err != nil {
		return err
	}
	st, err := store.Open(dbPath, pass)
	zero(pass)
	if err != nil {
		return err
	}
	defer st.Close()

	id, err := resolveSession(st, sessStr)
	if err != nil {
		return err
	}
	b, err := assembleBundle(st, id)
	if err != nil {
		return err
	}
	if err := addNotes(st, id, &b, includeNotes); err != nil {
		return err
	}
	html, err := report.HTML(b)
	if err != nil {
		return err
	}
	if out == "" {
		out = fmt.Sprintf("pentrail-report-session-%d.html", id)
	}
	if err := privatefs.WriteNew(out, html); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes)\n", out, len(html))
	return nil
}

func cmdExport(args []string) error {
	confirmed, args := flagBool(args, "--confirm-plaintext")
	if !confirmed {
		return fmt.Errorf("JSON/CSV is an unencrypted export; add --confirm-plaintext to create a masked export")
	}
	includeNotes, args := flagBool(args, "--include-notes")
	dbPath, args := flagValue(args, "--db", defaultDBPath())
	sessStr, args := flagValue(args, "--session", "")
	format, args := flagValue(args, "--format", "json")
	out, _ := flagValue(args, "--out", "")
	if includeNotes && format == "csv" {
		return report.ErrNotesCSV // refused before anything is opened or written
	}

	pass, err := getPassphrase()
	if err != nil {
		return err
	}
	st, err := store.Open(dbPath, pass)
	zero(pass)
	if err != nil {
		return err
	}
	defer st.Close()

	id, err := resolveSession(st, sessStr)
	if err != nil {
		return err
	}
	b, err := assembleBundle(st, id)
	if err != nil {
		return err
	}
	if err := addNotes(st, id, &b, includeNotes); err != nil {
		return err
	}

	var data []byte
	var ext string
	switch format {
	case "json":
		data, err = report.JSON(b)
		ext = "json"
	case "csv":
		data, err = report.CSV(b)
		ext = "csv"
	default:
		return fmt.Errorf("unknown --format %q (json|csv)", format)
	}
	if err != nil {
		return err
	}
	if out == "" {
		out = fmt.Sprintf("pentrail-session-%d.%s", id, ext)
	}
	if err := privatefs.WriteNew(out, data); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes)\n", out, len(data))
	return nil
}

// addNotes adds the session's active operator notes when --include-notes was
// given. Without it the bundle carries no notes at all (private by default).
func addNotes(st *store.Store, id int64, b *report.Bundle, include bool) error {
	if !include {
		return nil
	}
	all, err := st.ListNotes(id)
	if err != nil {
		return fmt.Errorf("operator notes: %w", err)
	}
	b.IncludeNotes = true
	b.Notes = []store.Note{}
	for _, n := range all {
		if !n.Archived {
			b.Notes = append(b.Notes, n)
		}
	}
	return nil
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", "⏎")
	r := []rune(s) // count characters, never cut a multi-byte (e.g. Polish) rune
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func refreshDerived(st *store.Store, id int64) error {
	if _, e := st.IngestArtifacts(id); e != nil {
		return fmt.Errorf("artifact ingest: %w", e)
	}
	if _, e := st.ExtractRegex(id); e != nil {
		return fmt.Errorf("output extraction: %w", e)
	}
	if _, _, e := st.ParseArtifacts(id); e != nil {
		return fmt.Errorf("artifact parsing: %w", e)
	}
	if _, e := st.DetectChanges(id); e != nil {
		return fmt.Errorf("change detection: %w", e)
	}

	return nil
}
