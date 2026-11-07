package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/BeBorq/Pentrail/internal/dbidentity"
	"github.com/BeBorq/Pentrail/internal/localipc"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/BeBorq/Pentrail/internal/background"
	"github.com/BeBorq/Pentrail/internal/capture"
	"github.com/BeBorq/Pentrail/internal/sessionio"
	"github.com/BeBorq/Pentrail/internal/store"
	"github.com/BeBorq/Pentrail/internal/view"
)

func userState() (background.State, error) {
	s, err := background.Load()
	if err != nil {
		return s, err
	}
	if s.Database == "" {
		s.Database = defaultDBPath()
	}
	s.Database = dbidentity.Canonical(s.Database)
	return s, err
}
func sessionSockets(db string) []string {
	paths, _ := filepath.Glob(filepath.Join(filepath.Dir(db), "run", "*.sock"))
	var result []string
	pattern := regexp.MustCompile(`^[0-9a-f]{16}\.sock$`)
	for _, p := range paths {
		if pattern.MatchString(filepath.Base(p)) {
			result = append(result, p)
		}
	}
	return result
}
func sameDatabase(a, b string) bool { return dbidentity.Canonical(a) == dbidentity.Canonical(b) }
func controlledSessions(db string) ([]string, error) {
	var out []string
	var failures []error
	for _, path := range sessionSockets(db) {
		state, e := sessionio.RequestControl(path, "status")
		if e != nil {
			if localipc.IsStaleError(e) {
				continue
			}
			failures = append(failures, fmt.Errorf("%s: %w", filepath.Base(path), e))
			continue
		}
		if state.DatabaseID == "" {
			failures = append(failures, errors.New("session database identity missing; close the old session before upgrading"))
			continue
		}
		if state.DatabaseID == dbidentity.ID(db) {
			out = append(out, path)
		}
	}
	return out, errors.Join(failures...)
}
func checkNoRecordingSessions(db string) error {
	paths, e := controlledSessions(db)
	if e != nil {
		return e
	}
	for _, path := range paths {
		state, e := sessionio.RequestControl(path, "status")
		if e != nil {
			return e
		}
		if state.Recording {
			return errors.New("pause existing recording sessions before changing the database")
		}
	}
	return nil
}
func controlAll(db, op string) error {
	paths, e := controlledSessions(db)
	var failures []error
	if e != nil {
		failures = append(failures, e)
	}
	for _, path := range paths {
		if _, e := sessionio.RequestControl(path, op); e != nil {
			if localipc.IsStaleError(e) {
				continue
			}
			failures = append(failures, e)
		}
	}
	return errors.Join(failures...)
}
func cmdOn(args []string) error {
	unlock, lockErr := background.Lock()
	if lockErr != nil {
		return lockErr
	}
	defer unlock()
	s, err := userState()
	if err != nil {
		return err
	}
	db, args := flagValue(args, "--db", s.Database)
	db = dbidentity.Canonical(db)
	allow, _ := flagBool(args, "--allow-plain")
	if !store.Encrypted() && !s.AllowPlain && !allow {
		return errors.New("background recording requires a SQLCipher build (plain is allowed only with explicit --allow-plain for development)")
	}
	if s.Enabled && !sameDatabase(s.Database, db) {
		return errors.New("disable recording before switching databases")
	}
	if !sameDatabase(s.Database, db) {
		if err = checkNoRecordingSessions(s.Database); err != nil {
			return err
		}
	}
	if err = ensureDatabaseDir(filepath.Dir(db)); err != nil {
		return err
	}
	if store.Encrypted() && !background.AgentReady() {
		key, err := getPassphrase()
		if err != nil {
			return err
		}
		defer zero(key)
		st, err := store.Open(db, key)
		if err != nil {
			return err
		}
		if err = st.Close(); err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(background.AgentSocket()), 0700); err != nil {
			return err
		}
		if err = removeAgentEndpoint(); err != nil {
			return err
		}
		if err = spawnWithKey("__key-agent", nil, key, filepath.Join(background.Dir(), "run", "key-agent.log")); err != nil {
			return err
		}
		until := time.Now().Add(5 * time.Second)
		for !background.AgentReady() {
			if time.Now().After(until) {
				return errors.New("key agent did not start")
			}
			time.Sleep(30 * time.Millisecond)
		}
	}
	s.Database = db
	s.Enabled = true
	s.AllowPlain = s.AllowPlain || allow
	if err = background.Save(s); err != nil {
		return err
	}
	if err = controlAll(db, "on"); err != nil {
		return fmt.Errorf("enabled for new terminals, but some existing sessions could not resume: %w", err)
	}
	fmt.Println("pentrail: recording enabled; configured new terminals start recording automatically.")
	return nil
}
func cmdOff() error {
	unlock, lockErr := background.Lock()
	if lockErr != nil {
		return lockErr
	}
	defer unlock()
	s, err := userState()
	if err != nil {
		return err
	}
	s.Enabled = false
	if err = background.Save(s); err != nil {
		return err
	}
	controlErr := controlAll(s.Database, "off")
	if background.AgentReady() {
		waitExit, e := agentExitWaiter()
		if e != nil {
			return fmt.Errorf("recording paused, cannot track key agent shutdown: %w", e)
		}
		_, stopErr := background.AgentRequest('L')
		waitErr := waitExit()
		if e = errors.Join(stopErr, waitErr); e != nil {
			return fmt.Errorf("recording paused, key agent shutdown failed (endpoint still answering: %t): %w", background.AgentReady(), e)
		}
		until := time.Now().Add(5 * time.Second)
		for background.AgentReady() {
			if time.Now().After(until) {
				return errors.New("recording paused, but key agent did not stop")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if controlErr != nil {
		return fmt.Errorf("disabled for new terminals, but some existing sessions did not acknowledge pause: %w", controlErr)
	}
	fmt.Println("pentrail: recording disabled; existing shells continue normally.")
	return nil
}
func cmdStatus() error {
	s, err := userState()
	if err != nil {
		return err
	}
	fmt.Printf("enabled=%t key_unlocked=%t database=%s\n", s.Enabled, background.AgentReady(), s.Database)
	for _, path := range sessionSockets(s.Database) {
		state, err := sessionio.RequestControl(path, "status")
		if err != nil {
			fmt.Printf("session=%s unavailable=%v\n", filepath.Base(path), err)
			continue
		}
		if state.DatabaseID == dbidentity.ID(s.Database) {
			fmt.Printf("session=%d recording=%t socket=%s\n", state.SessionID, state.Recording, path)
			if state.CaptureError != "" {
				fmt.Printf("session=%d RECORDING STOPPED after a storage failure: %s\n", state.SessionID, state.CaptureError)
			}
		}
	}
	return nil
}
func inheritedRecording() bool {
	path := os.Getenv("PENTRAIL_SOCKET")
	if path == "" {
		return false
	}
	until := time.Now().Add(2 * time.Second)
	for {
		state, e := sessionio.RequestControl(path, "status")
		if e == nil {
			return capture.SharesConsole(state.RootPID, state.ConsoleID)
		}
		if localipc.IsStaleError(e) || !strings.Contains(e.Error(), "not available") || time.Now().After(until) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func shouldAutoStart() bool { return autoEnabled() && !inheritedRecording() }
func autoEnabled() bool {
	s, err := userState()
	return err == nil && s.Enabled && (store.Encrypted() && background.AgentReady() || !store.Encrypted() && s.AllowPlain)
}
func captureEnabled() bool {
	path := os.Getenv("PENTRAIL_SOCKET")
	if path == "" {
		return false
	}
	s, err := sessionio.RequestControl(path, "status")
	return err == nil && s.Recording
}
func cmdKeyAgent() error {
	key, err := background.ReadKeyPipe()
	if err != nil {
		return err
	}
	if len(key) == 0 {
		return errors.New("key agent refuses an empty key")
	}
	_ = capture.Mlockall()
	return background.ServeAgent(background.AgentSocket(), key)
}
func cmdViewer(args []string) error {
	db, _ := flagValue(args, "--db", defaultDBPath())
	key, err := background.ReadKeyPipe()
	if err != nil {
		return err
	}
	st, err := store.Open(db, key)
	zero(key)
	if err != nil {
		return err
	}
	defer st.Close()
	ss, e := st.ListSessions()
	if e != nil {
		return e
	}
	for _, session := range ss {
		if e = refreshDerived(st, session.ID); e != nil {
			return e
		}
	}

	return view.New(st).Serve("127.0.0.1:0", false)
}
func viewerURL(logPath string) string {
	b, _ := os.ReadFile(logPath)
	m := regexp.MustCompile(`http://127\.0\.0\.1:[0-9]+/\?t=[0-9a-f]+`).Find(b)
	return string(m)
}
func viewerReady(link, identity string) bool {
	if link == "" {
		return false
	}
	u, e := url.Parse(link)
	if e != nil {
		return false
	}
	u.Path = "/api/identity"
	c := http.Client{Timeout: 500 * time.Millisecond}
	r, e := c.Get(u.String())
	if e != nil {
		return false
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return false
	}
	var state struct {
		DatabaseID string `json:"database_id"`
	}
	return json.NewDecoder(r.Body).Decode(&state) == nil && state.DatabaseID == identity
}
func cmdOpen(args []string) error {
	s, err := userState()
	if err != nil {
		return err
	}
	noBrowser, _ := flagBool(args, "--no-browser")
	logPath := filepath.Join(background.Dir(), "run", "viewer-"+dbidentity.ID(s.Database)[:16]+".log")
	link := viewerURL(logPath)
	if !viewerReady(link, dbidentity.ID(s.Database)) {
		key, err := getPassphrase()
		if err != nil {
			return err
		}
		defer zero(key)
		if err = spawnWithKey("__viewer", []string{"--db", s.Database}, key, logPath); err != nil {
			return err
		}
		until := time.Now().Add(20 * time.Second)
		for {
			link = viewerURL(logPath)
			if viewerReady(link, dbidentity.ID(s.Database)) {
				break
			}
			if time.Now().After(until) {
				return errors.New("viewer did not start; see ~/.pentrail/run/viewer.log")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	fmt.Println(link)
	if !noBrowser {
		if _, err = url.ParseRequestURI(link); err != nil {
			return err
		}
		if err = openBrowser(link); err != nil {
			return err
		}
	}
	return nil
}

const blockStart = "# >>> pentrail automatic capture >>>"
const blockEnd = "# <<< pentrail automatic capture <<<"

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
