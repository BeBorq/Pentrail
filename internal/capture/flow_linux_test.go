//go:build linux

package capture

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/sessionio"
	"github.com/BeBorq/Pentrail/internal/store"
)

// Codex 04D, Linux counterpart of TestNativeCMDLongOutputWithoutLF (NOT a
// Windows result: a Linux PTY, /bin/sh, no ConPTY): N MiB without LF
// (PENTRAIL_FLOW_MIB, default 2), then a next command. Measures the output
// path per stage with flowHook, client and raw byte counts, and checks the
// raw stream against the received one (only the documented fail-closed
// masking of over-long lines may differ).
func TestFlowLongLineWithoutLFLinux(t *testing.T) {
	mib := 2
	if s := os.Getenv("PENTRAIL_FLOW_MIB"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			mib = v
		}
	}
	const abc = "abcdefghijklmnopqrstuvwxyz0123456789"
	content := make([]byte, mib<<20)
	for i := range content {
		content[i] = abc[(i*7+i/97)%len(abc)]
	}
	flowRun(t, mib, content)
}

// Codex 04E: the same, but shaped like ConPTY's rendering of scrolling
// output — 120-column rows, each starting with a cursor-positioning
// sequence — which is what drove the redactor's continuation join.
func TestFlowCursorLedRowsLinux(t *testing.T) {
	mib := 1
	if s := os.Getenv("PENTRAIL_FLOW_MIB"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			mib = v
		}
	}
	const abc = "abcdefghijklmnopqrstuvwxyz0123456789"
	var content []byte
	for i := 0; len(content) < mib<<20; i++ {
		content = append(content, "\x1b[30;1H"...)
		for k := 0; k < 120; k++ {
			j := i*120 + k
			content = append(content, abc[(j*7+j/97)%len(abc)])
		}
		content = append(content, "\r\n"...)
	}
	flowRun(t, mib, content)
}

func flowRun(t *testing.T, mib int, content []byte) {
	t.Helper()
	dir := t.TempDir()
	big := filepath.Join(dir, "big.txt")
	if err := os.WriteFile(big, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("cat"); err != nil {
		t.Skip("no cat")
	}
	fs := installFlow(t)
	cs := installCommitStats(t)
	probe := startSchedProbe(t) // Codex 04J
	diag := startLatencyDiag(t) // Codex 04K, only with PENTRAIL_LATENCY_DIAG
	st, id, db, sock := sessionStore(t)
	done := make(chan error, 1)
	script := "read a; cat " + big + "; read b; printf AFTER_BIG; read c"
	go func() {
		done <- RunServer(Options{Shell: "/bin/sh", Args: []string{"-c", script}, Store: st, SessionID: id}, sock)
	}()
	c := sessionConnect(t, sock)
	defer c.Close()
	c.SetDeadline(time.Time{})
	if typ, _, err := sessionio.Read(c); err != nil || typ != sessionio.Hello {
		t.Fatal(typ, err)
	}
	w := sessionio.NewWriter(c)
	var screen bytes.Buffer
	readUntil := func(pred func() bool, d time.Duration) {
		t.Helper()
		c.SetReadDeadline(time.Now().Add(d))
		for !pred() {
			typ, p, err := sessionio.Read(c)
			if err != nil {
				t.Fatalf("client read: %v; %s; client bytes %d", err, fs.summary(), screen.Len())
			}
			if typ == sessionio.Output {
				screen.Write(p)
			}
		}
	}
	t0 := time.Now()
	w.Send(sessionio.Data, []byte("go\n"))
	readUntil(func() bool { return screen.Len() >= len(content) }, 10*time.Minute)
	got := time.Since(t0)
	t.Logf("FLOW_LINUX %d MiB received by the client in %v (%.2f MiB/s); %s; %s", mib, got.Round(time.Millisecond), float64(mib)/got.Seconds(), fs.summary(), cs.summary())
	t1 := time.Now()
	w.Send(sessionio.Data, []byte("x\n"))
	readUntil(func() bool { return bytes.Contains(screen.Bytes()[max(0, screen.Len()-64):], []byte("AFTER_BIG")) }, time.Minute)
	t.Logf("FLOW_LINUX next output after %v", time.Since(t1).Round(time.Millisecond))
	w.Send(sessionio.Data, []byte("y\n"))
	for {
		typ, p, err := sessionio.Read(c)
		if err != nil {
			t.Fatal(err)
		}
		if typ == sessionio.Output {
			screen.Write(p)
		}
		if typ == sessionio.Finished {
			var r sessionio.Result
			if err = json.Unmarshal(p, &r); err != nil || r.Err() != nil {
				t.Fatal(r, err)
			}
			break
		}
	}
	if err := awaitServer(t, done); err != nil {
		t.Fatal(err)
	}
	re, err := store.Open(db, []byte("session-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer re.Close()
	ss, _ := re.ListSessions()
	raw, missing, err := re.ReadRange(id, 0, ss[0].RawBytes)
	if err != nil || missing != 0 {
		t.Fatalf("raw: missing %d err %v", missing, err)
	}
	masked, err := rawMatchesClient(raw, screen.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "AFTER_BIG") {
		t.Fatal("next output not recorded")
	}
	// Codex 04J: the same latency check as the native test (durable writes
	// are profiled in the encrypted build only)
	if store.Encrypted() {
		fail, rep := checkLatency(t, screen.Bytes(), fs, cs, probe, diag)
		t.Log(rep)
		if fail {
			t.Fatal("latency: " + rep)
		}
	}
	t.Logf("FLOW_LINUX raw=%d client=%d masked(fail-closed, line > %d B)=%d encrypted=%v", len(raw), screen.Len(), 64<<10, masked, store.Encrypted())
}
