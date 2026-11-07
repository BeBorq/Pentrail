package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const diagSecret = "SyntheticDiagnosticSecret"

// Runs only as a child: behaves like a background process whose stdout and
// stderr are both the plain .log file.
func TestHelperMaskedBackgroundLog(t *testing.T) {
	if os.Getenv("PENTRAIL_MASK_HELPER") == "" {
		t.Skip("helper process only")
	}
	flush := maskStderr()
	fmt.Fprintln(os.Stderr, `pentrail: WARNING — artifact "/scans/password=`+diagSecret+`/nmap.xml" not imported (rejected_invalid)`)
	fmt.Fprintln(os.Stderr, "pentrail: RECORDING STOPPED — storage failure; the shell keeps running unrecorded")
	fmt.Fprint(os.Stderr, "unterminated token="+diagSecret) // no newline: must still be flushed
	fmt.Fprintln(os.Stdout, "pentrail: open  http://127.0.0.1:41234/?t=9f86d081884c7d659a2feaa0c55ad015   (read-only; Ctrl-C to stop)")
	flush()
	os.Exit(0)
}

// Codex iteration 03, finding 5: the diagnostic file of a background process
// must not contain secrets, must keep the warnings, and must still carry the
// viewer link (functional metadata read by `pentrail open`).
func TestBackgroundLogMasksDiagnosticsKeepsLink(t *testing.T) {
	log := filepath.Join(t.TempDir(), "viewer.log")
	f, err := os.OpenFile(log, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	c := exec.Command(os.Args[0], "-test.run=^TestHelperMaskedBackgroundLog$")
	c.Env = append(os.Environ(), "PENTRAIL_MASK_HELPER=1")
	c.Stdout, c.Stderr = f, f // exactly like spawnWithKey
	err = c.Run()
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(log)
	s := string(b)
	if strings.Contains(s, diagSecret) {
		t.Fatalf("secret in the background log: %q", s)
	}
	for _, want := range []string{"not imported", "RECORDING STOPPED", "unterminated token="} {
		if !strings.Contains(s, want) {
			t.Fatalf("diagnostic lost (%q): %q", want, s)
		}
	}
	if got := viewerURL(log); got != "http://127.0.0.1:41234/?t=9f86d081884c7d659a2feaa0c55ad015" {
		t.Fatalf("viewer link not readable from the log: %q in %q", got, s)
	}
}

// Codex 04F: the masking pipe cannot be created (forced here). The process
// must not write its diagnostics unmasked: only a fixed notice reaches the
// log, the viewer link on stdout still works, writes after the flush go
// nowhere, and the process ends normally (nothing blocks).
func TestHelperPipeErrorFailsClosed(t *testing.T) {
	if os.Getenv("PENTRAIL_MASK_PIPE_FAIL") == "" {
		t.Skip("helper process only")
	}
	osPipe = func() (*os.File, *os.File, error) { return nil, nil, errors.New("forced pipe failure") }
	flush := maskStderr()
	fmt.Fprintln(os.Stderr, `pentrail: WARNING — artifact "/scans/password=`+diagSecret+`/nmap.xml" not imported`)
	fmt.Fprint(os.Stderr, "unterminated token="+diagSecret)
	fmt.Fprintln(os.Stdout, "pentrail: open  http://127.0.0.1:41234/?t=9f86d081884c7d659a2feaa0c55ad015   (read-only; Ctrl-C to stop)")
	flush()
	fmt.Fprintln(os.Stderr, "after flush token="+diagSecret)
	os.Exit(0)
}

func TestPipeErrorFailsClosed(t *testing.T) {
	log := filepath.Join(t.TempDir(), "agent.log")
	f, err := os.OpenFile(log, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	c := exec.Command(os.Args[0], "-test.run=^TestHelperPipeErrorFailsClosed$")
	c.Env = append(os.Environ(), "PENTRAIL_MASK_PIPE_FAIL=1")
	c.Stdout, c.Stderr = f, f // exactly like spawnWithKey
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() { ended <- c.Wait() }() // only this test's own child
	select {
	case err = <-ended:
	case <-time.After(30 * time.Second):
		c.Process.Kill()
		t.Fatal("helper did not finish: something blocked")
	}
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(log)
	s := string(b)
	if strings.Contains(s, diagSecret) {
		t.Fatalf("secret written although masking was unavailable: %q", s)
	}
	if !strings.Contains(s, "pentrail: diagnostics suppressed: masking is unavailable") {
		t.Fatalf("no notice: %q", s)
	}
	if got := viewerURL(log); got != "http://127.0.0.1:41234/?t=9f86d081884c7d659a2feaa0c55ad015" {
		t.Fatalf("viewer link not readable from the log: %q in %q", got, s)
	}
}

// After the flush of a working masking pipe, stderr is discarded, not the
// unmasked file again.
func TestHelperWriteAfterFlush(t *testing.T) {
	if os.Getenv("PENTRAIL_MASK_AFTER_FLUSH") == "" {
		t.Skip("helper process only")
	}
	flush := maskStderr()
	fmt.Fprintln(os.Stderr, "before flush token="+diagSecret)
	flush()
	flush() // idempotent
	fmt.Fprintln(os.Stderr, "after flush token="+diagSecret)
	os.Exit(0)
}

func TestWriteAfterFlushIsDiscarded(t *testing.T) {
	log := filepath.Join(t.TempDir(), "session.log")
	f, err := os.OpenFile(log, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	c := exec.Command(os.Args[0], "-test.run=^TestHelperWriteAfterFlush$")
	c.Env = append(os.Environ(), "PENTRAIL_MASK_AFTER_FLUSH=1")
	c.Stdout, c.Stderr = f, f
	err = c.Run()
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(log)
	s := string(b)
	if strings.Contains(s, diagSecret) || strings.Contains(s, "after flush") || !strings.Contains(s, "before flush token=") {
		t.Fatalf("log %q", s)
	}
}
