package main

import (
	"bufio"
	"os"

	"github.com/BeBorq/Pentrail/internal/redact"
)

// maskStderr routes this process's stderr through the evidence masking rules
// before it reaches the real stderr. Background processes (session server,
// viewer, key agent) have a plain, unencrypted .log file as stderr; their
// diagnostics can contain paths and reasons with secrets (a scan directory
// named after a credential, a target URL with a token). Warnings are kept —
// only the secret parts are masked. Functional output (the viewer link with
// its access token) goes to stdout and is not touched. A Go runtime crash
// trace is written to the original file descriptor directly (not masked,
// but never lost). The returned function flushes.
//
// Fail closed (Codex 04F): if the masking pipe cannot be created, nothing
// that could not be masked is written — stderr is discarded and one fixed
// notice (no path, no reason text) says so; and after the flush stderr is
// discarded too, never the unmasked file again. Discarding never blocks.
func maskStderr() func() {
	real := os.Stderr
	pr, pw, err := osPipe()
	if err != nil {
		real.WriteString("pentrail: diagnostics suppressed: masking is unavailable\n")
		os.Stderr = discardStderr()
		return func() {}
	}
	os.Stderr = pw
	done := make(chan struct{})
	go func() {
		defer close(done)
		r := bufio.NewReader(pr)
		for {
			line, err := r.ReadString('\n')
			if line != "" {
				real.WriteString(redact.String(line))
			}
			if err != nil {
				return
			}
		}
	}()
	flushed := false
	return func() {
		if flushed {
			return
		}
		flushed = true
		os.Stderr = discardStderr()
		pw.Close()
		<-done
		pr.Close()
	}
}

// osPipe is os.Pipe; tests replace it to force the failure.
var osPipe = os.Pipe

// discardStderr: the null device, or a nil *os.File (writes then fail with
// an error and go nowhere) if even that cannot be opened.
func discardStderr() *os.File {
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return nil
	}
	return f
}
