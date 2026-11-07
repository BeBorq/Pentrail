//go:build windows

package capture

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Codex 04F baseline, native: the same output as TestNativeCMDLongOutputWithoutLF
// (PENTRAIL_BIG_MIB, default 8 MiB without LF, `type` in cmd.exe) read from
// ConPTY WITHOUT the recorder — no session server, no observer, no redactor,
// no store, no client — only reading the pseudoconsole as fast as it gives
// output. Then every recorder stage alone on exactly those reads
// (measureStages: redaction only; durable write per read; per batch).
// Synthetic data in this test's TempDir.
func TestNativeConPTYBaselineNoRecorder(t *testing.T) {
	mib := 8
	if s := os.Getenv("PENTRAIL_BIG_MIB"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			mib = v
		}
	}
	comspec := os.Getenv("ComSpec")
	if comspec == "" {
		comspec = filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	}
	big := filepath.Join(t.TempDir(), "big.txt")
	const abc = "abcdefghijklmnopqrstuvwxyz0123456789"
	content := make([]byte, mib<<20)
	for i := range content {
		content[i] = abc[(i*7+i/97)%len(abc)]
	}
	if err := os.WriteFile(big, content, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := startPTY(comspec, []string{"/D", "/Q", "/C", `type "` + big + `"`}, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	type res struct {
		chunks [][]byte
		err    error
	}
	done := make(chan res, 1)
	t0 := time.Now()
	go func() {
		var r res
		for {
			b := make([]byte, 32*1024)
			n, err := p.Read(b)
			if n > 0 {
				r.chunks = append(r.chunks, b[:n])
				if bytes.Contains(b[:n], []byte("\x1b[6n")) {
					p.Write([]byte("\x1b[1;1R")) // ConPTY's cursor query, as a terminal answers it
				}
			}
			if err != nil {
				r.err = err
				done <- r
				return
			}
		}
	}()
	var r res
	select {
	case r = <-done:
	case <-time.After(10 * time.Minute):
		p.Kill()
		t.Fatal("ConPTY baseline did not finish in 10 min")
	}
	d := time.Since(t0)
	n, small := 0, 0
	for _, c := range r.chunks {
		n += len(c)
		if len(c) < 256 {
			small++
		}
	}
	var all []byte
	for _, c := range r.chunks {
		all = append(all, c...)
	}
	rows, cursorLed := rowShapes(all)
	t.Logf("BASELINE windows ConPTY only (no recorder): %d MiB file -> %d bytes in %d reads (<256B: %d), %v (%.2f MiB/s), end %v; %d lines, %d start with a cursor sequence",
		mib, n, len(r.chunks), small, d.Round(time.Millisecond), float64(n)/(1<<20)/d.Seconds(), r.err, rows, cursorLed)
	if n < mib<<20 {
		t.Fatalf("ConPTY delivered %d bytes for a %d-byte file", n, mib<<20)
	}
	measureStages(t, "windows", r.chunks)
}
