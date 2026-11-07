//go:build linux

package capture

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Codex 04F baseline on Linux (NOT a Windows result): the same amount of
// ConPTY-shaped output read from a PTY without the recorder, then each
// recorder stage alone (measureStages).
func TestOutputPathBaselineLinux(t *testing.T) {
	mib := 2
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
	big := filepath.Join(t.TempDir(), "big.txt")
	if err := os.WriteFile(big, content, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := startPTY("/bin/sh", []string{"-c", "cat " + big}, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var chunks [][]byte
	n := 0
	t0 := time.Now()
	for {
		b := make([]byte, 32*1024)
		k, err := p.Read(b)
		if k > 0 {
			chunks = append(chunks, b[:k])
			n += k
		}
		if err != nil {
			break
		}
	}
	d := time.Since(t0)
	t.Logf("BASELINE linux PTY only (no recorder): %d bytes in %d reads, %v (%.1f MiB/s)", n, len(chunks), d.Round(time.Millisecond), float64(n)/(1<<20)/d.Seconds())
	measureStages(t, "linux", chunks)
}
