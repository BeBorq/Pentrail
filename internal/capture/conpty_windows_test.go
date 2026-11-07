//go:build windows

package capture

import (
	"bytes"
	"os/exec"
	"testing"
	"time"
)

func TestConPTYPassThrough(t *testing.T) {
	shell, e := exec.LookPath("powershell.exe")
	if e != nil {
		t.Fatal(e)
	}
	p, e := startPTY(shell, []string{"-NoProfile", "-Command", `[Console]::Write('BEGIN'+[char]27+']697;token;A'+[char]7+'END')`}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	done := make(chan struct{})
	var out bytes.Buffer
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, e := p.Read(buf)
			if n > 0 {
				out.Write(buf[:n])
				if bytes.Contains(buf[:n], []byte("\x1b[6n")) {
					p.Write([]byte("\x1b[1;1R"))
				}
			}
			if e != nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		p.Kill()
		t.Fatal("timeout")
	}
	code, e := p.Wait()
	if e != nil || code != 0 {
		t.Fatal(code, e)
	}
	t.Logf("ConPTY raw: %q", out.String())
	if !bytes.Contains(out.Bytes(), []byte("\x1b]697;token;A\x07")) {
		t.Fatal("custom marker not passed through ConPTY")
	}
}
