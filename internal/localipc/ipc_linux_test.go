//go:build linux

package localipc

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A database in a deep engagement folder must still be able to host session
// sockets: sun_path is limited to 108 bytes, and "<db dir>/run/<16 hex>.sock"
// used to fail with "bind: invalid argument".
func TestLongSocketPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), strings.Repeat("engagement-folder-", 6), "run")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "0123456789abcdef.sock")
	if len(path) <= maxSunPath {
		t.Fatalf("test path too short to exercise the limit: %d", len(path))
	}
	ln, err := Listen(path)
	if err != nil {
		t.Fatalf("listen on a %d-byte path: %v", len(path), err)
	}
	defer os.Remove(path)
	defer ln.Close()
	if fi, err := os.Stat(path); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket not created at its real location: %v", err)
	}
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Write([]byte("pong"))
			c.Close()
		}
	}()
	c, err := Dial(path, time.Second)
	if err != nil {
		t.Fatalf("dial a %d-byte path: %v", len(path), err)
	}
	defer c.Close()
	b, _ := io.ReadAll(c)
	if string(b) != "pong" {
		t.Fatalf("got %q", b)
	}
}
