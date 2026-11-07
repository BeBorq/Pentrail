// Package capture is Layer 1: the PTY wrapper.
//
// Its one job is pillar #1 — run the user's shell inside a pseudoterminal we
// control, pass every byte through untouched and with no added latency, and
// persist the raw output stream. It does not understand content. Command
// segmentation (the OSC-133 parser) rides alongside as a best-effort observer
// that can be disabled on the fly without affecting the terminal.
package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BeBorq/Pentrail/internal/store"
)

type Options struct {
	Shell      string
	Args       []string
	Store      *store.Store
	DatabaseID string
	SessionID  int64
	// ArtifactDir is the only directory an ARTIFACT marker may point into. The
	// marker arrives on the same stream as untrusted tool/remote output, so a
	// path outside this directory is rejected (it is not treated as evidence).
	ArtifactDir string
	// MarkerToken is the per-session secret the hook embeds in every marker;
	// the parser ignores any marker without it.
	MarkerToken string
}

// underDir reports whether path is inside dir. It applies a textual check
// (rejecting ".." escapes) and, when the path or dir exist on disk, re-checks
// the symlink-resolved real paths so a symlinked component cannot escape.
func underDir(dir, path string) bool {
	if dir == "" {
		return false
	}
	base := filepath.Clean(dir)
	if r, err := filepath.EvalSymlinks(base); err == nil {
		base = r
	}
	contains := func(root, p string) bool {
		rel, err := filepath.Rel(root, p)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	p := filepath.Clean(path)
	if !contains(base, p) {
		return false // textual floor
	}
	// If it resolves on disk, the real path must still be inside (catches a
	// symlinked directory component pointing outside the session dir).
	if r, err := filepath.EvalSymlinks(p); err == nil && !contains(base, r) {
		return false
	}
	return true
}

// feedSafely runs the parser with a panic guard. If the parser ever panics,
// capture continues with segmentation turned off for the rest of the session;
// the raw log and the live terminal are unaffected.
func feedSafely(p *Parser, b []byte, off int64) (disabled bool) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, "pentrail: OSC parser panicked, disabling segmentation (raw capture continues):", r)
			disabled = true
		}
	}()
	p.Feed(b, off)
	return false
}

// OutputMapping names the Windows rendered-VT limitation explicitly.
func OutputMapping(shell string) string {
	switch strings.ToLower(filepath.Base(shell)) {
	case "powershell.exe", "pwsh.exe", "cmd.exe":
		return "conpty-session"
	}
	return ""
}
