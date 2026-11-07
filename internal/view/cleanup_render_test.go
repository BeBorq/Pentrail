package view

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The real renderCleanup (extracted from the embedded page) against delayed,
// failed and superseded replies: a retired render must not draw the checklist
// or write a tick (rendercleanup.regression.test.cjs, node).
func TestCleanupRendererOwnsItsSession(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed: cleanup renderer regression not run")
	}
	page := string(indexHTML)
	start := strings.Index(page, "const CLEAN_LABEL")
	end := strings.Index(page, "\n// ---- tabs ----")
	if start < 0 || end <= start {
		t.Fatal("embedded cleanup renderer not found")
	}
	renderer := filepath.Join(t.TempDir(), "renderCleanup.js")
	if err := os.WriteFile(renderer, []byte(page[start:end]), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, "rendercleanup.regression.test.cjs", renderer).CombinedOutput()
	text := string(out)
	if err != nil || strings.Contains(text, "FAIL |") || strings.Count(text, "PASS |") != 11 {
		t.Fatalf("cleanup renderer regression: %v\n%s", err, out)
	}
	t.Log(strings.TrimSpace(text))
}
