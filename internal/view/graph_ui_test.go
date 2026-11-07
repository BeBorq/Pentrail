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

// Exercise the shipped scripts and the renderer extracted from embedded HTML.
func TestGraphUIRegression(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed: graph UI regression not run")
	}
	run := func(want int, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, node, args...).CombinedOutput()
		text := string(out)
		if err != nil || strings.Contains(text, "FAIL |") || (want > 0 && strings.Count(text, "PASS |") != want) {
			t.Fatalf("graph UI regression: %v\n%s", err, out)
		}
		t.Log(strings.TrimSpace(text))
	}
	run(0, "graph.test.cjs")
	run(18, "graph.regression.test.cjs", ".")
	page := string(indexHTML)
	start := strings.Index(page, "let graphRequest=0;")
	end := strings.Index(page, "\nloadSessions();")
	if start < 0 || end <= start {
		t.Fatal("embedded graph renderer not found")
	}
	renderer := filepath.Join(t.TempDir(), "renderGraph.js")
	if err := os.WriteFile(renderer, []byte(page[start:end]), 0600); err != nil {
		t.Fatal(err)
	}
	run(16, "rendergraph.regression.test.cjs", renderer)
}
