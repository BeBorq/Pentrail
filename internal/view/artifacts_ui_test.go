package view

import (
	"os/exec"
	"strings"
	"testing"
)

// Codex 04H: the page loads the real artifacts.js and uses it for the
// artifact list (no fallback that turns an error into an empty list), and
// artifacts.test.cjs runs that file (node; skipped where node is absent).
func TestArtifactsUIUsesModuleAndPasses(t *testing.T) {
	page := string(indexHTML)
	for _, want := range []string{`<script src="/artifacts.js"></script>`, "pentrailArtifacts.load(fetch,activeSession)", "pentrailArtifacts.render(document,arts,"} {
		if !strings.Contains(page, want) {
			t.Fatalf("index.html lacks %q", want)
		}
	}
	if strings.Contains(page, "r.ok?r.json():[]") || strings.Contains(page, ".catch(()=>[])") {
		t.Fatal("index.html still turns a failed artifact request into an empty list")
	}
	if len(artifactsJS) == 0 {
		t.Fatal("artifacts.js not embedded")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed: artifacts.test.cjs not run")
	}
	out, err := exec.Command(node, "artifacts.test.cjs").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "PASS artifacts") {
		t.Fatalf("artifacts.test.cjs: %v\n%s", err, out)
	}
	t.Log(strings.TrimSpace(string(out)))
}
