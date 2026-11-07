package view

import (
	"os/exec"
	"strings"
	"testing"
)

// 04BM: reads.regression.test.cjs runs the real graph, cleanup and timeline
// code of index.html and the real xref.js, cleanup.js, artifacts.js and
// notes.js against failed, invalid and never-settling reads.
func TestRemainingReadsAreBoundedAndReported(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed: reads.regression.test.cjs not run")
	}
	out, err := exec.Command(node, "reads.regression.test.cjs").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "PASS reads 15") {
		t.Fatalf("reads.regression.test.cjs: %v\n%s", err, out)
	}
}
