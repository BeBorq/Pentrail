package view

import (
	"os/exec"
	"strings"
	"testing"
)

// 04BL: loading.regression.test.cjs runs the real session-list and timeline
// code of index.html against rejected fetches, HTTP errors, invalid data,
// reads that never settle, Try again and stale/retired renders.
func TestReadFailuresNeverLeaveLoading(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed: loading.regression.test.cjs not run")
	}
	out, err := exec.Command(node, "loading.regression.test.cjs").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "PASS loading 13") {
		t.Fatalf("loading.regression.test.cjs: %v\n%s", err, out)
	}
}
