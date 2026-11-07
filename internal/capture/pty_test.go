//go:build linux

package capture

import "testing"

// A marker-supplied artifact path must be confined to the session directory,
// since the marker rides the same stream as untrusted output.
func TestUnderDir(t *testing.T) {
	dir := "/home/u/.pentrail/artifacts/1"
	cases := []struct {
		path string
		ok   bool
	}{
		{"/home/u/.pentrail/artifacts/1/nmap-1.xml", true},
		{"/home/u/.pentrail/artifacts/1/sub/x.json", true},
		{"/etc/passwd", false},
		{"/home/u/.pentrail/artifacts/1/../2/evil.xml", false},
		{"/home/u/.pentrail/artifacts/1/../../secret", false},
		{"/home/u/.pentrail/artifacts/10/x", false}, // sibling prefix must not pass
		{"", false},
	}
	for _, c := range cases {
		if got := underDir(dir, c.path); got != c.ok {
			t.Errorf("underDir(%q) = %v, want %v", c.path, got, c.ok)
		}
	}
	if underDir("", "/anything") {
		t.Error("empty dir must reject everything")
	}
}
