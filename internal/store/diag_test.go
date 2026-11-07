package store

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const diagSecret = "SyntheticDiagnosticSecret"

// Codex iteration 03, finding 5: a scan directory named after a credential
// (here "password=SyntheticDiagnosticSecret") leaked into stderr — the plain
// .log file of background processes — through artifact warnings. The
// warning must stay, the secret must not; the real path stays usable inside.
func TestArtifactDiagnosticsDoNotLeakSecrets(t *testing.T) {
	var out bytes.Buffer
	diagOut = &out
	defer func() { diagOut = nil }()
	st := openTemp(t)
	dir := filepath.Join(t.TempDir(), "password="+diagSecret)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.json")
	mustWrite(t, bad, []byte("{unfinished"))
	partial := filepath.Join(dir, "partial.xml")
	mustWrite(t, partial, []byte(`<nmaprun><host><address addr="10.9.1.1" addrtype="ipv4"/></host><host><address addr="10.9.1.2"`))
	artifactRow(t, st, 0, "ffuf", bad)
	artifactRow(t, st, 1, "nmap", partial)
	if _, err := st.IngestArtifacts(1); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if strings.Contains(s, diagSecret) {
		t.Fatalf("secret in diagnostics: %s", s)
	}
	if !strings.Contains(s, "not imported") || !strings.Contains(s, "INCOMPLETE") {
		t.Fatalf("warnings were hidden: %q", s)
	}
	// internally the real path is kept: file operations still work
	if !exists(bad) || exists(partial) {
		t.Fatalf("file handling changed: bad kept=%v partial removed=%v", exists(bad), !exists(partial))
	}
	if a := artifactByPath(t, st, bad); a.Path != bad {
		t.Fatalf("stored path altered: %q", a.Path)
	}
}
