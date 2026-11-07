package report

import (
	"strings"
	"testing"

	"github.com/BeBorq/Pentrail/internal/store"
)

// A partial or skipped artifact must be visible in the deliverables, not only
// on the stderr of a background process.
func TestArtifactStatusInReportAndExport(t *testing.T) {
	b := Bundle{Version: "t", Artifacts: []store.ArtifactInfo{
		{CmdIndex: 3, Tool: "nmap", Path: "/a/nmap.xml", State: store.ArtImportedPartial, Partial: true, Detail: "damaged tail masked"},
		{CmdIndex: 4, Tool: "nuclei", Path: "/a/n.jsonl", State: store.ArtTooLarge, Detail: "the file has 67108865 B"},
		{CmdIndex: 5, Tool: "ffuf", Path: "/a/f.json", State: store.ArtImported, CleanupPending: true, CleanupDetail: "could not remove the plaintext copy, will retry: busy"},
	}}
	html, err := HTML(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"imported PARTIALLY", "damaged tail masked", "skipped — too large", "67108865", "Plaintext copy waiting for deletion", "will retry"} {
		if !strings.Contains(string(html), want) {
			t.Fatalf("HTML report misses %q", want)
		}
	}
	js, err := JSON(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"artifacts"`, `"imported_partial"`, `"partial": true`, `"skipped_too_large"`, `"cleanup_pending": true`} {
		if !strings.Contains(string(js), want) {
			t.Fatalf("JSON export misses %s", want)
		}
	}
}

// A command whose end was not observed is never shown with an exit status.
func TestReportUnobservedCommandEnd(t *testing.T) {
	b := Bundle{Version: "t", Commands: []store.CommandInfo{
		{Index: 0, Command: "echo ok", Complete: true, ExitCode: 0},
		{Index: 1, Command: "long-scan", ExitCode: -1, EndReason: store.EndSessionEnded},
	}}
	html, err := HTML(b)
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	if !strings.Contains(s, "? (session ended while it ran)") || strings.Contains(s, `<span class="bad">-1</span>`) {
		t.Fatalf("unobserved end not labelled: %s", s)
	}
}
