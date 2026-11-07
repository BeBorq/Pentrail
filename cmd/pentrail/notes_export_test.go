package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/BeBorq/Pentrail/internal/store"
)

// pentrail report/export: operator notes only with --include-notes; CSV
// refuses them before anything is written.
func TestReportExportIncludeNotesFlag(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "notes.db")
	const pass = "synthetic-export-pass"
	st, err := store.Open(db, []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.StartSession("bash", "synthetic-host", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateNote(id, store.NoteAnchor{}, "active <i>note</i>", "keep password=ExportSecret1"); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateNote(id, store.NoteAnchor{}, "archived note", "set aside")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetNoteArchived(id, a.ID, a.Revision, true); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	sess := strconv.FormatInt(id, 10)
	run := func(f func([]string) error, out string, extra ...string) (string, error) {
		t.Setenv("PENTRAIL_PASSPHRASE", pass)
		args := append([]string{"--db", db, "--session", sess, "--out", filepath.Join(dir, out), "--confirm-plaintext"}, extra...)
		err := f(args)
		b, _ := os.ReadFile(filepath.Join(dir, out))
		return string(b), err
	}
	j, err := run(cmdExport, "default.json")
	if err != nil || strings.Contains(j, "operator_notes") || strings.Contains(j, "active") {
		t.Fatalf("default export: %v\n%s", err, j)
	}
	j, err = run(cmdExport, "notes.json", "--include-notes")
	if err != nil || !strings.Contains(j, `"operator_notes"`) || !strings.Contains(j, "NOT captured evidence") || !strings.Contains(j, "active \\u003ci\\u003enote") || strings.Contains(j, "archived note") || strings.Contains(j, "ExportSecret1") {
		t.Fatalf("export with notes: %v\n%s", err, j)
	}
	if _, err := run(cmdExport, "notes.csv", "--format", "csv", "--include-notes"); err == nil || !strings.Contains(err.Error(), "cannot include operator notes") {
		t.Fatalf("CSV with notes: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.csv")); !os.IsNotExist(err) {
		t.Fatal("a CSV file was written although notes were refused")
	}
	if c, err := run(cmdExport, "default.csv", "--format", "csv"); err != nil || strings.Contains(c, "active") {
		t.Fatalf("default CSV: %v %s", err, c)
	}
	h, err := run(cmdReport, "default.html")
	if err != nil || strings.Contains(h, "Operator notes") || strings.Contains(h, "active") {
		t.Fatalf("default report: %v", err)
	}
	h, err = run(cmdReport, "notes.html", "--include-notes")
	if err != nil || !strings.Contains(h, "Operator notes — annotations, not captured evidence") || !strings.Contains(h, "active &lt;i&gt;note&lt;/i&gt;") || strings.Contains(h, "archived note") || strings.Contains(h, "ExportSecret1") {
		t.Fatalf("report with notes: %v", err)
	}
}
