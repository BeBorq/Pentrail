package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/BeBorq/Pentrail/internal/store"
)

// Operator notes are private by default: a bundle without IncludeNotes never
// exports them, even if Notes were filled by mistake. With IncludeNotes they
// appear in their own, labelled section/field, escaped and masked.
func TestReportsOmitNotesByDefaultAndShowThemSeparatelyOnRequest(t *testing.T) {
	cmd := int64(2)
	note := store.Note{ID: strings.Repeat("a", 32), SessionID: 1, AnchorKind: store.AnchorCommand, CmdIndex: &cmd,
		AnchorLabel: "command #2: nmap -sV 192.0.2.10", Title: "<script>alert(1)</script> Zażółć",
		Body: "line one\nline <b>two</b> password=NoteSecret99\n**md**", CreatedMs: 1, UpdatedMs: 2, Revision: 3}
	base := Bundle{Session: store.SessionInfo{ID: 1}, Commands: []store.CommandInfo{{Index: 2, Command: "nmap -sV 192.0.2.10"}}}

	leaky := base
	leaky.Notes = []store.Note{note} // filled, but not asked for
	for _, b := range []Bundle{base, leaky} {
		j, err := JSON(b)
		if err != nil || bytes.Contains(j, []byte("operator_notes")) || bytes.Contains(j, []byte("NoteSecret")) || bytes.Contains(j, []byte("Zaż")) {
			t.Fatalf("default JSON carries notes: %v\n%s", err, j)
		}
		h, err := HTML(b)
		if err != nil || bytes.Contains(h, []byte("Operator notes")) || bytes.Contains(h, []byte("alert(1)")) {
			t.Fatalf("default HTML carries notes: %v", err)
		}
		if _, err := CSV(b); err != nil {
			t.Fatalf("default CSV: %v", err)
		}
	}

	with := base
	with.IncludeNotes = true
	with.Notes = []store.Note{note}
	j, err := JSON(with)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Commands      []any `json:"commands"`
		OperatorNotes struct {
			Notice string       `json:"notice"`
			Notes  []store.Note `json:"notes"`
		} `json:"operator_notes"`
	}
	if err := json.Unmarshal(j, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.OperatorNotes.Notes) != 1 || !strings.Contains(v.OperatorNotes.Notice, "NOT captured evidence") || v.OperatorNotes.Notes[0].Title != note.Title || v.OperatorNotes.Notes[0].AnchorLabel != note.AnchorLabel {
		t.Fatalf("JSON notes: %s", j)
	}
	if bytes.Contains(j, []byte("NoteSecret99")) {
		t.Fatal("JSON note not masked")
	}
	h, err := HTML(with)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Operator notes — annotations, not captured evidence", "NOT captured evidence", "&lt;script&gt;alert(1)&lt;/script&gt; Zażółć", "line &lt;b&gt;two&lt;/b&gt;", "command #2: nmap -sV 192.0.2.10", "rev 3"} {
		if !bytes.Contains(h, []byte(want)) {
			t.Fatalf("HTML lacks %q", want)
		}
	}
	if bytes.Contains(h, []byte("<script>alert")) || bytes.Contains(h, []byte("NoteSecret99")) {
		t.Fatal("HTML note not escaped or not masked")
	}
	if _, err := CSV(with); !errors.Is(err, ErrNotesCSV) {
		t.Fatalf("CSV with notes: %v", err)
	}
	empty := base
	empty.IncludeNotes = true
	j, _ = JSON(empty)
	if !bytes.Contains(j, []byte(`"notes": []`)) {
		t.Fatalf("asked for notes but none exist: %s", j)
	}
	h, _ = HTML(empty)
	if !bytes.Contains(h, []byte("no operator notes for this session")) {
		t.Fatal("HTML: empty notes section missing")
	}
}
