//go:build linux

package capture

import (
	"bytes"
	"strings"
	"testing"

	"github.com/BeBorq/Pentrail/internal/sessionio"
	"github.com/BeBorq/Pentrail/internal/store"
)

// Codex iteration 02, finding 3 (all shells): the shell ends while a command
// is still open (C marker seen, no D: `exit`, a closed terminal, a killed
// shell). The command must be closed at the end of the captured output,
// marked as not observed, exit status unknown — not left with EndedAt=0.
func TestSessionEOFClosesOpenCommand(t *testing.T) {
	st, id, db, sock := sessionStore(t)
	const tok = "eof-test-token"
	script := `printf '\033]697;` + tok + `;A\007$ '; ` +
		`printf '\033]697;` + tok + `;CMD;%s\007' "$(printf 'echo first' | base64)"; ` +
		`printf '\033]697;` + tok + `;C\007first\r\n\033]697;` + tok + `;D;0\007'; ` +
		`printf '\033]697;` + tok + `;A\007$ '; ` +
		`printf '\033]697;` + tok + `;CMD;%s\007' "$(printf 'long-scan' | base64)"; ` +
		`printf '\033]697;` + tok + `;C\007partial-scan-output\r\n'; sleep 0.2; printf 'last-line'`
	finished := make(chan error, 1)
	go func() {
		finished <- RunServer(Options{Shell: "/bin/sh", Args: []string{"-c", script}, Store: st, SessionID: id, MarkerToken: tok}, sock)
	}()
	c := sessionConnect(t, sock)
	defer c.Close()
	var screen bytes.Buffer
	if err := sessionio.Receive(c, &screen); err != nil {
		t.Fatalf("session result: %v", err)
	}
	if err := awaitServer(t, finished); err != nil {
		t.Fatal(err)
	}
	re, err := store.Open(db, []byte("session-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer re.Close()
	sessions, _ := re.ListSessions()
	cmds, err := re.ListCommands(id)
	if err != nil || len(cmds) != 2 {
		t.Fatalf("commands: %+v %v", cmds, err)
	}
	first, open := cmds[0], cmds[1]
	if !first.Complete || first.EndReason != "" || first.ExitCode != 0 {
		t.Fatalf("observed command: %+v", first)
	}
	var raw int64
	for _, s := range sessions {
		if s.ID == id {
			raw = s.RawBytes
		}
	}
	if open.Command != "long-scan" || open.EndedMs == 0 || open.OutEndOff != raw || open.EndReason != store.EndSessionEnded {
		t.Fatalf("open command not closed at EOF (raw end %d): %+v", raw, open)
	}
	if open.Complete || open.ExitCode != -1 {
		t.Fatalf("unknown exit status presented as known: %+v", open)
	}
	data, missing, err := re.ReadRange(id, open.OutStartOff, open.OutEndOff)
	if err != nil || missing != 0 || !strings.Contains(string(data), "partial-scan-output") || !strings.HasSuffix(string(data), "last-line") {
		t.Fatalf("range of the open command: %q missing=%d err=%v", data, missing, err)
	}
}
