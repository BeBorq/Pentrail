package capture

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Codex 04X: `pentrail status` of the new CLI, checked line by line. The
// CLI prints each session as "session=<id> recording=<bool> socket=<path>";
// the path may differ in letter case from the one the test knows (Windows
// paths are case-insensitive: the native run printed it in lower case), so
// FULL cleaned paths are compared case-insensitively — never a basename or a
// fragment. Exactly the expected sessions, each once, all recording.

var statusSessionLine = regexp.MustCompile(`^session=([0-9]+) recording=(true|false) socket=(.+)$`)

func checkStatusSessions(status string, want []string) error {
	return checkStatusSessionsState(status, want, true)
}

// checkStatusSessionsState: exactly the sessions of want, each once, each
// with recording=<recording> (Codex 04Y: also the paused state).
func checkStatusSessionsState(status string, want []string, recording bool) error {
	type entry struct {
		id        int64
		recording bool
		sock      string
	}
	var got []entry
	for _, line := range strings.Split(strings.ReplaceAll(status, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "session=") {
			continue
		}
		m := statusSessionLine.FindStringSubmatch(line)
		if m == nil {
			return fmt.Errorf("status line not a recording session: %q", line)
		}
		id, _ := strconv.ParseInt(m[1], 10, 64)
		got = append(got, entry{id, m[2] == "true", filepath.Clean(m[3])})
	}
	if len(got) != len(want) {
		return fmt.Errorf("%d sessions in status, want %d", len(got), len(want))
	}
	used := make([]bool, len(got))
	ids := map[int64]bool{}
	for _, w := range want {
		w = filepath.Clean(w)
		found := -1
		for i, e := range got {
			if strings.EqualFold(e.sock, w) {
				if found >= 0 {
					return fmt.Errorf("socket %s listed twice", w)
				}
				found = i
			}
		}
		if found < 0 {
			return fmt.Errorf("socket %s not in status", w)
		}
		if used[found] {
			return fmt.Errorf("socket %s matched twice", w)
		}
		used[found] = true
		e := got[found]
		if e.recording != recording {
			return fmt.Errorf("session %d (%s) recording=%t, want %t", e.id, w, e.recording, recording)
		}
		if ids[e.id] {
			return fmt.Errorf("session id %d listed twice", e.id)
		}
		ids[e.id] = true
	}
	return nil
}

func TestCheckStatusSessions(t *testing.T) {
	a, b := `C:\Users\Tester\AppData\Local\Temp\TestUpgrade1\001\.pentrail\run\0123456789abcdef.sock`,
		`C:\Users\Tester\AppData\Local\Temp\TestUpgrade1\001\.pentrail\run\fedcba9876543210.sock`
	head := "enabled=false key_unlocked=false database=c:\\x\\pentrail.db\r\n"
	line := func(id int, rec bool, sock string) string {
		return fmt.Sprintf("session=%d recording=%t socket=%s\r\n", id, rec, sock)
	}
	cases := []struct {
		name, status string
		ok           bool
	}{
		{"both, lower case (as printed natively)", head + line(1, true, strings.ToLower(a)) + line(2, true, strings.ToLower(b)), true},
		{"both, same case", head + line(2, true, b) + line(1, true, a), true},
		{"recording=false", head + line(1, false, a) + line(2, true, b), false},
		{"missing socket", head + line(1, true, a), false},
		{"wrong socket", head + line(1, true, a) + line(2, true, strings.Replace(b, "fedcba", "fedcbb", 1)), false},
		{"same basename, other directory", head + line(1, true, a) + line(2, true, `C:\other\run\fedcba9876543210.sock`), false},
		{"duplicate socket", head + line(1, true, a) + line(2, true, a), false},
		{"extra session", head + line(1, true, a) + line(2, true, b) + line(3, true, `C:\x\run\1111111111111111.sock`), false},
		{"duplicate id", head + line(1, true, a) + line(1, true, b), false},
		{"unavailable session", head + line(1, true, a) + "session=fedcba9876543210.sock unavailable=timeout\r\n", false},
		{"storage failure line", head + line(1, true, a) + line(2, true, b) + "session=2 RECORDING STOPPED after a storage failure: x\r\n", false},
	}
	for _, c := range cases {
		err := checkStatusSessions(c.status, []string{a, b})
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
	paused := head + line(1, false, a) + line(2, false, strings.ToLower(b))
	if err := checkStatusSessionsState(paused, []string{a, b}, false); err != nil {
		t.Errorf("both paused: %v", err)
	}
	if err := checkStatusSessionsState(head+line(1, false, a)+line(2, true, b), []string{a, b}, false); err == nil {
		t.Error("one session still recording was accepted as paused")
	}
}
