//go:build windows

package capture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/BeBorq/Pentrail/internal/redact"
	"github.com/BeBorq/Pentrail/internal/store"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fiftyCase struct {
	Expression string `json:"expression"`
	Value      string `json:"value"`
}

func flat50(s string) string {
	osc := regexp.MustCompile(`\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`)
	csi := regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	s = osc.ReplaceAllString(s, "")
	s = csi.ReplaceAllString(s, "")
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}
func TestFiftyCommandsEvidence(t *testing.T) {
	bin, home, cli := reviewNative(t)
	control := os.Getenv("PENTRAIL_50_CONTROL_DIR")
	if control == "" {
		t.Skip("set PENTRAIL_50_CONTROL_DIR to run the fifty-command evidence workflow")
	}
	os.WriteFile(filepath.Join(control, "run-root.txt"), []byte(home), 0600)
	var cases map[string][]fiftyCase
	data, e := os.ReadFile(filepath.Join(control, "cases.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(data, &cases); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		t.Log("CLEANUP isolated shell profiles, DB/WAL/SHM and session files scheduled for removal by test runner")
	})
	cli(true, "on")
	profile := filepath.Join(home, "empty-profile.ps1")
	os.WriteFile(profile, []byte("function prompt { 'TEST50> ' }\n"), 0600)
	expected := map[string][]string{}
	commands := map[string][]string{}
	shellList := []string{"powershell", "pwsh", "cmd"}
	if value := os.Getenv("PENTRAIL_50_SHELLS"); value != "" {
		shellList = strings.Split(value, ",")
	}
	for _, shell := range shellList {
		args := []string{"start", "--auto", "--shell", shell}
		if shell != "cmd" {
			args = append(args, "--startup-profile", profile)
		}
		screen := openScreen(t, bin, args)
		screen.wait(t, ";A\a")
		kind := "powershell"
		prefix := "PS50_"
		if shell == "cmd" {
			kind = "cmd"
			prefix = "CMD50_"
		}
		for i, c := range cases[kind] {
			id := fmt.Sprintf("%02d", i+1)
			frame := prefix + id + ":" + c.Value + " :END"
			command := ""
			if shell == "cmd" {
				if c.Expression != "" {
					command = `cmd /D /V:ON /C "set /a P50R=` + c.Expression + ` >nul & echo ` + prefix + id + `:!P50R! :END"`
				} else {
					command = `cmd /D /V:ON /C "set "P50R=` + c.Value + `" & echo ` + prefix + id + `:!P50R! :END"`
				}
			}

			if shell != "cmd" {
				method := "[Console]::WriteLine"
				if i == 48 {
					method = "[Console]::Error.WriteLine"
				}
				command = method + "((('" + prefix + "'+'" + id + ":') + [string](" + c.Expression + ") + ' :END'))"
			}
			before := strings.Count(screen.text(), ";A\a")
			screen.send(t, command)
			until := time.Now().Add(8 * time.Second)
			for time.Now().Before(until) {
				if strings.Contains(flat50(screen.text()), frame) && strings.Count(screen.text(), ";A\a") > before {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !strings.Contains(flat50(screen.text()), frame) {
				t.Fatalf("output mismatch shell=%s n=%s expected=%q tail=%q", shell, id, frame, tail50(screen.text(), 2000))
			}

			expected[shell] = append(expected[shell], redact.String(frame))
			commands[shell] = append(commands[shell], redact.String(command))
			t.Logf("LIVE shell=%s n=%s command=%s expected=%s result=PASS", shell, id, redact.String(command), redact.String(frame))
		}
		screen.exit(t)
		t.Logf("COMPLETED shell=%s commands=50", shell)
	}
	cli(false, "off")
	db := filepath.Join(home, ".pentrail", "pentrail.db")
	st, e := store.Open(db, []byte("synthetic-review-native-key"))
	if e != nil {
		t.Fatal(e)
	}
	sessions, e := st.ListSessions()
	if e != nil {
		t.Fatal(e)
	}
	if len(sessions) != len(shellList) {
		t.Fatalf("sessions=%d", len(sessions))
	}
	total := 0
	summary := map[string]interface{}{}
	var graphID int64
	for _, session := range sessions {
		shell := strings.TrimSuffix(strings.ToLower(filepath.Base(session.Shell)), ".exe")
		raw, missing, e := st.ReadRange(session.ID, 0, session.RawBytes)
		if e != nil || missing != 0 {
			t.Fatal("raw gap", missing, e)
		}
		clean := flat50(string(raw))
		cmds, e := st.ListCommands(session.ID)
		if e != nil {
			t.Fatal(e)
		}
		if len(cmds) != 51 {
			t.Errorf("%s expected 50 test commands plus exit, got %d", shell, len(cmds))
		}
		found := 0
		metadata := 0
		for i, want := range expected[shell] {
			ok := strings.Contains(clean, want)
			if ok {
				found++
			}
			present := false
			for _, c := range cmds {
				if strings.TrimSpace(c.Command) == strings.TrimSpace(commands[shell][i]) {
					present = true
					break
				}
			}
			if present {
				metadata++
			}
			t.Logf("STORED shell=%s n=%02d output=%t command_metadata=%t expected=%s", shell, i+1, ok, present, want)
		}
		if bytes.Contains(raw, []byte("Synthetic50Secret")) {
			at := bytes.Index(raw, []byte("Synthetic50Secret"))
			t.Errorf("synthetic password leaked to DB shell=%s context=%q", shell, raw[max(0, at-120):min(len(raw), at+150)])
		}
		if found != 50 {
			t.Errorf("%s stored outputs=%d/50", shell, found)
		}
		if metadata != 50 {
			t.Errorf("%s stored command metadata=%d/50", shell, metadata)
		}
		n, e := st.ExtractRegex(session.ID)
		if e != nil {
			t.Fatal(e)
		}
		g, e := st.BuildGraph(session.ID)
		if e != nil {
			t.Fatal(e)
		}
		for _, node := range g.Nodes {
			if strings.HasPrefix(node.Label, "37m.") {
				t.Errorf("VT became a graph node: %s", node.Label)
			}
		}
		t.Logf("SUMMARY shell=%s outputs=%d/50 metadata=%d/50 raw_missing=%d raw_bytes=%d extracted=%d graph_nodes=%d graph_edges=%d", shell, found, metadata, missing, session.RawBytes, n, len(g.Nodes), len(g.Edges))
		total += found
		summary[shell] = map[string]interface{}{"outputs": found, "metadata": metadata, "missing": missing, "graph_nodes": len(g.Nodes), "graph_edges": len(g.Edges)}
		if shell == "pwsh" {
			graphID = session.ID
		}
	}
	st.Close()
	if os.Getenv("PENTRAIL_50_NO_UI") == "1" {
		t.Logf("FINAL outputs_verified=%d/%d", total, len(shellList)*50)
		return
	}
	link := strings.TrimSpace(cli(true, "open", "--no-browser"))
	info := map[string]interface{}{"url": link, "home": home, "db": db, "session": graphID, "total_outputs": total, "shells": summary}
	b, _ := json.MarshalIndent(info, "", "  ")
	os.WriteFile(filepath.Join(control, "ui-ready.json"), b, 0600)
	t.Log("UI_READY screenshot can now be captured before cleanup")
	deadline := time.Now().Add(8 * time.Minute)
	for time.Now().Before(deadline) {
		if _, e := os.Stat(filepath.Join(control, "allow-cleanup")); e == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if _, e := os.Stat(filepath.Join(control, "allow-cleanup")); e != nil {
		t.Fatal("screenshot/cleanup handshake timed out")
	}
	t.Log("FINAL outputs_verified=" + strconv.Itoa(total) + "/150; synthetic data cleanup follows")
}
func tail50(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}
