//go:build windows

package capture

import (
	"bytes"
	"github.com/BeBorq/Pentrail/internal/store"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRapidOffOnWaitsForOldAgent(t *testing.T) {
	_, _, cli := reviewNative(t)
	for i := 0; i < 6; i++ {
		cli(true, "on")
		cli(false, "off")
	}
	t.Log("RAPID_OFF_ON cycles=6/6 old_agent_released=PASS")
}

func TestNativeCaptureRecoveryAfterKill(t *testing.T) {
	bin, home, cli := reviewNative(t)
	profile := filepath.Join(home, "profile.ps1")
	if e := os.WriteFile(profile, []byte("function prompt {'CRASH> '}"), 0600); e != nil {
		t.Fatal(e)
	}
	cli(true, "on")
	screen := openScreen(t, bin, []string{"start", "--auto", "--shell", "powershell", "--startup-profile", profile})
	screen.wait(t, ";A\a")
	command := "[Console]::Write(('CRASH_'+'PUBLIC_żółć')); Start-Sleep -Seconds 60"
	screen.send(t, command)
	screen.wait(t, "CRASH_PUBLIC_żółć")
	// No flush or graceful close: the displayed bytes must already be committed.
	files, e := filepath.Glob(filepath.Join(home, ".pentrail/run/*.pid"))
	var sessionFiles []string
	for _, p := range files {
		if filepath.Base(p) != "key-agent.pid" {
			sessionFiles = append(sessionFiles, p)
		}
	}
	files = sessionFiles
	if e != nil || len(files) != 1 {
		t.Fatal(files, e)
	}
	b, e := os.ReadFile(files[0])
	if e != nil {
		t.Fatal(e)
	}
	pid, e := strconv.Atoi(strings.TrimSpace(string(b)))
	if e != nil {
		t.Fatal(e)
	}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(pid))
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(h)
	image := make([]uint16, 32768)
	n := uint32(len(image))
	if e = windows.QueryFullProcessImageName(h, 0, &image[0], &n); e != nil || !strings.EqualFold(windows.UTF16ToString(image[:n]), bin) {
		t.Fatal("unexpected process", e)
	}
	if e = windows.TerminateProcess(h, 99); e != nil {
		t.Fatal(e)
	}
	if result, e := windows.WaitForSingleObject(h, 10000); e != nil || result != windows.WAIT_OBJECT_0 {
		t.Fatal("capture did not stop", result, e)
	}
	st, e := store.Open(filepath.Join(home, ".pentrail/pentrail.db"), []byte("synthetic-review-native-key"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	sessions, e := st.ListSessions()
	if e != nil || len(sessions) != 1 || sessions[0].Recoveries != 1 || sessions[0].PendingBytes != 0 {
		t.Fatal("recovery audit", sessions, e)
	}
	raw, missing, e := st.ReadRange(sessions[0].ID, 0, sessions[0].RawBytes)
	if e != nil || missing != 0 || !strings.Contains(flat50(string(raw)), "CRASH_PUBLIC_żółć") {
		t.Fatal("displayed partial output lost", string(raw), missing, e)
	}
	cmds, e := st.ListCommands(sessions[0].ID)
	if e != nil || len(cmds) != 1 || cmds[0].Command != command || cmds[0].Complete {
		t.Fatal("running command lost", cmds, e)
	}
	t.Log("NATIVE_CONPTY_KILL no_flush=PASS displayed_partial_recovered=PASS unicode_exact=PASS command_saved=PASS missing=0")
}

func TestRunningCommandAndPartialOutputCommittedToFile(t *testing.T) {
	bin, home, cli := reviewNative(t)
	profile := filepath.Join(home, "profile.ps1")
	os.WriteFile(profile, []byte("function prompt {'PERSIST> '}"), 0600)
	cli(true, "on")
	screen := openScreen(t, bin, []string{"start", "--auto", "--shell", "powershell", "--startup-profile", profile})
	screen.wait(t, ";A\a")
	command := "[Console]::Write('PERSIST_PARTIAL'); Start-Sleep -Seconds 6; [Console]::WriteLine('_DONE')"
	screen.send(t, command)
	screen.wait(t, ";C\a")
	time.Sleep(150 * time.Millisecond)
	cli(false, "flush")
	path := filepath.Join(home, ".pentrail", "pentrail.db")
	st, e := store.Open(path, []byte("synthetic-review-native-key"))
	if e != nil {
		t.Fatal(e)
	}
	sessions, _ := st.ListSessions()
	if len(sessions) != 1 {
		t.Fatal(sessions)
	}
	id := sessions[0].ID
	cmds, e := st.ListCommands(id)
	if e != nil || len(cmds) != 1 || cmds[0].Command != command || cmds[0].EndedMs != 0 {
		t.Fatal("running command missing from file", cmds, e)
	}
	data, missing, e := st.ReadRange(id, cmds[0].OutStartOff, sessions[0].RawBytes)
	st.Close()
	if e != nil || missing != 0 || !bytes.Contains(data, []byte("PERSIST_PARTIAL")) {
		t.Fatal("partial output not committed", string(data), missing, e)
	}
	screen.wait(t, "PERSIST_PARTIAL_DONE")
	screen.exit(t)
	cli(false, "off")
	st, e = store.Open(path, []byte("synthetic-review-native-key"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	sessions, _ = st.ListSessions()
	data, missing, e = st.ReadRange(id, 0, sessions[0].RawBytes)
	cmds, _ = st.ListCommands(id)
	if e != nil || missing != 0 || !strings.Contains(string(data), "PERSIST_PARTIAL_DONE") || len(cmds) != 2 || cmds[0].EndedMs == 0 || cmds[1].Command != "exit" {
		t.Fatal("final data missing or duplicated", missing, e, cmds)
	}
	t.Log("running command and partial output readable from a separately reopened encrypted DB; final output exact; one command row")
}
