//go:build windows

package capture

import (
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func reviewNative(t *testing.T) (string, string, func(bool, ...string) string) {
	t.Helper()
	bin := os.Getenv("PENTRAIL_TEST_BINARY")
	if bin == "" {
		t.Skip("set CLI binary")
	}
	bin = filepath.Clean(bin)
	home := t.TempDir()
	for k, v := range map[string]string{"USERPROFILE": home, "HOME": home, "LOCALAPPDATA": filepath.Join(home, "Local"), "APPDATA": filepath.Join(home, "Roaming"), "PENTRAIL": "", "PENTRAIL_SOCKET": "", "PENTRAIL_SESSION": "", "PENTRAIL_PASSPHRASE": "", "PENTRAIL_DB": ""} {
		t.Setenv(k, v)
	}
	cli := func(key bool, args ...string) string {
		t.Helper()
		c := exec.Command(bin, args...)
		c.Env = os.Environ()
		if key {
			c.Env = append(c.Env, "PENTRAIL_PASSPHRASE=synthetic-review-native-key")
		}
		b, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("%v: %v %s", args, e, b)
		}
		return string(b)
	}
	t.Cleanup(func() {
		c := exec.Command(bin, "off")
		c.Env = os.Environ()
		c.Run()
		files, _ := filepath.Glob(filepath.Join(home, ".pentrail/run/*.pid"))
		for _, p := range files {
			b, _ := os.ReadFile(p)
			id, e := strconv.Atoi(string(b))
			if e != nil {
				continue
			}
			h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(id))
			if e != nil {
				continue
			}
			buf := make([]uint16, 32768)
			n := uint32(len(buf))
			if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
				name := windows.UTF16ToString(buf[:n])
				if strings.EqualFold(name, bin) || strings.HasPrefix(strings.ToLower(name), strings.ToLower(home+string(filepath.Separator))) {
					windows.TerminateProcess(h, 0)
					windows.WaitForSingleObject(h, 10000)
				}
			}
			windows.CloseHandle(h)
		}
	})
	return bin, home, cli
}
func TestReviewNewWindowMustNotTrustInheritedFlag(t *testing.T) {
	bin, home, cli := reviewNative(t)
	profile := filepath.Join(home, "profile.ps1")
	os.WriteFile(profile, []byte("Write-Output 'REVIEW_PROFILE_READY'\n"), 0600)
	cli(false, "setup", "powershell", "--profile", profile)
	cli(true, "on")
	a := openScreen(t, bin, []string{"start", "--auto", "--shell", "cmd"})
	a.wait(t, ";A\a")
	paths, _ := filepath.Glob(filepath.Join(home, ".pentrail/run/*.sock"))
	if len(paths) != 2 {
		t.Logf("endpoints %v", paths)
	}
	var original string
	for _, p := range paths {
		if filepath.Base(p) != "key-agent.sock" {
			original = p
		}
	}
	t.Setenv("PENTRAIL", "1")
	t.Setenv("PENTRAIL_SOCKET", original)
	t.Setenv("PENTRAIL_SESSION", "1")
	shell, _ := exec.LookPath("powershell.exe")
	fresh := openScreen(t, shell, []string{"-NoProfile", "-NoLogo"})
	fresh.send(t, ". '"+strings.ReplaceAll(profile, "'", "''")+"'")
	fresh.wait(t, "REVIEW_PROFILE_READY")
	fresh.send(t, "Write-Output ('NEW_' + 'WINDOW_ONLY')")
	fresh.wait(t, "NEW_WINDOW_ONLY")
	status := cli(false, "status")
	t.Log(status)
	if strings.Count(status, "recording=true") != 2 {
		t.Fatal("independent new window inherited PENTRAIL=1 and was silently not recorded")
	}
}
func TestReviewWindowsDetachShortcut(t *testing.T) {
	bin, _, _ := reviewNative(t)
	t.Setenv("PENTRAIL_PASSPHRASE", "synthetic-review-native-key")
	screen := openScreen(t, bin, []string{"start", "--shell", "cmd"})
	screen.wait(t, ";A\a")
	screen.p.Write([]byte{0x1c})
	select {
	case <-screen.done:
		t.Log("detached successfully")
	case <-time.After(3 * time.Second):
		t.Fatalf("Ctrl-backslash did not detach the real ConPTY client: %q", screen.text())
	}
}
