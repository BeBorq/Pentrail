package hooks

import (
	"strings"
	"testing"
)

func TestPowerShellAutoStartBlock(t *testing.T) {
	b := PowerShellAutoStart(`C:\Users\a b\it's\pentrail.exe`, `C:\Program Files\PowerShell\7\pwsh.exe`, "")
	for _, want := range []string{
		`$__ptBinDir = 'C:\Users\a b\it''s'`,
		`& 'C:\Users\a b\it''s\pentrail.exe' __auto-check`,
		`'cwa'`, `'ec'`, `'commandwithargs'`, `'workingdirectory'`,
	} {
		if !strings.Contains(b, want) {
			t.Fatalf("missing %q in\n%s", want, b)
		}
	}
	if dirOf(`C:\pentrail.exe`) != `C:\` || dirOf(`C:\x\y.exe`) != `C:\x` {
		t.Fatal("dirOf")
	}
}
