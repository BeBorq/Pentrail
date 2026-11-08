package localipc

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// A fake Windows volume: existing directories with their long and 8.3 short
// spellings (case-insensitive lookup, as on NTFS).
type fakeVolume map[string][2]string // lower(any spelling) -> {long, short}

func newVolume(pairs ...[2]string) fakeVolume {
	v := fakeVolume{}
	for _, p := range pairs {
		v[strings.ToLower(p[0])] = p
		v[strings.ToLower(p[1])] = p
	}
	return v
}

func (v fakeVolume) conv(i int) func(string) (string, error) {
	return func(p string) (string, error) {
		if e, ok := v[strings.ToLower(p)]; ok {
			return e[i], nil
		}
		return "", errors.New("the system cannot find the file specified")
	}
}

var runner = newVolume(
	[2]string{`C:\`, `C:\`},
	[2]string{`C:\Users`, `C:\Users`},
	[2]string{`C:\Users\runneradmin`, `C:\Users\RUNNER~1`},
	[2]string{`C:\Users\runneradmin\AppData`, `C:\Users\RUNNER~1\AppData`},
	[2]string{`C:\Users\runneradmin\AppData\Local\Temp\TestA\001\a\run`, `C:\Users\RUNNER~1\AppData\Local\Temp\TestA\001\a\run`},
	[2]string{`C:\Users\runneradmin\AppData\Local`, `C:\Users\RUNNER~1\AppData\Local`},
	[2]string{`C:\Users\runneradmin\AppData\Local\Temp`, `C:\Users\RUNNER~1\AppData\Local\Temp`},
)

func TestEndpointKeysSameForLongShortAndCase(t *testing.T) {
	long, short := runner.conv(0), runner.conv(1)
	want := `c:\users\runneradmin\appdata\local\temp\testa\001\a\run\0123456789abcdef.sock`
	for _, p := range []string{
		`C:\Users\RUNNER~1\AppData\Local\Temp\TestA\001\a\run\0123456789abcdef.sock`,    // the listener's spelling (TEMP)
		`c:\users\runneradmin\appdata\local\temp\testa\001\a\run\0123456789abcdef.sock`, // dbidentity.Canonical
		`C:\USERS\RUNNERADMIN\AppData\Local\Temp\TestA\001\a\run\0123456789abcdef.sock`,
		`c:\users\runner~1\appdata\local\temp\testa\001\a\run\0123456789abcdef.sock`,
	} {
		if got, _ := endpointKeys(p, long, short); got != want {
			t.Errorf("%s: canonical %q, want %q", p, got, want)
		}
	}
}

func TestEndpointKeysEndpointNotYetExisting(t *testing.T) {
	long, short := runner.conv(0), runner.conv(1)
	// Neither the file nor the directory "new\run" exists yet: the deepest
	// existing ancestor is converted, the rest kept.
	p := `C:\Users\RUNNER~1\AppData\Local\Temp\new\run\x.sock`
	got, _ := endpointKeys(p, long, short)
	if want := `c:\users\runneradmin\appdata\local\temp\new\run\x.sock`; got != want {
		t.Fatalf("canonical %q, want %q", got, want)
	}
	// Nothing exists at all: the given spelling.
	nothing := func(string) (string, error) { return "", errors.New("no") }
	if got, legacy := endpointKeys(`D:\x\y.sock`, nothing, nothing); got != `d:\x\y.sock` || len(legacy) != 0 {
		t.Fatalf("%q %q", got, legacy)
	}
}

// Legacy keys are what an older server computed from the spelling it had.
func TestEndpointKeysLegacyForOldServers(t *testing.T) {
	long, short := runner.conv(0), runner.conv(1)
	longP := `C:\Users\runneradmin\AppData\Local\Temp\TestA\001\a\run\s.sock`
	shortP := `C:\Users\RUNNER~1\AppData\Local\Temp\TestA\001\a\run\s.sock`
	canon, legacy := endpointKeys(longP, long, short)
	// a long-spelled path: its old key equals the canonical one (old clients
	// of a long spelling still reach new servers), the short one is legacy
	if canon != strings.ToLower(longP) || !reflect.DeepEqual(legacy, []string{strings.ToLower(shortP)}) {
		t.Fatalf("long: %q %q", canon, legacy)
	}
	canon2, legacy2 := endpointKeys(shortP, long, short)
	if canon2 != canon || !reflect.DeepEqual(legacy2, []string{strings.ToLower(shortP)}) {
		t.Fatalf("short: %q %q", canon2, legacy2)
	}
	// no aliases: no legacy keys, the key is the old one
	plain := newVolume([2]string{`D:\data`, `D:\data`})
	c3, l3 := endpointKeys(`D:\data\s.sock`, plain.conv(0), plain.conv(1))
	if c3 != `d:\data\s.sock` || len(l3) != 0 {
		t.Fatalf("plain: %q %q", c3, l3)
	}
}

func TestConvertExistingDriveRoot(t *testing.T) {
	v := newVolume([2]string{`C:\`, `C:\`})
	if got := convertExisting(`C:\new.sock`, v.conv(0)); got != `C:\new.sock` {
		t.Fatalf("%q", got)
	}
	if got := convertExisting(`relative`, v.conv(0)); got != `relative` {
		t.Fatalf("%q", got)
	}
}

// An endpoint file that has its own 8.3 alias (a 16-hex ".sock" name is longer
// than 8.3). An older server hashed the short directory and the long file name
// before the file existed; clients that spell the file long or short both keep
// that key as a legacy candidate. Keys for other files are never produced.
func TestEndpointKeysOldServerKeyWhenLeafHasOwnShortAlias(t *testing.T) {
	v := newVolume(
		[2]string{`C:\`, `C:\`},
		[2]string{`C:\Users\runneradmin`, `C:\Users\RUNNER~1`},
		[2]string{`C:\Users\runneradmin\run`, `C:\Users\RUNNER~1\run`},
		[2]string{`C:\Users\runneradmin\run\0123456789abcdef.sock`, `C:\Users\RUNNER~1\run\012345~1.SOC`},
	)
	oldServer := `c:\users\runner~1\run\0123456789abcdef.sock`
	canonWant := `c:\users\runneradmin\run\0123456789abcdef.sock`
	for _, client := range []string{
		`C:\Users\runneradmin\run\0123456789abcdef.sock`, // long leaf (dbidentity.Canonical, Glob)
		`C:\Users\RUNNER~1\run\012345~1.SOC`,             // short leaf
		`C:\Users\RUNNER~1\run\0123456789abcdef.sock`,    // the old server's own spelling
	} {
		canon, legacy := endpointKeys(client, v.conv(0), v.conv(1))
		if canon != canonWant {
			t.Errorf("%s: canonical %q", client, canon)
		}
		found := false
		for _, k := range legacy {
			found = found || k == oldServer
			if !strings.HasSuffix(k, `\0123456789abcdef.sock`) && !strings.HasSuffix(k, `\012345~1.soc`) {
				t.Errorf("%s: legacy key for another file: %q", client, k)
			}
		}
		if !found {
			t.Errorf("%s: old server key %q missing from %q", client, oldServer, legacy)
		}
	}
}

func TestSplitLeaf(t *testing.T) {
	for _, c := range [][4]string{
		{`C:\a\b.sock`, `C:\a`, `\b.sock`, "true"},
		{`C:\b.sock`, `C:\`, `b.sock`, "true"},
		{`b.sock`, ``, ``, "false"},
		{`C:\a\`, ``, ``, "false"},
	} {
		d, l, ok := splitLeaf(c[0])
		if d != c[1] || l != c[2] || (ok != (c[3] == "true")) {
			t.Errorf("%s: %q %q %v", c[0], d, l, ok)
		}
	}
}
