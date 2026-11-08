package localipc

import (
	"strings"
	"testing"
)

// Independent model of a volume that assigns an 8.3 alias to the endpoint
// file itself. Old Listen hashed the short directory plus the original long
// basename before that file existed; creating the marker must not lose it.
func TestIndependentLegacyParentPathSurvivesExistingShortLeaf(t *testing.T) {
	longDir := `C:\Data Long`
	shortDir := `C:\DATALO~1`
	base := `0123456789abcdef.sock`
	volume := newVolume(
		[2]string{`C:\`, `C:\`},
		[2]string{longDir, shortDir},
		[2]string{longDir + `\` + base, shortDir + `\012345~1.SOC`},
	)
	_, legacy := endpointKeys(longDir+`\`+base, volume.conv(0), volume.conv(1))
	want := strings.ToLower(shortDir + `\` + base)
	for _, key := range legacy {
		if key == want {
			return
		}
	}
	t.Fatalf("old server key %q lost after endpoint marker gained its own short basename; got %q", want, legacy)
}
