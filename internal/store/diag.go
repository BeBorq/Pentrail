package store

import (
	"fmt"
	"io"
	"os"

	"github.com/BeBorq/Pentrail/internal/redact"
)

// diagOut overrides where diagnostics go (tests); nil means the process's
// current os.Stderr, which for background processes is a plain .log file.
var diagOut io.Writer

// diag writes one diagnostic line. Paths and reasons may contain secrets
// (a scan directory named after a credential, a target URL with a token):
// the WHOLE line is masked with the same rules as the evidence before it
// leaves the encrypted database. The real path stays in the database for
// file-system operations; only this human-readable copy is masked.
func diag(format string, args ...any) {
	w := diagOut
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprintln(w, redact.String("pentrail: "+fmt.Sprintf(format, args...)))
}
