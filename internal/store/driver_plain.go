//go:build !sqlcipher

package store

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// isBusy reports SQLITE_BUSY / SQLITE_LOCKED: another connection holds a lock.
// Matched on SQLite's own messages because the driver's typed error does not
// exist in CGO_ENABLED=0 builds of this development-only configuration.
func isBusy(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	return strings.Contains(m, "database is locked") || strings.Contains(m, "database table is locked")
}

// This is the development/test build: plain SQLite, NO encryption.
// It exists so capture (pillar #1) can be validated without pulling in the
// SQLCipher toolchain. Never run a real engagement on this build.

func openDB(path string, passphrase []byte) (*sql.DB, error) {
	if len(passphrase) > 0 {
		fmt.Fprintln(os.Stderr,
			"pentrail: WARNING — built without the 'sqlcipher' tag; the database is NOT encrypted. "+
				"Rebuild with:  CGO_ENABLED=1 go build -tags sqlcipher ./cmd/pentrail")
	}
	return sql.Open("sqlite3", path)
}

// Encrypted reports whether this build encrypts the database at rest.
func Encrypted() bool { return false }
