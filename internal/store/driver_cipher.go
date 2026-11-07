//go:build sqlcipher

package store

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	sqlitecipher "github.com/mutecomm/go-sqlcipher/v4"
	"path/filepath"
	"sync"
)

// Production build: a self-contained SQLCipher driver (the real SQLCipher
// amalgamation plus a bundled crypto provider). The whole database file is
// encrypted at rest and the key never leaves process memory — no system
// library to install.
//
// Build:
//
//	CGO_ENABLED=1 go build -tags "sqlcipher" ./cmd/pentrail
//
// Keying is done via DSN pragmas so EVERY connection the database/sql pool
// opens is keyed, with an explicit page size, before use. (A bare `PRAGMA key`
// after sql.Open is unsafe: the pool may drop and reopen the connection, and an
// unkeyed reopen fails — or, on a non-codec build, silently reads cleartext.
// The page size must also be pinned, or a reopened database fails to decrypt.)
const cipherPageSize = "4096"

var driverOnce sync.Once

func protectedDriver() {
	driverOnce.Do(func() {
		sql.Register("pentrail-sqlcipher", &sqlitecipher.SQLiteDriver{ConnectHook: func(c *sqlitecipher.SQLiteConn) error {
			_, e := c.Exec("PRAGMA temp_store=MEMORY; PRAGMA cipher_memory_security=ON; PRAGMA secure_delete=ON; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;", nil)
			return e
		}})
	})
}
func openDB(path string, passphrase []byte) (*sql.DB, error) {
	if len(passphrase) > 16384 || bytes.IndexByte(passphrase, 0) >= 0 || !utf8.Valid(passphrase) {
		return nil, fmt.Errorf("passphrase must be valid UTF-8 without NUL and at most 16384 bytes")
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("empty passphrase: refusing to open an encrypted database without a key")
	}

	// CRITICAL SAFETY GATE — run first, independent of the user's file and key.
	// Building with -tags sqlcipher is not by itself a guarantee: if the binary
	// were linked against plain SQLite, the key pragma is ignored and the
	// database is written in CLEARTEXT while looking fine — a pentester would
	// carry a "safe" file full of client credentials. verifyCodec proves the
	// real SQLCipher codec is present before we write anything.
	if err := verifyCodec(); err != nil {
		return nil, err
	}

	// SQLCipher runs its own PBKDF2 over the passphrase (used here as the key).
	protectedDriver()
	absolute, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	slash := filepath.ToSlash(absolute)
	if filepath.VolumeName(absolute) != "" {
		slash = "/" + slash
	}
	u := url.URL{Scheme: "file", Path: slash}
	q := u.Query()
	q.Set("_pragma_key", strings.ReplaceAll(string(passphrase), `"`, `""`))
	q.Set("_pragma_cipher_page_size", cipherPageSize)
	q.Set("_busy_timeout", "5000")
	q.Set("_synchronous", "FULL")
	dsn := u.String() + "?" + q.Encode()

	db, err := sql.Open("pentrail-sqlcipher", dsn)
	if err != nil {
		return nil, err
	}
	// Touch a page so a wrong passphrase fails here, cleanly, instead of deep in
	// schema init. On a new (empty) file this simply succeeds.
	if _, err := db.Exec("SELECT count(*) FROM sqlite_master;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("could not decrypt database (wrong passphrase?): %w", err)
	}
	return db, nil
}

// verifyCodec confirms a genuine SQLCipher codec is linked in, using a throwaway
// in-memory database so the result depends only on the binary, never on the
// user's file or passphrase. On a real codec cipher_version is a non-empty
// version string; on plain SQLite it is empty.
func verifyCodec() error {
	db, err := sql.Open("sqlite3",
		"file::memory:?_pragma_key=codec-selftest&_pragma_cipher_page_size="+cipherPageSize)
	if err != nil {
		return err
	}
	defer db.Close()
	var ver string
	if err := db.QueryRow("PRAGMA cipher_version;").Scan(&ver); err != nil || strings.TrimSpace(ver) == "" {
		return fmt.Errorf("this binary is NOT a real SQLCipher build (cipher_version empty): " +
			"refusing to run — it would write the database in CLEARTEXT")
	}
	return nil
}

// Encrypted reports whether this build encrypts the database at rest.
func Encrypted() bool { return true }

// isBusy reports SQLITE_BUSY / SQLITE_LOCKED: another connection holds a lock.
func isBusy(err error) bool {
	var e sqlitecipher.Error
	if errors.As(err, &e) {
		return e.Code == sqlitecipher.ErrBusy || e.Code == sqlitecipher.ErrLocked
	}
	if err == nil {
		return false
	}
	m := err.Error()
	return strings.Contains(m, "database is locked") || strings.Contains(m, "database table is locked")
}
