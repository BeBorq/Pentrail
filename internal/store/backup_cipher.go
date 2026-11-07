//go:build sqlcipher

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/BeBorq/Pentrail/internal/privatefs"
	"github.com/BeBorq/Pentrail/internal/redact"
	"io"
	"os"
	"time"
)

func integrity(db *sql.DB) error {
	rows, e := db.Query("PRAGMA cipher_integrity_check")
	if e != nil {
		return e
	}
	for rows.Next() {
		var msg string
		if e = rows.Scan(&msg); e != nil {
			rows.Close()
			return e
		}
		rows.Close()
		return errors.New("encrypted page integrity check failed")
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	var state string
	if e = db.QueryRow("PRAGMA integrity_check").Scan(&state); e != nil {
		return e
	}
	if state != "ok" {
		return errors.New("database integrity check failed")
	}
	rows, e = db.Query("PRAGMA foreign_key_check")
	if e != nil {
		return e
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("foreign key integrity check failed")
	}
	return rows.Err()
}
func VerifyFile(path string, key []byte) error {
	if _, e := os.Stat(path); e != nil {
		return e
	}
	db, e := openDB(path, key)
	if e != nil {
		return e
	}
	defer db.Close()
	return integrity(db)
}

// BackupFile takes a consistent encrypted snapshot, validates it, and publishes
// a new private file atomically. It never copies only the main file of a WAL DB.
func BackupFile(source, dest string, key []byte) (digest string, rerr error) {
	if len(key) == 0 {
		return "", errors.New("backup requires a key")
	}
	if _, e := os.Stat(source); e != nil {
		return "", e
	}
	f, e := privatefs.NewTemp(dest)
	if e != nil {
		return "", e
	}
	temp := f.Name()
	f.Close()
	defer func() {
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			_ = os.Remove(temp + suffix)
		}
	}()
	db, e := openDB(source, key)
	if e != nil {
		return "", e
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn, e := db.Conn(ctx)
	if e != nil {
		return "", e
	}
	defer conn.Close()
	if _, e = conn.ExecContext(ctx, "PRAGMA foreign_keys=OFF"); e != nil {
		return "", e
	}
	if _, e = conn.ExecContext(ctx, "ATTACH DATABASE ? AS protected_backup KEY ?", temp, string(key)); e != nil {
		return "", e
	}
	attached := true
	defer func() {
		if attached {
			_, _ = conn.ExecContext(context.Background(), "DETACH DATABASE protected_backup")
		}
	}()
	tx, e := conn.BeginTx(ctx, nil)
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "SELECT sqlcipher_export('protected_backup')"); e != nil {
		return "", e
	}
	if e = sanitizeBackupCheckpoints(ctx, tx); e != nil {
		return "", e
	}
	if e = tx.Commit(); e != nil {
		return "", e
	}
	if _, e = conn.ExecContext(ctx, "DETACH DATABASE protected_backup"); e != nil {
		return "", e
	}
	attached = false
	target, e := openDB(temp, key)
	if e != nil {
		return "", e
	}
	// Rebuild pages after removing original pending bytes. Never publish a
	// backup with obsolete checkpoint payloads in its freelist.
	if _, e = target.Exec("VACUUM"); e != nil {
		target.Close()
		return "", e
	}
	if e = integrity(target); e != nil {
		target.Close()
		return "", e
	}
	if e = target.Close(); e != nil {
		return "", e
	}
	file, e := os.OpenFile(temp, os.O_RDWR, 0)
	if e != nil {
		return "", e
	}
	if e = file.Sync(); e != nil {
		file.Close()
		return "", e
	}
	if e = file.Close(); e != nil {
		return "", e
	}
	file, e = os.Open(temp)
	if e != nil {
		return "", e
	}
	h := sha256.New()
	_, e = io.Copy(h, file)
	file.Close()
	if e != nil {
		return "", e
	}
	if e = privatefs.Publish(temp, dest); e != nil {
		return "", fmt.Errorf("publishing backup: %w", e)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sanitizeBackupCheckpoints(ctx context.Context, tx *sql.Tx) error {
	var exists int
	if e := tx.QueryRowContext(ctx, "SELECT count(*) FROM protected_backup.sqlite_master WHERE type='table' AND name='capture_checkpoints'").Scan(&exists); e != nil {
		return e
	}
	if exists == 0 {
		return nil
	}
	rows, e := tx.QueryContext(ctx, "SELECT session_id,state FROM protected_backup.capture_checkpoints")
	if e != nil {
		return e
	}
	type pending struct {
		id    int64
		state []byte
	}
	var all []pending
	for rows.Next() {
		var p pending
		if e = rows.Scan(&p.id, &p.state); e != nil {
			rows.Close()
			return e
		}
		all = append(all, p)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, p := range all {
		if len(p.state) > 200*1024 {
			return errors.New("oversized backup checkpoint")
		}
		var cp captureCheckpoint
		if e = json.Unmarshal(p.state, &cp); e != nil {
			return e
		}
		stream, err := redact.Restore(cp.Stream)
		if err != nil {
			return err
		}
		clean := stream.Finish()
		if len(clean) > 0 {
			if _, e = tx.ExecContext(ctx, `INSERT INTO protected_backup.raw_chunks(session_id,seq,ts,byte_offset,data,redacted_bytes) VALUES(?,?,?,?,?,?)`, p.id, cp.Seq, time.Now().UnixNano(), cp.Offset, clean, stream.Changed-cp.Accounted); e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, `UPDATE protected_backup.commands SET out_end_off=MAX(COALESCE(out_end_off,0),?) WHERE id=(SELECT id FROM protected_backup.commands WHERE session_id=? ORDER BY cmd_index DESC,id DESC LIMIT 1) AND complete=0`, cp.Offset+int64(len(clean)), p.id); e != nil {
				return e
			}
		}
	}
	if _, e = tx.ExecContext(ctx, "PRAGMA protected_backup.secure_delete=ON"); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "DELETE FROM protected_backup.capture_checkpoints")
	return e
}
