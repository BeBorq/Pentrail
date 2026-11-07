package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/BeBorq/Pentrail/internal/redact"
	"io"
	"os"
	"syscall"
	"time"
)

const maxArtifactBytes = 64 << 20 // 64 MiB hard cap, enforced during the read

// Artifact states (command_artifacts.state). They are persisted so the outcome
// of every structured-output file is visible in the viewer, report and export,
// not only on the stderr of a background process.
const (
	ArtWaiting         = "waiting"          // tool still running (no FIN yet)
	ArtPending         = "pending"          // finished, not processed yet
	ArtImported        = "imported"         // complete document imported
	ArtImportedPartial = "imported_partial" // damaged file: valid prefix imported, damaged tail masked
	ArtRejected        = "rejected_invalid" // nothing valid to import; original left on disk
	ArtTooLarge        = "skipped_too_large"
	ArtMissing         = "missing"
	ArtUnreadable      = "unreadable"
	ArtUnsafe          = "unsafe"            // symlink / reparse point / not a regular file
	ArtLegacyUnchecked = "legacy_unverified" // imported by an older version; a file still exists at the path
)

// errUnsafeArtifact is returned by openArtifact for symlinks/reparse points.
var errUnsafeArtifact = errors.New("artifact is a symbolic link, reparse point or not a regular file")

type cleanupOutcome int

const (
	cleanupRemoved     cleanupOutcome = iota
	cleanupGone                       // nothing at the path any more
	cleanupMismatch                   // something else is at the path now: not ours to delete
	cleanupFailed                     // could not verify/delete now; retry later
	cleanupKept                       // cannot be deleted safely here: kept, reported, not retried
	cleanupStuck                      // a quarantined file could not be put back: kept, reported, retried
	cleanupRemovedWarn                // deleted, with a warning that must stay visible
)

// IngestArtifacts imports each FINALIZED structured output file into the
// encrypted database and then removes the plaintext original.
//
// Every outcome is recorded in command_artifacts.state/state_detail:
// a damaged or oversized file never blocks the others, never aborts the
// viewer/report/export, and is never silently dropped.
//
// Removal is two-phase: the import commits content together with
// cleanup_pending=1 and the identity + sha256 of the ORIGINAL bytes; the file is
// deleted only after re-verifying it is that same file. A crash or a failed
// deletion leaves cleanup_pending=1 and the next call retries. Deleting unlinks
// the file only; full-disk encryption remains the backstop against recovery of
// the medium.
//
// The returned error is reserved for database failures.
func (s *Store) IngestArtifacts(sessionID int64) (int, error) {
	if err := s.retryArtifactCleanup(sessionID); err != nil {
		return 0, err
	}
	if err := s.classifyLegacyArtifacts(sessionID); err != nil {
		return 0, err
	}
	rows, err := s.db.Query(`
        SELECT id, path, tool, state, COALESCE(src_size,-1), COALESCE(src_mtime,-1) FROM command_artifacts
        WHERE session_id=? AND COALESCE(finalized,0)=1 AND COALESCE(ingested,0)=0`, sessionID)
	if err != nil {
		return 0, err
	}
	type pend struct {
		id              int64
		path, tool, st  string
		lastSize, lastM int64
	}
	var todo []pend
	for rows.Next() {
		var p pend
		if err := rows.Scan(&p.id, &p.path, &p.tool, &p.st, &p.lastSize, &p.lastM); err != nil {
			rows.Close()
			return 0, err
		}
		todo = append(todo, p)
	}
	rows.Close()

	count := 0
	for _, p := range todo {
		// A rejected document is not re-parsed every few seconds unless it changed.
		if p.st == ArtRejected {
			if fi, e := os.Lstat(p.path); e == nil && fi.Size() == p.lastSize && fi.ModTime().UnixNano() == p.lastM {
				continue
			}
		}
		var res artifactRead
		if s.isOwnFile(p.path) {
			// Opening (and closing) the database's own files would drop this
			// process's SQLite locks on them; never read or delete them.
			res = artifactRead{state: ArtUnsafe, detail: "the path points to a pentrail database file — not read and not deleted"}
		} else {
			res = readArtifact(p.path)
		}
		if res.state != "" {
			if err := s.setArtifactState(p.id, p.path, res.state, res.detail, res.size, res.mtime); err != nil {
				return count, err
			}
			continue
		}
		clean, partial, serr := redact.ArtifactPartial(p.tool, res.data)
		if serr != nil {
			if err := s.setArtifactState(p.id, p.path, ArtRejected,
				"invalid document, the file was left on disk: "+serr.Error(), res.size, res.mtime); err != nil {
				return count, err
			}
			continue
		}
		state, detail, part := ArtImported, "", 0
		if partial {
			state, part = ArtImportedPartial, 1
			detail = "damaged/unfinished file: the valid beginning was imported, the damaged tail was masked; the document is NOT complete"
		}
		sum := sha256.Sum256(clean)
		src := sha256.Sum256(res.data)
		r, err := s.db.Exec(`
            UPDATE command_artifacts SET sha256=?, length=?, content=?, ingested=1, partial=?,
                state=?, state_detail=?, src_sha256=?, src_size=?, src_identity=?, src_mtime=?,
                cleanup_pending=1, cleanup_detail=''
            WHERE id=? AND COALESCE(ingested,0)=0`,
			hex.EncodeToString(sum[:]), len(clean), clean, part, state, detail,
			hex.EncodeToString(src[:]), res.size, res.identity, res.mtime, p.id)
		if err != nil {
			return count, err
		}
		if n, _ := r.RowsAffected(); n == 0 {
			continue // imported concurrently by another process; it owns the cleanup
		}
		if partial {
			diag("WARNING — artifact %q imported INCOMPLETE (damaged tail masked)", p.path)
		}
		count++
		if err := s.cleanupArtifact(cleanupRow{id: p.id, path: p.path, ident: res.identity, size: res.size, sum: hex.EncodeToString(src[:])}); err != nil {
			return count, err
		}
	}
	return count, nil
}

type artifactRead struct {
	data          []byte
	identity      string
	size, mtime   int64
	state, detail string // non-empty: not importable now, and why
}

// readArtifact opens without following a final symlink/reparse point, checks
// the size BEFORE reading (no unbounded or repeated 64 MiB reads) and still
// bounds the read itself.
func readArtifact(path string) artifactRead {
	f, err := openArtifact(path)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return artifactRead{state: ArtMissing, detail: "the file does not exist (the tool may not have created it)"}
		case errors.Is(err, errUnsafeArtifact) || errors.Is(err, syscall.ELOOP):
			return artifactRead{state: ArtUnsafe, detail: "link/reparse point — not read and not deleted"}
		default:
			// Windows cannot open a directory without backup semantics
			// (Access is denied); classify what is at the path the same way
			// on both systems instead of reporting a permission problem.
			if li, lerr := os.Lstat(path); lerr == nil {
				switch {
				case li.Mode()&os.ModeSymlink != 0:
					return artifactRead{state: ArtUnsafe, detail: "link/reparse point — not read and not deleted"}
				case !li.Mode().IsRegular():
					return artifactRead{state: ArtUnsafe, detail: "this is not a regular file"}
				}
			}
			return artifactRead{state: ArtUnreadable, detail: "cannot open: " + err.Error()}
		}
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return artifactRead{state: ArtUnreadable, detail: "cannot read metadata: " + err.Error()}
	}
	if !fi.Mode().IsRegular() {
		return artifactRead{state: ArtUnsafe, detail: "this is not a regular file"}
	}
	size, mtime := fi.Size(), fi.ModTime().UnixNano()
	if size > maxArtifactBytes {
		return artifactRead{state: ArtTooLarge, size: size, mtime: mtime,
			detail: fmt.Sprintf("the file has %d B, the import limit is %d B; it was left on disk", size, maxArtifactBytes)}
	}
	identity, err := fileIdentity(f)
	if err != nil {
		return artifactRead{state: ArtUnreadable, detail: "cannot determine the file identity: " + err.Error()}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxArtifactBytes+1))
	if err != nil {
		return artifactRead{state: ArtUnreadable, detail: "read error: " + err.Error()}
	}
	if int64(len(data)) > maxArtifactBytes {
		return artifactRead{state: ArtTooLarge, size: int64(len(data)), mtime: mtime,
			detail: fmt.Sprintf("the file grew beyond the %d B limit while being read; it was left on disk", maxArtifactBytes)}
	}
	if int64(len(data)) != size {
		return artifactRead{state: ArtUnreadable, detail: "the file changed size while being read; will retry"}
	}
	return artifactRead{data: data, identity: identity, size: size, mtime: mtime}
}

// setArtifactState records a non-import outcome; it only writes (and warns)
// when the state or reason actually changed.
func (s *Store) setArtifactState(id int64, path, state, detail string, size, mtime int64) error {
	r, err := s.db.Exec(`UPDATE command_artifacts SET state=?, state_detail=?, src_size=?, src_mtime=?
        WHERE id=? AND COALESCE(ingested,0)=0 AND (state<>? OR state_detail<>? OR COALESCE(src_size,-1)<>? OR COALESCE(src_mtime,-1)<>?)`,
		state, detail, size, mtime, id, state, detail, size, mtime)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n > 0 {
		diag("WARNING — artifact %q not imported (%s): %s", path, state, detail)
	}
	return nil
}

func (s *Store) retryArtifactCleanup(sessionID int64) error {
	rows, err := s.db.Query(`SELECT id, path, COALESCE(src_identity,''), COALESCE(src_size,-1), COALESCE(src_sha256,''),
            cleanup_quarantine, cleanup_dir
        FROM command_artifacts WHERE session_id=? AND (cleanup_pending=1 OR cleanup_quarantine<>'')`, sessionID)
	if err != nil {
		return err
	}
	var todo []cleanupRow
	for rows.Next() {
		var p cleanupRow
		if err := rows.Scan(&p.id, &p.path, &p.ident, &p.size, &p.sum, &p.quarantine, &p.dirID); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, p)
	}
	rows.Close()
	for _, p := range todo {
		if err := s.cleanupArtifact(p); err != nil {
			return err
		}
	}
	return nil
}

type cleanupRow struct {
	id                int64
	path, ident, sum  string
	size              int64
	quarantine, dirID string
}

// cleanupArtifact deletes the plaintext original only if it is still exactly
// the file that was imported. A deletion failure is recorded and retried; it
// is never fatal to the session. An interrupted earlier attempt (quarantine
// record present) is recovered first.
func (s *Store) cleanupArtifact(p cleanupRow) error {
	if p.ident == "" || p.sum == "" {
		_, err := s.db.Exec(`UPDATE command_artifacts SET cleanup_pending=0,
            cleanup_detail='no checksum of the original — the file will not be deleted automatically' WHERE id=?`, p.id)
		return err
	}
	// The record is committed (synchronous=FULL) before the rename it
	// announces, so it survives a crash at any later point.
	logq := func(qname, dirID string) error {
		return retryBusy("cleanup quarantine record", func() error {
			_, err := s.db.Exec(`UPDATE command_artifacts SET cleanup_quarantine=?, cleanup_dir=? WHERE id=?`, qname, dirID, p.id)
			return err
		})
	}
	var outcome cleanupOutcome
	var why string
	done := false
	if p.quarantine != "" {
		outcome, why, done = recoverQuarantine(p.path, p.quarantine, p.dirID, p.ident, p.size, p.sum, logq)
	}
	if !done {
		outcome, why = removeVerified(p.path, p.ident, p.size, p.sum, logq)
	}
	setDetail := func(pending int, detail, warn string) error {
		r, err := s.db.Exec(`UPDATE command_artifacts SET cleanup_pending=?, cleanup_detail=? WHERE id=? AND (cleanup_pending<>? OR cleanup_detail<>?)`,
			pending, detail, p.id, pending, detail)
		if err == nil && warn != "" {
			if n, _ := r.RowsAffected(); n > 0 {
				diag("WARNING — "+warn+": %s (%s)", p.path, why)
			}
		}
		return err
	}
	switch outcome {
	case cleanupRemoved, cleanupGone:
		return setDetail(0, "", "")
	case cleanupRemovedWarn:
		return setDetail(0, why, "plaintext artifact removed with a warning")
	case cleanupMismatch:
		return setDetail(0, "the path holds a different file than the imported one ("+why+"); not deleted", "path no longer holds the imported artifact; NOT deleted")
	case cleanupKept:
		return setDetail(0, why, "plaintext artifact kept: cannot be deleted safely")
	case cleanupStuck:
		return setDetail(1, why, "plaintext artifact left in quarantine")
	default:
		return setDetail(1, "could not remove the plaintext copy, will retry: "+why, "could not remove plaintext artifact; will retry")
	}
}

// classifyLegacyArtifacts labels rows imported by versions without the state
// model. Their originals carry no checksum, so a file still present at the
// path cannot be proven to be the imported one: it is reported, not deleted.
func (s *Store) classifyLegacyArtifacts(sessionID int64) error {
	rows, err := s.db.Query(`SELECT id, path FROM command_artifacts
        WHERE session_id=? AND COALESCE(ingested,0)=1 AND state=''`, sessionID)
	if err != nil {
		return err
	}
	type row struct {
		id   int64
		path string
	}
	var todo []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.path); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, r)
	}
	rows.Close()
	for _, r := range todo {
		state, detail := ArtImported, ""
		if _, e := os.Lstat(r.path); e == nil {
			state = ArtLegacyUnchecked
			detail = "imported by an older version; the path still holds a file that cannot be confirmed as the original — not deleted automatically"
		}
		if _, err := s.db.Exec(`UPDATE command_artifacts SET state=?, cleanup_detail=? WHERE id=? AND state=''`, state, detail, r.id); err != nil {
			return err
		}
	}
	return nil
}

// hashFile reads at most want+1 bytes from f and reports whether it holds
// exactly want bytes with the given sha256.
func hashMatches(f io.Reader, want int64, sum string) (bool, string) {
	data, err := io.ReadAll(io.LimitReader(f, want+1))
	if err != nil {
		return false, "read error during verification: " + err.Error()
	}
	if int64(len(data)) != want {
		return false, "zmieniony rozmiar"
	}
	h := sha256.Sum256(data)
	if hex.EncodeToString(h[:]) != sum {
		return false, "content changed"
	}
	return true, ""
}

// safeRead opens path WITHOUT following a final symlink and reads at most
// maxArtifactBytes. ok is false when the file is missing, is a symlink or not a
// regular file, exceeds the hard cap, or (when minAge>0) was modified within
// minAge — i.e. may still be written. Used by the parser fallback.
func safeRead(path string, minAge time.Duration) ([]byte, bool) {
	return readLimited(path, maxArtifactBytes, minAge)
}

func readLimited(path string, max int64, minAge time.Duration) ([]byte, bool) {
	f, err := openArtifact(path)
	if err != nil {
		return nil, false // missing, or a symlink (O_NOFOLLOW => ELOOP)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	if minAge > 0 && time.Since(fi.ModTime()) < minAge {
		return nil, false // too fresh: a writer may still have it open
	}
	if fi.Size() > max {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, false
	}
	if int64(len(data)) > max {
		return nil, false
	}
	return data, true
}

// ArtifactInfo is the user-visible status of one structured-output file.
type ArtifactInfo struct {
	ID             int64  `json:"id"`
	CmdIndex       int64  `json:"cmd_index"`
	Tool           string `json:"tool"`
	Path           string `json:"path"`
	State          string `json:"state"`
	Detail         string `json:"detail,omitempty"`
	Partial        bool   `json:"partial"`
	Length         int64  `json:"stored_bytes"`
	SourceBytes    int64  `json:"source_bytes"`
	CleanupPending bool   `json:"cleanup_pending"`
	CleanupDetail  string `json:"cleanup_detail,omitempty"`
	// Quarantine: an interrupted cleanup moved the file to this name in the
	// same directory and has not resolved it yet.
	Quarantine string `json:"cleanup_quarantine,omitempty"`
}

// Problem reports whether the artifact needs the user's attention.
func (a ArtifactInfo) Problem() bool {
	return a.Partial || a.CleanupPending || a.CleanupDetail != "" || a.Quarantine != "" ||
		(a.State != ArtImported && a.State != ArtWaiting && a.State != ArtPending)
}

// ListArtifacts returns every artifact of a session with its import outcome.
func (s *Store) ListArtifacts(sessionID int64) ([]ArtifactInfo, error) {
	rows, err := s.db.Query(`SELECT id, cmd_index, tool, path, state, state_detail, partial,
            COALESCE(length,0), COALESCE(src_size,0), cleanup_pending, cleanup_detail,
            COALESCE(finalized,0), COALESCE(ingested,0), cleanup_quarantine
        FROM command_artifacts WHERE session_id=? ORDER BY cmd_index, id`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ArtifactInfo
	for rows.Next() {
		var a ArtifactInfo
		var partial, cleanup, fin, ing int64
		if err := rows.Scan(&a.ID, &a.CmdIndex, &a.Tool, &a.Path, &a.State, &a.Detail, &partial,
			&a.Length, &a.SourceBytes, &cleanup, &a.CleanupDetail, &fin, &ing, &a.Quarantine); err != nil {
			return nil, err
		}
		a.Partial, a.CleanupPending = partial == 1, cleanup == 1
		if a.State == "" {
			switch {
			case fin == 0:
				a.State = ArtWaiting
			case ing == 0:
				a.State = ArtPending
			default:
				a.State = ArtImported
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// isOwnFile reports whether path is this Store's database or one of its side
// files (compared with stat only, which opens nothing).
func (s *Store) isOwnFile(path string) bool {
	if s.file == nil {
		return false
	}
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	for _, own := range []string{s.path, s.path + "-wal", s.path + "-shm", s.path + "-journal"} {
		if o, err := os.Stat(own); err == nil && os.SameFile(o, fi) {
			return true
		}
	}
	return false
}
