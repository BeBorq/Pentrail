package store

import (
	"bytes"
	"github.com/BeBorq/Pentrail/internal/redact"
)

// Read-only accessors for Layer 4 (View). The view never parses or captures;
// it only reads what capture already persisted.

type SessionInfo struct {
	PendingBytes   int64  `json:"pending_bytes"`
	Unattributed   int64  `json:"unattributed_input"`
	Recoveries     int64  `json:"recoveries"`
	PrivacyVersion string `json:"privacy_version"`
	RedactedBytes  int64  `json:"redacted_bytes"`
	ID             int64  `json:"id"`
	StartedMs      int64  `json:"started_ms"` // unix milliseconds (JSON-safe; nanos overflow JS numbers)
	EndedMs        int64  `json:"ended_ms"`
	Shell          string `json:"shell"`
	Host           string `json:"host"`
	Version        string `json:"version"`
	Commands       int64  `json:"commands"`
	RawBytes       int64  `json:"raw_bytes"`
}

type CommandInfo struct {
	Index       int64  `json:"index"`
	Command     string `json:"command"`
	Cwd         string `json:"cwd"`
	StartedMs   int64  `json:"started_ms"`
	EndedMs     int64  `json:"ended_ms"`
	ExitCode    int64  `json:"exit_code"`
	OutStartOff int64  `json:"out_start_off"`
	OutEndOff   int64  `json:"out_end_off"`
	Complete    bool   `json:"complete"`
	RawMissing  int64  `json:"raw_missing"`          // bytes missing from this command's raw range
	EndReason   string `json:"end_reason,omitempty"` // non-empty: end not observed, exit status unknown
}

func msFromNano(n int64) int64 {
	if n == 0 {
		return 0
	}
	return n / 1_000_000
}

// ListSessions returns every session, newest first.
func (s *Store) ListSessions() ([]SessionInfo, error) {
	rows, err := s.db.Query(`
        SELECT s.id, s.started_at, COALESCE(s.ended_at,0), s.shell, s.hostname, s.version,
               (SELECT count(*) FROM commands c WHERE c.session_id=s.id),
               (SELECT COALESCE(sum(length(data)),0) FROM raw_chunks r WHERE r.session_id=s.id),
 s.privacy_version,(SELECT COALESCE(sum(redacted_bytes),0) FROM raw_chunks r WHERE r.session_id=s.id),
(SELECT COALESCE(sum(pending_bytes),0) FROM capture_checkpoints p WHERE p.session_id=s.id),
(SELECT count(*) FROM capture_recoveries r WHERE r.session_id=s.id),
 s.unattributed_input
        FROM sessions s ORDER BY s.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionInfo
	for rows.Next() {
		var si SessionInfo
		var started, ended int64
		if err := rows.Scan(&si.ID, &started, &ended, &si.Shell, &si.Host, &si.Version, &si.Commands, &si.RawBytes, &si.PrivacyVersion, &si.RedactedBytes, &si.PendingBytes, &si.Recoveries, &si.Unattributed); err != nil {
			return nil, err
		}
		si.StartedMs = msFromNano(started)
		si.EndedMs = msFromNano(ended)
		out = append(out, si)
	}
	return out, rows.Err()
}

// ListCommands returns the commands of a session in execution order.
func (s *Store) ListCommands(sessionID int64) ([]CommandInfo, error) {
	rows, err := s.db.Query(`
        SELECT cmd_index, COALESCE(command,''), COALESCE(cwd,''),
               COALESCE(started_at,0), COALESCE(ended_at,0), COALESCE(exit_code,0),
               COALESCE(out_start_off,0), COALESCE(out_end_off,0), complete,
               COALESCE(raw_missing,0), COALESCE(end_reason,'')
        FROM commands WHERE session_id=? ORDER BY cmd_index`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CommandInfo
	for rows.Next() {
		var ci CommandInfo
		var started, ended int64
		var comp int64
		if err := rows.Scan(&ci.Index, &ci.Command, &ci.Cwd, &started, &ended,
			&ci.ExitCode, &ci.OutStartOff, &ci.OutEndOff, &comp, &ci.RawMissing, &ci.EndReason); err != nil {
			return nil, err
		}
		ci.StartedMs = msFromNano(started)
		ci.EndedMs = msFromNano(ended)
		ci.Command = redact.String(ci.Command)
		ci.Cwd = redact.String(ci.Cwd)
		ci.Complete = comp == 1
		out = append(out, ci)
	}
	return out, rows.Err()
}

// ReadRange reassembles the raw output bytes for [start, end) of a session from
// the append-only source of truth, AND reports how many bytes in the range are
// missing (not covered by any chunk). A non-zero `missing` means the reassembled
// bytes are NOT a faithful contiguous slice — callers must not present them as
// complete. This closes the gap where concatenating sparse chunks silently
// produced plausible-looking but incomplete output.
func (s *Store) ReadRange(sessionID, start, end int64) (data []byte, missing int64, err error) {
	if end <= start {
		return nil, 0, nil
	}
	rows, qerr := s.db.Query(`
        SELECT byte_offset, data FROM raw_chunks
        WHERE session_id=? AND byte_offset < ? AND (byte_offset + length(data)) > ?
        ORDER BY byte_offset`, sessionID, end, start)
	if qerr != nil {
		return nil, 0, qerr
	}
	defer rows.Close()
	var buf bytes.Buffer
	cursor := start // next offset we expect to see covered
	for rows.Next() {
		var off int64
		var d []byte
		if err := rows.Scan(&off, &d); err != nil {
			return nil, 0, err
		}
		chunkEnd := off + int64(len(d))
		// account for a hole between what we've covered and this chunk
		covStart := off
		if covStart < start {
			covStart = start
		}
		if covStart > cursor {
			missing += covStart - cursor
		}
		from := start - off
		if from < 0 {
			from = 0
		}
		to := end - off
		if to > int64(len(d)) {
			to = int64(len(d))
		}
		if to > from {
			buf.Write(d[from:to])
		}
		if chunkEnd > cursor {
			cursor = chunkEnd
		}
	}
	if cursor < end {
		missing += end - cursor // trailing hole
	}
	return buf.Bytes(), missing, rows.Err()
}

// RawExtent includes gaps; SUM(length) alone would truncate the tail after loss.
func (s *Store) RawExtent(id int64) (int64, error) {
	var end int64
	e := s.db.QueryRow("SELECT COALESCE(MAX(byte_offset+length(data)),0) FROM raw_chunks WHERE session_id=?", id).Scan(&end)
	return end, e
}
