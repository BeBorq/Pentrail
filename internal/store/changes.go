package store

import (
	"time"

	"github.com/BeBorq/Pentrail/internal/cleanup"
)

// ChangeRow is one state-changing command, for the cleanup checklist.
type ChangeRow struct {
	CmdIndex    int64  `json:"cmd_index"`
	Command     string `json:"command"`
	Cwd         string `json:"cwd"`
	Category    string `json:"category"`
	Description string `json:"description"`
	DetectedMs  int64  `json:"detected_ms"`
	Offset      int64  `json:"offset"`
}

// DetectChanges scans a session's commands for state changes the operator made
// and (re)writes the cleanup checklist. Idempotent. Offline over captured data.
func (s *Store) DetectChanges(sessionID int64) (int, error) {
	type cmd struct {
		id, index        int64
		command, cwd     string
		startedAt, ended int64
		outStart         int64
	}
	rows, err := s.db.Query(`
        SELECT id, cmd_index, COALESCE(command,''), COALESCE(cwd,''),
               COALESCE(started_at,0), COALESCE(ended_at,0), COALESCE(out_start_off,0)
        FROM commands WHERE session_id=? ORDER BY cmd_index`, sessionID)
	if err != nil {
		return 0, err
	}
	var cmds []cmd
	for rows.Next() {
		var c cmd
		if err := rows.Scan(&c.id, &c.index, &c.command, &c.cwd, &c.startedAt, &c.ended, &c.outStart); err != nil {
			rows.Close()
			return 0, err
		}
		cmds = append(cmds, c)
	}
	rows.Close()

	type pending struct {
		idx, cmdID, when, offset int64
		command, cwd, cat, desc  string
	}
	var toInsert []pending
	for _, c := range cmds {
		when := c.ended
		if when == 0 {
			when = c.startedAt
		}
		if when == 0 {
			when = time.Now().UnixNano()
		}
		for _, h := range cleanup.Detect(c.command) {
			toInsert = append(toInsert, pending{
				idx: c.index, cmdID: c.id, when: when, offset: c.outStart,
				command: c.command, cwd: c.cwd, cat: string(h.Category), desc: h.Desc,
			})
		}
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM changes WHERE session_id=?`, sessionID); err != nil {
		tx.Rollback()
		return 0, err
	}
	stmt, err := tx.Prepare(`
        INSERT OR IGNORE INTO changes
            (session_id, cmd_index, source_command_id, command, cwd, category, description, detected_at, source_offset)
        VALUES(?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	defer stmt.Close()
	count := 0
	for _, p := range toInsert {
		res, err := stmt.Exec(sessionID, p.idx, p.cmdID, p.command, p.cwd, p.cat, p.desc, p.when, p.offset)
		if err != nil {
			tx.Rollback()
			return 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			count++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

// ListChanges returns the cleanup checklist for a session, in execution order.
func (s *Store) ListChanges(sessionID int64) ([]ChangeRow, error) {
	rows, err := s.db.Query(`
        SELECT cmd_index, COALESCE(command,''), COALESCE(cwd,''), category,
               COALESCE(description,''), COALESCE(detected_at,0), COALESCE(source_offset,0)
        FROM changes WHERE session_id=? ORDER BY cmd_index, category`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ChangeRow
	for rows.Next() {
		var r ChangeRow
		var det int64
		if err := rows.Scan(&r.CmdIndex, &r.Command, &r.Cwd, &r.Category, &r.Description, &det, &r.Offset); err != nil {
			return nil, err
		}
		r.DetectedMs = det / 1_000_000
		out = append(out, r)
	}
	return out, rows.Err()
}
