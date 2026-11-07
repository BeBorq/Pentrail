package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BeBorq/Pentrail/internal/extract"
)

// EntityRow is one derived indicator, joined to the command that revealed it.
type EntityRow struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	Confidence string `json:"confidence"`
	CmdIndex   int64  `json:"cmd_index"` // -1 if the source command is unknown
	Offset     int64  `json:"offset"`
	Tool       string `json:"tool"`
	Details    string `json:"details"` // raw JSON string, "" if none
}

// ExtractRegex runs the low-confidence generic extractors over every command's
// output in a session and (re)writes the resulting entities. It is idempotent:
// it first clears its own prior rows for the session, so it can be replayed
// after the rules change. Returns the number of entities written.
//
// This is Layer 3: it reads bytes already persisted by capture. It never runs
// in the live terminal.
func (s *Store) ExtractRegex(sessionID int64) (int, error) {
	// Fetch commands first (single connection: don't hold a cursor open while
	// we read ranges and insert below).
	type cmd struct {
		id               int64
		index            int64
		command          string
		startedAt        int64
		endedAt          int64
		outStart, outEnd int64
	}
	rows, err := s.db.Query(`
        SELECT id, cmd_index, COALESCE(command,''), COALESCE(started_at,0), COALESCE(ended_at,0),
               COALESCE(out_start_off,0), COALESCE(out_end_off,0)
        FROM commands WHERE session_id=? ORDER BY cmd_index`, sessionID)
	if err != nil {
		return 0, err
	}
	var cmds []cmd
	for rows.Next() {
		var c cmd
		if err := rows.Scan(&c.id, &c.index, &c.command, &c.startedAt, &c.endedAt, &c.outStart, &c.outEnd); err != nil {
			rows.Close()
			return 0, err
		}
		cmds = append(cmds, c)
	}
	rows.Close()

	// Read and scan every command's output BEFORE opening a write transaction.
	// The store uses a single connection, so reading (ReadRange) while a tx held
	// that connection would deadlock. Collect all rows to insert, then write.
	type pending struct {
		typ, value, tool, extractor, obsKey string
		cmdID, offset, when                 int64
	}
	var toInsert []pending
	for _, c := range cmds {
		if c.outEnd <= c.outStart {
			continue
		}
		spans, err := s.ReadSpans(sessionID, c.outStart, c.outEnd)
		missing := c.outEnd - c.outStart
		for _, span := range spans {
			missing -= int64(len(span.Data))
		}
		if err != nil {
			return 0, err
		}
		// Persist the gap on the command so it travels with the data (UI, export,
		// and the entities that link back to this command), not just to stderr.
		if _, uerr := s.db.Exec(`UPDATE commands SET raw_missing=? WHERE id=?`, missing, c.id); uerr != nil {
			return 0, uerr
		}
		if missing > 0 {
			fmt.Fprintf(os.Stderr, "pentrail: WARNING — session %d command #%d output is INCOMPLETE (%d bytes missing); extracted indicators may be partial\n",
				sessionID, c.index, missing)
		}
		tool := toolOf(c.command)
		when := c.endedAt
		if when == 0 {
			when = c.startedAt
		}
		if when == 0 {
			when = time.Now().UnixNano()
		}
		for _, span := range spans {
			for _, m := range extract.Run(span.Data) {
				obs := "regex\x1f" + string(m.Kind) + "\x1f" + m.Value + "\x1f" + strconv.FormatInt(c.index, 10)
				toInsert = append(toInsert, pending{
					typ: string(m.Kind), value: m.Value, tool: tool,
					extractor: "regex:" + string(m.Kind), obsKey: obs,
					cmdID: c.id, offset: span.Offset + int64(m.Offset), when: when,
				})
			}
		}

	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM entities WHERE session_id=? AND extractor LIKE 'regex:%'`, sessionID); err != nil {
		tx.Rollback()
		return 0, err
	}
	stmt, err := tx.Prepare(`
        INSERT OR IGNORE INTO entities
            (session_id, type, value, confidence, source_command_id, source_offset, tool, discovered_at, extractor, obs_key)
        VALUES(?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	defer stmt.Close()

	count := 0
	for _, p := range toInsert {
		res, err := stmt.Exec(sessionID, p.typ, p.value, "low",
			p.cmdID, p.offset, p.tool, p.when, p.extractor, p.obsKey)
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

// ListEntityRows returns every entity of a session joined to its command index.
func (s *Store) ListEntityRows(sessionID int64) ([]EntityRow, error) {
	rows, err := s.db.Query(`
        SELECT e.type, e.value, e.confidence, COALESCE(c.cmd_index,-1),
               COALESCE(e.source_offset,0), COALESCE(e.tool,''), COALESCE(e.details,'')
        FROM entities e
        LEFT JOIN commands c ON c.id = e.source_command_id
        WHERE e.session_id=?
        ORDER BY e.confidence DESC, e.type, e.value`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EntityRow
	for rows.Next() {
		var r EntityRow
		if err := rows.Scan(&r.Type, &r.Value, &r.Confidence, &r.CmdIndex, &r.Offset, &r.Tool, &r.Details); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// toolOf guesses the program that produced output, from the command line.
// Best-effort: strips a leading "sudo" and takes the basename of the argv[0].
func toolOf(command string) string {
	fields := strings.Fields(command)
	for len(fields) > 0 {
		f := fields[0]
		if f == "sudo" || strings.Contains(f, "=") { // skip sudo and VAR=val prefixes
			fields = fields[1:]
			continue
		}
		return filepath.Base(f)
	}
	return ""
}
