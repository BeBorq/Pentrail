package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/BeBorq/Pentrail/internal/redact"
	"strconv"
	"time"

	"github.com/BeBorq/Pentrail/internal/parsers"
)

// ParseArtifacts runs the high-confidence structured parsers over every
// artifact captured for a session (nmap XML, ffuf JSON, nuclei JSONL) and writes
// the resulting entities with confidence "high" and JSON details.
//
// It prefers the artifact bytes stored IN the encrypted database (see
// IngestArtifacts), falling back to the on-disk file only if not yet ingested.
// Each parsed artifact's entities are replaced atomically and in isolation: an
// artifact that is missing or malformed is skipped WITHOUT deleting the entities
// of artifacts that did parse (fixing destructive reparse). Idempotent.
//
// Returns the number of entities written and the number of artifacts parsed.
func (s *Store) ParseArtifacts(sessionID int64) (entities int, files int, err error) {
	type art struct {
		artifactID, finalized int64
		tool, path            string
		sha                   string
		content               []byte
		ingested, partial     int64
		cmdID, cmdIndex       int64
		outStart              int64
		startedAt, endedAt    int64
	}
	rows, err := s.db.Query(`
        SELECT a.id, a.finalized, a.tool, a.path, COALESCE(a.sha256,''), a.content, COALESCE(a.ingested,0),
               COALESCE(a.partial,0), c.id, c.cmd_index, COALESCE(c.out_start_off,0),
               COALESCE(c.started_at,0), COALESCE(c.ended_at,0)
        FROM command_artifacts a
        JOIN commands c ON c.session_id = a.session_id AND c.cmd_index = a.cmd_index
        WHERE a.session_id=?`, sessionID)
	if err != nil {
		return 0, 0, err
	}
	var arts []art
	for rows.Next() {
		var a art
		if err := rows.Scan(&a.artifactID, &a.finalized, &a.tool, &a.path, &a.sha, &a.content, &a.ingested,
			&a.partial, &a.cmdID, &a.cmdIndex, &a.outStart, &a.startedAt, &a.endedAt); err != nil {
			rows.Close()
			return 0, 0, err
		}
		arts = append(arts, a)
	}
	rows.Close()

	type pending struct {
		typ, value, tool, extractor, details, obsKey, ref string
		cmdID, offset, when                               int64
	}
	// Group parsed results per artifact sha, so we only replace what we re-read.
	type result struct {
		art   art
		items []pending
	}
	parsed := map[int64]*result{}
	counts := map[string]int{}
	for _, a := range arts {
		counts[fmt.Sprintf("%d:%s", a.cmdID, a.tool)]++
	}
	for _, a := range arts {
		if (a.ingested == 0 && a.finalized == 0) || !parsers.Supported(a.tool) {
			continue
		}
		data := a.content
		sha := a.sha
		if a.ingested == 0 || len(data) == 0 {
			// Fall back to the loose file ONLY through the same hardened reader
			// the importer uses (no symlink following, hard size cap).
			fileData, ok := safeRead(a.path, 0)
			if !ok {
				continue // not available/safe — keep any existing entities for it
			}
			var safeErr error
			var part bool
			data, part, safeErr = redact.ArtifactPartial(a.tool, fileData)
			if safeErr != nil {
				continue
			}
			if part {
				a.partial = 1
			}
			sum := sha256.Sum256(data)
			sha = hex.EncodeToString(sum[:])
		}
		var safeErr error
		data, safeErr = redact.Artifact(a.tool, data)
		if safeErr != nil {
			continue
		}
		ents, perr := parsers.Parse(a.tool, data)
		if perr != nil {
			continue // malformed — keep existing entities, don't wipe
		}
		files++
		parsed[a.artifactID] = &result{art: a}
		when := a.endedAt
		if when == 0 {
			when = a.startedAt
		}
		if when == 0 {
			when = time.Now().UnixNano()
		}
		for _, e := range ents {
			if a.partial == 1 {
				// Real records recovered from a damaged file: keep them, but never
				// present them as coming from a complete document.
				d := map[string]string{"artifact": "incomplete (valid beginning recovered)"}
				for k, v := range e.Details {
					d[k] = v
				}
				e.Details = d
			}
			det := ""
			if len(e.Details) > 0 {
				if b, mErr := json.Marshal(e.Details); mErr == nil {
					det = string(b)
				}
			}
			parsed[a.artifactID].items = append(parsed[a.artifactID].items, pending{
				typ: e.Type, value: e.Value, tool: a.tool,
				extractor: "parser:" + a.tool, details: det,
				obsKey: fmt.Sprintf("artifact:%d\x1f", a.artifactID) + parserObsKey(a.tool, a.cmdIndex, e), ref: sha,
				cmdID: a.cmdID, offset: a.outStart, when: when,
			})
		}
	}

	if len(parsed) == 0 {
		return 0, files, nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	ins, err := tx.Prepare(`
        INSERT OR IGNORE INTO entities
            (session_id, type, value, confidence, source_command_id, source_offset,
             tool, discovered_at, extractor, details, artifact_ref, obs_key)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return 0, 0, err
	}
	defer ins.Close()
	for id, result := range parsed {
		a := result.art
		items := result.items
		prefix := fmt.Sprintf("artifact:%d\x1f%%", id)
		legacySingle := counts[fmt.Sprintf("%d:%s", a.cmdID, a.tool)] == 1
		if _, err := tx.Exec(`DELETE FROM entities WHERE session_id=? AND (obs_key LIKE ? OR (source_command_id=? AND extractor=? AND obs_key NOT LIKE 'artifact:%' AND (? OR artifact_ref=?)))`, sessionID, prefix, a.cmdID, "parser:"+a.tool, legacySingle, a.sha); err != nil {
			tx.Rollback()
			return 0, 0, err
		}

		for _, p := range items {
			res, err := ins.Exec(sessionID, p.typ, p.value, "high",
				p.cmdID, p.offset, p.tool, p.when, p.extractor, nullStr(p.details), p.ref, p.obsKey)
			if err != nil {
				tx.Rollback()
				return 0, 0, err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				entities++
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return entities, files, nil
}

// parserObsKey gives each observation a stable, distinct identity so a finding
// is not collapsed by name alone and a parser result does not collide with a
// regex result for the same value+command.
func parserObsKey(tool string, cmdIndex int64, e parsers.Entity) string {
	disc := ""
	if e.Type == "finding" {
		disc = e.Details["template"] + "\x1f" + e.Details["matched"] + "\x1f" + e.Details["host"]
	}
	return "parser:" + tool + "\x1f" + e.Type + "\x1f" + e.Value + "\x1f" +
		strconv.FormatInt(cmdIndex, 10) + "\x1f" + disc
}

func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
