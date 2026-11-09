# Release notes

Pentrail has no stable release yet. Every version below is a candidate. The
packages are unsigned; verify them with the published SHA-256 checksums.

## 0.6.29-durable.1 (release candidate)

- Startup-file backups on Windows and Linux now use exclusive file creation.
  Repeated setup within the same clock tick keeps every backup, including the
  original UTF-16 PowerShell profile, instead of replacing an earlier copy.
- Note changes made in quick succession no longer keep a recording session's
  capture write waiting. SQLite has no fair lock queue, and back-to-back note
  changes from another process could take the write lock again after every
  commit, so one capture write waited through all of them (2.26 s on a
  Windows CI runner). Consecutive note changes of one process now leave the
  lock free for at least 200 ms. Nothing is skipped or reordered; durability,
  encryption and revision checks are unchanged.
- Deterministic regressions freeze the clock and verify original bytes,
  unique names, idempotent setup and backup errors. Existing tests and timing
  guards remain unchanged.
- This unsigned candidate supersedes 0.6.29-durable. Its original tag and
  published assets remain unchanged. Software-emulated Linux timing limits
  remain unresolved; see the release verification report.

## 0.6.29-durable (release candidate)

This candidate includes the following changes after 0.6.28-durable.
It remains unsigned; see the release assets for checksums and the verified
test scope. Known limitations remain documented in LIMITATIONS.md.

### Viewer

- The remaining viewer reads are bounded and report failures truthfully:
  the graph and its command/output details, the cleanup checklist and its
  browser-state identifier, the Notes list, and the parts of the full
  session record. A rejected connection, an expired link (HTTP 401/403), a
  missing resource (404), a server error (500), invalid data, or a request
  or reply body that never finishes now ends in an error message with
  **Try again** instead of endless loading or an empty result.
- Replies and retry buttons that belong to a session or view that is no
  longer shown can no longer change the page.
- A failed part of the full session record adds nothing; the button loads the
  same part again. Offsets and the missing-bytes warning are validated.
- Graph layout, dragging, relationship paths, note anchors, cleanup ticks and
  note writes are unchanged. Note saves are still revision-checked, have no
  automatic retry and are never reported as saved without confirmation.

### Windows: one session, several path spellings

- The private named pipe of a session or of the key agent is now named after
  the long-path spelling of its endpoint (case-insensitive). Before, a server
  started with an 8.3 short spelling (for example a `TEMP` under
  `C:\Users\RUNNER~1`) and a client using the long spelling computed
  different pipe names, so `pentrail off` could not reach a live session,
  treated it as ended and reported success while it kept recording.
- A client still finds a session of an older version that named its pipe
  after another spelling of the same path.
- `off`, `on`, `flush`, `backup` and the checks before
  switching databases no longer skip an endpoint whose pipe is missing
  unless its end is confirmed (no endpoint file, no such process, the process
  has exited, or its PID was reused). A running writer, or one that cannot be
  checked (for example a locked or invalid endpoint file), is reported as not
  reached. Recording for new terminals is still disabled by `off`.
- A client also finds an older session whose pipe was named after the short
  directory and the long file name, after that file got its own 8.3 alias.

### Notes while another process writes

- A note change no longer fails with "database is locked" when another
  process (for example a recording session) holds the database write lock for
  longer than SQLite's busy timeout. The change was not written in that case;
  it is now tried again from the start, with backoff, for up to 30 seconds,
  and then reported as failed. Revision checks apply on every attempt, and
  conflicts and other errors are returned at once.

### Security and dependencies

- `golang.org/x/sys` upgraded from v0.30.0 to v0.44.0 (GO-2026-5024 /
  CVE-2026-39824, an integer overflow in `windows.NewNTUnicodeString`).
- The project targets Go 1.27.3 (`toolchain go1.27.3` in `go.mod`, CI and the
  release instructions). `go.mod` now requires at least Go 1.25.0, the minimum
  of `golang.org/x/sys` v0.44.0. Older Go standard library versions had known
  vulnerabilities reported by `govulncheck`; release binaries must be built
  with the maintained toolchain. The audit scope (it excludes the bundled C
  code) is described in [SECURITY-MODEL.md](SECURITY-MODEL.md#dependency-audit).
- The read of the notes write token is bounded (15 seconds, request and
  body); when it fails, no write is sent and the note shows *Not saved* with
  Retry. Note writes themselves are unchanged.
- The full session record rejects a part whose offset headers are missing or
  not plain decimal numbers (previously a missing header could read as 0).
- In the graph, **Try again** after a failed command read shows the command
  that was asked for instead of the first command found.
- A known gap in the full session record (bytes missing from parts already
  loaded) stays visible after a failed part and its retry, and gaps of several
  parts add up; previously a later successful part could clear the warning.
- Graph data whose nodes or edges are unusable (for example `null` entries,
  missing or duplicate ids, wrong field types) is reported as invalid data with
  **Try again** instead of leaving the graph "loading"; an error while drawing
  is reported the same way. Edges to elements that are not in the graph are
  still left out, as before.
- `release/build_release.py` refuses a Go other than the `toolchain` of `go.mod`
  and binaries that contain local build paths,
  writes a `BUILDINFO-public.json` without local paths, environment or
  compiler output, and ships the complete documentation in every package so
  that all README links work.

### Project

- The Go module path is now `github.com/BeBorq/Pentrail`.
- Synthetic Windows test fixtures were stripped of local user and directory
  names (same lengths, checksums regenerated).
- New public documentation, MIT license, notices, contribution and security
  policies, issue templates and an offline CI workflow.
- Release packages now contain `LICENSE`, `NOTICE` and the documentation
  under `docs/`.

Capture, masking, the store, the session protocol (`pentrail-session/5`) and
the database schema are unchanged.

## 0.6.28-durable (candidate)

- Session list and timeline reads are bounded (15 seconds for fetch and body
  together), check the response status and shape, and show a clear error with
  **Try again**.
- Stale replies and retired retry handlers cannot repaint another session or
  view.
- Optional timeline reads (notes, imported tool files) are bounded at 10
  seconds and reported as unknown on failure; command-output read failures
  are shown as errors, not as captured output.

## 0.6.27-durable (candidate)

- Operator notes: plain-text annotations for sessions, timeline commands and
  graph elements, stored in the encrypted database with masking, autosave,
  revision checks and conflict resolution, search, archive and restore.
- Reports and exports leave notes out unless `--include-notes` is given (HTML
  and JSON; CSV refuses it).

## 0.6.26-durable (candidate)

- Graph laid out in chronological command bands with related elements kept
  together; keyboard, mouse and touch navigation; collapsible command and
  output sections in the timeline and graph details, with navigation between
  them.

## Earlier versions

Earlier development versions were not published. Their main features —
encrypted capture on Windows and Linux, masking before storage, crash
recovery of unfinished lines, encrypted backup, automatic capture of new
terminals, flow control for several clients, tool output import and the
cleanup checklist — are part of the versions above.
