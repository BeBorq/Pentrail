# How Pentrail works

Pentrail is a single Go program (`cmd/pentrail`) with four layers: capture,
store, analysis and viewer/report.

```text
 terminal window ──► client ──► session server ──► shell (PTY / ConPTY)
                                   │
                                   ├─ masking (internal/redact)
                                   ▼
                          SQLCipher database (internal/store)
                                   │
              ┌────────────────────┼─────────────────────┐
              ▼                    ▼                     ▼
   extraction / parsers      cleanup checklist     viewer (internal/view)
   (internal/extract,        (internal/cleanup)    report / export
    internal/parsers)                              (internal/report)
```

## Processes

- **Client** — the program you run in a terminal (`pentrail start`,
  `pentrail attach`). It puts the terminal in raw mode, forwards keystrokes
  and resizes, and draws the output it receives. `Ctrl+\` detaches it.
- **Session server** — a detached process (`__session-server`) that owns the
  shell, its pseudo-terminal (Linux PTY or Windows ConPTY) and the database
  connection. It survives the client, so the session keeps recording when a
  window is closed.
- **Key agent** — started by `pentrail on` (`__key-agent`). It keeps the key
  in memory and hands it to new session servers over a local socket or named
  pipe, so new terminals do not ask for the passphrase.
- **Viewer** — `pentrail open` starts a background viewer (`__viewer`) on a
  random loopback port; `pentrail serve` runs one in the foreground.

The client and the server speak a versioned, length-prefixed protocol
(`pentrail-session/5`) over a Unix socket or a named pipe; see
[SESSION-TRANSPORT.md](SESSION-TRANSPORT.md).

## Capture (internal/capture, internal/hooks)

The shell integration (embedded hooks for Bash, Zsh and PowerShell, and an
`AutoRun` script for CMD) emits invisible markers (OSC 133 style) around the
prompt and each command: the command text, the working directory, the start
and the exit code. The server records the full terminal byte stream and uses
the markers to assign ranges of that stream to commands.

On Windows, ConPTY re-renders the screen and may reorder markers, so command
boundaries are determined with a screen model (`vtscreen.go`), and CMD entries
are confirmed against the prompt (`cmdprompt.go`, `cmdsegment.go`).

## Masking (internal/redact)

Every chunk passes through the masking rules before it is stored. The rules
work on a stream, so a secret split across chunks or across a ConPTY line
break is still recognized; the unfinished tail of a line is carried over in
a checkpoint. Masks keep the byte length, so offsets stay valid. See
[DATA-PROTECTION.md](DATA-PROTECTION.md).

## Store (internal/store)

One SQLCipher database per engagement (default `~/.pentrail/pentrail.db`),
with WAL and `synchronous=FULL`. Main tables:

| Table | Content |
|---|---|
| `sessions` | one row per recorded shell: start/end time, shell, computer host name, Pentrail version, masking version |
| `raw_chunks` | the masked terminal stream with byte offsets |
| `commands` | command text, working directory, times, exit code, output range, end reason |
| `capture_events` | pauses, resumes and capture errors with their offsets |
| `capture_checkpoints` | the encrypted unfinished-line recovery buffer |
| `entities` | hosts, ports, URLs, e-mail addresses and findings with their provenance |
| `command_artifacts` | imported nmap/ffuf/nuclei files and the state of their cleanup |
| `changes` | the cleanup checklist |
| `notes` | operator notes (annotations, not evidence) |
| `db_meta` | database identity and the viewer's random namespace |

Each received chunk and its checkpoint are committed in one transaction
**before** the output is passed on to the client. On the next open, buffers of
dead owners are masked and recovered atomically.

## Analysis

- `internal/extract` — low-confidence indicators found with regular
  expressions (IP addresses, domains, URLs, e-mail addresses).
- `internal/parsers` — high-confidence results from nmap XML, ffuf JSON and
  nuclei JSONL.
- `internal/cleanup` — scans command text for changes to undo on the target
  (files written, configuration and permission changes, accounts, services,
  scheduled tasks).

The viewer runs these before it starts serving (unless `--no-extract`).

## Viewer (internal/view)

A Go HTTP server with an embedded single page (`index.html`) and small
JavaScript modules: `graph.js` (graph layout and interaction), `xref.js`
(links between graph elements and commands), `cleanup.js` (checklist ticks),
`artifacts.js` (imported tool files) and `notes.js` (operator notes). There
are no external scripts, fonts or network requests.

The evidence endpoints only read; no request changes captured evidence. Reads in the page are
bounded and report failures with a retry; replies for a session or view that
is no longer shown are discarded. Notes are written with revision checks so
that concurrent edits are never silently overwritten.

## Reports (internal/report)

`report` renders a masked HTML report; `export` writes JSON or CSV. Both
re-apply the current masking rules when they read, and refuse to run without
`--confirm-plaintext`.

## Other packages

- `internal/background` — the opt-in state (`~/.pentrail/state.json`); never
  stores a key.
- `internal/localipc` — Unix sockets and named pipes with owner-only access.
- `internal/privatefs` — creating files and directories with private
  permissions, without following links.
- `internal/sessionio` — the session protocol and the client hub with flow
  control.
- `internal/dbidentity` — a stable identifier for a database path.
- `cmd/background-evidence` — an end-to-end test program for Linux, run in an
  isolated test machine with synthetic data.
