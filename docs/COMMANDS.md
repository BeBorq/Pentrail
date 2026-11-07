# Pentrail command reference

Every public command of the `pentrail` CLI, with every flag and environment
variable it reads. The list was taken from the source
(`cmd/pentrail/main.go` and the platform files `background.go`,
`background_linux.go`, `protection.go`, `runtime_linux.go`,
`runtime_windows.go`, `setup_windows.go`), not from the help text: where
`pentrail --help` shows less than the code accepts, this file says so.

Conventions:

- Flags are separate words: `--db PATH`, never `--db=PATH`. A value flag
  takes the next argument; a flag given more than once uses the last value.
  Unknown words are ignored.
- The binary is `pentrail` on Linux and `pentrail.exe` on Windows. After
  `setup`, it is installed as `~/.local/bin/pentrail` (Linux) or
  `%LOCALAPPDATA%\Pentrail\bin\pentrail.exe` (Windows).
- "Database" is the SQLCipher evidence database. Commands that open it ask
  for the passphrase (see `PENTRAIL_PASSPHRASE`) unless the key agent
  started by `pentrail on` holds the key.
- Exit status: 0 on success; 1 with `pentrail: <error>` on stderr on
  failure; 2 for a missing or unknown command (the usage text is printed).

## Environment

| Variable | Read by | Meaning |
|---|---|---|
| `PENTRAIL_DB` | every command whose `--db` default is "the default path" (see below) | database path; default `~/.pentrail/pentrail.db` (on Windows `%USERPROFILE%\.pentrail\pentrail.db`) |
| `PENTRAIL_PASSPHRASE` | every command that opens the database | passphrase without a prompt. It is removed from the process environment as soon as it is read, so the recorded shell and its tools do not inherit it. Without it, an encrypted build asks the key agent (after `pentrail on`) and otherwise prompts `pentrail passphrase:` |
| `SHELL` | `start` (Linux) | default shell when `--shell` is not given; `/bin/bash` if unset |
| `ZDOTDIR` | `setup zsh` (Linux) | where `.zshrc` is written (default `~/.zshrc`) |
| `LOCALAPPDATA` | `setup` (Windows) | install location `%LOCALAPPDATA%\Pentrail\bin`; `setup` fails if it is unset |

Two kinds of database default exist:

- **the default path**: `PENTRAIL_DB`, else `~/.pentrail/pentrail.db`
  (`start`, `attach`, `inspect`, `serve`, `extract`, `parse`, `cleanup`,
  `report`, `export`);
- **the configured database**: the database saved by `setup`/`on` in
  `~/.pentrail/state.json`, else the default path (`setup`, `on`, `flush`,
  `backup`, `verify`, `status`, `open`, and `start --auto`).

Variables that pentrail SETS inside a recorded shell (not user settings;
listed so they are not mistaken for configuration): `PENTRAIL=1`,
`PENTRAIL_SESSION`, `PENTRAIL_SOCKET`, `PENTRAIL_TOKEN`, `PENTRAIL_BIN`,
`PENTRAIL_ARTIFACTS`, `__PENTRAIL_HOOKED`, and, on Linux,
`PENTRAIL_AUTOSTART_SKIP` (set for a fallback shell so it does not start a
capture again).

## Automatic capture (background mode)

### `pentrail setup SHELL [flags]`

Opt-in: installs the binary in the user's directory and adds an autostart
block so that NEW terminals of that shell are recorded while recording is
enabled (`pentrail on`). Existing terminals are not touched. Running it
again replaces the block (idempotent). Refused while recording is enabled
and the database would change, or while sessions of the old database are
recording.

| Platform | `SHELL` | What is changed |
|---|---|---|
| Linux | `bash`, `zsh` | a marked block in `~/.bashrc` / `~/.zshrc` (`$ZDOTDIR/.zshrc` if set) |
| Windows | `powershell`, `pwsh`, `cmd`, or `windows` (= all of them; `pwsh` only if `pwsh.exe` is on PATH) | PowerShell: the user's profile (backup kept); CMD: the `AutoRun` value of the Command Processor registry key and `~\.pentrail\cmd-autorun.cmd` |

| Flag | Platform | Meaning |
|---|---|---|
| `--db PATH` | both | database to use (stored in the state, made absolute); default: the configured database |
| `--allow-plain` | both | allow a build WITHOUT SQLCipher (synthetic development data only); refused otherwise |
| `--allow-plain-artifacts` | both | allow wrapped tools (nmap/ffuf/nuclei) to write their structured output files in plaintext for import; default off |
| `--profile PATH` | Windows, PowerShell | write the autostart block to this profile instead of the shell's `$PROFILE` |
| `--registry-key KEY` | Windows, CMD | registry key for `AutoRun` (default `Software\Microsoft\Command Processor`) |

`pentrail --help` lists only `--db` for `setup`.

```sh
# Linux
pentrail setup bash
pentrail setup zsh --db ~/engagements/acme/pentrail.db
```

```powershell
# Windows
.\pentrail.exe setup windows
.\pentrail.exe setup pwsh --profile "$HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
```

### `pentrail on [flags]`

Unlocks the database once (passphrase prompt or `PENTRAIL_PASSPHRASE`),
starts the key agent, enables recording for new terminals and resumes
paused sessions of that database.

| Flag | Meaning |
|---|---|
| `--db PATH` | database; default: the configured database. Switching databases is refused while recording is enabled |
| `--allow-plain` | allow a build without SQLCipher (development only) |

`pentrail --help` shows `on` without flags.

### `pentrail off`

No flags. Pauses recording in every session of the configured database
(the shells keep running), disables autostart for new terminals and stops
the key agent. Output while paused is not recorded.

### `pentrail status`

No flags. Prints `enabled=… key_unlocked=… database=…` and one line per
live session of the configured database:
`session=N recording=true|false socket=PATH`, plus
`session=N RECORDING STOPPED after a storage failure: …` when capture
stopped after a database error.

### `pentrail flush [--db PATH]`

Asks every live session of the database to commit its queued output to
disk. `--db` default: the configured database.

### `pentrail backup [--db PATH] [--out PATH]`

SQLCipher builds only. Flushes live sessions, then writes and verifies an
encrypted copy of the database. `--out` default:
`<database dir>/backups/pentrail-YYYYMMDD-HHMMSS-<random>.db`. `--db`
default: the configured database (`pentrail --help` shows only `--out`).

### `pentrail verify [--file PATH]`

Checks the integrity of an encrypted database file with the passphrase.
`--file` default: the configured database. Prints
`encrypted database integrity: OK`.

### `pentrail open [--no-browser]`

Starts the local viewer for the configured database (captured evidence
read-only, operator notes editable; see `serve`) if it is not running yet, prints its link (with the access token) and opens it in the
default browser. `--no-browser` only prints the link.

## Interactive sessions

### `pentrail start [flags]`

Starts a recorded shell: a detached session server owns the shell and the
database, and this terminal attaches to it as a client.

| Flag | Platform | Meaning |
|---|---|---|
| `--db PATH` | both | database; default: the default path |
| `--shell SHELL` | Linux | shell executable; default `$SHELL`, else `/bin/bash` |
| `--shell SHELL` | Windows | `powershell` (default), `pwsh`, `cmd`, or a path |
| `--auto` | both | used by the generated autostart blocks: start only when automatic capture is enabled and unlocked, with the configured database. On Linux, if it fails, a normal shell starts instead |
| `--startup-profile PATH` | Windows | used by the generated PowerShell autostart block for a custom `--profile` |

`--auto` and `--startup-profile` are written by `setup`; they are not
meant to be typed. `pentrail --help` does not list them.

**Detaching:** press **Ctrl-\\** (byte 0x1C) in the attached terminal. The
client exits and prints that the session keeps running; the shell and the
recording continue. Closing the terminal or killing the client has the same
effect. Typing `exit` in the shell ends the session; the client then waits
for the final capture status. Output produced while no client is attached
is recorded but not replayed to the next client.

```sh
# Linux
PENTRAIL_PASSPHRASE='…' pentrail start --shell /bin/zsh
```

```powershell
# Windows
.\pentrail.exe start --shell pwsh
.\pentrail.exe start --shell cmd --db D:\engagement\pentrail.db
```

### `pentrail attach [--db PATH] [--sock PATH]`

Attaches to a running session. Without `--sock`, the newest live session in
`<database dir>/run` is used (stale sockets there are removed). `--db`
default: the default path. Detach again with Ctrl-\\. Several clients can be
attached; the one that typed most recently paces the output.

### `pentrail hook bash|zsh|powershell|pwsh`

Prints the shell integration hook (the markers that split the record into
commands). `pentrail --help` lists only `bash|zsh`; the code also accepts
`powershell`, `pwsh`, `powershell.exe` and `pwsh.exe` (one PowerShell hook).

## Reading the evidence

All of these open the database (passphrase as above). Without `--session N`,
`extract`, `parse`, and `cleanup` process all sessions. Only `report` and
`export` default to the newest session. Specify an ID for repeatable output.

### `pentrail inspect [--db PATH]`

Prints sessions, commands and raw-record statistics.

### `pentrail serve [flags]`

Local web viewer, protected by a token in the printed link. Before serving,
it refreshes derived data (artifact import, regex extraction, parsing,
cleanup checklist) for every session.

Captured evidence (commands, output record, entities, graph, cleanup data) is
read-only. The only thing the viewer writes is **operator notes**: plain-text
annotations (title and text) for a session, a command or a graph element,
written in the Notes tab or with “Add note” in the timeline and the graph.

- Notes are stored in the same encrypted database (table `notes`, added
  automatically to existing databases; no evidence table is changed), so
  encrypted backup and restore carry them. Drafts not yet saved exist only in
  the page's memory (never in browser storage, files or logs).
- Before a note is stored, recognized secrets are masked with the same rules as
  the record; the editor reports how many bytes were masked.
- Saving is automatic after a short pause and shows Saving / Saved / Not saved
  (with Retry). Every save names the revision it is based on: if the note was
  changed in another tab or viewer meanwhile, nothing is overwritten — the
  draft is kept and you choose “Load the saved version” or “Save my text over
  it”. Closing the page with unsaved notes asks for confirmation.
- Notes are archived and restored, never deleted. A note keeps a snapshot of
  what it was attached to, so it stays in the Notes view even if that command
  or graph element is gone.
- Changes require a same-origin request from the viewer page with a JSON body
  and a per-viewer write token; there is no CORS.
- Notes are private: `report` and `export` leave them out unless
  `--include-notes` is given.

| Flag | Meaning |
|---|---|
| `--db PATH` | database; default: the default path |
| `--addr HOST:PORT` | listen address; default `127.0.0.1:7878`. A non-loopback address is refused |
| `--allow-remote` | allow a non-loopback address deliberately (exposes session data on the network) |
| `--no-extract` | skip the refresh of derived data (not listed by `pentrail --help`) |

### `pentrail extract [--db PATH] [--session N]`

Regex extraction of indicators (IP, domain, URL, e-mail) from the record.

### `pentrail parse [--db PATH] [--session N]`

Parses structured tool output files (nmap XML, ffuf JSON, nuclei JSONL).

### `pentrail cleanup [--db PATH] [--session N]`

Prints the checklist of target state changes found in the commands (files
written, configuration and permission changes, accounts, services and
scheduled tasks) for the pentester to review and undo.

## Plaintext exports (explicit confirmation)

The database is encrypted; reports and exports are NOT. Both commands refuse
to run without `--confirm-plaintext`. Recognized secrets are masked in the
output. Operator notes are left out unless `--include-notes` is given; then
the session's active (not archived) notes appear in a separate “Operator notes”
section (HTML) or `operator_notes` field (JSON), labelled as annotations and
not captured evidence. The CSV export has no place for notes and refuses
`--include-notes`. The output file is created new with owner-only permissions (0600 on
Linux); an existing file is never overwritten (`destination already
exists`).

### `pentrail report --confirm-plaintext [--db PATH] [--session N] [--out FILE] [--include-notes]`

Masked HTML report. `--out` default: `pentrail-report-session-N.html` in the
current directory.

### `pentrail export --confirm-plaintext [--db PATH] [--session N] [--format json|csv] [--out FILE] [--include-notes]`

Masked JSON (default) or CSV export. `--out` default:
`pentrail-session-N.json` / `.csv` in the current directory.

```sh
pentrail report --confirm-plaintext --session 3 --out /secure/report-3.html
pentrail export --confirm-plaintext --format csv
pentrail export --confirm-plaintext --session 3 --include-notes --out /secure/session-3-with-notes.json
```

## Help

`pentrail help`, `pentrail -h`, `pentrail --help`: usage text and whether the
build uses SQLCipher.

## Internal entrypoints (not user commands)

These arguments exist in the same binary for the processes and hooks that
pentrail itself starts. They are not a stable interface and are not meant to
be run by hand.

| Entrypoint | Used by |
|---|---|
| `__session-server --db --shell --sock` (Windows also `--startup-profile`, `--initial-command`) | the detached session server spawned by `start`; the key arrives on a pipe, never in arguments or the environment |
| `__key-agent` | the key agent spawned by `on` |
| `__viewer --db` | the viewer process spawned by `open` |
| `__auto-check` | autostart blocks: exit 0 if a new terminal should start a capture |
| `__cmd-check` | the CMD autorun script (Windows) |
| `__same-console` | the CMD autorun script: exit 0 if this console is already recorded |
| `__capture-check` | hooks: exit 0 while capture is enabled |
| `__artifact-check` | the nmap/ffuf/nuclei wrappers in the hooks: exit 0 if plaintext tool output files are allowed (`--allow-plain-artifacts`) and capture is enabled |
