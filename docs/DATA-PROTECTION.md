# Data protection: encryption and masking

This document describes how Pentrail protects the recorded data and where
that protection ends. It describes the current version; it is not a
guarantee that every secret is detected.

## Encryption at rest

Release packages are built with SQLCipher. The whole database — commands,
terminal stream, extracted findings, cleanup data and operator notes — is
encrypted with a key derived from your passphrase.

- The passphrase is asked for interactively (`pentrail passphrase:`) or read
  from `PENTRAIL_PASSPHRASE`, which Pentrail removes from its own environment
  as soon as it is read, so the recorded shell and its tools do not inherit
  it.
- The passphrase is not written to the profile, the registry, process
  arguments, configuration files or logs.
- `pentrail on` starts a key agent that keeps the key in memory so that new
  terminals do not ask again. It is reachable only through a local socket or
  named pipe of the current user (see [SECURITY-MODEL.md](SECURITY-MODEL.md)).
- `pentrail off` stops recording and the key agent. It is **not** a
  cryptographic log-out: session servers that keep running and an open viewer
  still hold the open database (and its key) in memory.
- A lost passphrase cannot be recovered.

A build without `-tags sqlcipher` stores the database **unencrypted**. It is
for development with synthetic data, and `setup`/`on` refuse it without
`--allow-plain`.

## Masking before storage

Before commands, the terminal stream and imported tool files are stored,
recognized secrets are replaced with `*`. The mask keeps the byte length, so
offsets in the record stay valid. The number of masked bytes is recorded and
shown.

The rules recognize, among others:

- labelled passwords (`password`, `passwd`, and other labels including
  Polish `hasło`), tokens and API keys;
- secret arguments of common tools;
- credentials in URLs (`scheme://user:secret@host`);
- `Authorization` and `Cookie` headers;
- JSON and XML fields with secret names;
- PEM private keys;
- selected token formats.

The rules handle ANSI colours, data that arrives split into chunks, lines
broken by the Windows console (ConPTY) and the CMD command marker. Large
JSON/JSONL/XML tool files are masked field by field, keeping their structure.

The viewer, the HTML report and the JSON/CSV exports apply the current rules
again when they read older records, so improvements to the rules also cover
data stored by earlier versions **on display**. The stored bytes of older
records are not rewritten.

### Limits of masking

- An arbitrary password cannot be reliably told apart from ordinary text. A
  secret without a recognizable label or format, a deliberately encoded
  secret, or one assembled from fragments **can remain in the record**.
- A very long line or an uncertain record boundary is masked conservatively,
  which can hide ordinary text too.
- Masking does not make a record non-confidential: targets, addresses,
  findings and unrecognized secrets remain.
- Pentrail does not touch the shell's own history, the clipboard, or files
  created by other tools. In recorded PowerShell sessions it turns off
  history-based command prediction so that a suggestion does not display a
  command typed during a pause, but deliberately recalling history can still
  show old data.

## The recovery buffer

To survive a crash of the recording process, an unfinished output line (up to
about 64 KiB per session) is kept in an encrypted checkpoint table in the same
transaction as the finished data, and committed before the output is shown on
the screen. This line **may contain a secret that has not been recognized
yet**, because the line is not complete. The viewer and exports never read
this table.

When the database is opened after the owning process has died, the buffer is
masked, appended to the record and removed in one transaction. A running
session's buffer is never recovered early. `pentrail off` removes the
checkpoint after committing the data from before the pause; output from the
pause never enters the record.

## Files and permissions

- The database and its auxiliary files are created with owner-only
  permissions (0600 on Linux; an access list of the current user on Windows).
  New data directories are private. An existing directory you name with
  `--db` keeps its permissions — choose a private directory.
- Destination files are created without following links. `report`, `export`
  and `backup` never overwrite an existing file. Exports are written to a
  private temporary file, synced, and only then given their final name.
- SQLite runs in WAL mode with `synchronous=FULL`; SQL temporary data is kept
  in memory.
- Diagnostics of background processes go to plaintext `.log` files in a
  private `run` directory (for example `~/.pentrail/run/`) and are masked with the same rules as the record. The
  viewer's access link (with its token) is written unmasked to the viewer
  process's private output file, because `pentrail open` reads it from there.

## Deletion is not secure erasure

Deleting or replacing data does not guarantee that older versions of
encrypted pages are physically erased from the WAL, the disk or external
snapshots. Someone who has the passphrase and a suitable disk image may
restore older versions. Migrations keep old data and do not erase it.

## Plaintext reports and exports

`report` and `export` create **unencrypted** files and refuse to run without
`--confirm-plaintext`. Recognized secrets are masked and CSV fields that
spreadsheets interpret as formulas are neutralized. After you copy a report
elsewhere, its permissions depend on the new location. Operator notes are
included only with `--include-notes`.

## Tool output files (nmap, ffuf, nuclei)

In Bash and Zsh sessions Pentrail can import the structured output of nmap
(XML), ffuf (JSON) and nuclei (JSONL). Writing these extra plaintext files is
**off by default** and enabled only with
`setup ... --allow-plain-artifacts`. When enabled:

1. the file is imported and masked after the producing tool has finished;
2. the plaintext copy is then deleted. On Linux the file is opened without
   following links, checked (same inode, a single link, unchanged size) and
   protected with a write lease until it is deleted; a file that is linked
   elsewhere, open in another process, not a regular file, or the database
   itself is not deleted, and the reason is recorded;
3. an interrupted deletion is finished or rolled back on the next start.

Until import, the file exists in plaintext. A crash, or a scan that outlives
the session, can leave it behind. Ordinary deletion is not secure erasure.
An invalid or truncated document is recorded as rejected or `PARTIAL` and is
not deleted. On Windows these extra files are not created; the commands and
output of the tools are recorded through the console.

## Operator notes

Notes are stored only in the encrypted database (so the encrypted backup
contains them), never in browser storage, draft files or logs. Recognized
secrets are masked before a note is stored; the original text is not kept.
Writing, archiving or restoring a note never changes captured evidence.
