# Security model

Pentrail is a single-user tool that runs on your own computer. This document
states what it protects against, what it relies on, and what it does not
protect against. Encryption and masking are described in
[DATA-PROTECTION.md](DATA-PROTECTION.md).

## Assets

- The recorded commands and terminal output, extracted findings, cleanup data
  and operator notes (the database and its backups).
- The database passphrase and the key derived from it.
- The viewer's access token.

## Trust boundary

**Trusted:** your user account, the processes running under it, and the
administrator (root) of the computer. Pentrail does not try to isolate the
key or the data from a malicious process running as the same user or from an
administrator; such a process can read process memory, keystrokes and the
terminal anyway.

**Not trusted:** other local user accounts, other computers on the network,
and web pages open in your browser.

## Protections

### Data at rest

- SQLCipher encryption of the database, WAL and backups (release builds).
- Owner-only permissions on the database, its auxiliary files and new data
  directories (0600/0700 on Linux, a current-user access list on Windows).
- Files are created without following symbolic links; reports, exports and
  backups never overwrite an existing file.

### The key

- The passphrase is never stored on disk and never passed to the recorded
  shell through arguments or the environment.
- The key agent (`pentrail on`) and session servers receive the key over a
  local pipe, not in arguments or the environment.
- Linux: the agent listens on a Unix socket (0600) in a private directory
  (0700) and checks the peer's user ID. `mlockall` is attempted to keep the key
  out of swap; this is best-effort.
- Windows: local IPC uses named pipes whose access list allows only the
  current user, and remote pipe clients are rejected. The agent tries to lock
  its key buffer against paging.

### The viewer

- Listens on `127.0.0.1` by default. A non-loopback address is refused unless
  `--allow-remote` is given.
- Every request must present a random 128-bit token (from the printed link,
  then an `HttpOnly`, `SameSite=Strict` cookie). Tokens are compared in
  constant time. A restarted viewer has a new token.
- Every request must carry a loopback `Host` header, and a present `Origin`
  must be a loopback origin. This defends against DNS rebinding and
  cross-site reads. (Because of this check a remote browser cannot use the
  viewer even with `--allow-remote`; use an SSH port forward to a loopback
  viewer instead.)
- Captured evidence is served read-only. The only writes are operator notes,
  which additionally require a same-origin JSON request with a per-viewer
  write token; there is no CORS.
- The viewer uses plain HTTP on the loopback interface; there is no TLS.

### Masking and plaintext output

- Recognized secrets are masked before they are stored (see the limits in
  [DATA-PROTECTION.md](DATA-PROTECTION.md#limits-of-masking)).
- Plaintext reports and exports need an explicit `--confirm-plaintext`.

## Not protected against

- Malware or another person using your unlocked user account. While the key
  agent, a session server or the viewer is running, the open database is
  accessible to processes of your account.
- Secrets that masking does not recognize.
- Someone who has the passphrase and an old disk image or backup.
- Physical attacks, cold-boot attacks and memory forensics.
- The loss of data that a crash, power loss or reboot prevents from being
  received and committed (see [LIMITATIONS.md](LIMITATIONS.md)).
- Tampering with the binary itself. Release packages are not code-signed;
  check their SHA-256 and, if needed, build them yourself
  ([RELEASING.md](RELEASING.md)).

## Dependency audit

Release builds use the Go toolchain named in `go.mod` (`toolchain go1.27.3`)
and the module versions in `go.sum`; `golang.org/x/sys` is at v0.44.0 or
later because of GO-2026-5024 (CVE-2026-39824); it is v0.49.0, the version
that `github.com/Microsoft/go-winio` v0.6.4 requires. Before a release the
binaries are checked with `govulncheck` (binary mode). Its scope and limits:

- It covers the Go standard library and the Go modules linked into the
  binary. In binary mode it reports vulnerable symbols that are present; this
  over-approximates what is reachable, and a JSON report with exit code 0 is
  not by itself a clean result — read the findings.
- It does **not** cover C code compiled into the binary: the SQLite 3.33.0
  amalgamation with SQLCipher 4.4.2 and LibTomCrypt (from
  `github.com/mutecomm/go-sqlcipher/v4` v4.4.2), and the musl or mingw-w64 C
  runtime. These have not been audited for this release. SQLite 3.33.0 dates
  from 2020; Pentrail opens only its own database files and does not run SQL
  supplied by others, but it does not claim the bundled C code is free of
  known vulnerabilities. Replacing it is a separate change, because it can
  affect the compatibility of existing encrypted databases.

No audit shows that a program has no vulnerabilities or bugs.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
