# Quick start

This guide takes you from a downloaded package to a recorded session and the
viewer. Every command and flag is described in [COMMANDS.md](COMMANDS.md).

In the examples, `pentrail` means `.\pentrail.exe` in PowerShell or
`./pentrail` on Linux when the program's directory is not on `PATH`.

## 1. Download and verify

Download `pentrail-<version>-windows-amd64.zip` or
`pentrail-<version>-linux-amd64.zip` and the `SHA256SUMS` file from the
release page. The packages are **not code-signed**; compare the checksum
before unpacking:

```powershell
Get-FileHash .\pentrail-<version>-windows-amd64.zip -Algorithm SHA256
# compare with the line for this file in SHA256SUMS
```

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

Unpack the package into a new, empty directory. On Linux use a tool that
keeps Unix permissions (for example Info-ZIP `unzip`); the `pentrail` binary
must be executable.

Windows may show a SmartScreen warning for an unsigned program. Only continue
if the checksum matches the release.

## 2. Requirements

- **Windows**: Windows 10 version 1809 or later, or Windows 11, x86-64.
  Windows PowerShell 5.1 (built in), PowerShell 7 (`pwsh`) or CMD. Nothing
  else needs to be installed.
- **Linux**: x86-64, Bash or Zsh. The release binary is static; no libraries
  need to be installed.
- A modern browser for the viewer.

## 3. Record one shell

Windows (PowerShell, in the unpacked directory):

```powershell
.\pentrail.exe start --shell powershell     # or: --shell pwsh, --shell cmd
```

Linux:

```sh
./pentrail start --shell bash               # or: --shell /bin/zsh
```

On first use Pentrail creates the encrypted database
`~/.pentrail/pentrail.db` (`%USERPROFILE%\.pentrail\pentrail.db` on Windows)
and asks for a passphrase (`pentrail passphrase:`). For a new database the
passphrase you type becomes its key. It is asked once, without a
confirmation prompt, so type it carefully. Remember it: **there is no way to
recover a database whose passphrase is lost.**

You now work in an ordinary shell whose commands and output are recorded.

- `exit` ends the shell and the session.
- `Ctrl+\` detaches this terminal; the session keeps running and recording.
- `pentrail attach` reattaches to the newest running session.

## 4. Open the viewer

In another terminal:

```sh
pentrail open
```

The viewer opens in your default browser at a `127.0.0.1` address with a
random access token. `pentrail open --no-browser` prints the link instead
(useful over SSH with a port forward). The [user guide](USER-GUIDE.md)
explains the timeline, the graph, the full session record, cleanup and notes.

## 5. Optional: record new terminals automatically

Instead of `start`, you can have every *new* terminal of a shell recorded
while recording is enabled. This changes your shell profile (a backup is made
first; the change can be repeated safely).

Windows:

```powershell
.\pentrail.exe setup windows          # PowerShell 5.1, CMD and PowerShell 7 if installed
# or only one: setup powershell | setup pwsh | setup cmd
& "$env:LOCALAPPDATA\Pentrail\bin\pentrail.exe" on
```

Linux:

```sh
./pentrail setup bash                 # or: ./pentrail setup zsh
~/.local/bin/pentrail on
```

Then open new terminal windows. Every day:

```sh
pentrail on        # unlock once and enable recording
pentrail off       # pause recording in all sessions; the shells keep running
pentrail status    # show the state of recording and of each session
pentrail open      # open the viewer
```

After a restart or log-out run `pentrail on` again; the passphrase is never
stored on disk. Terminals that were already open before `on` are not taken
over. Details: [WINDOWS.md](WINDOWS.md), [LINUX.md](LINUX.md).

## 6. Back up

```sh
pentrail backup --out backup-2026-11-01.db
pentrail verify --file backup-2026-11-01.db
```

The backup is encrypted with the same passphrase. See
[BACKUP-RECOVERY.md](BACKUP-RECOVERY.md).

## 7. Report (plaintext, only when you need it)

```sh
pentrail report --confirm-plaintext --session 1 --out report-session-1.html
```

Reports and exports are **not encrypted**. Recognized secrets are masked, but
targets, findings and unrecognized secrets remain. Store them accordingly.

## Removing automatic capture

`pentrail off` stops recording immediately. The `setup` block is marked in
your profile (`~/.bashrc`, `~/.zshrc`, the PowerShell profile) and the CMD
`AutoRun` value; a `.pentrail-backup-*` copy of the profile and, for CMD,
`~/.pentrail/cmd-autorun-backup.json` keep the previous state. There is no
`uninstall` command yet: remove the marked block (or restore the backup) and
delete the installed binary (`~/.local/bin/pentrail` or
`%LOCALAPPDATA%\Pentrail\bin`) by hand. Your database in `~/.pentrail` is not
deleted by any of this.
