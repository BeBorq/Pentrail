# Pentrail on Windows

Windows 10 version 1809 or later and Windows 11, x86-64. Pentrail uses the
native Windows console (ConPTY). WSL, Python, Node and a separate SQLCipher
installation are not needed. All commands and flags:
[COMMANDS.md](COMMANDS.md).

## One recorded shell

```powershell
.\pentrail.exe start --shell powershell   # Windows PowerShell 5.1 (default)
.\pentrail.exe start --shell pwsh         # PowerShell 7, if installed
.\pentrail.exe start --shell cmd
```

## Automatic capture of new terminals

In the folder of the unpacked package, in PowerShell:

```powershell
.\pentrail.exe setup windows
& "$env:LOCALAPPDATA\Pentrail\bin\pentrail.exe" on
```

`setup windows` configures Windows PowerShell 5.1, CMD and PowerShell 7 (if
`pwsh.exe` is on `PATH`). To configure only one shell, use
`setup powershell`, `setup pwsh` or `setup cmd`. Then open new terminal
windows.

Every day: `pentrail on`, `pentrail off`, `pentrail status`, `pentrail open`.
After a restart run `on` again. New configured windows start recording
without a banner and without asking for the passphrase again. `off` pauses
all managed sessions without closing the shells; `on` resumes them. Windows
opened earlier are not taken over.

## What setup changes

- The binary is copied to `%LOCALAPPDATA%\Pentrail\bin`. `PATH` is extended
  only inside the configured shells; the system `PATH` is not changed.
- **PowerShell**: a marked block at the beginning of the CurrentUserAllHosts
  profile (or the profile given with `--profile PATH`). The rest of your
  profile runs once, inside the recorded shell. UTF-8 and UTF-16 profiles are
  supported; a `.pentrail-backup-*` copy is made first; running setup again
  does not duplicate the block. The execution policy is not changed — it must
  allow your own profile to run.
- **CMD**: only the `AutoRun` value of
  `HKCU\Software\Microsoft\Command Processor` for the current user (or the
  key given with `--registry-key`). The previous value and its type are
  saved in `~\.pentrail\cmd-autorun-backup.json`; an existing AutoRun command
  still runs first. The script `~\.pentrail\cmd-autorun.cmd` is ASCII and
  independent of the code page.

To undo setup, remove the marked block from the PowerShell profile (or restore
the backup copy), restore the previous `AutoRun` value, and delete
`%LOCALAPPDATA%\Pentrail\bin`.

## Security on Windows

The passphrase is not stored in the profile, the registry, process arguments
or the environment of started tools. The key stays in the memory of the key
agent. Local IPC uses named pipes with an access list for the current user
only and rejects remote clients. The state and IPC directories have private
access lists. Processes of the same account and administrators are outside
the isolation boundary. See [SECURITY-MODEL.md](SECURITY-MODEL.md).

The default database is `%USERPROFILE%\.pentrail\pentrail.db`. For a custom
`--db`, choose a private directory: Pentrail does not change the access list
of an existing directory.

## The record on Windows

ConPTY returns a *rendered* terminal stream. The split into commands is
auxiliary, and the viewer always offers the **Full session record** and warns
about gaps. Reports and JSON exports state the capture mode `conpty-session`.
PowerShell uses PSReadLine to learn accepted commands; CMD recognizes simple
entries at the prompt. The import of nmap/ffuf/nuclei output files is a
Bash/Zsh feature; on Windows the commands and output of these tools are
recorded through the console. Details: [LIMITATIONS.md](LIMITATIONS.md).

## Building on Windows

The release package contains the encrypted binary. A custom build needs Go
and a CGO-compatible C compiler, for example MinGW-w64 `gcc`:

```powershell
$env:CGO_ENABLED = '1'
go build -tags sqlcipher -o pentrail.exe ./cmd/pentrail
```

Release packages are built with `zig cc`; see [RELEASING.md](RELEASING.md).
