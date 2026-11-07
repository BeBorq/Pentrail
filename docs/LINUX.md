# Pentrail on Linux

Linux x86-64 with Bash or Zsh. The release binary is statically linked and
includes SQLCipher. All commands and flags: [COMMANDS.md](COMMANDS.md).

## One recorded shell

```sh
./pentrail start                    # $SHELL, or /bin/bash if unset
./pentrail start --shell /bin/zsh
```

## Automatic capture of new terminals

```sh
./pentrail setup zsh                # or: ./pentrail setup bash
~/.local/bin/pentrail on
```

`setup` copies the binary to `~/.local/bin/pentrail` and adds a marked block
to `~/.bashrc` or `~/.zshrc` (`$ZDOTDIR/.zshrc` if `ZDOTDIR` is set). A
`.pentrail-backup-*` copy is made first; running setup again does not
duplicate the block. Setup alone does not enable recording.

Then open new terminal windows. The automatic start shows no banner, opens no
browser and does not ask for the passphrase again. Non-interactive scripts are
not wrapped, and a shell already running under Pentrail does not get a second
wrapper. If the automatic start fails, an error is printed and an ordinary
shell starts — a capture failure is never hidden.

```sh
pentrail on                  # unlock the key and enable recording; resume managed sessions
pentrail off                 # stop recording in all managed sessions
pentrail status              # global state, key lock and the state of each session
pentrail open                # open the viewer in the browser
pentrail open --no-browser   # print the link, e.g. when working over SSH
```

`on` and `off` also work from another terminal. While recording is off, output
still reaches the terminal but is not recorded, and the nmap/ffuf/nuclei
wrappers do not add the flags that create output files. After a restart or
the loss of the key agent, run `on` again; `status` then shows
`key_unlocked=false`. The passphrase is never stored on disk.

To undo setup, remove the marked block from `~/.bashrc`/`~/.zshrc` (or restore
the backup copy) and delete `~/.local/bin/pentrail`.

## Tool output files

In Bash and Zsh, the hooks can add output-file flags to nmap, ffuf and nuclei
so that their structured results are imported. This is **off by default**;
enable it with `setup ... --allow-plain-artifacts`, and read
[DATA-PROTECTION.md](DATA-PROTECTION.md#tool-output-files-nmap-ffuf-nuclei)
first, because the files exist in plaintext until they are imported.

## Security on Linux

The key agent uses a Unix socket (0600) in a private directory (0700) and
checks the client's user ID. The key is passed through the socket, not
through the shell environment or a configuration file. `mlockall` is
best-effort. The agent trusts processes of the same user. `off` ends the key
agent, but running session servers and an open viewer keep their open
database. See [SECURITY-MODEL.md](SECURITY-MODEL.md).

## Over SSH

Run `pentrail open --no-browser` on the remote computer; it prints a link
with a port chosen at start. Forward that port, for example
`ssh -L 41234:127.0.0.1:41234 host` for a link on port 41234, and open the
link locally. For a fixed port, run `pentrail serve` instead (default
`127.0.0.1:7878`). Do not use `--allow-remote` for this.

## Building on Linux

```sh
CGO_ENABLED=1 go build -tags sqlcipher -o pentrail ./cmd/pentrail
```

needs Go and a C compiler (`gcc` or `clang`). The release binary is built
statically with `zig cc` and musl; see [RELEASING.md](RELEASING.md).
