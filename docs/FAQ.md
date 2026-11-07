# Frequently asked questions

### Does Pentrail send anything over the network?

No. Pentrail has no telemetry and makes no network requests of its own,
apart from `pentrail open` checking its own viewer on `127.0.0.1`. The
viewer listens on the loopback interface and its page loads no external
scripts or fonts. Programs you run inside a recorded shell of course use the
network as usual.

### Where is my data?

In one encrypted database, by default `~/.pentrail/pentrail.db`
(`%USERPROFILE%\.pentrail\pentrail.db` on Windows), plus its `-wal`/`-shm`
files, backups you create, and the state and log files in `~/.pentrail`.
Use `--db` or `PENTRAIL_DB` to keep a separate database per engagement.

### I forgot my passphrase. Can the data be recovered?

No. There is no recovery key.

### Are my passwords stored?

Recognized secrets are masked before storage, but masking cannot recognize
every secret. Treat the database as confidential. See
[DATA-PROTECTION.md](DATA-PROTECTION.md#limits-of-masking).

### Why is the command list incomplete, or why are commands split oddly?

The command list is derived from shell markers and is auxiliary. Inside `ssh`,
a subshell or an interactive program there are no markers; on Windows the
console reorders screen output. The **Full session record** in the timeline
always contains the recorded terminal stream. See
[LIMITATIONS.md](LIMITATIONS.md#splitting-the-record-into-commands).

### Can I record a session on a remote server?

Run Pentrail on the computer where the shell runs. If you `ssh` from a
recorded local shell, the remote session's output is recorded as part of the
local terminal stream, without a split into remote commands.

### Does `pentrail off` lock the database?

It stops recording and the key agent, but running session servers and an open
viewer keep their open database in memory until they end. It is not a
cryptographic log-out.

### The viewer says the link expired (401).

The viewer was restarted and has a new token. Run `pentrail open` again and
use the new link.

### Why are the packages not signed?

Code-signing certificates are not used for this project. Verify the SHA-256
checksum from the release page, or build the packages yourself from the
tagged sources ([RELEASING.md](RELEASING.md)). Windows SmartScreen may warn
about an unknown publisher.

### Can I use the unencrypted build?

Only for development with synthetic data. It requires `--allow-plain` for
`setup` and `on`.

### How do I update?

Unpack the new version into a separate directory. Sessions that are already
running keep using the old program; let them finish (or keep serving them
with the old binary) and start new sessions with the new version. For
automatic capture, run `setup` again with the new binary; it replaces the
installed copy and keeps a single profile block.

### Does Pentrail work on macOS or ARM?

Not at the moment. Only Windows x86-64 and Linux x86-64 are built and tested.

### How do I stop using Pentrail?

Run `pentrail off`, remove the marked blocks that `setup` added (see
[QUICKSTART.md](QUICKSTART.md#removing-automatic-capture)) and delete the
installed binary. Delete the database and backups only when you no longer
need the record.
