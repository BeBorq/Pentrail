# Backup and recovery

## Making a backup

```sh
pentrail backup                         # default: <database dir>/backups/pentrail-YYYYMMDD-HHMMSS-<random>.db
pentrail backup --out /secure/pentrail-backup.db
pentrail verify --file /secure/pentrail-backup.db
```

`backup`:

1. asks running sessions of the database to commit their queued output;
2. writes a consistent image of the committed data — including data that is
   still only in the WAL — to a new file; unfinished lines from the recovery
   buffer are masked and written into the record of the copy;
3. checks the copy with SQLCipher and SQLite integrity checks and prints its
   SHA-256.

The backup is encrypted with **the same passphrase**. The source database is
not changed, and an existing destination file is refused. Operator notes are
part of the database and are included.

Never copy only the `.db` file of a database that is in use: recent data can
be in the `-wal` file next to it. Use `pentrail backup`.

## Verifying

```sh
pentrail verify --file PATH
```

prints `encrypted database integrity: OK` when the file opens with the
passphrase and passes the integrity checks of the database and its relations.
It does not prove that the recording itself is complete.

## Reading a backup

A backup is an ordinary Pentrail database. Use it with `--db`:

```sh
pentrail inspect --db /secure/pentrail-backup.db
pentrail serve   --db /secure/pentrail-backup.db
```

## Restoring

There is no restore command. To go back to a backup:

1. run `pentrail off` and end the recorded sessions of the database (`exit`);
2. close the viewer;
3. move the current database files (`pentrail.db`, `pentrail.db-wal`,
   `pentrail.db-shm`) aside — do not delete them until the restored copy
   works;
4. copy the backup to the database path, for example
   `~/.pentrail/pentrail.db`;
5. run `pentrail verify` and `pentrail on`.

Never overwrite the database of a running session.

## After a crash

If a session server or the computer crashed, open the database again (for
example with `pentrail inspect` or the viewer). Pentrail checks whether the
owner of each unfinished-line buffer is still running; for a dead owner it
masks the buffer and appends it to the record in one transaction, and marks
the command as unfinished. Bytes that never reached Pentrail cannot be
recovered. See [LIMITATIONS.md](LIMITATIONS.md#durability).

## Losing the passphrase

The database and all its backups are encrypted with the passphrase. There is
no recovery key and no way to recover a lost passphrase.

## Storing backups

Backups contain everything the database contains. Store them where only you
can read them. Deleting a backup file is not secure erasure of the disk.
