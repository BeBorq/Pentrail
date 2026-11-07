//go:build linux

package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// O_NONBLOCK: opening a FIFO planted under the artifact name must not hang
// the importer (it has no effect on regular files).
func openArtifact(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func identityOf(fi os.FileInfo) (string, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino), true
}

func fileIdentity(f *os.File) (string, error) {
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	id, ok := identityOf(fi)
	if !ok {
		return "", errors.New("no inode information")
	}
	return id, nil
}

// cleanupHook lets tests act at exact points of the cleanup (nil in
// production). Stages: verified, intent, quarantined, before-unlink.
var cleanupHook func(stage, dir, name string)

func hook(stage, dir, name string) {
	if cleanupHook != nil {
		cleanupHook(stage, dir, name)
	}
}

// setLease takes a write lease; tests replace it to simulate a filesystem or
// file owner that does not allow one.
var setLease = func(fd int) error {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_SETLEASE, unix.F_WRLCK)
	return err
}

// leaseIntact reports whether our write lease is still held with no break
// pending (F_GETLEASE returns the target type while a break is pending).
func leaseIntact(fd int) bool {
	t, err := unix.FcntlInt(uintptr(fd), unix.F_GETLEASE, 0)
	return err == nil && t == unix.F_WRLCK
}

// quarantineLog durably records (qname != "") or clears (qname == "") the
// quarantine name in the database. It is called BEFORE the rename, so a
// crash at any later point leaves a record that recovery can follow.
type quarantineLog func(qname, dirIdentity string) error

// heldFile is the original, opened without following symlinks, verified
// and protected by a write lease for the whole cleanup.
type heldFile struct {
	f     *os.File
	fd    int
	lease bool
}

func (h *heldFile) close() {
	if h.lease {
		unix.FcntlInt(uintptr(h.fd), unix.F_SETLEASE, unix.F_UNLCK)
	}
	h.f.Close()
}

// removeVerified deletes path only if it is still the imported file.
//
// Unix has no "unlink this inode" call (Codex iterations 02/03). Protocol:
//
//  1. open the name inside the opened parent directory without following
//     symlinks; check: regular file, same dev:inode, ONE link, same size;
//  2. take a WRITE LEASE on that descriptor. It is granted only if no other
//     open file description exists, and from then on every other open of the
//     inode waits (lease break) until we release it — so the bytes cannot
//     change behind us. No lease (filesystem or file owner does not allow
//     it) means no such guarantee: the file is KEPT and that is recorded;
//  3. hash the bytes (SHA-256 of the imported original) under the lease;
//  4. durably record a random quarantine name in the database, THEN move the
//     name there (renameat2 RENAME_NOREPLACE: nothing is ever overwritten).
//     A crash after this point is recovered from the record;
//  5. check that the quarantine name holds OUR inode (the original name may
//     have been swapped before the rename) and that the lease is intact (no
//     other process tried to open the file in the meantime);
//  6. unlink the quarantine name while the lease is still held; check the
//     lease once more; only then release it and clear the record.
//
// Anything unexpected puts the file back under its name with
// RENAME_NOREPLACE; if that name was taken meanwhile, nothing is overwritten:
// the file stays under the recorded quarantine name, cleanup stays pending
// and the stored state says where.
func removeVerified(path, identity string, size int64, sum string, logq quarantineLog) (cleanupOutcome, string) {
	dirPath := filepath.Dir(path)
	dir, err := os.OpenFile(dirPath, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return cleanupGone, ""
		}
		return cleanupFailed, err.Error()
	}
	defer dir.Close()
	dfd := int(dir.Fd())
	dirID, err := fileIdentity(dir)
	if err != nil {
		return cleanupFailed, err.Error()
	}
	name := filepath.Base(path)

	h, outcome, why := holdVerified(dfd, name, identity, size, sum)
	if h == nil {
		return outcome, why
	}
	defer h.close()
	hook("verified", dirPath, name)

	qname, err := quarantineName()
	if err != nil {
		return cleanupFailed, err.Error()
	}
	if err := logq(qname, dirID); err != nil {
		return cleanupFailed, "could not record the quarantine name: " + err.Error()
	}
	hook("intent", dirPath, qname)
	if err := unix.Renameat2(dfd, name, dfd, qname, unix.RENAME_NOREPLACE); err != nil {
		logq("", "")
		switch {
		case errors.Is(err, unix.ENOENT):
			return movedAway(h)
		case errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS):
			return cleanupKept, "the file system does not support a safe rename (renameat2); delete the plaintext copy manually"
		default:
			return cleanupFailed, err.Error()
		}
	}
	hook("quarantined", dirPath, qname)
	return finishQuarantined(dfd, dirPath, name, qname, h, logq)
}

// holdVerified opens name in dfd and verifies it under a write lease. On
// success the caller owns the returned heldFile.
func holdVerified(dfd int, name, identity string, size int64, sum string) (*heldFile, cleanupOutcome, string) {
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOENT):
			return nil, cleanupGone, ""
		case errors.Is(err, unix.ELOOP):
			return nil, cleanupMismatch, "symbolic link"
		default:
			return nil, cleanupFailed, err.Error()
		}
	}
	h := &heldFile{f: os.NewFile(uintptr(fd), name), fd: fd}
	fail := func(o cleanupOutcome, why string) (*heldFile, cleanupOutcome, string) {
		h.close()
		return nil, o, why
	}
	fi, err := h.f.Stat()
	if err != nil {
		return fail(cleanupFailed, err.Error())
	}
	if !fi.Mode().IsRegular() {
		return fail(cleanupMismatch, "this is not a regular file")
	}
	st := fi.Sys().(*syscall.Stat_t)
	if id, _ := identityOf(fi); id != identity {
		return fail(cleanupMismatch, "a different file (different inode)")
	}
	if st.Nlink != 1 {
		return fail(cleanupMismatch, fmt.Sprintf("the file has %d hard links — removing one name would not remove the data", st.Nlink))
	}
	if fi.Size() != size {
		return fail(cleanupMismatch, "zmieniony rozmiar")
	}
	switch err := setLease(fd); {
	case err == nil:
		h.lease = true
	case errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EBUSY):
		return fail(cleanupFailed, "the file is open in another process; will retry later")
	default:
		// No equivalent guarantee that the bytes cannot change between the
		// hash and the deletion: keep the file (Codex iteration 03).
		return fail(cleanupKept, "no file lease ("+err.Error()+"; e.g. another file owner or a file system without leases) — it is not certain that the bytes to delete are the imported ones; the plaintext copy was kept, delete it manually")
	}
	if ok, why := hashMatches(h.f, size, sum); !ok {
		return fail(cleanupMismatch, why)
	}
	after, err := h.f.Stat()
	if err != nil {
		return fail(cleanupFailed, err.Error())
	}
	ast := after.Sys().(*syscall.Stat_t)
	if after.Size() != size || ast.Mtim != st.Mtim || ast.Ctim != st.Ctim || ast.Nlink != 1 || !leaseIntact(fd) {
		return fail(cleanupFailed, "the file changed or was opened during verification; will retry")
	}
	return h, cleanupRemoved, ""
}

// finishQuarantined deletes qname if it still is the held, leased file.
func finishQuarantined(dfd int, dirPath, name, qname string, h *heldFile, logq quarantineLog) (cleanupOutcome, string) {
	var qs unix.Stat_t
	if err := unix.Fstatat(dfd, qname, &qs, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			logq("", "")
			return movedAway(h)
		}
		return cleanupFailed, err.Error()
	}
	var hs unix.Stat_t
	if err := unix.Fstat(h.fd, &hs); err != nil {
		return cleanupFailed, err.Error()
	}
	if qs.Dev != hs.Dev || qs.Ino != hs.Ino {
		// the original name had been swapped before the rename: what we
		// moved is someone else's file
		return restore(dfd, dirPath, qname, name, logq, cleanupMismatch, "a different file was under the name at the moment of the move")
	}
	hook("before-unlink", dirPath, qname)
	if !leaseIntact(h.fd) {
		return restore(dfd, dirPath, qname, name, logq, cleanupFailed, "another process opened the file during deletion; not deleted, will retry")
	}
	if err := unix.Unlinkat(dfd, qname, 0); err != nil {
		return restore(dfd, dirPath, qname, name, logq, cleanupFailed, err.Error())
	}
	intact := leaseIntact(h.fd)
	hook("unlinked", dirPath, qname)
	logq("", "")
	if !intact {
		// An open of the quarantine name raced with unlink: its writes, if
		// any, go to the deleted inode. Rare (it must name the random file)
		// but never silent.
		return cleanupRemovedWarn, "deleted, but another process was opening this file at the moment of deletion — anything it wrote to it may be lost"
	}
	return cleanupRemoved, ""
}

// movedAway: the name disappeared under us. If the inode still has a link it
// was moved, not deleted — that is not a clean state.
func movedAway(h *heldFile) (cleanupOutcome, string) {
	var s unix.Stat_t
	if err := unix.Fstat(h.fd, &s); err == nil && s.Nlink > 0 {
		return cleanupMismatch, "the file was moved by another process; the plaintext copy still exists elsewhere"
	}
	return cleanupGone, ""
}

func quarantineName() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return ".pentrail-cleanup-" + hex.EncodeToString(b[:]), nil
}

// restore puts the quarantined file back under its original name, never
// overwriting anything created there in the meantime. Only a successful
// restore clears the quarantine record.
func restore(dfd int, dirPath, qname, name string, logq quarantineLog, outcome cleanupOutcome, why string) (cleanupOutcome, string) {
	err := unix.Renameat2(dfd, qname, dfd, name, unix.RENAME_NOREPLACE)
	if err == nil {
		logq("", "")
		return outcome, why
	}
	where := filepath.Join(dirPath, qname)
	if errors.Is(err, unix.EEXIST) {
		return cleanupStuck, fmt.Sprintf("%s; a new file already exists under the original name, so it was not overwritten — this file was left as %s", why, where)
	}
	return cleanupStuck, fmt.Sprintf("%s; could not restore the name (%v) — the file was left as %s", why, err, where)
}

// recoverQuarantine follows a quarantine record left by an interrupted
// cleanup (crash or kill between the record and its clearing). done=false:
// nothing is quarantined any more, continue with the normal cleanup.
func recoverQuarantine(path, qname, dirIdentity, identity string, size int64, sum string, logq quarantineLog) (cleanupOutcome, string, bool) {
	dirPath := filepath.Dir(path)
	where := filepath.Join(dirPath, qname)
	dir, err := os.OpenFile(dirPath, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return cleanupStuck, fmt.Sprintf("interrupted deletion: directory %s is not accessible (%v); the plaintext copy may still exist as %s or in the moved directory", dirPath, err, qname), true
	}
	defer dir.Close()
	dfd := int(dir.Fd())
	if id, err := fileIdentity(dir); err != nil || id != dirIdentity {
		return cleanupStuck, fmt.Sprintf("interrupted deletion: directory %s was replaced by another one (moved?); the plaintext copy may still exist as %s in the moved directory — nothing was deleted", dirPath, qname), true
	}
	var qs unix.Stat_t
	if err := unix.Fstatat(dfd, qname, &qs, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			// never renamed, or already deleted: forget the record and
			// continue with the original name
			if err := logq("", ""); err != nil {
				return cleanupFailed, err.Error(), true
			}
			return 0, "", false
		}
		return cleanupFailed, err.Error(), true
	}
	h, outcome, why := holdVerified(dfd, qname, identity, size, sum)
	if h == nil {
		switch outcome {
		case cleanupFailed:
			return cleanupFailed, "interrupted deletion, quarantined file " + where + ": " + why, true
		case cleanupGone:
			logq("", "")
			return 0, "", false
		}
		// not (or no longer provably) the imported bytes: give it back
		o, w := restore(dfd, dirPath, qname, filepath.Base(path), logq, cleanupMismatch, "interrupted deletion: the quarantined file is not the imported original ("+why+"); restored under the original name")
		return o, w, true
	}
	defer h.close()
	hook("recover-verified", dirPath, qname)
	o, w := finishQuarantined(dfd, dirPath, filepath.Base(path), qname, h, logq)
	return o, w, true
}
