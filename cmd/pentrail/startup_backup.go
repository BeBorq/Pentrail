package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"
)

// backupNow is the clock used to name startup-file backups (a test seam).
var backupNow = time.Now

// writeStartupBackup saves data next to path as a new file named
// path.pentrail-backup-<unix nanoseconds>, with a -<n> suffix when that name
// already exists. It never replaces an existing backup. The wall clock is
// coarse on some systems (on Windows it can return the same value for
// consecutive calls), so two setups in quick succession used to get the same
// name, and the second backup silently replaced the first: the copy of the
// user's original file was lost (GitHub Actions, windows-2025,
// TestWindowsSetupPreservesUTF16ProfileAndBackup: "missing backups").
func writeStartupBackup(path string, data []byte) (string, error) {
	base := path + fmt.Sprintf(".pentrail-backup-%d", backupNow().UnixNano())
	for n := 0; n < 1000; n++ {
		name := base
		if n > 0 {
			name = fmt.Sprintf("%s-%d", base, n)
		}
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		_, err = f.Write(data)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(name)
			return "", err
		}
		return name, nil
	}
	return "", fmt.Errorf("no free backup name for %s", path)
}
