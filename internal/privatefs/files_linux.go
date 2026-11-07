//go:build linux

package privatefs

import (
	"os"
	"path/filepath"
	"syscall"
)

func protectDir(path string) error   { return os.Chmod(path, 0700) }
func protectHandle(f *os.File) error { return f.Chmod(0600) }
func openPrivate(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
func Publish(from, to string) error {
	if e := os.Link(from, to); e != nil {
		return e
	}
	if e := os.Remove(from); e != nil {
		return e
	}
	d, e := os.OpenFile(filepath.Dir(to), os.O_RDONLY, 0)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
