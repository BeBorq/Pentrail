package privatefs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func EnsureDir(path string) error {
	fi, e := os.Stat(path)
	if e == nil {
		if !fi.IsDir() {
			return errors.New("parent is not a directory")
		}
		return nil
	}
	if !os.IsNotExist(e) {
		return e
	}
	if e = os.MkdirAll(path, 0700); e != nil {
		return e
	}
	return protectDir(path)
}
func NewTemp(dest string) (*os.File, error) {
	if _, e := os.Lstat(dest); e == nil {
		return nil, fmt.Errorf("destination already exists: %s", dest)
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if e := EnsureDir(filepath.Dir(dest)); e != nil {
		return nil, e
	}
	f, e := os.CreateTemp(filepath.Dir(dest), ".pentrail-private-*")
	if e != nil {
		return nil, e
	}
	if e = protectHandle(f); e != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, e
	}
	return f, nil
}
func WriteNew(path string, data []byte) error {
	f, e := NewTemp(path)
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return Publish(name, path)
}
func ProtectExisting(path string) error {
	f, e := openPrivate(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return protectHandle(f)
}
func PrepareDB(path string) error {
	if e := EnsureDir(filepath.Dir(path)); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e == nil {
		e = protectHandle(f)
		f.Close()
		return e
	}
	if !os.IsExist(e) {
		return e
	}
	return ProtectExisting(path)
}
