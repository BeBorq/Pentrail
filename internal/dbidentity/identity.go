package dbidentity

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

func Canonical(path string) string {
	a, e := filepath.Abs(path)
	if e != nil {
		return filepath.Clean(path)
	}
	if real, e := filepath.EvalSymlinks(a); e == nil {
		a = real
	} else if real, e := filepath.EvalSymlinks(filepath.Dir(a)); e == nil {
		a = filepath.Join(real, filepath.Base(a))
	}
	if runtime.GOOS == "windows" {
		a = strings.ToLower(a)
	}
	return filepath.Clean(a)
}
func ID(path string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(Canonical(path)))) }
