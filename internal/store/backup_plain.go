//go:build !sqlcipher

package store

import "errors"

func BackupFile(source, dest string, key []byte) (string, error) {
	return "", errors.New("encrypted backup requires a SQLCipher build")
}
func VerifyFile(path string, key []byte) error {
	return errors.New("encrypted verification requires a SQLCipher build")
}
