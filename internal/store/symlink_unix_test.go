//go:build !windows

package store

func symlinkUnavailable(error) bool { return false }
