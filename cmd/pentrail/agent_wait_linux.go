//go:build linux

package main

func agentExitWaiter() (func() error, error) { return func() error { return nil }, nil }
