//go:build linux

package capture

func newShellObserver(Options) shellObserver { return noopObserver{} }
