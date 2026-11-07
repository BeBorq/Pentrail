//go:build !windows && !linux

package capture

import "time"

func osThreadSnap() (uint64, time.Duration, uint64, time.Duration) { return 0, 0, 0, 0 }
