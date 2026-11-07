package redact

import "time"

var clockStart = time.Now()

func nowSeconds() float64 { return time.Since(clockStart).Seconds() }
