package internal

import (
	"fmt"
	"os"
)

// debugEnabled caches whether the DEBUG env var is set, checked once at
// startup rather than on every log call.
var debugEnabled = os.Getenv("DEBUG") == "true"

// Debugf prints a debug line to stderr when the DEBUG env var is set to
// "true". It is a no-op otherwise.
func Debugf(format string, args ...interface{}) {
	if !debugEnabled {
		return
	}
	fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
}
