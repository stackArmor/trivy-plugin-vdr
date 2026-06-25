// Package log provides a small leveled logger for human-facing progress output.
//
// Logs are written to stderr so they never contaminate the report written to
// stdout or to a file. The default level is INFO, which announces each phase of
// a run (inventory collection, registry auth, scanning, enrichment).
package log

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level controls which messages are emitted.
type Level int

const (
	// LevelDebug emits everything, including verbose diagnostics.
	LevelDebug Level = iota
	// LevelInfo emits phase progress, warnings, and errors (the default).
	LevelInfo
	// LevelQuiet emits only warnings and errors.
	LevelQuiet
)

// Logger writes timestamped, leveled messages to a writer.
type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	level Level
}

// New returns a Logger writing to stderr at the given level.
func New(level Level) *Logger {
	return &Logger{out: os.Stderr, level: level}
}

// NewWithWriter returns a Logger writing to w at the given level. Useful in tests.
func NewWithWriter(w io.Writer, level Level) *Logger {
	return &Logger{out: w, level: level}
}

// LevelFromFlags maps the quiet/debug config flags to a Level. Debug wins if both are set.
func LevelFromFlags(quiet, debug bool) Level {
	switch {
	case debug:
		return LevelDebug
	case quiet:
		return LevelQuiet
	default:
		return LevelInfo
	}
}

func (l *Logger) log(min Level, label, format string, args ...any) {
	if l == nil || l.level > min {
		return
	}
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s\t%s\t%s\n", time.Now().Format(time.RFC3339), label, msg)
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprint(l.out, line)
}

// Debug logs at the DEBUG level (only shown with --debug).
func (l *Logger) Debug(format string, args ...any) { l.log(LevelDebug, "DEBUG", format, args...) }

// Info logs phase progress at the INFO level (the default).
func (l *Logger) Info(format string, args ...any) { l.log(LevelInfo, "INFO", format, args...) }

// Warn logs a recoverable problem; always shown unless output is fully suppressed.
func (l *Logger) Warn(format string, args ...any) { l.log(LevelQuiet, "WARN", format, args...) }

// Error logs a failure; always shown.
func (l *Logger) Error(format string, args ...any) { l.log(LevelQuiet, "ERROR", format, args...) }
