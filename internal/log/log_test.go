package log

import (
	"bytes"
	"strings"
	"testing"
)

func TestLevelFromFlags(t *testing.T) {
	cases := []struct {
		quiet, debug bool
		want         Level
	}{
		{false, false, LevelInfo},
		{true, false, LevelQuiet},
		{false, true, LevelDebug},
		{true, true, LevelDebug},
	}
	for _, c := range cases {
		if got := LevelFromFlags(c.quiet, c.debug); got != c.want {
			t.Fatalf("LevelFromFlags(%v,%v) = %v, want %v", c.quiet, c.debug, got, c.want)
		}
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithWriter(&buf, LevelInfo)
	l.Debug("debug message")
	l.Info("info message")
	l.Warn("warn message")

	out := buf.String()
	if strings.Contains(out, "debug message") {
		t.Fatalf("debug message should be suppressed at INFO: %q", out)
	}
	if !strings.Contains(out, "info message") || !strings.Contains(out, "INFO") {
		t.Fatalf("info message missing: %q", out)
	}
	if !strings.Contains(out, "warn message") || !strings.Contains(out, "WARN") {
		t.Fatalf("warn message missing: %q", out)
	}
}

func TestQuietSuppressesInfo(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithWriter(&buf, LevelQuiet)
	l.Info("info message")
	l.Error("error message")

	out := buf.String()
	if strings.Contains(out, "info message") {
		t.Fatalf("info should be suppressed at quiet: %q", out)
	}
	if !strings.Contains(out, "error message") {
		t.Fatalf("error should be shown at quiet: %q", out)
	}
}

func TestNilLoggerSafe(t *testing.T) {
	var l *Logger
	l.Info("should not panic")
}
