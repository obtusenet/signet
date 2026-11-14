// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package logging

import (
	"bytes"
	"errors"
	"fmt"
	"log/syslog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	// Test stdout logger
	logger, err := New(false, "info")
	if err != nil {
		t.Fatal(err)
	}
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
	if logger.useSyslog {
		t.Error("expected useSyslog to be false")
	}
	logger.Close()

	// Test syslog logger (this will fail on most systems without syslog, but we test the error path)
	_, err = New(true, "info")
	// We don't assert error here because syslog might be available
}

func TestLoggerMethods(t *testing.T) {
	logger, err := New(false, "info")
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	// These should not panic
	logger.Info("test info")
	logger.Warn("test warn")
	logger.Error("test error")
	logger.Debug("test debug")
}

func TestReportFatalReachesStderrAndSyslog(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "log")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var stderr bytes.Buffer
	reportFatal(&stderr, func() (*syslog.Writer, error) {
		return syslog.Dial("unixgram", sock, syslog.LOG_ERR|syslog.LOG_DAEMON, "signet")
	}, "cookie_secret must be set")

	if !strings.Contains(stderr.String(), "cookie_secret must be set") {
		t.Errorf("stderr = %q", stderr.String())
	}
	buf := make([]byte, 1024)
	listener.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := listener.Read(buf)
	if err != nil {
		t.Fatalf("nothing reached syslog: %v", err)
	}
	got := string(buf[:n])
	// daemon (3) * 8 + err (3) = 27
	if !strings.HasPrefix(got, "<27>") || !strings.Contains(got, "cookie_secret must be set") {
		t.Errorf("syslog message = %q", got)
	}
}

func TestReportFatalWithoutSyslogStillReachesStderr(t *testing.T) {
	var stderr bytes.Buffer
	reportFatal(&stderr, func() (*syslog.Writer, error) {
		return nil, errors.New("no syslog daemon")
	}, "cookie_secret must be set")
	if !strings.Contains(stderr.String(), "cookie_secret must be set") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestOnJournal(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	match := fmt.Sprintf("%d:%d", uint64(st.Dev), uint64(st.Ino))

	tests := []struct {
		name, value string
		want        bool
	}{
		{"its own stream", match, true},
		{"not set", "", false},
		{"inherited from another stream", fmt.Sprintf("%d:%d", uint64(st.Dev), uint64(st.Ino)+1), false},
		{"malformed", "journal", false},
		{"not numbers", "a:b", false},
	}
	for _, tt := range tests {
		if got := onJournal(file, tt.value); got != tt.want {
			t.Errorf("%s: onJournal(%q) = %v, want %v", tt.name, tt.value, got, tt.want)
		}
	}
}

func TestCleanLine(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"plain message", "plain message"},
		{"naïve ✓", "naïve ✓"},
		{"x@example.com\nINFO: forged", `x@example.com\nINFO: forged`},
		{"a\r\nb", `a\r\nb`},
		{"a\u2028b\u2029c\u0085d", `a\u2028b\u2029c\u0085d`},
		{"esc\x1b[31m", `esc\x1b[31m`},
		{"bad\xffbyte", "bad\uFFFDbyte"},
	} {
		if got := cleanLine(tc.in); got != tc.want {
			t.Errorf("cleanLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	long := cleanLine(strings.Repeat("a", 10*maxLineLength))
	if len(long) > maxLineLength+len("...(truncated)") || !strings.HasSuffix(long, "...(truncated)") {
		t.Errorf("long message came out %d bytes", len(long))
	}
	if got := cleanLine(strings.Repeat("a", maxLineLength)); strings.Contains(got, "truncated") {
		t.Error("a message at the limit was truncated")
	}
}
