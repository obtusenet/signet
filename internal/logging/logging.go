// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package logging

import (
	"fmt"
	"io"
	"log"
	"log/syslog"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode"
)

// Logger wraps the standard logger with syslog support
type Logger struct {
	logger    *log.Logger
	useSyslog bool
}

// New creates a new logger
func New(useSyslog bool, level string) (*Logger, error) {
	var writer *log.Logger
	var err error

	// systemd's journal is the log on those hosts, and it collects stdout.
	if onJournal(os.Stderr, os.Getenv("JOURNAL_STREAM")) {
		useSyslog = false
	}

	if useSyslog {
		var s *syslog.Writer
		s, err = syslog.New(syslog.LOG_INFO, "signet")
		if err != nil {
			return nil, err
		}
		writer = log.New(s, "", 0)
	} else {
		writer = log.New(os.Stdout, "", 0)
	}

	return &Logger{
		logger:    writer,
		useSyslog: useSyslog,
	}, nil
}

// Info logs an info message
func (l *Logger) Info(msg string) {
	l.logger.Println("INFO:", cleanLine(msg))
}

// Warn logs a warning message
func (l *Logger) Warn(msg string) {
	l.logger.Println("WARN:", cleanLine(msg))
}

// Error logs an error message
func (l *Logger) Error(msg string) {
	l.logger.Println("ERROR:", cleanLine(msg))
}

// Debug logs a debug message (only if level is debug)
func (l *Logger) Debug(msg string) {
	// For now, always log debug; can add level filtering later
	l.logger.Println("DEBUG:", cleanLine(msg))
}

// maxLineLength bounds one log message, in bytes.
const maxLineLength = 8192

// cleanLine makes a message safe to log whatever a caller managed to get into it:
// exactly one line, so nobody can forge another, and of bounded size, so nobody
// can fill the disk with a few requests.
func cleanLine(msg string) string {
	truncated := len(msg) > maxLineLength
	if truncated {
		msg = msg[:maxLineLength]
	}
	var out strings.Builder
	for _, r := range strings.ToValidUTF8(msg, "\uFFFD") {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			quoted := strconv.QuoteRune(r)
			out.WriteString(quoted[1 : len(quoted)-1])
			continue
		}
		out.WriteRune(r)
	}
	if truncated {
		out.WriteString("...(truncated)")
	}
	return out.String()
}

// Close closes the logger (for syslog, this closes the connection)
func (l *Logger) Close() error {
	if l.useSyslog {
		// The syslog writer is closed by the GC; no explicit close needed
		return nil
	}
	return nil
}

// onJournal reports whether stderr is connected to systemd's journal.  systemd sets
// JOURNAL_STREAM to the device and inode of that stream, and a process must compare
// them with its own, since a child of a service can inherit the variable while
// its stderr goes somewhere else.
func onJournal(stderr *os.File, journalStream string) bool {
	device, inode, ok := strings.Cut(journalStream, ":")
	if !ok {
		return false
	}
	wantDevice, err := strconv.ParseUint(device, 10, 64)
	if err != nil {
		return false
	}
	wantInode, err := strconv.ParseUint(inode, 10, 64)
	if err != nil {
		return false
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(stderr.Fd()), &st); err != nil {
		return false
	}
	return uint64(st.Dev) == wantDevice && uint64(st.Ino) == wantInode
}

// ReportFatal reports an error that stops the server, to stderr and to syslog.
// It needs no Logger, because the config that would set one up may be what
// failed, and it ignores log_syslog for the same reason.  An rc.d service has no
// terminal, so syslog is the only place its administrator can read why it failed.
// Under systemd stderr already reaches the journal, so syslog would only repeat it.
// A host with no syslog daemon still gets stderr.
func ReportFatal(msg string) {
	if onJournal(os.Stderr, os.Getenv("JOURNAL_STREAM")) {
		fmt.Fprintln(os.Stderr, msg)
		return
	}
	reportFatal(os.Stderr, func() (*syslog.Writer, error) {
		return syslog.New(syslog.LOG_ERR|syslog.LOG_DAEMON, "signet")
	}, msg)
}

func reportFatal(stderr io.Writer, dial func() (*syslog.Writer, error), msg string) {
	fmt.Fprintln(stderr, msg)
	w, err := dial()
	if err != nil {
		return
	}
	defer w.Close()
	w.Err(msg)
}
