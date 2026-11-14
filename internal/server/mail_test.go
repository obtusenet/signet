// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/config"
)

// fakeSendmail stands in for sendmail(8), so nothing here reaches a mail system.
// It records its standard input and arguments, then runs tail.
func fakeSendmail(t *testing.T, tail string) (program, stdin, args string) {
	t.Helper()
	dir := t.TempDir()
	program = filepath.Join(dir, "sendmail")
	stdin = filepath.Join(dir, "stdin")
	args = filepath.Join(dir, "args")
	script := "#!/bin/sh\necho \"$@\" > " + args + "\ncat > " + stdin + "\n" + tail + "\n"
	if err := os.WriteFile(program, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return program, stdin, args
}

func newMailServer(t *testing.T, program string) (*Server, *csv.Backend) {
	t.Helper()
	first, backend := newRegisterServer(t, "disabled")
	cfg := *first.cfg
	cfg.AuthMethods = map[string]string{"email_pin": "enabled"}
	cfg.Mail.Program = program
	cfg.Mail.FromAddress = "noreply@example.com"
	cfg.TemplatesDir = "../../web/templates"
	cfg.EmailRateLimit = 100
	cfg.EmailRateWindow = 60
	return New(&cfg, first.logger, first.db, backend), backend
}

func sendPIN(s *Server, addr string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/email-pin/send", strings.NewReader(`{"email":"`+addr+`"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w
}

func TestPINGoesToTheMailProgramWithTheTemplates(t *testing.T) {
	program, stdin, args := fakeSendmail(t, "")
	s, backend := newMailServer(t, program)
	if err := backend.CreateUser("user@example.com", "!", "bcrypt", []string{csv.FlagApproved}); err != nil {
		t.Fatal(err)
	}

	if w := sendPIN(s, "user@example.com"); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	s.mailJobs.Wait()
	got, err := os.ReadFile(args)
	if err != nil {
		t.Fatalf("the program did not run: %v", err)
	}
	if want := "-i -f noreply@example.com -- user@example.com\n"; string(got) != want {
		t.Errorf("args %q, want %q", got, want)
	}
	message, err := os.ReadFile(stdin)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(message), "multipart/alternative") {
		t.Errorf("the shipped templates were not used:\n%s", message)
	}
}

// A refused recipient must look like any address with no account.
func TestRefusedPINLooksLikeNoAccount(t *testing.T) {
	program, _, _ := fakeSendmail(t, "echo '550 Invalid recipient' >&2\nexit 70")
	s, backend := newMailServer(t, program)
	if err := backend.CreateUser("user@example.com", "!", "bcrypt", []string{csv.FlagApproved}); err != nil {
		t.Fatal(err)
	}

	refused := sendPIN(s, "user@example.com")
	unknown := sendPIN(s, "nobody@example.com")
	if refused.Code != unknown.Code || refused.Body.String() != unknown.Body.String() {
		t.Errorf("refused %d %q, unknown %d %q", refused.Code, refused.Body, unknown.Code, unknown.Body)
	}
}

// A missing program is an error, never a silent fall back to logging the PIN.
func TestMissingMailProgramSendsNothing(t *testing.T) {
	s, backend := newMailServer(t, filepath.Join(t.TempDir(), "absent"))
	if err := backend.CreateUser("user@example.com", "!", "bcrypt", []string{csv.FlagApproved}); err != nil {
		t.Fatal(err)
	}
	if w := sendPIN(s, "user@example.com"); w.Code != http.StatusOK {
		t.Errorf("status %d", w.Code)
	}
}

// A slow mail system must not show in the reply: only an account gets a message,
// so its timing would tell which addresses have accounts.
func TestPINReplyDoesNotWaitForMail(t *testing.T) {
	program, stdin, _ := fakeSendmail(t, "sleep 2")
	s := recoveryServer(t, func(c *config.Config) {
		c.AuthMethods = map[string]string{"password": "enabled", "email_pin": "enabled"}
		c.Mail.Program = program
	})
	start := time.Now()
	r := httptest.NewRequest(http.MethodPost, "/email-pin/send", strings.NewReader(`{"email":"`+recoveryUser+`"}`))
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	if took := time.Since(start); took > time.Second {
		t.Errorf("the reply took %s, waiting for the mail system", took)
	}
	if w.Code != http.StatusOK {
		t.Errorf("status %d", w.Code)
	}
	s.mailJobs.Wait()
	if _, err := os.Stat(stdin); err != nil {
		t.Errorf("the message never went out: %v", err)
	}
}
