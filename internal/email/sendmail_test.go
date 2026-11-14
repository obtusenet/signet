// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package email

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSendmail stands in for sendmail(8), so these tests never reach a mail
// system.  It records its arguments and standard input, then runs tail.
func fakeSendmail(t *testing.T, tail string) (program, argsFile, stdinFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	stdinFile = filepath.Join(dir, "stdin")
	program = filepath.Join(dir, "sendmail")
	script := "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\" >> " + argsFile + "; done\ncat > " + stdinFile + "\n" + tail + "\n"
	if err := os.WriteFile(program, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return program, argsFile, stdinFile
}

func readString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func parseMessage(t *testing.T, path string) *mail.Message {
	t.Helper()
	m, err := mail.ReadMessage(strings.NewReader(readString(t, path)))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSendmailInvocation(t *testing.T) {
	program, args, _ := fakeSendmail(t, "")
	s := NewSendmailSender(program, "noreply@example.com", "Signet")
	if err := s.Send("user@example.com", "Hello", "body\n", ""); err != nil {
		t.Fatal(err)
	}
	want := "-i\n-f\nnoreply@example.com\n--\nuser@example.com\n"
	if got := readString(t, args); got != want {
		t.Errorf("args:\n%s\nwant:\n%s", got, want)
	}
}

func TestSendmailWithoutFromLeavesItToTheMailSystem(t *testing.T) {
	program, args, stdin := fakeSendmail(t, "")
	s := NewSendmailSender(program, "", "Signet")
	if err := s.Send("user@example.com", "Hello", "body\n", ""); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, args); got != "-i\n--\nuser@example.com\n" {
		t.Errorf("args: %q", got)
	}
	if m := parseMessage(t, stdin); m.Header.Get("From") != "" {
		t.Errorf("From: %q", m.Header.Get("From"))
	}
}

// Options after -- are addresses, whatever they look like.
func TestSendmailRecipientCannotBeAnOption(t *testing.T) {
	program, args, _ := fakeSendmail(t, "")
	s := NewSendmailSender(program, "", "")
	if err := s.Send("-oQ/tmp/x@example.com", "Hello", "body\n", ""); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, args); got != "-i\n--\n-oQ/tmp/x@example.com\n" {
		t.Errorf("args: %q", got)
	}
}

func TestSendmailPlainMessage(t *testing.T) {
	program, _, stdin := fakeSendmail(t, "")
	s := NewSendmailSender(program, "noreply@example.com", "Sïgnet")
	text := "Your PIN: 123456\n" + strings.Repeat("long ", 40) + "\n.\nafter a dot\n"
	if err := s.Send("user@example.com", "Prüfung", text, ""); err != nil {
		t.Fatal(err)
	}
	if raw := readString(t, stdin); strings.Contains(raw, "\r") {
		t.Error("the message holds carriage returns")
	}
	m := parseMessage(t, stdin)
	from, err := m.Header.AddressList("From")
	if err != nil || from[0].Name != "Sïgnet" || from[0].Address != "noreply@example.com" {
		t.Errorf("From: %v %v", from, err)
	}
	if to := m.Header.Get("To"); !strings.Contains(to, "user@example.com") {
		t.Errorf("To: %q", to)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
	if err != nil || subject != "Prüfung" {
		t.Errorf("Subject: %q %v", subject, err)
	}
	if _, err := m.Header.Date(); err != nil {
		t.Errorf("Date: %v", err)
	}
	body, err := io.ReadAll(quotedprintable.NewReader(m.Body))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.ReplaceAll(string(body), "\r\n", "\n"); got != text {
		t.Errorf("body:\n%q\nwant:\n%q", got, text)
	}
}

func TestSendmailMultipartMessage(t *testing.T) {
	program, _, stdin := fakeSendmail(t, "")
	s := NewSendmailSender(program, "", "")
	if err := s.Send("user@example.com", "Hello", "plain 123456\n", "<b>rich 123456</b>\n"); err != nil {
		t.Fatal(err)
	}
	m := parseMessage(t, stdin)
	kind, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || kind != "multipart/alternative" {
		t.Fatalf("Content-Type %q: %v", kind, err)
	}
	reader := multipart.NewReader(m.Body, params["boundary"])
	for i, want := range []struct{ kind, body string }{
		{"text/plain", "plain 123456"},
		{"text/html", "<b>rich 123456</b>"},
	} {
		part, err := reader.NextRawPart()
		if err != nil {
			t.Fatalf("part %d: %v", i, err)
		}
		if got, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type")); got != want.kind {
			t.Errorf("part %d: %q, want %q", i, got, want.kind)
		}
		body, err := io.ReadAll(quotedprintable.NewReader(part))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(body, []byte(want.body)) {
			t.Errorf("part %d: %q", i, body)
		}
	}
}

// A refusal must carry the mail system's reason and never the message.
func TestSendmailRefusal(t *testing.T) {
	program, _, _ := fakeSendmail(t, "echo '550 Invalid recipient' >&2\nexit 70")
	s := NewSendmailSender(program, "", "")
	err := s.Send("user@example.com", "Hello", "PIN 123456\n", "")
	if err == nil {
		t.Fatal("a refusal was reported as sent")
	}
	if !strings.Contains(err.Error(), "550 Invalid recipient") {
		t.Errorf("reason lost: %v", err)
	}
	if strings.Contains(err.Error(), "123456") {
		t.Errorf("the message reached the error: %v", err)
	}
}

func TestSendmailMissingProgram(t *testing.T) {
	s := NewSendmailSender(filepath.Join(t.TempDir(), "absent"), "", "")
	if err := s.Send("user@example.com", "Hello", "body\n", ""); err == nil {
		t.Error("a missing program was reported as sent")
	}
}

func TestSendmailRefusesHeaderInjection(t *testing.T) {
	program, _, stdin := fakeSendmail(t, "")
	for name, s := range map[string]struct {
		sender      *SendmailSender
		to, subject string
	}{
		"recipient": {NewSendmailSender(program, "", ""), "a@example.com\nBcc: b@example.com", "Hello"},
		"subject":   {NewSendmailSender(program, "", ""), "a@example.com", "Hello\r\nBcc: b@example.com"},
		"from":      {NewSendmailSender(program, "a@example.com\nBcc: b@example.com", ""), "a@example.com", "Hello"},
		"name":      {NewSendmailSender(program, "a@example.com", "x\nBcc: b@example.com"), "a@example.com", "Hello"},
	} {
		if err := s.sender.Send(s.to, s.subject, "body\n", ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := os.Stat(stdin); err == nil {
		t.Error("the program ran")
	}
}

func TestSendmailTimeout(t *testing.T) {
	program, _, _ := fakeSendmail(t, "sleep 5")
	s := NewSendmailSender(program, "", "")
	s.timeout = 200 * time.Millisecond
	start := time.Now()
	err := s.Send("user@example.com", "Hello", "body\n", "")
	if err == nil {
		t.Fatal("a hung program was reported as sent")
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Errorf("waited %v", elapsed)
	}
}

func TestRenderPINEmailFallsBackToBuiltIn(t *testing.T) {
	data := &PINEmailData{PIN: "123456", Email: "a@example.com", ExpiryMinutes: 10, AppName: "Signet"}
	text, html, err := RenderPINEmailData(t.TempDir(), data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "123456") || html != "" {
		t.Errorf("text %q html %q", text, html)
	}
}

func TestRenderShippedPINTemplates(t *testing.T) {
	data := &PINEmailData{PIN: "123456", Email: "a@example.com", ExpiryMinutes: 10, AppName: "Signet"}
	text, html, err := RenderPINEmailData("../../web/templates", data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "123456") {
		t.Errorf("text part: %q", text)
	}
	if !strings.Contains(html, "123456") {
		t.Errorf("HTML part: %q", html)
	}
}

func TestRenderBrokenTemplateIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "email"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "email", "pin.txt"), []byte("{{.Broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RenderPINEmailData(dir, &PINEmailData{}); err == nil {
		t.Error("a broken template was accepted")
	}
}

func TestRenderShippedLinkTemplates(t *testing.T) {
	data := &LinkMailData{Link: "https://signet.example/recover#token=abc_-1", Email: "a@example.com", Lifetime: "1 hour", AppName: "Signet"}
	for _, message := range []struct{ name, fallback string }{
		{"recover", RecoverFallback},
		{"password-changed", PasswordChangedFallback},
		{"register", RegisterFallback},
		{"account-exists", AccountExistsFallback},
	} {
		text, html, err := RenderLinkMail("../../web/templates", message.name, message.fallback, data)
		if err != nil {
			t.Fatalf("%s: %v", message.name, err)
		}
		if html == "" || !strings.Contains(text, "a@example.com") || !strings.Contains(html, "a@example.com") {
			t.Errorf("%s: text %q, html %q", message.name, text, html)
		}
		if message.name != "password-changed" {
			// The token must survive HTML escaping, or the link does nothing.
			for _, part := range []string{text, html} {
				if !strings.Contains(part, data.Link) {
					t.Errorf("%s: no link in %q", message.name, part)
				}
				if message.name != "account-exists" && !strings.Contains(part, "1 hour") {
					t.Errorf("%s: no lifetime in %q", message.name, part)
				}
			}
		}
	}
}

func TestLinkMailFallsBackToBuiltIn(t *testing.T) {
	data := &LinkMailData{Link: "https://signet.example/recover#token=abc", Email: "a@example.com", Lifetime: "1 hour", AppName: "Signet"}
	text, html, err := RenderLinkMail(t.TempDir(), "recover", RecoverFallback, data)
	if err != nil {
		t.Fatal(err)
	}
	if html != "" || !strings.Contains(text, data.Link) || !strings.Contains(text, "1 hour") {
		t.Errorf("text %q, html %q", text, html)
	}
	for _, fallback := range []string{PasswordChangedFallback, RegisterFallback, AccountExistsFallback} {
		if text, _, err := RenderLinkMail(t.TempDir(), "absent", fallback, data); err != nil || strings.Contains(text, "{{") {
			t.Errorf("fallback: %q, %v", text, err)
		}
	}
}
