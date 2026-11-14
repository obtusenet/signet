// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package email

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	htmltmpl "html/template"
	"io/fs"
	"log"
	"math/big"
	"os"
	"sync"
	texttmpl "text/template"
	"time"
)

// Sender is the interface for sending emails.  html may be empty.
type Sender interface {
	Send(to, subject, text, html string) error
}

// StubSender logs emails instead of sending them, for tests and for
// deployments that set mail.program to empty.
type StubSender struct {
	mu      sync.Mutex
	sent    []SentEmail
	maxSize int
}

// SentEmail represents a sent email
type SentEmail struct {
	To      string    `json:"to"`
	Subject string    `json:"subject"`
	Body    string    `json:"body"`
	HTML    string    `json:"html,omitempty"`
	SentAt  time.Time `json:"sent_at"`
}

// NewStubSender creates a new stub email sender
func NewStubSender() *StubSender {
	return &StubSender{
		sent:    make([]SentEmail, 0),
		maxSize: 1000,
	}
}

// Send logs the email (does not actually send)
func (s *StubSender) Send(to, subject, body, html string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	email := SentEmail{
		To:      to,
		Subject: subject,
		Body:    body,
		HTML:    html,
		SentAt:  time.Now(),
	}

	// Add to history (truncate if too large)
	s.sent = append(s.sent, email)
	if len(s.sent) > s.maxSize {
		s.sent = s.sent[len(s.sent)-s.maxSize:]
	}

	log.Printf("[STUB EMAIL] To: %s, Subject: %s", to, subject)
	log.Printf("[STUB EMAIL] Body:\n%s", body)
	return nil
}

// GetSentEmails returns the list of sent emails
func (s *StubSender) GetSentEmails() []SentEmail {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent
}

// GeneratePIN generates a random 6-digit PIN (deprecated, use GeneratePINSafe)
func GeneratePIN() (string, error) {
	return GeneratePINSafe()
}

// GeneratePINSafe generates a cryptographically secure 6-digit PIN
func GeneratePINSafe() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", fmt.Errorf("generating random number: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// PINEmailData represents the data for a PIN email
type PINEmailData struct {
	PIN           string
	Email         string
	ExpiryMinutes int
	AppName       string
}

// RenderPINEmailData renders the PIN message from email/pin.txt and
// email/pin.html under templatesDir.  It returns the text part, which falls back
// to the built-in body, and the HTML part, which is empty without its template.
func RenderPINEmailData(templatesDir string, data *PINEmailData) (string, string, error) {
	return renderMessage(templatesDir, "pin", buildInPINEmailBody(data), data)
}

// LinkMailData is what the messages with a link, and the notices, can use.
type LinkMailData struct {
	Link     string // empty in a notice
	Email    string
	Lifetime string // how long the link works, in words
	Change   string // what happened to the account, in a notice
	AppName  string
}

// These fallbacks are the text of messages whose
// templates are missing, as on an installation that kept its old template tree.
const (
	RecoverFallback = "Hello {{.Email}},\n\nSomeone asked to reset the password of this account. To choose a new one, open this link:\n\n    {{.Link}}\n\nIt works once, for {{.Lifetime}}. Using it ends every session of this account.\n\nIf this was not you, ignore this email. Your password has not changed.\n\n---\nThis email was sent by {{.AppName}}.\n"

	RegisterFallback = "Hello,\n\nSomeone asked to create an account with this address, {{.Email}}. To finish and choose a password, open this link:\n\n    {{.Link}}\n\nIt works once, for {{.Lifetime}}.\n\nIf this was not you, ignore this email. No account has been created.\n\n---\nThis email was sent by {{.AppName}}.\n"

	AccountExistsFallback = "Hello {{.Email}},\n\nSomeone asked to create an account with this address, but it already has one. If that was you, sign in here, where you can also recover a forgotten password:\n\n    {{.Link}}\n\nIf this was not you, ignore this email. Nothing has changed.\n\n---\nThis email was sent by {{.AppName}}.\n"

	AccountChangeFallback = "Hello {{.Email}},\n\n{{.Change}}\n\nIf this was you, there is nothing more to do. If it was not, contact your administrator now.\n\n---\nThis email was sent by {{.AppName}}.\n"

	PasswordChangedFallback = "Hello {{.Email}},\n\nThe password of this account was just changed through a recovery link, and every session of the account has ended.\n\nIf this was not you, contact your administrator now: someone else can read this mailbox or has its recovery link.\n\n---\nThis email was sent by {{.AppName}}.\n"
)

// RenderLinkMail renders email/<name>.txt and email/<name>.html under
// templatesDir, with fallback as the template when the first is missing.
func RenderLinkMail(templatesDir, name, fallback string, data *LinkMailData) (string, string, error) {
	tmpl, err := texttmpl.New(name).Parse(fallback)
	if err != nil {
		return "", "", fmt.Errorf("parsing built-in text: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", "", fmt.Errorf("rendering built-in text: %w", err)
	}
	return renderMessage(templatesDir, name, buf.String(), data)
}

// renderMessage renders email/<name>.txt and email/<name>.html under
// templatesDir.  fallback is the text part when its template is missing, and the
// HTML part is empty when its template is.
func renderMessage(templatesDir, name, fallback string, data interface{}) (string, string, error) {
	text := fallback
	txtBytes, err := os.ReadFile(templatesDir + "/email/" + name + ".txt")
	if err == nil {
		tmpl, err := texttmpl.New(name).Parse(string(txtBytes))
		if err != nil {
			return "", "", fmt.Errorf("parsing text template: %w", err)
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			return "", "", fmt.Errorf("rendering text template: %w", err)
		}
		text = buf.String()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", "", fmt.Errorf("reading text template: %w", err)
	}

	htmlBytes, err := os.ReadFile(templatesDir + "/email/" + name + ".html")
	if errors.Is(err, fs.ErrNotExist) {
		return text, "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("reading HTML template: %w", err)
	}
	tmpl, err := htmltmpl.New(name).Parse(string(htmlBytes))
	if err != nil {
		return "", "", fmt.Errorf("parsing HTML template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", "", fmt.Errorf("rendering HTML template: %w", err)
	}
	return text, buf.String(), nil
}

// buildInPINEmailBody creates the built-in PIN email body
func buildInPINEmailBody(data *PINEmailData) string {
	return fmt.Sprintf("Hello %s,\n\nUse the following PIN to authenticate with Signet:\n\n    %s\n\nThis PIN will expire in %d minutes.\n\nIf you did not request this PIN, please ignore this email. Your account remains secure.\n\n---\nThis email was sent by %s.\nIf you have any questions, please contact your administrator.\n", data.Email, data.PIN, data.ExpiryMinutes, data.AppName)
}
