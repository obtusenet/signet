// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package email

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"os/exec"
	"strings"
	"time"
)

// sendmailTimeout bounds one hand-off to the mail system.  It only has to queue
// the message; delivery happens later and is not waited for.
const sendmailTimeout = 30 * time.Second

// SendmailSender hands messages to the system's mail infrastructure the way
// mail(1) does: it runs sendmail(8) with the message on standard input.  What may
// be delivered where is the mail system's policy, and a refusal comes back as an
// error.
type SendmailSender struct {
	program  string
	fromAddr string
	fromName string
	timeout  time.Duration
}

// NewSendmailSender creates a sender that runs program.  An empty fromAddr leaves
// the sender's address for the mail system to fill in.
func NewSendmailSender(program, fromAddr, fromName string) *SendmailSender {
	return &SendmailSender{
		program:  program,
		fromAddr: fromAddr,
		fromName: fromName,
		timeout:  sendmailTimeout,
	}
}

// Send hands one message to the mail system.  html may be empty.
func (s *SendmailSender) Send(to, subject, text, html string) error {
	for _, field := range []string{to, subject, s.fromAddr, s.fromName} {
		if strings.ContainsAny(field, "\r\n") {
			return errors.New("line break in a mail header")
		}
	}
	message, err := s.message(to, subject, text, html)
	if err != nil {
		return fmt.Errorf("building message: %w", err)
	}

	// -i: a line holding a single dot does not end the message.
	// --: an address cannot be taken for an option.
	args := []string{"-i"}
	if s.fromAddr != "" {
		args = append(args, "-f", s.fromAddr)
	}
	args = append(args, "--", to)

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.program, args...)
	cmd.Stdin = bytes.NewReader(message)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	// A child left holding the pipes must not outlive the timeout.
	cmd.WaitDelay = 2 * time.Second

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s timed out after %v", s.program, s.timeout)
		}
		return fmt.Errorf("%s: %w: %s", s.program, err, strings.TrimSpace(output.String()))
	}
	return nil
}

// message builds the RFC 5322 message, with the plain line endings sendmail(8)
// expects on standard input.
func (s *SendmailSender) message(to, subject, text, html string) ([]byte, error) {
	var out bytes.Buffer
	if s.fromAddr != "" {
		from := mail.Address{Name: s.fromName, Address: s.fromAddr}
		fmt.Fprintf(&out, "From: %s\r\n", from.String())
	}
	recipient := mail.Address{Address: to}
	fmt.Fprintf(&out, "To: %s\r\n", recipient.String())
	fmt.Fprintf(&out, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&out, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	out.WriteString("MIME-Version: 1.0\r\n")

	if html == "" {
		out.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		out.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		if err := writeQuotedPrintable(&out, text); err != nil {
			return nil, err
		}
	} else {
		parts := multipart.NewWriter(&out)
		fmt.Fprintf(&out, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", parts.Boundary())
		for _, part := range []struct{ kind, body string }{
			{"text/plain; charset=utf-8", text},
			{"text/html; charset=utf-8", html},
		} {
			w, err := parts.CreatePart(textproto.MIMEHeader{
				"Content-Type":              {part.kind},
				"Content-Transfer-Encoding": {"quoted-printable"},
			})
			if err != nil {
				return nil, err
			}
			if err := writeQuotedPrintable(w, part.body); err != nil {
				return nil, err
			}
		}
		if err := parts.Close(); err != nil {
			return nil, err
		}
	}
	return bytes.ReplaceAll(out.Bytes(), []byte("\r\n"), []byte("\n")), nil
}

func writeQuotedPrintable(w io.Writer, body string) error {
	encoder := quotedprintable.NewWriter(w)
	if _, err := io.WriteString(encoder, body); err != nil {
		return err
	}
	return encoder.Close()
}
