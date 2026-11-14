// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/obtusenet/signet/internal/auth"
	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/config"
	"github.com/obtusenet/signet/internal/db"
	"github.com/obtusenet/signet/internal/email"
	"github.com/obtusenet/signet/internal/logging"
	"github.com/obtusenet/signet/internal/maillink"
)

// mailSlots bounds the mail work in progress, and mailJobTimeout each job.
const (
	mailSlots      = 8
	mailJobTimeout = 2 * time.Minute
)

// newMailer is how this instance sends mail.
func newMailer(cfg *config.Config, logger *logging.Logger) email.Sender {
	if cfg.Mail.Program == "" {
		if cfg.AuthMethods["email_pin"] == "enabled" || cfg.PasswordRecovery == "enabled" || cfg.SelfRegistration == "enabled" {
			logger.Warn("mail.program is empty: messages, with their PINs and links, go to the log and reach no mailbox")
		}
		return email.NewStubSender()
	}
	if _, err := exec.LookPath(cfg.Mail.Program); err != nil {
		logger.Warn(fmt.Sprintf("mail.program: %v; mail cannot be sent", err))
	}
	return email.NewSendmailSender(cfg.Mail.Program, cfg.Mail.FromAddress, cfg.Mail.FromName)
}

// startMailLinks switches on what needs a link in mail, if it can work.  What is
// missing is said once, and the pages then say the feature is not available.
func (s *Server) startMailLinks(dbStore *db.DB) {
	recovery := strings.EqualFold(s.cfg.PasswordRecovery, "enabled")
	registration := s.cfg.SelfRegistration == "enabled"
	verify := registration && s.cfg.EmailVerification != "disabled"
	s.verifyRegistration = verify
	s.registrationOn = registration && !verify // needs no mail

	refuse := func(reason string) {
		if recovery {
			s.logger.Warn("password_recovery is enabled, but it stays off " + reason)
		}
		if verify {
			s.logger.Warn("self_registration with email_verification is enabled, but it stays off " + reason)
		}
	}
	if !recovery && !verify {
		return
	}
	if s.cfg.PublicURL == "" {
		refuse("until public_url is set: links in mail need it")
		return
	}
	if !s.cfg.MethodEnabled("password") {
		refuse("while auth_methods.password is disabled")
		return
	}
	links, err := maillink.NewStore(dbStore.DB())
	if err != nil {
		refuse(fmt.Sprintf("because of this: %v", err))
		return
	}
	s.links = links
	s.linkAddressLimit = auth.NewEmailRateLimiter(s.cfg.MailLinkRateLimit, time.Duration(s.cfg.MailLinkRateWindow)*time.Second)
	s.linkSourceLimit = auth.NewEmailRateLimiter(s.cfg.MailLinkSourceRateLimit, time.Duration(s.cfg.MailLinkSourceRateWindow)*time.Second)
	s.recoveryOn = recovery
	if verify {
		s.registrationOn = true
	}
	s.housekeeping = append(s.housekeeping, func(ctx context.Context) {
		s.linkAddressLimit.Cleanup()
		s.linkSourceLimit.Cleanup()
		if n, err := s.links.PurgeExpired(ctx); err != nil {
			s.logger.Warn(fmt.Sprintf("removing expired mail links: %v", err))
		} else if n > 0 {
			s.logger.Info(fmt.Sprintf("removed %d expired mail links", n))
		}
	})
	if recovery {
		s.logger.Info("Password recovery enabled")
	}
	if verify {
		s.logger.Info("Self-registration with email verification enabled")
	}
}

// pageReply answers a page's form: the page itself, or JSON for a script.
func (s *Server) pageReply(w http.ResponseWriter, r *http.Request, page string, data map[string]interface{}) func(int) {
	return func(status int) {
		w.Header().Set("Cache-Control", "no-store")
		if wantsJSON(r) {
			body := map[string]interface{}{"success": status < 400}
			if data["Error"] != "" {
				body["error"] = data["Error"]
			}
			if data["Message"] != "" {
				body["message"] = data["Message"]
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(body)
			return
		}
		if err := s.renderTemplate(w, page, data, status); err != nil {
			s.logger.Error(fmt.Sprintf("rendering %s: %v", page, err))
			http.Error(w, "Template error", http.StatusInternalServerError)
		}
	}
}

// mailInBackground runs work that must not show in a reply's timing: whether an
// address has an account decides whether a message goes out at all.
func (s *Server) mailInBackground(job func(ctx context.Context)) {
	select {
	case s.mailSlots <- struct{}{}:
	default:
		s.logger.Error("too much mail in progress: dropping a message")
		return
	}
	s.mailJobs.Add(1)
	go func() {
		defer s.mailJobs.Done()
		defer func() { <-s.mailSlots }()
		ctx, cancel := context.WithTimeout(context.Background(), mailJobTimeout)
		defer cancel()
		job(ctx)
	}()
}

// allowMailLink spends the budgets for one requested message: one for who asks,
// and one for the mailbox, since many requesters could otherwise flood it.  They
// apply to every address, so a refusal shows nothing about accounts.
func (s *Server) allowMailLink(r *http.Request, address string) bool {
	client := s.clients.Addr(r)
	if !s.linkSourceLimit.Allow(client) || !s.linkAddressLimit.Allow(address) {
		s.logger.Warn(fmt.Sprintf("rate limited: mail link for %s from %s", address, client))
		return false
	}
	return true
}

// publicLink is the address a link in a message points at.  It comes from
// public_url and never from the request: a forged Host would otherwise put the
// attacker's site in a real message.  The fragment keeps the token out of every
// access log.
func (s *Server) publicLink(path, token string) string {
	return strings.TrimRight(s.cfg.PublicURL, "/") + s.path(path) + "#token=" + token
}

// sendLinkMail renders a message from templates and hands it to the mail system.
func (s *Server) sendLinkMail(to, subject, template, fallback string, data *email.LinkMailData) error {
	text, html, err := email.RenderLinkMail(s.cfg.TemplatesDir, template, fallback, data)
	if err != nil {
		return fmt.Errorf("rendering %s: %w", template, err)
	}
	return s.mailer.Send(to, subject, text, html)
}

// handleRecover serves the recovery page.  POST does three things, all on this
// path so that a web server routing /recover needs no change: with email it asks
// for a link, with token it checks one, and with token and password it spends one.
func (s *Server) handleRecover(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"RecoveryEnabled": s.recoveryOn,
		"Error":           "",
		"Message":         "",
		"Email":           "",
		"Token":           "",
		"Done":            false,
	}
	reply := s.pageReply(w, r, "recover.html", data)

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		reply(http.StatusOK)
		return
	case http.MethodPost:
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.recoveryOn {
		data["Error"] = "Password recovery is disabled for this installation."
		reply(http.StatusForbidden)
		return
	}

	token := r.PostFormValue("token")
	switch {
	case token == "":
		s.requestRecovery(r, data, reply)
	case r.PostFormValue("password") == "":
		s.checkRecovery(r, token, data, reply)
	default:
		s.finishRecovery(w, r, token, data, reply)
	}
}

// requestRecovery answers every address alike.  What happens next is in the
// background and the log.
func (s *Server) requestRecovery(r *http.Request, data map[string]interface{}, reply func(int)) {
	address := strings.TrimSpace(r.PostFormValue("email"))
	data["Email"] = address
	if address == "" {
		data["Error"] = "An email address is required."
		reply(http.StatusBadRequest)
		return
	}
	data["Message"] = fmt.Sprintf("If that address has an account, a recovery link is on its way. It works once, for %s.",
		humanDuration(s.cfg.RecoveryLinkTTL))

	if err := csv.ValidateEmail(address); err != nil {
		s.logger.Warn(fmt.Sprintf("recovery refused from %s: %v", s.clients.Addr(r), err))
		reply(http.StatusOK)
		return
	}
	address = s.accounts.Resolve(address)
	if s.allowMailLink(r, address) {
		s.mailInBackground(func(ctx context.Context) { s.sendRecoveryLink(ctx, address) })
	}
	reply(http.StatusOK)
}

// sendRecoveryLink mails a link to an account that may sign in.
func (s *Server) sendRecoveryLink(ctx context.Context, address string) {
	user, err := s.accounts.Check(address)
	if err != nil {
		s.logger.Info(fmt.Sprintf("no recovery link for %s: %v", address, err))
		return
	}
	ttl := time.Duration(s.cfg.RecoveryLinkTTL) * time.Second
	token, err := s.links.Create(ctx, maillink.Recovery, user.Email, ttl)
	if err != nil {
		s.logger.Error(fmt.Sprintf("creating a recovery link for %s: %v", user.Email, err))
		return
	}
	if err := s.sendLinkMail(user.Email, "Reset your Signet password", "recover", email.RecoverFallback, &email.LinkMailData{
		Link:     s.publicLink("/recover", token),
		Email:    user.Email,
		Lifetime: humanDuration(s.cfg.RecoveryLinkTTL),
		AppName:  "Signet",
	}); err != nil {
		s.logger.Error(fmt.Sprintf("sending a recovery link to %s: %v", user.Email, err))
		return
	}
	s.logger.Info(fmt.Sprintf("recovery link sent to %s", user.Email))
}

const invalidLinkMessage = "This link is not valid or has expired. You can ask for a new one."

const shortPasswordMessage = "The password must be at least 8 characters."

// linkAccount returns the address a recovery token may act on, or "".
func (s *Server) linkAccount(r *http.Request, token string) string {
	address, err := s.links.Email(r.Context(), maillink.Recovery, token)
	if err != nil {
		if !errors.Is(err, maillink.ErrInvalid) {
			s.logger.Error(fmt.Sprintf("checking a recovery link: %v", err))
		}
		return ""
	}
	// The account may have been locked or removed since the link went out.
	if _, err := s.accounts.Check(address); err != nil {
		s.logger.Warn(fmt.Sprintf("recovery link refused for %s: %v", address, err))
		return ""
	}
	return address
}

// checkRecovery lets the page refuse a dead link before asking for a password.
func (s *Server) checkRecovery(r *http.Request, token string, data map[string]interface{}, reply func(int)) {
	if s.linkAccount(r, token) == "" {
		data["Error"] = invalidLinkMessage
		reply(http.StatusBadRequest)
		return
	}
	data["Token"] = token
	reply(http.StatusOK)
}

// finishRecovery spends the token and sets the password.  The password is checked
// and hashed first, so a typo or a failure there leaves the link usable.
func (s *Server) finishRecovery(w http.ResponseWriter, r *http.Request, token string, data map[string]interface{}, reply func(int)) {
	if s.linkAccount(r, token) == "" {
		data["Error"] = invalidLinkMessage
		reply(http.StatusBadRequest)
		return
	}
	newPassword := r.PostFormValue("password")
	if err := csv.ValidatePassword(newPassword); err != nil {
		data["Error"] = shortPasswordMessage
		data["Token"] = token
		reply(http.StatusBadRequest)
		return
	}
	hash, err := s.hasher.Hash(newPassword)
	if err != nil {
		s.logger.Error(fmt.Sprintf("hashing a recovered password: %v", err))
		data["Error"] = "The password could not be changed. Try again."
		data["Token"] = token
		reply(http.StatusInternalServerError)
		return
	}

	address, err := s.links.Consume(r.Context(), maillink.Recovery, token)
	if err != nil {
		data["Error"] = invalidLinkMessage
		reply(http.StatusBadRequest)
		return
	}
	if err := s.backend.UpdateUser(address, map[string]string{
		"password_hash":  hash,
		"hash_algorithm": s.cfg.PasswordHashAlg,
	}); err != nil {
		s.logger.Error(fmt.Sprintf("storing a recovered password for %s: %v", address, err))
		data["Error"] = "The password could not be changed. Ask for a new link."
		reply(http.StatusInternalServerError)
		return
	}
	s.logger.Info(fmt.Sprintf("password reset by recovery link for %s from %s", address, s.clients.Addr(r)))

	s.passwordAuth.ClearAddressLimit(address)
	// Holding the mailbox ends a lock: a guesser must not keep the owner out.
	s.clearLockout(r.Context(), address)
	s.mailInBackground(func(ctx context.Context) {
		if err := s.sendLinkMail(address, "Your Signet password was changed", "password-changed", email.PasswordChangedFallback, &email.LinkMailData{
			Email:   address,
			AppName: "Signet",
		}); err != nil {
			s.logger.Error(fmt.Sprintf("sending the password notice to %s: %v", address, err))
		}
	})

	// Whoever had this account's sessions, perhaps the reason for the reset, is out.
	http.SetCookie(w, s.cookieMgr.ExpiredAuthCookie())
	data["Done"] = true
	if err := s.sessionStore.RevokeAll(r.Context(), address); err != nil {
		s.logger.Error(fmt.Sprintf("ending sessions for %s after a password reset: %v", address, err))
		data["Error"] = "The password was changed, but this account's other sessions could not be ended."
		reply(http.StatusInternalServerError)
		return
	}
	data["Message"] = "Your password has been changed, and every session of this account has ended. You can sign in now."
	reply(http.StatusOK)
}

// humanDuration says a lifetime in seconds the way a person would.
func humanDuration(seconds int) string {
	switch {
	case seconds >= 3600 && seconds%3600 == 0:
		if seconds == 3600 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", seconds/3600)
	case seconds >= 60:
		if seconds < 120 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", seconds/60)
	}
	return fmt.Sprintf("%d seconds", seconds)
}
