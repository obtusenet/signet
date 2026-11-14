// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/email"
	"github.com/obtusenet/signet/internal/maillink"
)

// handleRegister serves the registration page.  With email_verification required,
// POST does what /recover does: with email it asks for a link, with token it checks
// one, and with token and password it spends one and creates the account.  An
// address that has not proved itself is never in users.csv, so nobody can register
// someone else's address with their own password and wait for its owner to confirm.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"RegistrationEnabled":  s.registrationOn,
		"VerificationRequired": s.verifyRegistration,
		"Error":                "",
		"Message":              "",
		"Email":                "",
		"Token":                "",
		"Done":                 false,
	}
	reply := s.pageReply(w, r, "register.html", data)

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		reply(http.StatusOK)
		return
	case http.MethodPost:
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.cfg.SelfRegistration != "enabled" {
		s.logger.Warn(fmt.Sprintf("registration refused from %s: self_registration is disabled", s.clients.Addr(r)))
		s.registerFailure(w, data, reply, http.StatusForbidden, "Self-registration is disabled")
		return
	}
	if !s.registrationOn {
		s.registerFailure(w, data, reply, http.StatusForbidden, "Creating an account is not available on this installation.")
		return
	}
	if !s.verifyRegistration {
		s.registerDirectly(w, r, data, reply)
		return
	}

	token := r.PostFormValue("token")
	switch {
	case token == "":
		s.requestRegistration(r, data, reply)
	case r.PostFormValue("password") == "":
		s.checkRegistration(r, token, data, reply)
	default:
		s.finishRegistration(r, token, data, reply)
	}
}

// registerFailure answers on the page, or plainly when there are no templates.
func (s *Server) registerFailure(w http.ResponseWriter, data map[string]interface{}, reply func(int), status int, message string) {
	if s.tmpl == nil {
		http.Error(w, message, status)
		return
	}
	data["Error"] = message
	reply(status)
}

// requestRegistration answers every address alike.  What happens next is in the
// background and the log.
func (s *Server) requestRegistration(r *http.Request, data map[string]interface{}, reply func(int)) {
	address := strings.TrimSpace(r.PostFormValue("email"))
	data["Email"] = address
	if address == "" {
		data["Error"] = "An email address is required."
		reply(http.StatusBadRequest)
		return
	}
	data["Message"] = fmt.Sprintf("Check your mail: a message is on its way to that address. A link in it works once, for %s.",
		humanDuration(s.cfg.RegistrationLinkTTL))

	if err := csv.ValidateEmail(address); err != nil {
		s.logger.Warn(fmt.Sprintf("registration refused from %s: %v", s.clients.Addr(r), err))
		reply(http.StatusOK)
		return
	}
	address = s.accounts.Resolve(address)
	if s.allowMailLink(r, address) {
		s.mailInBackground(func(ctx context.Context) { s.sendRegistrationMail(ctx, address) })
	}
	reply(http.StatusOK)
}

// sendRegistrationMail sends a link to finish, or tells the owner of an address
// that already has an account, who would otherwise wait for a message forever.
func (s *Server) sendRegistrationMail(ctx context.Context, address string) {
	_, err := s.backend.GetUser(address)
	if err == nil {
		if err := s.sendLinkMail(address, "You already have a Signet account", "account-exists", email.AccountExistsFallback, &email.LinkMailData{
			Link:    strings.TrimRight(s.cfg.PublicURL, "/") + s.path("/login"),
			Email:   address,
			AppName: "Signet",
		}); err != nil {
			s.logger.Error(fmt.Sprintf("telling %s about their account: %v", address, err))
			return
		}
		s.logger.Info(fmt.Sprintf("registration asked for %s, which has an account: told its owner", address))
		return
	}
	if !errors.Is(err, csv.ErrUserNotFound) {
		s.logger.Error(fmt.Sprintf("looking up %s for registration: %v", address, err))
		return
	}

	ttl := time.Duration(s.cfg.RegistrationLinkTTL) * time.Second
	token, err := s.links.Create(ctx, maillink.Registration, address, ttl)
	if err != nil {
		s.logger.Error(fmt.Sprintf("creating a registration link for %s: %v", address, err))
		return
	}
	if err := s.sendLinkMail(address, "Finish creating your Signet account", "register", email.RegisterFallback, &email.LinkMailData{
		Link:     s.publicLink("/register", token),
		Email:    address,
		Lifetime: humanDuration(s.cfg.RegistrationLinkTTL),
		AppName:  "Signet",
	}); err != nil {
		s.logger.Error(fmt.Sprintf("sending a registration link to %s: %v", address, err))
		return
	}
	s.logger.Info(fmt.Sprintf("registration link sent to %s", address))
}

// registrationAddress returns the address a live token can register, or "".
func (s *Server) registrationAddress(r *http.Request, token string) string {
	address, err := s.links.Email(r.Context(), maillink.Registration, token)
	if err != nil {
		if !errors.Is(err, maillink.ErrInvalid) {
			s.logger.Error(fmt.Sprintf("checking a registration link: %v", err))
		}
		return ""
	}
	// An account may have appeared since the link went out.
	if _, err := s.backend.GetUser(address); !errors.Is(err, csv.ErrUserNotFound) {
		s.logger.Warn(fmt.Sprintf("registration link refused for %s: the address has an account, or could not be checked", address))
		return ""
	}
	return address
}

// checkRegistration lets the page refuse a dead link before asking for a password.
func (s *Server) checkRegistration(r *http.Request, token string, data map[string]interface{}, reply func(int)) {
	if s.registrationAddress(r, token) == "" {
		data["Error"] = invalidLinkMessage
		reply(http.StatusBadRequest)
		return
	}
	data["Token"] = token
	reply(http.StatusOK)
}

// newAccountFlags are the flags of a self-registered account, which may still need
// an administrator's approval.
func (s *Server) newAccountFlags() []string {
	flags := []string{csv.FlagSelfRegistered}
	if s.cfg.ApprovalRequired != "required" {
		flags = append(flags, csv.FlagApproved)
	}
	return flags
}

// finishRegistration spends the token and creates the account.  The password is
// checked and hashed first, so a typo or a failure there leaves the link usable.
func (s *Server) finishRegistration(r *http.Request, token string, data map[string]interface{}, reply func(int)) {
	if s.registrationAddress(r, token) == "" {
		data["Error"] = invalidLinkMessage
		reply(http.StatusBadRequest)
		return
	}
	password := r.PostFormValue("password")
	if err := csv.ValidatePassword(password); err != nil {
		data["Error"] = shortPasswordMessage
		data["Token"] = token
		reply(http.StatusBadRequest)
		return
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		s.logger.Error(fmt.Sprintf("hashing a new account's password: %v", err))
		data["Error"] = "The account could not be created. Try again."
		data["Token"] = token
		reply(http.StatusInternalServerError)
		return
	}

	address, err := s.links.Consume(r.Context(), maillink.Registration, token)
	if err != nil {
		data["Error"] = invalidLinkMessage
		reply(http.StatusBadRequest)
		return
	}
	if err := s.backend.CreateUser(address, hash, s.cfg.PasswordHashAlg, s.newAccountFlags()); err != nil {
		if errors.Is(err, csv.ErrUserExists) {
			data["Error"] = invalidLinkMessage
			reply(http.StatusBadRequest)
			return
		}
		s.logger.Error(fmt.Sprintf("creating the account for %s: %v", address, err))
		data["Error"] = "The account could not be created. Ask for a new link."
		reply(http.StatusInternalServerError)
		return
	}
	s.logger.Info(fmt.Sprintf("New user registered: %s, by a link in mail", address))

	data["Done"] = true
	if s.cfg.ApprovalRequired == "required" {
		data["Message"] = "Your account has been created, and is waiting for an administrator's approval."
	} else {
		data["Message"] = "Your account has been created. You can sign in now."
	}
	reply(http.StatusOK)
}

// registerDirectly creates the account at once, for email_verification: disabled.
// Nothing proves the address, and the reply shows which addresses have accounts.
func (s *Server) registerDirectly(w http.ResponseWriter, r *http.Request, data map[string]interface{}, reply func(int)) {
	address := r.PostFormValue("email")
	password := r.PostFormValue("password")
	data["Email"] = address

	if address == "" || password == "" {
		s.registerFailure(w, data, reply, http.StatusBadRequest, "email and password are required")
		return
	}
	if err := csv.ValidateEmail(address); err != nil {
		s.registerFailure(w, data, reply, http.StatusBadRequest, err.Error())
		return
	}
	address = s.accounts.Resolve(address)
	if err := csv.ValidatePassword(password); err != nil {
		s.registerFailure(w, data, reply, http.StatusBadRequest, err.Error())
		return
	}

	// After validation, so a typo costs nothing, and before hashing, which is
	// the expensive step.
	if client := s.clients.Addr(r); !s.registerLimiter.Allow(client) {
		s.logger.Warn(fmt.Sprintf("rate limited: registration from %s", client))
		s.registerFailure(w, data, reply, http.StatusTooManyRequests, "Too many registration attempts")
		return
	}

	hash, err := s.hasher.Hash(password)
	if err != nil {
		s.registerFailure(w, data, reply, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.backend.CreateUser(address, hash, s.cfg.PasswordHashAlg, s.newAccountFlags()); err != nil {
		if errors.Is(err, csv.ErrUserExists) {
			s.registerFailure(w, data, reply, http.StatusConflict, "User already exists")
			return
		}
		s.registerFailure(w, data, reply, http.StatusInternalServerError, "internal error")
		return
	}

	s.logger.Info(fmt.Sprintf("New user registered: %s", address))
	http.Redirect(w, r, s.path("/login"), http.StatusFound)
}
