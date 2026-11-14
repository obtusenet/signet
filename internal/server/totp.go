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
	"unicode"

	"github.com/obtusenet/signet/internal/auth"
	"github.com/obtusenet/signet/internal/db"
	"github.com/obtusenet/signet/internal/otp"
	"github.com/obtusenet/signet/internal/session"
)

// How many wrong codes an address may try per window.  A person gets here only with
// the first step passed, so nobody can use this to block someone they cannot sign in as.
const (
	totpMaxFailures   = 5
	totpFailureWindow = 300 // seconds
)

const wrongCodeMessage = "That code is not right. Try the next one."

const wrongRecoveryCodeMessage = "That recovery code does not work. Each one works once, and replacing them ends the old set."

const expiredStepMessage = "This sign-in has expired. Start again."

// startTOTP switches TOTP on if auth_methods.totp says so.  Turned off, nothing asks
// for a code, so an account with a key signs in without one: say so.
func (s *Server) startTOTP(dbStore *db.DB, secret []byte) {
	if s.cfg.SecondFactorRequired() {
		s.logger.Info(fmt.Sprintf("second_factor is required: %s", strings.Join(s.cfg.SecondFactorMethods, ", ")))
		if s.cfg.SecondFactorAllows("email_pin") {
			s.logger.Warn("second_factor_methods lists email_pin: password recovery is by mail too, so whoever holds the mailbox can sign in with it alone")
		}
	}
	// Whatever happens below, a password or a PIN asks whether a second step
	// follows; with no store and second_factor required, the answer refuses.
	s.passwordAuth.SetSecondStep(s.secondStep)
	if s.emailPINAuth != nil {
		s.emailPINAuth.SetSecondStep(s.secondStep)
	}
	store, err := otp.NewTOTPStore(dbStore.DB(), secret, s.cfg.TOTPIssuer)
	if err != nil {
		if s.authMethodEnabled("totp") || s.cfg.SecondFactorRequired() {
			s.logger.Warn(fmt.Sprintf("auth_methods.totp is enabled or second_factor required, but the sign-in steps are off: %v", err))
		}
		return
	}
	// The steps of a sign-in live in the TOTP store's table, which every second
	// step uses, with TOTP on or off.
	s.steps = store
	s.totpLimit = auth.NewRateLimiter(totpMaxFailures, totpFailureWindow)
	s.housekeeping = append(s.housekeeping, func(ctx context.Context) {
		s.totpLimit.Cleanup()
		if err := s.steps.PurgeExpired(ctx); err != nil {
			s.logger.Warn(fmt.Sprintf("removing expired sign-in steps: %v", err))
		}
	})
	if !s.authMethodEnabled("totp") {
		if n, err := store.CountAll(context.Background()); err == nil && n > 0 {
			s.logger.Warn(fmt.Sprintf("auth_methods.totp is disabled, so the %d TOTP keys on file are ignored and sign-in asks for no code", n))
		}
		return
	}
	s.totp = store
	s.logger.Info("TOTP enabled")
}

// finishSecondStep takes the code step of a sign-in: a code from an authenticator, or
// a recovery code.  It always answers with the page or a redirect, as a plain form.
func (s *Server) finishSecondStep(w http.ResponseWriter, r *http.Request) {
	pending := r.PostFormValue("pending")
	code := r.PostFormValue("code")
	client := s.clients.Addr(r)
	refuse := func(token, message string) {
		s.renderLoginPage(w, r, token, message, http.StatusUnauthorized)
	}

	if s.steps == nil {
		refuse("", expiredStepMessage)
		return
	}
	address, method, step, err := s.steps.Step(r.Context(), pending)
	if err != nil {
		if !errors.Is(err, otp.ErrNoPending) {
			s.logger.Error(fmt.Sprintf("checking a sign-in step: %v", err))
		}
		refuse("", expiredStepMessage)
		return
	}
	// The account may have been locked since the first step.
	if _, err := s.accounts.Check(address); err != nil {
		s.logger.Warn(fmt.Sprintf("code step refused for %s: %v", address, err))
		refuse("", expiredStepMessage)
		return
	}
	switch step {
	case otp.StepMail:
		s.finishMailStep(w, r, pending, address, method)
		return
	case otp.StepEnrol:
		s.enrolStep(w, r, pending, address, method)
		return
	}
	if s.totp == nil {
		refuse("", expiredStepMessage)
		return
	}
	// The attempt counts before the code is checked, and one check per account
	// runs at a time, so codes sent together cannot all pass the limits.
	if !s.totpLimit.Take(address) {
		s.logger.Warn(fmt.Sprintf("rate limited: codes for %s from %s", address, client))
		refuse(pending, wrongCodeMessage)
		return
	}
	counted := true
	defer func() {
		if !counted {
			s.totpLimit.Refund(address)
		}
	}()
	release := s.lockout.Guard(address)
	defer release()
	if until, locked, err := s.lockout.Locked(r.Context(), address); err != nil || locked {
		counted = false
		if err != nil {
			s.logger.Error(fmt.Sprintf("checking the lockout of %s: %v", address, err))
		} else {
			s.logger.Warn(fmt.Sprintf("rate limited: %s is locked until %s after too many failed sign-ins",
				address, until.UTC().Format(time.RFC3339)))
		}
		refuse(pending, wrongCodeMessage)
		return
	}

	how := "totp"
	good := false
	if otp.LooksLikeRecoveryCode(code) {
		how = "recovery-code"
		good, err = s.totp.UseRecoveryCode(r.Context(), address, code)
	} else {
		err = s.totp.Verify(r.Context(), address, code, time.Now())
		good = err == nil
		if errors.Is(err, otp.ErrBadCode) {
			if strings.Contains(err.Error(), "cookie_secret") {
				s.logger.Error(fmt.Sprintf("TOTP keys of %s: %v", address, err))
			}
			err = nil
		}
	}
	if err != nil {
		counted = false
		s.logger.Error(fmt.Sprintf("checking a code for %s: %v", address, err))
		refuse(pending, "The code could not be checked. Try again.")
		return
	}
	if !good {
		if err := s.lockout.Fail(r.Context(), address); err != nil {
			s.logger.Error(fmt.Sprintf("counting a failed sign-in of %s: %v", address, err))
		}
		if how == "recovery-code" {
			s.logger.Warn(fmt.Sprintf("wrong recovery code for %s from %s", address, client))
			refuse(pending, wrongRecoveryCodeMessage)
			return
		}
		s.logger.Warn(fmt.Sprintf("wrong code for %s from %s", address, client))
		refuse(pending, wrongCodeMessage)
		return
	}
	counted = false

	if err := s.totp.TakePending(r.Context(), pending); err != nil {
		refuse("", expiredStepMessage)
		return
	}
	s.totpLimit.Reset(address)

	authCookie, ok := s.stepSession(w, r, address, method, method+"+"+how)
	if !ok {
		return
	}
	if how == "recovery-code" {
		left, _ := s.totp.RecoveryCodesLeft(r.Context(), address)
		s.logger.Warn(fmt.Sprintf("recovery code used by %s from %s: %d left", address, client, left))
		s.notifyAccountChange(address, fmt.Sprintf("A recovery code was used to sign in to this account. %d are left.", left))
	}
	if authCookie != nil {
		http.SetCookie(w, authCookie)
	}
	http.Redirect(w, r, s.loginRedirect(r), http.StatusFound)
}

// validKeyLabel keeps labels to what an administrator's terminal and a page can show.
func validKeyLabel(label string) bool {
	return len(label) <= 64 && strings.IndexFunc(label, unicode.IsControl) < 0
}

func (s *Server) totpOff(w http.ResponseWriter) bool {
	if s.totp == nil {
		accountError(w, http.StatusForbidden, "Authenticator apps are not enabled for this installation.")
		return true
	}
	return false
}

func (s *Server) beginTOTP(w http.ResponseWriter, r *http.Request, address *session.Session, label string) {
	if s.totpOff(w) {
		return
	}
	label = strings.TrimSpace(label)
	if label == "" {
		label = "Authenticator"
	}
	if !validKeyLabel(label) {
		accountError(w, http.StatusBadRequest, "That name is too long or has characters it cannot have.")
		return
	}
	enrollment, err := s.totp.BeginEnrollment(r.Context(), address.UserEmail, label)
	if errors.Is(err, otp.ErrTooManyKeys) {
		accountError(w, http.StatusBadRequest, fmt.Sprintf("An account can have at most %d keys.", otp.MaxTOTPKeys))
		return
	}
	if err != nil {
		s.logger.Error(fmt.Sprintf("starting a TOTP key for %s: %v", address.UserEmail, err))
		accountError(w, http.StatusInternalServerError, "The key could not be started.")
		return
	}
	accountReply(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"secret":  enrollment.Secret,
		"url":     enrollment.URL,
		"qr":      enrollment.QR,
	})
}

func (s *Server) finishTOTP(w http.ResponseWriter, r *http.Request, address *session.Session, code string) {
	if s.totpOff(w) {
		return
	}
	codes, err := s.totp.FinishEnrollment(r.Context(), address.UserEmail, code, time.Now())
	switch {
	case errors.Is(err, otp.ErrBadCode):
		accountError(w, http.StatusBadRequest, "That code is not right. Check the app has this key, and try the next code.")
		return
	case errors.Is(err, otp.ErrNoEnrollment):
		accountError(w, http.StatusBadRequest, "This setup has expired. Start again.")
		return
	case err != nil:
		s.logger.Error(fmt.Sprintf("saving a TOTP key for %s: %v", address.UserEmail, err))
		accountError(w, http.StatusInternalServerError, "The key could not be saved.")
		return
	}
	s.logger.Info(fmt.Sprintf("TOTP key added by %s from %s", address.UserEmail, s.clients.Addr(r)))
	s.notifyAccountChange(address.UserEmail, "An authenticator app was added to this account. Signing in with a password or a PIN now needs a code from it.")
	body := map[string]interface{}{"success": true}
	if codes != nil {
		body["recovery_codes"] = codes
	}
	accountReply(w, http.StatusOK, body)
}

func (s *Server) removeTOTP(w http.ResponseWriter, r *http.Request, address *session.Session, token, id string) {
	if s.totpOff(w) {
		return
	}
	if err := s.mayRemoveSecondFactor(r.Context(), address.UserEmail, "totp"); err != nil {
		accountError(w, http.StatusConflict, err.Error())
		return
	}
	err := s.totp.DeleteKey(r.Context(), address.UserEmail, id)
	if errors.Is(err, otp.ErrKeyNotFound) {
		accountError(w, http.StatusNotFound, "There is no such key.")
		return
	}
	if err != nil {
		s.logger.Error(fmt.Sprintf("removing a TOTP key of %s: %v", address.UserEmail, err))
		accountError(w, http.StatusInternalServerError, "The key could not be removed.")
		return
	}
	s.logger.Info(fmt.Sprintf("TOTP key removed by %s from %s", address.UserEmail, s.clients.Addr(r)))
	s.notifyAccountChange(address.UserEmail, "An authenticator app was removed from this account, and its other sessions have ended.")
	if err := s.sessionStore.RevokeOthers(r.Context(), address.UserEmail, token); err != nil {
		s.logger.Error(fmt.Sprintf("ending other sessions for %s: %v", address.UserEmail, err))
		accountError(w, http.StatusInternalServerError, "The key was removed, but this account's other sessions could not be ended.")
		return
	}
	accountReply(w, http.StatusOK, map[string]interface{}{"success": true})
}

func (s *Server) newRecoveryCodes(w http.ResponseWriter, r *http.Request, address *session.Session) {
	if s.totpOff(w) {
		return
	}
	codes, err := s.totp.NewRecoveryCodes(r.Context(), address.UserEmail)
	if errors.Is(err, otp.ErrKeyNotFound) {
		accountError(w, http.StatusBadRequest, "This account has no authenticator app.")
		return
	}
	if err != nil {
		s.logger.Error(fmt.Sprintf("replacing recovery codes of %s: %v", address.UserEmail, err))
		accountError(w, http.StatusInternalServerError, "The codes could not be replaced.")
		return
	}
	s.logger.Info(fmt.Sprintf("recovery codes replaced by %s from %s", address.UserEmail, s.clients.Addr(r)))
	s.notifyAccountChange(address.UserEmail, "This account's recovery codes were replaced, so the old ones no longer work.")
	accountReply(w, http.StatusOK, map[string]interface{}{"success": true, "recovery_codes": codes})
}
