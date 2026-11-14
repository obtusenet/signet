// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/obtusenet/signet/internal/auth"
	"github.com/obtusenet/signet/internal/otp"
)

// mailStepTTL matches a mailed PIN's life.
const mailStepTTL = 10 * time.Minute

const wrongStepPINMessage = "That PIN is not right. Check the latest message, and try again."

const spentStepPINMessage = "Too many wrong PINs. Start again."

// secondStep decides what follows a first step that passed, by method: a code
// from the account's authenticator app, a PIN by mail, or adding a second factor.
// It answers the step's token and kind, or "" when the sign-in may finish.
//
// With second_factor optional, only an account with an authenticator app takes a
// second step.  With it required, every sign-in by password or PIN does:
//  1. a code, when the account has an app;
//  2. a mailed PIN, after a password, when email_pin is in second_factor_methods;
//  3. none, when the account has a security key: the key signs in by itself
//     (auth.ErrUseSecurityKey);
//  4. adding an app or a key, when the account has neither.
func (s *Server) secondStep(ctx context.Context, address, method string) (string, string, error) {
	if s.totp != nil {
		has, err := s.totp.HasKeys(ctx, address)
		if err != nil {
			return "", "", fmt.Errorf("checking for TOTP keys: %w", err)
		}
		if has {
			token, err := s.totp.CreatePending(ctx, address, method)
			return token, otp.StepCode, err
		}
	}
	if !s.cfg.SecondFactorRequired() {
		return "", "", nil
	}
	if s.steps == nil {
		return "", "", errors.New("second_factor is required, but the sign-in steps are off")
	}
	if method == "password" && s.cfg.SecondFactorAllows("email_pin") && s.emailPINAuth != nil {
		token, err := s.steps.CreateStep(ctx, address, method, otp.StepMail, mailStepTTL)
		if err != nil {
			return "", "", err
		}
		s.emailPINAuth.SendStepPIN(ctx, address, "second step")
		return token, otp.StepMail, nil
	}
	if s.webauthnSvc != nil {
		keys, err := s.webauthnSvc.ListUserCredentials(ctx, address)
		if err != nil {
			return "", "", fmt.Errorf("checking for security keys: %w", err)
		}
		if len(keys) > 0 {
			return "", "", auth.ErrUseSecurityKey
		}
	}
	if !s.canEnrolTOTP() && !s.canEnrolKey() {
		return "", "", auth.ErrNoSecondFactor
	}
	token, err := s.steps.CreateStep(ctx, address, method, otp.StepEnrol, otp.EnrolStepTTL)
	return token, otp.StepEnrol, err
}

func (s *Server) canEnrolTOTP() bool {
	return s.totp != nil && s.cfg.SecondFactorAllows("totp")
}

func (s *Server) canEnrolKey() bool {
	return s.webauthnSvc != nil && s.cfg.SecondFactorAllows("webauthn")
}

// askForStep answers a first step that passed, for an account that must take a
// second.  JSON gets the token and the kind; a form gets the page at that step.
func (s *Server) askForStep(w http.ResponseWriter, r *http.Request, pending, step string) {
	if wantsJSON(r) {
		accountReply(w, http.StatusOK, map[string]interface{}{
			"success":       false,
			"totp_required": step == otp.StepCode,
			"step":          step,
			"pending":       pending,
		})
		return
	}
	switch step {
	case otp.StepEnrol:
		s.renderEnrolStep(w, r, loginStep{Pending: pending}, http.StatusOK)
	default:
		s.renderLoginStep(w, r, loginStep{Pending: pending, Step: step}, http.StatusOK)
	}
}

// stepSession signs in an account that has taken its second step.  On failure it
// has answered, and ok is false.
func (s *Server) stepSession(w http.ResponseWriter, r *http.Request, address, firstMethod, sessionMethod string) (*http.Cookie, bool) {
	var authCookie *http.Cookie
	var err error
	if firstMethod == "email_pin" && s.emailPINAuth != nil {
		authCookie, err = s.emailPINAuth.CreateSession(r.Context(), address, sessionMethod)
	} else {
		authCookie, err = s.passwordAuth.CreateSession(r.Context(), address, sessionMethod)
	}
	if errors.Is(err, auth.ErrClaimsRefused) {
		s.logger.Warn(fmt.Sprintf("Login refused for %s: %v", address, err))
		s.renderLoginPage(w, r, "", "Sign-in refused", http.StatusForbidden)
		return nil, false
	}
	if err != nil {
		s.logger.Error(fmt.Sprintf("creating a session for %s: %v", address, err))
		s.renderLoginPage(w, r, "", "The sign-in could not be finished. Try again.", http.StatusInternalServerError)
		return nil, false
	}
	return authCookie, true
}

// finishMailStep takes the PIN mailed after a password.
func (s *Server) finishMailStep(w http.ResponseWriter, r *http.Request, pending, address, method string) {
	refuse := func(token, message string) {
		step := loginStep{Pending: token, Error: message}
		if token != "" {
			step.Step = otp.StepMail
		}
		s.renderLoginStep(w, r, step, http.StatusUnauthorized)
	}
	if s.emailPINAuth == nil {
		refuse("", expiredStepMessage)
		return
	}
	pin := strings.TrimSpace(r.PostFormValue("code"))
	err := s.emailPINAuth.CheckStepPIN(r.Context(), address, pin)
	switch {
	case errors.Is(err, auth.ErrStepPINWrong):
		s.logger.Warn(fmt.Sprintf("wrong mailed PIN for %s from %s", address, s.clients.Addr(r)))
		refuse(pending, wrongStepPINMessage)
		return
	case errors.Is(err, auth.ErrStepPINSpent):
		s.logger.Warn(fmt.Sprintf("rate limited: mailed PIN for %s from %s: too many failed attempts", address, s.clients.Addr(r)))
		_ = s.steps.TakePending(r.Context(), pending)
		refuse("", spentStepPINMessage)
		return
	case err != nil:
		s.logger.Error(fmt.Sprintf("checking a mailed PIN for %s: %v", address, err))
		refuse(pending, "The PIN could not be checked. Try again.")
		return
	}
	if err := s.steps.TakePending(r.Context(), pending); err != nil {
		refuse("", expiredStepMessage)
		return
	}
	authCookie, ok := s.stepSession(w, r, address, method, method+"+email_pin")
	if !ok {
		return
	}
	if authCookie != nil {
		http.SetCookie(w, authCookie)
	}
	http.Redirect(w, r, s.loginRedirect(r), http.StatusFound)
}

// renderEnrolStep shows the page that adds a second factor, with what this
// installation offers.
func (s *Server) renderEnrolStep(w http.ResponseWriter, r *http.Request, step loginStep, status int) {
	step.Step = otp.StepEnrol
	step.EnrolTOTP = s.canEnrolTOTP()
	step.EnrolKey = s.canEnrolKey()
	s.renderLoginStep(w, r, step, status)
}

// enrolStep adds a second factor to an account that passed its first step and has
// none.  The form's action says what to do:
//   - "" shows the choices;
//   - "totp-begin" makes an authenticator app's key and shows it;
//   - "totp-finish" takes a code from the app, saves the key, and signs in: the
//     code proves the app, so it is the second factor;
//   - "key" sends the browser to enroll a security key with a one-time invite,
//     after which the key signs in by itself.
func (s *Server) enrolStep(w http.ResponseWriter, r *http.Request, pending, address, method string) {
	ctx := r.Context()
	page := func(step loginStep, status int) {
		step.Pending = pending
		s.renderEnrolStep(w, r, step, status)
	}
	switch r.PostFormValue("action") {
	case "":
		page(loginStep{}, http.StatusOK)

	case "totp-begin":
		if !s.canEnrolTOTP() {
			page(loginStep{Error: "Authenticator apps are not offered here."}, http.StatusForbidden)
			return
		}
		enrollment, err := s.totp.BeginEnrollment(ctx, address, "Authenticator")
		if err != nil {
			s.logger.Error(fmt.Sprintf("starting a TOTP key for %s: %v", address, err))
			page(loginStep{Error: "The key could not be started. Try again."}, http.StatusInternalServerError)
			return
		}
		// The QR code is a PNG made here; nothing in it comes from the request.
		page(loginStep{TOTPStarted: true, TOTPSecret: enrollment.Secret, TOTPQR: template.URL(enrollment.QR)}, http.StatusOK)

	case "totp-finish":
		if !s.canEnrolTOTP() {
			page(loginStep{Error: "Authenticator apps are not offered here."}, http.StatusForbidden)
			return
		}
		codes, err := s.totp.FinishEnrollment(ctx, address, strings.TrimSpace(r.PostFormValue("code")), time.Now())
		switch {
		case errors.Is(err, otp.ErrBadCode):
			page(loginStep{TOTPStarted: true, Error: "That code is not right. Check the app has this key, and try the next code."}, http.StatusUnauthorized)
			return
		case errors.Is(err, otp.ErrNoEnrollment):
			page(loginStep{Error: "This setup has expired. Start again."}, http.StatusUnauthorized)
			return
		case err != nil:
			s.logger.Error(fmt.Sprintf("saving a TOTP key for %s: %v", address, err))
			page(loginStep{Error: "The key could not be saved. Try again."}, http.StatusInternalServerError)
			return
		}
		if err := s.steps.TakePending(ctx, pending); err != nil {
			s.renderLoginPage(w, r, "", expiredStepMessage, http.StatusUnauthorized)
			return
		}
		s.logger.Info(fmt.Sprintf("TOTP key added by %s from %s, at sign-in", address, s.clients.Addr(r)))
		s.notifyAccountChange(address, "An authenticator app was added to this account while signing in. Signing in now needs a code from it.")
		authCookie, ok := s.stepSession(w, r, address, method, method+"+totp")
		if !ok {
			return
		}
		if authCookie != nil {
			http.SetCookie(w, authCookie)
		}
		// The recovery codes are shown once, before going on.
		s.renderLoginStep(w, r, loginStep{
			Step:          otp.StepEnrol,
			RecoveryCodes: codes,
			Continue:      s.loginRedirect(r),
			Message:       "The authenticator app is added, and you are signed in.",
		}, http.StatusOK)

	case "key":
		if !s.canEnrolKey() {
			page(loginStep{Error: "Security keys are not offered here."}, http.StatusForbidden)
			return
		}
		token, err := s.webauthnSvc.CreateInvite(ctx, address, otp.EnrolStepTTL)
		if err != nil {
			s.logger.Error(fmt.Sprintf("creating a key invite for %s: %v", address, err))
			page(loginStep{Error: "The key could not be started. Try again."}, http.StatusInternalServerError)
			return
		}
		// The step is spent: the key, once added, signs in by itself.
		_ = s.steps.TakePending(ctx, pending)
		s.logger.Info(fmt.Sprintf("security key invite made for %s at sign-in, from %s", address, s.clients.Addr(r)))
		// The fragment keeps the invite out of every access log.
		http.Redirect(w, r, s.path("/webauthn/keys")+"#invite="+token, http.StatusSeeOther)

	default:
		page(loginStep{Error: "That is not something this page does."}, http.StatusBadRequest)
	}
}

// errLastSecondFactor refuses to remove an account's last second factor while
// second_factor is required.
var errLastSecondFactor = errors.New("This installation needs a second way to sign in. Add another before removing this one.")

// mayRemoveSecondFactor answers errLastSecondFactor when second_factor is
// required, and taking one of kind ("totp" or "webauthn") from the account would
// leave it no authenticator app and no security key.  A mailed PIN, when
// second_factor_methods lists it, is always there.
func (s *Server) mayRemoveSecondFactor(ctx context.Context, address, kind string) error {
	if !s.cfg.SecondFactorRequired() || s.cfg.SecondFactorAllows("email_pin") {
		return nil
	}
	left := 0
	if s.totp != nil {
		keys, err := s.totp.ListKeys(ctx, address)
		if err != nil {
			return fmt.Errorf("checking for TOTP keys: %w", err)
		}
		left += len(keys)
	}
	if s.webauthnSvc != nil {
		keys, err := s.webauthnSvc.ListUserCredentials(ctx, address)
		if err != nil {
			return fmt.Errorf("checking for security keys: %w", err)
		}
		left += len(keys)
	}
	if left <= 1 {
		return errLastSecondFactor
	}
	return nil
}
