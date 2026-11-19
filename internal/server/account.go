// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/obtusenet/signet/internal/auth"
	"github.com/obtusenet/signet/internal/avatar"
	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/email"
	"github.com/obtusenet/signet/internal/otp"
	"github.com/obtusenet/signet/internal/session"
)

const signInAgainMessage = "Sign in again to change this: your sign-in is no longer recent."

// callerSession returns the session of the request and its token, or nil.
func (s *Server) callerSession(r *http.Request) (*session.Session, string) {
	token, err := s.cookieMgr.ValidateAuthCookie(r)
	if err != nil {
		return nil, ""
	}
	sess, err := s.sessionStore.Get(r.Context(), token)
	if err != nil {
		return nil, ""
	}
	return sess, token
}

// reauthWindow is how long a sign-in counts as recent, for account changes.
func (s *Server) reauthWindow() time.Duration {
	return time.Duration(s.cfg.AccountReauthWindow) * time.Second
}

// notifyAccountChange tells an account's mailbox about a change to the account,
// which is how its owner hears of one they did not make.
//
// RADIUS accounts get none: their names need not be mailboxes, and a mailbox
// that matches one need not be theirs.
func (s *Server) notifyAccountChange(address, change string) {
	if !s.isLocal(address) {
		return
	}
	s.mailInBackground(func(ctx context.Context) {
		if err := s.sendLinkMail(address, "A change to your Signet account", "account-change", email.AccountChangeFallback, &email.LinkMailData{
			Email:   address,
			Change:  change,
			AppName: "Signet",
		}); err != nil {
			s.logger.Error(fmt.Sprintf("sending a notice to %s: %v", address, err))
		}
	})
}

func accountReply(w http.ResponseWriter, status int, body map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

func accountError(w http.ResponseWriter, status int, message string) {
	accountReply(w, status, map[string]interface{}{"success": false, "error": message})
}

// handleAccount serves the account page, and takes every change on it as a POST
// to this one path, so that a web server needs one route.  Security keys have
// their own routes, under /webauthn/.
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	sess, token := s.callerSession(r)
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if sess == nil {
			http.Redirect(w, r, s.path("/login")+"?referrer="+url.QueryEscape(s.path("/account")), http.StatusFound)
			return
		}
		s.renderAccountPage(w, r, sess)
	case http.MethodPost:
		if sess == nil {
			accountError(w, http.StatusUnauthorized, "Sign in first.")
			return
		}
		s.changeAccount(w, r, sess, token)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) renderAccountPage(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	// A RADIUS account has no password here and no keys: its password is the
	// server's, and a key would sign it in without the server.
	radiusAccount := s.isRadiusAccount(sess.UserEmail)
	hasPassword := false
	if !radiusAccount {
		user, err := s.accounts.Check(sess.UserEmail)
		if err != nil {
			s.logger.Warn(fmt.Sprintf("account page refused for %s: %v", sess.UserEmail, err))
			http.Error(w, "This account cannot sign in.", http.StatusForbidden)
			return
		}
		hasPassword = user.PasswordHash != noPassword
	}
	var err error
	var totpKeys []otp.TOTPKey
	recoveryLeft := 0
	if s.totp != nil {
		if totpKeys, err = s.totp.ListKeys(r.Context(), sess.UserEmail); err == nil {
			recoveryLeft, err = s.totp.RecoveryCodesLeft(r.Context(), sess.UserEmail)
		}
		if err != nil {
			s.logger.Error(fmt.Sprintf("listing TOTP keys for %s: %v", sess.UserEmail, err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	if err := s.renderTemplate(w, "account.html", map[string]interface{}{
		"Email":           sess.UserEmail,
		"Fresh":           time.Since(sess.CreatedAt) <= s.reauthWindow(),
		"PasswordEnabled": s.authMethodEnabled("password") && !radiusAccount,
		"HasPassword":     hasPassword,
		"WebAuthnEnabled": s.webauthnHandler != nil && !radiusAccount,
		"RadiusAccount":   radiusAccount,
		"TOTPEnabled":     s.totp != nil,
		"TOTPKeys":        totpKeys,
		"RecoveryLeft":    recoveryLeft,
		"MaxTOTPKeys":     otp.MaxTOTPKeys,
		"AvatarsEnabled":  s.avatars != nil,
		"Avatar":          s.avatarPath(r.Context(), sess.UserEmail),
		"AvatarSize":      s.cfg.AvatarSize,
		// Generated here from the address, so it is safe as a data: URL.
		"Identicon": template.URL(avatar.IdenticonURL(sess.UserEmail)),
	}); err != nil {
		s.logger.Error(fmt.Sprintf("rendering account page: %v", err))
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// noPassword is the hash of an account with no password.
const noPassword = "!"

// changeAccount applies one change.  A session alone does not allow any: it may
// be someone else's at an unattended browser, so the sign-in must be recent.
func (s *Server) changeAccount(w http.ResponseWriter, r *http.Request, sess *session.Session, token string) {
	var req struct {
		Action  string `json:"action"`
		Current string `json:"current"`
		New     string `json:"new"`
		Label   string `json:"label"`
		Code    string `json:"code"`
		ID      string `json:"id"`
		Image   string `json:"image"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		accountError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if time.Since(sess.CreatedAt) > s.reauthWindow() {
		accountError(w, http.StatusForbidden, signInAgainMessage)
		return
	}
	switch req.Action {
	case "password":
		s.changePassword(w, r, sess, token, req.Current, req.New)
	case "totp-begin":
		s.beginTOTP(w, r, sess, req.Label)
	case "totp-finish":
		s.finishTOTP(w, r, sess, req.Code)
	case "totp-remove":
		s.removeTOTP(w, r, sess, token, req.ID)
	case "totp-codes":
		s.newRecoveryCodes(w, r, sess)
	case "avatar-set":
		s.setAvatar(w, r, sess, req.Image)
	case "avatar-remove":
		s.removeAvatar(w, r, sess)
	default:
		accountError(w, http.StatusBadRequest, "Unknown action")
	}
}

// changePassword needs the current password, if there is one: a recent sign-in may
// have been by a method that says nothing about it.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, sess *session.Session, token, current, replacement string) {
	address := sess.UserEmail
	if !s.authMethodEnabled("password") {
		accountError(w, http.StatusForbidden, "Passwords are disabled for this installation.")
		return
	}
	user, err := s.accounts.Check(address)
	if err != nil {
		s.logger.Warn(fmt.Sprintf("password change refused for %s: %v", address, err))
		accountError(w, http.StatusForbidden, "This account cannot change its password.")
		return
	}
	if user.PasswordHash != noPassword {
		switch err := s.passwordAuth.CheckPassword(address, s.clients.Addr(r), current); {
		case errors.Is(err, auth.ErrRateLimited), errors.Is(err, auth.ErrSourceRateLimited):
			s.logger.Warn(fmt.Sprintf("rate limited: password change for %s from %s", address, s.clients.Addr(r)))
			accountError(w, http.StatusBadRequest, "The current password is not right.")
			return
		case err != nil:
			s.logger.Warn(fmt.Sprintf("password change for %s from %s: wrong current password", address, s.clients.Addr(r)))
			accountError(w, http.StatusBadRequest, "The current password is not right.")
			return
		}
	}
	if err := csv.ValidatePassword(replacement); err != nil {
		accountError(w, http.StatusBadRequest, shortPasswordMessage)
		return
	}
	hash, err := s.hasher.Hash(replacement)
	if err != nil {
		s.logger.Error(fmt.Sprintf("hashing a new password: %v", err))
		accountError(w, http.StatusInternalServerError, "The password could not be changed.")
		return
	}
	if err := s.backend.UpdateUser(address, map[string]string{
		"password_hash":  hash,
		"hash_algorithm": s.cfg.PasswordHashAlg,
	}); err != nil {
		s.logger.Error(fmt.Sprintf("storing a new password for %s: %v", address, err))
		accountError(w, http.StatusInternalServerError, "The password could not be changed.")
		return
	}
	s.logger.Info(fmt.Sprintf("password changed by %s from %s", address, s.clients.Addr(r)))
	s.notifyAccountChange(address, "The password of this account was changed.")

	if err := s.sessionStore.RevokeOthers(r.Context(), address, token); err != nil {
		s.logger.Error(fmt.Sprintf("ending other sessions for %s: %v", address, err))
		accountError(w, http.StatusInternalServerError, "The password was changed, but this account's other sessions could not be ended.")
		return
	}
	accountReply(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Your password has been changed, and this account's other sessions have ended.",
	})
}
