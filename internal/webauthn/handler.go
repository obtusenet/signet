// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package webauthn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/obtusenet/signet/internal/auth"
	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/claims"
	"github.com/obtusenet/signet/internal/cookie"
	"github.com/obtusenet/signet/internal/logging"
	"github.com/obtusenet/signet/internal/session"
)

// InviteHeader carries an enrollment invite.  The token is a header, and the
// link that delivers it uses a URL fragment, so it never reaches a URI in a
// web-server or signet access log.
const InviteHeader = "X-Signet-Invite"

const maxLabelLength = 64

// Handler manages HTTP endpoints for WebAuthn operations
type Handler struct {
	service    *Service
	sessions   *session.Store
	cookieMgr  *cookie.CookieManager
	accounts   *auth.AccountPolicy
	logger     *logging.Logger
	claimsHook *claims.ClaimsHook

	reauthWindow time.Duration // 0 lets any session change keys
	notify       func(address, change string)
	signedIn     func(ctx context.Context, address string) // after a finished sign-in
	mayRemove    func(ctx context.Context, address string) error
}

// SetRemovalCheck says whether an account may lose one of its keys.  A non-nil
// error refuses, and its text is the reply.
func (h *Handler) SetRemovalCheck(check func(ctx context.Context, address string) error) {
	h.mayRemove = check
}

// SetAccountChanges says how recent a sign-in must be to change an account's keys,
// and how to tell the account about a change.
func (h *Handler) SetAccountChanges(reauthWindow time.Duration, notify func(address, change string)) {
	h.reauthWindow = reauthWindow
	h.notify = notify
}

// SetSignedIn says what to do once a security key has signed someone in, such as
// clearing their count of failed sign-ins.
func (h *Handler) SetSignedIn(after func(ctx context.Context, address string)) {
	h.signedIn = after
}

func (h *Handler) notifyChange(address, change string) {
	if h.notify != nil {
		h.notify(address, change)
	}
}

const signInAgainMessage = "Sign in again to change security keys: your sign-in is no longer recent."

// recentSession says whether the caller's session may change keys.
func (h *Handler) recentSession(r *http.Request) bool {
	if h.reauthWindow <= 0 {
		return true
	}
	token, err := h.cookieMgr.ValidateAuthCookie(r)
	if err != nil {
		return false
	}
	sess, err := h.sessions.Get(r.Context(), token)
	if err != nil {
		return false
	}
	return time.Since(sess.CreatedAt) <= h.reauthWindow
}

// NewHandler creates a new WebAuthn HTTP handler.  The session store and
// cookie manager identify the caller and sign a user in after an assertion;
// the account policy decides who may sign in or enroll at all.
func NewHandler(service *Service, sessions *session.Store, cookieMgr *cookie.CookieManager, accounts *auth.AccountPolicy, logger *logging.Logger, claimsHook ...*claims.ClaimsHook) *Handler {
	h := &Handler{service: service, sessions: sessions, cookieMgr: cookieMgr, accounts: accounts, logger: logger}
	if len(claimsHook) > 0 && claimsHook[0] != nil {
		h.claimsHook = claimsHook[0]
	}
	return h
}

// RegisterResponse is the response from a registration operation
type RegisterResponse struct {
	Success    bool                         `json:"success"`
	Error      string                       `json:"error,omitempty"`
	Credential *WebAuthnCredential          `json:"credential,omitempty"`
	Options    *protocol.CredentialCreation `json:"options,omitempty"`
	Ceremony   string                       `json:"ceremony,omitempty"`
}

// LoginResponse is the response from a login operation
type LoginResponse struct {
	Success  bool                          `json:"success"`
	Error    string                        `json:"error,omitempty"`
	Options  *protocol.CredentialAssertion `json:"options,omitempty"`
	Ceremony string                        `json:"ceremony,omitempty"`
}

// sessionEmail is the address of the caller's signed-in session, or "".
func (h *Handler) sessionEmail(r *http.Request) string {
	token, err := h.cookieMgr.ValidateAuthCookie(r)
	if err != nil {
		return ""
	}
	sess, err := h.sessions.Get(r.Context(), token)
	if err != nil {
		return ""
	}
	return sess.UserEmail
}

// enrollingAccount decides which account a registration acts on.  Only two
// things grant it: a live invite or a signed-in session.  The address is never
// taken from the request, so nobody can enroll a key on someone else's account.
// It answers the address and the invite token, if one was used.
func (h *Handler) enrollingAccount(r *http.Request) (string, string, int, string) {
	var userEmail string
	invite := strings.TrimSpace(r.Header.Get(InviteHeader))
	if invite != "" {
		address, err := h.service.InviteEmail(r.Context(), invite)
		if err != nil {
			return "", "", http.StatusUnauthorized, "this invite is not valid or has expired"
		}
		userEmail = address
	} else {
		userEmail = h.sessionEmail(r)
		if userEmail == "" {
			return "", "", http.StatusUnauthorized, "sign in to manage security keys"
		}
		if !h.recentSession(r) {
			return "", "", http.StatusForbidden, signInAgainMessage
		}
	}
	if _, err := h.accounts.Check(userEmail); err != nil {
		h.logger.Warn(fmt.Sprintf("webauthn enrollment refused for %s: %v", userEmail, err))
		return "", "", http.StatusForbidden, "this account cannot enroll security keys"
	}
	return userEmail, invite, 0, ""
}

// requirePOST answers 405 for other methods.
func requirePOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return false
	}
	return true
}

// HandleCheckInvite handles GET /webauthn/invite: whether the invite in the
// header can still enroll a key.  It spends nothing, so the page can refuse a
// used or expired link before asking anyone to name a key.
func (h *Handler) HandleCheckInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, RegisterResponse{Error: "Method not allowed"})
		return
	}
	if strings.TrimSpace(r.Header.Get(InviteHeader)) == "" {
		writeJSON(w, http.StatusBadRequest, RegisterResponse{Error: "invite is required"})
		return
	}
	if _, _, status, message := h.enrollingAccount(r); status != 0 {
		writeJSON(w, status, RegisterResponse{Error: message})
		return
	}
	writeJSON(w, http.StatusOK, RegisterResponse{Success: true})
}

// HandleBeginRegistration handles POST /webauthn/register/start
func (h *Handler) HandleBeginRegistration(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	userEmail, _, status, message := h.enrollingAccount(r)
	if status != 0 {
		writeJSON(w, status, RegisterResponse{Error: message})
		return
	}

	opts, ceremony, err := h.service.BeginRegistration(r.Context(), userEmail)
	if err != nil {
		h.logger.Error(fmt.Sprintf("webauthn registration start for %s: %v", userEmail, err))
		writeJSON(w, http.StatusInternalServerError, RegisterResponse{Error: "cannot start enrollment"})
		return
	}

	writeJSON(w, http.StatusOK, RegisterResponse{Success: true, Options: opts, Ceremony: ceremony})
}

// HandleFinishRegistration handles POST /webauthn/register/finish
func (h *Handler) HandleFinishRegistration(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	userEmail, invite, status, message := h.enrollingAccount(r)
	if status != 0 {
		writeJSON(w, status, RegisterResponse{Error: message})
		return
	}

	label := strings.TrimSpace(r.URL.Query().Get("label"))
	if label == "" {
		label = "Default"
	}
	if len(label) > maxLabelLength {
		writeJSON(w, http.StatusBadRequest, RegisterResponse{Error: "label is too long"})
		return
	}
	// user-list-webauthn prints labels on an administrator's terminal.
	if strings.IndexFunc(label, unicode.IsControl) >= 0 {
		writeJSON(w, http.StatusBadRequest, RegisterResponse{Error: "label cannot contain control characters"})
		return
	}

	var beforeStore func() error
	if invite != "" {
		beforeStore = func() error { return h.service.ConsumeInvite(r.Context(), invite) }
	}

	cred, err := h.service.FinishRegistration(r.Context(), userEmail, r.URL.Query().Get("ceremony"), r, label, beforeStore)
	if err != nil {
		h.logger.Warn(fmt.Sprintf("webauthn registration for %s failed: %v", userEmail, err))
		writeJSON(w, http.StatusBadRequest, RegisterResponse{Error: "the security key could not be enrolled"})
		return
	}

	h.logger.Info(fmt.Sprintf("webauthn credential enrolled for %s: invite=%v", userEmail, invite != ""))
	h.notifyChange(userEmail, "A security key was added to this account.")
	writeJSON(w, http.StatusOK, RegisterResponse{Success: true, Credential: cred})
}

// loginFailure is the one reply to a login that cannot proceed.  The reason
// goes to the log; a client learns nothing about whether the account exists.
func (h *Handler) loginFailure(w http.ResponseWriter, userEmail string, err error) {
	h.logger.Warn(fmt.Sprintf("webauthn login for %s failed: %v", userEmail, err))
	writeJSON(w, http.StatusUnauthorized, LoginResponse{Error: "security key sign-in failed"})
}

// validAddress gives what cannot be an address the one reply to a failed login,
// without letting it near the log.
// It answers the address as its account has it.
func (h *Handler) validAddress(w http.ResponseWriter, address string) (string, bool) {
	if err := csv.ValidateEmail(address); err != nil {
		h.logger.Warn(fmt.Sprintf("webauthn login refused: %v", err))
		writeJSON(w, http.StatusUnauthorized, LoginResponse{Error: "security key sign-in failed"})
		return "", false
	}
	return h.accounts.Resolve(address), true
}

// HandleBeginLogin handles POST /webauthn/authenticate/start
func (h *Handler) HandleBeginLogin(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	userEmail := r.URL.Query().Get("email")
	if userEmail == "" {
		writeJSON(w, http.StatusBadRequest, LoginResponse{Error: "email is required"})
		return
	}
	var ok bool
	if userEmail, ok = h.validAddress(w, userEmail); !ok {
		return
	}

	// An address that cannot sign in with a key gets the same kind of answer as
	// one that can.  The reason goes to the log.
	opts, ceremony, err := h.beginLogin(r.Context(), userEmail)
	if err != nil {
		h.logger.Warn(fmt.Sprintf("webauthn login for %s will fail, answering with decoy keys: %v", userEmail, err))
		opts, ceremony, err = h.service.BeginDecoyLogin(r.Context(), userEmail)
	}
	if err != nil {
		h.loginFailure(w, userEmail, err)
		return
	}

	writeJSON(w, http.StatusOK, LoginResponse{Success: true, Options: opts, Ceremony: ceremony})
}

// beginLogin starts a real ceremony for an account that may use its keys.
func (h *Handler) beginLogin(ctx context.Context, userEmail string) (*protocol.CredentialAssertion, string, error) {
	if _, err := h.accounts.Check(userEmail); err != nil {
		return nil, "", err
	}
	return h.service.BeginLogin(ctx, userEmail)
}

// HandleFinishLogin handles POST /webauthn/authenticate/finish
func (h *Handler) HandleFinishLogin(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	userEmail := r.URL.Query().Get("email")
	if userEmail == "" {
		writeJSON(w, http.StatusBadRequest, LoginResponse{Error: "email is required"})
		return
	}
	var ok bool
	if userEmail, ok = h.validAddress(w, userEmail); !ok {
		return
	}

	// The account may have been locked since the ceremony started.
	if _, err := h.accounts.Check(userEmail); err != nil {
		h.loginFailure(w, userEmail, err)
		return
	}

	if _, err := h.service.FinishLogin(r.Context(), userEmail, r.URL.Query().Get("ceremony"), r); err != nil {
		h.loginFailure(w, userEmail, err)
		return
	}

	authCookie, err := h.createSession(r.Context(), userEmail)
	if errors.Is(err, auth.ErrClaimsRefused) {
		h.logger.Warn(fmt.Sprintf("Login refused for %s: %v", userEmail, err))
		writeJSON(w, http.StatusForbidden, LoginResponse{Error: "Sign-in refused"})
		return
	}
	if err != nil {
		h.logger.Error(fmt.Sprintf("webauthn session for %s: %v", userEmail, err))
		writeJSON(w, http.StatusInternalServerError, LoginResponse{Error: "cannot create a session"})
		return
	}
	http.SetCookie(w, authCookie)

	h.logger.Info(fmt.Sprintf("User %s logged in via webauthn", userEmail))
	writeJSON(w, http.StatusOK, LoginResponse{Success: true})
}

// createSession turns a verified assertion into a session, applying the claims
// hook exactly as the other login methods do.
func (h *Handler) createSession(ctx context.Context, userEmail string) (*http.Cookie, error) {
	token, err := cookie.GenerateRandomToken()
	if err != nil {
		return nil, fmt.Errorf("generating token: %w", err)
	}

	claimsData := map[string]interface{}{}
	if h.claimsHook != nil {
		hookClaims, err := h.claimsHook.GetClaims(ctx, userEmail)
		if err != nil {
			// GetClaims only errors under on_failure: fail-closed.
			return nil, fmt.Errorf("%w: %v", auth.ErrClaimsRefused, err)
		}
		if hookClaims != nil {
			claimsData = hookClaims
		}
	}
	claimsJSON, err := json.Marshal(claimsData)
	if err != nil {
		return nil, fmt.Errorf("encoding claims: %w", err)
	}

	now := time.Now()
	maxAge := h.cookieMgr.MaxAge
	if maxAge <= 0 {
		maxAge = 86400
	}
	sess := &session.Session{
		Token:      token,
		UserEmail:  userEmail,
		AuthMethod: "webauthn",
		Claims:     string(claimsJSON),
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Duration(maxAge) * time.Second),
	}
	if err := h.sessions.Create(ctx, sess); err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}
	if h.signedIn != nil {
		h.signedIn(ctx, userEmail)
	}
	return h.cookieMgr.CreateAuthCookie(token), nil
}

// HandleListCredentials handles GET /webauthn/credentials: the signed-in
// user's own credentials.
func (h *Handler) HandleListCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"success": false, "error": "Method not allowed"})
		return
	}
	userEmail := h.sessionEmail(r)
	if userEmail == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "sign in to manage security keys"})
		return
	}

	creds, err := h.service.ListUserCredentials(r.Context(), userEmail)
	if err != nil {
		h.logger.Error(fmt.Sprintf("listing webauthn credentials for %s: %v", userEmail, err))
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "cannot list security keys"})
		return
	}
	if creds == nil {
		creds = []WebAuthnCredential{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"user":        userEmail,
		"credentials": creds,
	})
}

// HandleDeleteCredential handles DELETE /webauthn/credentials/<credential_id>
// for a credential belonging to the signed-in user.  It ends every session of
// the account, this one included: whoever signed in with a key being removed,
// perhaps a stolen one, must not stay signed in.
func (h *Handler) HandleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"success": false, "error": "Method not allowed"})
		return
	}
	userEmail := h.sessionEmail(r)
	if userEmail == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "sign in to manage security keys"})
		return
	}
	if !h.recentSession(r) {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"success": false, "error": signInAgainMessage})
		return
	}

	credentialID := strings.TrimPrefix(r.URL.Path, "/webauthn/credentials/")
	if h.mayRemove != nil {
		if err := h.mayRemove(r.Context(), userEmail); err != nil {
			writeJSON(w, http.StatusConflict, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
	}
	if err := h.service.DeleteUserCredential(r.Context(), userEmail, credentialID); err != nil {
		if errors.Is(err, ErrCredentialNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "no such security key"})
			return
		}
		h.logger.Error(fmt.Sprintf("deleting webauthn credential for %s: %v", userEmail, err))
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "cannot delete the security key"})
		return
	}

	h.logger.Info(fmt.Sprintf("webauthn credential deleted by %s", userEmail))
	h.notifyChange(userEmail, "A security key was removed from this account, and all of its sessions have ended.")

	if err := h.sessions.RevokeAll(r.Context(), userEmail); err != nil {
		h.logger.Error(fmt.Sprintf("ending sessions for %s after deleting a webauthn credential: %v", userEmail, err))
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "the security key was removed, but this account could not be signed out"})
		return
	}
	http.SetCookie(w, h.cookieMgr.ExpiredAuthCookie())
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "signed_out": true})
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
