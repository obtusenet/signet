// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/claims"
	"github.com/obtusenet/signet/internal/clientaddr"
	"github.com/obtusenet/signet/internal/cookie"
	"github.com/obtusenet/signet/internal/email"
	"github.com/obtusenet/signet/internal/logging"
	"github.com/obtusenet/signet/internal/session"
)

// EmailPINAuth handles email PIN authentication
type EmailPINAuth struct {
	clients         *clientaddr.Resolver
	store           *email.PINStore
	accounts        *AccountPolicy
	session         *session.Store
	cookieMgr       *cookie.CookieManager
	logger          *logging.Logger
	rateLimit       *EmailRateLimiter
	maxRetries      int
	lockoutDuration time.Duration
	claimsHook      *claims.ClaimsHook
	verifyMu        sync.Mutex
	background      func(func(context.Context))
	secondStep      SecondStep
	accountLockout  *Lockout // consecutive failures per account, with passwords and codes
}

// SetLockout counts wrong PINs with an account's other failed sign-ins.
func (e *EmailPINAuth) SetLockout(l *Lockout) {
	e.accountLockout = l
}

// accountLocked reports whether the account refuses guesses now; a failure to
// check refuses too.
func (e *EmailPINAuth) accountLocked(ctx context.Context, address string) bool {
	until, locked, err := e.accountLockout.Locked(ctx, address)
	if err != nil {
		e.logger.Error(fmt.Sprintf("checking the lockout of %s: %v", address, err))
		return true
	}
	if locked {
		e.logger.Warn(fmt.Sprintf("rate limited: %s is locked until %s after too many failed sign-ins", address, until.UTC().Format(time.RFC3339)))
	}
	return locked
}

// errPINLocked reports an address with too many recent wrong guesses.  Callers
// answer it like any other wrong PIN: a distinct reply would confirm that the
// address is a real account.
var errPINLocked = errors.New("too many failed PIN attempts")

// SetClientAddr says which proxies to believe about a requester's address.
// Without it, none are.
func (e *EmailPINAuth) SetClientAddr(clients *clientaddr.Resolver) {
	e.clients = clients
}

// SetSecondStep says how to find out whether an account also needs a code.
func (e *EmailPINAuth) SetSecondStep(step SecondStep) {
	e.secondStep = step
}

// SetBackground says how to run what follows a send request, so that its timing
// is not in the reply.  Without it, that runs during the request.
func (e *EmailPINAuth) SetBackground(run func(func(context.Context))) {
	e.background = run
}

// NewEmailPINAuth creates a new EmailPINAuth
func NewEmailPINAuth(store *email.PINStore, accounts *AccountPolicy, sessStore *session.Store, cookieMgr *cookie.CookieManager, logger *logging.Logger, rateLimit *EmailRateLimiter, maxRetries int, lockoutDuration time.Duration, claimsHook ...*claims.ClaimsHook) *EmailPINAuth {
	e := &EmailPINAuth{
		store:           store,
		accounts:        accounts,
		session:         sessStore,
		cookieMgr:       cookieMgr,
		logger:          logger,
		rateLimit:       rateLimit,
		maxRetries:      maxRetries,
		lockoutDuration: lockoutDuration,
	}

	// Optional claims hook (variadic parameter)
	if len(claimsHook) > 0 && claimsHook[0] != nil {
		e.claimsHook = claimsHook[0]
	}

	return e
}

// genericSendReply is the answer to every accepted send, whether or not a mail
// went out, so the endpoint cannot be used to discover which addresses exist.
func genericSendReply(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "PIN sent to your email",
	})
}

// SendPINRequest handles a request to send a PIN to the user's email
func (e *EmailPINAuth) SendPINRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" {
		writeJSONError(w, http.StatusBadRequest, "Email is required")
		return
	}
	var ok bool
	if req.Email, ok = e.validAddress(w, r, req.Email); !ok {
		return
	}

	// Two budgets: per requester, and per target address.  A requester with many
	// addresses would get through the first alone, so a mailbox needs the second.
	if !e.rateLimit.Allow("send:"+e.clients.Addr(r)) || !e.rateLimit.Allow("send-to:"+req.Email) {
		e.logger.Warn(fmt.Sprintf("rate limited: PIN send for %s from %s", req.Email, e.clients.Addr(r)))
		writeJSONError(w, http.StatusTooManyRequests, "Rate limit exceeded")
		return
	}

	// Whether a message goes out depends on the account, so none of that may show
	// in the reply, or in how long it takes.
	client := e.clients.Addr(r)
	if e.background != nil {
		e.background(func(ctx context.Context) { e.sendPIN(ctx, req.Email, client) })
	} else {
		e.sendPIN(r.Context(), req.Email, client)
	}
	genericSendReply(w)
}

// sendPIN mails a PIN to an account allowed to sign in.  What stops it goes to
// the log.
func (e *EmailPINAuth) sendPIN(ctx context.Context, address, client string) {
	if _, err := e.accounts.Check(address); err != nil {
		e.logger.Info(fmt.Sprintf("PIN not sent to %s: %v", address, err))
		return
	}
	locked, err := e.isAccountLocked(ctx, address)
	if err != nil {
		e.logger.Error(fmt.Sprintf("checking PIN lockout: %v", err))
		return
	}
	if locked {
		e.logger.Warn(fmt.Sprintf("rate limited: PIN send for %s from %s: too many failed attempts", address, client))
		return
	}
	if e.accountLocked(ctx, address) {
		return
	}
	pinID, err := e.store.CreateAndSendPIN(ctx, address)
	if err != nil {
		e.logger.Error(fmt.Sprintf("failed to send PIN to %s: %v", address, err))
		return
	}
	e.logger.Info(fmt.Sprintf("PIN sent: email=%s pin_id=%s", address, pinID))
}

// SecondFactorMessage is what a person is told when the first step passed and
// no second step can follow it.
func SecondFactorMessage(err error) string {
	if errors.Is(err, ErrUseSecurityKey) {
		return "This account signs in with its security key."
	}
	return "This account needs a second way to sign in, and has none it can use here. Ask the administrator."
}

// SendStepPIN mails a PIN to an account that passed its password, as the second
// step of its sign-in.  Its limits are the ones a PIN sign-in has.
func (e *EmailPINAuth) SendStepPIN(ctx context.Context, address, client string) {
	if !e.rateLimit.Allow("send-to:" + address) {
		e.logger.Warn(fmt.Sprintf("rate limited: PIN send for %s from %s", address, client))
		return
	}
	if e.background != nil {
		e.background(func(ctx context.Context) { e.sendPIN(ctx, address, client) })
		return
	}
	e.sendPIN(ctx, address, client)
}

// CheckStepPIN tests a PIN mailed as a second step.  A wrong one counts toward
// the account's lockout.  It answers ErrStepPINSpent when the PIN can take no
// more tries.
func (e *EmailPINAuth) CheckStepPIN(ctx context.Context, address, pin string) error {
	release := e.accountLockout.Guard(address)
	defer release()
	if e.accountLocked(ctx, address) {
		return ErrStepPINSpent
	}
	err := e.checkPIN(ctx, address, pin)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errPINLocked):
		return ErrStepPINSpent
	case errors.Is(err, email.ErrPINNotFound), errors.Is(err, email.ErrPINExpired):
		if ferr := e.accountLockout.Fail(ctx, address); ferr != nil {
			e.logger.Error(fmt.Sprintf("counting a failed sign-in of %s: %v", address, ferr))
		}
		return ErrStepPINWrong
	default:
		return err
	}
}

// Answers of CheckStepPIN.
var (
	ErrStepPINWrong = errors.New("wrong or expired PIN")
	ErrStepPINSpent = errors.New("the PIN can take no more tries")
)

// checkPIN applies the lockout and tests the guess as one step, so a burst of
// concurrent guesses cannot all pass the check before any failure is recorded.
func (e *EmailPINAuth) checkPIN(ctx context.Context, email, pin string) error {
	e.verifyMu.Lock()
	defer e.verifyMu.Unlock()

	locked, err := e.isAccountLocked(ctx, email)
	if err != nil {
		return err
	}
	if locked {
		return errPINLocked
	}
	return e.store.VerifyPIN(ctx, email, pin)
}

// VerifyPINRequest handles a request to verify a PIN
func (e *EmailPINAuth) VerifyPINRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Email string `json:"email"`
		PIN   string `json:"pin"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" || req.PIN == "" {
		writeJSONError(w, http.StatusBadRequest, "Email and PIN are required")
		return
	}
	var ok bool
	if req.Email, ok = e.validAddress(w, r, req.Email); !ok {
		return
	}

	// A separate budget from sending, so checking a PIN does not use up the
	// allowance for requesting one.  This is only a coarse brake: the real
	// limit on guessing is the per-address lockout in checkPIN.
	if !e.rateLimit.Allow("verify:" + e.clients.Addr(r)) {
		e.logger.Warn(fmt.Sprintf("rate limited: PIN verification for %s from %s", req.Email, e.clients.Addr(r)))
		writeJSONError(w, http.StatusTooManyRequests, "Rate limit exceeded")
		return
	}

	// The account may have been removed, locked or left unapproved since the
	// PIN was sent.
	if _, err := e.accounts.Check(req.Email); err != nil {
		e.logger.Warn(fmt.Sprintf("PIN verification refused for %s: %v", req.Email, err))
		writeJSONError(w, http.StatusBadRequest, "Invalid or expired PIN")
		return
	}
	// One check per account at a time, so the lockout sees each wrong PIN
	// before the next is checked.
	release := e.accountLockout.Guard(req.Email)
	defer release()
	// Answered like a wrong PIN, which tells nobody that the account exists.
	if e.accountLocked(r.Context(), req.Email) {
		writeJSONError(w, http.StatusBadRequest, "Invalid or expired PIN")
		return
	}

	if err := e.checkPIN(r.Context(), req.Email, req.PIN); err != nil {
		switch {
		case errors.Is(err, errPINLocked):
			e.logger.Warn(fmt.Sprintf("rate limited: PIN verification for %s from %s: too many failed attempts", req.Email, e.clients.Addr(r)))
		case errors.Is(err, email.ErrPINNotFound), errors.Is(err, email.ErrPINExpired):
			e.logger.Warn(fmt.Sprintf("PIN verification failed for %s from %s", req.Email, e.clients.Addr(r)))
			if err := e.accountLockout.Fail(r.Context(), req.Email); err != nil {
				e.logger.Error(fmt.Sprintf("counting a failed sign-in of %s: %v", req.Email, err))
			}
		default:
			e.logger.Error(fmt.Sprintf("PIN verification failed: %v", err))
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "Invalid or expired PIN")
		return
	}

	e.logger.Info(fmt.Sprintf("PIN verified successfully: email=%s", req.Email))

	if e.secondStep != nil {
		pending, step, err := e.secondStep(r.Context(), req.Email, "email_pin")
		if errors.Is(err, ErrUseSecurityKey) || errors.Is(err, ErrNoSecondFactor) {
			e.logger.Warn(fmt.Sprintf("PIN sign-in of %s stopped: %v", req.Email, err))
			writeJSONError(w, http.StatusForbidden, SecondFactorMessage(err))
			return
		}
		if err != nil {
			e.logger.Error(fmt.Sprintf("checking for a second step: %v", err))
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		if pending != "" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":       false,
				"totp_required": step == "code",
				"step":          step,
				"pending":       pending,
			})
			return
		}
	}

	authCookie, err := e.CreateSession(r.Context(), req.Email, "email_pin")
	if errors.Is(err, ErrClaimsRefused) {
		e.logger.Warn(fmt.Sprintf("login refused for %s: %v", req.Email, err))
		writeJSONError(w, http.StatusForbidden, "Sign-in refused")
		return
	}
	if err != nil {
		e.logger.Error(err.Error())
		writeJSONError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// The browser keeps the session in the same signed cookie as every
	// other method; without it the following request has no identity.
	if authCookie != nil {
		http.SetCookie(w, authCookie)
	}

	// Respond with success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "PIN verified successfully",
	})
}

// CreateSession signs an account in, once every step is done.  method is what the
// session records as how.  The cookie is nil without a cookie manager.
func (e *EmailPINAuth) CreateSession(ctx context.Context, address, method string) (*http.Cookie, error) {
	// Generate a random session token, as password login does.
	sessionToken, err := cookie.GenerateRandomToken()
	if err != nil {
		return nil, fmt.Errorf("generating session token: %w", err)
	}

	// Call claims hook to get user claims
	claimsData := map[string]interface{}{
		"email":  address,
		"method": method,
	}
	if e.claimsHook != nil {
		hookClaims, err := e.claimsHook.GetClaims(ctx, address)
		if err != nil {
			// GetClaims only errors under on_failure: fail-closed.
			return nil, fmt.Errorf("%w: %v", ErrClaimsRefused, err)
		} else if hookClaims != nil {
			// Merge hook claims with basic claims
			for k, v := range hookClaims {
				claimsData[k] = v
			}
		}
	}

	// Create session
	claimsJSON, err := json.Marshal(claimsData)
	if err != nil {
		e.logger.Warn(fmt.Sprintf("failed to marshal claims: %v", err))
		claimsJSON = []byte("{}")
	}

	now := time.Now()
	sess := &session.Session{
		Token:      sessionToken,
		UserEmail:  address,
		AuthMethod: method,
		Claims:     string(claimsJSON),
		CreatedAt:  now,
		ExpiresAt:  now.Add(e.sessionLifetime()),
	}
	// A cookie without a session row would look like success and then fail on
	// the very next request.
	if err := e.session.Create(ctx, sess); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	if _, err := e.accountLockout.Clear(ctx, address); err != nil {
		e.logger.Error(fmt.Sprintf("clearing the failed sign-ins of %s: %v", address, err))
	}
	if e.cookieMgr == nil {
		return nil, nil
	}
	return e.cookieMgr.CreateAuthCookie(sessionToken), nil
}

// sessionLifetime matches the session row to the cookie it backs.
func (e *EmailPINAuth) sessionLifetime() time.Duration {
	if e.cookieMgr != nil && e.cookieMgr.MaxAge > 0 {
		return time.Duration(e.cookieMgr.MaxAge) * time.Second
	}
	return 24 * time.Hour
}

// isAccountLocked reports whether the address has used up its wrong guesses
// within the lockout window.  This locks PIN sign-in only; the account's other
// methods are unaffected, so a guesser cannot lock its owner out entirely.
func (e *EmailPINAuth) isAccountLocked(ctx context.Context, email string) (bool, error) {
	failures, err := e.store.RecentFailures(ctx, email, time.Now().Add(-e.lockoutDuration))
	if err != nil {
		return false, err
	}
	return failures >= e.maxRetries, nil
}

// writeJSONError answers a JSON failure with a status code the caller can
// branch on, instead of a plain-text body.
func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// validAddress refuses what cannot be an address before it reaches the limiter's
// memory or the log.  Whether an address has an account stays unrevealed, since
// this looks only at its form.
// It answers the address as its account has it.
func (e *EmailPINAuth) validAddress(w http.ResponseWriter, r *http.Request, address string) (string, bool) {
	if err := csv.ValidateEmail(address); err != nil {
		e.logger.Warn(fmt.Sprintf("PIN request refused from %s: %v", e.clients.Addr(r), err))
		writeJSONError(w, http.StatusBadRequest, "Invalid email address")
		return "", false
	}
	return e.accounts.Resolve(address), true
}
