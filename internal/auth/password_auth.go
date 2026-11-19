// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/claims"
	"github.com/obtusenet/signet/internal/cookie"
	"github.com/obtusenet/signet/internal/logging"
	"github.com/obtusenet/signet/internal/password"
	"github.com/obtusenet/signet/internal/radius"
	"github.com/obtusenet/signet/internal/session"
)

// ErrRateLimited reports that the login limiter refused the attempt before
// the password was even checked.
var ErrRateLimited = errors.New("too many login attempts")

// SecondStepRequired reports that the first step of a sign-in succeeded, and the
// account must take a second.  Pending is what that step presents, and Step which
// it is: "code", "mail" or "enrol".
type SecondStepRequired struct {
	Pending string
	Step    string
}

func (e *SecondStepRequired) Error() string {
	return "this account also needs a second step"
}

// SecondStep decides whether an account that passed the first step, by method,
// must take a second, and answers the token for that step and which it is, or "".
// facts are what the first step learned, for the session the step will make.
type SecondStep func(ctx context.Context, email, method string, facts claims.Facts) (pending, step string, err error)

// ErrUseSecurityKey reports that second_factor is required and the account has a
// security key, its only second factor: the key signs in by itself.
var ErrUseSecurityKey = errors.New("this account signs in with its security key")

// ErrNoSecondFactor reports that second_factor is required and the account has no
// second factor, nor any it may add.
var ErrNoSecondFactor = errors.New("this account has no second factor it can use")

// ErrSourceRateLimited reports that the client has failed too often, whichever
// addresses it tried.
var ErrSourceRateLimited = errors.New("too many failed logins from this client")

// PasswordAuth handles password authentication
type PasswordAuth struct {
	accounts     *AccountPolicy
	hasher       *password.Hasher
	cookieMgr    *cookie.CookieManager
	sessionStore *session.Store
	logger       *logging.Logger
	rateLimiter  *RateLimiter // per address; nil when switched off
	sourceLimit  *RateLimiter // per client address; nil when switched off
	maxAge       int
	claimsHook   *claims.ClaimsHook
	secondStep   SecondStep
	lockout      *Lockout      // consecutive failures per account; nil when off
	radius       *RadiusSource // addresses users.csv lacks; nil when off

	// dummyHash is verified when there is no real hash to check, so a login
	// costs the same whether or not the address exists.
	dummyHash string
}

// NewPasswordAuth creates a new PasswordAuth handler
func NewPasswordAuth(
	accounts *AccountPolicy,
	hasher *password.Hasher,
	cookieMgr *cookie.CookieManager,
	sessionStore *session.Store,
	logger *logging.Logger,
	rateLimit, rateWindowSec int,
	claimsHook ...*claims.ClaimsHook,
) *PasswordAuth {
	pa := &PasswordAuth{
		accounts:     accounts,
		hasher:       hasher,
		cookieMgr:    cookieMgr,
		sessionStore: sessionStore,
		logger:       logger,
		rateLimiter:  NewRateLimiter(rateLimit, rateWindowSec),
		maxAge:       cookieMgr.MaxAge,
	}

	if pa.maxAge <= 0 {
		pa.maxAge = 86400
	}

	if token, err := cookie.GenerateRandomToken(); err == nil {
		if hash, err := hasher.Hash(token); err == nil {
			pa.dummyHash = hash
		}
	}
	if pa.dummyHash == "" {
		logger.Warn("could not prepare a dummy password hash: login timing may reveal which addresses exist")
	}

	// Optional claims hook (variadic parameter)
	if len(claimsHook) > 0 && claimsHook[0] != nil {
		pa.claimsHook = claimsHook[0]
	}

	return pa
}

// SetSecondStep says how to find out whether an account also needs a code.
func (pa *PasswordAuth) SetSecondStep(step SecondStep) {
	pa.secondStep = step
}

// SetLockout caps consecutive failures per account.
func (pa *PasswordAuth) SetLockout(l *Lockout) {
	pa.lockout = l
}

// lockedOut reports whether the account refuses guesses now.  A failure to check
// refuses too: the cap must not fall open.
func (pa *PasswordAuth) lockedOut(ctx context.Context, email string) bool {
	until, locked, err := pa.lockout.Locked(ctx, email)
	if err != nil {
		pa.logger.Error(fmt.Sprintf("checking the lockout of %s: %v", email, err))
		return true
	}
	if locked {
		pa.logger.Warn(fmt.Sprintf("rate limited: %s is locked until %s after too many failed sign-ins", email, until.UTC().Format(time.RFC3339)))
	}
	return locked
}

// countFailure adds a wrong password on an account that exists to its count.
func (pa *PasswordAuth) countFailure(ctx context.Context, email string) {
	if err := pa.lockout.Fail(ctx, email); err != nil {
		pa.logger.Error(fmt.Sprintf("counting a failed sign-in of %s: %v", email, err))
	}
}

// DisableAddressLimit stops counting failures per address.
func (pa *PasswordAuth) DisableAddressLimit() {
	pa.rateLimiter = nil
}

// SetSourceLimit counts failures per client address as well.  They are not
// cleared by a success, or signing in to one's own account would reset the count.
func (pa *PasswordAuth) SetSourceLimit(limit, windowSec int) {
	pa.sourceLimit = NewRateLimiter(limit, windowSec)
}

// ClearAddressLimit forgets an address's failures, when its owner has just shown
// they hold the mailbox.  Without it the new password would be refused for a while.
func (pa *PasswordAuth) ClearAddressLimit(email string) {
	if pa.rateLimiter != nil {
		pa.rateLimiter.Reset(email)
	}
}

// CheckPassword tests a password without signing anyone in, under the same limits
// as a login, so a stolen session cannot be used to guess one.  It clears nothing.
func (pa *PasswordAuth) CheckPassword(email, source, passwordStr string) error {
	ctx := context.Background()
	done, err := pa.admit(ctx, email, source)
	if err != nil {
		return err
	}
	user, err := pa.accounts.Check(email)
	if err != nil {
		done(false)
		return err
	}
	if err := pa.hasher.Verify(passwordStr, user.PasswordHash); err != nil {
		pa.warnMalformed(email, err)
		pa.countFailure(ctx, email)
		done(false)
		return errors.New("invalid password")
	}
	done(true)
	return nil
}

// warnMalformed tells the administrator when an account's stored hash cannot
// be checked, since its owner can never sign in with a password until it is
// replaced.  The hash itself is not logged.
func (pa *PasswordAuth) warnMalformed(email string, err error) {
	if errors.Is(err, password.ErrMalformedHash) && pa.logger != nil {
		pa.logger.Warn(fmt.Sprintf("the password hash of %s in the accounts file cannot be checked: %v", email, err))
	}
}

// admit lets an attempt for email from source go ahead, or refuses it.  The
// attempt is counted against every limit before the password is checked, so
// attempts sent together cannot all pass, and checks of one account run one at a
// time, so the lockout sees each failure before the next check.  done ends the
// attempt; a success gives back what it was counted, since only failures count.
func (pa *PasswordAuth) admit(ctx context.Context, email, source string) (done func(success bool), err error) {
	if pa.sourceLimit != nil && !pa.sourceLimit.Take(source) {
		return nil, ErrSourceRateLimited
	}
	refund := func() {
		if pa.sourceLimit != nil {
			pa.sourceLimit.Refund(source)
		}
	}
	if pa.rateLimiter != nil && !pa.rateLimiter.Take(email) {
		refund()
		return nil, ErrRateLimited
	}
	refund = func() {
		if pa.sourceLimit != nil {
			pa.sourceLimit.Refund(source)
		}
		if pa.rateLimiter != nil {
			pa.rateLimiter.Refund(email)
		}
	}
	release := pa.lockout.Guard(email)
	if pa.lockedOut(ctx, email) {
		release()
		refund()
		return nil, ErrRateLimited
	}
	return func(success bool) {
		release()
		if success {
			refund()
		}
	}, nil
}

// Authenticate validates a password from the client at source and creates a
// session.
func (pa *PasswordAuth) Authenticate(ctx context.Context, email, source, passwordStr string) (*http.Cookie, error) {
	done, err := pa.admit(ctx, email, source)
	if err != nil {
		return nil, err
	}

	// Look up user.  An address users.csv lacks goes to RADIUS when it is on;
	// one it has, in any state, never does.
	user, err := pa.accounts.Check(email)
	if errors.Is(err, csv.ErrUserNotFound) && pa.radius != nil {
		return pa.radiusSignIn(ctx, done, radius.Request{UserName: email, Password: passwordStr, CallingStationID: source})
	}
	if err != nil {
		// Unknown, locked and unapproved accounts all pay for a hash and
		// count as a failure, so neither the reply nor its timing tells
		// them apart from a wrong password.
		pa.burnHash(passwordStr)
		done(false)
		if errors.Is(err, csv.ErrUserNotFound) {
			return nil, errors.New("invalid email or password")
		}
		return nil, fmt.Errorf("authenticate user: %w", err)
	}

	// Verify password.  An account without a password (hash "!") has nothing
	// a hasher can work on, so it is treated like an unknown address.
	if user.PasswordHash == noPasswordHash {
		pa.burnHash(passwordStr)
		pa.countFailure(ctx, email)
		done(false)
		return nil, errors.New("invalid email or password")
	}
	if err := pa.hasher.Verify(passwordStr, user.PasswordHash); err != nil {
		pa.warnMalformed(email, err)
		pa.countFailure(ctx, email)
		done(false)
		return nil, errors.New("invalid email or password")
	}
	done(true)
	if pa.rateLimiter != nil {
		pa.rateLimiter.Reset(email)
	}

	if pa.secondStep != nil {
		pending, step, err := pa.secondStep(ctx, email, "password", claims.LocalFacts)
		if err != nil {
			return nil, err
		}
		if pending != "" {
			return nil, &SecondStepRequired{Pending: pending, Step: step}
		}
	}
	return pa.CreateSession(ctx, email, "password")
}

// CreateSession signs a users.csv account in, once every step is done.  method is
// what the session records as how.
func (pa *PasswordAuth) CreateSession(ctx context.Context, email, method string) (*http.Cookie, error) {
	return pa.CreateSessionFacts(ctx, email, method, claims.LocalFacts)
}

// CreateSessionFacts signs an account in with what its sign-in learned, which
// the claims are made from and the session keeps.
func (pa *PasswordAuth) CreateSessionFacts(ctx context.Context, email, method string, facts claims.Facts) (*http.Cookie, error) {
	// Generate session token
	token, err := cookie.GenerateRandomToken()
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	// The hook's claims, or the facts' own without one.
	claimsData, err := pa.claimsHook.ClaimsFor(ctx, email, facts)
	if err != nil {
		// ClaimsFor only errors under on_failure: fail-closed.
		return nil, fmt.Errorf("%w: %v", ErrClaimsRefused, err)
	}
	if claimsData == nil {
		claimsData = map[string]interface{}{}
	}

	// Serialize claims to JSON
	claimsJSON, err := json.Marshal(claimsData)
	if err != nil {
		pa.logger.Warn(fmt.Sprintf("failed to marshal claims: %v", err))
		claimsJSON = []byte("{}")
	}

	// Create session
	now := time.Now()
	sess := &session.Session{
		Token:      token,
		UserEmail:  email,
		AuthMethod: method,
		Claims:     string(claimsJSON),
		Facts:      facts.String(),
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Duration(pa.maxAge) * time.Second),
	}

	if err := pa.sessionStore.Create(ctx, sess); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	pa.logger.Info(fmt.Sprintf("User %s logged in via %s", email, method))
	if _, err := pa.lockout.Clear(ctx, email); err != nil {
		pa.logger.Error(fmt.Sprintf("clearing the failed sign-ins of %s: %v", email, err))
	}

	// Create auth cookie
	authCookie := pa.cookieMgr.CreateAuthCookie(token)
	return authCookie, nil
}

// noPasswordHash marks an account created without a password.
const noPasswordHash = "!"

// burnHash does the work of a password check whose result does not matter.
func (pa *PasswordAuth) burnHash(passwordStr string) {
	if pa.dummyHash != "" {
		_ = pa.hasher.Verify(passwordStr, pa.dummyHash)
	}
}

// PruneRateLimiter forgets addresses with no recent failures.
func (pa *PasswordAuth) PruneRateLimiter() {
	if pa.rateLimiter != nil {
		pa.rateLimiter.Cleanup()
	}
	if pa.sourceLimit != nil {
		pa.sourceLimit.Cleanup()
	}
}

// Logout revokes the session associated with the given token
func (pa *PasswordAuth) Logout(ctx context.Context, token string) error {
	return pa.sessionStore.Revoke(ctx, token)
}
