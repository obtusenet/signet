// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/obtusenet/signet/internal/auth"
	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/otp"
)

// maxChallengeRounds is how many challenges one sign-in answers.
const maxChallengeRounds = 3

const radiusUnavailableMessage = "Sign-in is unavailable. Try again later."

const challengeExpiredMessage = "This sign-in has expired. Start again."

// startRadius turns on the RADIUS client when the settings say so.  A server
// that cannot be set up (an unreadable secret_file) leaves RADIUS sign-ins
// failing closed, and says why each time.
func (s *Server) startRadius() {
	if !s.cfg.Radius.Enabled {
		return
	}
	maxSession, maxIdle := s.cfg.RadiusCeilings()
	src, err := auth.NewRadiusSource(s.cfg.Radius, maxSession, maxIdle)
	if err != nil {
		s.logger.Error(fmt.Sprintf("RADIUS cannot be used: %v", err))
		src = auth.BrokenRadiusSource(err)
	} else {
		s.logger.Info(fmt.Sprintf("RADIUS on for addresses users.csv lacks: %d servers, NAS-Identifier %q",
			len(s.cfg.Radius.Servers), s.cfg.Radius.NASIdentifier))
	}
	s.passwordAuth.SetRadius(src)
}

// isLocal reports whether users.csv has the account, in any state.
func (s *Server) isLocal(address string) bool {
	_, err := s.backend.GetUser(address)
	return !errors.Is(err, csv.ErrUserNotFound)
}

// isRadiusAccount reports whether an account signs in through RADIUS: RADIUS is
// on, and users.csv does not have it.
func (s *Server) isRadiusAccount(address string) bool {
	return s.passwordAuth.RadiusEnabled() && !s.isLocal(address)
}

// stepAccountAllowed checks, at a second step, that the account may still sign
// in: users.csv's policy for its accounts, and for a RADIUS one that RADIUS is
// still on and users.csv has not since gained the address.
func (s *Server) stepAccountAllowed(address, method string) error {
	if method == auth.MethodRadius {
		if !s.isRadiusAccount(address) {
			return errors.New("no longer a RADIUS account")
		}
		return nil
	}
	_, err := s.accounts.Check(address)
	return err
}

// validRadiusName accepts what a RADIUS User-Name may be: 1 to 253 bytes of
// text, without control characters or spaces at either end.
func validRadiusName(name string) bool {
	return len(name) > 0 && len(name) <= 253 && utf8.ValidString(name) &&
		!strings.ContainsFunc(name, unicode.IsControl) && strings.TrimSpace(name) == name
}

// isAddress reports whether an account name is a mail address, which only then
// is given as one (Remote-Email, "email").
func isAddress(name string) bool {
	return csv.ValidateEmail(name) == nil
}

// radiusStep is what a challenge step keeps: what to send back, and where.
type radiusStep struct {
	State   []byte `json:"state"`
	Server  int    `json:"server"`
	Round   int    `json:"round"`
	Message string `json:"message"`
}

// askRadiusChallenge keeps a challenge as a step and asks for its answer.
func (s *Server) askRadiusChallenge(w http.ResponseWriter, r *http.Request, ch *auth.RadiusChallenge, round int) {
	if round > maxChallengeRounds {
		s.logger.Warn(fmt.Sprintf("RADIUS sign-in of %s stopped: more than %d challenges", ch.UserName, maxChallengeRounds))
		s.loginReply(w, r, http.StatusUnauthorized,
			map[string]interface{}{"success": false, "error": "Invalid email or password"},
			"Invalid email or password")
		return
	}
	data, _ := json.Marshal(radiusStep{State: ch.State, Server: ch.Server, Round: round, Message: ch.Message})
	token, err := s.steps.CreateStepData(r.Context(), ch.UserName, auth.MethodRadius, otp.StepRadius, otp.PendingTTL, string(data))
	if err != nil {
		s.logger.Error(fmt.Sprintf("keeping a RADIUS challenge for %s: %v", ch.UserName, err))
		s.loginReply(w, r, http.StatusInternalServerError,
			map[string]interface{}{"success": false, "error": "The sign-in could not be finished. Try again."},
			"The sign-in could not be finished. Try again.")
		return
	}
	s.logger.Info(fmt.Sprintf("RADIUS challenge %d for %s from %s", round, ch.UserName, s.clients.Addr(r)))
	if wantsJSON(r) {
		accountReply(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"step":    otp.StepRadius,
			"pending": token,
			"message": ch.Message,
		})
		return
	}
	s.renderLoginStep(w, r, loginStep{Pending: token, Step: otp.StepRadius, Message: ch.Message}, http.StatusOK)
}

// finishRadiusStep sends the answer to a challenge.  The server may accept,
// reject, or ask again.
func (s *Server) finishRadiusStep(w http.ResponseWriter, r *http.Request, pending, user, data string) {
	var st radiusStep
	if err := json.Unmarshal([]byte(data), &st); err != nil || st.State == nil {
		s.logger.Error(fmt.Sprintf("RADIUS challenge step of %s is unreadable", user))
		s.renderLoginPage(w, r, "", challengeExpiredMessage, http.StatusUnauthorized)
		return
	}
	// One answer per challenge: the step is spent before the server is asked.
	if err := s.steps.TakePending(r.Context(), pending); err != nil {
		s.renderLoginPage(w, r, "", challengeExpiredMessage, http.StatusUnauthorized)
		return
	}
	answer := r.PostFormValue("code")
	authCookie, err := s.passwordAuth.AnswerRadiusChallenge(r.Context(), user, s.clients.Addr(r), answer, st.State, st.Server)
	s.finishPasswordSignIn(w, r, user, authCookie, err, st.Round+1)
}

// finishPasswordSignIn answers what a password, or a challenge's answer, came
// to.  round is the number the next challenge would have.
func (s *Server) finishPasswordSignIn(w http.ResponseWriter, r *http.Request, email string, authCookie *http.Cookie, err error, round int) {
	var second *auth.SecondStepRequired
	if errors.As(err, &second) {
		s.askForStep(w, r, second.Pending, second.Step)
		return
	}
	var challenge *auth.RadiusChallenge
	if errors.As(err, &challenge) {
		s.askRadiusChallenge(w, r, challenge, round)
		return
	}
	if errors.Is(err, auth.ErrRadiusUnavailable) {
		s.logger.Error(fmt.Sprintf("sign-in of %s from %s: %v", email, s.clients.Addr(r), err))
		s.loginReply(w, r, http.StatusServiceUnavailable,
			map[string]interface{}{"success": false, "error": radiusUnavailableMessage},
			radiusUnavailableMessage)
		return
	}
	if errors.Is(err, auth.ErrUseSecurityKey) || errors.Is(err, auth.ErrNoSecondFactor) {
		// The password was right, so saying what comes next reveals nothing.
		s.logger.Warn(fmt.Sprintf("password sign-in of %s stopped: %v", email, err))
		message := auth.SecondFactorMessage(err)
		s.loginReply(w, r, http.StatusForbidden,
			map[string]interface{}{"success": false, "error": message}, message)
		return
	}
	if err != nil {
		if errors.Is(err, auth.ErrClaimsRefused) {
			// The password was right, so this reveals nothing new, and
			// telling the user to retype it would only mislead.
			s.logger.Warn(fmt.Sprintf("Login refused for %s: %v", email, err))
			s.loginReply(w, r, http.StatusForbidden,
				map[string]interface{}{"success": false, "error": "Sign-in refused"},
				"Sign-in refused")
			return
		}
		if errors.Is(err, auth.ErrRateLimited) {
			s.logger.Warn(fmt.Sprintf("rate limited: login attempts for %s from %s", email, s.clients.Addr(r)))
		} else if errors.Is(err, auth.ErrSourceRateLimited) {
			s.logger.Warn(fmt.Sprintf("rate limited: failed logins from %s, now trying %s", s.clients.Addr(r), email))
		} else {
			s.logger.Warn(fmt.Sprintf("Login failed for %s: %v", email, err))
		}
		s.loginReply(w, r, http.StatusUnauthorized,
			map[string]interface{}{"success": false, "error": "Invalid email or password"},
			"Invalid email or password")
		return
	}

	http.SetCookie(w, authCookie)
	target := s.loginRedirect(r)
	if wantsJSON(r) {
		s.loginReply(w, r, http.StatusOK,
			map[string]interface{}{"success": true, "redirect": target}, "")
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}
