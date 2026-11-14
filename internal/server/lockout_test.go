// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/obtusenet/signet/internal/config"
)

// lockoutServer locks after three failures in a row; the per-address throttle
// allows more, so only the lockout can be what refuses.
func lockoutServer(t *testing.T) *Server {
	t.Helper()
	return totpServer(t, func(c *config.Config) {
		c.LockoutThreshold = 3
		c.LockoutDuration = 30
		c.LoginRateLimit = 50
	})
}

func failures(t *testing.T, s *Server) int {
	t.Helper()
	n, err := s.lockout.Failures(context.Background(), recoveryUser)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLockoutRefusesTheRightPassword(t *testing.T) {
	s := lockoutServer(t)
	for i := 0; i < 3; i++ {
		if got := passwordLogin(s, "wrong-password-"+string(rune('a'+i))); got != http.StatusUnauthorized {
			t.Fatalf("wrong password: %d", got)
		}
	}
	// Answered like a wrong password, which tells nobody the account exists.
	if got := passwordLogin(s, recoveryOldPass); got != http.StatusUnauthorized {
		t.Errorf("the right password during a lock: %d", got)
	}
	if failures(t, s) != 3 {
		t.Errorf("%d failures: a refused attempt was counted", failures(t, s))
	}
	if !mailSays(t, s, "After 3 failed sign-ins in a row") {
		t.Error("the owner was not told of the lock")
	}

	// Recovery by mail ends it.
	if w := recoverPost(s, url.Values{"token": {requestToken(t, s)}, "password": {recoveryNewPass}}); w.Code != http.StatusOK {
		t.Fatalf("recovery: %d", w.Code)
	}
	if got := passwordLogin(s, recoveryNewPass); got != http.StatusFound {
		t.Errorf("after recovery: %d", got)
	}
}

func TestLockoutClearsOnSignIn(t *testing.T) {
	s := lockoutServer(t)
	passwordLogin(s, "wrong-password-1")
	passwordLogin(s, "wrong-password-2")
	if got := passwordLogin(s, recoveryOldPass); got != http.StatusFound {
		t.Fatalf("right password: %d", got)
	}
	if failures(t, s) != 0 {
		t.Errorf("%d failures after a sign-in", failures(t, s))
	}
	// An address with no account is not counted, so nothing grows for strangers.
	form := url.Values{"email": {"nobody@example.com"}, "password": {"whatever-it-is"}}
	r := httptest.NewRequest(http.MethodPost, "https://signet.example/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handler().ServeHTTP(httptest.NewRecorder(), r)
	if n, _ := s.lockout.Failures(context.Background(), "nobody@example.com"); n != 0 {
		t.Errorf("an unknown address has %d failures", n)
	}
}

// A right password that still needs its code clears nothing, or knowing the
// password would buy unlimited guesses at the code.
func TestLockoutCountsCodesAcrossTheSteps(t *testing.T) {
	s := lockoutServer(t)
	secret, _ := enrollTOTP(t, s, signedIn(t, s, recoveryUser, "tok", 0), "phone")
	passwordLogin(s, "wrong-password-1")
	if w := secondStep(s, firstStep(t, s), "000000"); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", w.Code)
	}
	if failures(t, s) != 2 {
		t.Fatalf("%d failures, want 2: the password step cleared them", failures(t, s))
	}
	pending := firstStep(t, s)
	if w := secondStep(s, pending, "111111"); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", w.Code)
	}
	// Locked now: the right code is refused too.
	if w := secondStep(s, pending, nextCode(t, secret)); w.Code != http.StatusUnauthorized {
		t.Errorf("the right code during a lock: %d", w.Code)
	}
}

func TestLockoutCountsPINs(t *testing.T) {
	s := lockoutServer(t)
	verify := func(pin string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"email": recoveryUser, "pin": pin})
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/email-pin/verify", strings.NewReader(string(body))))
		return w
	}
	passwordLogin(s, "wrong-password-1")
	passwordLogin(s, "wrong-password-2")
	if w := verify("000000"); w.Code != http.StatusBadRequest {
		t.Fatalf("wrong PIN: %d", w.Code)
	}
	if failures(t, s) != 3 {
		t.Fatalf("%d failures: a wrong PIN did not count", failures(t, s))
	}
	// Locked: no PIN is sent.
	before := len(sentMail(t, s))
	s.handler().ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/email-pin/send", strings.NewReader(`{"email":"`+recoveryUser+`"}`)))
	for _, m := range sentMail(t, s)[before:] {
		if strings.Contains(m.Subject, "PIN") && regexp.MustCompile(`\b\d{6}\b`).MatchString(m.Body) {
			t.Error("a PIN was sent to a locked account")
		}
	}
}

func TestLockoutSwitchedOff(t *testing.T) {
	s := totpServer(t, func(c *config.Config) { c.LockoutThreshold = 0; c.LoginRateLimit = 50 })
	for i := 0; i < 5; i++ {
		passwordLogin(s, "wrong-password")
	}
	if got := passwordLogin(s, recoveryOldPass); got != http.StatusFound {
		t.Errorf("with the lockout off: %d", got)
	}
}

// A PIN mailed before the lock does not sign in during it.
func TestLockoutRefusesAGoodPIN(t *testing.T) {
	s := lockoutServer(t)
	s.handler().ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/email-pin/send", strings.NewReader(`{"email":"`+recoveryUser+`"}`)))
	var pin string
	for _, m := range sentMail(t, s) {
		if found := regexp.MustCompile(`\b\d{6}\b`).FindString(m.Body); found != "" && strings.Contains(m.Subject, "PIN") {
			pin = found
		}
	}
	if pin == "" {
		t.Fatal("no PIN")
	}
	for i := 0; i < 3; i++ {
		passwordLogin(s, "wrong-password")
	}
	body, _ := json.Marshal(map[string]string{"email": recoveryUser, "pin": pin})
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/email-pin/verify", strings.NewReader(string(body))))
	if w.Code != http.StatusBadRequest || strings.Contains(w.Header().Get("Set-Cookie"), s.cfg.CookieName+"=") {
		t.Errorf("a good PIN during a lock: %d", w.Code)
	}
}

// The current password asked for on the account page counts, and is refused
// during a lock, so a stolen session cannot be used to guess past the cap.
func TestLockoutCoversTheAccountPage(t *testing.T) {
	s := lockoutServer(t)
	c := signedIn(t, s, recoveryUser, "tok", 0)
	for i := 0; i < 3; i++ {
		if w := accountPost(s, c, passwordChange("wrong-current-password", recoveryNewPass)); w.Code != http.StatusBadRequest {
			t.Fatalf("wrong current password: %d", w.Code)
		}
	}
	if failures(t, s) != 3 {
		t.Fatalf("%d failures: the account page's check did not count", failures(t, s))
	}
	if w := accountPost(s, c, passwordChange(recoveryOldPass, recoveryNewPass)); w.Code != http.StatusBadRequest {
		t.Errorf("the right current password during a lock: %d", w.Code)
	}
	if got := passwordLogin(s, recoveryNewPass); got == http.StatusFound {
		t.Error("the password was changed during a lock")
	}
}
