// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/config"
	"github.com/obtusenet/signet/internal/session"
)

// signedIn gives the account a session that started age ago, and its cookie.
func signedIn(t *testing.T, s *Server, address, token string, age time.Duration) *http.Cookie {
	t.Helper()
	now := time.Now()
	if err := s.sessionStore.Create(context.Background(), &session.Session{
		Token: token, UserEmail: address, AuthMethod: "password", Claims: "{}",
		CreatedAt: now.Add(-age), ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return s.cookieMgr.CreateAuthCookie(token)
}

func accountPost(s *Server, c *http.Cookie, body string, headers ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://signet.example/account", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if c != nil {
		r.AddCookie(c)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	return w
}

func accountGet(s *Server, c *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "https://signet.example/account", nil)
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	return w
}

func passwordChange(current, replacement string) string {
	body, _ := json.Marshal(map[string]string{"action": "password", "current": current, "new": replacement})
	return string(body)
}

func TestAccountPageNeedsASession(t *testing.T) {
	s := recoveryServer(t)
	w := accountGet(s, nil)
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "/login?referrer=%2Faccount") {
		t.Errorf("%d to %q", w.Code, w.Header().Get("Location"))
	}
	if w := accountPost(s, nil, passwordChange(recoveryOldPass, recoveryNewPass)); w.Code != http.StatusUnauthorized {
		t.Errorf("POST: %d", w.Code)
	}
	if got := passwordLogin(s, recoveryOldPass); got != http.StatusFound {
		t.Errorf("the password changed: %d", got)
	}
}

func TestAccountPageShowsTheAccount(t *testing.T) {
	s := recoveryServer(t)
	w := accountGet(s, signedIn(t, s, recoveryUser, "tok", 0))
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, recoveryUser) || !strings.Contains(body, `id="password-form"`) || !strings.Contains(body, `id="current"`) {
		t.Errorf("%d: %s", w.Code, body)
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Error("the page may be cached")
	}
}

func TestChangingThePassword(t *testing.T) {
	s := recoveryServer(t)
	mine := signedIn(t, s, recoveryUser, "mine", 0)
	signedIn(t, s, recoveryUser, "other", 0)
	signedIn(t, s, "else@example.com", "theirs", 0)

	w := accountPost(s, mine, passwordChange(recoveryOldPass, recoveryNewPass))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if got := passwordLogin(s, recoveryOldPass); got != http.StatusUnauthorized {
		t.Errorf("old password: %d", got)
	}
	if got := passwordLogin(s, recoveryNewPass); got != http.StatusFound {
		t.Errorf("new password: %d", got)
	}

	ctx := context.Background()
	if _, err := s.sessionStore.Get(ctx, "mine"); err != nil {
		t.Errorf("this session ended: %v", err)
	}
	if _, err := s.sessionStore.Get(ctx, "other"); err == nil {
		t.Error("the account's other session survived")
	}
	if _, err := s.sessionStore.Get(ctx, "theirs"); err != nil {
		t.Errorf("another account's session ended: %v", err)
	}

	mail := sentMail(t, s)
	if len(mail) != 1 || mail[0].To != recoveryUser || !strings.Contains(mail[0].Body, "password of this account was changed") {
		t.Errorf("notice: %+v", mail)
	}
}

func TestChangingThePasswordRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		body   string
		status int
	}{
		"wrong current": {passwordChange("not-the-password", recoveryNewPass), http.StatusBadRequest},
		"no current":    {passwordChange("", recoveryNewPass), http.StatusBadRequest},
		"short new":     {passwordChange(recoveryOldPass, "short"), http.StatusBadRequest},
		"bad action":    {`{"action":"nonsense"}`, http.StatusBadRequest},
		"not JSON":      {`not json`, http.StatusBadRequest},
	} {
		s := recoveryServer(t)
		c := signedIn(t, s, recoveryUser, "tok", 0)
		signedIn(t, s, recoveryUser, "other", 0)
		if w := accountPost(s, c, tc.body); w.Code != tc.status {
			t.Errorf("%s: %d: %s", name, w.Code, w.Body)
		}
		if got := passwordLogin(s, recoveryOldPass); got != http.StatusFound {
			t.Errorf("%s: the password changed: %d", name, got)
		}
		if _, err := s.sessionStore.Get(context.Background(), "other"); err != nil {
			t.Errorf("%s: another session ended", name)
		}
		if got := len(sentMail(t, s)); got != 0 {
			t.Errorf("%s: %d messages", name, got)
		}
	}
}

// An old session at an unattended browser must not change anything.
func TestAStaleSignInChangesNothing(t *testing.T) {
	s := recoveryServer(t, func(c *config.Config) { c.AccountReauthWindow = 60 })
	stale := signedIn(t, s, recoveryUser, "stale", 2*time.Minute)
	w := accountPost(s, stale, passwordChange(recoveryOldPass, recoveryNewPass))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Sign in again") {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if got := passwordLogin(s, recoveryOldPass); got != http.StatusFound {
		t.Errorf("the password changed: %d", got)
	}

	page := accountGet(s, stale).Body.String()
	if strings.Contains(page, `id="password-form"`) {
		t.Error("the stale page offers the form")
	}
	if !strings.Contains(page, "/login?referrer=%2Faccount") {
		t.Error("the stale page offers no way back")
	}

	recent := signedIn(t, s, recoveryUser, "recent", 30*time.Second)
	if w := accountPost(s, recent, passwordChange(recoveryOldPass, recoveryNewPass)); w.Code != http.StatusOK {
		t.Errorf("a recent sign-in: %d: %s", w.Code, w.Body)
	}
}

// With a stolen session, guessing the current password must hit the login limits.
func TestGuessingTheCurrentPasswordIsLimited(t *testing.T) {
	s := recoveryServer(t, func(c *config.Config) { c.LoginRateLimit = 2 })
	c := signedIn(t, s, recoveryUser, "tok", 0)
	for i := 0; i < 2; i++ {
		accountPost(s, c, passwordChange("wrong-guess", recoveryNewPass))
	}
	if w := accountPost(s, c, passwordChange(recoveryOldPass, recoveryNewPass)); w.Code != http.StatusBadRequest {
		t.Errorf("the right password after the limit: %d", w.Code)
	}
	user, err := s.backend.GetUser(recoveryUser)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.hasher.Verify(recoveryOldPass, user.PasswordHash); err != nil {
		t.Error("the password changed")
	}
}

func TestAnAccountWithNoPasswordCanSetOne(t *testing.T) {
	s := recoveryServer(t)
	const addr = "nopass@example.com"
	if err := s.backend.CreateUser(addr, noPassword, "bcrypt", []string{csv.FlagApproved}); err != nil {
		t.Fatal(err)
	}
	c := signedIn(t, s, addr, "tok", 0)
	page := accountGet(s, c).Body.String()
	if strings.Contains(page, `id="current"`) || !strings.Contains(page, "no password yet") {
		t.Errorf("page: %s", page)
	}
	if w := accountPost(s, c, passwordChange("", recoveryNewPass)); w.Code != http.StatusOK {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if got := loginAs(s, addr, recoveryNewPass); got != http.StatusFound {
		t.Errorf("sign-in: %d", got)
	}
}

func TestALockedAccountCannotUseItsSession(t *testing.T) {
	s := recoveryServer(t)
	c := signedIn(t, s, recoveryUser, "tok", 0)
	if err := s.backend.AddFlag(recoveryUser, csv.FlagLocked); err != nil {
		t.Fatal(err)
	}
	if w := accountGet(s, c); w.Code != http.StatusForbidden {
		t.Errorf("page: %d", w.Code)
	}
	if w := accountPost(s, c, passwordChange(recoveryOldPass, recoveryNewPass)); w.Code != http.StatusForbidden {
		t.Errorf("change: %d", w.Code)
	}
}

func TestPasswordsDisabledHidesTheSection(t *testing.T) {
	s := recoveryServer(t, func(c *config.Config) {
		c.AuthMethods = map[string]string{"password": "disabled"}
		c.PasswordRecovery = "disabled"
	})
	c := signedIn(t, s, recoveryUser, "tok", 0)
	if page := accountGet(s, c).Body.String(); strings.Contains(page, `id="password-form"`) {
		t.Error("the page offers it")
	}
	if w := accountPost(s, c, passwordChange(recoveryOldPass, recoveryNewPass)); w.Code != http.StatusForbidden {
		t.Errorf("%d", w.Code)
	}
}

func TestAnotherSiteCannotChangeTheAccount(t *testing.T) {
	s := recoveryServer(t)
	c := signedIn(t, s, recoveryUser, "tok", 0)
	if w := accountPost(s, c, passwordChange(recoveryOldPass, recoveryNewPass), "Origin", "https://evil.example"); w.Code != http.StatusForbidden {
		t.Errorf("%d", w.Code)
	}
	if got := passwordLogin(s, recoveryOldPass); got != http.StatusFound {
		t.Errorf("the password changed: %d", got)
	}
}

func TestLandingPageLinksToTheAccount(t *testing.T) {
	s := recoveryServer(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(signedIn(t, s, recoveryUser, "tok", 0))
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), `href="/account"`) {
		t.Errorf("%s", w.Body)
	}
}

// Keys follow the same rule as the rest of the account.
func TestKeysNeedARecentSignIn(t *testing.T) {
	s := keysServer(t, 60)
	stale := signedIn(t, s, recoveryUser, "stale", 2*time.Minute)
	recent := signedIn(t, s, recoveryUser, "recent", 0)
	call := func(c *http.Cookie, method, path string) int {
		r := httptest.NewRequest(method, "https://signet.example"+path, nil)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		return w.Code
	}
	if got := call(stale, http.MethodPost, "/webauthn/register/start"); got != http.StatusForbidden {
		t.Errorf("stale add: %d", got)
	}
	if got := call(stale, http.MethodPost, "/webauthn/register/finish?ceremony=x"); got != http.StatusForbidden {
		t.Errorf("stale finish: %d", got)
	}
	if got := call(stale, http.MethodDelete, "/webauthn/credentials/x"); got != http.StatusForbidden {
		t.Errorf("stale remove: %d", got)
	}
	if got := call(stale, http.MethodGet, "/webauthn/credentials"); got != http.StatusOK {
		t.Errorf("stale list: %d", got)
	}
	if got := call(recent, http.MethodPost, "/webauthn/register/start"); got != http.StatusOK {
		t.Errorf("recent add: %d", got)
	}
	if got := call(recent, http.MethodDelete, "/webauthn/credentials/x"); got != http.StatusNotFound {
		t.Errorf("recent remove: %d", got)
	}
}

func keysServer(t *testing.T, window int) *Server {
	t.Helper()
	return recoveryServer(t, func(c *config.Config) {
		c.AuthMethods = map[string]string{"password": "enabled", "webauthn": "enabled"}
		c.RPID = "signet.example"
		c.WebAuthnOrigins = []string{"https://signet.example"}
		c.AccountReauthWindow = window
	})
}

func TestAccountPageShowsKeysOnlyWhenOn(t *testing.T) {
	with := keysServer(t, 600)
	if page := accountGet(with, signedIn(t, with, recoveryUser, "a", 0)).Body.String(); !strings.Contains(page, `id="keys-section"`) || !strings.Contains(page, "webauthn.js") {
		t.Errorf("with keys: %s", page)
	}
	without := recoveryServer(t)
	if page := accountGet(without, signedIn(t, without, recoveryUser, "b", 0)).Body.String(); strings.Contains(page, `id="keys-section"`) {
		t.Error("without keys: the section is there")
	}
}
