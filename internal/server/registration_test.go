// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/config"
	"github.com/obtusenet/signet/internal/maillink"
)

const newUser = "new@example.com"

// registrationServer verifies addresses, with the account of recoveryServer.
func registrationServer(t *testing.T, change ...func(*config.Config)) *Server {
	t.Helper()
	return recoveryServer(t, append([]func(*config.Config){func(c *config.Config) {
		c.SelfRegistration = "enabled"
		c.EmailVerification = "required"
		c.ApprovalRequired = "auto_approve"
	}}, change...)...)
}

func registerPost(s *Server, form url.Values, headers ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://signet.example/register", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	return w
}

var registerLink = regexp.MustCompile(`(\S*)/register#token=([A-Za-z0-9_-]+)`)

func registrationToken(t *testing.T, s *Server, address string) string {
	t.Helper()
	before := len(sentMail(t, s))
	if w := registerPost(s, url.Values{"email": {address}}); w.Code != http.StatusOK {
		t.Fatalf("request: %d: %s", w.Code, w.Body)
	}
	mail := sentMail(t, s)
	if len(mail) != before+1 {
		t.Fatalf("%d messages, want %d", len(mail), before+1)
	}
	match := registerLink.FindStringSubmatch(mail[len(mail)-1].Body)
	if match == nil {
		t.Fatalf("no link in: %s", mail[len(mail)-1].Body)
	}
	return match[2]
}

func loginAs(s *Server, address, password string) int {
	form := url.Values{"email": {address}, "password": {password}}
	r := httptest.NewRequest(http.MethodPost, "https://signet.example/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	return w.Code
}

func TestRegistrationCreatesTheAccountOnlyFromTheLink(t *testing.T) {
	s := registrationServer(t)
	token := registrationToken(t, s, newUser)
	if _, err := s.backend.GetUser(newUser); err == nil {
		t.Fatal("the account exists before the link was used")
	}

	w := registerPost(s, url.Values{"token": {token}, "password": {recoveryNewPass}})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "has been created") {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	user, err := s.backend.GetUser(newUser)
	if err != nil {
		t.Fatal(err)
	}
	if !user.HasFlag(csv.FlagSelfRegistered) || !user.HasFlag(csv.FlagApproved) {
		t.Errorf("flags: %v", user.Flags)
	}
	if got := loginAs(s, newUser, recoveryNewPass); got != http.StatusFound {
		t.Errorf("sign-in: %d", got)
	}
	if w := registerPost(s, url.Values{"token": {token}, "password": {"another-long-password"}}); w.Code != http.StatusBadRequest {
		t.Errorf("second use: %d", w.Code)
	}
	if got := loginAs(s, newUser, recoveryNewPass); got != http.StatusFound {
		t.Errorf("after the refused second use: %d", got)
	}
}

// An attacker registers someone's address, with their own password, and waits for
// its owner to confirm.  The password in that first request must count for nothing.
func TestRegistrationCannotBePreparedForSomeoneElse(t *testing.T) {
	s := registrationServer(t)
	const attacker = "attackers-password"
	if w := registerPost(s, url.Values{"email": {newUser}, "password": {attacker}}); w.Code != http.StatusOK {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	mail := sentMail(t, s)
	token := registerLink.FindStringSubmatch(mail[0].Body)[2]
	if _, err := s.backend.GetUser(newUser); err == nil {
		t.Fatal("that request created an account")
	}
	if got := loginAs(s, newUser, attacker); got == http.StatusFound {
		t.Fatal("the attacker signed in")
	}

	// The owner finishes it, choosing their own password.
	if w := registerPost(s, url.Values{"token": {token}, "password": {recoveryNewPass}}); w.Code != http.StatusOK {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if got := loginAs(s, newUser, attacker); got == http.StatusFound {
		t.Error("the attacker's password works on the finished account")
	}
	if got := loginAs(s, newUser, recoveryNewPass); got != http.StatusFound {
		t.Errorf("the owner's password: %d", got)
	}
}

func TestRegistrationRepliesAlikeWhetherAnAccountExists(t *testing.T) {
	s := registrationServer(t)
	free := registerPost(s, url.Values{"email": {newUser}})
	taken := registerPost(s, url.Values{"email": {recoveryUser}})
	invalid := registerPost(s, url.Values{"email": {"not an address"}})
	strip := func(w *httptest.ResponseRecorder, address string) string {
		return strings.ReplaceAll(w.Body.String(), html.EscapeString(address), "")
	}
	want := strip(free, newUser)
	if taken.Code != free.Code || strip(taken, recoveryUser) != want {
		t.Errorf("an address with an account differs: %d", taken.Code)
	}
	if invalid.Code != free.Code || strip(invalid, "not an address") != want {
		t.Errorf("an invalid address differs: %d", invalid.Code)
	}

	mail := sentMail(t, s)
	if len(mail) != 2 {
		t.Fatalf("%d messages", len(mail))
	}
	for _, m := range mail {
		switch m.To {
		case newUser:
			if !registerLink.MatchString(m.Body) {
				t.Errorf("no link: %s", m.Body)
			}
		case recoveryUser:
			if !strings.Contains(m.Body, "already has one") || !strings.Contains(m.Body, "https://signet.example/login") {
				t.Errorf("no notice: %s", m.Body)
			}
			if strings.Contains(m.Body, "#token=") {
				t.Error("the owner of an account was sent a token")
			}
		default:
			t.Errorf("mail to %s", m.To)
		}
	}
}

func TestRegistrationLinkIgnoresTheRequestHost(t *testing.T) {
	s := registrationServer(t)
	r := httptest.NewRequest(http.MethodPost, "https://evil.example/register", strings.NewReader(url.Values{"email": {newUser}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handler().ServeHTTP(httptest.NewRecorder(), r)
	mail := sentMail(t, s)
	if len(mail) != 1 {
		t.Fatalf("%d messages", len(mail))
	}
	for _, part := range []string{mail[0].Body, mail[0].HTML} {
		if strings.Contains(part, "evil.example") || !strings.Contains(part, "https://signet.example/register#token=") {
			t.Errorf("wrong link: %s", part)
		}
	}
}

func TestRegistrationStillNeedsApprovalWhenConfigured(t *testing.T) {
	s := registrationServer(t, func(c *config.Config) { c.ApprovalRequired = "required" })
	w := registerPost(s, url.Values{"token": {registrationToken(t, s, newUser)}, "password": {recoveryNewPass}})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "approval") {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if got := loginAs(s, newUser, recoveryNewPass); got == http.StatusFound {
		t.Error("signed in before approval")
	}
	if err := s.backend.AddFlag(newUser, csv.FlagApproved); err != nil {
		t.Fatal(err)
	}
	if got := loginAs(s, newUser, recoveryNewPass); got != http.StatusFound {
		t.Errorf("after approval: %d", got)
	}
}

func TestRegistrationCheckSpendsNothingAndATypoKeepsTheLink(t *testing.T) {
	s := registrationServer(t)
	token := registrationToken(t, s, newUser)
	for i := 0; i < 2; i++ {
		if w := registerPost(s, url.Values{"token": {token}}, "Accept", "application/json"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"success":true`) {
			t.Fatalf("check %d: %d: %s", i, w.Code, w.Body)
		}
	}
	if w := registerPost(s, url.Values{"token": {"nonsense"}}, "Accept", "application/json"); w.Code != http.StatusBadRequest {
		t.Errorf("bad token: %d", w.Code)
	}
	w := registerPost(s, url.Values{"token": {token}, "password": {"short"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "at least 8") || !strings.Contains(w.Body.String(), token) {
		t.Fatalf("short password: %d: %s", w.Code, w.Body)
	}
	if _, err := s.backend.GetUser(newUser); err == nil {
		t.Error("the account exists after a refused password")
	}
	if w := registerPost(s, url.Values{"token": {token}, "password": {recoveryNewPass}}); w.Code != http.StatusOK {
		t.Errorf("second try: %d: %s", w.Code, w.Body)
	}
}

// Whoever got there first keeps the account: a link cannot replace its password.
func TestRegistrationLinkIsRefusedOnceAnAccountExists(t *testing.T) {
	s := registrationServer(t)
	token := registrationToken(t, s, newUser)
	if err := s.backend.CreateUser(newUser, "!", "bcrypt", []string{csv.FlagApproved}); err != nil {
		t.Fatal(err)
	}
	if w := registerPost(s, url.Values{"token": {token}}, "Accept", "application/json"); w.Code != http.StatusBadRequest {
		t.Errorf("check: %d", w.Code)
	}
	if w := registerPost(s, url.Values{"token": {token}, "password": {recoveryNewPass}}); w.Code != http.StatusBadRequest {
		t.Errorf("use: %d", w.Code)
	}
	user, err := s.backend.GetUser(newUser)
	if err != nil {
		t.Fatal(err)
	}
	if user.PasswordHash != "!" {
		t.Error("the link changed an existing account's password")
	}
}

func TestLinksOfOneKindDoNotWorkForTheOther(t *testing.T) {
	s := registrationServer(t, func(c *config.Config) { c.PasswordRecovery = "enabled" })
	ctx := context.Background()
	recovery, err := s.links.Create(ctx, maillink.Recovery, newUser, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	registration, err := s.links.Create(ctx, maillink.Registration, recoveryUser, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if w := registerPost(s, url.Values{"token": {recovery}, "password": {recoveryNewPass}}); w.Code != http.StatusBadRequest {
		t.Errorf("a recovery link registered: %d", w.Code)
	}
	if w := recoverPost(s, url.Values{"token": {registration}, "password": {recoveryNewPass}}); w.Code != http.StatusBadRequest {
		t.Errorf("a registration link reset a password: %d", w.Code)
	}
	if got := loginAs(s, recoveryUser, recoveryOldPass); got != http.StatusFound {
		t.Errorf("the old password: %d", got)
	}
}

func TestRegistrationMailIsLimited(t *testing.T) {
	s := registrationServer(t, func(c *config.Config) { c.MailLinkRateLimit = 2 })
	for _, client := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		if w := registerPost(s, url.Values{"email": {newUser}}, "X-Forwarded-For", client); w.Code != http.StatusOK {
			t.Errorf("%s: %d", client, w.Code)
		}
	}
	if got := len(sentMail(t, s)); got != 2 {
		t.Errorf("%d messages, want 2", got)
	}
}

func TestRegistrationLifetimeFollowsTheConfig(t *testing.T) {
	s := registrationServer(t, func(c *config.Config) { c.RegistrationLinkTTL = 7200 })
	w := registerPost(s, url.Values{"email": {newUser}})
	if !strings.Contains(w.Body.String(), "2 hours") {
		t.Errorf("reply: %s", w.Body)
	}
	if mail := sentMail(t, s); !strings.Contains(mail[0].Body, "2 hours") {
		t.Errorf("mail: %s", mail[0].Body)
	}
	var left int64
	if err := s.db.DB().QueryRow(`SELECT expires_unix - unixepoch() FROM mail_links`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left < 7100 || left > 7210 {
		t.Errorf("the link lasts %d seconds", left)
	}
}

func registerPage(s *Server) string {
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/register", nil))
	return w.Body.String()
}

func loginPage(s *Server) string {
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login", nil))
	return w.Body.String()
}

func TestRegistrationStaysOffUntilItCanWork(t *testing.T) {
	for name, change := range map[string]func(*config.Config){
		"switched off":      func(c *config.Config) { c.SelfRegistration = "disabled" },
		"no public_url":     func(c *config.Config) { c.PublicURL = "" },
		"passwords are off": func(c *config.Config) { c.AuthMethods = map[string]string{"password": "disabled"} },
	} {
		s := registrationServer(t, change)
		if w := registerPost(s, url.Values{"email": {newUser}}); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d", name, w.Code)
		}
		if got := len(sentMail(t, s)); got != 0 {
			t.Errorf("%s: %d messages", name, got)
		}
		page := registerPage(s)
		if !strings.Contains(page, "not available") || strings.Contains(page, `action="/register"`) {
			t.Errorf("%s: the page offers registration", name)
		}
		if strings.Contains(loginPage(s), `href="/register"`) {
			t.Errorf("%s: the login page links to it", name)
		}
	}
}

func TestRegisterPageShowsWhatTheConfigAsks(t *testing.T) {
	verified := registrationServer(t)
	page := registerPage(verified)
	if !strings.Contains(page, "Send Link") || strings.Contains(page, `id="direct-password"`) {
		t.Errorf("verifying page: %s", page)
	}
	if !strings.Contains(loginPage(verified), `href="/register"`) {
		t.Error("the login page does not link to it")
	}

	direct := registrationServer(t, func(c *config.Config) { c.EmailVerification = "disabled" })
	page = registerPage(direct)
	if !strings.Contains(page, `id="direct-password"`) || strings.Contains(page, "Send Link") {
		t.Errorf("direct page: %s", page)
	}
}

// With verification off an account appears at once, which needs no public_url.
func TestDirectRegistrationStillWorks(t *testing.T) {
	s := registrationServer(t, func(c *config.Config) {
		c.EmailVerification = "disabled"
		c.PublicURL = ""
		c.PasswordRecovery = "disabled"
	})
	w := registerPost(s, url.Values{"email": {newUser}, "password": {recoveryNewPass}})
	if w.Code != http.StatusFound {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if got := loginAs(s, newUser, recoveryNewPass); got != http.StatusFound {
		t.Errorf("sign-in: %d", got)
	}
	if w := registerPost(s, url.Values{"email": {newUser}, "password": {recoveryNewPass}}); w.Code != http.StatusConflict {
		t.Errorf("again: %d", w.Code)
	}
	if got := len(sentMail(t, s)); got != 0 {
		t.Errorf("%d messages", got)
	}
}

func TestVerifyEmailStubIsGone(t *testing.T) {
	s := registrationServer(t)
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/verify-email", nil))
	if w.Code == http.StatusNotImplemented {
		t.Errorf("status %d", w.Code)
	}
}

func TestRegistrationReplyDoesNotWaitForMail(t *testing.T) {
	s := registrationServer(t)
	sender := &blockedSender{release: make(chan struct{})}
	s.mailer = sender
	defer func() {
		close(sender.release)
		s.mailJobs.Wait()
	}()
	replied := make(chan int)
	go func() { replied <- registerPost(s, url.Values{"email": {newUser}}).Code }()
	select {
	case code := <-replied:
		if code != http.StatusOK {
			t.Errorf("status %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reply waited for the mail system")
	}
}

func TestRegistrationLeavesNoLinkBehind(t *testing.T) {
	s := registrationServer(t)
	if w := registerPost(s, url.Values{"token": {registrationToken(t, s, newUser)}, "password": {recoveryNewPass}}); w.Code != http.StatusOK {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	var left int
	if err := s.db.DB().QueryRow(`SELECT count(*) FROM mail_links`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("%d links left", left)
	}
}

func TestRegistrationRefusalSaysWhy(t *testing.T) {
	s := registrationServer(t, func(c *config.Config) { c.SelfRegistration = "disabled" })
	w := registerPost(s, url.Values{"email": {newUser}})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Self-registration is disabled") {
		t.Errorf("%d: %s", w.Code, w.Body)
	}
}

// Each feature has its own switch, though they share the links.
func TestRecoveryAndRegistrationSwitchSeparately(t *testing.T) {
	s := registrationServer(t, func(c *config.Config) { c.PasswordRecovery = "disabled" })
	if w := recoverPost(s, url.Values{"email": {recoveryUser}}); w.Code != http.StatusForbidden {
		t.Errorf("recovery off, registration on: recovery answered %d", w.Code)
	}
	if w := registerPost(s, url.Values{"email": {newUser}}); w.Code != http.StatusOK {
		t.Errorf("recovery off, registration on: registration answered %d", w.Code)
	}
	if got := len(sentMail(t, s)); got != 1 {
		t.Errorf("%d messages", got)
	}

	s = registrationServer(t, func(c *config.Config) { c.SelfRegistration = "disabled" })
	if w := recoverPost(s, url.Values{"email": {recoveryUser}}); w.Code != http.StatusOK {
		t.Errorf("registration off, recovery on: recovery answered %d", w.Code)
	}
	if w := registerPost(s, url.Values{"email": {newUser}}); w.Code != http.StatusForbidden {
		t.Errorf("registration off, recovery on: registration answered %d", w.Code)
	}
}
