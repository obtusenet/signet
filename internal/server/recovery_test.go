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
	"github.com/obtusenet/signet/internal/email"
	"github.com/obtusenet/signet/internal/maillink"
	"github.com/obtusenet/signet/internal/session"
)

const (
	recoveryUser    = "user@example.com"
	recoveryOldPass = "the-old-password"
	recoveryNewPass = "a-brand-new-password"
)

// recoveryServer has one approved account, and mail goes to a stub.
func recoveryServer(t *testing.T, change ...func(*config.Config)) *Server {
	t.Helper()
	first, backend := newRegisterServer(t, "disabled")
	cfg := *first.cfg
	cfg.TemplatesDir = "../../web/templates"
	cfg.PasswordRecovery = "enabled"
	cfg.PublicURL = "https://signet.example/"
	cfg.Mail.Program = ""
	cfg.AuthMethods = map[string]string{"password": "enabled"}
	cfg.TrustedProxies = []string{"192.0.2.1"} // httptest's default peer
	for _, c := range change {
		c(&cfg)
	}
	s := New(&cfg, first.logger, first.db, backend)
	hash, err := s.hasher.Hash(recoveryOldPass)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.CreateUser(recoveryUser, hash, "bcrypt", []string{csv.FlagApproved}); err != nil {
		t.Fatal(err)
	}
	return s
}

func recoverPost(s *Server, form url.Values, headers ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://signet.example/recover", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	return w
}

func sentMail(t *testing.T, s *Server) []email.SentEmail {
	t.Helper()
	s.mailJobs.Wait()
	return s.mailer.(*email.StubSender).GetSentEmails()
}

var linkPattern = regexp.MustCompile(`(\S*)/recover#token=([A-Za-z0-9_-]+)`)

// requestToken asks for a link and returns the token in the mail.
func requestToken(t *testing.T, s *Server) string {
	t.Helper()
	before := len(sentMail(t, s))
	if w := recoverPost(s, url.Values{"email": {recoveryUser}}); w.Code != http.StatusOK {
		t.Fatalf("request: %d: %s", w.Code, w.Body)
	}
	mail := sentMail(t, s)
	if len(mail) != before+1 {
		t.Fatalf("%d messages, want %d", len(mail), before+1)
	}
	match := linkPattern.FindStringSubmatch(mail[len(mail)-1].Body)
	if match == nil {
		t.Fatalf("no link in: %s", mail[len(mail)-1].Body)
	}
	return match[2]
}

func passwordLogin(s *Server, password string) int {
	form := url.Values{"email": {recoveryUser}, "password": {password}}
	r := httptest.NewRequest(http.MethodPost, "https://signet.example/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	return w.Code
}

func TestRecoveryChangesThePassword(t *testing.T) {
	s := recoveryServer(t)
	token := requestToken(t, s)

	w := recoverPost(s, url.Values{"token": {token}, "password": {recoveryNewPass}})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "has been changed") {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if got := passwordLogin(s, recoveryOldPass); got != http.StatusUnauthorized {
		t.Errorf("old password: %d", got)
	}
	if got := passwordLogin(s, recoveryNewPass); got != http.StatusFound {
		t.Errorf("new password: %d", got)
	}
	if w := recoverPost(s, url.Values{"token": {token}, "password": {"yet-another-password"}}); w.Code != http.StatusBadRequest {
		t.Errorf("second use: %d", w.Code)
	}
	if got := passwordLogin(s, recoveryNewPass); got != http.StatusFound {
		t.Errorf("after the refused second use: %d", got)
	}

	mail := sentMail(t, s)
	last := mail[len(mail)-1]
	if last.To != recoveryUser || !strings.Contains(last.Subject, "changed") || !strings.Contains(last.Body, "was just changed") {
		t.Errorf("no notice: %+v", last)
	}
}

func TestRecoveryEndsEverySessionAndCookie(t *testing.T) {
	s := recoveryServer(t)
	store := session.NewStore(s.db.DB())
	ctx := context.Background()
	now := time.Now()
	for token, addr := range map[string]string{"mine": recoveryUser, "theirs": "other@example.com"} {
		if err := store.Create(ctx, &session.Session{Token: token, UserEmail: addr, AuthMethod: "password", Claims: "{}", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	w := recoverPost(s, url.Values{"token": {requestToken(t, s)}, "password": {recoveryNewPass}})
	if w.Code != http.StatusOK {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if _, err := store.Get(ctx, "mine"); err == nil {
		t.Error("the account's session survived")
	}
	if _, err := store.Get(ctx, "theirs"); err != nil {
		t.Errorf("another account's session went: %v", err)
	}
	if !strings.Contains(w.Header().Get("Set-Cookie"), "Max-Age=0") && !strings.Contains(w.Header().Get("Set-Cookie"), "Max-Age=-1") {
		t.Errorf("cookie not expired: %q", w.Header().Get("Set-Cookie"))
	}
}

// A forged Host must not reach the link, or a real message would send its reader,
// and their token, to the attacker.
func TestRecoveryLinkIgnoresTheRequestHost(t *testing.T) {
	s := recoveryServer(t)
	r := httptest.NewRequest(http.MethodPost, "https://evil.example/recover", strings.NewReader(url.Values{"email": {recoveryUser}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Forwarded-Host", "evil.example")
	s.handler().ServeHTTP(httptest.NewRecorder(), r)

	mail := sentMail(t, s)
	if len(mail) != 1 {
		t.Fatalf("%d messages", len(mail))
	}
	for _, part := range []string{mail[0].Body, mail[0].HTML} {
		if strings.Contains(part, "evil.example") {
			t.Errorf("the forged host is in the message: %s", part)
		}
		if !strings.Contains(part, "https://signet.example/recover#token=") {
			t.Errorf("no link to public_url: %s", part)
		}
	}
}

func TestRecoveryRepliesAlikeForEveryAddress(t *testing.T) {
	s := recoveryServer(t)
	if err := s.backend.CreateUser("locked@example.com", "!", "bcrypt", []string{csv.FlagApproved, csv.FlagLocked}); err != nil {
		t.Fatal(err)
	}
	if err := s.backend.CreateUser("pending@example.com", "!", "bcrypt", []string{csv.FlagSelfRegistered}); err != nil {
		t.Fatal(err)
	}
	want := recoverPost(s, url.Values{"email": {recoveryUser}})
	for _, addr := range []string{"nobody@example.com", "locked@example.com", "pending@example.com", "not an address", "#x@example.com"} {
		got := recoverPost(s, url.Values{"email": {addr}})
		wantBody := strings.ReplaceAll(want.Body.String(), recoveryUser, "")
		gotBody := strings.ReplaceAll(got.Body.String(), html.EscapeString(addr), "")
		if got.Code != want.Code || gotBody != wantBody {
			t.Errorf("%s: %d differs from %d:\n%s", addr, got.Code, want.Code, gotBody)
		}
	}
	mail := sentMail(t, s)
	if len(mail) != 1 || mail[0].To != recoveryUser {
		t.Errorf("mail went to: %+v", mail)
	}
}

func TestRecoveryAccountWithoutAPasswordCanSetOne(t *testing.T) {
	s := recoveryServer(t)
	const addr = "nopassword@example.com"
	if err := s.backend.CreateUser(addr, "!", "bcrypt", []string{csv.FlagApproved}); err != nil {
		t.Fatal(err)
	}
	recoverPost(s, url.Values{"email": {addr}})
	mail := sentMail(t, s)
	if len(mail) != 1 {
		t.Fatalf("%d messages", len(mail))
	}
	token := linkPattern.FindStringSubmatch(mail[0].Body)[2]
	if w := recoverPost(s, url.Values{"token": {token}, "password": {recoveryNewPass}}); w.Code != http.StatusOK {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	user, err := s.backend.GetUser(addr)
	if err != nil {
		t.Fatal(err)
	}
	if user.PasswordHash == "!" {
		t.Error("the account still has no password")
	}
}

func TestRecoveryLinkIsRefusedOnceTheAccountCannotSignIn(t *testing.T) {
	s := recoveryServer(t)
	token := requestToken(t, s)
	if err := s.backend.AddFlag(recoveryUser, csv.FlagLocked); err != nil {
		t.Fatal(err)
	}
	if w := recoverPost(s, url.Values{"token": {token}}, "Accept", "application/json"); w.Code != http.StatusBadRequest {
		t.Errorf("check: %d", w.Code)
	}
	if w := recoverPost(s, url.Values{"token": {token}, "password": {recoveryNewPass}}); w.Code != http.StatusBadRequest {
		t.Errorf("use: %d", w.Code)
	}
	s.backend.RemoveFlag(recoveryUser, csv.FlagLocked)
	if got := passwordLogin(s, recoveryOldPass); got != http.StatusFound {
		t.Errorf("the password changed anyway: %d", got)
	}
}

func TestRecoveryCheckSpendsNothing(t *testing.T) {
	s := recoveryServer(t)
	token := requestToken(t, s)
	for i := 0; i < 3; i++ {
		w := recoverPost(s, url.Values{"token": {token}}, "Accept", "application/json")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"success":true`) {
			t.Fatalf("check %d: %d: %s", i, w.Code, w.Body)
		}
	}
	w := recoverPost(s, url.Values{"token": {"nonsense"}}, "Accept", "application/json")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"success":false`) {
		t.Errorf("bad token: %d: %s", w.Code, w.Body)
	}
	if w := recoverPost(s, url.Values{"token": {token}, "password": {recoveryNewPass}}); w.Code != http.StatusOK {
		t.Errorf("use after checks: %d", w.Code)
	}
}

// A typo must not cost the link.
func TestRecoveryShortPasswordKeepsTheLink(t *testing.T) {
	s := recoveryServer(t)
	token := requestToken(t, s)
	w := recoverPost(s, url.Values{"token": {token}, "password": {"short"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "at least 8") {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), token) {
		t.Error("the page lost the token, so the form cannot be resubmitted")
	}
	if got := passwordLogin(s, recoveryOldPass); got != http.StatusFound {
		t.Errorf("old password after the refusal: %d", got)
	}
	if w := recoverPost(s, url.Values{"token": {token}, "password": {recoveryNewPass}}); w.Code != http.StatusOK {
		t.Errorf("second try: %d: %s", w.Code, w.Body)
	}
}

func TestRecoveryClearsTheAddressLimit(t *testing.T) {
	s := recoveryServer(t, func(c *config.Config) { c.LoginRateLimit = 2 })
	for i := 0; i < 2; i++ {
		passwordLogin(s, "wrong-password")
	}
	if got := passwordLogin(s, recoveryOldPass); got != http.StatusUnauthorized {
		t.Fatalf("not limited: %d", got)
	}
	if w := recoverPost(s, url.Values{"token": {requestToken(t, s)}, "password": {recoveryNewPass}}); w.Code != http.StatusOK {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if got := passwordLogin(s, recoveryNewPass); got != http.StatusFound {
		t.Errorf("new password while limited: %d", got)
	}
}

func TestRecoveryMailIsLimited(t *testing.T) {
	limits := func(c *config.Config) {
		c.MailLinkRateLimit = 2
		c.MailLinkSourceRateLimit = 3
	}
	from := func(s *Server, client, addr string) *httptest.ResponseRecorder {
		return recoverPost(s, url.Values{"email": {addr}}, "X-Forwarded-For", client)
	}

	t.Run("per address, from many clients", func(t *testing.T) {
		s := recoveryServer(t, limits)
		for _, client := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"} {
			if w := from(s, client, recoveryUser); w.Code != http.StatusOK {
				t.Errorf("%s: %d", client, w.Code)
			}
		}
		if got := len(sentMail(t, s)); got != 2 {
			t.Errorf("%d messages, want 2", got)
		}
	})
	t.Run("per client, to many addresses", func(t *testing.T) {
		s := recoveryServer(t, limits)
		for _, addr := range []string{"a@example.com", "b@example.com", "c@example.com", "d@example.com", recoveryUser} {
			from(s, "198.51.100.1", addr)
		}
		if got := len(sentMail(t, s)); got != 0 {
			t.Errorf("%d messages: the fifth request was over the client's budget", got)
		}
		from(s, "198.51.100.2", recoveryUser)
		if got := len(sentMail(t, s)); got != 1 {
			t.Errorf("another client: %d messages", got)
		}
	})
}

func TestRecoveryLifetimeFollowsTheConfig(t *testing.T) {
	s := recoveryServer(t, func(c *config.Config) { c.RecoveryLinkTTL = 1800 })
	w := recoverPost(s, url.Values{"email": {recoveryUser}})
	if !strings.Contains(w.Body.String(), "30 minutes") {
		t.Errorf("reply: %s", w.Body)
	}
	if mail := sentMail(t, s); !strings.Contains(mail[0].Body, "30 minutes") {
		t.Errorf("mail: %s", mail[0].Body)
	}
	var left int64
	if err := s.db.DB().QueryRow(`SELECT expires_unix - unixepoch() FROM mail_links`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left < 1700 || left > 1810 {
		t.Errorf("the link lasts %d seconds", left)
	}
}

func TestRecoveryStaysOffUntilItCanWork(t *testing.T) {
	for name, change := range map[string]func(*config.Config){
		"switched off":      func(c *config.Config) { c.PasswordRecovery = "disabled" },
		"no public_url":     func(c *config.Config) { c.PublicURL = "" },
		"passwords are off": func(c *config.Config) { c.AuthMethods = map[string]string{"password": "disabled"} },
	} {
		s := recoveryServer(t, change)
		w := recoverPost(s, url.Values{"email": {recoveryUser}})
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: %d", name, w.Code)
		}
		if got := len(sentMail(t, s)); got != 0 {
			t.Errorf("%s: %d messages", name, got)
		}
		r := httptest.NewRequest(http.MethodGet, "/recover", nil)
		page := httptest.NewRecorder()
		s.handler().ServeHTTP(page, r)
		if !strings.Contains(page.Body.String(), "not available") || strings.Contains(page.Body.String(), `action="/recover"`) {
			t.Errorf("%s: the page offers recovery", name)
		}
	}
}

func TestOnlyARecoveryTokenWorksHere(t *testing.T) {
	s := recoveryServer(t)
	other, err := s.links.Create(context.Background(), "another-kind", recoveryUser, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if w := recoverPost(s, url.Values{"token": {other}, "password": {recoveryNewPass}}); w.Code != http.StatusBadRequest {
		t.Errorf("%d", w.Code)
	}
	if _, err := s.links.Email(context.Background(), maillink.Recovery, other); err == nil {
		t.Error("it is a recovery token after all")
	}
}

func TestAnotherSiteCannotUseRecovery(t *testing.T) {
	s := recoveryServer(t)
	w := recoverPost(s, url.Values{"email": {recoveryUser}}, "Origin", "https://evil.example")
	if w.Code != http.StatusForbidden || len(sentMail(t, s)) != 0 {
		t.Errorf("%d", w.Code)
	}
}

func TestHumanDuration(t *testing.T) {
	for seconds, want := range map[int]string{3600: "1 hour", 7200: "2 hours", 1800: "30 minutes", 60: "1 minute", 90: "1 minute", 30: "30 seconds", 5400: "90 minutes"} {
		if got := humanDuration(seconds); got != want {
			t.Errorf("%d: %q, want %q", seconds, got, want)
		}
	}
}

// blockedSender holds every message until release is closed.
type blockedSender struct {
	release chan struct{}
}

func (b *blockedSender) Send(to, subject, text, html string) error {
	<-b.release
	return nil
}

// A slow mail system must not show in the reply, or its timing would tell which
// addresses have accounts.
func TestRecoveryReplyDoesNotWaitForMail(t *testing.T) {
	s := recoveryServer(t)
	sender := &blockedSender{release: make(chan struct{})}
	s.mailer = sender
	defer func() {
		close(sender.release)
		s.mailJobs.Wait()
	}()

	replied := make(chan int)
	go func() { replied <- recoverPost(s, url.Values{"email": {recoveryUser}}).Code }()
	select {
	case code := <-replied:
		if code != http.StatusOK {
			t.Errorf("status %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reply waited for the mail system")
	}
}
