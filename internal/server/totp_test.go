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
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"

	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/config"
	signetotp "github.com/obtusenet/signet/internal/otp"
)

func totpServer(t *testing.T, change ...func(*config.Config)) *Server {
	t.Helper()
	return recoveryServer(t, append([]func(*config.Config){func(c *config.Config) {
		c.AuthMethods = map[string]string{"password": "enabled", "email_pin": "enabled", "totp": "enabled"}
	}}, change...)...)
}

func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := hotp.GenerateCodeCustom(secret, uint64(at.Unix()/30), hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// enrollTOTP adds a key through the account page, and returns its secret and any
// recovery codes.  The code it used is the current one, so it cannot sign in again.
func enrollTOTP(t *testing.T, s *Server, c *http.Cookie, label string) (string, []string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"action": "totp-begin", "label": label})
	w := accountPost(s, c, string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("begin: %d: %s", w.Code, w.Body)
	}
	var begun struct {
		Secret, QR string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &begun); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(begun.QR, "data:image/png;base64,") {
		t.Errorf("QR: %.40s", begun.QR)
	}
	body, _ = json.Marshal(map[string]string{"action": "totp-finish", "code": codeAt(t, begun.Secret, time.Now())})
	w = accountPost(s, c, string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("finish: %d: %s", w.Code, w.Body)
	}
	var finished struct {
		Codes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &finished); err != nil {
		t.Fatal(err)
	}
	return begun.Secret, finished.Codes
}

var pendingField = regexp.MustCompile(`name="pending" value="([^"]+)"`)

// firstStep posts the password as a plain form and returns the code step's token.
func firstStep(t *testing.T, s *Server) string {
	t.Helper()
	return firstStepAs(t, s, recoveryUser)
}

// firstStepAs is firstStep with the address typed as given.
func firstStepAs(t *testing.T, s *Server, address string) string {
	t.Helper()
	form := url.Values{"email": {address}, "password": {recoveryOldPass}, "referrer": {"/next"}}
	r := httptest.NewRequest(http.MethodPost, "https://signet.example/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	if strings.Contains(w.Header().Get("Set-Cookie"), s.cfg.CookieName+"=") {
		t.Fatal("the first step alone set a session cookie")
	}
	match := pendingField.FindStringSubmatch(w.Body.String())
	if w.Code != http.StatusOK || match == nil {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	return match[1]
}

func secondStep(s *Server, pending, code string) *httptest.ResponseRecorder {
	form := url.Values{"pending": {pending}, "code": {code}, "referrer": {"/next"}}
	r := httptest.NewRequest(http.MethodPost, "https://signet.example/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	return w
}

func sessionMethod(t *testing.T, s *Server, w *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == s.cfg.CookieName && c.Value != "" {
			token, err := s.cookieMgr.ValidateCookieValue(c.Value)
			if err != nil {
				t.Fatal(err)
			}
			sess, err := s.sessionStore.Get(context.Background(), token)
			if err != nil {
				t.Fatal(err)
			}
			return sess.AuthMethod
		}
	}
	t.Fatalf("no cookie: %d: %s", w.Code, w.Body)
	return ""
}

// mailSays looks through what was sent.  Each message goes out on its own, so their
// order means nothing.
func mailSays(t *testing.T, s *Server, text string) bool {
	t.Helper()
	for _, m := range sentMail(t, s) {
		if strings.Contains(m.Body, text) {
			return true
		}
	}
	return false
}

func nextCode(t *testing.T, secret string) string {
	t.Helper()
	return codeAt(t, secret, time.Now().Add(30*time.Second))
}

func TestPasswordThenCode(t *testing.T) {
	s := totpServer(t)
	secret, codes := enrollTOTP(t, s, signedIn(t, s, recoveryUser, "tok", 0), "phone")
	if len(codes) != signetotp.RecoveryCodeCount {
		t.Errorf("%d recovery codes", len(codes))
	}

	pending := firstStep(t, s)
	if w := secondStep(s, pending, "000000"); w.Code != http.StatusUnauthorized || !pendingField.MatchString(w.Body.String()) {
		t.Errorf("a wrong code should keep the step: %d", w.Code)
	}
	w := secondStep(s, pending, nextCode(t, secret))
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/next" {
		t.Fatalf("%d to %q: %s", w.Code, w.Header().Get("Location"), w.Body)
	}
	if got := sessionMethod(t, s, w); got != "password+totp" {
		t.Errorf("method %q", got)
	}
	if w := secondStep(s, pending, nextCode(t, secret)); w.Code != http.StatusUnauthorized || pendingField.MatchString(w.Body.String()) {
		t.Errorf("the step used again: %d", w.Code)
	}
}

func TestLoginPageReplyAsksForTheCodeInJSON(t *testing.T) {
	s := totpServer(t)
	enrollTOTP(t, s, signedIn(t, s, recoveryUser, "tok", 0), "phone")
	form := url.Values{"email": {recoveryUser}, "password": {recoveryOldPass}}
	r := httptest.NewRequest(http.MethodPost, "https://signet.example/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	var reply struct {
		Success  bool
		Required bool   `json:"totp_required"`
		Pending  string `json:"pending"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatalf("%v: %s", err, w.Body)
	}
	if reply.Success || !reply.Required || reply.Pending == "" {
		t.Errorf("%+v", reply)
	}
	if w.Header().Get("Set-Cookie") != "" {
		t.Error("a cookie was set")
	}
}

func TestWrongPasswordNeverReachesTheCodeStep(t *testing.T) {
	s := totpServer(t)
	enrollTOTP(t, s, signedIn(t, s, recoveryUser, "tok", 0), "phone")
	if got := passwordLogin(s, "not-the-password"); got != http.StatusUnauthorized {
		t.Errorf("%d", got)
	}
}

func TestAccountsWithoutAKeyAreNotAsked(t *testing.T) {
	s := totpServer(t)
	if got := passwordLogin(s, recoveryOldPass); got != http.StatusFound {
		t.Errorf("%d", got)
	}
}

func TestPINThenCode(t *testing.T) {
	s := totpServer(t)
	secret, _ := enrollTOTP(t, s, signedIn(t, s, recoveryUser, "tok", 0), "phone")

	send := httptest.NewRequest(http.MethodPost, "/email-pin/send", strings.NewReader(`{"email":"`+recoveryUser+`"}`))
	s.handler().ServeHTTP(httptest.NewRecorder(), send)
	var pin string
	for _, m := range sentMail(t, s) {
		if found := regexp.MustCompile(`\b\d{6}\b`).FindString(m.Body); found != "" && strings.Contains(m.Subject, "PIN") {
			pin = found
		}
	}
	if pin == "" {
		t.Fatal("no PIN")
	}
	body, _ := json.Marshal(map[string]string{"email": recoveryUser, "pin": pin})
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/email-pin/verify", strings.NewReader(string(body))))
	var reply struct {
		Required bool   `json:"totp_required"`
		Pending  string `json:"pending"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatalf("%v: %s", err, w.Body)
	}
	if !reply.Required || reply.Pending == "" || w.Header().Get("Set-Cookie") != "" {
		t.Fatalf("the mailbox alone was enough: %d: %s", w.Code, w.Body)
	}
	done := secondStep(s, reply.Pending, nextCode(t, secret))
	if done.Code != http.StatusFound {
		t.Fatalf("%d: %s", done.Code, done.Body)
	}
	if got := sessionMethod(t, s, done); got != "email_pin+totp" {
		t.Errorf("method %q", got)
	}
	// Made by the PIN method, its session has the claims that method gives.
	var claims string
	if err := s.db.DB().QueryRow(`SELECT claims FROM sessions WHERE auth_method = 'email_pin+totp'`).Scan(&claims); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(claims, `"method":"email_pin+totp"`) {
		t.Errorf("claims %s", claims)
	}
}

// Resetting the password by mail must not skip the code.
func TestRecoveryLinkDoesNotSkipTheCode(t *testing.T) {
	s := totpServer(t)
	secret, _ := enrollTOTP(t, s, signedIn(t, s, recoveryUser, "tok", 0), "phone")
	if w := recoverPost(s, url.Values{"token": {requestToken(t, s)}, "password": {recoveryNewPass}}); w.Code != http.StatusOK {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	form := url.Values{"email": {recoveryUser}, "password": {recoveryNewPass}}
	r := httptest.NewRequest(http.MethodPost, "https://signet.example/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	match := pendingField.FindStringSubmatch(w.Body.String())
	if w.Code == http.StatusFound || match == nil {
		t.Fatalf("no code was asked for: %d", w.Code)
	}
	if done := secondStep(s, match[1], nextCode(t, secret)); done.Code != http.StatusFound {
		t.Errorf("%d", done.Code)
	}
}

// An address typed in another case is the same account: it needs the same code,
// and the session records the account's own form.
func TestAnotherCaseIsTheSameAccount(t *testing.T) {
	s := totpServer(t)
	secret, _ := enrollTOTP(t, s, signedIn(t, s, recoveryUser, "tok", 0), "phone")
	pending := firstStepAs(t, s, strings.ToUpper(recoveryUser))
	w := secondStep(s, pending, nextCode(t, secret))
	if w.Code != http.StatusFound {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == s.cfg.CookieName && c.Value != "" {
			token, _ := s.cookieMgr.ValidateCookieValue(c.Value)
			sess, err := s.sessionStore.Get(context.Background(), token)
			if err != nil {
				t.Fatal(err)
			}
			if sess.UserEmail != recoveryUser {
				t.Errorf("session for %q, want %q", sess.UserEmail, recoveryUser)
			}
		}
	}
}

func TestCodesAreLimited(t *testing.T) {
	s := totpServer(t)
	secret, _ := enrollTOTP(t, s, signedIn(t, s, recoveryUser, "tok", 0), "phone")
	pending := firstStep(t, s)
	for i := 0; i < totpMaxFailures; i++ {
		secondStep(s, pending, "000000")
	}
	// Starting again does not start a new budget.
	again := firstStep(t, s)
	if w := secondStep(s, again, nextCode(t, secret)); w.Code != http.StatusUnauthorized {
		t.Errorf("the right code over the limit: %d", w.Code)
	}
}

func TestRecoveryCodeSignsInOnceAndTellsTheOwner(t *testing.T) {
	s := totpServer(t)
	_, codes := enrollTOTP(t, s, signedIn(t, s, recoveryUser, "tok", 0), "phone")
	w := secondStep(s, firstStep(t, s), codes[0])
	if w.Code != http.StatusFound {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if got := sessionMethod(t, s, w); got != "password+recovery-code" {
		t.Errorf("method %q", got)
	}
	if !mailSays(t, s, "recovery code was used") || !mailSays(t, s, "9 are left") {
		t.Errorf("no notice: %+v", sentMail(t, s))
	}
	if w := secondStep(s, firstStep(t, s), codes[0]); w.Code != http.StatusUnauthorized {
		t.Errorf("used twice: %d", w.Code)
	}
}

func TestACodeStepCannotSignInWithoutTheFirstStep(t *testing.T) {
	s := totpServer(t)
	secret, _ := enrollTOTP(t, s, signedIn(t, s, recoveryUser, "tok", 0), "phone")
	if w := secondStep(s, "made-up", nextCode(t, secret)); w.Code != http.StatusUnauthorized || w.Header().Get("Set-Cookie") != "" {
		t.Errorf("%d", w.Code)
	}
}

func TestLockingStopsTheCodeStep(t *testing.T) {
	s := totpServer(t)
	secret, _ := enrollTOTP(t, s, signedIn(t, s, recoveryUser, "tok", 0), "phone")
	pending := firstStep(t, s)
	if err := s.backend.AddFlag(recoveryUser, csv.FlagLocked); err != nil {
		t.Fatal(err)
	}
	if w := secondStep(s, pending, nextCode(t, secret)); w.Code != http.StatusUnauthorized || w.Header().Get("Set-Cookie") != "" {
		t.Errorf("%d", w.Code)
	}
}

func TestEnrollmentRefusals(t *testing.T) {
	s := totpServer(t)
	c := signedIn(t, s, recoveryUser, "tok", 0)
	if w := accountPost(s, c, `{"action":"totp-finish","code":"000000"}`); w.Code != http.StatusBadRequest {
		t.Errorf("nothing started: %d", w.Code)
	}
	if w := accountPost(s, c, `{"action":"totp-begin","label":"`+strings.Repeat("x", 65)+`"}`); w.Code != http.StatusBadRequest {
		t.Errorf("a long name: %d", w.Code)
	}
	if w := accountPost(s, c, `{"action":"totp-begin","label":"a\u0007b"}`); w.Code != http.StatusBadRequest {
		t.Errorf("a control character: %d", w.Code)
	}
	if w := accountPost(s, c, `{"action":"totp-begin"}`); w.Code != http.StatusOK {
		t.Fatalf("begin: %d", w.Code)
	}
	if w := accountPost(s, c, `{"action":"totp-finish","code":"not-a-code"}`); w.Code != http.StatusBadRequest {
		t.Errorf("a wrong code: %d", w.Code)
	}
	if has, _ := s.totp.HasKeys(context.Background(), recoveryUser); has {
		t.Error("a key was saved without a working code")
	}
	if got := passwordLogin(s, recoveryOldPass); got != http.StatusFound {
		t.Errorf("unproved, it must not change sign-in: %d", got)
	}
}

func TestTOTPChangesNeedARecentSignIn(t *testing.T) {
	s := totpServer(t, func(c *config.Config) { c.AccountReauthWindow = 60 })
	stale := signedIn(t, s, recoveryUser, "stale", 2*time.Minute)
	for _, action := range []string{`{"action":"totp-begin"}`, `{"action":"totp-finish","code":"1"}`, `{"action":"totp-remove","id":"x"}`, `{"action":"totp-codes"}`} {
		if w := accountPost(s, stale, action); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d", action, w.Code)
		}
	}
	if page := accountGet(s, stale).Body.String(); strings.Contains(page, `id="totp-begin"`) {
		t.Error("the stale page offers it")
	}
}

func TestRemovingAKey(t *testing.T) {
	s := totpServer(t)
	mine := signedIn(t, s, recoveryUser, "mine", 0)
	signedIn(t, s, recoveryUser, "other", 0)
	enrollTOTP(t, s, mine, "phone")
	keys, err := s.totp.ListKeys(context.Background(), recoveryUser)
	if err != nil || len(keys) != 1 {
		t.Fatalf("%d, %v", len(keys), err)
	}
	if w := accountPost(s, mine, `{"action":"totp-remove","id":"nonsense"}`); w.Code != http.StatusNotFound {
		t.Errorf("no such key: %d", w.Code)
	}
	body, _ := json.Marshal(map[string]string{"action": "totp-remove", "id": keys[0].ID})
	if w := accountPost(s, mine, string(body)); w.Code != http.StatusOK {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if _, err := s.sessionStore.Get(context.Background(), "other"); err == nil {
		t.Error("the other session survived")
	}
	if _, err := s.sessionStore.Get(context.Background(), "mine"); err != nil {
		t.Errorf("this session ended: %v", err)
	}
	if got := passwordLogin(s, recoveryOldPass); got != http.StatusFound {
		t.Errorf("sign-in still asks for a code: %d", got)
	}
	if len(sentMail(t, s)) != 2 || !mailSays(t, s, "was added") || !mailSays(t, s, "was removed") {
		t.Errorf("notices: %+v", sentMail(t, s))
	}
}

func TestAnotherAccountsKeyCannotBeRemoved(t *testing.T) {
	s := totpServer(t)
	enrollTOTP(t, s, signedIn(t, s, recoveryUser, "mine", 0), "phone")
	keys, _ := s.totp.ListKeys(context.Background(), recoveryUser)
	theirs := signedIn(t, s, "else@example.com", "theirs", 0)
	if err := s.backend.CreateUser("else@example.com", noPassword, "bcrypt", []string{csv.FlagApproved}); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"action": "totp-remove", "id": keys[0].ID})
	if w := accountPost(s, theirs, string(body)); w.Code != http.StatusNotFound {
		t.Errorf("%d", w.Code)
	}
	if has, _ := s.totp.HasKeys(context.Background(), recoveryUser); !has {
		t.Error("the key went")
	}
}

func TestReplacingRecoveryCodes(t *testing.T) {
	s := totpServer(t)
	c := signedIn(t, s, recoveryUser, "tok", 0)
	if w := accountPost(s, c, `{"action":"totp-codes"}`); w.Code != http.StatusBadRequest {
		t.Errorf("no keys: %d", w.Code)
	}
	_, old := enrollTOTP(t, s, c, "phone")
	w := accountPost(s, c, `{"action":"totp-codes"}`)
	var reply struct {
		Codes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || len(reply.Codes) != signetotp.RecoveryCodeCount {
		t.Fatalf("%v: %s", err, w.Body)
	}
	if w := secondStep(s, firstStep(t, s), old[0]); w.Code != http.StatusUnauthorized ||
		!strings.Contains(w.Body.String(), wrongRecoveryCodeMessage) {
		t.Errorf("an old code: %d", w.Code)
	}
	// The page says which kind of code failed, so an old recovery code is told
	// apart from a wrong app code.
	if w := secondStep(s, firstStep(t, s), "000000"); w.Code != http.StatusUnauthorized ||
		!strings.Contains(w.Body.String(), wrongCodeMessage) || strings.Contains(w.Body.String(), wrongRecoveryCodeMessage) {
		t.Errorf("a wrong app code: %d", w.Code)
	}
	if w := secondStep(s, firstStep(t, s), reply.Codes[0]); w.Code != http.StatusFound {
		t.Errorf("a new code: %d", w.Code)
	}
}

func TestTOTPSwitchedOff(t *testing.T) {
	first := totpServer(t)
	enrollTOTP(t, first, signedIn(t, first, recoveryUser, "tok", 0), "phone")
	cfg := *first.cfg
	cfg.AuthMethods = map[string]string{"password": "enabled"}
	s := New(&cfg, first.logger, first.db, first.backend)
	if got := passwordLogin(s, recoveryOldPass); got != http.StatusFound {
		t.Errorf("a code was asked for: %d", got)
	}
	c := signedIn(t, s, recoveryUser, "off", 0)
	if w := accountPost(s, c, `{"action":"totp-begin"}`); w.Code != http.StatusForbidden {
		t.Errorf("enrollment: %d", w.Code)
	}
	if page := accountGet(s, c).Body.String(); strings.Contains(page, `id="totp-section"`) {
		t.Error("the page offers it")
	}
	if w := secondStep(s, "whatever", "000000"); w.Code != http.StatusUnauthorized {
		t.Errorf("the code step: %d", w.Code)
	}
}

func TestAccountPageListsKeys(t *testing.T) {
	s := totpServer(t)
	c := signedIn(t, s, recoveryUser, "tok", 0)
	page := accountGet(s, c).Body.String()
	if !strings.Contains(page, `id="totp-begin"`) || strings.Contains(page, "recovery codes left") {
		t.Errorf("before: %s", page)
	}
	enrollTOTP(t, s, c, "<b>my phone</b>")
	page = accountGet(s, c).Body.String()
	if !strings.Contains(page, "&lt;b&gt;my phone&lt;/b&gt;") || strings.Contains(page, "<b>my phone") {
		t.Error("the name is not escaped")
	}
	if !strings.Contains(page, "10 recovery codes left") {
		t.Errorf("after: %s", page)
	}
}

func TestLoginPageHidesMethodsDuringTheCodeStep(t *testing.T) {
	s := totpServer(t)
	enrollTOTP(t, s, signedIn(t, s, recoveryUser, "tok", 0), "phone")
	form := url.Values{"email": {recoveryUser}, "password": {recoveryOldPass}}
	r := httptest.NewRequest(http.MethodPost, "https://signet.example/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), `<div id="sign-in-methods" hidden>`) {
		t.Error("the other methods are showing")
	}
	plain := httptest.NewRecorder()
	s.handler().ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "/login", nil))
	if !strings.Contains(plain.Body.String(), `<form id="code-form" method="POST" action="/login" hidden>`) {
		t.Error("the code form is showing on an ordinary login page")
	}
}

// A person who gets it right starts afresh, so typos spread over a day add up to nothing.
func TestARightCodeClearsTheFailures(t *testing.T) {
	s := totpServer(t)
	_, codes := enrollTOTP(t, s, signedIn(t, s, recoveryUser, "tok", 0), "phone")
	for round := 0; round < 2; round++ {
		pending := firstStep(t, s)
		for i := 0; i < totpMaxFailures-1; i++ {
			secondStep(s, pending, "000000")
		}
		if w := secondStep(s, pending, codes[round]); w.Code != http.StatusFound {
			t.Fatalf("round %d: %d", round, w.Code)
		}
	}
}
