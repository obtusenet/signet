// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/auth"
	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/claims"
	"github.com/obtusenet/signet/internal/clientaddr"
	"github.com/obtusenet/signet/internal/config"
	"github.com/obtusenet/signet/internal/cookie"
	"github.com/obtusenet/signet/internal/db"
	"github.com/obtusenet/signet/internal/email"
	"github.com/obtusenet/signet/internal/logging"
	"github.com/obtusenet/signet/internal/password"
	"github.com/obtusenet/signet/internal/session"
)

// fixture is a backend, session store and PIN store on a throwaway database.
type fixture struct {
	db       *sql.DB
	backend  *csv.Backend
	hasher   *password.Hasher
	sessions *session.Store
	cookies  *cookie.CookieManager
	logger   *logging.Logger
	sender   *email.StubSender
	pins     *email.PINStore
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	logger, err := logging.New(false, "error")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store, err := db.New(filepath.Join(dir, "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	backend, err := csv.New(filepath.Join(dir, "users.csv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backend.Close() })

	sender := email.NewStubSender()
	pins, err := email.NewPINStore(store.DB(), sender, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		db:      store.DB(),
		backend: backend,
		hasher: password.NewHasher("bcrypt", 4, password.Argon2idParams{
			Time: 1, Memory: 1024, Parallel: 1, SaltLength: 16, KeyLength: 32,
		}),
		sessions: session.NewStore(store.DB()),
		cookies:  cookie.NewCookieManager("signetid", "", 3600, []byte("test-secret-key-for-testing-only")),
		logger:   logger,
		sender:   sender,
		pins:     pins,
	}
}

func (f *fixture) addUser(t *testing.T, addr string, flags ...string) {
	t.Helper()
	hash, err := f.hasher.Hash("correct-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.backend.CreateUser(addr, hash, "bcrypt", flags); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) pinAuth(requireApproval bool, hook ...*claims.ClaimsHook) *auth.EmailPINAuth {
	pa := auth.NewEmailPINAuth(
		f.pins,
		auth.NewAccountPolicy(f.backend, requireApproval),
		f.sessions,
		f.cookies,
		f.logger,
		auth.NewEmailRateLimiter(1000, time.Minute),
		3,
		30*time.Minute,
		hook...,
	)
	// httptest's default peer, so post can choose a requester.
	clients, err := clientaddr.New([]string{"192.0.2.1"})
	if err != nil {
		panic(err)
	}
	pa.SetClientAddr(clients)
	return pa
}

func (f *fixture) passwordAuth(requireApproval bool, hook ...*claims.ClaimsHook) *auth.PasswordAuth {
	return auth.NewPasswordAuth(
		auth.NewAccountPolicy(f.backend, requireApproval),
		f.hasher,
		f.cookies,
		f.sessions,
		f.logger,
		5,
		300,
		hook...,
	)
}

// post calls handler with a JSON body and a chosen X-Forwarded-For.
func post(handler http.HandlerFunc, body, forwardedFor string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if forwardedFor != "" {
		r.Header.Set("X-Forwarded-For", forwardedFor)
	}
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}

func sendBody(addr string) string { return fmt.Sprintf(`{"email":%q}`, addr) }

func verifyBody(addr, pin string) string { return fmt.Sprintf(`{"email":%q,"pin":%q}`, addr, pin) }

// lastPIN is the PIN from the most recent stub email.
func (f *fixture) lastPIN(t *testing.T) string {
	t.Helper()
	sent := f.sender.GetSentEmails()
	if len(sent) == 0 {
		t.Fatal("no email was sent")
	}
	return extractPINFromEmail(sent[len(sent)-1].Body)
}

// sessionCount is the number of session rows for an address.
func (f *fixture) sessionCount(t *testing.T, addr string) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_email = ?`, addr).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// wrongPIN differs from pin in every position.
func wrongPIN(pin string) string {
	b := []byte(pin)
	for i := range b {
		b[i] = '0' + (b[i]-'0'+1)%10
	}
	return string(b)
}

func hasSessionCookie(w *httptest.ResponseRecorder) bool {
	for _, c := range w.Result().Cookies() {
		if c.Name == "signetid" && c.Value != "" {
			return true
		}
	}
	return false
}

func TestPINGuessingLocksAcrossRotatingForwardedFor(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "victim@example.com")
	pa := f.pinAuth(false)

	if w := post(pa.SendPINRequest, sendBody("victim@example.com"), "198.51.100.1"); w.Code != http.StatusOK {
		t.Fatalf("send: %d", w.Code)
	}
	pin := f.lastPIN(t)
	wrong := wrongPIN(pin)

	for i := 0; i < 3; i++ {
		w := post(pa.VerifyPINRequest, verifyBody("victim@example.com", wrong), fmt.Sprintf("198.51.100.%d", 10+i))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("guess %d: status %d", i, w.Code)
		}
	}

	// The right PIN from yet another claimed address must now be refused.
	w := post(pa.VerifyPINRequest, verifyBody("victim@example.com", pin), "198.51.100.99")
	if w.Code == http.StatusOK || hasSessionCookie(w) {
		t.Fatalf("correct PIN accepted after lockout: %d", w.Code)
	}

	// While locked, no further mail goes out, though the reply is unchanged.
	before := len(f.sender.GetSentEmails())
	if w := post(pa.SendPINRequest, sendBody("victim@example.com"), "198.51.100.100"); w.Code != http.StatusOK {
		t.Fatalf("send while locked: %d", w.Code)
	}
	if after := len(f.sender.GetSentEmails()); after != before {
		t.Errorf("sent %d emails while locked", after-before)
	}
}

func TestPINLockoutEndsAfterTheWindow(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "user@example.com")

	if _, err := f.pins.CreateAndSendPIN(context.Background(), "user@example.com"); err != nil {
		t.Fatal(err)
	}
	wrong := wrongPIN(f.lastPIN(t))
	for i := 0; i < 3; i++ {
		if err := f.pins.VerifyPIN(context.Background(), "user@example.com", wrong); !errors.Is(err, email.ErrPINNotFound) {
			t.Fatalf("guess %d: %v", i, err)
		}
	}

	count, err := f.pins.RecentFailures(context.Background(), "user@example.com", time.Now().Add(-time.Minute))
	if err != nil || count != 3 {
		t.Fatalf("within window: count=%d err=%v", count, err)
	}
	count, err = f.pins.RecentFailures(context.Background(), "user@example.com", time.Now().Add(time.Minute))
	if err != nil || count != 0 {
		t.Fatalf("after window: count=%d err=%v", count, err)
	}
}

func TestNewPINRetiresEarlierOnes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.pins.CreateAndSendPIN(ctx, "user@example.com"); err != nil {
		t.Fatal(err)
	}
	first := f.lastPIN(t)
	// Regenerate until the two differ; equal PINs would make this vacuous.
	var second string
	for second = first; second == first; second = f.lastPIN(t) {
		if _, err := f.pins.CreateAndSendPIN(ctx, "user@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.pins.VerifyPIN(ctx, "user@example.com", first); !errors.Is(err, email.ErrPINNotFound) {
		t.Errorf("earlier PIN: got %v, want ErrPINNotFound", err)
	}
	if err := f.pins.VerifyPIN(ctx, "user@example.com", second); err != nil {
		t.Errorf("newest PIN: %v", err)
	}
}

func TestPINRefusedForAccountsThatMayNotSignIn(t *testing.T) {
	cases := []struct {
		name  string
		flags []string
		add   bool
	}{
		{"unknown address", nil, false},
		{"locked account", []string{csv.FlagLocked}, true},
		{"unapproved self-registration", []string{csv.FlagSelfRegistered}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.add {
				f.addUser(t, "user@example.com", tc.flags...)
			}
			pa := f.pinAuth(true)

			// Same reply as a real send, but nothing goes out.
			if w := post(pa.SendPINRequest, sendBody("user@example.com"), ""); w.Code != http.StatusOK {
				t.Errorf("send: %d", w.Code)
			}
			if n := len(f.sender.GetSentEmails()); n != 0 {
				t.Errorf("sent %d emails", n)
			}

			// Even a genuinely issued PIN must not produce a session.
			if _, err := f.pins.CreateAndSendPIN(context.Background(), "user@example.com"); err != nil {
				t.Fatal(err)
			}
			w := post(pa.VerifyPINRequest, verifyBody("user@example.com", f.lastPIN(t)), "")
			if w.Code == http.StatusOK || hasSessionCookie(w) {
				t.Errorf("verify gave access: %d", w.Code)
			}
		})
	}
}

func TestPINSendCreatesNoSession(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "user@example.com")
	pa := f.pinAuth(false)

	if w := post(pa.SendPINRequest, sendBody("user@example.com"), ""); w.Code != http.StatusOK {
		t.Fatalf("send: %d", w.Code)
	}
	if n := f.sessionCount(t, "user@example.com"); n != 0 {
		t.Errorf("send left %d session rows", n)
	}
}

// hook writes an executable script that answers one request and returns a
// configured ClaimsHook.
func hook(t *testing.T, f *fixture, script, onFailure string) *claims.ClaimsHook {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hook.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return claims.NewClaimsHook(config.ClaimsHookConfig{
		Enabled: true, Program: path, TimeoutSec: 5, OnFailure: onFailure,
	}, f.logger)
}

const denyingHook = `read line; echo '{"type":"claim_error","error":"not allowed"}'`

func TestFailClosedHookRefusesPasswordLogin(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "user@example.com")
	pa := f.passwordAuth(false, hook(t, f, denyingHook, "fail-closed"))

	_, err := pa.Authenticate(context.Background(), "user@example.com", "192.0.2.1", "correct-password")
	if !errors.Is(err, auth.ErrClaimsRefused) {
		t.Fatalf("got %v, want ErrClaimsRefused", err)
	}
	if n := f.sessionCount(t, "user@example.com"); n != 0 {
		t.Errorf("%d sessions created", n)
	}
}

func TestFailOpenHookAllowsPasswordLogin(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "user@example.com")
	pa := f.passwordAuth(false, hook(t, f, denyingHook, "fail-open"))

	if _, err := pa.Authenticate(context.Background(), "user@example.com", "192.0.2.1", "correct-password"); err != nil {
		t.Fatalf("fail-open refused the login: %v", err)
	}
}

func TestFailClosedHookRefusesPINLogin(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "user@example.com")
	pa := f.pinAuth(false, hook(t, f, denyingHook, "fail-closed"))

	if w := post(pa.SendPINRequest, sendBody("user@example.com"), ""); w.Code != http.StatusOK {
		t.Fatalf("send: %d", w.Code)
	}
	w := post(pa.VerifyPINRequest, verifyBody("user@example.com", f.lastPIN(t)), "")
	if w.Code != http.StatusForbidden || hasSessionCookie(w) {
		t.Errorf("status %d, cookie %v; want 403 and no cookie", w.Code, hasSessionCookie(w))
	}
}

func TestApprovalEnforcedForPasswordLogin(t *testing.T) {
	cases := []struct {
		name     string
		flags    []string
		required bool
		allowed  bool
	}{
		{"pending, approval required", []string{csv.FlagSelfRegistered}, true, false},
		{"approved, approval required", []string{csv.FlagSelfRegistered, csv.FlagApproved}, true, true},
		{"admin-created, approval required", []string{csv.FlagApproved}, true, true},
		{"hand-added with no flags, approval required", nil, true, true},
		{"pending, auto_approve", []string{csv.FlagSelfRegistered}, false, true},
		{"locked", []string{csv.FlagApproved, csv.FlagLocked}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.addUser(t, "user@example.com", tc.flags...)
			pa := f.passwordAuth(tc.required)

			_, err := pa.Authenticate(context.Background(), "user@example.com", "192.0.2.1", "correct-password")
			if tc.allowed && err != nil {
				t.Errorf("refused: %v", err)
			}
			if !tc.allowed && err == nil {
				t.Error("allowed")
			}
		})
	}
}

// Unknown addresses must pay for a hash too.  The comparison is deliberately
// loose: an unprotected path answers in microseconds, a bcrypt check in tens of
// milliseconds.
func TestLoginTimingDoesNotRevealUnknownAddresses(t *testing.T) {
	f := newFixture(t)
	f.hasher = password.NewHasher("bcrypt", 10, password.Argon2idParams{
		Time: 1, Memory: 1024, Parallel: 1, SaltLength: 16, KeyLength: 32,
	})
	f.addUser(t, "known@example.com")
	pa := f.passwordAuth(false)

	timed := func(addr string) time.Duration {
		start := time.Now()
		if _, err := pa.Authenticate(context.Background(), addr, "192.0.2.1", "wrong-password"); err == nil {
			t.Fatalf("%s: login succeeded", addr)
		}
		return time.Since(start)
	}
	known := timed("known@example.com")
	unknown := timed("nobody@example.com")
	if unknown < known/4 {
		t.Errorf("unknown address took %s, known %s", unknown, known)
	}
}

func TestLoginRateLimitIsConfigurable(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "user@example.com")
	pa := auth.NewPasswordAuth(
		auth.NewAccountPolicy(f.backend, false),
		f.hasher, f.cookies, f.sessions, f.logger,
		2, 300, // two failures, not the old fixed five
	)
	for i := 0; i < 2; i++ {
		_, err := pa.Authenticate(context.Background(), "user@example.com", "192.0.2.1", "wrong")
		if errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("attempt %d limited early", i)
		}
	}
	_, err := pa.Authenticate(context.Background(), "user@example.com", "192.0.2.1", "correct-password")
	if !errors.Is(err, auth.ErrRateLimited) {
		t.Errorf("third attempt: got %v, want ErrRateLimited", err)
	}
}

func TestSessionLifetimeFollowsCookieMaxAge(t *testing.T) {
	f := newFixture(t) // cookie_max_age 3600
	f.addUser(t, "user@example.com")
	pa := f.passwordAuth(false)

	if _, err := pa.Authenticate(context.Background(), "user@example.com", "192.0.2.1", "correct-password"); err != nil {
		t.Fatal(err)
	}
	var expires time.Time
	if err := f.db.QueryRow(`SELECT expires_at FROM sessions WHERE user_email = ?`, "user@example.com").Scan(&expires); err != nil {
		t.Fatal(err)
	}
	if left := time.Until(expires); left > 2*time.Hour || left < 30*time.Minute {
		t.Errorf("session lasts %s, want about an hour", left)
	}
}

// An argon2id hash in users.csv that the argon2 package cannot run with (here
// p=0, which made it panic) refuses the password like a wrong one.
func TestMalformedHashRefusesPasswordLogin(t *testing.T) {
	f := newFixture(t)
	bad := "$argon2id$v=19$m=64,t=1,p=0$c2FsdHNhbHRzYWx0c2FsdA$" +
		"a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U"
	if err := f.backend.CreateUser("user@example.com", bad, "argon2id", nil); err != nil {
		t.Fatal(err)
	}
	pa := f.passwordAuth(false)
	if _, err := pa.Authenticate(context.Background(), "user@example.com", "192.0.2.1", "correct-password"); err == nil {
		t.Fatal("signed in with a malformed hash")
	}
	if n := f.sessionCount(t, "user@example.com"); n != 0 {
		t.Errorf("%d sessions created", n)
	}
}
