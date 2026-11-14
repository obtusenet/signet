// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/config"
)

func newWebAuthnServer(t *testing.T, limit int) *Server {
	t.Helper()
	first, backend := newRegisterServer(t, "disabled")
	cfg := *first.cfg
	cfg.AuthMethods = map[string]string{"webauthn": "enabled"}
	cfg.RPID = "signet.example"
	cfg.WebAuthnOrigins = []string{"https://signet.example"}
	cfg.WebAuthnRateLimit = limit
	cfg.TrustedProxies = []string{"192.0.2.1"} // httptest's default peer
	s := New(&cfg, first.logger, first.db, backend)
	if s.webauthnHandler == nil {
		t.Fatal("WebAuthn did not start")
	}
	return s
}

func webauthnCall(s *Server, method, path, from string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("X-Forwarded-For", from)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w
}

func TestWebAuthnCeremonyStepsShareARequesterBudget(t *testing.T) {
	s := newWebAuthnServer(t, 4)
	steps := []string{
		"/webauthn/authenticate/start?email=a@example.com",
		"/webauthn/authenticate/finish?email=a@example.com&ceremony=x",
		"/webauthn/register/start",
		"/webauthn/register/finish?ceremony=x",
	}
	for _, path := range steps {
		if w := webauthnCall(s, http.MethodPost, path, "192.0.2.1"); w.Code == http.StatusTooManyRequests {
			t.Fatalf("%s limited too early", path)
		}
	}
	for _, path := range steps {
		w := webauthnCall(s, http.MethodPost, path, "192.0.2.1")
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("%s: status %d, want 429", path, w.Code)
		}
		if got := w.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("%s: Content-Type %q", path, got)
		}
		if !strings.Contains(w.Body.String(), `"success":false`) {
			t.Errorf("%s: body %q", path, w.Body)
		}
	}
}

// One requester's flood must not stop anyone else signing in with the same address.
func TestWebAuthnBudgetIsPerRequesterNotPerAddress(t *testing.T) {
	s := newWebAuthnServer(t, 2)
	path := "/webauthn/authenticate/start?email=victim@example.com"
	for i := 0; i < 3; i++ {
		webauthnCall(s, http.MethodPost, path, "192.0.2.1")
	}
	if w := webauthnCall(s, http.MethodPost, path, "192.0.2.1"); w.Code != http.StatusTooManyRequests {
		t.Errorf("the flooder got %d", w.Code)
	}
	if w := webauthnCall(s, http.MethodPost, path, "192.0.2.2"); w.Code == http.StatusTooManyRequests {
		t.Error("another requester was limited for the same address")
	}
}

// Listing and removing keys need a session, so they are not ceremony steps.
func TestWebAuthnKeyManagementIsNotLimited(t *testing.T) {
	s := newWebAuthnServer(t, 1)
	for i := 0; i < 3; i++ {
		if w := webauthnCall(s, http.MethodGet, "/webauthn/credentials", "192.0.2.1"); w.Code == http.StatusTooManyRequests {
			t.Fatal("limited")
		}
	}
}

func registerFrom(s *Server, addr, from, password string) *httptest.ResponseRecorder {
	form := url.Values{"email": {addr}, "password": {password}}
	r := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Forwarded-For", from)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w
}

func newLimitedRegisterServer(t *testing.T, limit int) *Server {
	t.Helper()
	first, backend := newRegisterServer(t, "enabled")
	cfg := *first.cfg
	cfg.RegisterRateLimit = limit
	cfg.TrustedProxies = []string{"192.0.2.1"} // httptest's default peer
	return New(&cfg, first.logger, first.db, backend)
}

func TestRegisterLimitStopsBeforeCreatingAnAccount(t *testing.T) {
	s := newLimitedRegisterServer(t, 2)
	for i := 0; i < 2; i++ {
		if w := registerFrom(s, fmt.Sprintf("u%d@example.com", i), "192.0.2.1", "long-enough-password"); w.Code != http.StatusFound {
			t.Fatalf("attempt %d: status %d", i, w.Code)
		}
	}
	if w := registerFrom(s, "over@example.com", "192.0.2.1", "long-enough-password"); w.Code != http.StatusTooManyRequests {
		t.Errorf("status %d, want 429", w.Code)
	}
	if _, err := s.backend.GetUser("over@example.com"); err == nil {
		t.Error("the account was created")
	}
	if w := registerFrom(s, "other@example.com", "192.0.2.2", "long-enough-password"); w.Code != http.StatusFound {
		t.Errorf("another requester: status %d", w.Code)
	}
}

func TestRegisterTyposDoNotUseTheBudget(t *testing.T) {
	s := newLimitedRegisterServer(t, 1)
	for i := 0; i < 3; i++ {
		if w := registerFrom(s, "not-an-address", "192.0.2.1", "long-enough-password"); w.Code != http.StatusBadRequest {
			t.Fatalf("status %d", w.Code)
		}
	}
	if w := registerFrom(s, "real@example.com", "192.0.2.1", "long-enough-password"); w.Code != http.StatusFound {
		t.Errorf("status %d", w.Code)
	}
}

func TestDisabledRegistrationStillAnswers403(t *testing.T) {
	first, _ := newRegisterServer(t, "disabled")
	first.registerLimiter = nil // never reached while disabled
	if w := registerFrom(first, "a@example.com", "192.0.2.1", "long-enough-password"); w.Code != http.StatusForbidden {
		t.Errorf("status %d", w.Code)
	}
}

// A client must not get a fresh budget by inventing a new address each time.
func TestForgedForwardedForDoesNotBuyABudget(t *testing.T) {
	first, backend := newRegisterServer(t, "disabled")
	cfg := *first.cfg
	cfg.AuthMethods = map[string]string{"webauthn": "enabled"}
	cfg.RPID = "signet.example"
	cfg.WebAuthnOrigins = []string{"https://signet.example"}
	cfg.WebAuthnRateLimit = 2
	s := New(&cfg, first.logger, first.db, backend) // no trusted proxies

	path := "/webauthn/authenticate/start?email=a@example.com"
	for i := 0; i < 2; i++ {
		webauthnCall(s, http.MethodPost, path, fmt.Sprintf("198.51.100.%d", i))
	}
	if w := webauthnCall(s, http.MethodPost, path, "198.51.100.99"); w.Code != http.StatusTooManyRequests {
		t.Errorf("a forged address got status %d, want 429", w.Code)
	}
}

// The PIN budgets go through the same resolver as everything else.
func TestPINBudgetIgnoresAForgedForwardedFor(t *testing.T) {
	program, _, _ := fakeSendmail(t, "")
	s, backend := newMailServer(t, program)
	if err := backend.CreateUser("user@example.com", "!", "bcrypt", []string{csv.FlagApproved}); err != nil {
		t.Fatal(err)
	}
	cfg := *s.cfg
	cfg.EmailRateLimit = 2
	limited := New(&cfg, s.logger, s.db, backend)

	send := func(addr, from string) int {
		r := httptest.NewRequest(http.MethodPost, "/email-pin/send", strings.NewReader(`{"email":"`+addr+`"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-For", from)
		w := httptest.NewRecorder()
		limited.mux.ServeHTTP(w, r)
		return w.Code
	}
	// Different target addresses, so only the requester budget can refuse.
	for i := 0; i < 2; i++ {
		send(fmt.Sprintf("u%d@example.com", i), fmt.Sprintf("198.51.100.%d", i))
	}
	if code := send("u9@example.com", "198.51.100.99"); code != http.StatusTooManyRequests {
		t.Errorf("a forged address got status %d, want 429", code)
	}
}

// Switched on without saying where it applies, WebAuthn stays off: no routes,
// and no button on the login page.
func TestWebAuthnNeedsAnRPID(t *testing.T) {
	first, backend := newRegisterServer(t, "disabled")
	for name, change := range map[string]func(*config.Config){
		"no RP ID":  func(c *config.Config) { c.RPID = ""; c.WebAuthnOrigins = []string{"https://signet.example"} },
		"no origin": func(c *config.Config) { c.RPID = "signet.example"; c.WebAuthnOrigins = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := *first.cfg
			cfg.AuthMethods = map[string]string{"webauthn": "enabled"}
			change(&cfg)
			s := New(&cfg, first.logger, first.db, backend)
			if s.webauthnHandler != nil {
				t.Fatal("WebAuthn came up")
			}
			w := httptest.NewRecorder()
			s.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/webauthn/keys", nil))
			if w.Code != http.StatusNotFound {
				t.Errorf("/webauthn/keys: %d", w.Code)
			}
		})
	}
}

// Instances sharing a database share cookie_secret, and must offer the same decoy
// keys, or a request to each would show that an address has no real one.
func TestDecoyKeysFollowCookieSecret(t *testing.T) {
	offered := func(secret string) string {
		first, backend := newRegisterServer(t, "disabled")
		cfg := *first.cfg
		cfg.AuthMethods = map[string]string{"webauthn": "enabled"}
		cfg.RPID = "signet.example"
		cfg.WebAuthnOrigins = []string{"https://signet.example"}
		cfg.CookieSecret = secret
		s := New(&cfg, first.logger, first.db, backend)
		w := webauthnCall(s, http.MethodPost, "/webauthn/authenticate/start?email=nobody@example.com", "192.0.2.1")
		_, after, found := strings.Cut(w.Body.String(), `"allowCredentials":`)
		if w.Code != http.StatusOK || !found {
			t.Fatalf("%d: %s", w.Code, w.Body)
		}
		return after[:strings.Index(after, "]")]
	}
	const one, two = "a-secret-long-enough-for-the-test-one", "a-secret-long-enough-for-the-test-two"
	if offered(one) != offered(one) {
		t.Error("two instances with one secret offered different keys")
	}
	if offered(one) == offered(two) {
		t.Error("the keys did not depend on the secret")
	}
}
