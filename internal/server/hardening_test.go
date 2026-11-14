// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/config"
	"github.com/obtusenet/signet/internal/db"
	"github.com/obtusenet/signet/internal/logging"
)

func newRegisterServer(t *testing.T, selfRegistration string) (*Server, *csv.Backend) {
	t.Helper()
	dir := t.TempDir()
	logger, err := logging.New(false, "error")
	if err != nil {
		t.Fatal(err)
	}
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

	cfg := config.DefaultConfig()
	cfg.SelfRegistration = selfRegistration
	cfg.EmailVerification = "disabled" // these exercise direct registration
	cfg.TemplatesDir = ""
	cfg.AuthMethods = map[string]string{"password": "enabled"}
	cfg.PasswordHashAlg = "bcrypt"
	cfg.BcryptCost = 4
	return New(cfg, logger, store, backend), backend
}

func register(s *Server, addr string) *httptest.ResponseRecorder {
	form := url.Values{"email": {addr}, "password": {"long-enough-password"}}
	r := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w
}

func TestRegisterRefusedWhenDisabled(t *testing.T) {
	s, backend := newRegisterServer(t, "disabled")

	if w := register(s, "mallory@example.com"); w.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", w.Code)
	}
	if _, err := backend.GetUser("mallory@example.com"); err == nil {
		t.Error("the account was created")
	}
}

func TestRegisterAllowedWhenEnabled(t *testing.T) {
	s, backend := newRegisterServer(t, "enabled")

	if w := register(s, "new@example.com"); w.Code != http.StatusFound {
		t.Errorf("status %d, want 302", w.Code)
	}
	if _, err := backend.GetUser("new@example.com"); err != nil {
		t.Errorf("account missing: %v", err)
	}
}

// One hostile registration must not leave users.csv unreadable.
func TestRegisterRejectsAddressesThatCorruptTheCSV(t *testing.T) {
	s, backend := newRegisterServer(t, "enabled")

	for _, addr := range []string{"a@b\n#x", "a@b\rc", "#hidden@example.com", "a\t@b"} {
		if w := register(s, addr); w.Code != http.StatusBadRequest {
			t.Errorf("%q: status %d, want 400", addr, w.Code)
		}
	}
	if err := backend.Reload(); err != nil {
		t.Fatalf("users.csv no longer parses: %v", err)
	}
	users, err := backend.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 0 {
		t.Errorf("%d rows written", len(users))
	}
}

func TestSafeReturnPathRefusesAnotherHost(t *testing.T) {
	s := &Server{cfg: &config.Config{AllowedRedirectHosts: []string{"app.example.net"}}}
	r := httptest.NewRequest(http.MethodPost, "http://example.com/login", nil)

	cases := []struct{ in, want string }{
		{"/", "/"},
		{"/dashboard?a=1", "/dashboard?a=1"},
		{"http://example.com/dashboard", "/dashboard"},
		{"http://example.com", "/"},
		{"https://app.example.net/x", "https://app.example.net/x"},

		{"//evil.test/", ""},
		{`/\evil.test`, ""},
		{`/\/evil.test`, ""},
		{"/\t/evil.test", ""},
		{"/\n/evil.test", ""},
		{"http://example.com//evil.test/", ""},
		// Parsing percent-encodes the backslash, which keeps it on this host.
		{`http://example.com/\evil.test`, "/%5Cevil.test"},
		{"https://evil.test/", ""},
		{"javascript:alert(1)", ""},

		// Dot segments resolve to //evil.test/ in the browser.
		{"/.//evil.test/x", ""},
		{"/a/..//evil.test/x", ""},
		{"/%2e//evil.test/x", ""},
		{"/%2E%2E//evil.test/x", ""},
		{"/x/../login", ""},
		{"http://example.com/.//evil.test/x", ""},
		{"/%zz", ""},
		{"/a.b/c..d/?q=../x#..", "/a.b/c..d/?q=../x#.."},
	}
	for _, tc := range cases {
		if got := s.safeReturnPath(tc.in, r); got != tc.want {
			t.Errorf("safeReturnPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A mistyped listen path must never delete what it points at.
func TestListenUnixLeavesRegularFileAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.csv")
	if err := os.WriteFile(path, []byte("precious\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: &config.Config{}}

	ln, err := s.listenUnix(path)
	if err == nil {
		ln.Close()
		t.Fatal("bound over a regular file")
	}
	got, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("file is gone: %v", rerr)
	}
	if string(got) != "precious\n" {
		t.Errorf("file changed: %q", got)
	}
}

func TestPasswordLoginHonoursAuthMethods(t *testing.T) {
	s, _ := newRegisterServer(t, "disabled")
	s.cfg.AuthMethods = map[string]string{"password": "disabled"}

	form := url.Values{"email": {"a@example.com"}, "password": {"whatever"}}
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", w.Code)
	}
}

func TestConfiguredSecretLetsInstancesShareCookies(t *testing.T) {
	first, _ := newRegisterServer(t, "disabled")
	second, _ := newRegisterServer(t, "disabled")

	make := func(secret string) *Server {
		cfg := *first.cfg
		cfg.CookieSecret = secret
		return New(&cfg, first.logger, first.db, first.backend)
	}
	a, b := make(strings.Repeat("s", 64)), make(strings.Repeat("s", 64))
	other := make(strings.Repeat("t", 64))
	_ = second

	value := a.cookieMgr.CreateAuthCookie("token").Value
	if _, err := b.cookieMgr.ValidateCookieValue(value); err != nil {
		t.Errorf("same secret: %v", err)
	}
	if _, err := other.cookieMgr.ValidateCookieValue(value); err == nil {
		t.Error("a different secret accepted the cookie")
	}
}

// Without a secret a server must never sign with an empty key.
func TestUnconfiguredSecretIsNotEmpty(t *testing.T) {
	s, _ := newRegisterServer(t, "disabled")
	if len(s.cookieMgr.Secret) == 0 {
		t.Fatal("signing with an empty key")
	}
}

func TestRequestLimitsAndHeaders(t *testing.T) {
	s, _ := newRegisterServer(t, "disabled")
	h := s.handler()
	do := func(method, target string, body io.Reader, length int64) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, body)
		if length >= 0 {
			r.ContentLength = length
		} else {
			r.ContentLength = -1 // chunked: it does not say how big it is
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	for _, target := range []string{"/health", "/login", "/nosuchpage"} {
		w := do(http.MethodGet, target, nil, 0)
		if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("%s: X-Frame-Options %q", target, got)
		}
		if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options %q", target, got)
		}
	}

	big := strings.Repeat("a", maxRequestBody+1)
	w := do(http.MethodPost, "/login", strings.NewReader(big), int64(len(big)))
	if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), `"success":false`) {
		t.Errorf("declared too big: %d: %s", w.Code, w.Body)
	}
	// It lied about nothing, but said nothing either: reading stops at the limit.
	w = do(http.MethodPost, "/login", strings.NewReader("email="+big+"&password=x"), -1)
	if w.Code != http.StatusBadRequest {
		t.Errorf("undeclared too big: %d", w.Code)
	}
	// One at the limit still reaches the handler.
	ok := "email=" + strings.Repeat("a", 10) + "&password=x&pad=" + strings.Repeat("b", 1000)
	w = do(http.MethodPost, "/login", strings.NewReader(ok), int64(len(ok)))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("ordinary size: %d", w.Code)
	}
}

// What cannot be an address gets the ordinary refusal, and never a limiter entry.
func TestInvalidAddressStopsAtTheDoor(t *testing.T) {
	s, _ := newRegisterServer(t, "disabled")
	for _, address := range []string{
		"x@example.com\nINFO: User admin@example.com logged in via password",
		"no-at-sign",
		strings.Repeat("a", 300) + "@example.com",
	} {
		form := url.Values{"email": {address}, "password": {"whatever-it-is"}}.Encode()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()
		s.handleLogin(w, r)
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Invalid email or password") {
			t.Errorf("%.30q: %d: %s", address, w.Code, w.Body)
		}
	}
}
