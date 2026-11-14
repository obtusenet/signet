// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/obtusenet/signet/internal/backend/csv"
)

// originServer has one account, and returns to apps.example without a port.
func originServer(t *testing.T) *Server {
	t.Helper()
	s, backend := newRegisterServer(t, "disabled")
	hash, err := s.hasher.Hash("correct-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.CreateUser("user@example.com", hash, "bcrypt", []string{csv.FlagApproved}); err != nil {
		t.Fatal(err)
	}
	s.cfg.AllowedRedirectHosts = []string{"apps.example"}
	return s
}

func loginFrom(s *Server, headers map[string]string) *httptest.ResponseRecorder {
	form := url.Values{"email": {"user@example.com"}, "password": {"correct-password"}}
	r := httptest.NewRequest(http.MethodPost, "https://signet.example/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	return w
}

func TestCrossOriginLoginIsRefused(t *testing.T) {
	s := originServer(t)
	for name, headers := range map[string]map[string]string{
		"another site":              {"Origin": "https://evil.example"},
		"another site, fetch-site":  {"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
		"fetch-site alone":          {"Sec-Fetch-Site": "cross-site"},
		"a sibling subdomain":       {"Origin": "https://evil.signet.example", "Sec-Fetch-Site": "same-site"},
		"a sandboxed page":          {"Origin": "null"},
		"the same host, other port": {"Origin": "https://signet.example:8443"},
		"a listed host, other port": {"Origin": "https://apps.example:8443"},
	} {
		w := loginFrom(s, headers)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", name, w.Code)
		}
		if strings.Contains(w.Header().Get("Set-Cookie"), s.cfg.CookieName) {
			t.Errorf("%s: a session cookie was set", name)
		}
	}
}

func TestLegitimateLoginsPassTheOriginCheck(t *testing.T) {
	s := originServer(t)
	for name, headers := range map[string]map[string]string{
		"no browser headers, as curl": {},
		"its own origin, over HTTP":   {"Origin": "https://signet.example"},
		"its own origin, fetch-site":  {"Origin": "https://signet.example", "Sec-Fetch-Site": "same-origin"},
		"a proxy changed the Host":    {"Origin": "https://public.example", "Sec-Fetch-Site": "same-origin"},
		"a listed application":        {"Origin": "https://apps.example", "Sec-Fetch-Site": "cross-site"},
	} {
		if w := loginFrom(s, headers); w.Code != http.StatusFound {
			t.Errorf("%s: status %d, want 302", name, w.Code)
		}
	}
}

func TestOriginCheckCoversEveryStateChangingRoute(t *testing.T) {
	s := originServer(t)
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/logout"},
		{http.MethodPost, "/register"},
		{http.MethodPost, "/recover"},
		{http.MethodPost, "/email-pin/send"},
		{http.MethodPost, "/webauthn/authenticate/start"},
		{http.MethodDelete, "/webauthn/credentials/x"},
		{http.MethodPut, "/login"},
	} {
		r := httptest.NewRequest(route.method, "https://signet.example"+route.path, nil)
		r.Header.Set("Origin", "https://evil.example")
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s: status %d, want 403", route.method, route.path, w.Code)
		}
	}
}

func TestOriginCheckLeavesReadsAndTheAPIAlone(t *testing.T) {
	s := originServer(t)
	for _, route := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/health", http.StatusOK},
		{http.MethodGet, "/session", http.StatusUnauthorized},
		{http.MethodPost, "/api/v1/validate", http.StatusUnauthorized}, // no key; CORS is its own
	} {
		r := httptest.NewRequest(route.method, "https://signet.example"+route.path, nil)
		r.Header.Set("Origin", "https://evil.example")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		if w.Code != route.want {
			t.Errorf("%s %s: status %d, want %d", route.method, route.path, w.Code, route.want)
		}
	}
}

func TestLoginLimitsFollowTheConfig(t *testing.T) {
	build := func(t *testing.T, addressLimit, sourceLimit string) *Server {
		first, backend := newRegisterServer(t, "disabled")
		cfg := *first.cfg
		cfg.LoginAddressLimit = addressLimit
		cfg.LoginSourceLimit = sourceLimit
		cfg.LoginRateLimit = 2
		cfg.LoginSourceRateLimit = 3
		cfg.TrustedProxies = []string{"192.0.2.1"} // httptest's default peer
		s := New(&cfg, first.logger, first.db, backend)
		hash, err := s.hasher.Hash("correct-password")
		if err != nil {
			t.Fatal(err)
		}
		if err := backend.CreateUser("user@example.com", hash, "bcrypt", []string{csv.FlagApproved}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	attempt := func(s *Server, from, addr, password string) int {
		form := url.Values{"email": {addr}, "password": {password}}
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-Forwarded-For", from)
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		return w.Code
	}
	const user = "user@example.com"

	t.Run("address only", func(t *testing.T) {
		s := build(t, "enabled", "disabled")
		for i := 0; i < 2; i++ {
			attempt(s, "198.51.100.1", user, "wrong")
		}
		if got := attempt(s, "198.51.100.2", user, "correct-password"); got != http.StatusUnauthorized {
			t.Errorf("status %d: the address limit should hold from any source", got)
		}
	})
	t.Run("source only", func(t *testing.T) {
		s := build(t, "disabled", "enabled")
		for i := 0; i < 3; i++ {
			attempt(s, "198.51.100.1", user, "wrong")
		}
		if got := attempt(s, "198.51.100.2", user, "correct-password"); got != http.StatusFound {
			t.Errorf("status %d: another client should not be blocked", got)
		}
		for i := 0; i < 3; i++ {
			attempt(s, "198.51.100.3", user, "wrong")
		}
		if got := attempt(s, "198.51.100.3", user, "correct-password"); got != http.StatusUnauthorized {
			t.Errorf("status %d: that client should be limited", got)
		}
	})
	t.Run("both off", func(t *testing.T) {
		s := build(t, "disabled", "disabled")
		for i := 0; i < 10; i++ {
			attempt(s, "198.51.100.1", user, "wrong")
		}
		if got := attempt(s, "198.51.100.1", user, "correct-password"); got != http.StatusFound {
			t.Errorf("status %d: nothing should be limiting", got)
		}
	})
}
