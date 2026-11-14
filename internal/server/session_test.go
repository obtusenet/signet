// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/auth"
	"github.com/obtusenet/signet/internal/claims"
	"github.com/obtusenet/signet/internal/config"
	"github.com/obtusenet/signet/internal/cookie"
	"github.com/obtusenet/signet/internal/db"
	"github.com/obtusenet/signet/internal/logging"
	"github.com/obtusenet/signet/internal/session"
)

// newSessionTestServer builds a Server with an in-memory database and a
// cookie manager, which is all /session and /logout need.
func newSessionTestServer(t *testing.T) (*Server, *cookie.CookieManager, *session.Store) {
	t.Helper()

	store, err := db.New(":memory:")
	if err != nil {
		t.Fatalf("opening in-memory db: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	logger, err := logging.New(false, "debug")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}

	cm := cookie.NewCookieManager("signetid", "", 3600, []byte("test-secret"))
	ss := session.NewStore(store.DB())

	return &Server{
		cookieMgr:      cm,
		sessionStore:   ss,
		logger:         logger,
		refreshLimiter: auth.NewEmailRateLimiter(2, time.Minute),
	}, cm, ss
}

func createTestSession(t *testing.T, ss *session.Store, token, claims string) {
	t.Helper()
	err := ss.Create(context.Background(), &session.Session{
		Token:      token,
		UserEmail:  "test@localhost",
		AuthMethod: "password",
		Claims:     claims,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}
}

func getSession(t *testing.T, s *Server, authCookie *http.Cookie) (int, map[string]interface{}) {
	t.Helper()
	r := httptest.NewRequest("GET", "/session", nil)
	if authCookie != nil {
		r.AddCookie(authCookie)
	}
	w := httptest.NewRecorder()
	s.handleSession(w, r)

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response %q: %v", w.Body.String(), err)
	}
	return w.Code, body
}

// getValidSession asserts a 200 and returns the body.
func getValidSession(t *testing.T, s *Server, authCookie *http.Cookie) map[string]interface{} {
	t.Helper()
	code, body := getSession(t, s, authCookie)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	return body
}

// getInvalidSession asserts a 401 and returns the body.
func getInvalidSession(t *testing.T, s *Server, authCookie *http.Cookie) map[string]interface{} {
	t.Helper()
	code, body := getSession(t, s, authCookie)
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
	if body["valid"] != false {
		t.Errorf("valid = %v, want false", body["valid"])
	}
	if _, ok := body["error"]; !ok {
		t.Error("401 body has no error field")
	}
	return body
}

func TestSessionWithoutCookie(t *testing.T) {
	s, _, _ := newSessionTestServer(t)

	getInvalidSession(t, s, nil)
}

func TestSessionReturnsStoredClaims(t *testing.T) {
	s, cm, ss := newSessionTestServer(t)
	createTestSession(t, ss, "token-1", `{"role":"admin","dept":"IT"}`)

	body := getValidSession(t, s, cm.CreateAuthCookie("token-1"))
	if body["valid"] != true {
		t.Fatalf("valid = %v, want true", body["valid"])
	}
	if body["user"] != "test@localhost" {
		t.Errorf("user = %v", body["user"])
	}
	if body["method"] != "password" {
		t.Errorf("method = %v", body["method"])
	}
	for _, k := range []string{"created_at", "expires_at"} {
		if _, ok := body[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	claims, ok := body["claims"].(map[string]interface{})
	if !ok {
		t.Fatalf("claims is not an object: %T", body["claims"])
	}
	if claims["role"] != "admin" || claims["dept"] != "IT" {
		t.Errorf("claims = %v", claims)
	}
}

func TestSessionWithoutClaimsReturnsEmptyObject(t *testing.T) {
	s, cm, ss := newSessionTestServer(t)
	createTestSession(t, ss, "token-2", "")

	body := getValidSession(t, s, cm.CreateAuthCookie("token-2"))
	claims, ok := body["claims"].(map[string]interface{})
	if !ok {
		t.Fatalf("claims is not an object: %T", body["claims"])
	}
	if len(claims) != 0 {
		t.Errorf("claims = %v, want {}", claims)
	}
}

func TestSessionRejectsForgedCookie(t *testing.T) {
	s, cm, ss := newSessionTestServer(t)
	createTestSession(t, ss, "token-3", "{}")

	forged := &http.Cookie{Name: "signetid", Value: "token-3:deadbeef"}
	getInvalidSession(t, s, forged)
	_ = cm
}

func TestLogoutRevokesSessionAndClearsCookie(t *testing.T) {
	s, cm, ss := newSessionTestServer(t)
	createTestSession(t, ss, "token-4", "{}")

	r := httptest.NewRequest("POST", "/logout", nil)
	r.AddCookie(cm.CreateAuthCookie("token-4"))
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	s.handleLogout(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["success"] != true {
		t.Errorf("success = %v", body["success"])
	}

	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == "signetid" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout did not expire the session cookie")
	}

	// The session is gone: the same cookie must no longer be valid.
	if _, err := ss.Get(context.Background(), "token-4"); err == nil {
		t.Error("session still present after logout")
	}
	getInvalidSession(t, s, cm.CreateAuthCookie("token-4"))
}

func TestLogoutWithoutSessionStillSucceeds(t *testing.T) {
	s, _, _ := newSessionTestServer(t)

	r := httptest.NewRequest("GET", "/logout", nil)
	w := httptest.NewRecorder()
	s.handleLogout(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
}

// TestSessionRefreshRunsHook covers ?claims=refresh: the hook is re-run, the
// session row updated, and later plain calls return the stored fresh claims.
func TestSessionRefreshRunsHook(t *testing.T) {
	s, cm, ss := newSessionTestServer(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "hook.sh")
	body := "#!/bin/sh\nread line\n" +
		"echo '{\"type\":\"claim_response\",\"claims\":{\"role\":\"operator\",\"level\":7}}'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("writing hook: %v", err)
	}
	s.claimsHook = claims.NewClaimsHook(config.ClaimsHookConfig{
		Enabled:    true,
		Program:    script,
		TimeoutSec: 5,
	}, s.logger)

	createTestSession(t, ss, "token-5", `{"role":"viewer"}`)
	ck := cm.CreateAuthCookie("token-5")

	// Without the parameter the stored claims are returned unchanged.
	before := getValidSession(t, s, ck)
	if before["claims_refreshed"] != false {
		t.Errorf("claims_refreshed = %v, want false", before["claims_refreshed"])
	}
	if before["claims"].(map[string]interface{})["role"] != "viewer" {
		t.Errorf("claims = %v, want stored viewer claims", before["claims"])
	}

	// With ?claims=refresh the hook runs and the answer is returned.
	r := httptest.NewRequest("GET", "/session?claims=refresh", nil)
	r.AddCookie(ck)
	w := httptest.NewRecorder()
	s.handleSession(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var refreshed map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &refreshed); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if refreshed["claims_refreshed"] != true {
		t.Errorf("claims_refreshed = %v, want true", refreshed["claims_refreshed"])
	}
	fresh := refreshed["claims"].(map[string]interface{})
	if fresh["role"] != "operator" || fresh["level"] != float64(7) {
		t.Errorf("claims = %v, want the hook's answer", fresh)
	}

	// The refreshed claims are persisted.
	after := getValidSession(t, s, ck)
	if after["claims"].(map[string]interface{})["role"] != "operator" {
		t.Errorf("stored claims = %v, want operator", after["claims"])
	}
}

// Each refresh starts a program, so an account gets a limited number; past it the
// stored claims are answered.
func TestSessionRefreshIsLimited(t *testing.T) {
	s, cm, ss := newSessionTestServer(t)
	dir := t.TempDir()
	count := filepath.Join(dir, "runs")
	script := filepath.Join(dir, "hook.sh")
	body := "#!/bin/sh\nread line\necho run >> " + count + "\n" +
		"echo '{\"type\":\"claim_response\",\"claims\":{\"role\":\"operator\"}}'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	s.claimsHook = claims.NewClaimsHook(config.ClaimsHookConfig{Enabled: true, Program: script, TimeoutSec: 5}, s.logger)
	createTestSession(t, ss, "token-7", `{"role":"viewer"}`)
	ck := cm.CreateAuthCookie("token-7")

	var got []interface{}
	for i := 0; i < 4; i++ {
		r := httptest.NewRequest("GET", "/session?claims=refresh", nil)
		r.AddCookie(ck)
		w := httptest.NewRecorder()
		s.handleSession(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("refresh %d: status %d", i, w.Code)
		}
		var answer map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
			t.Fatal(err)
		}
		got = append(got, answer["claims_refreshed"])
	}
	if want := []interface{}{true, true, false, false}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("claims_refreshed %v, want %v", got, want)
	}
	runs, _ := os.ReadFile(count)
	if n := strings.Count(string(runs), "run"); n != 2 {
		t.Errorf("the hook ran %d times, want 2", n)
	}
}

// Without a configured hook, ?claims=refresh is a no-op, not an error.
func TestSessionRefreshWithoutHookIsNoop(t *testing.T) {
	s, cm, ss := newSessionTestServer(t)
	createTestSession(t, ss, "token-6", `{"role":"viewer"}`)

	r := httptest.NewRequest("GET", "/session?claims=refresh", nil)
	r.AddCookie(cm.CreateAuthCookie("token-6"))
	w := httptest.NewRecorder()
	s.handleSession(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if body["claims_refreshed"] != false {
		t.Errorf("claims_refreshed = %v, want false", body["claims_refreshed"])
	}
	if body["claims"].(map[string]interface{})["role"] != "viewer" {
		t.Errorf("claims = %v", body["claims"])
	}
}

// A reverse proxy can copy these headers onto the upstream request after a
// forward-auth check (Caddy: forward_auth ... copy_headers Remote-User).
func TestSessionSetsRemoteUserHeader(t *testing.T) {
	s, cm, ss := newSessionTestServer(t)
	createTestSession(t, ss, "token-7", `{"role":"admin"}`)

	r := httptest.NewRequest("GET", "/session", nil)
	r.AddCookie(cm.CreateAuthCookie("token-7"))
	w := httptest.NewRecorder()
	s.handleSession(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Remote-User"); got != "test@localhost" {
		t.Errorf("Remote-User = %q, want test@localhost", got)
	}
	if got := w.Header().Get("Remote-Email"); got != "test@localhost" {
		t.Errorf("Remote-Email = %q, want test@localhost", got)
	}

	// An invalid session must not carry them.
	w = httptest.NewRecorder()
	s.handleSession(w, httptest.NewRequest("GET", "/session", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if got := w.Header().Get("Remote-User"); got != "" {
		t.Errorf("401 carries Remote-User = %q", got)
	}
}
