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

	"github.com/obtusenet/signet/internal/apiclient"
	"github.com/obtusenet/signet/internal/cookie"
	"github.com/obtusenet/signet/internal/db"
	"github.com/obtusenet/signet/internal/logging"
	"github.com/obtusenet/signet/internal/session"
)

func newValidateTestServer(t *testing.T, rateLimit int) (*Server, *cookie.CookieManager, string) {
	t.Helper()

	d, err := db.New(":memory:")
	if err != nil {
		t.Fatalf("opening db: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	logger, err := logging.New(false, "debug")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}

	cm := cookie.NewCookieManager("signetid", "", 3600, []byte("test-secret"))
	s := &Server{
		cookieMgr:    cm,
		sessionStore: session.NewStore(d.DB()),
		apiClients:   apiclient.NewStore(d.DB()),
		apiLimiter:   apiclient.NewLimiter(rateLimit, time.Minute),
		logger:       logger,
	}

	key, err := s.apiClients.Create(context.Background(), "test-app", []string{"https://app.example.com"})
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}
	return s, cm, key
}

func validateRequest(t *testing.T, s *Server, key, headerCookie, body string) (int, map[string]interface{}, http.Header) {
	t.Helper()

	var r *http.Request
	if body != "" {
		r = httptest.NewRequest("POST", "/api/v1/validate", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest("POST", "/api/v1/validate", nil)
	}
	if key != "" {
		r.Header.Set("X-API-Key", key)
	}
	if headerCookie != "" {
		r.Header.Set("Cookie", "signetid="+headerCookie)
	}

	w := httptest.NewRecorder()
	s.handleValidate(w, r)

	var out map[string]interface{}
	body2 := w.Body.String()
	if body2 != "" {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("response is not JSON (%q): %v", body2, err)
		}
	}
	return w.Code, out, w.Header()
}

func TestValidateRequiresAPIKey(t *testing.T) {
	s, _, _ := newValidateTestServer(t, 10)

	code, body, _ := validateRequest(t, s, "", "", "")
	if code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", code)
	}
	if body["valid"] != false {
		t.Errorf("valid = %v, want false", body["valid"])
	}
	if body["error"] == "" || body["error"] == nil {
		t.Error("no error message")
	}
}

func TestValidateRejectsUnknownKey(t *testing.T) {
	s, _, _ := newValidateTestServer(t, 10)

	code, body, _ := validateRequest(t, s, "sk_nope", "", "")
	if code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", code)
	}
	if body["valid"] != false {
		t.Errorf("valid = %v", body["valid"])
	}
}

func TestValidateSessionFromCookieHeader(t *testing.T) {
	s, cm, key := newValidateTestServer(t, 10)
	createTestSession(t, s.sessionStore, "tok-hdr", `{"role":"admin"}`)

	code, body, _ := validateRequest(t, s, key, cm.CreateAuthCookie("tok-hdr").Value, "")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %v)", code, body)
	}
	if body["valid"] != true || body["user"] != "test@localhost" || body["method"] != "password" {
		t.Errorf("body = %v", body)
	}
	claims, ok := body["claims"].(map[string]interface{})
	if !ok || claims["role"] != "admin" {
		t.Errorf("claims = %v", body["claims"])
	}
}

func TestValidateBodyCookieWinsOverHeader(t *testing.T) {
	s, cm, key := newValidateTestServer(t, 10)
	createTestSession(t, s.sessionStore, "good", `{}`)

	good := cm.CreateAuthCookie("good").Value
	bad := "bogus:deadbeef"

	// Header invalid, body valid -> success.
	code, body, _ := validateRequest(t, s, key, bad, `{"cookie":"`+good+`"}`)
	if code != http.StatusOK || body["valid"] != true {
		t.Errorf("body should win: status=%d body=%v", code, body)
	}

	// Header valid, body invalid -> failure, proving precedence.
	code, body, _ = validateRequest(t, s, key, good, `{"cookie":"`+bad+`"}`)
	if code != http.StatusUnauthorized || body["valid"] != false {
		t.Errorf("body should win: status=%d body=%v", code, body)
	}
}

func TestValidateRejectsBadCookie(t *testing.T) {
	s, _, key := newValidateTestServer(t, 10)

	for _, c := range []string{"bogus:deadbeef", "no-colon"} {
		code, body, _ := validateRequest(t, s, key, c, "")
		if code != http.StatusUnauthorized {
			t.Errorf("%q: status = %d, want 401", c, code)
		}
		if body["valid"] != false {
			t.Errorf("%q: valid = %v", c, body["valid"])
		}
	}
}

func TestValidateRateLimit(t *testing.T) {
	s, cm, key := newValidateTestServer(t, 2)
	createTestSession(t, s.sessionStore, "tok-rate", `{}`)
	ck := cm.CreateAuthCookie("tok-rate").Value

	for i := 0; i < 2; i++ {
		if code, _, _ := validateRequest(t, s, key, ck, ""); code != http.StatusOK {
			t.Fatalf("call %d: status = %d", i, code)
		}
	}
	code, body, _ := validateRequest(t, s, key, ck, "")
	if code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", code)
	}
	if body["valid"] != false {
		t.Errorf("valid = %v", body["valid"])
	}
}

func TestValidateRejectsWrongMethod(t *testing.T) {
	s, _, key := newValidateTestServer(t, 10)

	r := httptest.NewRequest("GET", "/api/v1/validate", nil)
	r.Header.Set("X-API-Key", key)
	w := httptest.NewRecorder()
	s.handleValidate(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestValidateCORS(t *testing.T) {
	s, _, key := newValidateTestServer(t, 10)

	// Preflight from an allowed origin.
	r := httptest.NewRequest("OPTIONS", "/api/v1/validate", nil)
	r.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	s.handleValidate(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("ACAO = %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "X-API-Key") {
		t.Errorf("ACAH = %q", got)
	}

	// Preflight from an unknown origin.
	r = httptest.NewRequest("OPTIONS", "/api/v1/validate", nil)
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	s.handleValidate(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("disallowed preflight status = %d, want 403", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO set for a disallowed origin: %q", got)
	}

	_ = key
}
