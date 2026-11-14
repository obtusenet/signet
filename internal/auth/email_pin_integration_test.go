// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/obtusenet/signet/internal/auth"
	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/config"
	"github.com/obtusenet/signet/internal/cookie"
	"github.com/obtusenet/signet/internal/db"
	"github.com/obtusenet/signet/internal/email"
	"github.com/obtusenet/signet/internal/logging"
	"github.com/obtusenet/signet/internal/password"
	"github.com/obtusenet/signet/internal/session"
)

func TestEmailPINIntegration(t *testing.T) {
	// Setup
	logger, err := logging.New(false, "debug")
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	cfg := config.DefaultConfig()

	// Create temporary directory for CSV and DB
	tmpDir, err := os.MkdirTemp("", "signet-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create in-memory database
	dbStore, err := db.New(filepath.Join(tmpDir, "sessions.db"))
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}

	// Create backend
	backend, err := csv.New(filepath.Join(tmpDir, "users.csv"))
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Create password hasher
	hasher := password.NewHasher(cfg.PasswordHashAlg, cfg.BcryptCost, password.Argon2idParams{
		Time:       cfg.Argon2idTime,
		Memory:     cfg.Argon2idMemory,
		Parallel:   cfg.Argon2idParallel,
		SaltLength: cfg.Argon2idSaltLen,
		KeyLength:  cfg.Argon2idKeyLen,
	})

	// Create session store
	sessionStore := session.NewStore(dbStore.DB())

	// Create email PIN auth
	emailSender := email.NewStubSender()
	pinStore, err := email.NewPINStore(dbStore.DB(), emailSender, 10*60e9) // 10 minutes
	if err != nil {
		t.Fatalf("failed to create PIN store: %v", err)
	}

	// Create cookie manager
	secret := []byte("test-secret-key-for-testing-only")
	cookieMgr := cookie.NewCookieManager(cfg.CookieName, cfg.CookieDomain, cfg.CookieMaxAge, secret)

	emailRateLimiter := auth.NewEmailRateLimiter(10, 60e9) // 10 requests per minute
	emailPINAuth := auth.NewEmailPINAuth(
		pinStore,
		auth.NewAccountPolicy(backend, false),
		sessionStore,
		cookieMgr,
		logger,
		emailRateLimiter,
		3,
		30*60e9,
	)

	// Create password auth
	_ = auth.NewPasswordAuth(
		auth.NewAccountPolicy(backend, false),
		hasher,
		cookieMgr,
		sessionStore,
		logger,
		cfg.LoginRateLimit,
		cfg.LoginRateWindow,
	)

	// Create a test user
	err = backend.CreateUser("test@example.com", "password123", "argon2id", nil)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Test 1: Send PIN request
	t.Run("SendPINRequest", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/email-pin/send", nil)
		r.Body = io.NopCloser(bytes.NewBufferString(`{"email":"test@example.com"}`))
		r.Header.Set("Content-Type", "application/json")

		emailPINAuth.SendPINRequest(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp["success"] != true {
			t.Errorf("expected success to be true, got %v", resp["success"])
		}

		// Check that email was sent (stub)
		sentEmails := emailSender.GetSentEmails()
		if len(sentEmails) != 1 {
			t.Fatalf("expected 1 sent email, got %d", len(sentEmails))
		}

		if sentEmails[0].To != "test@example.com" {
			t.Errorf("expected email to test@example.com, got %s", sentEmails[0].To)
		}
	})

	// Test 2: Verify PIN
	t.Run("VerifyPIN", func(t *testing.T) {
		// Get the PIN from the sent email
		sentEmails := emailSender.GetSentEmails()
		pin := extractPINFromEmail(sentEmails[0].Body)

		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/email-pin/verify", nil)
		r.Body = io.NopCloser(bytes.NewBufferString(`{"email":"test@example.com","pin":"` + pin + `"}`))
		r.Header.Set("Content-Type", "application/json")

		emailPINAuth.VerifyPINRequest(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp["success"] != true {
			t.Errorf("expected success to be true, got %v", resp["success"])
		}

		// The response must carry the signed session cookie.
		var authCookie *http.Cookie
		for _, c := range w.Result().Cookies() {
			if c.Name == cfg.CookieName {
				authCookie = c
			}
		}
		if authCookie == nil {
			t.Fatal("verify did not set the session cookie")
		}
		if _, err := cookieMgr.ValidateAuthCookie(&http.Request{Header: http.Header{"Cookie": {authCookie.Name + "=" + authCookie.Value}}}); err != nil {
			t.Errorf("cookie does not validate: %v", err)
		}
	})

	// Test 3: Verify PIN twice (should fail on second attempt)
	t.Run("VerifyPINReuse", func(t *testing.T) {
		// Get the PIN from the sent email
		sentEmails := emailSender.GetSentEmails()
		pin := extractPINFromEmail(sentEmails[0].Body)

		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/email-pin/verify", nil)
		r.Body = io.NopCloser(bytes.NewBufferString(`{"email":"test@example.com","pin":"` + pin + `"}`))
		r.Header.Set("Content-Type", "application/json")

		emailPINAuth.VerifyPINRequest(w, r)

		if w.Code == http.StatusOK {
			t.Error("expected failure for reused PIN, but got success")
		}
	})

	// Test 4: Verify wrong PIN
	t.Run("VerifyWrongPIN", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/email-pin/verify", nil)
		r.Body = io.NopCloser(bytes.NewBufferString(`{"email":"test@example.com","pin":"000000"}`))
		r.Header.Set("Content-Type", "application/json")

		emailPINAuth.VerifyPINRequest(w, r)

		if w.Code == http.StatusOK {
			t.Error("expected failure for wrong PIN, but got success")
		}
	})

	// Test 5: Rate limiting
	t.Run("RateLimiting", func(t *testing.T) {
		// Use up the rate limit
		for i := 0; i < 10; i++ {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/email-pin/send", nil)
			r.Body = io.NopCloser(bytes.NewBufferString(`{"email":"test@example.com"}`))
			r.Header.Set("Content-Type", "application/json")

			emailPINAuth.SendPINRequest(w, r)
		}

		// Next request should be rate limited
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/email-pin/send", nil)
		r.Body = io.NopCloser(bytes.NewBufferString(`{"email":"test@example.com"}`))
		r.Header.Set("Content-Type", "application/json")

		emailPINAuth.SendPINRequest(w, r)

		if w.Code != http.StatusTooManyRequests {
			t.Errorf("expected status 429, got %d", w.Code)
		}
	})
}

// extractPINFromEmail extracts the 6-digit PIN from the email body
func extractPINFromEmail(body string) string {
	for i, c := range body {
		if c >= '0' && c <= '9' {
			pin := body[i : i+6]
			return pin
		}
	}
	return ""
}
