// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package otp

import (
	"context"
	"os"
	"testing"

	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/logging"
	"github.com/obtusenet/signet/internal/password"
)

func setupTest(t *testing.T) (*OTPHandler, *csv.Backend) {
	t.Helper()

	// Create temp directory for CSV
	tmpDir, err := os.MkdirTemp("", "signet-otp-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	// Setup logger
	logger, err := logging.New(false, "debug")
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Setup CSV backend
	backend, err := csv.New(tmpDir + "/users.csv")
	if err != nil {
		t.Fatalf("failed to create CSV backend: %v", err)
	}

	// Setup password hasher
	hasher := password.NewHasher("argon2id", 12, password.Argon2idParams{
		Time:       1,
		Memory:     64,
		Parallel:   1,
		SaltLength: 16,
		KeyLength:  32,
	})

	// Create test user
	err = backend.CreateUser("test@example.com", "password123", "argon2id", []string{"self_registered", "approved"})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	handler := NewOTPHandler(backend, hasher, logger)

	return handler, backend
}

func TestEnableYubikey(t *testing.T) {
	handler, _ := setupTest(t)

	// Enable Yubikey with valid prefix (12 characters)
	err := handler.EnableYubikey(context.Background(), "test@example.com", "abcdefghijkl")
	if err != nil {
		t.Fatalf("failed to enable Yubikey: %v", err)
	}
}

func TestEnableYubikeyInvalidPrefix(t *testing.T) {
	handler, _ := setupTest(t)

	// Enable Yubikey with invalid prefix (too short)
	err := handler.EnableYubikey(context.Background(), "test@example.com", "short")
	if err == nil {
		t.Fatal("expected error for invalid prefix, got nil")
	}
}

func TestVerifyYubikey(t *testing.T) {
	handler, _ := setupTest(t)

	// Enable Yubikey
	prefix := "abcdefghijkl"
	err := handler.EnableYubikey(context.Background(), "test@example.com", prefix)
	if err != nil {
		t.Fatalf("failed to enable Yubikey: %v", err)
	}

	// Create fake Yubikey OTP (prefix + random data)
	otpCode := prefix + "qrstuvwxyz123456"

	// Verify Yubikey
	email, err := handler.VerifyYubikey(context.Background(), otpCode)
	if err != nil {
		t.Fatalf("failed to verify Yubikey: %v", err)
	}

	if email != "test@example.com" {
		t.Errorf("expected email test@example.com, got %s", email)
	}
}

func TestExtractYubikeyPrefix(t *testing.T) {
	tests := []struct {
		name    string
		otpCode string
		want    string
		wantErr bool
	}{
		{
			name:    "valid prefix",
			otpCode: "abcdefghijkl" + "qrstuvwxyz123456",
			want:    "abcdefghijkl",
			wantErr: false,
		},
		{
			name:    "too short",
			otpCode: "short",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid character",
			otpCode: "!bcdefghijklmnop" + "qrstuvwxyz123456",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractYubikeyPrefix(tt.otpCode)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractYubikeyPrefix() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ExtractYubikeyPrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDisableYubikey(t *testing.T) {
	handler, _ := setupTest(t)

	// Enable Yubikey
	err := handler.EnableYubikey(context.Background(), "test@example.com", "abcdefghijkl")
	if err != nil {
		t.Fatalf("failed to enable Yubikey: %v", err)
	}

	// Disable Yubikey
	err = handler.DisableYubikey(context.Background(), "test@example.com")
	if err != nil {
		t.Fatalf("failed to disable Yubikey: %v", err)
	}
}
