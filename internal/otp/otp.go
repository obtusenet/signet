// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package otp

import (
	"context"
	"errors"
	"fmt"

	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/logging"
	"github.com/obtusenet/signet/internal/password"
)

// OTPError represents an error during OTP operations
type OTPError struct {
	Err error
}

func (e *OTPError) Error() string {
	return e.Err.Error()
}

func (e *OTPError) Unwrap() error {
	return e.Err
}

// YubikeyPrefixLen is the length of a Yubikey public ID prefix
const YubikeyPrefixLen = 12

// OTPHandler handles Yubikey OTP authentication.  It stores a prefix over the
// password, so it must change before anything uses it.  TOTP is in totp.go.
type OTPHandler struct {
	backend         *csv.Backend
	hasher          *password.Hasher
	logger          *logging.Logger
	yubikeyPrefixes []string
}

// NewOTPHandler creates a new OTPHandler
func NewOTPHandler(backend *csv.Backend, hasher *password.Hasher, logger *logging.Logger) *OTPHandler {
	return &OTPHandler{
		backend: backend,
		hasher:  hasher,
		logger:  logger,
	}
}

// EnableYubikey enables Yubikey for a user by storing the prefix
func (h *OTPHandler) EnableYubikey(ctx context.Context, email string, prefix string) error {
	// Check if user exists
	_, err := h.backend.GetUser(email)
	if err != nil {
		return &OTPError{Err: fmt.Errorf("user not found: %w", err)}
	}

	// Validate prefix length
	if len(prefix) != YubikeyPrefixLen {
		return &OTPError{Err: fmt.Errorf("yubikey prefix must be %d characters", YubikeyPrefixLen)}
	}

	// Update user with Yubikey prefix
	updates := map[string]string{
		"password_hash":  prefix,
		"hash_algorithm": "yubikey",
	}
	if err := h.backend.UpdateUser(email, updates); err != nil {
		return &OTPError{Err: fmt.Errorf("updating user with Yubikey prefix: %w", err)}
	}

	// Add Yubikey flag
	if err := h.backend.AddFlag(email, "yubikey_enabled"); err != nil {
		return &OTPError{Err: fmt.Errorf("adding Yubikey flag: %w", err)}
	}

	// Add to known prefixes
	h.yubikeyPrefixes = append(h.yubikeyPrefixes, prefix)

	h.logger.Info(fmt.Sprintf("Yubikey enabled for user: %s (prefix: %s)", email, prefix))
	return nil
}

// DisableYubikey disables Yubikey for a user
func (h *OTPHandler) DisableYubikey(ctx context.Context, email string) error {
	// Check if user exists
	user, err := h.backend.GetUser(email)
	if err != nil {
		return &OTPError{Err: fmt.Errorf("user not found: %w", err)}
	}

	// Remove Yubikey prefix
	updates := map[string]string{
		"password_hash":  "",
		"hash_algorithm": user.HashAlg,
	}
	if err := h.backend.UpdateUser(email, updates); err != nil {
		return &OTPError{Err: fmt.Errorf("disabling Yubikey: %w", err)}
	}

	// Remove Yubikey flag
	if err := h.backend.RemoveFlag(email, "yubikey_enabled"); err != nil {
		return &OTPError{Err: fmt.Errorf("removing Yubikey flag: %w", err)}
	}

	// Remove from known prefixes
	h.yubikeyPrefixes = removePrefix(h.yubikeyPrefixes, user.PasswordHash)

	h.logger.Info(fmt.Sprintf("Yubikey disabled for user: %s", email))
	return nil
}

// VerifyYubikey verifies a Yubikey OTP for a user
func (h *OTPHandler) VerifyYubikey(ctx context.Context, otpCode string) (string, error) {
	// Extract public ID prefix from OTP
	prefix, err := ExtractYubikeyPrefix(otpCode)
	if err != nil {
		return "", &OTPError{Err: fmt.Errorf("extracting Yubikey prefix: %w", err)}
	}

	// Find user with this prefix
	users, err := h.backend.ListUsers()
	if err != nil {
		return "", &OTPError{Err: fmt.Errorf("listing users: %w", err)}
	}

	for _, user := range users {
		if user.PasswordHash == prefix && hasFlag(user.Flags, "yubikey_enabled") {
			h.logger.Info(fmt.Sprintf("Yubikey verified for user: %s", user.Email))
			return user.Email, nil
		}
	}

	return "", &OTPError{Err: errors.New("invalid Yubikey OTP")}
}

// ExtractYubikeyPrefix extracts the 12-character public ID prefix from a Yubikey OTP
func ExtractYubikeyPrefix(otpCode string) (string, error) {
	if len(otpCode) < YubikeyPrefixLen {
		return "", fmt.Errorf("OTP too short: expected at least %d characters", YubikeyPrefixLen)
	}

	prefix := otpCode[:YubikeyPrefixLen]

	for _, c := range prefix {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return "", fmt.Errorf("invalid character in Yubikey prefix: %c", c)
		}
	}

	return prefix, nil
}

// Helper functions

func hasFlag(flags []string, flag string) bool {
	for _, f := range flags {
		if f == flag {
			return true
		}
	}
	return false
}

func removePrefix(prefixes []string, prefix string) []string {
	var result []string
	for _, p := range prefixes {
		if p != prefix {
			result = append(result, p)
		}
	}
	return result
}
