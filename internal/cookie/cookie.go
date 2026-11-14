// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package cookie

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CookieManager handles creating and validating auth cookies
type CookieManager struct {
	Name   string
	Domain string
	MaxAge int
	// Secure marks the cookie Secure.  Keep it true in production (the
	// service is meant to sit behind a TLS-terminating proxy); a plain
	// HTTP deployment on a test box needs it off or browsers drop the
	// cookie.
	Secure bool
	Secret []byte
}

// NewCookieManager creates a new CookieManager
func NewCookieManager(name, domain string, maxAge int, secret []byte) *CookieManager {
	return &CookieManager{
		Name:   name,
		Domain: domain,
		MaxAge: maxAge,
		Secure: true,
		Secret: secret,
	}
}

// CreateAuthCookie creates a new auth cookie with a random token
func (cm *CookieManager) CreateAuthCookie(sessionToken string) *http.Cookie {
	// Sign the token with the secret
	signature := cm.sign(sessionToken)

	cookieValue := fmt.Sprintf("%s:%s", sessionToken, signature)

	return &http.Cookie{
		Name:     cm.Name,
		Value:    cookieValue,
		Path:     "/",
		Domain:   cm.Domain,
		MaxAge:   cm.MaxAge,
		HttpOnly: true,
		Secure:   cm.Secure,
		SameSite: http.SameSiteStrictMode,
	}
}

// ExpiredAuthCookie tells the browser to discard the auth cookie.
func (cm *CookieManager) ExpiredAuthCookie() *http.Cookie {
	return &http.Cookie{
		Name:     cm.Name,
		Value:    "",
		Path:     "/",
		Domain:   cm.Domain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cm.Secure,
		SameSite: http.SameSiteStrictMode,
	}
}

// ValidateAuthCookie validates an auth cookie and returns the session token
func (cm *CookieManager) ValidateAuthCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(cm.Name)
	if err != nil {
		return "", fmt.Errorf("cookie not found: %w", err)
	}
	return cm.ValidateCookieValue(cookie.Value)
}

// ValidateCookieValue checks a raw cookie value ("token:signature") and
// returns the session token.  It lets callers validate a value handed to
// them out of band, such as the cookie an application sends to the
// validation API.
func (cm *CookieManager) ValidateCookieValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	// Accept a full "name=value" pair or a bare value; drop any attributes.
	if i := strings.IndexByte(value, ';'); i >= 0 {
		value = strings.TrimSpace(value[:i])
	}
	value = strings.TrimPrefix(value, cm.Name+"=")

	// Split the cookie value into token and signature
	parts := splitColon(value)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid cookie format")
	}

	token := parts[0]
	signature := parts[1]

	// Verify the signature
	expectedSignature := cm.sign(token)
	if !constantTimeCompare([]byte(signature), []byte(expectedSignature)) {
		return "", fmt.Errorf("invalid cookie signature")
	}

	return token, nil
}

// sign answers SHA-256(secret || token) in hex.  It is not an HMAC, and a
// length-extension forgery would gain nothing: ValidateAuthCookie's caller looks
// the token up in the session store, and only tokens Signet made are there.
func (cm *CookieManager) sign(token string) string {
	h := sha256.New()
	h.Write(cm.Secret)
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

// GenerateRandomToken generates a random 32-byte token
func GenerateRandomToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// splitColon splits a string by ':' and returns non-empty parts
func splitColon(s string) []string {
	var result []string
	parts := splitChar(s, ':')
	for _, p := range parts {
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// splitChar splits a string by a character and returns all parts
func splitChar(s string, c byte) []string {
	var result []string
	current := ""
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			result = append(result, current)
			current = ""
		} else {
			current += string(s[i])
		}
	}
	result = append(result, current)
	return result
}

// constantTimeCompare compares two byte slices in constant time
func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := byte(0)
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// Now returns the current time (for testing)
func Now() time.Time {
	return time.Now()
}
