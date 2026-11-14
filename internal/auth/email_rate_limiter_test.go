// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth

import (
	"testing"
	"time"
)

func TestEmailRateLimiter(t *testing.T) {
	rateLimit := NewEmailRateLimiter(3, time.Second)

	// Should allow first 3 requests
	for i := 0; i < 3; i++ {
		if !rateLimit.Allow("test@example.com") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// Fourth request should be rejected
	if rateLimit.Allow("test@example.com") {
		t.Fatal("fourth request should be rejected")
	}
}

func TestEmailRateLimiterDifferentKeys(t *testing.T) {
	rateLimit := NewEmailRateLimiter(2, time.Second)

	// Each key should have its own limit
	if !rateLimit.Allow("user1@example.com") {
		t.Fatal("first request for user1 should be allowed")
	}
	if !rateLimit.Allow("user1@example.com") {
		t.Fatal("second request for user1 should be allowed")
	}
	if rateLimit.Allow("user1@example.com") {
		t.Fatal("third request for user1 should be rejected")
	}

	// Different user should still be allowed
	if !rateLimit.Allow("user2@example.com") {
		t.Fatal("first request for user2 should be allowed")
	}
}

func TestEmailRateLimiterCleanup(t *testing.T) {
	rateLimit := NewEmailRateLimiter(2, 100*time.Millisecond)

	// Use up the rate limit
	rateLimit.Allow("test@example.com")
	rateLimit.Allow("test@example.com")

	// Should be rejected
	if rateLimit.Allow("test@example.com") {
		t.Fatal("should be rejected after exceeding limit")
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Cleanup should remove old requests
	rateLimit.Cleanup()

	// Should be allowed again
	if !rateLimit.Allow("test@example.com") {
		t.Fatal("should be allowed after window expires")
	}
}

func TestEmailRateLimiterExpiry(t *testing.T) {
	rateLimit := NewEmailRateLimiter(1, 100*time.Millisecond)

	// First request should be allowed
	if !rateLimit.Allow("test@example.com") {
		t.Fatal("first request should be allowed")
	}

	// Second request should be rejected
	if rateLimit.Allow("test@example.com") {
		t.Fatal("second request should be rejected")
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	if !rateLimit.Allow("test@example.com") {
		t.Fatal("should be allowed after window expires")
	}
}
