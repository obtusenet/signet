// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth

import "testing"

// Only failures consume the budget: a success after several failures must
// still be allowed, and a success clears the history.
func TestRateLimiterCountsFailuresOnly(t *testing.T) {
	rl := NewRateLimiter(3, 300)

	for i := 0; i < 3; i++ {
		if !rl.Allow("user@example.com") {
			t.Fatalf("attempt %d refused before any failure", i+1)
		}
		rl.Increment("user@example.com")
	}

	if rl.Allow("user@example.com") {
		t.Fatal("attempt allowed after the failure budget was used up")
	}

	// A different identity is unaffected.
	if !rl.Allow("other@example.com") {
		t.Fatal("unrelated identity was rate limited")
	}
}

func TestRateLimiterReset(t *testing.T) {
	rl := NewRateLimiter(1, 300)
	rl.Increment("user@example.com")
	if rl.Allow("user@example.com") {
		t.Fatal("expected the key to be locked")
	}

	rl.Reset("user@example.com")
	if !rl.Allow("user@example.com") {
		t.Fatal("expected Reset to clear the failure history")
	}
}

func TestRateLimiterWindowExpiry(t *testing.T) {
	// A zero-length window means every recorded failure is already stale.
	rl := NewRateLimiter(1, 0)
	rl.Increment("user@example.com")
	if !rl.Allow("user@example.com") {
		t.Fatal("failures outside the window must not count")
	}
}

func TestTakeCountsAndRefundGivesBack(t *testing.T) {
	rl := NewRateLimiter(2, 60)
	if !rl.Take("k") || !rl.Take("k") {
		t.Fatal("first two refused")
	}
	if rl.Take("k") {
		t.Fatal("third taken")
	}
	rl.Refund("k")
	if !rl.Take("k") {
		t.Fatal("refused after a refund")
	}
	rl.Refund("other") // nothing to give back
}
