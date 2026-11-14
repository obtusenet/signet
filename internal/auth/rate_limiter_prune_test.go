// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth

import (
	"testing"
	"time"
)

func TestRateLimiterCleanupForgetsIdleKeysOnly(t *testing.T) {
	rl := NewRateLimiter(2, 60)
	rl.Increment("recent")
	rl.Increment("recent")
	rl.requests["idle"] = []time.Time{time.Now().Add(-2 * time.Minute)}
	rl.Allow("never-failed") // Allow alone leaves an empty key behind

	rl.Cleanup()

	if _, ok := rl.requests["idle"]; ok {
		t.Error("an idle key stayed")
	}
	if _, ok := rl.requests["never-failed"]; ok {
		t.Error("an empty key stayed")
	}
	if rl.Allow("recent") {
		t.Error("cleanup forgave recent failures")
	}
}

func TestEmailRateLimiterCleanupForgetsIdleKeysOnly(t *testing.T) {
	rl := NewEmailRateLimiter(1, time.Minute)
	rl.Allow("recent")
	rl.requests["idle"] = []time.Time{time.Now().Add(-2 * time.Minute)}

	rl.Cleanup()

	if _, ok := rl.requests["idle"]; ok {
		t.Error("an idle key stayed")
	}
	if rl.Allow("recent") {
		t.Error("cleanup forgave a recent request")
	}
}
