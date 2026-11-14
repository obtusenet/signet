// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth

import (
	"sync"
	"time"
)

// RateLimiter implements a sliding window rate limiter
type RateLimiter struct {
	mu        sync.Mutex
	requests  map[string][]time.Time
	limit     int
	windowSec int
}

// NewRateLimiter creates a new RateLimiter
func NewRateLimiter(limit, windowSec int) *RateLimiter {
	return &RateLimiter{
		requests:  make(map[string][]time.Time),
		limit:     limit,
		windowSec: windowSec,
	}
}

// Allow reports whether key may make another attempt.  Only failures are
// recorded (see Increment), so a correct password is never refused because
// earlier tries used up the budget of a shared counter.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-time.Duration(rl.windowSec) * time.Second)

	var recent []time.Time
	for _, t := range rl.requests[key] {
		if t.After(windowStart) {
			recent = append(recent, t)
		}
	}
	rl.requests[key] = recent

	return len(recent) < rl.limit
}

// Take counts an attempt for key now, before it is checked, and reports whether
// it is within the limit.  Checking and counting in one step means attempts sent
// at the same moment cannot all pass a check that none of them has counted in
// yet.  A refused attempt is not counted.  Give back with Refund an attempt that
// should not count after all, such as one that succeeded.
func (rl *RateLimiter) Take(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-time.Duration(rl.windowSec) * time.Second)

	var recent []time.Time
	for _, t := range rl.requests[key] {
		if t.After(windowStart) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= rl.limit {
		rl.requests[key] = recent
		return false
	}
	rl.requests[key] = append(recent, now)
	return true
}

// Refund gives back one attempt counted by Take.
func (rl *RateLimiter) Refund(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	times := rl.requests[key]
	switch len(times) {
	case 0:
	case 1:
		delete(rl.requests, key)
	default:
		rl.requests[key] = times[:len(times)-1]
	}
}

// Reset clears the failure history for key (called after a successful login).
func (rl *RateLimiter) Reset(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.requests, key)
}

// Increment manually increments the count for a key (for failed login attempts)
func (rl *RateLimiter) Increment(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-time.Duration(rl.windowSec) * time.Second)

	// Filter out old requests
	var recent []time.Time
	for _, t := range rl.requests[key] {
		if t.After(windowStart) {
			recent = append(recent, t)
		}
	}

	rl.requests[key] = append(recent, now)
}

// Cleanup forgets keys with no failure left in the window, so addresses tried
// once do not accumulate.
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	windowStart := time.Now().Add(-time.Duration(rl.windowSec) * time.Second)
	for key, times := range rl.requests {
		var recent []time.Time
		for _, t := range times {
			if t.After(windowStart) {
				recent = append(recent, t)
			}
		}
		if len(recent) == 0 {
			delete(rl.requests, key)
		} else {
			rl.requests[key] = recent
		}
	}
}
