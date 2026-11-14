// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth

import (
	"sync"
	"time"
)

// EmailRateLimiter implements a sliding window rate limiter for email PIN operations
type EmailRateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	rate     int
	window   time.Duration
}

// NewEmailRateLimiter creates a new EmailRateLimiter
func NewEmailRateLimiter(rate int, window time.Duration) *EmailRateLimiter {
	return &EmailRateLimiter{
		requests: make(map[string][]time.Time),
		rate:     rate,
		window:   window,
	}
}

// Allow checks if a request is allowed
func (r *EmailRateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-r.window)

	// Get existing requests for this key
	requests := r.requests[key]

	// Remove expired requests
	validRequests := make([]time.Time, 0)
	for _, t := range requests {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}

	// Check if limit exceeded
	if len(validRequests) >= r.rate {
		r.requests[key] = validRequests
		return false
	}

	// Add new request
	validRequests = append(validRequests, now)
	r.requests[key] = validRequests
	return true
}

// Cleanup removes expired requests
func (r *EmailRateLimiter) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-r.window)

	for key, requests := range r.requests {
		validRequests := make([]time.Time, 0)
		for _, t := range requests {
			if t.After(windowStart) {
				validRequests = append(validRequests, t)
			}
		}
		if len(validRequests) == 0 {
			delete(r.requests, key)
		} else {
			r.requests[key] = validRequests
		}
	}
}
