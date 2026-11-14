// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package apiclient

import (
	"sync"
	"time"
)

// Limiter is a per-client sliding-window counter.  Unlike the login limiter,
// every call counts: an API call costs budget even when it succeeds.
type Limiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	limit  int
	window time.Duration
}

// NewLimiter creates a limiter allowing limit calls per window.  A limit of
// zero or less disables limiting.
func NewLimiter(limit int, window time.Duration) *Limiter {
	return &Limiter{
		hits:   make(map[string][]time.Time),
		limit:  limit,
		window: window,
	}
}

// Allow records one call for key and reports whether it is within budget.
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.limit <= 0 {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.window)

	// Build a fresh slice: reusing the old backing array would overwrite the
	// entries being ranged over.
	recent := make([]time.Time, 0, len(l.hits[key]))
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= l.limit {
		l.hits[key] = recent
		return false
	}

	l.hits[key] = append(recent, now)
	return true
}
