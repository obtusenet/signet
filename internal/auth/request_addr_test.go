// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth

import (
	"net/http/httptest"
	"testing"

	"github.com/obtusenet/signet/internal/clientaddr"
)

// Two requests from the same host but different ephemeral ports must share a
// budget; keying on RemoteAddr verbatim gave every request a fresh one.
func TestEmailRateLimiterSharesBudgetAcrossPorts(t *testing.T) {
	limit := NewEmailRateLimiter(2, 60e9)
	var clients *clientaddr.Resolver

	first := httptest.NewRequest("POST", "/email-pin/send", nil)
	first.RemoteAddr = "192.0.2.9:10001"
	second := httptest.NewRequest("POST", "/email-pin/send", nil)
	second.RemoteAddr = "192.0.2.9:10002"
	third := httptest.NewRequest("POST", "/email-pin/send", nil)
	third.RemoteAddr = "192.0.2.9:10003"

	if !limit.Allow(clients.Addr(first)) || !limit.Allow(clients.Addr(second)) {
		t.Fatal("first two requests refused")
	}
	if limit.Allow(clients.Addr(third)) {
		t.Error("third request allowed despite the same host")
	}
}
