// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"net/http/httptest"
	"testing"
)

func TestWantsJSON(t *testing.T) {
	cases := []struct {
		name     string
		accept   string
		xhr      string
		expected bool
	}{
		{"fetch with accept", "application/json", "", true},
		{"accept list", "text/html, application/json;q=0.9", "", true},
		{"xhr header", "*/*", "XMLHttpRequest", true},
		{"plain form post", "text/html", "", false},
		{"no headers", "", "", false},
	}

	for _, tc := range cases {
		r := httptest.NewRequest("POST", "/login", nil)
		if tc.accept != "" {
			r.Header.Set("Accept", tc.accept)
		}
		if tc.xhr != "" {
			r.Header.Set("X-Requested-With", tc.xhr)
		}
		if got := wantsJSON(r); got != tc.expected {
			t.Errorf("%s: wantsJSON = %v, want %v", tc.name, got, tc.expected)
		}
	}
}
