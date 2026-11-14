// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/obtusenet/signet/internal/logging"
)

func TestStatusRecorderDefaultsTo200(t *testing.T) {
	w := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: w}

	if _, err := rec.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if rec.status != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.status)
	}
	if rec.bytes != 5 {
		t.Errorf("bytes = %d, want 5", rec.bytes)
	}
}

func TestStatusRecorderKeepsFirstStatus(t *testing.T) {
	w := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: w}

	rec.WriteHeader(http.StatusUnauthorized)
	rec.WriteHeader(http.StatusTeapot)
	if rec.status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.status)
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("underlying status = %d, want 401", w.Code)
	}
}

func TestRequestLogPassesResponseThrough(t *testing.T) {
	logger, err := logging.New(false, "debug")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	s := &Server{logger: logger}

	handler := s.withRequestLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"valid":false}`))
	}))

	r := httptest.NewRequest("GET", "/session?claims=refresh", nil)
	r.RemoteAddr = "10.0.0.5:41234"
	r.Header.Set("X-Forwarded-For", "192.0.2.9, 10.0.0.5")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if body := w.Body.String(); body != `{"valid":false}` {
		t.Errorf("body = %q", body)
	}
}
