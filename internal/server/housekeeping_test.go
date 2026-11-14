// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/session"
)

func TestHousekeepingRemovesExpiredSessions(t *testing.T) {
	s, _ := newRegisterServer(t, "disabled")
	ctx := context.Background()
	expired := time.Now().Add(-time.Minute)
	if err := s.sessionStore.Create(ctx, &session.Session{
		Token: "old", UserEmail: "a@example.com", AuthMethod: "password", Claims: "{}",
		CreatedAt: expired.Add(-time.Hour), ExpiresAt: expired,
	}); err != nil {
		t.Fatal(err)
	}
	if len(s.housekeeping) == 0 {
		t.Fatal("nothing was registered")
	}
	for _, task := range s.housekeeping {
		task(ctx)
	}
	var left int
	if err := s.db.DB().QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("%d rows left", left)
	}
}

func TestHousekeepingRunsAtStartAndStopsAtShutdown(t *testing.T) {
	s, _ := newRegisterServer(t, "disabled")
	var runs atomic.Int32
	s.housekeeping = []func(context.Context){func(context.Context) { runs.Add(1) }}

	s.startHousekeeping(10 * time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for runs.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if runs.Load() < 2 {
		t.Fatalf("ran %d times", runs.Load())
	}

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	settled := runs.Load()
	time.Sleep(50 * time.Millisecond)
	if runs.Load() != settled {
		t.Error("still running after Shutdown")
	}
}

// Only a real Start proves the upkeep is wired to a running server.
func TestStartRunsHousekeeping(t *testing.T) {
	s, _ := newRegisterServer(t, "disabled")
	s.cfg.Listen = "127.0.0.1:0"
	ran := make(chan struct{}, 1)
	s.housekeeping = []func(context.Context){func(context.Context) {
		select {
		case ran <- struct{}{}:
		default:
		}
	}}

	done := make(chan error, 1)
	go func() { done <- s.Start() }()
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not run the upkeep")
	}

	// Shutdown only reaches a server that Start has already recorded.
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		s.srvMu.Lock()
		ready := s.srv != nil
		s.srvMu.Unlock()
		if ready {
			break
		}
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Shutdown")
	}
}
