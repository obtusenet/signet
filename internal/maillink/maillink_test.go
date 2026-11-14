// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package maillink

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/db"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	database, err := db.New(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	store, err := NewStore(database.DB())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestTokenWorksOnceAndCheckingSpendsNothing(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	token, err := s.Create(ctx, Recovery, "a@example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if email, err := s.Email(ctx, Recovery, token); err != nil || email != "a@example.com" {
			t.Fatalf("check %d: %q, %v", i, email, err)
		}
	}
	if email, err := s.Consume(ctx, Recovery, token); err != nil || email != "a@example.com" {
		t.Fatalf("consume: %q, %v", email, err)
	}
	if _, err := s.Consume(ctx, Recovery, token); !errors.Is(err, ErrInvalid) {
		t.Errorf("second use: %v", err)
	}
	if _, err := s.Email(ctx, Recovery, token); !errors.Is(err, ErrInvalid) {
		t.Errorf("check after use: %v", err)
	}
}

func TestOnlyTheHashIsStored(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	token, err := s.Create(ctx, Recovery, "a@example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := s.db.QueryRow(`SELECT token_hash FROM mail_links`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token || strings.Contains(stored, token) {
		t.Errorf("the token itself was stored: %q", stored)
	}
}

func TestANewerTokenEndsTheOlder(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	first, _ := s.Create(ctx, Recovery, "a@example.com", time.Hour)
	other, _ := s.Create(ctx, Recovery, "b@example.com", time.Hour)
	second, _ := s.Create(ctx, Recovery, "a@example.com", time.Hour)
	if _, err := s.Email(ctx, Recovery, first); !errors.Is(err, ErrInvalid) {
		t.Errorf("older token: %v", err)
	}
	if _, err := s.Email(ctx, Recovery, second); err != nil {
		t.Errorf("newer token: %v", err)
	}
	if _, err := s.Email(ctx, Recovery, other); err != nil {
		t.Errorf("another address's token: %v", err)
	}
}

func TestExpiredAndForeignTokensAreRefused(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	expired, _ := s.Create(ctx, Recovery, "old@example.com", -time.Minute)
	if _, err := s.Email(ctx, Recovery, expired); !errors.Is(err, ErrInvalid) {
		t.Errorf("expired check: %v", err)
	}
	if _, err := s.Consume(ctx, Recovery, expired); !errors.Is(err, ErrInvalid) {
		t.Errorf("expired consume: %v", err)
	}
	live, _ := s.Create(ctx, Recovery, "a@example.com", time.Hour)
	if _, err := s.Email(ctx, "another-kind", live); !errors.Is(err, ErrInvalid) {
		t.Errorf("another kind, checked: %v", err)
	}
	if _, err := s.Consume(ctx, "another-kind", live); !errors.Is(err, ErrInvalid) {
		t.Errorf("another kind, spent: %v", err)
	}
	if _, err := s.Email(ctx, Recovery, "not-a-token"); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown: %v", err)
	}
}

func TestOneTokenCannotBeSpentTwiceAtOnce(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	token, _ := s.Create(ctx, Recovery, "a@example.com", time.Hour)
	var mu sync.Mutex
	won := 0
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Consume(ctx, Recovery, token); err == nil {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if won != 1 {
		t.Errorf("%d requests spent the token", won)
	}
}

func TestDeleteEmailAndPurge(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	gone, _ := s.Create(ctx, Recovery, "gone@example.com", time.Hour)
	kept, _ := s.Create(ctx, Recovery, "kept@example.com", time.Hour)
	if err := s.DeleteEmail(ctx, "gone@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Email(ctx, Recovery, gone); !errors.Is(err, ErrInvalid) {
		t.Errorf("deleted address: %v", err)
	}
	if _, err := s.Create(ctx, Recovery, "old@example.com", -time.Minute); err != nil {
		t.Fatal(err)
	}
	if n, err := s.PurgeExpired(ctx); err != nil || n != 1 {
		t.Errorf("purge: %d, %v", n, err)
	}
	if _, err := s.Email(ctx, Recovery, kept); err != nil {
		t.Errorf("purge took a live token: %v", err)
	}
}
