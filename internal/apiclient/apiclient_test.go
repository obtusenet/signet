// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package apiclient

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/db"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	d, err := db.New(":memory:")
	if err != nil {
		t.Fatalf("opening db: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return NewStore(d.DB())
}

func TestCreateAndLookup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key, err := s.Create(ctx, "scribe", []string{"https://app.example.com"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !strings.HasPrefix(key, "sk_") {
		t.Errorf("key %q does not carry the sk_ prefix", key)
	}

	c, err := s.Lookup(ctx, key)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if c.Name != "scribe" {
		t.Errorf("name = %q", c.Name)
	}
	if len(c.AllowedOrigins) != 1 || c.AllowedOrigins[0] != "https://app.example.com" {
		t.Errorf("origins = %v", c.AllowedOrigins)
	}

	// The plaintext key must not be stored.
	var stored string
	if err := s.db.QueryRow(`SELECT api_key FROM api_clients WHERE name = 'scribe'`).Scan(&stored); err != nil {
		t.Fatalf("reading stored key: %v", err)
	}
	if stored == key || strings.Contains(stored, key) {
		t.Error("plaintext API key was stored")
	}
	if stored != HashKey(key) {
		t.Error("stored value is not the key hash")
	}
}

func TestLookupRejectsUnknownAndEmpty(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Lookup(ctx, ""); err != ErrNotFound {
		t.Errorf("empty key: err = %v, want ErrNotFound", err)
	}
	if _, err := s.Lookup(ctx, "sk_deadbeef"); err != ErrNotFound {
		t.Errorf("unknown key: err = %v, want ErrNotFound", err)
	}
}

func TestDuplicateName(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Create(ctx, "dup", nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Create(ctx, "dup", nil); err == nil {
		t.Error("creating the same name twice succeeded")
	}
	if _, err := s.Create(ctx, "  ", nil); err == nil {
		t.Error("creating an unnamed client succeeded")
	}
}

func TestListAndRevoke(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key, err := s.Create(ctx, "wiki", []string{"https://wiki.example.com", "https://m.example.com"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	clients, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(clients) != 1 || clients[0].Name != "wiki" {
		t.Fatalf("clients = %+v", clients)
	}
	if len(clients[0].AllowedOrigins) != 2 {
		t.Errorf("origins = %v", clients[0].AllowedOrigins)
	}

	removed, err := s.Revoke(ctx, "wiki")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !removed {
		t.Error("revoke reported no rows")
	}
	if _, err := s.Lookup(ctx, key); err != ErrNotFound {
		t.Errorf("revoked key still resolves: %v", err)
	}
	if removed, _ := s.Revoke(ctx, "wiki"); removed {
		t.Error("second revoke removed a row")
	}
}

func TestOriginAllowed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Create(ctx, "a", []string{"https://a.example.com"}); err != nil {
		t.Fatalf("create: %v", err)
	}

	ok, err := s.OriginAllowed(ctx, "https://a.example.com")
	if err != nil || !ok {
		t.Errorf("allowed origin: ok=%v err=%v", ok, err)
	}
	if ok, _ := s.OriginAllowed(ctx, "https://b.example.com"); ok {
		t.Error("unknown origin allowed")
	}
	if ok, _ := s.OriginAllowed(ctx, ""); ok {
		t.Error("empty origin allowed")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(2, time.Minute)
	if !l.Allow("a") || !l.Allow("a") {
		t.Fatal("first two calls refused")
	}
	if l.Allow("a") {
		t.Error("third call allowed")
	}
	if !l.Allow("b") {
		t.Error("budget is not per key")
	}

	unlimited := NewLimiter(0, time.Minute)
	for i := 0; i < 100; i++ {
		if !unlimited.Allow("x") {
			t.Fatal("a zero limit must not limit")
		}
	}
}
