// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/obtusenet/signet/internal/auth"
)

func TestSourceLimitStopsOneClientTryingManyAccounts(t *testing.T) {
	f := newFixture(t)
	pa := f.passwordAuth(false)
	pa.SetSourceLimit(3, 300)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("user%d@example.com", i)
		if _, err := pa.Authenticate(ctx, addr, "198.51.100.1", "wrong"); errors.Is(err, auth.ErrSourceRateLimited) {
			t.Fatalf("attempt %d limited early", i)
		}
	}
	f.addUser(t, "user@example.com")
	if _, err := pa.Authenticate(ctx, "user@example.com", "198.51.100.1", "correct-password"); !errors.Is(err, auth.ErrSourceRateLimited) {
		t.Errorf("fourth attempt from that client: got %v, want ErrSourceRateLimited", err)
	}
	if _, err := pa.Authenticate(ctx, "user@example.com", "198.51.100.2", "correct-password"); err != nil {
		t.Errorf("another client was refused: %v", err)
	}
}

func TestSourceLimitIsNotClearedBySigningIn(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "attacker@example.com")
	pa := f.passwordAuth(false)
	pa.SetSourceLimit(2, 300)
	ctx := context.Background()

	if _, err := pa.Authenticate(ctx, "victim@example.com", "198.51.100.1", "wrong"); err == nil {
		t.Fatal("login succeeded")
	}
	if _, err := pa.Authenticate(ctx, "attacker@example.com", "198.51.100.1", "correct-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := pa.Authenticate(ctx, "victim@example.com", "198.51.100.1", "wrong"); err == nil {
		t.Fatal("login succeeded")
	}
	if _, err := pa.Authenticate(ctx, "attacker@example.com", "198.51.100.1", "correct-password"); !errors.Is(err, auth.ErrSourceRateLimited) {
		t.Errorf("got %v, want ErrSourceRateLimited: a success must not reset the count", err)
	}
}

// Turned off, nobody can block a person's password login by failing on purpose.
func TestAddressLimitCanBeTurnedOff(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "user@example.com")
	pa := f.passwordAuth(false)
	pa.DisableAddressLimit()
	ctx := context.Background()

	for i := 0; i < 8; i++ {
		if _, err := pa.Authenticate(ctx, "user@example.com", "198.51.100.1", "wrong"); errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("attempt %d limited with the limit off", i)
		}
	}
	if _, err := pa.Authenticate(ctx, "user@example.com", "198.51.100.1", "correct-password"); err != nil {
		t.Errorf("correct password: %v", err)
	}
	pa.PruneRateLimiter() // must cope with the limit being off
}

// Off is the default of a bare PasswordAuth; the server turns it on from config.
func TestSourcesAreNotLimitedUnlessAsked(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "user@example.com")
	pa := f.passwordAuth(false)
	ctx := context.Background()
	for i := 0; i < 30; i++ {
		addr := fmt.Sprintf("user%d@example.com", i)
		if _, err := pa.Authenticate(ctx, addr, "198.51.100.1", "wrong"); errors.Is(err, auth.ErrSourceRateLimited) {
			t.Fatal("limited by source with no source limit")
		}
	}
}
