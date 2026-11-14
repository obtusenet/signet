// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/auth"
)

// attempts runs n wrong passwords for addr at the same moment and counts how many
// were checked rather than refused by a limit.
func attempts(t *testing.T, pa *auth.PasswordAuth, addr string, n int) (checked int) {
	t.Helper()
	var wg sync.WaitGroup
	var mu sync.Mutex
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := pa.Authenticate(context.Background(), addr, "198.51.100.1", "wrong")
			if err == nil {
				t.Error("a wrong password signed in")
				return
			}
			if !errors.Is(err, auth.ErrRateLimited) && !errors.Is(err, auth.ErrSourceRateLimited) {
				mu.Lock()
				checked++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	return checked
}

// Guesses sent together must not all pass a limit none of them has counted in yet.
func TestAddressLimitHoldsForGuessesSentTogether(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "user@example.com")
	pa := f.passwordAuth(false) // 5 failures per address
	if got := attempts(t, pa, "user@example.com", 40); got != 5 {
		t.Errorf("%d of 40 guesses sent together were checked, want 5", got)
	}
}

func TestSourceLimitHoldsForGuessesSentTogether(t *testing.T) {
	f := newFixture(t)
	pa := f.passwordAuth(false)
	pa.DisableAddressLimit()
	pa.SetSourceLimit(4, 300)
	if got := attempts(t, pa, "nobody@example.com", 40); got != 4 {
		t.Errorf("%d of 40 guesses sent together were checked, want 4", got)
	}
}

func TestLockoutHoldsForGuessesSentTogether(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "user@example.com")
	pa := f.passwordAuth(false)
	pa.DisableAddressLimit()
	l, err := auth.NewLockout(f.db, 3, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pa.SetLockout(l)
	if got := attempts(t, pa, "User@Example.com", 30); got != 3 {
		t.Errorf("%d of 30 guesses sent together were checked, want 3", got)
	}
	if n, _ := l.Failures(context.Background(), "user@example.com"); n != 3 {
		t.Errorf("lockout count %d, want 3", n)
	}
}

// A success gives back what it was counted, so signing in does not use up the limit.
func TestSuccessIsNotCounted(t *testing.T) {
	f := newFixture(t)
	f.addUser(t, "user@example.com")
	pa := f.passwordAuth(false)
	pa.SetSourceLimit(2, 300)
	for i := 0; i < 5; i++ {
		if _, err := pa.Authenticate(context.Background(), "user@example.com", "198.51.100.1", "correct-password"); err != nil {
			t.Fatalf("sign-in %d: %v", i, err)
		}
		if err := pa.CheckPassword("user@example.com", "198.51.100.1", "correct-password"); err != nil {
			t.Fatalf("check %d: %v", i, err)
		}
	}
}
