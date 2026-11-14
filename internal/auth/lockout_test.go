// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/db"
)

func testLockout(t *testing.T, threshold int) (*Lockout, *time.Time, *[]string) {
	t.Helper()
	store, err := db.New(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	l, err := NewLockout(store.DB(), threshold, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	l.now = func() time.Time { return now }
	var locks []string
	l.OnLock(func(address string, until time.Time, failures int) {
		locks = append(locks, address)
		if want := now.Add(10 * time.Minute); !until.Equal(want) {
			t.Errorf("locked until %v, want %v", until, want)
		}
	})
	return l, &now, &locks
}

func TestLockoutCapsConsecutiveFailures(t *testing.T) {
	ctx := context.Background()
	l, now, locks := testLockout(t, 3)
	const who = "a@example.com"
	for i := 0; i < 2; i++ {
		if err := l.Fail(ctx, who); err != nil {
			t.Fatal(err)
		}
	}
	if _, locked, _ := l.Locked(ctx, who); locked || len(*locks) != 0 {
		t.Fatal("locked before the threshold")
	}
	if err := l.Fail(ctx, "A@Example.com"); err != nil {
		t.Fatal(err)
	}
	until, locked, err := l.Locked(ctx, who)
	if err != nil || !locked || len(*locks) != 1 {
		t.Fatalf("not locked at the threshold: %v %v %d", locked, err, len(*locks))
	}
	if want := now.Add(10 * time.Minute); !until.Equal(want) {
		t.Errorf("until %v, want %v", until, want)
	}
	if _, locked, _ := l.Locked(ctx, "b@example.com"); locked {
		t.Error("another account is locked")
	}

	// When the lock ends, one more failure locks again: one try per lock.
	*now = now.Add(10 * time.Minute)
	if _, locked, _ := l.Locked(ctx, who); locked {
		t.Fatal("still locked after the duration")
	}
	if err := l.Fail(ctx, who); err != nil {
		t.Fatal(err)
	}
	if _, locked, _ := l.Locked(ctx, who); !locked || len(*locks) != 2 {
		t.Errorf("a failure after the lock did not lock again: %d locks", len(*locks))
	}

	if n, _ := l.Failures(ctx, who); n != 4 {
		t.Errorf("%d failures, want 4", n)
	}
	if had, err := l.Clear(ctx, who); err != nil || !had {
		t.Fatalf("clear: %v %v", had, err)
	}
	if _, locked, _ := l.Locked(ctx, who); locked {
		t.Error("still locked after a clear")
	}
	if n, _ := l.Failures(ctx, who); n != 0 {
		t.Errorf("%d failures after a clear", n)
	}
	if had, _ := l.Clear(ctx, who); had {
		t.Error("a second clear found something")
	}
}

// Instances sharing a database share the count.
func TestLockoutIsShared(t *testing.T) {
	ctx := context.Background()
	store, err := db.New(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	one, _ := NewLockout(store.DB(), 2, time.Hour)
	other, _ := NewLockout(store.DB(), 2, time.Hour)
	one.Fail(ctx, "a@example.com")
	other.Fail(ctx, "a@example.com")
	if _, locked, _ := one.Locked(ctx, "a@example.com"); !locked {
		t.Error("two instances' failures were not added up")
	}
}

func TestLockoutOff(t *testing.T) {
	ctx := context.Background()
	store, err := db.New(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	l, err := NewLockout(store.DB(), 0, time.Hour)
	if err != nil || l != nil {
		t.Fatalf("threshold 0: %v %v", l, err)
	}
	// Its methods are safe to call, and do nothing.
	l.OnLock(func(string, time.Time, int) { t.Error("told of a lock") })
	if err := l.Fail(ctx, "a@example.com"); err != nil {
		t.Error(err)
	}
	if _, locked, err := l.Locked(ctx, "a@example.com"); locked || err != nil {
		t.Error("an absent lockout locked")
	}
	if had, err := l.Clear(ctx, "a@example.com"); had || err != nil {
		t.Error("an absent lockout cleared something")
	}
}

func TestLockoutGuardRunsOneCheckPerAccount(t *testing.T) {
	l, _, _ := testLockout(t, 3)
	release := l.Guard("a@example.com")
	other := make(chan struct{})
	go func() { l.Guard("b@example.com")(); close(other) }()
	select {
	case <-other:
	case <-time.After(time.Second):
		t.Fatal("another account waited")
	}
	same := make(chan struct{})
	go func() { l.Guard("A@EXAMPLE.COM")(); close(same) }()
	select {
	case <-same:
		t.Fatal("the same account did not wait")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	<-same
	if len(l.guards) != 0 {
		t.Errorf("%d guards left", len(l.guards))
	}
	var none *Lockout
	none.Guard("a@example.com")()
}
