// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Lockout caps consecutive failed sign-ins on an account, as NIST SP 800-63B
// §5.2.2 asks: no more than a set number before the account stops accepting
// guesses.  The rate limiters slow guessing down; this bounds it.  The count is in
// the database, so every instance sharing it sees the same one, and a restart
// does not clear it.
//
// Wrong passwords, PINs and codes count, for accounts that exist.  Only a
// finished sign-in clears the count: a right password that still needs its code
// does not, or knowing the password would buy unlimited guesses at the code.
// While locked, those methods refuse without checking; once the lock ends, one
// more failure locks again, so a guesser gets one try per lock.  A security key
// is not affected, and neither is recovery by mail, which clears the count.
type Lockout struct {
	db        *sql.DB
	threshold int
	duration  time.Duration
	now       func() time.Time
	onLock    func(address string, until time.Time, failures int)

	mu     sync.Mutex
	guards map[string]*accountGuard
}

// accountGuard lets one check at a time run against an account.
type accountGuard struct {
	mu    sync.Mutex
	users int
}

// NewLockout keeps its counts in db.  A threshold of 0 switches it off, and then it
// is nil, whose methods do nothing.
func NewLockout(db *sql.DB, threshold int, duration time.Duration) (*Lockout, error) {
	if threshold <= 0 {
		return nil, nil
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS account_failures (
		email TEXT PRIMARY KEY,
		failures INTEGER NOT NULL,
		last_unix INTEGER NOT NULL
	)`); err != nil {
		return nil, fmt.Errorf("creating the lockout table: %w", err)
	}
	return &Lockout{db: db, threshold: threshold, duration: duration, now: time.Now}, nil
}

// OnLock is told each time a lock starts.
func (l *Lockout) OnLock(notify func(address string, until time.Time, failures int)) {
	if l != nil {
		l.onLock = notify
	}
}

func lockoutKey(address string) string { return strings.ToLower(address) }

// Guard waits until no other check of the account's credentials is running, and
// answers the function that ends this one.  Between Locked and Fail a check takes
// as long as a password hash; without the guard, guesses sent together would all
// see the count before any of them had added to it.  The count is in the
// database, but the guard is in this process: instances that share a database
// each run one check per account at a time.
func (l *Lockout) Guard(address string) (release func()) {
	if l == nil {
		return func() {}
	}
	key := lockoutKey(address)
	l.mu.Lock()
	if l.guards == nil {
		l.guards = make(map[string]*accountGuard)
	}
	g := l.guards[key]
	if g == nil {
		g = &accountGuard{}
		l.guards[key] = g
	}
	g.users++
	l.mu.Unlock()

	g.mu.Lock()
	return func() {
		g.mu.Unlock()
		l.mu.Lock()
		g.users--
		if g.users == 0 {
			delete(l.guards, key)
		}
		l.mu.Unlock()
	}
}

// Locked reports whether the account is refusing guesses, and until when.
func (l *Lockout) Locked(ctx context.Context, address string) (time.Time, bool, error) {
	if l == nil {
		return time.Time{}, false, nil
	}
	var failures int
	var last int64
	err := l.db.QueryRowContext(ctx, `SELECT failures, last_unix FROM account_failures WHERE email = ?`,
		lockoutKey(address)).Scan(&failures, &last)
	if err == sql.ErrNoRows {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	until := time.Unix(last, 0).Add(l.duration)
	if failures >= l.threshold && l.now().Before(until) {
		return until, true, nil
	}
	return time.Time{}, false, nil
}

// Fail counts a failure.  Reaching the threshold, or failing again after a lock
// has ended, starts a lock.
func (l *Lockout) Fail(ctx context.Context, address string) error {
	if l == nil {
		return nil
	}
	now := l.now()
	var failures int
	err := l.db.QueryRowContext(ctx, `INSERT INTO account_failures (email, failures, last_unix) VALUES (?, 1, ?)
		ON CONFLICT(email) DO UPDATE SET failures = failures + 1, last_unix = excluded.last_unix
		RETURNING failures`, lockoutKey(address), now.Unix()).Scan(&failures)
	if err != nil {
		return err
	}
	if failures >= l.threshold && l.onLock != nil {
		l.onLock(address, time.Unix(now.Unix(), 0).Add(l.duration), failures)
	}
	return nil
}

// Clear forgets the account's failures: after a finished sign-in, a recovery, or
// `signet user-unlock`.  It reports whether there were any.
func (l *Lockout) Clear(ctx context.Context, address string) (bool, error) {
	if l == nil {
		return false, nil
	}
	result, err := l.db.ExecContext(ctx, `DELETE FROM account_failures WHERE email = ?`, lockoutKey(address))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n > 0, err
}

// Failures is the account's count of consecutive failures.
func (l *Lockout) Failures(ctx context.Context, address string) (int, error) {
	if l == nil {
		return 0, nil
	}
	var failures int
	err := l.db.QueryRowContext(ctx, `SELECT failures FROM account_failures WHERE email = ?`,
		lockoutKey(address)).Scan(&failures)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return failures, err
}
