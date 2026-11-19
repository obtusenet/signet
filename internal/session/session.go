// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package session

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
)

// HashToken is what the database holds for a token.  The token is the bearer
// credential, so a copy of the database, a backup or a temporary file must not give
// working sessions.  Tokens are 32 random bytes, so plain SHA-256 is enough: there
// is nothing to guess and no need for a salt or a slow hash.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Session represents an authenticated session
type Session struct {
	Token      string // the bearer value; never stored
	UserEmail  string
	AuthMethod string
	Claims     string // JSON serialized
	// Facts are what the sign-in learned besides who it was, as
	// claims.Facts encodes them: "" for a users.csv account.
	Facts     string
	CreatedAt time.Time
	ExpiresAt time.Time
	// IdleTimeout is this session's own idle limit in seconds, set from a
	// RADIUS reply; 0 is the store's (session_idle_timeout).
	IdleTimeout int
	// LastSeen is when a request last read the session, to within the
	// store's touch interval.
	LastSeen time.Time
}

// Store manages sessions in the database
type Store struct {
	db   *sql.DB
	idle time.Duration // session_idle_timeout; 0 is none
}

// SetIdleTimeout ends sessions after d without a request that reads them, unless
// a session has its own; 0 switches it off.
func (s *Store) SetIdleTimeout(d time.Duration) {
	s.idle = d
}

// touchEvery is how often a session's last use is written: at most once a
// minute, or more often for a shorter idle limit, so a busy session costs few
// writes and the limit is kept to within a quarter of itself.
func touchEvery(idle time.Duration) time.Duration {
	if q := idle / 4; q < time.Minute {
		return q
	}
	return time.Minute
}

// NewStore creates a new session store
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Create creates a new session
func (s *Store) Create(ctx context.Context, session *Session) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token, user_email, auth_method, claims, facts, idle_timeout, last_seen_unix, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		HashToken(session.Token),
		session.UserEmail,
		session.AuthMethod,
		session.Claims,
		session.Facts,
		session.IdleTimeout,
		session.CreatedAt.Unix(),
		session.CreatedAt,
		session.ExpiresAt,
	)
	if err != nil {
		return err
	}
	return nil
}

// Get retrieves a session by token
func (s *Store) Get(ctx context.Context, token string) (*Session, error) {
	session := Session{Token: token}
	var lastSeen int64
	err := s.db.QueryRowContext(ctx,
		`SELECT user_email, auth_method, claims, facts, idle_timeout, last_seen_unix, created_at, expires_at
		 FROM sessions WHERE token = ?`,
		HashToken(token),
	).Scan(
		&session.UserEmail,
		&session.AuthMethod,
		&session.Claims,
		&session.Facts,
		&session.IdleTimeout,
		&lastSeen,
		&session.CreatedAt,
		&session.ExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}

	// Check if session is expired
	now := time.Now()
	if now.After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	// Rows from before the idle limit have no last use: their sign-in is it.
	session.LastSeen = session.CreatedAt
	if lastSeen > 0 {
		session.LastSeen = time.Unix(lastSeen, 0)
	}
	idle := s.idle
	if session.IdleTimeout > 0 {
		idle = time.Duration(session.IdleTimeout) * time.Second
	}
	if idle > 0 {
		if now.Sub(session.LastSeen) > idle {
			return nil, ErrSessionExpired
		}
		if now.Sub(session.LastSeen) >= touchEvery(idle) {
			if _, err := s.db.ExecContext(ctx,
				`UPDATE sessions SET last_seen_unix = ? WHERE token = ?`,
				now.Unix(), HashToken(token)); err != nil {
				return nil, err
			}
			session.LastSeen = now
		}
	}

	return &session, nil
}

// UpdateClaims updates the claims for a session
func (s *Store) UpdateClaims(ctx context.Context, token, claims string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET claims = ? WHERE token = ?`,
		claims,
		HashToken(token),
	)
	return err
}

// Revoke revokes a session by token
func (s *Store) Revoke(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE token = ?`,
		HashToken(token),
	)
	if err == sql.ErrNoRows {
		return ErrSessionNotFound
	}
	return err
}

// RevokeAll revokes all sessions for a user
func (s *Store) RevokeAll(ctx context.Context, userEmail string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE user_email = ?`,
		userEmail,
	)
	return err
}

// RevokeAccount ends every session of an account and answers how many there
// were.  The name must match as the session holds it.
func (s *Store) RevokeAccount(ctx context.Context, account string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_email = ?`, account)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RevokeOthers revokes all sessions for a user except the one with this token.
func (s *Store) RevokeOthers(ctx context.Context, userEmail, keepToken string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE user_email = ? AND token <> ?`,
		userEmail, HashToken(keepToken),
	)
	return err
}

// Cleanup removes expired sessions.  julianday compares instants: the column
// holds local time with its offset, and as text a row written under another
// offset, as across a daylight-saving change, could sort as expired while valid.
func (s *Store) Cleanup(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE julianday(expires_at) < julianday('now')`,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
