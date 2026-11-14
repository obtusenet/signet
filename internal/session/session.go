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
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// Store manages sessions in the database
type Store struct {
	db *sql.DB
}

// NewStore creates a new session store
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Create creates a new session
func (s *Store) Create(ctx context.Context, session *Session) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token, user_email, auth_method, claims, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		HashToken(session.Token),
		session.UserEmail,
		session.AuthMethod,
		session.Claims,
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
	err := s.db.QueryRowContext(ctx,
		`SELECT user_email, auth_method, claims, created_at, expires_at
		 FROM sessions WHERE token = ?`,
		HashToken(token),
	).Scan(
		&session.UserEmail,
		&session.AuthMethod,
		&session.Claims,
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
	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
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
