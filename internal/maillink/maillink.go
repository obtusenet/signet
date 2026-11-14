// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

// Package maillink keeps the one-time tokens carried by links sent in mail.  A
// token proves the holder can read that mailbox and nothing else, so only its
// hash is stored, it works once, and a newer one replaces the older.
package maillink

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Kinds of link.  A token only ever works for the kind it was made for.
const (
	Recovery     = "recovery"
	Registration = "registration"
)

// ErrInvalid reports a token that is unknown, used, expired or of another kind.
var ErrInvalid = errors.New("link is not valid or has expired")

// Store holds the tokens in the database that instances share.
type Store struct {
	db *sql.DB
}

// NewStore creates the table if needed.
func NewStore(db *sql.DB) (*Store, error) {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS mail_links (
			token_hash TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			email TEXT NOT NULL,
			expires_unix INTEGER NOT NULL
		)`); err != nil {
		return nil, fmt.Errorf("creating mail_links: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_mail_links_email ON mail_links(email)`); err != nil {
		return nil, fmt.Errorf("indexing mail_links: %w", err)
	}
	return &Store{db: db}, nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Create makes a token for the address, ending any earlier one of that kind.
func (s *Store) Create(ctx context.Context, kind, email string, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM mail_links WHERE kind = ? AND email = ?`, kind, email); err != nil {
		return "", fmt.Errorf("ending earlier links: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO mail_links (token_hash, kind, email, expires_unix) VALUES (?, ?, ?, ?)`,
		hashToken(token), kind, email, time.Now().Add(ttl).Unix()); err != nil {
		return "", fmt.Errorf("storing link: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

// Email returns the address a live token belongs to, spending nothing.
func (s *Store) Email(ctx context.Context, kind, token string) (string, error) {
	var email string
	err := s.db.QueryRowContext(ctx,
		`SELECT email FROM mail_links WHERE token_hash = ? AND kind = ? AND expires_unix >= ?`,
		hashToken(token), kind, time.Now().Unix()).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalid
	}
	return email, err
}

// Consume spends a token and returns its address.  The delete decides, so of two
// requests racing with one token only one gets the address.
func (s *Store) Consume(ctx context.Context, kind, token string) (string, error) {
	var email string
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM mail_links WHERE token_hash = ? AND kind = ? AND expires_unix >= ? RETURNING email`,
		hashToken(token), kind, time.Now().Unix()).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalid
	}
	return email, err
}

// DeleteEmail ends every link for an address, when its account goes.
func (s *Store) DeleteEmail(ctx context.Context, email string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM mail_links WHERE email = ?`, email)
	return err
}

// PurgeExpired removes what can no longer be used.
func (s *Store) PurgeExpired(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM mail_links WHERE expires_unix < ?`, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
