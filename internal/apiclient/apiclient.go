// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

// Package apiclient manages the applications allowed to call the validation
// API.  A client owns an API key; only a hash of the key is stored, so a key
// is shown once, when it is created.
package apiclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNotFound is returned when no client matches.
var ErrNotFound = errors.New("api client not found")

// Client is one registered application.
type Client struct {
	ID             int64
	Name           string
	AllowedOrigins []string
	CreatedAt      time.Time
}

// Store is the api_clients table.
type Store struct {
	db *sql.DB
}

// NewStore wraps a database handle.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// GenerateKey returns a new API key.  The "sk_" prefix makes a leaked key
// recognisable in logs and scanners.
func GenerateKey() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("reading randomness: %w", err)
	}
	return "sk_" + hex.EncodeToString(buf), nil
}

// HashKey is what is stored and compared; the plaintext key never reaches
// the database.
func HashKey(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hex.EncodeToString(sum[:])
}

// Create registers a client and returns its key.  The key cannot be
// recovered later.
func (s *Store) Create(ctx context.Context, name string, origins []string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("client name is required")
	}

	key, err := GenerateKey()
	if err != nil {
		return "", err
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO api_clients (name, api_key, allowed_origins) VALUES (?, ?, ?)`,
		name, HashKey(key), strings.Join(origins, " "))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return "", fmt.Errorf("client %q already exists", name)
		}
		return "", fmt.Errorf("inserting client: %w", err)
	}
	return key, nil
}

// List returns every registered client (never the keys).
func (s *Store) List(ctx context.Context) ([]Client, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, COALESCE(allowed_origins, ''), created_at
		   FROM api_clients ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("listing clients: %w", err)
	}
	defer rows.Close()

	var out []Client
	for rows.Next() {
		var c Client
		var origins string
		if err := rows.Scan(&c.ID, &c.Name, &origins, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning client: %w", err)
		}
		c.AllowedOrigins = strings.Fields(origins)
		out = append(out, c)
	}
	return out, rows.Err()
}

// Lookup finds the client owning key.
func (s *Store) Lookup(ctx context.Context, key string) (*Client, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, ErrNotFound
	}

	var c Client
	var origins string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, COALESCE(allowed_origins, ''), created_at
		   FROM api_clients WHERE api_key = ?`, HashKey(key)).
		Scan(&c.ID, &c.Name, &origins, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("looking up client: %w", err)
	}
	c.AllowedOrigins = strings.Fields(origins)
	return &c, nil
}

// Revoke deletes the named client.  It reports whether a row was removed.
func (s *Store) Revoke(ctx context.Context, name string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_clients WHERE name = ?`, strings.TrimSpace(name))
	if err != nil {
		return false, fmt.Errorf("deleting client: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// OriginAllowed reports whether any client lists origin among its allowed
// origins.  It is used for CORS preflight, which carries no API key.
func (s *Store) OriginAllowed(ctx context.Context, origin string) (bool, error) {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return false, nil
	}

	rows, err := s.db.QueryContext(ctx, `SELECT COALESCE(allowed_origins, '') FROM api_clients`)
	if err != nil {
		return false, fmt.Errorf("reading allowed origins: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var list string
		if err := rows.Scan(&list); err != nil {
			return false, err
		}
		for _, o := range strings.Fields(list) {
			if strings.EqualFold(o, origin) {
				return true, nil
			}
		}
	}
	return false, rows.Err()
}
