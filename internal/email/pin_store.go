// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package email

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

// ErrPINNotFound is returned when a PIN is not found
var ErrPINNotFound = errors.New("PIN not found")

// ErrPINExpired is returned when a PIN has expired
var ErrPINExpired = errors.New("PIN expired")

// ErrPINAlreadyUsed is returned when a PIN has already been used
var ErrPINAlreadyUsed = errors.New("PIN already used")

// PIN represents a stored PIN
type PIN struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	PINHash   string    `json:"-"` // SHA256 hash of the PIN
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
	CreatedAt time.Time `json:"created_at"`
}

// PINStore manages PIN storage in SQLite3
type PINStore struct {
	db           *sql.DB
	ttl          time.Duration
	sender       Sender
	templatesDir string
}

// NewPINStore creates a new PIN store
func NewPINStore(db *sql.DB, sender Sender, ttl time.Duration) (*PINStore, error) {
	store := &PINStore{
		db:     db,
		ttl:    ttl,
		sender: sender,
	}

	// Create table if not exists
	if err := store.createTable(); err != nil {
		return nil, fmt.Errorf("creating PIN table: %w", err)
	}

	return store, nil
}

// NewPINStoreWithTemplate creates a new PIN store with template support
func NewPINStoreWithTemplate(db *sql.DB, sender Sender, ttl time.Duration, templatesDir string) (*PINStore, error) {
	store, err := NewPINStore(db, sender, ttl)
	if err != nil {
		return nil, err
	}
	store.templatesDir = templatesDir
	return store, nil
}

// createTable creates the PINs table
func (s *PINStore) createTable() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS pins (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			pin_hash TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			used INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0
		)
	`)
	if err != nil {
		return err
	}

	// Databases created before attempts were counted lack the column.  Two
	// instances may share a database, so losing this race is not an error.
	if _, err := s.db.Exec(`ALTER TABLE pins ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	return nil
}

// CreateAndSendPIN creates a new PIN, hashes it, stores it, and sends it via email
func (s *PINStore) CreateAndSendPIN(ctx context.Context, email string) (string, error) {
	// Generate PIN
	pin, err := GeneratePINSafe()
	if err != nil {
		return "", fmt.Errorf("generating PIN: %w", err)
	}

	// Hash PIN
	pinHash := hashPIN(pin)

	// Create PIN record
	p := &PIN{
		ID:        uuid.New().String(),
		Email:     email,
		PINHash:   pinHash,
		ExpiresAt: time.Now().Add(s.ttl),
		Used:      false,
		CreatedAt: time.Now(),
	}

	// Only the newest PIN is valid, so repeated sends cannot add live targets
	// for a guesser.  Attempts stay on the old rows and keep counting.
	if _, err := s.db.ExecContext(ctx,
		`UPDATE pins SET used = 1 WHERE email = ? AND used = 0`, email); err != nil {
		return "", fmt.Errorf("retiring earlier PINs: %w", err)
	}

	if err := s.storePIN(ctx, p); err != nil {
		return "", fmt.Errorf("storing PIN: %w", err)
	}

	// Render email template
	emailTemplate := &PINEmailData{
		PIN:           pin,
		Email:         email,
		ExpiryMinutes: int(s.ttl.Minutes()),
		AppName:       "Signet",
	}

	subject := "Your Signet PIN"
	text := buildInPINEmailBody(emailTemplate)
	html := ""
	if s.templatesDir != "" {
		text, html, err = RenderPINEmailData(s.templatesDir, emailTemplate)
		if err != nil {
			return "", fmt.Errorf("rendering email template: %w", err)
		}
	}

	// Send PIN via email
	if err := s.sender.Send(email, subject, text, html); err != nil {
		return "", fmt.Errorf("sending PIN email: %w", err)
	}

	return p.ID, nil
}

// storePIN stores a PIN in the database
func (s *PINStore) storePIN(ctx context.Context, p *PIN) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO pins (id, email, pin_hash, expires_at, used, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		p.ID,
		p.Email,
		p.PINHash,
		p.ExpiresAt,
		p.Used,
		p.CreatedAt,
	)
	return err
}

// VerifyPIN checks a guess against the live PINs for an address.  A wrong
// guess while a PIN is live is counted against the address (see
// RecentFailures); a guess when nothing is live cannot succeed, so it is not.
func (s *PINStore) VerifyPIN(ctx context.Context, email, pin string) error {
	type candidate struct {
		id        string
		hash      string
		expiresAt time.Time
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, pin_hash, expires_at FROM pins WHERE email = ? AND used = 0`,
		email,
	)
	if err != nil {
		return fmt.Errorf("querying PIN: %w", err)
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.hash, &c.expiresAt); err != nil {
			rows.Close()
			return fmt.Errorf("scanning PIN: %w", err)
		}
		candidates = append(candidates, c)
	}
	// The pool holds a single connection: finish reading before writing.
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("reading PINs: %w", err)
	}

	now := time.Now()
	pinHash := []byte(hashPIN(pin))
	var match *candidate
	var live []string
	for i := range candidates {
		c := &candidates[i]
		isMatch := subtle.ConstantTimeCompare([]byte(c.hash), pinHash) == 1
		if now.After(c.expiresAt) {
			if isMatch {
				return ErrPINExpired
			}
			continue
		}
		live = append(live, c.id)
		if isMatch {
			match = c
		}
	}

	if match == nil {
		for _, id := range live {
			if _, err := s.db.ExecContext(ctx,
				`UPDATE pins SET attempts = attempts + 1 WHERE id = ?`, id); err != nil {
				return fmt.Errorf("recording failed attempt: %w", err)
			}
		}
		return ErrPINNotFound
	}

	// Conditional, so two concurrent requests cannot both spend the PIN.
	result, err := s.db.ExecContext(ctx,
		`UPDATE pins SET used = 1 WHERE id = ? AND used = 0`, match.id)
	if err != nil {
		return fmt.Errorf("marking PIN as used: %w", err)
	}
	if n, err := result.RowsAffected(); err != nil || n == 0 {
		return ErrPINNotFound
	}

	// The address has proved itself; earlier typos no longer count.
	if _, err := s.db.ExecContext(ctx,
		`UPDATE pins SET attempts = 0 WHERE email = ?`, email); err != nil {
		return fmt.Errorf("clearing failed attempts: %w", err)
	}
	return nil
}

// RecentFailures counts wrong guesses against PINs issued for the address
// since the given time.  The count lives in the database, so it is shared by
// every signet process using it and survives a restart.
func (s *PINStore) RecentFailures(ctx context.Context, email string, since time.Time) (int, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT attempts, created_at FROM pins WHERE email = ? AND attempts > 0`,
		email,
	)
	if err != nil {
		return 0, fmt.Errorf("querying failed attempts: %w", err)
	}
	defer rows.Close()

	total := 0
	for rows.Next() {
		var attempts int
		var createdAt time.Time
		if err := rows.Scan(&attempts, &createdAt); err != nil {
			return 0, fmt.Errorf("scanning failed attempts: %w", err)
		}
		if createdAt.After(since) {
			total += attempts
		}
	}
	return total, rows.Err()
}

// hashPIN hashes a PIN using SHA256
func hashPIN(pin string) string {
	h := sha256.Sum256([]byte(pin))
	return fmt.Sprintf("%x", h)
}

// PurgeExpiredPins removes PINs that expired more than keep ago.  Failed guesses
// are counted on these rows (see RecentFailures), so keep must cover the lockout
// window, or removing a row would also forgive its failures.
func (s *PINStore) PurgeExpiredPins(ctx context.Context, keep time.Duration) (int, error) {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM pins WHERE julianday(expires_at) < julianday('now', ?)`,
		fmt.Sprintf("-%d seconds", int64(keep.Seconds())),
	)
	if err != nil {
		return 0, fmt.Errorf("purging expired PINs: %w", err)
	}

	n, _ := result.RowsAffected()
	return int(n), nil
}
