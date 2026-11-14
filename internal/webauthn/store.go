// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package webauthn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	_ "github.com/mattn/go-sqlite3"
)

// Store manages WebAuthn credentials, in-flight ceremonies and enrollment
// invites in SQLite3, so every signet process sharing the database sees them.
type Store struct {
	db *sql.DB
}

// NewStore creates a new WebAuthn credential store
func NewStore(db *sql.DB) (*Store, error) {
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrating webauthn store: %w", err)
	}
	return s, nil
}

// migrate ensures the tables exist.  db.New creates webauthn_credentials with
// the original, shorter column list on databases that predate these columns,
// so missing ones are added rather than assumed.
func (s *Store) migrate() error {
	if _, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS webauthn_credentials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		credential_id TEXT NOT NULL,
		public_key BLOB NOT NULL,
		counter INTEGER NOT NULL DEFAULT 0,
		attestation_format TEXT,
		label TEXT,
		user_email TEXT NOT NULL,
		aaguid BLOB,
		backup_eligible INTEGER NOT NULL DEFAULT 0,
		backup_state INTEGER NOT NULL DEFAULT 0,
		transports TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	)`); err != nil {
		return err
	}

	for _, column := range []string{
		"aaguid BLOB",
		"backup_eligible INTEGER NOT NULL DEFAULT 0",
		"backup_state INTEGER NOT NULL DEFAULT 0",
		"transports TEXT",
	} {
		// Two instances may share a database, so losing this race is fine.
		if _, err := s.db.Exec(`ALTER TABLE webauthn_credentials ADD COLUMN ` + column); err != nil &&
			!strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}

	_, err := s.db.Exec(`
	CREATE INDEX IF NOT EXISTS idx_webauthn_creds_user ON webauthn_credentials(user_email);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_creds_unique_id ON webauthn_credentials(credential_id);
	CREATE TABLE IF NOT EXISTS webauthn_ceremonies (
		id TEXT PRIMARY KEY,
		kind TEXT NOT NULL,
		user_email TEXT NOT NULL,
		data BLOB NOT NULL,
		expires_unix INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS webauthn_invites (
		token_hash TEXT PRIMARY KEY,
		user_email TEXT NOT NULL,
		expires_unix INTEGER NOT NULL,
		used INTEGER NOT NULL DEFAULT 0
	);
	`)
	return err
}

// WebAuthnCredential is our storage representation of a WebAuthn credential
type WebAuthnCredential struct {
	ID             string    `json:"id"`
	PublicKey      []byte    `json:"-"`
	Counter        uint32    `json:"counter"`
	AttestationFmt string    `json:"attestation_format"`
	Label          string    `json:"label"`
	UserEmail      string    `json:"user_email"`
	AAGUID         []byte    `json:"-"`
	BackupEligible bool      `json:"backup_eligible"`
	BackupState    bool      `json:"backup_state"`
	Transports     []string  `json:"transports"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// transportsToString converts a slice of transports to a JSON string
func transportsToString(ts []protocol.AuthenticatorTransport) string {
	if len(ts) == 0 {
		return ""
	}
	s := "["
	for i, t := range ts {
		if i > 0 {
			s += ","
		}
		s += fmt.Sprintf("%q", string(t))
	}
	s += "]"
	return s
}

// parseTransports parses a JSON transport string to a slice
func parseTransports(s string) []string {
	if s == "" {
		return nil
	}
	result := []string{}
	inString := false
	current := ""
	for _, c := range s {
		switch {
		case c == '"':
			if inString {
				result = append(result, current)
				current = ""
				inString = false
			} else {
				inString = true
			}
		case inString:
			current += string(c)
		}
	}
	return result
}

// CreateUser registers a WebAuthn credential for a user
func (s *Store) CreateUser(ctx context.Context, cred *webauthn.Credential, userEmail, label string) error {
	now := time.Now()
	credID := hex.EncodeToString(cred.ID)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO webauthn_credentials 
		(credential_id, public_key, counter, attestation_format, label, user_email, aaguid, backup_eligible, backup_state, transports, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		credID,
		cred.PublicKey,
		cred.Authenticator.SignCount,
		cred.AttestationFormat,
		label,
		userEmail,
		cred.Authenticator.AAGUID,
		cred.Flags.BackupEligible,
		cred.Flags.BackupState,
		transportsToString(cred.Transport),
		now,
		now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrCredentialExists
		}
		return fmt.Errorf("inserting credential: %w", err)
	}
	return nil
}

// credentialColumns tolerates rows from before the optional columns existed.
const credentialColumns = `credential_id, public_key, counter,
	COALESCE(attestation_format, ''), COALESCE(label, ''), user_email, aaguid,
	backup_eligible, backup_state, COALESCE(transports, ''), created_at, updated_at`

// scanCredential reads one row selected with credentialColumns.
func scanCredential(scan func(...any) error) (*WebAuthnCredential, error) {
	var c WebAuthnCredential
	var transports string
	if err := scan(
		&c.ID,
		&c.PublicKey,
		&c.Counter,
		&c.AttestationFmt,
		&c.Label,
		&c.UserEmail,
		&c.AAGUID,
		&c.BackupEligible,
		&c.BackupState,
		&transports,
		&c.CreatedAt,
		&c.UpdatedAt,
	); err != nil {
		return nil, err
	}
	c.Transports = parseTransports(transports)
	return &c, nil
}

// GetUserCredentials retrieves all WebAuthn credentials for a user
func (s *Store) GetUserCredentials(ctx context.Context, userEmail string) ([]WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+credentialColumns+` FROM webauthn_credentials WHERE user_email = ?`,
		userEmail,
	)
	if err != nil {
		return nil, fmt.Errorf("querying credentials: %w", err)
	}
	defer rows.Close()

	var creds []WebAuthnCredential
	for rows.Next() {
		c, err := scanCredential(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scanning credential: %w", err)
		}
		creds = append(creds, *c)
	}
	return creds, rows.Err()
}

// GetCredential retrieves a single WebAuthn credential by ID
func (s *Store) GetCredential(ctx context.Context, credentialID string) (*WebAuthnCredential, error) {
	c, err := scanCredential(s.db.QueryRowContext(ctx,
		`SELECT `+credentialColumns+` FROM webauthn_credentials WHERE credential_id = ?`,
		credentialID,
	).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCredentialNotFound
		}
		return nil, fmt.Errorf("querying credential: %w", err)
	}
	return c, nil
}

// DeleteCredential removes a WebAuthn credential
func (s *Store) DeleteCredential(ctx context.Context, credentialID string) error {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM webauthn_credentials WHERE credential_id = ?`,
		credentialID,
	)
	if err != nil {
		return fmt.Errorf("deleting credential: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrCredentialNotFound
	}
	return nil
}

// DeleteUser removes everything WebAuthn holds for an address: credentials,
// invites and in-flight ceremonies.  It returns the number of credentials
// removed.  A later account with the same address must not inherit any of it.
func (s *Store) DeleteUser(ctx context.Context, userEmail string) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM webauthn_credentials WHERE user_email = ?`, userEmail)
	if err != nil {
		return 0, fmt.Errorf("deleting credentials: %w", err)
	}
	removed, _ := result.RowsAffected()
	for _, stmt := range []string{
		`DELETE FROM webauthn_invites WHERE user_email = ?`,
		`DELETE FROM webauthn_ceremonies WHERE user_email = ?`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt, userEmail); err != nil {
			return removed, fmt.Errorf("deleting WebAuthn state: %w", err)
		}
	}
	return removed, nil
}

// UpdateCounter updates the signature counter for a credential
func (s *Store) UpdateCounter(ctx context.Context, credentialID string, counter uint32) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE webauthn_credentials SET counter = ?, updated_at = ? WHERE credential_id = ?`,
		counter,
		time.Now(),
		credentialID,
	)
	if err != nil {
		return fmt.Errorf("updating counter: %w", err)
	}
	return nil
}

// ErrCredentialExists is returned when a credential with the same ID already exists
var ErrCredentialExists = errors.New("credential already exists")

// ErrCredentialNotFound is returned when a credential is not found
var ErrCredentialNotFound = errors.New("credential not found")

// ErrCeremonyNotFound is returned for an unknown, expired or mismatched ceremony.
var ErrCeremonyNotFound = errors.New("webauthn ceremony not found")

// ErrInviteNotFound is returned for an unknown, expired or used invite.
var ErrInviteNotFound = errors.New("invite is not valid")

// randomToken returns n random bytes, base64url encoded.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// saveCeremony stores challenge state and returns the ceremony's ID.  Expired
// ceremonies are dropped here, which keeps the table bounded.
func (s *Store) saveCeremony(ctx context.Context, kind, userEmail string, data []byte, ttl time.Duration) (string, error) {
	now := time.Now()
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM webauthn_ceremonies WHERE expires_unix < ?`, now.Unix()); err != nil {
		return "", fmt.Errorf("purging ceremonies: %w", err)
	}
	id, err := randomToken(16)
	if err != nil {
		return "", err
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO webauthn_ceremonies (id, kind, user_email, data, expires_unix) VALUES (?, ?, ?, ?, ?)`,
		id, kind, userEmail, data, now.Add(ttl).Unix()); err != nil {
		return "", fmt.Errorf("storing ceremony: %w", err)
	}
	return id, nil
}

// takeCeremony returns a ceremony's state and removes it, so a challenge can
// be answered only once.  The kind and address must match how it was started.
func (s *Store) takeCeremony(ctx context.Context, id, kind, userEmail string) ([]byte, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT data FROM webauthn_ceremonies
		 WHERE id = ? AND kind = ? AND user_email = ? AND expires_unix >= ?`,
		id, kind, userEmail, time.Now().Unix()).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCeremonyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying ceremony: %w", err)
	}

	// Conditional on the row still existing, so two racing requests cannot
	// both spend it.
	result, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_ceremonies WHERE id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("deleting ceremony: %w", err)
	}
	if n, err := result.RowsAffected(); err != nil || n == 0 {
		return nil, ErrCeremonyNotFound
	}
	return data, nil
}

// hashInvite is what the database holds, so reading it does not yield usable
// links.  The token has 256 bits of entropy, so a fast hash is sufficient.
func hashInvite(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateInvite issues a one-time enrollment token for an address and returns
// it.  This is the only time the token is available.  Earlier invites for the
// address stop working.
func (s *Store) CreateInvite(ctx context.Context, userEmail string, ttl time.Duration) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM webauthn_invites WHERE user_email = ? OR expires_unix < ?`,
		userEmail, time.Now().Unix()); err != nil {
		return "", fmt.Errorf("retiring earlier invites: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO webauthn_invites (token_hash, user_email, expires_unix) VALUES (?, ?, ?)`,
		hashInvite(token), userEmail, time.Now().Add(ttl).Unix()); err != nil {
		return "", fmt.Errorf("storing invite: %w", err)
	}
	return token, nil
}

// InviteEmail returns the address a live invite belongs to, without using it.
func (s *Store) InviteEmail(ctx context.Context, token string) (string, error) {
	var userEmail string
	err := s.db.QueryRowContext(ctx,
		`SELECT user_email FROM webauthn_invites
		 WHERE token_hash = ? AND used = 0 AND expires_unix >= ?`,
		hashInvite(token), time.Now().Unix()).Scan(&userEmail)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInviteNotFound
	}
	if err != nil {
		return "", fmt.Errorf("querying invite: %w", err)
	}
	return userEmail, nil
}

// ConsumeInvite spends an invite.  Exactly one caller can succeed.
func (s *Store) ConsumeInvite(ctx context.Context, token string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE webauthn_invites SET used = 1
		 WHERE token_hash = ? AND used = 0 AND expires_unix >= ?`,
		hashInvite(token), time.Now().Unix())
	if err != nil {
		return fmt.Errorf("using invite: %w", err)
	}
	if n, err := result.RowsAffected(); err != nil || n == 0 {
		return ErrInviteNotFound
	}
	return nil
}

// ToWebAuthnCredential converts a stored credential to a webauthn.Credential.
// The ID column holds the hex form of the raw credential ID.
func (c *WebAuthnCredential) ToWebAuthnCredential() (webauthn.Credential, error) {
	id, err := hex.DecodeString(c.ID)
	if err != nil {
		return webauthn.Credential{}, fmt.Errorf("decoding credential ID: %w", err)
	}
	transport := make([]protocol.AuthenticatorTransport, len(c.Transports))
	for i, t := range c.Transports {
		transport[i] = protocol.AuthenticatorTransport(t)
	}
	return webauthn.Credential{
		ID:                id,
		PublicKey:         c.PublicKey,
		AttestationFormat: c.AttestationFmt,
		Authenticator: webauthn.Authenticator{
			SignCount: c.Counter,
			AAGUID:    c.AAGUID,
		},
		Flags: webauthn.CredentialFlags{
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Transport: transport,
	}, nil
}
