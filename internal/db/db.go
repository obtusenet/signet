// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps the SQL database connection
type DB struct {
	db *sql.DB
}

// New opens or creates the SQLite3 database
func New(path string) (*DB, error) {
	if err := createPrivate(path); err != nil {
		return nil, fmt.Errorf("creating database: %w", err)
	}

	database, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_timeout=5000&_secure_delete=true")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// secure_delete overwrites removed rows with zeros, so tokens, PINs and keys do
	// not stay readable in free pages of the file.

	// Set connection pool
	database.SetMaxOpenConns(1) // SQLite doesn't handle concurrent writes well
	database.SetMaxIdleConns(1)

	if err := database.Ping(); err != nil {
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	// Run migrations
	if err := migrate(database); err != nil {
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return &DB{db: database}, nil
}

// createPrivate creates a missing database file readable by its owner alone,
// since it holds session tokens.  SQLite would otherwise create it from the
// umask, and gives the -wal and -shm files the mode of the database.  An existing
// file keeps its mode: changing that is the operator's call, and serve warns.
func createPrivate(path string) error {
	if path == ":memory:" || strings.HasPrefix(path, "file:") {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return f.Close()
}

// Close closes the database connection
func (d *DB) Close() error {
	return d.db.Close()
}

// DB returns the underlying *sql.DB (for health checks, etc.)
func (d *DB) DB() *sql.DB {
	return d.db
}

// migrate ensures the database schema is up to date
func migrate(database *sql.DB) error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			user_email TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			ip_address TEXT,
			user_agent TEXT,
			auth_method TEXT,
			claims JSON
		)`,
		`CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_email TEXT NOT NULL,
			credential_id BLOB NOT NULL,
			public_key BLOB NOT NULL,
			counter INTEGER DEFAULT 0,
			attestation_format TEXT,
			label TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(user_email, credential_id)
		)`,
		`CREATE TABLE IF NOT EXISTS api_clients (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			api_key TEXT NOT NULL UNIQUE,
			allowed_origins TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_email ON sessions(user_email)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_webauthn_user_email ON webauthn_credentials(user_email)`,
		`CREATE INDEX IF NOT EXISTS idx_webauthn_credential_id ON webauthn_credentials(credential_id)`,
	}

	tx, err := database.Begin()
	if err != nil {
		return err
	}

	for _, stmt := range schema {
		if _, err := tx.Exec(stmt); err != nil {
			tx.Rollback()
			return fmt.Errorf("executing migration: %w", err)
		}
	}

	// Record schema version
	_, err = tx.Exec("INSERT OR IGNORE INTO schema_migrations (version) VALUES (1)")
	if err != nil {
		tx.Rollback()
		return err
	}

	// What a sign-in learned besides who it was (claims.Facts): the RADIUS
	// reply, kept for claims refreshes.  Tables from before RADIUS lack it.
	if _, err := tx.Exec(`ALTER TABLE sessions ADD COLUMN facts TEXT NOT NULL DEFAULT ''`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column") {
		tx.Rollback()
		return fmt.Errorf("adding the facts column: %w", err)
	}

	// A session's own idle limit (from a RADIUS reply) and its last use, for
	// session_idle_timeout.  0 means none, and never used since sign-in.
	for _, stmt := range []string{
		`ALTER TABLE sessions ADD COLUMN idle_timeout INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE sessions ADD COLUMN last_seen_unix INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := tx.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			tx.Rollback()
			return fmt.Errorf("adding the idle columns: %w", err)
		}
	}

	if err := hashSessionTokens(tx); err != nil {
		tx.Rollback()
		return fmt.Errorf("hashing session tokens: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	compactOnce(database)
	return nil
}

// compactOnce rewrites the file after the tokens are hashed.  Updating a row only
// overwrites its current bytes: copies left in free space by earlier updates, from
// before secure_delete, would keep plain tokens on disk.  VACUUM copies live rows
// only, and the checkpoint clears the old frames from the write-ahead log.
//
// Failing is not fatal, as the sessions already work: another instance may be busy.
// The version is recorded only on success, so the next start tries again.
func compactOnce(database *sql.DB) {
	var done int
	if err := database.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = 3").Scan(&done); err != nil || done > 0 {
		return
	}
	if _, err := database.Exec("VACUUM"); err != nil {
		return
	}
	if _, err := database.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return
	}
	database.Exec("INSERT OR IGNORE INTO schema_migrations (version) VALUES (3)")
}

// hashSessionTokens replaces stored tokens with their hashes, once, so upgrading
// signs nobody out: a cookie's token still hashes to its row.  The hash must match
// session.HashToken, as a test checks.  Claiming the version comes first and takes
// the write lock, so instances starting together cannot hash a token twice.
func hashSessionTokens(tx *sql.Tx) error {
	claim, err := tx.Exec("INSERT OR IGNORE INTO schema_migrations (version) VALUES (2)")
	if err != nil {
		return err
	}
	if n, err := claim.RowsAffected(); err != nil || n == 0 {
		return err
	}

	rows, err := tx.Query("SELECT token FROM sessions")
	if err != nil {
		return err
	}
	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			rows.Close()
			return err
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	for _, token := range tokens {
		sum := sha256.Sum256([]byte(token))
		if _, err := tx.Exec("UPDATE sessions SET token = ? WHERE token = ?",
			hex.EncodeToString(sum[:]), token); err != nil {
			return err
		}
	}
	return nil
}
