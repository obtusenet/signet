// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package db

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestNew(t *testing.T) {
	// Create a temporary database file
	tmpFile, err := os.CreateTemp("", "signet-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	database, err := New(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// Check that the database is reachable
	if err := database.DB().Ping(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrations(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "signet-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	database, err := New(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// Verify tables exist
	tables := []string{"schema_migrations", "sessions", "webauthn_credentials", "api_clients"}
	for _, table := range tables {
		var count int
		err := database.DB().QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("expected table %s to exist", table)
		}
	}
}

// The umask is opened up, so only the explicit mode can keep these private.
func TestNewDatabaseIsPrivate(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	path := filepath.Join(t.TempDir(), "sessions.db")
	database, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.DB().Exec(`INSERT INTO schema_migrations (version) VALUES (999)`); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s: mode %04o, want 0600", filepath.Base(name), perm)
		}
	}
}

func TestExistingDatabaseKeepsItsMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	database, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Errorf("mode %04o, want 0640 left alone", perm)
	}
}

func TestSecureDeleteIsOn(t *testing.T) {
	database, err := New(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var on int
	if err := database.DB().QueryRow(`PRAGMA secure_delete`).Scan(&on); err != nil {
		t.Fatal(err)
	}
	if on != 1 {
		t.Errorf("secure_delete = %d", on)
	}
}

// Removing a row must remove its bytes from the file, not just unlink the row.
func TestDeletedRowLeavesNoBytesBehind(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	database, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, stmt := range []string{
		`INSERT INTO sessions (token, user_email, expires_at) VALUES ('DELETEDROWMARKER', 'a@example.com', datetime('now'))`,
		`PRAGMA wal_checkpoint(TRUNCATE)`,
		`DELETE FROM sessions WHERE token = 'DELETEDROWMARKER'`,
		`PRAGMA wal_checkpoint(TRUNCATE)`,
	} {
		if _, err := database.DB().Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "DELETEDROWMARKER") {
		t.Error("the deleted row is still in the file")
	}
}
