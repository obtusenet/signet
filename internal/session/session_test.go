// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package session

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/db"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	database, err := db.New(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return NewStore(database.DB())
}

func addSession(t *testing.T, s *Store, token string, expires time.Time) {
	t.Helper()
	if err := s.Create(context.Background(), &Session{
		Token: token, UserEmail: "a@example.com", AuthMethod: "password", Claims: "{}",
		CreatedAt: expires.Add(-time.Hour), ExpiresAt: expires,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupRemovesOnlyExpiredSessions(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	addSession(t, s, "expired", time.Now().Add(-time.Minute))
	addSession(t, s, "valid", time.Now().Add(time.Hour))

	n, err := s.Cleanup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("removed %d, want 1", n)
	}
	if _, err := s.Get(ctx, "valid"); err != nil {
		t.Errorf("the valid session went: %v", err)
	}
	if _, err := s.Get(ctx, "expired"); err == nil {
		t.Error("the expired session is still there")
	}
}

// The column holds local time with its offset, so the same instant can read
// earlier or later as text.  Only the instant may decide.
func TestCleanupComparesInstantsAcrossOffsets(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	west := time.FixedZone("west", -11*3600)
	east := time.FixedZone("east", 13*3600)
	addSession(t, s, "valid-west", time.Now().Add(30*time.Minute).In(west))
	addSession(t, s, "expired-east", time.Now().Add(-30*time.Minute).In(east))

	if _, err := s.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "valid-west"); err != nil {
		t.Errorf("a valid session went because of its offset: %v", err)
	}
	var left int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE token = ?`, HashToken("expired-east")).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Error("an expired session stayed because of its offset")
	}
}

func TestDatabaseHoldsOnlyTheHash(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	addSession(t, s, "the-bearer-token", time.Now().Add(time.Hour))

	var stored string
	if err := s.db.QueryRow(`SELECT token FROM sessions`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "the-bearer-token" {
		t.Error("the token is stored as it is")
	}
	if stored != HashToken("the-bearer-token") {
		t.Errorf("stored %q", stored)
	}

	sess, err := s.Get(ctx, "the-bearer-token")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Token != "the-bearer-token" {
		t.Errorf("Get returned Token %q", sess.Token)
	}

	// What a copy of the database holds must not work as a credential.
	if _, err := s.Get(ctx, stored); err == nil {
		t.Error("the stored value worked as a token")
	}
}

func TestEveryOperationFindsTheSessionByItsToken(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	addSession(t, s, "tok", time.Now().Add(time.Hour))

	if err := s.UpdateClaims(ctx, "tok", `{"role":"admin"}`); err != nil {
		t.Fatal(err)
	}
	sess, err := s.Get(ctx, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Claims != `{"role":"admin"}` {
		t.Errorf("claims %q", sess.Claims)
	}
	if err := s.Revoke(ctx, "tok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "tok"); err == nil {
		t.Error("the revoked session still works")
	}
}

// An upgrade signs nobody out, and hashes only once however often it starts.
func TestUpgradeHashesExistingTokensOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	database, err := db.New(path)
	if err != nil {
		t.Fatal(err)
	}
	// As a database from before the migration looks.
	for _, stmt := range []string{
		`DELETE FROM schema_migrations WHERE version >= 2`,
		`INSERT INTO sessions (token, user_email, auth_method, claims, created_at, expires_at)
		 VALUES ('old-plain-token', 'a@example.com', 'password', '{"k":1}',
		         datetime('now'), datetime('now', '+1 hour'))`,
	} {
		if _, err := database.DB().Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	database.Close()

	for i := 0; i < 3; i++ {
		database, err := db.New(path)
		if err != nil {
			t.Fatal(err)
		}
		s := NewStore(database.DB())
		sess, err := s.Get(context.Background(), "old-plain-token")
		if err != nil {
			t.Fatalf("start %d: an existing session stopped working: %v", i, err)
		}
		if sess.Claims != `{"k":1}` {
			t.Errorf("start %d: claims %q", i, sess.Claims)
		}
		var plain int
		if err := database.DB().QueryRow(`SELECT COUNT(*) FROM sessions WHERE token = 'old-plain-token'`).Scan(&plain); err != nil {
			t.Fatal(err)
		}
		if plain != 0 {
			t.Errorf("start %d: the plain token is still there", i)
		}
		database.Close()
	}
}

// The plain value must leave the files, including the stale copies an earlier
// update left in free space while secure_delete was off, as on an existing database.
func TestUpgradeLeavesNoPlainTokenOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	database, err := db.New(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`PRAGMA secure_delete = OFF`,
		`DELETE FROM schema_migrations WHERE version >= 2`,
		`INSERT INTO sessions (token, user_email, auth_method, claims, created_at, expires_at)
		 VALUES ('PLAINTOKENMARKER', 'a@example.com', 'password', '{}',
		         datetime('now'), datetime('now', '+1 hour'))`,
		// Rows coming and going split and free pages, which leaves stale copies
		// of the marker's row in free space, as a real database's history does.
		`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3000)
		 INSERT INTO sessions (token, user_email, auth_method, claims, created_at, expires_at)
		 SELECT printf('filler%059d', i), 'b@example.com', 'password', '{}',
		        datetime('now'), datetime('now', '+1 hour') FROM n`,
		`DELETE FROM sessions WHERE user_email = 'b@example.com'`,
		`PRAGMA wal_checkpoint(TRUNCATE)`,
	} {
		if _, err := database.DB().Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	database.Close()

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(before, []byte("PLAINTOKENMARKER")) {
		t.Fatal("the test did not set up a plain token on disk")
	}

	database, err = db.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, name := range []string{path, path + "-wal"} {
		contents, err := os.ReadFile(name)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if bytes.Contains(contents, []byte("PLAINTOKENMARKER")) {
			t.Errorf("%s still holds the plain token", filepath.Base(name))
		}
	}
	if _, err := NewStore(database.DB()).Get(context.Background(), "PLAINTOKENMARKER"); err != nil {
		t.Errorf("the session stopped working: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode %04o after the rewrite", perm)
	}
}

// A database hashed before the rewrite existed, or whose rewrite failed, still gets one.
func TestRewriteRunsOnceEvenAfterTheHashing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	database, err := db.New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.DB().Exec(`DELETE FROM schema_migrations WHERE version = 3`); err != nil {
		t.Fatal(err)
	}
	database.Close()

	for i := 0; i < 2; i++ {
		database, err := db.New(path)
		if err != nil {
			t.Fatal(err)
		}
		var done int
		if err := database.DB().QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 3`).Scan(&done); err != nil {
			t.Fatal(err)
		}
		if done != 1 {
			t.Errorf("start %d: version 3 recorded %d times", i, done)
		}
		database.Close()
	}
}
