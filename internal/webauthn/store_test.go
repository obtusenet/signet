// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package webauthn

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestNewStore(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	if store == nil {
		t.Fatal("expected store to be non-nil")
	}
}

func TestStoreGetUserCredentials(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()

	// Get credentials for a user with no credentials
	creds, err := store.GetUserCredentials(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("failed to get credentials: %v", err)
	}

	if len(creds) != 0 {
		t.Fatalf("expected no credentials, got %d", len(creds))
	}
}

func TestStoreDeleteCredentialNotFound(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()

	// Delete a credential that doesn't exist
	err = store.DeleteCredential(ctx, "nonexistent")
	if err != ErrCredentialNotFound {
		t.Fatalf("expected ErrCredentialNotFound, got: %v", err)
	}
}

func TestStoreGetCredentialNotFound(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()

	// Get a credential that doesn't exist
	_, err = store.GetCredential(ctx, "nonexistent")
	if err != ErrCredentialNotFound {
		t.Fatalf("expected ErrCredentialNotFound, got: %v", err)
	}
}
