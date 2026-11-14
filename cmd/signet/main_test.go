// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/obtusenet/signet/internal/db"
	"github.com/obtusenet/signet/internal/session"
	"github.com/obtusenet/signet/internal/webauthn"
)

func TestDeleteCredentialEndsTheAccountsSessions(t *testing.T) {
	ctx := context.Background()
	database, err := db.New(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := webauthn.NewStore(database.DB())
	if err != nil {
		t.Fatal(err)
	}
	sessions := session.NewStore(database.DB())

	id := []byte{1, 2, 3, 4}
	if err := keys.CreateUser(ctx, &gowebauthn.Credential{ID: id, PublicKey: []byte{1}}, "alice@example.com", "mine"); err != nil {
		t.Fatal(err)
	}
	for token, addr := range map[string]string{"a1": "alice@example.com", "a2": "alice@example.com", "b1": "bob@example.com"} {
		now := time.Now()
		if err := sessions.Create(ctx, &session.Session{Token: token, UserEmail: addr, AuthMethod: "password", Claims: "{}", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := deleteCredentialAndSessions(ctx, keys, sessions, "nonexistent"); err == nil {
		t.Error("an unknown credential was accepted")
	}
	if _, err := sessions.Get(ctx, "a1"); err != nil {
		t.Errorf("a failed delete ended a session: %v", err)
	}

	addr, err := deleteCredentialAndSessions(ctx, keys, sessions, hex.EncodeToString(id))
	if err != nil {
		t.Fatal(err)
	}
	if addr != "alice@example.com" {
		t.Errorf("answered %q", addr)
	}
	if _, err := keys.GetCredential(ctx, hex.EncodeToString(id)); err == nil {
		t.Error("key still present")
	}
	for _, token := range []string{"a1", "a2"} {
		if _, err := sessions.Get(ctx, token); err == nil {
			t.Errorf("session %s survived", token)
		}
	}
	if _, err := sessions.Get(ctx, "b1"); err != nil {
		t.Errorf("another account's session ended: %v", err)
	}
}

func TestReadPasswordLine(t *testing.T) {
	for input, want := range map[string]string{
		"s3cret\n":        "s3cret",
		"s3cret":          "s3cret",
		"s3cret\r\n":      "s3cret",
		" with spaces \n": " with spaces ",
		"first\nsecond\n": "first",
	} {
		got, err := readPasswordLine(strings.NewReader(input))
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "\n", "\r\n"} {
		if got, err := readPasswordLine(strings.NewReader(input)); err == nil {
			t.Errorf("%q: got %q, want an error", input, got)
		}
	}
}
