// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package email

import (
	"context"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"path/filepath"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/db"
)

func TestGeneratePIN(t *testing.T) {
	pin, err := GeneratePINSafe()
	if err != nil {
		t.Fatalf("failed to generate PIN: %v", err)
	}

	if len(pin) != 6 {
		t.Fatalf("expected PIN length 6, got %d", len(pin))
	}

	// Check that PIN is numeric
	for _, c := range pin {
		if c < '0' || c > '9' {
			t.Fatalf("PIN contains non-numeric character: %c", c)
		}
	}
}

func TestGeneratePINSafe(t *testing.T) {
	pin1, err := GeneratePINSafe()
	if err != nil {
		t.Fatalf("failed to generate PIN: %v", err)
	}

	pin2, err := GeneratePINSafe()
	if err != nil {
		t.Fatalf("failed to generate PIN: %v", err)
	}

	// Two generated PINs should be different (with high probability)
	if pin1 == pin2 {
		t.Fatal("two generated PINs should be different")
	}
}

func TestPINStore(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	sender := NewStubSender()
	store, err := NewPINStore(db, sender, 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to create PIN store: %v", err)
	}

	ctx := context.Background()

	// Create and send PIN
	_, err = store.CreateAndSendPIN(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("failed to create and send PIN: %v", err)
	}

	// Verify sent email
	sentEmails := sender.GetSentEmails()
	if len(sentEmails) != 1 {
		t.Fatalf("expected 1 sent email, got %d", len(sentEmails))
	}

	if sentEmails[0].To != "test@example.com" {
		t.Fatalf("expected email to test@example.com, got %s", sentEmails[0].To)
	}

	// Verify PIN
	err = store.VerifyPIN(ctx, "test@example.com", "123456")
	if err != ErrPINNotFound {
		t.Fatalf("expected ErrPINNotFound, got: %v", err)
	}
}

func TestPINStoreVerifyCorrectPIN(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	sender := NewStubSender()
	store, err := NewPINStore(db, sender, 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to create PIN store: %v", err)
	}

	ctx := context.Background()

	// Create and send PIN
	_, err = store.CreateAndSendPIN(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("failed to create and send PIN: %v", err)
	}

	// Get the PIN from sent email
	sentEmails := sender.GetSentEmails()
	if len(sentEmails) != 1 {
		t.Fatalf("expected 1 sent email, got %d", len(sentEmails))
	}

	// Extract PIN from email body
	pin := ""
	for _, c := range sentEmails[0].Body {
		if c >= '0' && c <= '9' {
			pin += string(c)
		}
		if len(pin) == 6 {
			break
		}
	}

	if len(pin) != 6 {
		t.Fatalf("expected 6-digit PIN in email body, got %d digits", len(pin))
	}

	// Verify correct PIN
	err = store.VerifyPIN(ctx, "test@example.com", pin)
	if err != nil {
		t.Fatalf("failed to verify correct PIN: %v", err)
	}

	// Verify PIN is now used (should return ErrPINNotFound)
	err = store.VerifyPIN(ctx, "test@example.com", pin)
	if err != ErrPINNotFound {
		t.Fatalf("expected ErrPINNotFound for used PIN, got: %v", err)
	}
}

// Failures are counted on the PIN rows, so purging at expiry would forgive them.
func TestPurgeKeepsRowsThroughTheLockoutWindow(t *testing.T) {
	database, err := db.New(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewPINStore(database.DB(), NewStubSender(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	add := func(id string, age time.Duration) {
		t.Helper()
		created := time.Now().Add(-age)
		if err := store.storePIN(ctx, &PIN{
			ID: id, Email: "a@example.com", PINHash: "x",
			ExpiresAt: created.Add(10 * time.Minute), CreatedAt: created,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := database.DB().Exec(`UPDATE pins SET attempts = 2 WHERE id = ?`, id); err != nil {
			t.Fatal(err)
		}
	}
	add("in-lockout", 20*time.Minute) // expired, but its failures still count
	add("past-lockout", 2*time.Hour)

	n, err := store.PurgeExpiredPins(ctx, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("removed %d, want 1", n)
	}
	failures, err := store.RecentFailures(ctx, "a@example.com", time.Now().Add(-30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if failures != 2 {
		t.Errorf("%d failures counted, want 2", failures)
	}
}

// The old modulo over 24 bits favoured values under 777216 by about 6%.
func TestGeneratePINCoversTheRange(t *testing.T) {
	var low, high int
	for i := 0; i < 20000; i++ {
		pin, err := GeneratePINSafe()
		if err != nil {
			t.Fatal(err)
		}
		if len(pin) != 6 {
			t.Fatalf("PIN %q", pin)
		}
		if pin < "500000" {
			low++
		} else {
			high++
		}
	}
	if low < 9000 || high < 9000 {
		t.Errorf("uneven: %d below 500000, %d above", low, high)
	}
}
