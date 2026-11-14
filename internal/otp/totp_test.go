// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package otp

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"

	"github.com/obtusenet/signet/internal/db"
)

const addr = "a@example.com"

func newTOTP(t *testing.T) *TOTPStore {
	t.Helper()
	database, err := db.New(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	s, err := NewTOTPStore(database.DB(), []byte("a-secret"), "Signet")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := hotp.GenerateCodeCustom(secret, uint64(at.Unix()/totpPeriod), hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func enroll(t *testing.T, s *TOTPStore, email string, now time.Time) (string, []string) {
	t.Helper()
	e, err := s.BeginEnrollment(context.Background(), email, "phone")
	if err != nil {
		t.Fatal(err)
	}
	codes, err := s.FinishEnrollment(context.Background(), email, codeAt(t, e.Secret, now), now)
	if err != nil {
		t.Fatal(err)
	}
	return e.Secret, codes
}

// The published test vector: SHA-1, 8 digits, this secret, at 59 s (RFC 6238 App. B).
func TestCodesFollowTheRFC(t *testing.T) {
	secret := recoveryEncoding.EncodeToString([]byte("12345678901234567890"))
	code, err := hotp.GenerateCodeCustom(secret, 59/totpPeriod, hotp.ValidateOpts{Digits: otp.DigitsEight, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	if code != "94287082" {
		t.Errorf("got %s", code)
	}
}

func TestEnrollmentNeedsAWorkingCode(t *testing.T) {
	ctx := context.Background()
	s := newTOTP(t)
	now := time.Now()
	e, err := s.BeginEnrollment(ctx, addr, "phone")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(e.QR, "data:image/png;base64,") || !strings.Contains(e.URL, "otpauth://totp/") || !strings.Contains(e.URL, "issuer=Signet") {
		t.Errorf("enrollment: %+v", e.URL)
	}
	if has, _ := s.HasKeys(ctx, addr); has {
		t.Fatal("a key exists before it was proved")
	}
	if _, err := s.FinishEnrollment(ctx, addr, "000000", now.Add(-time.Hour)); !errors.Is(err, ErrBadCode) && !errors.Is(err, ErrNoEnrollment) {
		t.Errorf("a wrong code: %v", err)
	}
	if has, _ := s.HasKeys(ctx, addr); has {
		t.Fatal("a wrong code saved a key")
	}
	codes, err := s.FinishEnrollment(ctx, addr, codeAt(t, e.Secret, now), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != RecoveryCodeCount {
		t.Errorf("%d recovery codes", len(codes))
	}
	if _, err := s.FinishEnrollment(ctx, addr, codeAt(t, e.Secret, now), now); !errors.Is(err, ErrNoEnrollment) {
		t.Errorf("finished twice: %v", err)
	}
}

func TestEnrollmentExpires(t *testing.T) {
	ctx := context.Background()
	s := newTOTP(t)
	e, err := s.BeginEnrollment(ctx, addr, "phone")
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(enrollmentTTL + time.Minute)
	if _, err := s.FinishEnrollment(ctx, addr, codeAt(t, e.Secret, later), later); !errors.Is(err, ErrNoEnrollment) {
		t.Errorf("%v", err)
	}
}

func TestACodeWorksOnce(t *testing.T) {
	ctx := context.Background()
	s := newTOTP(t)
	now := time.Now()
	secret, _ := enroll(t, s, addr, now)

	// The code that proved the key is spent.
	if err := s.Verify(ctx, addr, codeAt(t, secret, now), now); !errors.Is(err, ErrBadCode) {
		t.Errorf("the enrollment code: %v", err)
	}
	next := now.Add(totpPeriod * time.Second)
	if err := s.Verify(ctx, addr, codeAt(t, secret, next), next); err != nil {
		t.Errorf("the next code: %v", err)
	}
	if err := s.Verify(ctx, addr, codeAt(t, secret, next), next); !errors.Is(err, ErrBadCode) {
		t.Errorf("that code again: %v", err)
	}
	// An earlier code still inside the window is no good after a later one.
	if err := s.Verify(ctx, addr, codeAt(t, secret, now), next); !errors.Is(err, ErrBadCode) {
		t.Errorf("an earlier code: %v", err)
	}
}

func TestOneCodeCannotBeUsedTwiceAtOnce(t *testing.T) {
	ctx := context.Background()
	s := newTOTP(t)
	now := time.Now()
	secret, _ := enroll(t, s, addr, now)
	next := now.Add(totpPeriod * time.Second)
	code := codeAt(t, secret, next)
	var mu sync.Mutex
	won := 0
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.Verify(ctx, addr, code, next) == nil {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if won != 1 {
		t.Errorf("%d requests used the code", won)
	}
}

func TestCodeWindow(t *testing.T) {
	ctx := context.Background()
	s := newTOTP(t)
	start := time.Now().Add(-time.Hour)
	secret, _ := enroll(t, s, addr, start)
	now := time.Now()
	for name, at := range map[string]time.Duration{"two steps old": -2 * totpPeriod * time.Second, "two steps ahead": 2 * totpPeriod * time.Second} {
		if err := s.Verify(ctx, addr, codeAt(t, secret, now.Add(at)), now); !errors.Is(err, ErrBadCode) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := s.Verify(ctx, addr, codeAt(t, secret, now.Add(-totpPeriod*time.Second)), now); err != nil {
		t.Errorf("one step old: %v", err)
	}
	if err := s.Verify(ctx, addr, " "+codeAt(t, secret, now)[:3]+" "+codeAt(t, secret, now)[3:]+" ", now); err != nil {
		t.Errorf("with spaces: %v", err)
	}
}

func TestAnyOfSeveralKeysWorks(t *testing.T) {
	ctx := context.Background()
	s := newTOTP(t)
	now := time.Now()
	first, codes := enroll(t, s, addr, now)
	second, more := enroll(t, s, addr, now)
	if len(codes) != RecoveryCodeCount || more != nil {
		t.Errorf("codes: %d then %d", len(codes), len(more))
	}
	next := now.Add(totpPeriod * time.Second)
	if err := s.Verify(ctx, addr, codeAt(t, second, next), next); err != nil {
		t.Errorf("second key: %v", err)
	}
	if err := s.Verify(ctx, addr, codeAt(t, first, next), next); err != nil {
		t.Errorf("first key: %v", err)
	}
}

func TestSecretsAreEncryptedAndBoundToTheAccount(t *testing.T) {
	ctx := context.Background()
	s := newTOTP(t)
	now := time.Now()
	secret, _ := enroll(t, s, addr, now)

	var stored []byte
	if err := s.db.QueryRow(`SELECT secret FROM totp_keys`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), secret) {
		t.Error("the secret is stored in the clear")
	}
	// A row moved to another account is no use there.
	if _, err := s.db.Exec(`UPDATE totp_keys SET email = 'b@example.com'`); err != nil {
		t.Fatal(err)
	}
	next := now.Add(totpPeriod * time.Second)
	if err := s.Verify(ctx, "b@example.com", codeAt(t, secret, next), next); !errors.Is(err, ErrBadCode) {
		t.Errorf("moved row: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE totp_keys SET email = ?`, addr); err != nil {
		t.Fatal(err)
	}
	// Another cookie_secret cannot read it, and says why.
	other, err := NewTOTPStore(s.db, []byte("another-secret"), "Signet")
	if err != nil {
		t.Fatal(err)
	}
	err = other.Verify(ctx, addr, codeAt(t, secret, next), next)
	if !errors.Is(err, ErrBadCode) || !strings.Contains(err.Error(), "cookie_secret") {
		t.Errorf("another secret: %v", err)
	}
}

func TestRecoveryCodes(t *testing.T) {
	ctx := context.Background()
	s := newTOTP(t)
	_, codes := enroll(t, s, addr, time.Now())
	seen := map[string]bool{}
	for _, code := range codes {
		if seen[code] || !LooksLikeRecoveryCode(code) {
			t.Errorf("code %q", code)
		}
		seen[code] = true
	}
	if ok, err := s.UseRecoveryCode(ctx, "b@example.com", codes[0]); ok || err != nil {
		t.Errorf("another account: %v, %v", ok, err)
	}
	if ok, err := s.UseRecoveryCode(ctx, addr, strings.ToUpper(strings.ReplaceAll(codes[0], "-", ""))); !ok || err != nil {
		t.Errorf("typed differently: %v, %v", ok, err)
	}
	if ok, _ := s.UseRecoveryCode(ctx, addr, codes[0]); ok {
		t.Error("a code worked twice")
	}
	if left, _ := s.RecoveryCodesLeft(ctx, addr); left != RecoveryCodeCount-1 {
		t.Errorf("%d left", left)
	}
	var stored string
	if err := s.db.QueryRow(`SELECT code_hash FROM totp_recovery_codes LIMIT 1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	for _, code := range codes {
		if strings.Contains(stored, normalizeRecoveryCode(code)) {
			t.Error("a code is stored in the clear")
		}
	}

	fresh, err := s.NewRecoveryCodes(ctx, addr)
	if err != nil || len(fresh) != RecoveryCodeCount {
		t.Fatalf("%d, %v", len(fresh), err)
	}
	if ok, _ := s.UseRecoveryCode(ctx, addr, codes[1]); ok {
		t.Error("an old code survived replacement")
	}
	if ok, _ := s.UseRecoveryCode(ctx, addr, fresh[0]); !ok {
		t.Error("a new code did not work")
	}
	if _, err := s.NewRecoveryCodes(ctx, "nokeys@example.com"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("no keys: %v", err)
	}
	if LooksLikeRecoveryCode("123 456") {
		t.Error("a six-digit code looks like a recovery code")
	}
}

func TestDeletingKeys(t *testing.T) {
	ctx := context.Background()
	s := newTOTP(t)
	now := time.Now()
	enroll(t, s, addr, now)
	enroll(t, s, addr, now)
	enroll(t, s, "b@example.com", now)
	keys, err := s.ListKeys(ctx, addr)
	if err != nil || len(keys) != 2 || keys[0].Label != "phone" {
		t.Fatalf("%+v, %v", keys, err)
	}
	others, _ := s.ListKeys(ctx, "b@example.com")
	if err := s.DeleteKey(ctx, addr, others[0].ID); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("another account's key: %v", err)
	}
	if err := s.DeleteKey(ctx, addr, keys[0].ID); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.RecoveryCodesLeft(ctx, addr); left != RecoveryCodeCount {
		t.Errorf("codes went with a key that was not the last: %d", left)
	}
	if err := s.DeleteKey(ctx, addr, keys[1].ID); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.RecoveryCodesLeft(ctx, addr); left != 0 {
		t.Errorf("%d codes outlived the last key", left)
	}
	if has, _ := s.HasKeys(ctx, "b@example.com"); !has {
		t.Error("another account lost its key")
	}
	if n, err := s.DeleteAll(ctx, "b@example.com"); n != 1 || err != nil {
		t.Errorf("delete all: %d, %v", n, err)
	}
	if left, _ := s.RecoveryCodesLeft(ctx, "b@example.com"); left != 0 {
		t.Errorf("%d codes left", left)
	}
}

func TestKeysAreBounded(t *testing.T) {
	ctx := context.Background()
	s := newTOTP(t)
	now := time.Now()
	for i := 0; i < MaxTOTPKeys; i++ {
		enroll(t, s, addr, now)
	}
	if _, err := s.BeginEnrollment(ctx, addr, "one more"); !errors.Is(err, ErrTooManyKeys) {
		t.Errorf("%v", err)
	}
}

func TestStepKinds(t *testing.T) {
	ctx := context.Background()
	s := newTOTP(t)
	token, err := s.CreateStep(ctx, addr, "password", StepEnrol, EnrolStepTTL)
	if err != nil {
		t.Fatal(err)
	}
	email, method, step, err := s.Step(ctx, token)
	if err != nil || email != addr || method != "password" || step != StepEnrol {
		t.Fatalf("%q %q %q %v", email, method, step, err)
	}
	code, _ := s.CreatePending(ctx, addr, "email_pin")
	if _, _, step, _ := s.Step(ctx, code); step != StepCode {
		t.Errorf("CreatePending made a %q step", step)
	}
}

// A database made before steps had kinds gains the column, and its steps ask for
// a code.
func TestStepColumnIsAdded(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE totp_pending (token_hash TEXT PRIMARY KEY, email TEXT NOT NULL,
		method TEXT NOT NULL, expires_unix INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO totp_pending VALUES (?, ?, 'password', 9999999999)`, hashSecret("t"), addr); err != nil {
		t.Fatal(err)
	}
	s, err := NewTOTPStore(db, []byte("secret"), "Signet")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, step, err := s.Step(context.Background(), "t"); err != nil || step != StepCode {
		t.Errorf("%q %v", step, err)
	}
	if _, err := NewTOTPStore(db, []byte("secret"), "Signet"); err != nil {
		t.Errorf("a second start: %v", err)
	}
}

func TestPendingStep(t *testing.T) {
	ctx := context.Background()
	s := newTOTP(t)
	token, err := s.CreatePending(ctx, addr, "password")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		email, method, err := s.Pending(ctx, token)
		if err != nil || email != addr || method != "password" {
			t.Fatalf("%q %q %v", email, method, err)
		}
	}
	if err := s.TakePending(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err := s.TakePending(ctx, token); !errors.Is(err, ErrNoPending) {
		t.Errorf("second take: %v", err)
	}
	if _, _, err := s.Pending(ctx, token); !errors.Is(err, ErrNoPending) {
		t.Errorf("after take: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO totp_pending (token_hash, email, method, expires_unix) VALUES ('old', ?, 'password', 1)`, addr); err != nil {
		t.Fatal(err)
	}
	if err := s.PurgeExpired(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM totp_pending`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d left, %v", n, err)
	}
}
