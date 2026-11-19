// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package otp

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"image/png"
	"strings"
	"time"
	"unicode"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

const (
	totpPeriod = 30 // seconds in a step (RFC 6238 §4.1)
	// totpSkew is how many steps either side of now a code may be from, for a
	// clock that is a little off (RFC 6238 §5.2).
	totpSkew = 1

	enrollmentTTL = 10 * time.Minute
	pendingTTL    = 5 * time.Minute
	// EnrolStepTTL leaves time to install an app or find a key.
	EnrolStepTTL = 15 * time.Minute

	// RecoveryCodeCount is how many recovery codes an account gets at a time.
	RecoveryCodeCount = 10
	// MaxTOTPKeys bounds one account's keys.
	MaxTOTPKeys = 10
)

var (
	// ErrBadCode reports a code that is wrong, too old or already used.
	ErrBadCode = errors.New("code is not valid")
	// ErrNoEnrollment reports that no enrollment is in progress.
	ErrNoEnrollment = errors.New("no enrollment in progress")
	// ErrNoPending reports a sign-in step that is unknown, used or expired.
	ErrNoPending = errors.New("sign-in step is not valid or has expired")
	// ErrKeyNotFound reports a key the account does not have.
	ErrKeyNotFound = errors.New("no such key")
	// ErrTooManyKeys reports an account at MaxTOTPKeys.
	ErrTooManyKeys = errors.New("too many keys")
)

// TOTPKey describes a key, without its secret.
type TOTPKey struct {
	ID        string
	Label     string
	CreatedAt time.Time
}

// Enrollment is what a person needs to set up an authenticator.
type Enrollment struct {
	Secret string // base32, to type in
	URL    string // the otpauth:// address a QR code holds
	QR     string // a PNG of that QR code, as a data: URI
}

// TOTPStore keeps TOTP keys in the database that instances share.  A secret must be
// readable to check a code, so it cannot be hashed.  It is encrypted with a key
// derived from cookie_secret, so a leaked database or backup alone is no use.
// Changing cookie_secret therefore makes every key unreadable.
type TOTPStore struct {
	db     *sql.DB
	aead   cipher.AEAD
	issuer string
}

// NewTOTPStore creates the tables if needed.
func NewTOTPStore(db *sql.DB, secret []byte, issuer string) (*TOTPStore, error) {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("signet totp secrets"))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS totp_keys (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			label TEXT NOT NULL,
			secret BLOB NOT NULL,
			last_step INTEGER NOT NULL,
			created_unix INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_totp_keys_email ON totp_keys(email)`,
		`CREATE TABLE IF NOT EXISTS totp_enrollments (
			email TEXT PRIMARY KEY,
			label TEXT NOT NULL,
			secret BLOB NOT NULL,
			expires_unix INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS totp_recovery_codes (
			code_hash TEXT PRIMARY KEY,
			email TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_totp_recovery_email ON totp_recovery_codes(email)`,
		`CREATE TABLE IF NOT EXISTS totp_pending (
			token_hash TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			method TEXT NOT NULL,
			expires_unix INTEGER NOT NULL
		)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return nil, fmt.Errorf("creating TOTP tables: %w", err)
		}
	}
	// What the step asks for: StepCode, StepMail or StepEnrol.  Tables made
	// before 0.13.28 lack the column, and every step in them asked for a code.
	if _, err := db.Exec(`ALTER TABLE totp_pending ADD COLUMN step TEXT NOT NULL DEFAULT 'code'`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column") {
		return nil, fmt.Errorf("adding the step column: %w", err)
	}
	// What the step carries forward: a RADIUS challenge's State, and the facts
	// the session will keep.  Opaque here.
	if _, err := db.Exec(`ALTER TABLE totp_pending ADD COLUMN data TEXT NOT NULL DEFAULT ''`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column") {
		return nil, fmt.Errorf("adding the data column: %w", err)
	}
	return &TOTPStore{db: db, aead: aead, issuer: issuer}, nil
}

// The address is bound in, so a row copied to another account does not decrypt.
func (s *TOTPStore) seal(email, secret string) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, []byte(secret), []byte(email)), nil
}

func (s *TOTPStore) open(email string, sealed []byte) (string, error) {
	if len(sealed) < s.aead.NonceSize() {
		return "", errors.New("stored secret is too short")
	}
	nonce, body := sealed[:s.aead.NonceSize()], sealed[s.aead.NonceSize():]
	plain, err := s.aead.Open(nil, nonce, body, []byte(email))
	if err != nil {
		return "", fmt.Errorf("stored secret cannot be read, perhaps because cookie_secret changed: %w", err)
	}
	return string(plain), nil
}

func randomID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashSecret(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// BeginEnrollment starts adding a key, replacing any enrollment in progress.  Nothing
// is saved as a key until a code proves the authenticator has it.
func (s *TOTPStore) BeginEnrollment(ctx context.Context, email, label string) (*Enrollment, error) {
	keys, err := s.ListKeys(ctx, email)
	if err != nil {
		return nil, err
	}
	if len(keys) >= MaxTOTPKeys {
		return nil, ErrTooManyKeys
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: email,
		Period:      totpPeriod,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("generating a secret: %w", err)
	}
	sealed, err := s.seal(email, key.Secret())
	if err != nil {
		return nil, fmt.Errorf("encrypting a secret: %w", err)
	}
	now := time.Now()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM totp_enrollments WHERE expires_unix < ?`, now.Unix()); err != nil {
		return nil, err
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO totp_enrollments (email, label, secret, expires_unix) VALUES (?, ?, ?, ?)`,
		email, label, sealed, now.Add(enrollmentTTL).Unix()); err != nil {
		return nil, fmt.Errorf("storing an enrollment: %w", err)
	}

	image, err := key.Image(240, 240)
	if err != nil {
		return nil, fmt.Errorf("drawing a QR code: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, image); err != nil {
		return nil, fmt.Errorf("encoding a QR code: %w", err)
	}
	return &Enrollment{
		Secret: key.Secret(),
		URL:    key.URL(),
		QR:     "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
	}, nil
}

// FinishEnrollment saves the key if the code proves the authenticator has it, and
// that code cannot then be used to sign in.  The first key of an account also gets
// recovery codes, returned this once.
func (s *TOTPStore) FinishEnrollment(ctx context.Context, email, code string, now time.Time) ([]string, error) {
	var label string
	var sealed []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT label, secret FROM totp_enrollments WHERE email = ? AND expires_unix >= ?`,
		email, now.Unix()).Scan(&label, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoEnrollment
	}
	if err != nil {
		return nil, err
	}
	secret, err := s.open(email, sealed)
	if err != nil {
		return nil, err
	}
	step, ok := matchingStep(secret, code, now, 0)
	if !ok {
		return nil, ErrBadCode
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}

	had, err := s.HasKeys(ctx, email)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO totp_keys (id, email, label, secret, last_step, created_unix) VALUES (?, ?, ?, ?, ?, ?)`,
		id, email, label, sealed, step, now.Unix()); err != nil {
		return nil, fmt.Errorf("storing a key: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM totp_enrollments WHERE email = ?`, email); err != nil {
		return nil, err
	}
	var codes []string
	if !had {
		if codes, err = replaceRecoveryCodes(ctx, tx, email); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}

// matchingStep finds the time step a code belongs to, later than after.
func matchingStep(secret, code string, now time.Time, after int64) (int64, bool) {
	code = strings.Join(strings.Fields(code), "")
	current := now.Unix() / totpPeriod
	opts := hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	for step := current - totpSkew; step <= current+totpSkew; step++ {
		if step <= after {
			continue
		}
		want, err := hotp.GenerateCodeCustom(secret, uint64(step), opts)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// Verify accepts a code from any of the account's keys, once: a code is never good
// again, nor is any from an earlier step of that key (RFC 6238 §5.2).  The update
// decides, so of two requests racing with one code only one succeeds.
func (s *TOTPStore) Verify(ctx context.Context, email, code string, now time.Time) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id, secret, last_step FROM totp_keys WHERE email = ?`, email)
	if err != nil {
		return err
	}
	type stored struct {
		id     string
		sealed []byte
		last   int64
	}
	var keys []stored
	for rows.Next() {
		var k stored
		if err := rows.Scan(&k.id, &k.sealed, &k.last); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	var unreadable error
	for _, k := range keys {
		secret, err := s.open(email, k.sealed)
		if err != nil {
			unreadable = err
			continue
		}
		step, ok := matchingStep(secret, code, now, k.last)
		if !ok {
			continue
		}
		result, err := s.db.ExecContext(ctx,
			`UPDATE totp_keys SET last_step = ? WHERE id = ? AND last_step < ?`, step, k.id, step)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err == nil && n == 1 {
			return nil
		}
	}
	if unreadable != nil {
		return fmt.Errorf("%w: %v", ErrBadCode, unreadable)
	}
	return ErrBadCode
}

// HasKeys reports whether the account has any key.
func (s *TOTPStore) HasKeys(ctx context.Context, email string) (bool, error) {
	var found int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM totp_keys WHERE email = ? LIMIT 1`, email).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// CountAll reports how many keys there are, for a warning while TOTP is off.
func (s *TOTPStore) CountAll(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM totp_keys`).Scan(&n)
	return n, err
}

// ListKeys lists the account's keys, oldest first.
func (s *TOTPStore) ListKeys(ctx context.Context, email string) ([]TOTPKey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, label, created_unix FROM totp_keys WHERE email = ? ORDER BY created_unix, id`, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []TOTPKey
	for rows.Next() {
		var key TOTPKey
		var created int64
		if err := rows.Scan(&key.ID, &key.Label, &created); err != nil {
			return nil, err
		}
		key.CreatedAt = time.Unix(created, 0)
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// DeleteKey removes a key of the account.  Without keys the recovery codes have no
// purpose, so they go with the last one.
func (s *TOTPStore) DeleteKey(ctx context.Context, email, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM totp_keys WHERE id = ? AND email = ?`, id, email)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrKeyNotFound
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM totp_recovery_codes WHERE email = ? AND NOT EXISTS (SELECT 1 FROM totp_keys WHERE email = ?)`,
		email, email); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteAll removes everything TOTP about an account.  It answers how many keys went.
func (s *TOTPStore) DeleteAll(ctx context.Context, email string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM totp_keys WHERE email = ?`, email)
	if err != nil {
		return 0, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	for _, table := range []string{"totp_recovery_codes", "totp_enrollments", "totp_pending"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE email = ?`, email); err != nil {
			return 0, err
		}
	}
	return n, tx.Commit()
}

// normalizeRecoveryCode lets a code be typed with or without its dashes, in any case.
func normalizeRecoveryCode(code string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToLower(r)
	}, code)
}

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func replaceRecoveryCodes(ctx context.Context, tx *sql.Tx, email string) ([]string, error) {
	if _, err := tx.ExecContext(ctx, `DELETE FROM totp_recovery_codes WHERE email = ?`, email); err != nil {
		return nil, err
	}
	codes := make([]string, 0, RecoveryCodeCount)
	for i := 0; i < RecoveryCodeCount; i++ {
		raw := make([]byte, 10) // 80 bits, so a plain hash is enough
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		text := strings.ToLower(recoveryEncoding.EncodeToString(raw))
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO totp_recovery_codes (code_hash, email) VALUES (?, ?)`,
			hashSecret(text), email); err != nil {
			return nil, err
		}
		codes = append(codes, text[:4]+"-"+text[4:8]+"-"+text[8:12]+"-"+text[12:])
	}
	return codes, nil
}

// NewRecoveryCodes replaces the account's recovery codes, for one with keys.
func (s *TOTPStore) NewRecoveryCodes(ctx context.Context, email string) ([]string, error) {
	has, err := s.HasKeys(ctx, email)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, ErrKeyNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	codes, err := replaceRecoveryCodes(ctx, tx, email)
	if err != nil {
		return nil, err
	}
	return codes, tx.Commit()
}

// UseRecoveryCode spends one code of the account, reporting whether it was good.
func (s *TOTPStore) UseRecoveryCode(ctx context.Context, email, code string) (bool, error) {
	var found string
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM totp_recovery_codes WHERE code_hash = ? AND email = ? RETURNING email`,
		hashSecret(normalizeRecoveryCode(code)), email).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// RecoveryCodesLeft counts the account's unused recovery codes.
func (s *TOTPStore) RecoveryCodesLeft(ctx context.Context, email string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM totp_recovery_codes WHERE email = ?`, email).Scan(&n)
	return n, err
}

// LooksLikeRecoveryCode tells a recovery code from a six-digit one.
func LooksLikeRecoveryCode(code string) bool {
	return len(normalizeRecoveryCode(code)) > 8
}

// The second steps of a sign-in.
const (
	StepCode   = "code"   // a code from an authenticator app, or a recovery code
	StepMail   = "mail"   // a PIN mailed after a password
	StepEnrol  = "enrol"  // add a second factor; the account has none
	StepRadius = "radius" // answer a RADIUS server's challenge
)

// PendingTTL is how long the code step waits.
const PendingTTL = pendingTTL

// CreatePending records that an account passed its first step by method.  The token
// allows only the code step, and only for a few minutes.
func (s *TOTPStore) CreatePending(ctx context.Context, email, method string) (string, error) {
	return s.CreateStep(ctx, email, method, StepCode, pendingTTL)
}

// CreateStep records that an account passed its first step by method, and must
// take step next.  The token allows only that step, for ttl.
func (s *TOTPStore) CreateStep(ctx context.Context, email, method, step string, ttl time.Duration) (string, error) {
	return s.CreateStepData(ctx, email, method, step, ttl, "")
}

// CreateStepData is CreateStep with data the step carries forward.
func (s *TOTPStore) CreateStepData(ctx context.Context, email, method, step string, ttl time.Duration, data string) (string, error) {
	token, err := randomID()
	if err != nil {
		return "", err
	}
	now := time.Now()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM totp_pending WHERE expires_unix < ?`, now.Unix()); err != nil {
		return "", err
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO totp_pending (token_hash, email, method, step, data, expires_unix) VALUES (?, ?, ?, ?, ?, ?)`,
		hashSecret(token), email, method, step, data, now.Add(ttl).Unix()); err != nil {
		return "", fmt.Errorf("storing a sign-in step: %w", err)
	}
	return token, nil
}

// Pending returns who a live token belongs to and how they passed the first step.
func (s *TOTPStore) Pending(ctx context.Context, token string) (string, string, error) {
	email, method, _, err := s.Step(ctx, token)
	return email, method, err
}

// Step returns who a live token belongs to, how they passed the first step, and
// which step it allows.
func (s *TOTPStore) Step(ctx context.Context, token string) (email, method, step string, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT email, method, step FROM totp_pending WHERE token_hash = ? AND expires_unix >= ?`,
		hashSecret(token), time.Now().Unix()).Scan(&email, &method, &step)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", ErrNoPending
	}
	return email, method, step, err
}

// StepData answers what a live step carries forward.
func (s *TOTPStore) StepData(ctx context.Context, token string) (string, error) {
	var data string
	err := s.db.QueryRowContext(ctx,
		`SELECT data FROM totp_pending WHERE token_hash = ? AND expires_unix >= ?`,
		hashSecret(token), time.Now().Unix()).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNoPending
	}
	return data, err
}

// TakePending spends a token.  The delete decides, so only one request gets it.
func (s *TOTPStore) TakePending(ctx context.Context, token string) error {
	var email string
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM totp_pending WHERE token_hash = ? AND expires_unix >= ? RETURNING email`,
		hashSecret(token), time.Now().Unix()).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNoPending
	}
	return err
}

// PurgeExpired removes enrollments and sign-in steps that can no longer be used.
func (s *TOTPStore) PurgeExpired(ctx context.Context) error {
	now := time.Now().Unix()
	for _, table := range []string{"totp_enrollments", "totp_pending"} {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM `+table+` WHERE expires_unix < ?`, now); err != nil {
			return err
		}
	}
	return nil
}
