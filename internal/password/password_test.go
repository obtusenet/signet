// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package password

import (
	"errors"
	"strings"
	"testing"
)

func TestHashArgon2id(t *testing.T) {
	h := NewHasher("argon2id", 12, Argon2idParams{
		Time:       1,
		Memory:     64 * 1024,
		Parallel:   4,
		SaltLength: 16,
		KeyLength:  32,
	})

	hash, err := h.Hash("password123")
	if err != nil {
		t.Fatal(err)
	}

	if !isArgon2id(hash) {
		t.Error("expected argon2id hash format")
	}

	// Verify the hash
	if err := h.Verify("password123", hash); err != nil {
		t.Errorf("verification failed: %v", err)
	}

	// Wrong password should fail
	if err := h.Verify("wrongpassword", hash); err == nil {
		t.Error("expected verification to fail for wrong password")
	}
}

func TestHashBcrypt(t *testing.T) {
	h := NewHasher("bcrypt", 10, Argon2idParams{})

	hash, err := h.Hash("password123")
	if err != nil {
		t.Fatal(err)
	}

	if !isBcrypt(hash) {
		t.Error("expected bcrypt hash format")
	}

	// Verify the hash
	if err := h.Verify("password123", hash); err != nil {
		t.Errorf("verification failed: %v", err)
	}

	// Wrong password should fail
	if err := h.Verify("wrongpassword", hash); err == nil {
		t.Error("expected verification to fail for wrong password")
	}
}

func TestAlgorithmFromHash(t *testing.T) {
	tests := []struct {
		hash     string
		expected string
	}{
		{"$argon2id$v=19$m=65536,t=1,p=4$...", "argon2id"},
		{"$2a$10$...", "bcrypt"},
		{"invalid_hash", "unknown"},
	}

	for _, tt := range tests {
		got := AlgorithmFromHash(tt.hash)
		if got != tt.expected {
			t.Errorf("AlgorithmFromHash(%q) = %q, want %q", tt.hash, got, tt.expected)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		pw  string
		err bool
	}{
		{"short", true},
		{"1234567", true},
		{"12345678", false},
		{"longenough", false},
	}

	for _, tt := range tests {
		err := ValidatePassword(tt.pw)
		if tt.err && err == nil {
			t.Errorf("expected error for password %q", tt.pw)
		}
		if !tt.err && err != nil {
			t.Errorf("unexpected error for password %q: %v", tt.pw, err)
		}
	}
}

func TestConstantTimeCompare(t *testing.T) {
	if err := constantTimeCompare([]byte("same"), []byte("same")); err != nil {
		t.Errorf("equal: %v", err)
	}
	for _, other := range []string{"sAme", "samE", "sam", "same!", ""} {
		if err := constantTimeCompare([]byte("same"), []byte(other)); !errors.Is(err, ErrHashMismatch) {
			t.Errorf("%q: %v", other, err)
		}
	}
}

func TestHashesRunBounded(t *testing.T) {
	if n := cap(slots); n < 1 || n > 8 {
		t.Errorf("%d hashes at once, want 1 to 8", n)
	}
}

// A malformed argon2id hash is refused like a wrong password.  Several of
// these made the argon2 package panic before the parameters were checked.
func TestVerifyMalformedArgon2id(t *testing.T) {
	h := NewHasher("argon2id", 10, Argon2idParams{Time: 1, Memory: 64, Parallel: 1, SaltLength: 16, KeyLength: 32})
	good, err := h.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Verify("correct horse", good); err != nil {
		t.Fatalf("good hash refused: %v", err)
	}
	parts := strings.Split(good, "$")
	salt, key := parts[4], parts[5]
	mk := func(params, s, k string) string { return "$argon2id$v=19$" + params + "$" + s + "$" + k }
	cases := map[string]string{
		"p=0":            mk("m=64,t=1,p=0", salt, key),
		"p=256":          mk("m=4096,t=1,p=256", salt, key),
		"t=0":            mk("m=64,t=0,p=1", salt, key),
		"t too high":     mk("m=64,t=65,p=1", salt, key),
		"m under 8p":     mk("m=7,t=1,p=1", salt, key),
		"m too high":     mk("m=4194305,t=1,p=1", salt, key),
		"empty key":      mk("m=64,t=1,p=1", salt, ""),
		"short key":      mk("m=64,t=1,p=1", salt, "AAAA"),
		"empty salt":     mk("m=64,t=1,p=1", "", key),
		"bad base64":     mk("m=64,t=1,p=1", salt, "!!!!"),
		"missing p":      mk("m=64,t=1", salt, key),
		"repeated m":     mk("m=64,m=64,t=1", salt, key),
		"order":          mk("t=1,m=64,p=1", salt, key),
		"negative":       mk("m=64,t=-1,p=1", salt, key),
		"not a number":   mk("m=64,t=x,p=1", salt, key),
		"version":        strings.Replace(good, "v=19", "v=16", 1),
		"extra field":    good + "$x",
		"too few fields": "$argon2id$v=19$m=64,t=1,p=1$" + salt,
		"prefix only":    "$argon2id$",
	}
	for name, hash := range cases {
		t.Run(name, func(t *testing.T) {
			err := h.Verify("correct horse", hash)
			if !errors.Is(err, ErrMalformedHash) || !errors.Is(err, ErrHashMismatch) {
				t.Fatalf("got %v, want ErrMalformedHash", err)
			}
		})
	}
}

func TestCheckArgon2idParams(t *testing.T) {
	if err := CheckArgon2idParams(1, 65536, 4, 16, 32); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
	for _, c := range [][5]uint32{
		{0, 65536, 4, 16, 32}, {65, 65536, 4, 16, 32}, {1, 31, 4, 16, 32},
		{1, MaxArgon2idMemory + 1, 4, 16, 32}, {1, 65536, 0, 16, 32},
		{1, 65536, 256, 16, 32}, {1, 65536, 4, 7, 32}, {1, 65536, 4, 16, 15},
	} {
		if CheckArgon2idParams(c[0], c[1], c[2], c[3], c[4]) == nil {
			t.Errorf("%v accepted", c)
		}
	}
}
