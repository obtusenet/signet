// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Errors
var (
	ErrInvalidAlgorithm = errors.New("invalid hash algorithm")
	ErrHashMismatch     = errors.New("hash mismatch")
	ErrWeakPassword     = errors.New("password too weak")
)

// slots bounds how many hashes run at once.  An argon2id hash holds its memory
// (64 MiB by default) for as long as it runs, so without a bound a burst of
// sign-ins can use up the server's memory.  Hashes beyond the bound wait their
// turn; more than one per CPU would not finish any sooner.
var slots = make(chan struct{}, hashSlots())

func hashSlots() int {
	return min(max(runtime.GOMAXPROCS(0), 1), 8)
}

func acquire() func() {
	slots <- struct{}{}
	return func() { <-slots }
}

// Hasher handles password hashing and verification
type Hasher struct {
	Algorithm        string
	BcryptCost       int
	Argon2idTime     uint32
	Argon2idMemory   uint32
	Argon2idParallel uint8
	Argon2idSaltLen  uint32
	Argon2idKeyLen   uint32
}

// NewHasher creates a new Hasher with the given parameters
func NewHasher(algorithm string, bcryptCost int, argon2idParams Argon2idParams) *Hasher {
	return &Hasher{
		Algorithm:        algorithm,
		BcryptCost:       bcryptCost,
		Argon2idTime:     argon2idParams.Time,
		Argon2idMemory:   argon2idParams.Memory,
		Argon2idParallel: argon2idParams.Parallel,
		Argon2idSaltLen:  argon2idParams.SaltLength,
		Argon2idKeyLen:   argon2idParams.KeyLength,
	}
}

// Argon2idParams holds parameters for Argon2id hashing
type Argon2idParams struct {
	Time       uint32
	Memory     uint32
	Parallel   uint8
	SaltLength uint32
	KeyLength  uint32
}

// Hash generates a hash for the given password using the configured algorithm
func (h *Hasher) Hash(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}

	defer acquire()()
	switch h.Algorithm {
	case "argon2id":
		return hashArgon2id(password, h.Argon2idTime, h.Argon2idMemory, h.Argon2idParallel, h.Argon2idSaltLen, h.Argon2idKeyLen)
	case "bcrypt":
		return hashBcrypt(password, h.BcryptCost)
	default:
		return "", fmt.Errorf("%w: %s", ErrInvalidAlgorithm, h.Algorithm)
	}
}

// hashArgon2id hashes a password using Argon2id with a standard format
func hashArgon2id(password string, time, memory uint32, parallel uint8, saltLen, keyLen uint32) (string, error) {
	salt, err := generateSalt(saltLen)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, time, memory, parallel, keyLen)

	// Encode as base64url (no padding)
	b64Salt := base64.RawURLEncoding.EncodeToString(salt)
	b64Hash := base64.RawURLEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=memory,t=time,p=parallel$salt$hash
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, time, parallel, b64Salt, b64Hash), nil
}

// hashBcrypt hashes a password using bcrypt
func hashBcrypt(password string, cost int) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// Verify checks if the given password matches the hash
func (h *Hasher) Verify(password, hash string) error {
	defer acquire()()
	switch {
	case isArgon2id(hash):
		return verifyArgon2id(password, hash)
	case isBcrypt(hash):
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	default:
		return fmt.Errorf("%w: unrecognized format", ErrHashMismatch)
	}
}

// Limits on Argon2id parameters, for hashes Signet makes and hashes it reads.
// The lower ones are what golang.org/x/crypto/argon2 needs to run at all: it
// panics on no passes, no threads or an empty key.  The upper ones keep a hash
// in users.csv from holding a hashing slot, and the server's memory, without end.
const (
	MinArgon2idKeyLen  = 16
	MinArgon2idSaltLen = 8
	MaxArgon2idTime    = 64
	MaxArgon2idMemory  = 4 << 20 // KiB: 4 GiB
)

// ErrMalformedHash marks a stored hash that cannot be checked.  It wraps
// ErrHashMismatch, so the password is refused like a wrong one.
var ErrMalformedHash = fmt.Errorf("%w: malformed hash", ErrHashMismatch)

// CheckArgon2idParams reports whether Argon2id can hash with these parameters.
// memory is in KiB.
func CheckArgon2idParams(time, memory, parallel, saltLen, keyLen uint32) error {
	switch {
	case time < 1 || time > MaxArgon2idTime:
		return fmt.Errorf("time %d is outside 1 to %d", time, MaxArgon2idTime)
	case parallel < 1 || parallel > 255:
		return fmt.Errorf("parallelism %d is outside 1 to 255", parallel)
	case memory < 8*parallel || memory > MaxArgon2idMemory:
		return fmt.Errorf("memory %d KiB is outside 8 x parallelism (%d) to %d", memory, 8*parallel, MaxArgon2idMemory)
	case saltLen < MinArgon2idSaltLen:
		return fmt.Errorf("salt length %d is under %d", saltLen, MinArgon2idSaltLen)
	case keyLen < MinArgon2idKeyLen:
		return fmt.Errorf("key length %d is under %d", keyLen, MinArgon2idKeyLen)
	}
	return nil
}

// verifyArgon2id checks password against a hash of the form
// $argon2id$v=19$m=<KiB>,t=<passes>,p=<threads>$<salt>$<key>, salt and key in
// unpadded base64url.  Anything else, or parameters outside
// CheckArgon2idParams, is ErrMalformedHash: the argon2 package panics on some
// of them, and a hash in users.csv must not stop the server.
func verifyArgon2id(password, hash string) error {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return fmt.Errorf("%w: not $argon2id$v=19$params$salt$key", ErrMalformedHash)
	}
	opts := strings.Split(parts[3], ",")
	if len(opts) != 3 {
		return fmt.Errorf("%w: parameters are not m=,t=,p=", ErrMalformedHash)
	}
	var vals [3]uint32
	for i, name := range []string{"m=", "t=", "p="} {
		v, ok := strings.CutPrefix(opts[i], name)
		if !ok {
			return fmt.Errorf("%w: parameters are not m=,t=,p=", ErrMalformedHash)
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return fmt.Errorf("%w: parameter %s%s", ErrMalformedHash, name, v)
		}
		vals[i] = uint32(n)
	}
	memory, time, parallel := vals[0], vals[1], vals[2]

	salt, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("%w: salt: %v", ErrMalformedHash, err)
	}
	expectedHash, err := base64.RawURLEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("%w: key: %v", ErrMalformedHash, err)
	}
	if err := CheckArgon2idParams(time, memory, parallel, uint32(len(salt)), uint32(len(expectedHash))); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedHash, err)
	}

	actualHash := argon2.IDKey([]byte(password), salt, time, memory, uint8(parallel), uint32(len(expectedHash)))
	return constantTimeCompare(actualHash, expectedHash)
}

// AlgorithmFromHash returns the algorithm used to hash the given string
func AlgorithmFromHash(hash string) string {
	if isArgon2id(hash) {
		return "argon2id"
	}
	if isBcrypt(hash) {
		return "bcrypt"
	}
	return "unknown"
}

// isArgon2id checks if a hash string is in Argon2id format
func isArgon2id(hash string) bool {
	return strings.HasPrefix(hash, "$argon2id$")
}

// isBcrypt checks if a hash string is in bcrypt format
func isBcrypt(hash string) bool {
	return strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$")
}

// ValidatePassword checks if a password meets minimum requirements
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return ErrWeakPassword
	}
	return nil
}

// generateSalt generates a random salt of the given length
func generateSalt(length uint32) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// constantTimeCompare compares two byte slices in constant time
func constantTimeCompare(a, b []byte) error {
	if subtle.ConstantTimeCompare(a, b) != 1 {
		return ErrHashMismatch
	}
	return nil
}
