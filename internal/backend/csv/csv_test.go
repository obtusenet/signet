// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package csv

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestBackend(t *testing.T) (*Backend, string) {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "users.csv")

	b, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b, path
}

func TestNew(t *testing.T) {
	b, path := newTestBackend(t)
	if b == nil {
		t.Fatal("expected non-nil backend")
	}

	// Check file exists
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestCreateUser(t *testing.T) {
	b, _ := newTestBackend(t)

	err := b.CreateUser("test@example.com", "hashed_password", "argon2id", []string{"approved"})
	if err != nil {
		t.Fatal(err)
	}

	user, err := b.GetUser("test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got '%s'", user.Email)
	}
	if user.HashAlg != "argon2id" {
		t.Errorf("expected hash_alg 'argon2id', got '%s'", user.HashAlg)
	}
}

func TestCreateUser_Duplicate(t *testing.T) {
	b, _ := newTestBackend(t)

	b.CreateUser("test@example.com", "hash1", "argon2id", nil)
	err := b.CreateUser("test@example.com", "hash2", "argon2id", nil)
	if err != ErrUserExists {
		t.Errorf("expected ErrUserExists, got %v", err)
	}
}

func TestAuthenticate(t *testing.T) {
	b, _ := newTestBackend(t)

	b.CreateUser("test@example.com", "hashed_password", "argon2id", []string{"approved"})

	user, err := b.Authenticate("test@example.com", "password")
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got '%s'", user.Email)
	}
}

func TestAuthenticate_UserNotFound(t *testing.T) {
	b, _ := newTestBackend(t)

	_, err := b.Authenticate("nonexistent@example.com", "password")
	if err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

func TestAuthenticate_Locked(t *testing.T) {
	b, _ := newTestBackend(t)

	b.CreateUser("test@example.com", "hashed_password", "argon2id", []string{"approved", "locked"})

	_, err := b.Authenticate("test@example.com", "password")
	if err == nil {
		t.Error("expected error for locked account")
	}
}

func TestUpdateUser(t *testing.T) {
	b, _ := newTestBackend(t)

	b.CreateUser("test@example.com", "hash1", "argon2id", []string{"approved"})

	err := b.UpdateUser("test@example.com", map[string]string{
		"password_hash": "hash2",
	})
	if err != nil {
		t.Fatal(err)
	}

	user, err := b.GetUser("test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if user.PasswordHash != "hash2" {
		t.Errorf("expected password_hash 'hash2', got '%s'", user.PasswordHash)
	}
}

func TestUpdateUser_NotFound(t *testing.T) {
	b, _ := newTestBackend(t)

	err := b.UpdateUser("nonexistent@example.com", map[string]string{"flags": "approved"})
	if err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

func TestAddFlag(t *testing.T) {
	b, _ := newTestBackend(t)

	b.CreateUser("test@example.com", "hash", "argon2id", nil)

	err := b.AddFlag("test@example.com", "approved")
	if err != nil {
		t.Fatal(err)
	}

	user, err := b.GetUser("test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range user.Flags {
		if f == "approved" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'approved' flag to be set")
	}
}

func TestRemoveFlag(t *testing.T) {
	b, _ := newTestBackend(t)

	b.CreateUser("test@example.com", "hash", "argon2id", []string{"approved"})

	err := b.RemoveFlag("test@example.com", "approved")
	if err != nil {
		t.Fatal(err)
	}

	user, err := b.GetUser("test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range user.Flags {
		if f == "approved" {
			t.Error("expected 'approved' flag to be removed")
		}
	}
}

func TestListUsers(t *testing.T) {
	b, _ := newTestBackend(t)

	b.CreateUser("user1@example.com", "hash1", "argon2id", nil)
	b.CreateUser("user2@example.com", "hash2", "argon2id", nil)

	users, err := b.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		email string
		err   bool
	}{
		{"", true},
		{"invalid", true},
		{"test@example.com", false},
		{"with spaces@example.com", true},
	}

	for _, tt := range tests {
		err := ValidateEmail(tt.email)
		if tt.err && err == nil {
			t.Errorf("expected error for email '%s'", tt.email)
		}
		if !tt.err && err != nil {
			t.Errorf("unexpected error for email '%s': %v", tt.email, err)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		pw  string
		err bool
	}{
		{"", true},
		{"1234567", true},
		{"12345678", false},
	}

	for _, tt := range tests {
		err := ValidatePassword(tt.pw)
		if tt.err && err == nil {
			t.Errorf("expected error for password")
		}
		if !tt.err && err != nil {
			t.Errorf("unexpected error for password: %v", err)
		}
	}
}

func TestCommentLines(t *testing.T) {
	b, path := newTestBackend(t)

	// Create a user
	b.CreateUser("test@example.com", "hash1", "argon2id", nil)

	// Manually add comment lines to the CSV file
	content, _ := os.ReadFile(path)
	content = append(content, []byte("# This is a comment\n")...)
	content = append(content, []byte("# Another comment\n")...)
	os.WriteFile(path, content, 0644)

	// Reload cache
	b.Reload()

	// List users - comments should be ignored
	users, err := b.ListUsers()
	if err != nil {
		t.Fatal(err)
	}

	if len(users) != 1 {
		t.Errorf("expected 1 user (comments ignored), got %d", len(users))
	}
	if users[0].Email != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got '%s'", users[0].Email)
	}
}

func TestCacheReload(t *testing.T) {
	b, path := newTestBackend(t)

	// Create initial user
	b.CreateUser("user1@example.com", "hash1", "argon2id", nil)

	// Verify cache
	users, _ := b.ListUsers()
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}

	// Simulate external modification (like user-add CLI)
	content, _ := os.ReadFile(path)
	content = append(content, []byte("user2@example.com,hash2,argon2id,self_registered,\n")...)
	os.WriteFile(path, content, 0644)

	// Without reload, cache should still show 1 user
	users, _ = b.ListUsers()
	if len(users) != 1 {
		t.Errorf("expected 1 user (stale cache), got %d", len(users))
	}

	// After reload, cache should show 2 users
	b.Reload()
	users, _ = b.ListUsers()
	if len(users) != 2 {
		t.Errorf("expected 2 users after reload, got %d", len(users))
	}
}

func TestConcurrentAccess(t *testing.T) {
	b, _ := newTestBackend(t)

	// Simulate server reading and CLI writing concurrently
	var wg sync.WaitGroup
	wg.Add(3)

	// Server: continuously read users
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			b.ListUsers()
			time.Sleep(time.Millisecond)
		}
	}()

	// CLI 1: create users with unique emails
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			email := fmt.Sprintf("cli1_user%d@example.com", i)
			b.CreateUser(email, "hash", "argon2id", nil)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// CLI 2: create users with unique emails
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			email := fmt.Sprintf("cli2_user%d@example.com", i)
			b.CreateUser(email, "hash", "argon2id", nil)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	wg.Wait()

	// Verify all users were created
	users, err := b.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 20 {
		t.Errorf("expected 20 users, got %d", len(users))
	}
}

func TestFileWatcher(t *testing.T) {
	b, _ := newTestBackend(t)

	// Create initial user
	b.CreateUser("user1@example.com", "hash1", "argon2id", nil)

	// Start watcher
	if err := b.StartWatcher(); err != nil {
		t.Fatal(err)
	}

	// Wait a moment for watcher to start
	time.Sleep(100 * time.Millisecond)

	// Modify the file externally
	content, _ := os.ReadFile(b.path)
	content = append(content, []byte("user2@example.com,hash2,argon2id,self_registered,\n")...)
	os.WriteFile(b.path, content, 0644)

	// Wait for watcher to detect change and reload
	time.Sleep(500 * time.Millisecond)

	// Cache should be updated
	users, _ := b.ListUsers()
	if len(users) != 2 {
		t.Errorf("expected 2 users (auto-reloaded), got %d", len(users))
	}

	// Cleanup
	b.Close()
}

func TestParseCSV_Comments(t *testing.T) {
	csvContent := `email,password_hash,hash_algorithm,flags,otp_secret
# This is a comment
user1@example.com,hash1,argon2id,self_registered,
# Another comment
user2@example.com,hash2,bcrypt,approved,
`

	users, err := parseCSV(strings.NewReader(csvContent))
	if err != nil {
		t.Fatal(err)
	}

	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}

	if users[0].Email != "user1@example.com" {
		t.Errorf("expected 'user1@example.com', got '%s'", users[0].Email)
	}
	if users[1].Email != "user2@example.com" {
		t.Errorf("expected 'user2@example.com', got '%s'", users[1].Email)
	}
}

func TestParseCSV_EmptyAndComments(t *testing.T) {
	csvContent := `email,password_hash,hash_algorithm,flags,otp_secret
# Comment
user1@example.com,hash1,argon2id,,
# Another comment
`

	users, err := parseCSV(strings.NewReader(csvContent))
	if err != nil {
		t.Fatal(err)
	}

	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
}

func TestValidateEmailRejectsWhatWouldCorruptTheFile(t *testing.T) {
	bad := []string{"a@b\n#x", "a@b\r", "a\t@b", "a b@c", "#a@b", "a\x00@b", "a\x7f@b",
		strings.Repeat("a", 255) + "@b"}
	for _, addr := range bad {
		if err := ValidateEmail(addr); err == nil {
			t.Errorf("ValidateEmail(%q) accepted it", addr)
		}
	}
	for _, addr := range []string{"a@b", "first.last+tag@example.com", "o'neil@example.com",
		"x_y-z@sub.example.com", "jürgen@bücher.example"} {
		if err := ValidateEmail(addr); err != nil {
			t.Errorf("ValidateEmail(%q) = %v", addr, err)
		}
	}
}

// One address and nothing else: a mailer splits a recipient at commas, and an
// application or hook may read any one of a list.
func TestValidateEmailRefusesMoreThanOneAddress(t *testing.T) {
	for _, addr := range []string{
		"victim@example.com,attacker@example.net",
		"attacker@example.net,x@admin.example.com",
		`"quoted,comma"@example.com`,
		"Name <a@example.com>",
		"<a@example.com>",
		"a@example.com (comment)",
		"a(comment)@example.com",
		"a@b@example.com",
		"a;b@example.com",
		"|/bin/sh@example.com",
		"/etc/passwd@example.com",
		"@route:a@example.com",
		"a@[192.0.2.1]",
		".a@example.com", "a.@example.com", "a..b@example.com",
		"a@", "@example.com", "a@example..com", "a@.example.com", "a@example.com.",
		"a@-example.com", "a@example-.com",
		`a\b@example.com`,
	} {
		if err := ValidateEmail(addr); err == nil {
			t.Errorf("ValidateEmail(%q) accepted it", addr)
		}
	}
}

func TestAddressesMatchWithoutCase(t *testing.T) {
	b, err := New(filepath.Join(t.TempDir(), "users.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.CreateUser("Alice@Example.com", "hash", "bcrypt", nil); err != nil {
		t.Fatal(err)
	}
	if err := b.CreateUser("alice@example.com", "hash", "bcrypt", nil); !errors.Is(err, ErrUserExists) {
		t.Errorf("a case variant was created: %v", err)
	}
	u, err := b.GetUser("ALICE@example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "Alice@Example.com" {
		t.Errorf("found %q", u.Email)
	}
	if got := b.Resolve("alice@EXAMPLE.com"); got != "Alice@Example.com" {
		t.Errorf("Resolve = %q", got)
	}
	if got := b.Resolve("Bob@Example.com"); got != "Bob@Example.com" {
		t.Errorf("Resolve of an unknown address = %q", got)
	}
	if err := b.AddFlag("alice@example.com", FlagApproved); err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteUser("ALICE@EXAMPLE.COM"); err != nil {
		t.Fatal(err)
	}
}

// Two rows that differ only in case would be one account with two passwords.
func TestCaseVariantRowsAreRefused(t *testing.T) {
	_, err := parseCSV(strings.NewReader("a@example.com,h,bcrypt,,\nA@example.com,h,bcrypt,,\n"))
	if !errors.Is(err, ErrValidation) {
		t.Errorf("got %v", err)
	}
}

// A file an administrator wrote with CSV quoting still loads.
func TestCSVMetacharactersLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.csv")
	addr := `"quoted,comma"@example.com`
	content := "email,password_hash,hash_algorithm,flags\n\"\"\"quoted,comma\"\"@example.com\",hash,bcrypt,approved\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	u, err := b.GetUser(addr)
	if err != nil {
		t.Fatal(err)
	}
	if !u.HasFlag(FlagApproved) {
		t.Errorf("flags = %v", u.Flags)
	}
}

// A file without the optional otp_secret column used to panic on record[4].
func TestFourColumnFileLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.csv")
	content := "email,password_hash,hash_algorithm,flags\nold@example.com,hash,bcrypt,approved\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	u, err := b.GetUser("old@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.OTPSecret != "" || !u.HasFlag(FlagApproved) {
		t.Errorf("user = %+v", u)
	}
}

// The directory came from TrimRight(path, "/users.csv"), which strips a set of
// characters rather than a suffix: data/accounts.csv created data/account.
func TestNewCreatesOnlyTheParentDirectory(t *testing.T) {
	root := t.TempDir()
	b, err := New(filepath.Join(root, "data", "accounts.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	if _, err := os.Stat(filepath.Join(root, "data", "accounts.csv")); err != nil {
		t.Errorf("file not created: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("data/ holds %d entries, want only the CSV", len(entries))
	}
}

func TestNewFileIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.csv")
	b, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("mode %04o", perm)
	}
}

func TestDeleteUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.csv")
	b, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	for _, addr := range []string{"keep@example.com", "gone@example.com"} {
		if err := b.CreateUser(addr, "hash", "bcrypt", nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.DeleteUser("gone@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.GetUser("gone@example.com"); err == nil {
		t.Error("user still present")
	}
	if _, err := b.GetUser("keep@example.com"); err != nil {
		t.Errorf("other user lost: %v", err)
	}
	if err := b.DeleteUser("gone@example.com"); err != ErrUserNotFound {
		t.Errorf("second delete: %v", err)
	}
}

// rewriteFixture is a file with everything the parser does not return as a user.
const rewriteFixture = `# staff accounts
email,password_hash,hash_algorithm,flags,otp_secret
a@example.com,hash-a,bcrypt,approved,

# parked for now
#b@example.com,hash-b,bcrypt,approved,
short@example.com,onlytwo
c@example.com,hash-c,bcrypt,approved,
`

func newFixture(t *testing.T, content string) (*Backend, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.csv")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b, path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

func TestRewriteKeepsWhatItDoesNotUnderstand(t *testing.T) {
	want := strings.Replace(rewriteFixture, "a@example.com,hash-a,bcrypt,approved,\n", "", 1)

	b, path := newFixture(t, rewriteFixture)
	if err := b.DeleteUser("a@example.com"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != want {
		t.Errorf("after delete:\n%s\nwant:\n%s", got, want)
	}

	b, path = newFixture(t, rewriteFixture)
	if err := b.UpdateUser("c@example.com", map[string]string{"password_hash": "new"}); err != nil {
		t.Fatal(err)
	}
	want = strings.Replace(rewriteFixture, "hash-c", "new", 1)
	if got := readFile(t, path); got != want {
		t.Errorf("after update:\n%s\nwant:\n%s", got, want)
	}
}

func TestCommentedUserIsNotAUserAndSurvivesRewrites(t *testing.T) {
	b, path := newFixture(t, rewriteFixture)
	if _, err := b.GetUser("b@example.com"); err == nil {
		t.Error("a commented-out row is a user")
	}
	if err := b.CreateUser("new@example.com", "hash", "bcrypt", []string{"approved"}); err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteUser("new@example.com"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != rewriteFixture {
		t.Errorf("add then delete changed the file:\n%s", got)
	}
}

func TestCreateAfterLastLineWithoutNewline(t *testing.T) {
	for _, tail := range []string{"# no newline", "c@example.com,hash-c,bcrypt,approved,"} {
		b, _ := newFixture(t, "email,password_hash,hash_algorithm,flags,otp_secret\n"+tail)
		if err := b.CreateUser("new@example.com", "hash", "bcrypt", []string{"approved"}); err != nil {
			t.Fatal(err)
		}
		if err := b.Reload(); err != nil {
			t.Fatal(err)
		}
		if _, err := b.GetUser("new@example.com"); err != nil {
			t.Errorf("after %q the new row was swallowed: %v", tail, err)
		}
	}
}

// A row quoted across lines cannot be matched line by line, so nothing is written.
func TestRewriteRefusesWhatItCannotReadSafely(t *testing.T) {
	content := "email,password_hash,hash_algorithm,flags,otp_secret\n" +
		"a@example.com,hash-a,bcrypt,approved,\n" +
		"\"b@example.com\nmore\",hash-b,bcrypt,approved,\n"
	b, path := newFixture(t, content)
	if err := b.DeleteUser("a@example.com"); err == nil {
		t.Error("the rewrite was accepted")
	}
	if got := readFile(t, path); got != content {
		t.Errorf("the refused write changed the file:\n%s", got)
	}
}

func TestRewriteAddsAMissingHeaderAndKeepsArgon2Hashes(t *testing.T) {
	hash := `$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA`
	b, path := newFixture(t, "# top\n\"a@example.com\",\""+hash+"\",argon2id,approved,\nc@example.com,hash-c,bcrypt,approved,\n")
	if err := b.DeleteUser("c@example.com"); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	if !strings.HasPrefix(got, csvHeader+"\n# top\n") {
		t.Errorf("header or comment misplaced:\n%s", got)
	}
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	u, err := b.GetUser("a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.PasswordHash != hash {
		t.Errorf("hash changed: %q", u.PasswordHash)
	}
}

func TestRewriteKeepsFileMode(t *testing.T) {
	b, path := newFixture(t, rewriteFixture)
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteUser("a@example.com"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Errorf("mode %04o, want 0640", perm)
	}
}

// A reader that opened the file before a write keeps a complete old copy: the old
// write truncated this file in place, so it would have seen the new contents or none.
func TestWriteReplacesRatherThanTruncates(t *testing.T) {
	b, path := newFixture(t, rewriteFixture)
	before, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer before.Close()

	if err := b.DeleteUser("a@example.com"); err != nil {
		t.Fatal(err)
	}
	old, err := io.ReadAll(before)
	if err != nil {
		t.Fatal(err)
	}
	if string(old) != rewriteFixture {
		t.Errorf("the open file changed under its reader:\n%s", old)
	}
	if _, err := os.Stat(path + ".new"); err == nil {
		t.Error("the temporary file was left behind")
	}
}

func TestFailedWriteLeavesTheFileIntact(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	b, path := newFixture(t, rewriteFixture)
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	if err := b.DeleteUser("a@example.com"); err == nil {
		t.Error("a write that could not happen was reported as done")
	}
	if got := readFile(t, path); got != rewriteFixture {
		t.Errorf("the file changed:\n%s", got)
	}
}

// A crash can leave the temporary file behind, unreadable and half written.
func TestLeftoverTemporaryFileIsReplaced(t *testing.T) {
	b, path := newFixture(t, rewriteFixture)
	if err := os.WriteFile(path+".new", []byte("half a wri"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteUser("a@example.com"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(readFile(t, path), "half a wri") {
		t.Error("the leftover reached the file")
	}
	if _, err := os.Stat(path + ".new"); err == nil {
		t.Error("the leftover stayed")
	}
}

// Each server and command is a process of its own; two Backends have separate
// descriptors, as they would.  A lock left on a replaced inode would lose rows here.
func TestProcessesWritingTogetherLoseNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.csv")
	backends := make([]*Backend, 4)
	for i := range backends {
		b, err := New(path)
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		backends[i] = b
	}

	const perBackend = 25
	var wg sync.WaitGroup
	errs := make(chan error, len(backends)*perBackend)
	for i, b := range backends {
		wg.Add(1)
		go func(i int, b *Backend) {
			defer wg.Done()
			for n := 0; n < perBackend; n++ {
				addr := fmt.Sprintf("u%d-%d@example.com", i, n)
				if err := b.CreateUser(addr, "hash", "bcrypt", []string{FlagApproved}); err != nil {
					errs <- err
				}
			}
		}(i, b)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	if err := backends[0].Reload(); err != nil {
		t.Fatal(err)
	}
	users, err := backends[0].ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if want := len(backends) * perBackend; len(users) != want {
		t.Errorf("%d rows, want %d", len(users), want)
	}
}

// Twice, because a watch on the file itself would end with the first rename.
func TestWatcherSeesEveryWriteFromAnotherProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.csv")
	writer, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	server, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.StartWatcher(); err != nil {
		t.Fatal(err)
	}

	for _, addr := range []string{"first@example.com", "second@example.com"} {
		if err := writer.CreateUser(addr, "hash", "bcrypt", []string{FlagApproved}); err != nil {
			t.Fatal(err)
		}
		// Well inside the cache's own five seconds, so only the watcher can do it.
		deadline := time.Now().Add(3 * time.Second)
		for {
			server.cacheMu.RLock()
			found := false
			for _, u := range server.cache {
				found = found || u.Email == addr
			}
			server.cacheMu.RUnlock()
			if found {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s did not reach the server", addr)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func TestWriteThroughSymlinkKeepsTheLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.csv")
	if err := os.WriteFile(target, []byte(rewriteFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "users.csv")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	b, err := New(link)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.DeleteUser("a@example.com"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("the link was replaced by a file")
	}
	if strings.Contains(readFile(t, target), "a@example.com") {
		t.Error("the target was not updated")
	}
}
