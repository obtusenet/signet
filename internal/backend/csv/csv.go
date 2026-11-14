// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package csv

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/fsnotify/fsnotify"
)

// User represents a user account in the CSV file
type User struct {
	Email        string
	PasswordHash string
	HashAlg      string
	Flags        []string
	OTPSecret    string
}

// Flags
const (
	FlagSelfRegistered = "self_registered"
	FlagApproved       = "approved"
	FlagMFACredentials = "mfa_enabled"
	FlagLocked         = "locked"
)

// Backend implements the AuthBackend interface using a CSV file.
// Writes replace the file by rename, so a reader or a crash sees the old contents
// or the new ones, never part of either.  The lock for a write is on the parent
// directory, because a rename would leave a lock on the file itself behind on the
// old inode, where another process no longer sees it.
// The server caches users in memory and watches the file for changes.
type Backend struct {
	mu          sync.Mutex
	path        string
	watcher     *fsnotify.Watcher
	watchCtx    context.Context
	watchCancel context.CancelFunc

	// Cache
	cache   []*User
	cacheAt time.Time
	cacheMu sync.RWMutex
}

// ErrUserNotFound is returned when a user is not found
var ErrUserNotFound = errors.New("user not found")

// ErrUserExists is returned when trying to create a user that already exists
var ErrUserExists = errors.New("user already exists")

// ErrValidation is returned when user data is invalid
var ErrValidation = errors.New("validation error")

// New creates a new CSV backend (no file lock acquired here)
func New(path string) (*Backend, error) {
	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating directory %s: %w", dir, err)
	}

	// The file holds password hashes; a new one is readable by its owner only.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening CSV file: %w", err)
	}
	f.Close()

	// A rename onto a symlink would replace the link, not the file it names.
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("resolving CSV path: %w", err)
	}

	b := &Backend{path: resolved}

	// Load initial cache
	if err := b.loadCache(); err != nil {
		return nil, err
	}

	return b, nil
}

// Close releases resources and stops the file watcher
func (b *Backend) Close() error {
	if b.watchCancel != nil {
		b.watchCancel()
	}
	if b.watcher != nil {
		return b.watcher.Close()
	}
	return nil
}

// StartWatcher begins watching the CSV file for changes and auto-reloading.
// It uses fsnotify (inotify/fen/kqueue) with polling fallback.
func (b *Backend) StartWatcher() error {
	b.watchCtx, b.watchCancel = context.WithCancel(context.Background())

	// Try fsnotify first (uses inotify/fen/kqueue)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		// Fall back to polling
		go b.pollWatcher(2 * time.Second)
		return nil
	}
	b.watcher = watcher

	// The directory, because a write replaces the file and a watch on the file
	// would end with the first rename.
	if err := watcher.Add(filepath.Dir(b.path)); err != nil {
		// Fall back to polling
		watcher.Close()
		go b.pollWatcher(2 * time.Second)
		return nil
	}

	go b.fsnotifyWatcher()
	return nil
}

func (b *Backend) fsnotifyWatcher() {
	for {
		select {
		case <-b.watchCtx.Done():
			return
		case event, ok := <-b.watcher.Events:
			if !ok {
				return
			}
			if filepath.Clean(event.Name) != b.path {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0 {
				b.reloadCache()
			}
		case err, ok := <-b.watcher.Errors:
			if !ok {
				return
			}
			fmt.Fprintf(os.Stderr, "csv watcher error: %v\n", err)
		}
	}
}

// pollWatcher polls the CSV file for changes using mtime comparison
func (b *Backend) pollWatcher(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastMod time.Time
	check := func() {
		info, err := os.Stat(b.path)
		if err != nil {
			return
		}
		mod := info.ModTime()
		if !mod.Equal(lastMod) && !mod.IsZero() {
			lastMod = mod
			b.reloadCache()
		}
	}

	// Initial check
	check()

	for {
		select {
		case <-b.watchCtx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

// Reload re-reads the CSV file and updates the cache
func (b *Backend) Reload() error {
	return b.reloadCache()
}

// loadCache reads all users from the CSV file and stores them in the cache.
func (b *Backend) loadCache() error {
	users, err := b.readUsersFromFile()
	if err != nil {
		return err
	}

	b.cacheMu.Lock()
	b.cache = users
	b.cacheAt = time.Now()
	b.cacheMu.Unlock()

	return nil
}

// reloadCache is like loadCache but used after file changes
func (b *Backend) reloadCache() error {
	users, err := b.readUsersFromFile()
	if err != nil {
		return err
	}

	b.cacheMu.Lock()
	b.cache = users
	b.cacheAt = time.Now()
	b.cacheMu.Unlock()

	return nil
}

// getCachedUsers returns the cached users, reloading if stale (>5 seconds).
func (b *Backend) getCachedUsers() ([]*User, error) {
	b.cacheMu.RLock()
	users := b.cache
	cacheAt := b.cacheAt
	b.cacheMu.RUnlock()

	if time.Since(cacheAt) > 5*time.Second {
		if err := b.reloadCache(); err != nil {
			return nil, err
		}
		b.cacheMu.RLock()
		users = b.cache
		b.cacheMu.RUnlock()
	}

	return users, nil
}

// Authenticate checks if the given email/password combination is valid
func (b *Backend) Authenticate(email, password string) (*User, error) {
	users, err := b.getCachedUsers()
	if err != nil {
		return nil, err
	}

	for _, u := range users {
		if strings.EqualFold(u.Email, email) {
			if isLocked(u) {
				return nil, fmt.Errorf("account %s is locked", email)
			}
			return u, nil
		}
	}
	return nil, ErrUserNotFound
}

// CreateUser adds a new user to the CSV file using flock for safe concurrent writes
func (b *Backend) CreateUser(email, passwordHash, hashAlg string, flags []string) error {
	if err := b.validateUser(email, passwordHash, hashAlg, flags); err != nil {
		return err
	}

	// Goroutine mutex first, then the process lock: every goroutine shares
	// one open file, so a second flock would succeed at once and the first
	// holder's release would drop the lock while the second was still writing.
	b.mu.Lock()
	defer b.mu.Unlock()

	unlock, err := b.lockForWrite()
	if err != nil {
		return err
	}
	defer unlock()

	users, err := b.readUsersFromFile()
	if err != nil {
		return err
	}

	for _, u := range users {
		if strings.EqualFold(u.Email, email) {
			return ErrUserExists
		}
	}

	user := &User{
		Email:        email,
		PasswordHash: passwordHash,
		HashAlg:      hashAlg,
		Flags:        flags,
	}

	if err := b.writeUsers(append(users, user)); err != nil {
		return err
	}

	// Update cache
	b.reloadCache()
	return nil
}

// UpdateUser modifies an existing user's fields using flock for safe concurrent writes
func (b *Backend) UpdateUser(email string, updates map[string]string) error {
	// Same order as CreateUser: goroutine mutex, then process lock.
	b.mu.Lock()
	defer b.mu.Unlock()

	unlock, err := b.lockForWrite()
	if err != nil {
		return err
	}
	defer unlock()

	users, err := b.readUsersFromFile()
	if err != nil {
		return err
	}

	found := false
	for i, u := range users {
		if strings.EqualFold(u.Email, email) {
			found = true
			if val, ok := updates["password_hash"]; ok {
				users[i].PasswordHash = val
			}
			if val, ok := updates["hash_algorithm"]; ok {
				users[i].HashAlg = val
			}
			if val, ok := updates["flags"]; ok {
				users[i].Flags = parseFlags(val)
			}
			if val, ok := updates["otp_secret"]; ok {
				users[i].OTPSecret = val
			}
			break
		}
	}

	if !found {
		return ErrUserNotFound
	}

	if err := b.writeUsers(users); err != nil {
		return err
	}

	// Update cache
	b.reloadCache()
	return nil
}

// DeleteUser removes a user's row, using flock for safe concurrent writes.
func (b *Backend) DeleteUser(email string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	unlock, err := b.lockForWrite()
	if err != nil {
		return err
	}
	defer unlock()

	users, err := b.readUsersFromFile()
	if err != nil {
		return err
	}

	kept := make([]*User, 0, len(users))
	for _, u := range users {
		if !strings.EqualFold(u.Email, email) {
			kept = append(kept, u)
		}
	}
	if len(kept) == len(users) {
		return ErrUserNotFound
	}

	if err := b.writeUsers(kept); err != nil {
		return err
	}

	b.reloadCache()
	return nil
}

// Resolve answers the address as the account has it, when an account matches
// address apart from case, and otherwise address unchanged.  Sign-ins, sessions,
// keys and codes all record the account's own form, so an address typed in
// another case reaches the same account and the same records.
func (b *Backend) Resolve(address string) string {
	if u, err := b.GetUser(address); err == nil {
		return u.Email
	}
	return address
}

// GetUser returns a user by email, matched without regard to case
func (b *Backend) GetUser(email string) (*User, error) {
	users, err := b.getCachedUsers()
	if err != nil {
		return nil, err
	}

	for _, u := range users {
		if strings.EqualFold(u.Email, email) {
			return u, nil
		}
	}
	return nil, ErrUserNotFound
}

// ListUsers returns all users
func (b *Backend) ListUsers() ([]*User, error) {
	return b.getCachedUsers()
}

// AddFlag adds a flag to a user
func (b *Backend) AddFlag(email, flag string) error {
	flags, err := b.getUserFlags(email)
	if err != nil {
		return err
	}
	if !hasFlag(flags, flag) {
		flags = append(flags, flag)
	}
	return b.UpdateUser(email, map[string]string{
		"flags": flagsToString(flags),
	})
}

// RemoveFlag removes a flag from a user
func (b *Backend) RemoveFlag(email, flag string) error {
	flags, err := b.getUserFlags(email)
	if err != nil {
		return err
	}
	newFlags := make([]string, 0, len(flags))
	for _, f := range flags {
		if f != flag {
			newFlags = append(newFlags, f)
		}
	}
	return b.UpdateUser(email, map[string]string{
		"flags": flagsToString(newFlags),
	})
}

// getUserFlags returns a user's flags (reads from cache)
func (b *Backend) getUserFlags(email string) ([]string, error) {
	users, err := b.getCachedUsers()
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if strings.EqualFold(u.Email, email) {
			return u.Flags, nil
		}
	}
	return nil, ErrUserNotFound
}

// readUsersFromFile reads all users from the CSV file, skipping comments (lines starting with #).
// No file lock is held by the caller.
func (b *Backend) readUsersFromFile() ([]*User, error) {
	f, err := os.Open(b.path)
	if err != nil {
		return nil, fmt.Errorf("opening CSV file: %w", err)
	}
	defer f.Close()

	return parseCSV(f)
}

// parseCSV parses a CSV file, skipping comment lines (starting with #) and the header row
func parseCSV(r io.Reader) ([]*User, error) {
	scanner := bufio.NewScanner(r)
	var lines []string

	for scanner.Scan() {
		line := scanner.Text()
		// Skip empty lines and comments
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning CSV: %w", err)
	}

	if len(lines) == 0 {
		return []*User{}, nil
	}

	reader := csv.NewReader(strings.NewReader(strings.Join(lines, "\n")))
	reader.FieldsPerRecord = -1 // otp_secret is optional; short rows are handled below
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parsing CSV: %w", err)
	}

	var users []*User
	seen := make(map[string]string)
	for i, record := range records {
		// Skip header row
		if i == 0 && len(record) > 0 && record[0] == "email" {
			continue
		}
		if len(record) < 4 {
			continue
		}
		user := &User{
			Email:        record[0],
			PasswordHash: record[1],
			HashAlg:      record[2],
			Flags:        parseFlags(record[3]),
		}
		if len(record) > 4 {
			user.OTPSecret = record[4]
		}
		// Addresses match without regard to case, so two rows that differ
		// only in case would be one account with two passwords.
		key := strings.ToLower(user.Email)
		if first, ok := seen[key]; ok {
			return nil, fmt.Errorf("%w: %s and %s are the same address; remove one from the file", ErrValidation, first, user.Email)
		}
		seen[key] = user.Email
		users = append(users, user)
	}
	return users, nil
}

// csvHeader is the first line of a file signet has written.
const csvHeader = "email,password_hash,hash_algorithm,flags,otp_secret"

// writeRecord writes one user as a CSV row.
func writeRecord(w io.Writer, u *User) error {
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{
		u.Email,
		u.PasswordHash,
		u.HashAlg,
		flagsToString(u.Flags),
		u.OTPSecret,
	}); err != nil {
		return err
	}
	writer.Flush()
	return writer.Error()
}

// writeUsers makes the file hold exactly these users (caller must hold file
// lock).  Everything else in it stays where it is: comments, blank lines and
// rows too short to be a user, none of which the parser returns.  A row is
// rewritten in place, one no longer listed is dropped and a new one goes last.
//
// A line that cannot be read safely refuses the write and leaves the file as it
// was, as does any failure while replacing it.
func (b *Backend) writeUsers(users []*User) error {
	raw, err := os.ReadFile(b.path)
	if err != nil {
		return err
	}

	// A list per address, because a hand-edited file can repeat one.
	pending := make(map[string][]*User, len(users))
	for _, u := range users {
		pending[u.Email] = append(pending[u.Email], u)
	}

	var body bytes.Buffer
	hasHeader := false
	text := strings.TrimSuffix(string(raw), "\n")
	if text != "" {
		for i, line := range strings.Split(text, "\n") {
			line = strings.TrimSuffix(line, "\r")
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				body.WriteString(line + "\n")
				continue
			}
			reader := csv.NewReader(strings.NewReader(line))
			reader.FieldsPerRecord = -1
			record, err := reader.Read()
			if err != nil {
				return fmt.Errorf("refusing to rewrite %s: line %d: %w", b.path, i+1, err)
			}
			if !hasHeader && len(record) > 0 && record[0] == "email" {
				hasHeader = true
				body.WriteString(line + "\n")
				continue
			}
			if len(record) < 4 {
				body.WriteString(line + "\n")
				continue
			}
			if rows := pending[record[0]]; len(rows) > 0 {
				if err := writeRecord(&body, rows[0]); err != nil {
					return err
				}
				pending[record[0]] = rows[1:]
			}
		}
	}

	// What the file did not already hold, in the order given.
	for _, u := range users {
		if rows := pending[u.Email]; len(rows) > 0 {
			if err := writeRecord(&body, rows[0]); err != nil {
				return err
			}
			pending[u.Email] = rows[1:]
		}
	}

	var out bytes.Buffer
	if !hasHeader {
		out.WriteString(csvHeader + "\n")
	}
	out.Write(body.Bytes())

	return b.replaceFile(out.Bytes())
}

// replaceFile swaps in the new contents with the same owner and mode.  They reach
// the disk before the rename, and the rename reaches it afterwards, so a crash or
// a full disk at any point leaves a complete file.  A leftover from a crash is only
// ever overwritten, as the caller holds the write lock.
func (b *Backend) replaceFile(contents []byte) error {
	info, err := os.Stat(b.path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("reading the owner of %s", b.path)
	}

	tmp := b.path + ".new"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("replacing %s: %w", b.path, err)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("replacing %s: signet needs write access to its directory: %w", b.path, err)
	}
	defer os.Remove(tmp) // nothing to remove once the rename has happened

	write := func() error {
		if _, err := f.Write(contents); err != nil {
			return err
		}
		if int(stat.Uid) != os.Geteuid() || int(stat.Gid) != os.Getegid() {
			if err := f.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
				return err
			}
		}
		if err := f.Chmod(info.Mode().Perm()); err != nil {
			return err
		}
		return f.Sync()
	}
	if err := write(); err != nil {
		f.Close()
		return fmt.Errorf("replacing %s: %w", b.path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("replacing %s: %w", b.path, err)
	}
	if err := os.Rename(tmp, b.path); err != nil {
		return fmt.Errorf("replacing %s: %w", b.path, err)
	}

	// The write has happened by now, so a directory that cannot be flushed is no
	// reason to report it as failed.
	if dir, err := os.Open(filepath.Dir(b.path)); err == nil {
		dir.Sync()
		dir.Close()
	}
	return nil
}

// validateUser validates user data before write operations
func (b *Backend) validateUser(email, passwordHash, hashAlg string, flags []string) error {
	if err := ValidateEmail(email); err != nil {
		return err
	}
	if passwordHash == "" {
		return fmt.Errorf("%w: password_hash cannot be empty", ErrValidation)
	}
	if hashAlg != "bcrypt" && hashAlg != "argon2id" {
		return fmt.Errorf("%w: hash_algorithm must be 'bcrypt' or 'argon2id'", ErrValidation)
	}
	return nil
}

// parseFlags parses a pipe-delimited flags string into a slice
func parseFlags(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, "|")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// hasFlag checks if a flags slice contains the given flag
func hasFlag(flags []string, flag string) bool {
	for _, f := range flags {
		if f == flag {
			return true
		}
	}
	return false
}

// flagsToString converts a flags slice to a pipe-delimited string
func flagsToString(flags []string) string {
	return strings.Join(flags, "|")
}

// isLocked checks if a user is locked
func isLocked(u *User) bool {
	return u.HasFlag(FlagLocked)
}

// HasFlag reports whether the user carries the given flag.
func (u *User) HasFlag(flag string) bool {
	return hasFlag(u.Flags, flag)
}

// maxEmailLength is the longest address SMTP can carry (RFC 5321 §4.5.3.1.3
// limits a path to 256 octets including the angle brackets).
const maxEmailLength = 254

// ValidateEmail accepts exactly one plain address: local@domain, nothing else.
// The address is handed to sendmail as a recipient, shown to applications in
// Remote-Email and given to the claims hook, so anything a mailer or a parser
// could read as more than one address, a name, a comment, a route or a program
// is refused: commas, quotes, angle brackets, parentheses, spaces, a second @, a
// pipe or a slash.  OpenSMTPD, sendmail and Postfix all split a recipient
// argument at commas.
//
// The local part is a dot-atom (RFC 5322 §3.4.1) without | and /, which sendmail
// reads as a program or a file.  The domain is dot-separated labels of letters,
// digits and hyphens; letters may be non-ASCII, for internationalised names.
// Address literals ([192.0.2.1]) are refused.
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("%w: email cannot be empty", ErrValidation)
	}
	if len(email) > maxEmailLength {
		return fmt.Errorf("%w: email is longer than %d bytes", ErrValidation, maxEmailLength)
	}
	local, domain, ok := strings.Cut(email, "@")
	if !ok {
		return fmt.Errorf("%w: email must contain @", ErrValidation)
	}
	if strings.Contains(domain, "@") {
		return fmt.Errorf("%w: email must contain one @", ErrValidation)
	}
	// A leading # would turn the row in users.csv into a comment.
	if strings.HasPrefix(email, "#") {
		return fmt.Errorf("%w: email cannot start with #", ErrValidation)
	}
	if !dotSeparated(local, isLocalRune) {
		return fmt.Errorf("%w: the part before @ may hold only letters, digits, dots and %s", ErrValidation, localSpecials)
	}
	if !dotSeparated(domain, isDomainRune) {
		return fmt.Errorf("%w: the domain may hold only letters, digits, hyphens and dots", ErrValidation)
	}
	for _, label := range strings.Split(domain, ".") {
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("%w: a domain label cannot start or end with a hyphen", ErrValidation)
		}
	}
	return nil
}

// localSpecials are the characters other than letters, digits and dots that a
// local part may hold: RFC 5322 atext without | and /.
const localSpecials = "!#$%&'*+-=?^_`{}~"

func isLocalRune(r rune) bool {
	return isAlnum(r) || strings.ContainsRune(localSpecials, r)
}

func isDomainRune(r rune) bool { return isAlnum(r) || r == '-' }

// isAlnum is an ASCII letter or digit, or a non-ASCII letter or digit.
func isAlnum(r rune) bool {
	if r < utf8.RuneSelf {
		return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
	}
	return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.Mn, r)
}

// dotSeparated reports whether s is one or more non-empty runs of runes that
// satisfy ok, joined by single dots.
func dotSeparated(s string, ok func(rune) bool) bool {
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return false
		}
		for _, r := range part {
			if !ok(r) {
				return false
			}
		}
	}
	return true
}

// ValidatePassword checks if the password meets minimum requirements
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("%w: password must be at least 8 characters", ErrValidation)
	}
	return nil
}

// flock/unflock helpers
// lockForWrite takes the write lock, shared by every process using the file, and
// returns its release.  Callers hold b.mu as well.
func (b *Backend) lockForWrite() (func(), error) {
	dir, err := os.Open(filepath.Dir(b.path))
	if err != nil {
		return nil, fmt.Errorf("locking CSV file: %w", err)
	}
	if err := syscall.Flock(int(dir.Fd()), syscall.LOCK_EX); err != nil {
		dir.Close()
		return nil, fmt.Errorf("locking CSV file: %w", err)
	}
	return func() { dir.Close() }, nil // closing the descriptor releases the lock
}
