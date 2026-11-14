// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Listen != ":8080" {
		t.Errorf("expected listen ':8080', got '%s'", cfg.Listen)
	}
	if cfg.SocketMode != "0660" {
		t.Errorf("expected socket_mode '0660', got '%s'", cfg.SocketMode)
	}
	if cfg.Protocol != "http" {
		t.Errorf("expected protocol 'http', got '%s'", cfg.Protocol)
	}
	if cfg.CookieName != "signetid" {
		t.Errorf("expected cookie_name 'signetid', got '%s'", cfg.CookieName)
	}
	if cfg.PasswordHashAlg != "argon2id" {
		t.Errorf("expected password_hash_algorithm 'argon2id', got '%s'", cfg.PasswordHashAlg)
	}
	if cfg.SelfRegistration != "disabled" {
		t.Errorf("expected self_registration 'disabled', got '%s'", cfg.SelfRegistration)
	}
}

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	content := `
listen: ":9090"
cookie_name: "testcookie"
password_hash_algorithm: "bcrypt"
bcrypt_cost: 10
self_registration: "enabled"
`
	tmpFile, err := os.CreateTemp("", "signet-test-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	cfg, err := LoadConfig(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Listen != ":9090" {
		t.Errorf("expected listen ':9090', got '%s'", cfg.Listen)
	}
	if cfg.CookieName != "testcookie" {
		t.Errorf("expected cookie_name 'testcookie', got '%s'", cfg.CookieName)
	}
	if cfg.PasswordHashAlg != "bcrypt" {
		t.Errorf("expected password_hash_algorithm 'bcrypt', got '%s'", cfg.PasswordHashAlg)
	}
	if cfg.BcryptCost != 10 {
		t.Errorf("expected bcrypt_cost 10, got %d", cfg.BcryptCost)
	}
	if cfg.SelfRegistration != "enabled" {
		t.Errorf("expected self_registration 'enabled', got '%s'", cfg.SelfRegistration)
	}
}

func TestLoadConfig_Invalid(t *testing.T) {
	content := `
listen: ":8080"
password_hash_algorithm: "invalid_algo"
`
	tmpFile, err := os.CreateTemp("", "signet-test-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	tmpFile.WriteString(content)
	tmpFile.Close()

	_, err = LoadConfig(tmpFile.Name())
	if err == nil {
		t.Error("expected error for invalid password_hash_algorithm")
	}
}

func TestLoadConfig_Missing(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for missing config file")
	}
}

// The deprecated listen_addr key still binds when listen is absent, and the
// new key wins when both are present.
func TestListenAddrDeprecatedAlias(t *testing.T) {
	write := func(t *testing.T, content string) string {
		t.Helper()
		f, err := os.CreateTemp("", "signet-alias-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove(f.Name()) })
		defer f.Close()
		f.WriteString(content)
		return f.Name()
	}

	cfg, err := LoadConfig(write(t, "listen_addr: \"/run/signet.sock\"\n"))
	if err != nil {
		t.Fatalf("deprecated listen_addr should load: %v", err)
	}
	if cfg.Listen != "/run/signet.sock" {
		t.Errorf("alias: got %q", cfg.Listen)
	}

	cfg, err = LoadConfig(write(t, "listen: \":9999\"\nlisten_addr: \":1111\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9999" {
		t.Errorf("listen should win over listen_addr, got %q", cfg.Listen)
	}
}

func TestSocketModeValidation(t *testing.T) {
	f, err := os.CreateTemp("", "signet-mode-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("listen: \"/x/y.sock\"\nsocket_mode: \"0999\"\n")
	f.Close()
	if _, err := LoadConfig(f.Name()); err == nil {
		t.Error("expected error for out-of-range socket_mode")
	}

	f2, err := os.CreateTemp("", "signet-mode-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f2.Name())
	f2.WriteString("listen: \"/x/y.sock\"\nsocket_mode: \"0666\"\n")
	f2.Close()
	cfg, err := LoadConfig(f2.Name())
	if err != nil {
		t.Fatalf("valid socket_mode: %v", err)
	}
	if cfg.SocketMode != "0666" {
		t.Errorf("got %q", cfg.SocketMode)
	}
}

func TestProtocolLoadAndValidation(t *testing.T) {
	f, err := os.CreateTemp("", "signet-proto-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("listen: \"/run/signet/fcgi.sock\"\nprotocol: fastcgi\n")
	f.Close()
	cfg, err := LoadConfig(f.Name())
	if err != nil {
		t.Fatalf("protocol fastcgi should validate: %v", err)
	}
	if cfg.Protocol != "fastcgi" {
		t.Errorf("expected protocol 'fastcgi', got '%s'", cfg.Protocol)
	}

	f2, err := os.CreateTemp("", "signet-proto-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f2.Name())
	f2.WriteString("listen: \":9090\"\nprotocol: scgi\n")
	f2.Close()
	if _, err := LoadConfig(f2.Name()); err == nil {
		t.Error("expected error for unknown protocol")
	}
}

func TestValidateForServeRequiresASecret(t *testing.T) {
	cfg := DefaultConfig()
	if err := ValidateForServe(cfg); err == nil {
		t.Error("no secret accepted")
	}
	cfg.CookieSecret = "too-short"
	if err := ValidateForServe(cfg); err == nil {
		t.Error("short secret accepted")
	}
	cfg.CookieSecret = strings.Repeat("a", MinCookieSecretLength)
	if err := ValidateForServe(cfg); err != nil {
		t.Errorf("good secret refused: %v", err)
	}
	// Administrative commands load the file through Validate alone.
	if err := Validate(DefaultConfig()); err != nil {
		t.Errorf("Validate wants a secret: %v", err)
	}
}

func TestRateLimitKeysMustBePositive(t *testing.T) {
	for _, key := range []string{
		"webauthn_rate_limit", "webauthn_rate_window",
		"register_rate_limit", "register_rate_window",
	} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(key+": 0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Errorf("%s: 0 was accepted", key)
		}
	}
}

func TestWebAuthnHasOneSwitch(t *testing.T) {
	for _, tc := range []struct {
		name       string
		yaml       string
		enabled    bool
		deprecated bool
	}{
		{"nothing said", "", false, false},
		{"switch on", "auth_methods:\n  webauthn: enabled\n", true, false},
		{"switch off", "auth_methods:\n  webauthn: disabled\n", false, false},
		// The old key keeps its meaning: WebAuthn was on only when both agreed,
		// and auth_methods.webauthn defaulted to enabled.
		{"old key on", "webauthn_enabled: true\n", true, true},
		{"old key on, switch on", "webauthn_enabled: true\nauth_methods:\n  webauthn: enabled\n", true, true},
		{"old key on, switch off", "webauthn_enabled: true\nauth_methods:\n  webauthn: disabled\n", false, true},
		{"old key off", "webauthn_enabled: false\n", false, true},
		{"old key off, switch on", "webauthn_enabled: false\nauth_methods:\n  webauthn: enabled\n", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.MethodEnabled("webauthn"); got != tc.enabled {
				t.Errorf("enabled = %v, want %v", got, tc.enabled)
			}
			if got := len(cfg.Deprecations) > 0; got != tc.deprecated {
				t.Errorf("deprecation warning = %v, want %v", got, tc.deprecated)
			}
		})
	}
}

func TestLoginLimitSwitches(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.LoginAddressLimit != "enabled" || cfg.LoginSourceLimit != "enabled" {
		t.Errorf("defaults: address %q, source %q", cfg.LoginAddressLimit, cfg.LoginSourceLimit)
	}
	if err := Validate(cfg); err != nil {
		t.Errorf("defaults: %v", err)
	}
	for name, change := range map[string]func(*Config){
		"address switch":  func(c *Config) { c.LoginAddressLimit = "off" },
		"source switch":   func(c *Config) { c.LoginSourceLimit = "" },
		"address of zero": func(c *Config) { c.LoginRateLimit = 0 },
		"address window":  func(c *Config) { c.LoginRateWindow = 0 },
		"source of zero":  func(c *Config) { c.LoginSourceRateLimit = 0 },
		"negative source": func(c *Config) { c.LoginSourceRateLimit = -1 },
		"source window":   func(c *Config) { c.LoginSourceRateWindow = 0 },
	} {
		cfg := DefaultConfig()
		change(cfg)
		if err := Validate(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// Off, its numbers mean nothing.
	cfg = DefaultConfig()
	cfg.LoginAddressLimit, cfg.LoginRateLimit = "disabled", 0
	cfg.LoginSourceLimit, cfg.LoginSourceRateLimit = "disabled", 0
	if err := Validate(cfg); err != nil {
		t.Errorf("both off: %v", err)
	}
}

func TestPublicURL(t *testing.T) {
	for _, good := range []string{"", "https://signet.example.com", "http://host:8080", "https://example.com/auth/"} {
		cfg := DefaultConfig()
		cfg.PublicURL = good
		if err := Validate(cfg); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	for _, bad := range []string{"signet.example.com", "ftp://host", "https://", "https://host/?x=1", "https://host/#x", "//host"} {
		cfg := DefaultConfig()
		cfg.PublicURL = bad
		if err := Validate(cfg); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

func TestMailLinkNumbersMustBePositive(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"ttl":            func(c *Config) { c.RecoveryLinkTTL = 0 },
		"address":        func(c *Config) { c.MailLinkRateLimit = 0 },
		"address window": func(c *Config) { c.MailLinkRateWindow = -1 },
		"source":         func(c *Config) { c.MailLinkSourceRateLimit = 0 },
		"source window":  func(c *Config) { c.MailLinkSourceRateWindow = 0 },
	} {
		cfg := DefaultConfig()
		change(cfg)
		if err := Validate(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEmailVerificationSetting(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.EmailVerification != "required" || cfg.RegistrationLinkTTL != 86400 {
		t.Errorf("defaults: %q, %d", cfg.EmailVerification, cfg.RegistrationLinkTTL)
	}
	cfg.EmailVerification = "off"
	if err := Validate(cfg); err == nil {
		t.Error("a bad value was accepted")
	}
	cfg = DefaultConfig()
	cfg.RegistrationLinkTTL = 0
	if err := Validate(cfg); err == nil {
		t.Error("a lifetime of 0 was accepted")
	}
}

// A file with a removed key still loads, and serve is told to say so.
func TestRemovedKeysWarn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("email_pin_auth: \"enabled\"\nlog_file: \"/var/log/signet.log\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Deprecations) != 2 ||
		!strings.Contains(cfg.Deprecations[0], "email_pin_auth does nothing") ||
		!strings.Contains(cfg.Deprecations[1], "log_file does nothing") {
		t.Errorf("warnings: %q", cfg.Deprecations)
	}

	clean := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(clean, []byte("log_level: \"info\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadConfig(clean); err != nil || len(cfg.Deprecations) != 0 {
		t.Errorf("a file without them: %v, %q", err, cfg.Deprecations)
	}
}

// Argon2id settings the argon2 package cannot run with stop the load, rather
// than a panic at the first sign-in.
func TestArgon2idSettingsValidation(t *testing.T) {
	for _, bad := range []string{
		"argon2id_parallelism: 0\n",
		"argon2id_time: 0\n",
		"argon2id_key_length: 0\n",
		"argon2id_memory: 16\n",
	} {
		path := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "argon2id") {
			t.Errorf("%q: got %v, want an argon2id error", bad, err)
		}
	}
}

// A key signet does not know stops the load, at the top level or inside a
// block, so a misspelt security setting cannot leave its default in force.
func TestUnknownKeysRefused(t *testing.T) {
	for _, c := range []struct{ yaml, want string }{
		{"second_facter: required\n", "second_facter"},
		{"claims_hook:\n  enabeld: true\n", "enabeld"},
		{"mail:\n  progam: /usr/sbin/sendmail\n", "progam"},
		{"auth_methods:\n  passkey: enabled\n", "auth_methods.passkey"},
		{"auth_methods:\n  totp: enabeld\n", "auth_methods.totp"},
	} {
		path := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(path, []byte(c.yaml), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: got %v, want an error naming %s", c.yaml, err, c.want)
		}
	}
}

// Renamed and removed keys still load, as they did before keys were checked,
// and an empty file is all defaults.
func TestLegacyKeysAndEmptyFileLoad(t *testing.T) {
	for _, y := range []string{
		"",
		"listen_addr: \"127.0.0.1:9999\"\n",
		"webauthn_enabled: false\n",
		"email_pin_auth: true\nlog_file: /var/log/signet.log\n",
	} {
		path := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(path, []byte(y), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err != nil {
			t.Errorf("%q: %v", y, err)
		}
	}
}

// Every configuration the repository ships loads under the strict rules.
func TestShippedConfigsLoad(t *testing.T) {
	for _, path := range []string{
		"../../config/example.yaml",
		"../../contrib/packaging/openbsd/www/signet/files/config.yaml",
		"../../contrib/packaging/freebsd/www/signet/files/config.yaml.sample",
	} {
		if _, err := LoadConfig(path); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}
