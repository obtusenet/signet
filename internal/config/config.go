// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/obtusenet/signet/internal/clientaddr"
	"github.com/obtusenet/signet/internal/password"
	"github.com/obtusenet/signet/internal/radius"
)

// Config holds all application configuration
type Config struct {
	Listen     string `yaml:"listen"`
	Protocol   string `yaml:"protocol"`    // "http" (default) or "fastcgi"
	SocketMode string `yaml:"socket_mode"` // octal file mode when listen is a Unix socket path

	TemplatesDir string `yaml:"templates_dir"`
	StaticDir    string `yaml:"static_dir"`
	CookieName   string `yaml:"cookie_name"`
	CookieDomain string `yaml:"cookie_domain"`
	CookieMaxAge int    `yaml:"cookie_max_age"`
	// SessionIdleTimeout ends a session after this many seconds without a
	// request that reads it; 0, the default, never does.
	SessionIdleTimeout int    `yaml:"session_idle_timeout"`
	CookieSecure       bool   `yaml:"cookie_secure"`
	CookieSecret       string `yaml:"cookie_secret"`
	DatabasePath       string `yaml:"database_path"`
	CSVPath            string `yaml:"csv_path"`
	PasswordHashAlg    string `yaml:"password_hash_algorithm"`
	BcryptCost         int    `yaml:"bcrypt_cost"`
	Argon2idTime       uint32 `yaml:"argon2id_time"`
	Argon2idMemory     uint32 `yaml:"argon2id_memory"`
	Argon2idParallel   uint8  `yaml:"argon2id_parallelism"`
	Argon2idSaltLen    uint32 `yaml:"argon2id_salt_length"`
	Argon2idKeyLen     uint32 `yaml:"argon2id_key_length"`
	SelfRegistration   string `yaml:"self_registration"`
	ApprovalRequired   string `yaml:"self_registration_approval"`
	// EmailVerification is how self-registration proves the address: "required"
	// creates the account only from a link in mail, "disabled" at once.
	EmailVerification string `yaml:"email_verification"`
	// TOTPIssuer is the name an authenticator app shows for a key.
	TOTPIssuer string `yaml:"totp_issuer"`
	// How recent a sign-in must be to change the account, in seconds.
	AccountReauthWindow int `yaml:"account_reauth_window"`
	// How long a registration link works, in seconds.
	RegistrationLinkTTL int    `yaml:"registration_link_ttl"`
	MultiDevice         string `yaml:"multi_device"`
	PasswordRecovery    string `yaml:"password_recovery"`
	// Avatars switches the image each account may set on /account.  AvatarSize is
	// its side in pixels; uploads are limited per account.
	Avatars          string `yaml:"avatars"`
	AvatarSize       int    `yaml:"avatar_size"`
	AvatarRateLimit  int    `yaml:"avatar_rate_limit"`
	AvatarRateWindow int    `yaml:"avatar_rate_window"`
	// PublicURL is the address of this instance as a browser reaches it, for
	// links in mail.  It is never taken from a request.
	PublicURL string `yaml:"public_url"`
	// BasePath is the path every route is served under, like "/comments-auth",
	// so that instances can share a host.  Empty serves from the root.
	BasePath string `yaml:"base_path"`
	// How long a recovery link works, in seconds.
	RecoveryLinkTTL int `yaml:"recovery_link_ttl"`
	// Messages with a link: per address, and per client address.
	MailLinkRateLimit        int `yaml:"mail_link_rate_limit"`
	MailLinkRateWindow       int `yaml:"mail_link_rate_window"`
	MailLinkSourceRateLimit  int `yaml:"mail_link_source_rate_limit"`
	MailLinkSourceRateWindow int `yaml:"mail_link_source_rate_window"`
	// LoginAddressLimit switches the failed-password limit per address, which
	// stops guessing one account but lets anyone block its password login.
	LoginAddressLimit string `yaml:"login_address_limit"`
	LoginRateLimit    int    `yaml:"login_rate_limit"`
	LoginRateWindow   int    `yaml:"login_rate_window"`
	// LoginSourceLimit switches the failed-password limit per client address,
	// which stops one source trying a password across every account.
	LoginSourceLimit      string `yaml:"login_source_limit"`
	LoginSourceRateLimit  int    `yaml:"login_source_rate_limit"`
	LoginSourceRateWindow int    `yaml:"login_source_rate_window"`
	// After LockoutThreshold failed sign-ins in a row, passwords, PINs and codes
	// are refused for LockoutDuration minutes.  A threshold of 0 switches it off.
	LockoutThreshold int `yaml:"account_lockout_threshold"`
	LockoutDuration  int `yaml:"account_lockout_duration"`
	EmailRateLimit   int `yaml:"email_rate_limit"`
	EmailRateWindow  int `yaml:"email_rate_window"`
	// TrustedProxies are the peers whose X-Forwarded-For is believed: IP
	// addresses, CIDR ranges, or "unix" for a peer on a unix socket.
	TrustedProxies     []string `yaml:"trusted_proxies"`
	WebAuthnRateLimit  int      `yaml:"webauthn_rate_limit"`
	WebAuthnRateWindow int      `yaml:"webauthn_rate_window"`
	RegisterRateLimit  int      `yaml:"register_rate_limit"`
	RegisterRateWindow int      `yaml:"register_rate_window"`
	APIRateLimit       int      `yaml:"api_rate_limit"`
	APIRateWindow      int      `yaml:"api_rate_window"`
	LogLevel           string   `yaml:"log_level"`
	LogSyslog          bool     `yaml:"log_syslog"`

	// WebAuthn configuration
	// auth_methods.webauthn is the switch; these say where it applies.
	RPID            string   `yaml:"webauthn_rpid"`
	RPDisplayName   string   `yaml:"webauthn_rp_name"`
	WebAuthnOrigins []string `yaml:"webauthn_origins"`

	// AllowedRedirectHosts lists hostnames that a login may redirect back
	// to when the return location is an absolute URL on a different host
	// (applications protected through signet, e.g. via Caddy forward_auth).
	// Local paths and same-host URLs need no listing.  An entry matches
	// case-insensitively against the target URL's hostname; without a port
	// it accepts the scheme's default port only, with a port it accepts
	// that port only.  IP addresses work as entries; IPv6 literals may be
	// written full or minified (bracket them to carry a port), and both
	// spellings match either URL form.
	AllowedRedirectHosts []string `yaml:"allowed_redirect_hosts"`

	Mail       MailConfig       `yaml:"mail"`
	ClaimsHook ClaimsHookConfig `yaml:"claims_hook"`

	// Radius checks the passwords of addresses users.csv does not have.
	Radius RadiusConfig `yaml:"radius"`

	AuthMethods map[string]string `yaml:"auth_methods"`

	// Legacy names the keys LoadConfig still reads by hand, renamed or removed
	// ones, so that the strict decoder accepts them.
	Legacy LegacyKeys `yaml:",inline"`

	// SecondFactor is "optional", where an account's own keys decide, or
	// "required", where every sign-in proves two factors.  SecondFactorMethods
	// are what may follow a password or a mailed PIN, and what an account may
	// enroll: "totp", "webauthn" and "email_pin".
	SecondFactor        string   `yaml:"second_factor"`
	SecondFactorMethods []string `yaml:"second_factor_methods"`

	// Deprecations are warnings about this file for `serve` to log.
	Deprecations []string `yaml:"-"`
}

// MailConfig says how messages reach the system's mail infrastructure.  Signet
// speaks no mail protocol itself: it runs Program as mail(1) would.
type MailConfig struct {
	// Program is the sendmail(8) to run.  Empty writes messages to the log
	// instead, PINs included.
	Program string `yaml:"program"`
	// FromAddress is the sender's address; empty leaves it to the mail system.
	FromAddress string `yaml:"from_address"`
	FromName    string `yaml:"from_name"`
}

// RadiusConfig is the RADIUS client: the servers to ask, in order, about
// addresses users.csv does not have.
type RadiusConfig struct {
	Enabled bool `yaml:"enabled"`
	// NASIdentifier names this application to the servers (RFC 2865 §5.32).
	NASIdentifier string               `yaml:"nas_identifier"`
	Servers       []RadiusServerConfig `yaml:"servers"`
	TimeoutSec    int                  `yaml:"timeout_seconds"`
	Retries       int                  `yaml:"retries"`
	// GroupAttributes are the reply attributes whose values are groups.
	GroupAttributes []string `yaml:"group_attributes"`
	// RequireMessageAuthenticator drops replies without one (CVE-2024-3596).
	RequireMessageAuthenticator bool `yaml:"require_message_authenticator"`
	// The most a reply's Session-Timeout and Idle-Timeout may set, in
	// seconds.  0 is Signet's own: see RadiusCeilings.
	MaxSessionTimeout int `yaml:"max_session_timeout"`
	MaxIdleTimeout    int `yaml:"max_idle_timeout"`
}

// RadiusServerConfig is one server.  Exactly one of Secret and SecretFile.
type RadiusServerConfig struct {
	Address    string `yaml:"address"` // host:port; the port defaults to 1812
	Secret     string `yaml:"secret"`
	SecretFile string `yaml:"secret_file"`
	Auth       string `yaml:"auth"` // "pap" (default) or "mschapv2"
}

// ClaimsHookConfig holds external claims hook configuration
type ClaimsHookConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Program    string `yaml:"program"`
	TimeoutSec int    `yaml:"timeout_seconds"`
	OnFailure  string `yaml:"on_failure"` // "fail-closed" or "fail-open"

	// RefreshRateLimit hook runs by /session?claims=refresh per account in
	// RefreshRateWindow seconds; past it, the stored claims are answered.
	RefreshRateLimit  int `yaml:"refresh_rate_limit"`
	RefreshRateWindow int `yaml:"refresh_rate_window"`
}

// DefaultConfig returns a Config with all defaults set
func DefaultConfig() *Config {
	return &Config{
		Listen:                   ":8080",
		Protocol:                 "http",
		SocketMode:               "0660",
		TemplatesDir:             "/etc/signet/templates",
		StaticDir:                "/etc/signet/static",
		CookieName:               "signetid",
		CookieDomain:             "",
		CookieMaxAge:             86400,
		CookieSecure:             true,
		DatabasePath:             "/var/lib/signet/sessions.db",
		CSVPath:                  "/var/lib/signet/users.csv",
		PasswordHashAlg:          "argon2id",
		BcryptCost:               12,
		Argon2idTime:             1,
		Argon2idMemory:           65536,
		Argon2idParallel:         4,
		Argon2idSaltLen:          16,
		Argon2idKeyLen:           32,
		SelfRegistration:         "disabled",
		ApprovalRequired:         "required",
		EmailVerification:        "required",
		RegistrationLinkTTL:      86400,
		AccountReauthWindow:      600,
		TOTPIssuer:               "Signet",
		MultiDevice:              "enabled",
		PasswordRecovery:         "disabled",
		Avatars:                  "disabled",
		AvatarSize:               256,
		AvatarRateLimit:          10,
		AvatarRateWindow:         3600,
		RecoveryLinkTTL:          3600,
		MailLinkRateLimit:        3,
		MailLinkRateWindow:       3600,
		MailLinkSourceRateLimit:  10,
		MailLinkSourceRateWindow: 3600,
		LoginAddressLimit:        "enabled",
		LoginRateLimit:           5,
		LoginRateWindow:          300,
		LoginSourceLimit:         "enabled",
		LoginSourceRateLimit:     20,
		LoginSourceRateWindow:    300,
		LockoutDuration:          30,
		LockoutThreshold:         100,
		EmailRateLimit:           3,
		EmailRateWindow:          60,
		WebAuthnRateLimit:        30,
		WebAuthnRateWindow:       60,
		RegisterRateLimit:        5,
		RegisterRateWindow:       3600,
		APIRateLimit:             60,
		APIRateWindow:            60,
		LogLevel:                 "info",
		LogSyslog:                false,
		RPDisplayName:            "Signet",
		Mail: MailConfig{
			Program:  "/usr/sbin/sendmail",
			FromName: "Signet",
		},
		ClaimsHook: ClaimsHookConfig{
			Enabled:           false,
			TimeoutSec:        5,
			OnFailure:         "fail-closed",
			RefreshRateLimit:  6,
			RefreshRateWindow: 60,
		},
		Radius: RadiusConfig{
			TimeoutSec:                  3,
			Retries:                     2,
			GroupAttributes:             []string{"Filter-Id"},
			RequireMessageAuthenticator: true,
		},
		SecondFactor:        "optional",
		SecondFactorMethods: []string{"totp", "webauthn"},
		AuthMethods: map[string]string{
			"password":  "enabled",
			"webauthn":  "disabled",
			"email_pin": "enabled",
			"totp":      "disabled",
			"yubikey":   "disabled",
		},
	}
}

// LegacyKeys are old keys a file may still have.  LoadConfig honours or reports
// each; nothing else reads these fields.
type LegacyKeys struct {
	ListenAddr      any `yaml:"listen_addr"`
	WebAuthnEnabled any `yaml:"webauthn_enabled"`
	EmailPINAuth    any `yaml:"email_pin_auth"`
	LogFile         any `yaml:"log_file"`
}

// authMethodNames are the keys auth_methods may have.
var authMethodNames = []string{"password", "webauthn", "email_pin", "totp", "yubikey"}

// LoadConfig reads and parses a YAML config file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	// A key signet does not know stops the load: a misspelt one, such as
	// second_facter, would otherwise leave its default in force unseen.
	cfg := DefaultConfig()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Deprecated: listen_addr was renamed to listen.  Honour the old key
	// when the new one is absent, so existing installs keep binding.
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err == nil {
		if _, ok := raw["listen"]; !ok {
			if v, ok := raw["listen_addr"]; ok {
				if s, ok := v.(string); ok {
					cfg.Listen = s
				}
			}
		}
		applyDeprecatedWebAuthnEnabled(cfg, raw)
		noteRemovedKeys(cfg, raw)
	}

	if err := Validate(cfg); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// removedKeys are keys that once loaded and now do nothing, with what decides instead.
var removedKeys = []struct{ key, instead string }{
	{"email_pin_auth", "auth_methods.email_pin is the switch"},
	{"log_file", "the log goes to stdout under systemd, else to syslog or stdout as log_syslog says"},
}

// noteRemovedKeys warns about each removed key the file still has.  A file with
// one still loads: the key never did anything.
func noteRemovedKeys(cfg *Config, raw map[string]interface{}) {
	for _, k := range removedKeys {
		if _, ok := raw[k.key]; ok {
			cfg.Deprecations = append(cfg.Deprecations,
				fmt.Sprintf("%s does nothing and is no longer read: %s, so remove it from this file", k.key, k.instead))
		}
	}
}

// applyDeprecatedWebAuthnEnabled honours webauthn_enabled, which was a second
// switch beside auth_methods.webauthn: WebAuthn was on only when both agreed.
// A file that still has it means what it meant before.
func applyDeprecatedWebAuthnEnabled(cfg *Config, raw map[string]interface{}) {
	v, ok := raw["webauthn_enabled"]
	if !ok {
		return
	}
	cfg.Deprecations = append(cfg.Deprecations,
		"webauthn_enabled is deprecated and will go away: auth_methods.webauthn is the only switch, so remove it from this file")
	if enabled, _ := v.(bool); !enabled {
		cfg.AuthMethods["webauthn"] = "disabled"
		return
	}
	methods, _ := raw["auth_methods"].(map[string]interface{})
	if _, explicit := methods["webauthn"]; !explicit {
		cfg.AuthMethods["webauthn"] = "enabled"
	}
}

// MethodEnabled reports whether an auth method in the auth_methods block is on.
func (c *Config) MethodEnabled(name string) bool {
	v, ok := c.AuthMethods[name]
	if !ok {
		// Passwords are the baseline method; a configuration without the
		// block keeps them available.
		return name == "password"
	}
	return strings.EqualFold(v, "enabled")
}

// SecondFactorRequired reports whether every sign-in must prove two factors.
func (c *Config) SecondFactorRequired() bool {
	return c.SecondFactor == "required"
}

// SecondFactorAllows reports whether method is in second_factor_methods.
func (c *Config) SecondFactorAllows(method string) bool {
	for _, m := range c.SecondFactorMethods {
		if m == method {
			return true
		}
	}
	return false
}

// validateSecondFactor checks second_factor and its methods.  Each method listed
// must be on in auth_methods, since the same code does the work.
func validateSecondFactor(cfg *Config) error {
	switch cfg.SecondFactor {
	case "optional", "required":
	default:
		return fmt.Errorf("second_factor must be 'optional' or 'required'")
	}
	seen := map[string]bool{}
	for _, m := range cfg.SecondFactorMethods {
		switch m {
		case "totp", "webauthn", "email_pin":
		default:
			return fmt.Errorf("second_factor_methods: %q is not one of totp, webauthn, email_pin", m)
		}
		if seen[m] {
			return fmt.Errorf("second_factor_methods lists %s twice", m)
		}
		seen[m] = true
		if cfg.SecondFactorRequired() && !cfg.MethodEnabled(m) {
			return fmt.Errorf("second_factor_methods lists %s, but auth_methods.%s is not enabled", m, m)
		}
	}
	if cfg.SecondFactorRequired() && len(cfg.SecondFactorMethods) == 0 {
		return fmt.Errorf("second_factor is required, but second_factor_methods is empty")
	}
	return nil
}

// MinCookieSecretLength is the shortest accepted cookie_secret, in bytes:
// what `openssl rand -hex 32` produces is 64.
const MinCookieSecretLength = 32

// ValidateForServe checks what only a running server needs.  Administrative
// commands load the same file and have no use for the signing secret, so they
// keep working on a configuration that has not been given one yet.
func ValidateForServe(cfg *Config) error {
	if len(cfg.CookieSecret) < MinCookieSecretLength {
		return fmt.Errorf("cookie_secret must be set to at least %d characters (generate one with: openssl rand -hex 32); instances sharing a database must use the same value", MinCookieSecretLength)
	}
	return nil
}

// Validate checks that all required config fields are set correctly
func Validate(cfg *Config) error {
	if cfg.Listen == "" {
		return fmt.Errorf("listen is required")
	}
	if err := validateSecondFactor(cfg); err != nil {
		return err
	}
	switch cfg.Protocol {
	case "", "http", "fastcgi":
	default:
		return fmt.Errorf("protocol must be 'http' or 'fastcgi'")
	}
	if cfg.SocketMode != "" {
		mode, err := strconv.ParseUint(cfg.SocketMode, 8, 32)
		if err != nil || mode > 0777 {
			return fmt.Errorf("socket_mode must be an octal file mode like 0660")
		}
	}
	for name, value := range cfg.AuthMethods {
		known := false
		for _, n := range authMethodNames {
			known = known || n == name
		}
		if !known {
			return fmt.Errorf("auth_methods.%s is not a method: use %s", name, strings.Join(authMethodNames, ", "))
		}
		if !strings.EqualFold(value, "enabled") && !strings.EqualFold(value, "disabled") {
			return fmt.Errorf("auth_methods.%s must be 'enabled' or 'disabled'", name)
		}
	}
	if cfg.PasswordHashAlg != "bcrypt" && cfg.PasswordHashAlg != "argon2id" {
		return fmt.Errorf("password_hash_algorithm must be 'bcrypt' or 'argon2id'")
	}
	if cfg.BcryptCost < 4 || cfg.BcryptCost > 31 {
		return fmt.Errorf("bcrypt_cost must be between 4 and 31")
	}
	// The argon2 package panics on some of these, so they are checked here
	// rather than at the first sign-in.
	if err := password.CheckArgon2idParams(cfg.Argon2idTime, cfg.Argon2idMemory,
		uint32(cfg.Argon2idParallel), cfg.Argon2idSaltLen, cfg.Argon2idKeyLen); err != nil {
		return fmt.Errorf("argon2id settings: %w", err)
	}
	if cfg.SelfRegistration != "enabled" && cfg.SelfRegistration != "disabled" {
		return fmt.Errorf("self_registration must be 'enabled' or 'disabled'")
	}
	if cfg.ApprovalRequired != "required" && cfg.ApprovalRequired != "auto_approve" {
		return fmt.Errorf("self_registration_approval must be 'required' or 'auto_approve'")
	}
	if cfg.EmailVerification != "required" && cfg.EmailVerification != "disabled" {
		return fmt.Errorf("email_verification must be 'required' or 'disabled'")
	}
	if cfg.MultiDevice != "enabled" && cfg.MultiDevice != "disabled" {
		return fmt.Errorf("multi_device must be 'enabled' or 'disabled'")
	}
	if cfg.Avatars != "enabled" && cfg.Avatars != "disabled" {
		return fmt.Errorf("avatars must be 'enabled' or 'disabled'")
	}
	// The page sends the image in the request body, which stops at 128 KiB.
	if cfg.AvatarSize < 32 || cfg.AvatarSize > 512 {
		return fmt.Errorf("avatar_size must be from 32 to 512 pixels")
	}
	for _, limit := range []struct {
		key, state, number, window string
		max, seconds               int
	}{
		{"login_address_limit", cfg.LoginAddressLimit, "login_rate_limit", "login_rate_window", cfg.LoginRateLimit, cfg.LoginRateWindow},
		{"login_source_limit", cfg.LoginSourceLimit, "login_source_rate_limit", "login_source_rate_window", cfg.LoginSourceRateLimit, cfg.LoginSourceRateWindow},
	} {
		if limit.state != "enabled" && limit.state != "disabled" {
			return fmt.Errorf("%s must be 'enabled' or 'disabled'", limit.key)
		}
		// Zero would refuse every login, not switch the limit off.
		if limit.state == "enabled" && limit.max <= 0 {
			return fmt.Errorf("%s must be greater than 0; to turn the limit off, set %s to 'disabled'", limit.number, limit.key)
		}
		if limit.state == "enabled" && limit.seconds <= 0 {
			return fmt.Errorf("%s must be greater than 0; to turn the limit off, set %s to 'disabled'", limit.window, limit.key)
		}
	}
	for name, value := range map[string]int{
		"webauthn_rate_limit":          cfg.WebAuthnRateLimit,
		"webauthn_rate_window":         cfg.WebAuthnRateWindow,
		"register_rate_limit":          cfg.RegisterRateLimit,
		"register_rate_window":         cfg.RegisterRateWindow,
		"recovery_link_ttl":            cfg.RecoveryLinkTTL,
		"registration_link_ttl":        cfg.RegistrationLinkTTL,
		"account_reauth_window":        cfg.AccountReauthWindow,
		"mail_link_rate_limit":         cfg.MailLinkRateLimit,
		"mail_link_rate_window":        cfg.MailLinkRateWindow,
		"mail_link_source_rate_limit":  cfg.MailLinkSourceRateLimit,
		"mail_link_source_rate_window": cfg.MailLinkSourceRateWindow,
		"avatar_rate_limit":            cfg.AvatarRateLimit,
		"avatar_rate_window":           cfg.AvatarRateWindow,
	} {
		if value <= 0 {
			return fmt.Errorf("%s must be greater than 0", name)
		}
	}
	if cfg.TOTPIssuer == "" || strings.Contains(cfg.TOTPIssuer, ":") {
		return fmt.Errorf("totp_issuer must be set and cannot contain a colon")
	}
	if cfg.LockoutThreshold < 0 {
		return fmt.Errorf("account_lockout_threshold cannot be negative (0 switches the lockout off)")
	}
	if cfg.LockoutThreshold > 0 && cfg.LockoutDuration < 1 {
		return fmt.Errorf("account_lockout_duration must be at least 1 minute while account_lockout_threshold is set")
	}
	if err := checkBasePath(cfg.BasePath); err != nil {
		return err
	}
	if cfg.PublicURL != "" {
		u, err := url.Parse(cfg.PublicURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("public_url must be an http or https address like https://signet.example.com")
		}
		if cfg.BasePath != "" && strings.Trim(u.Path, "/") != "" {
			return fmt.Errorf("public_url must have no path when base_path is set: links are public_url, then base_path, then the page")
		}
	}
	if _, err := clientaddr.New(cfg.TrustedProxies); err != nil {
		return fmt.Errorf("trusted_proxies: %w", err)
	}
	if cfg.ClaimsHook.OnFailure != "fail-closed" && cfg.ClaimsHook.OnFailure != "fail-open" {
		return fmt.Errorf("claims_hook.on_failure must be 'fail-closed' or 'fail-open'")
	}
	if cfg.ClaimsHook.RefreshRateLimit <= 0 || cfg.ClaimsHook.RefreshRateWindow <= 0 {
		return fmt.Errorf("claims_hook.refresh_rate_limit and claims_hook.refresh_rate_window must be positive")
	}
	if cfg.SessionIdleTimeout < 0 {
		return fmt.Errorf("session_idle_timeout cannot be negative (0 switches it off)")
	}
	if err := validateRadius(cfg); err != nil {
		return err
	}
	return nil
}

// RadiusCeilings are the most a RADIUS reply may set a session's lifetime and
// idle limit to: radius.max_session_timeout, else cookie_max_age; and
// radius.max_idle_timeout, else session_idle_timeout, else cookie_max_age.  So
// unless they are raised, a server can only shorten a session.
func (c *Config) RadiusCeilings() (session, idle int) {
	session = c.Radius.MaxSessionTimeout
	if session == 0 {
		session = c.CookieMaxAge
	}
	idle = c.Radius.MaxIdleTimeout
	if idle == 0 {
		idle = c.SessionIdleTimeout
	}
	if idle == 0 {
		idle = c.CookieMaxAge
	}
	return session, idle
}

// validateRadius checks the radius block when it is on, and gives each server
// address its port.
func validateRadius(cfg *Config) error {
	r := &cfg.Radius
	if !r.Enabled {
		return nil
	}
	if !cfg.MethodEnabled("password") {
		return fmt.Errorf("radius.enabled needs auth_methods.password: RADIUS checks passwords")
	}
	if r.NASIdentifier == "" || len(r.NASIdentifier) > 253 || strings.ContainsFunc(r.NASIdentifier, unicode.IsControl) {
		return fmt.Errorf("radius.nas_identifier must name this application to the RADIUS servers, in 1 to 253 bytes")
	}
	if len(r.Servers) == 0 {
		return fmt.Errorf("radius.servers must list at least one server")
	}
	for i := range r.Servers {
		srv := &r.Servers[i]
		if srv.Address == "" {
			return fmt.Errorf("radius.servers[%d].address is empty", i)
		}
		if _, _, err := net.SplitHostPort(srv.Address); err != nil {
			srv.Address = net.JoinHostPort(strings.Trim(srv.Address, "[]"), "1812")
		}
		if _, port, err := net.SplitHostPort(srv.Address); err != nil || port == "" {
			return fmt.Errorf("radius.servers[%d].address %q must be host or host:port", i, srv.Address)
		}
		if (srv.Secret == "") == (srv.SecretFile == "") {
			return fmt.Errorf("radius.servers[%d] (%s) needs exactly one of secret and secret_file", i, srv.Address)
		}
		// Read here too, so a reload with an unreadable file keeps the
		// running server.
		if srv.SecretFile != "" {
			b, err := os.ReadFile(srv.SecretFile)
			if err != nil {
				return fmt.Errorf("radius.servers[%d].secret_file: %w", i, err)
			}
			if strings.TrimRight(string(b), "\r\n") == "" {
				return fmt.Errorf("radius.servers[%d].secret_file %s is empty", i, srv.SecretFile)
			}
		}
		switch srv.Auth {
		case "":
			srv.Auth = "pap"
		case "pap", "mschapv2":
		default:
			return fmt.Errorf("radius.servers[%d].auth must be pap or mschapv2, not %q", i, srv.Auth)
		}
	}
	if r.TimeoutSec < 1 || r.TimeoutSec > 60 {
		return fmt.Errorf("radius.timeout_seconds must be 1 to 60")
	}
	if r.Retries < 0 || r.Retries > 10 {
		return fmt.Errorf("radius.retries must be 0 to 10")
	}
	if r.MaxSessionTimeout < 0 || r.MaxIdleTimeout < 0 {
		return fmt.Errorf("radius.max_session_timeout and radius.max_idle_timeout cannot be negative (0 is Signet's own)")
	}

	for _, a := range r.GroupAttributes {
		if _, err := radius.ParseGroupAttribute(a); err != nil {
			return fmt.Errorf("radius.group_attributes: %w", err)
		}
	}
	return nil
}

// checkBasePath accepts "" or segments like "/comments-auth" or "/auth/comments":
// a leading slash, no trailing one, and nothing a browser or a web server would
// read differently from Signet.
func checkBasePath(p string) error {
	if p == "" {
		return nil
	}
	bad := fmt.Errorf("base_path %q must look like /comments-auth: a leading slash, no trailing one, and only letters, digits and . _ ~ - in each part (leave it empty for the root)", p)
	if !strings.HasPrefix(p, "/") {
		return bad
	}
	for _, part := range strings.Split(p[1:], "/") {
		if part == "" || part == "." || part == ".." {
			return bad
		}
		for _, r := range part {
			ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._~-", r)
			if !ok {
				return bad
			}
		}
	}
	return nil
}

// KeepRestartOnly copies into next the settings a running server cannot change, so
// a reload keeps them, and answers the keys among them that the file changed.
// They are where it listens, what it speaks there, which database and users file
// it opened, and where it logs.
func KeepRestartOnly(running, next *Config) []string {
	var changed []string
	keep := func(key string, old, new *string) {
		if *old != *new {
			changed = append(changed, key)
			*new = *old
		}
	}
	keep("listen", &running.Listen, &next.Listen)
	keep("protocol", &running.Protocol, &next.Protocol)
	keep("socket_mode", &running.SocketMode, &next.SocketMode)
	keep("database_path", &running.DatabasePath, &next.DatabasePath)
	keep("csv_path", &running.CSVPath, &next.CSVPath)
	if running.LogSyslog != next.LogSyslog {
		changed = append(changed, "log_syslog")
		next.LogSyslog = running.LogSyslog
	}
	return changed
}
