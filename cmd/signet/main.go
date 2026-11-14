// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/obtusenet/signet/internal/apiclient"
	"github.com/obtusenet/signet/internal/auth"
	"github.com/obtusenet/signet/internal/avatar"
	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/config"
	"github.com/obtusenet/signet/internal/db"
	"github.com/obtusenet/signet/internal/logging"
	"github.com/obtusenet/signet/internal/maillink"
	"github.com/obtusenet/signet/internal/otp"
	"github.com/obtusenet/signet/internal/password"
	"github.com/obtusenet/signet/internal/server"
	"github.com/obtusenet/signet/internal/session"
	"github.com/obtusenet/signet/internal/webauthn"
)

var (
	gitHash   = "unknown"
	buildTime = "unknown"
	version   = "0.14.0"
	// defaultConfig is where commands look without -config.  Packages set it at link
	// time (-X main.defaultConfig=/etc/signet/config.yaml); a plain build reads the
	// current directory.
	defaultConfig = "config.yaml"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "serve":
		cmdServe(os.Args[2:])
	case "user-add":
		cmdUserAdd(os.Args[2:])
	case "user-list":
		cmdUserList(os.Args[2:])
	case "user-approve":
		cmdUserApprove(os.Args[2:])
	case "user-delete":
		cmdUserDelete(os.Args[2:])
	case "webauthn-invite":
		cmdWebAuthnInvite(os.Args[2:])
	case "user-list-webauthn":
		cmdUserListWebAuthn(os.Args[2:])
	case "user-delete-webauthn":
		cmdUserDeleteWebAuthn(os.Args[2:])
	case "user-delete-totp":
		cmdUserDeleteTOTP(os.Args[2:])
	case "user-unlock":
		cmdUserUnlock(os.Args[2:])
	case "avatar-remove":
		cmdAvatarRemove(os.Args[2:])
	case "client-add":
		cmdClientAdd(os.Args[2:])
	case "client-list":
		cmdClientList(os.Args[2:])
	case "client-revoke":
		cmdClientRevoke(os.Args[2:])
	case "help":
		printHelp()
	case "version":
		fmt.Printf("signet %s (built %s, hash %s)\n", version, buildTime, gitHash)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printHelp()
		os.Exit(1)
	}
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", defaultConfig, "path to config file")
	fs.Parse(args)

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logging.ReportFatal(fmt.Sprintf("Error loading config %s: %v", *configPath, err))
		os.Exit(1)
	}

	if err := config.ValidateForServe(cfg); err != nil {
		logging.ReportFatal(fmt.Sprintf("Error in config %s: %v", *configPath, err))
		os.Exit(1)
	}

	if err := server.CheckTemplates(cfg.TemplatesDir); err != nil {
		logging.ReportFatal(fmt.Sprintf("Error in templates_dir %s: %v", cfg.TemplatesDir, err))
		os.Exit(1)
	}

	// Initialize logging
	logger, err := logging.New(cfg.LogSyslog, cfg.LogLevel)
	if err != nil {
		logging.ReportFatal(fmt.Sprintf("Error initializing logger: %v", err))
		os.Exit(1)
	}
	defer logger.Close()

	logger.Info(fmt.Sprintf("Signet starting (hash=%s)", gitHash))

	// Report sensitive files anyone on the host can read.  Fixing permissions
	// stays with the administrator; signet only states the fact.
	warnIfWorldReadable(logger, *configPath, "holds cookie_secret")
	warnIfWorldReadable(logger, cfg.CSVPath, "holds password hashes")
	warnIfWorldReadable(logger, cfg.DatabasePath, "holds session tokens")

	// Initialize database
	dbStore, err := db.New(cfg.DatabasePath)
	if err != nil {
		logging.ReportFatal(fmt.Sprintf("Error initializing database: %v", err))
		os.Exit(1)
	}
	defer dbStore.Close()

	// Initialize CSV backend
	backend, err := csv.New(cfg.CSVPath)
	if err != nil {
		logging.ReportFatal(fmt.Sprintf("Error initializing CSV backend: %v", err))
		os.Exit(1)
	}
	defer backend.Close()

	// Start file watcher for auto-reload on CSV changes
	if err := backend.StartWatcher(); err != nil {
		logger.Warn(fmt.Sprintf("Error starting CSV watcher (polling fallback): %v", err))
	}

	// Create server
	srv := server.New(cfg, logger, dbStore, backend)

	// Set up signal handling for SIGHUP (config reload) and SIGTERM/SIGINT (graceful shutdown)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		// Loop: a SIGHUP must not consume the channel and leave a later
		// SIGTERM unhandled.
		for sig := range sigCh {
			logger.Info(fmt.Sprintf("Received signal: %v", sig))
			switch sig {
			case syscall.SIGHUP:
				if next, ok := reloadConfig(*configPath, cfg, logger); ok {
					srv.Swap(server.New(next, logger, dbStore, backend))
					cfg = next
					logger.Info(fmt.Sprintf("configuration and templates reloaded from %s", *configPath))
				}
			default:
				// Stop accepting connections and drain in-flight
				// requests; Start() returns once the listener is
				// closed, which is what lets rcctl stop finish
				// instead of escalating to SIGKILL.
				shutdownCtx, shutdownCancel :=
					context.WithTimeout(context.Background(), 10*time.Second)
				if err := srv.Shutdown(shutdownCtx); err != nil {
					logger.Warn(fmt.Sprintf("graceful shutdown: %v", err))
				}
				shutdownCancel()
				cancel()
				return
			}
		}
	}()

	// Start server
	if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		// Nothing is listening, so waiting for a signal would leave a live
		// process doing no work, and a supervisor would never restart it.
		// os.Exit skips the deferred closes.
		logging.ReportFatal(fmt.Sprintf("Server error: %v", err))
		backend.Close()
		dbStore.Close()
		logger.Close()
		os.Exit(1)
	}

	// Wait for shutdown signal
	<-ctx.Done()
	logger.Info("Shutdown complete")
}

// reloadConfig reads the config and its templates again for a SIGHUP.  If either
// is wrong, the running configuration stays and the log says why.  Settings that
// need a restart keep their running values, and the log names them.
func reloadConfig(path string, running *config.Config, logger *logging.Logger) (*config.Config, bool) {
	next, err := config.LoadConfig(path)
	if err == nil {
		err = config.ValidateForServe(next)
	}
	if err != nil {
		logger.Error(fmt.Sprintf("reload refused, keeping the running configuration: %v", err))
		return nil, false
	}
	if err := server.CheckTemplates(next.TemplatesDir); err != nil {
		logger.Error(fmt.Sprintf("reload refused, keeping the running configuration: templates_dir %s: %v", next.TemplatesDir, err))
		return nil, false
	}
	for _, key := range config.KeepRestartOnly(running, next) {
		logger.Warn(fmt.Sprintf("%s changed in %s: it takes effect at the next restart, not on reload", key, path))
	}
	warnIfWorldReadable(logger, path, "holds cookie_secret")
	return next, true
}

func cmdUserAdd(args []string) {
	fs := flag.NewFlagSet("user-add", flag.ExitOnError)
	configPath := fs.String("config", defaultConfig, "path to config file")
	hashAlgorithm := fs.String("hash", "argon2id", "hash algorithm (bcrypt or argon2id)")
	passwordStdin := fs.Bool("password-stdin", false, "read the password from the first line of standard input")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: signet user-add [options] <email> [password]\n")
		os.Exit(1)
	}

	email := fs.Arg(0)
	passwd := ""
	if fs.NArg() > 1 {
		passwd = fs.Arg(1)
		if !*passwordStdin {
			fmt.Fprintln(os.Stderr, "Warning: a password given as an argument can be seen in the process list and stays in shell history; use -password-stdin")
		}
	}
	if *passwordStdin {
		if passwd != "" {
			fmt.Fprintln(os.Stderr, "Error: give the password as an argument or with -password-stdin, not both")
			os.Exit(1)
		}
		var err error
		if passwd, err = readPasswordLine(os.Stdin); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading the password: %v\n", err)
			os.Exit(1)
		}
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logging
	logger, err := logging.New(cfg.LogSyslog, cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	// Initialize CSV backend
	backend, err := csv.New(cfg.CSVPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing CSV backend: %v\n", err)
		os.Exit(1)
	}
	defer backend.Close()

	// Hash password
	hasher := password.NewHasher(
		*hashAlgorithm,
		cfg.BcryptCost,
		password.Argon2idParams{
			Time:       cfg.Argon2idTime,
			Memory:     cfg.Argon2idMemory,
			Parallel:   cfg.Argon2idParallel,
			SaltLength: cfg.Argon2idSaltLen,
			KeyLength:  cfg.Argon2idKeyLen,
		},
	)

	var hash string
	if passwd != "" {
		hash, err = hasher.Hash(passwd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error hashing password: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Generate a random password hash (for users who must set their password)
		fmt.Fprintf(os.Stderr, "No password provided, user will need to use recovery\n")
		hash = "!" // Invalid hash that can never be matched
	}

	// Create user.  An administrator adding the account is the approval.
	flags := []string{"approved"}
	if err := backend.CreateUser(email, hash, *hashAlgorithm, flags); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating user: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("User %s created successfully\n", email)
}

// readPasswordLine reads a password from the first line of r.  An argument is
// visible in ps and shell history; this is not.  Nothing but the line ending is
// removed, and an empty line is an error: asking for this and getting an account
// with no password would be a surprise.
func readPasswordLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", errors.New("standard input has no password")
	}
	return line, nil
}

// cmdUserApprove approves accounts: self-registrations awaiting approval, and
// accounts that older versions of user-add marked self_registered.
func cmdUserApprove(args []string) {
	fs := flag.NewFlagSet("user-approve", flag.ExitOnError)
	configPath := fs.String("config", defaultConfig, "path to config file")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: signet user-approve [options] <email>...\n")
		os.Exit(1)
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	backend, err := csv.New(cfg.CSVPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing CSV backend: %v\n", err)
		os.Exit(1)
	}
	defer backend.Close()

	failed := false
	for _, email := range fs.Args() {
		if err := backend.AddFlag(email, csv.FlagApproved); err != nil {
			fmt.Fprintf(os.Stderr, "Error approving %s: %v\n", email, err)
			failed = true
			continue
		}
		fmt.Printf("User %s approved\n", email)
	}
	if failed {
		backend.Close()
		os.Exit(1)
	}
}

// warnIfWorldReadable logs a warning for a sensitive file with the world-read
// bit set.  A missing file is not an error here; whatever opens it reports that.
func warnIfWorldReadable(logger *logging.Logger, path, why string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if info.Mode().Perm()&0o004 != 0 {
		logger.Warn(fmt.Sprintf("%s is world-readable (mode %04o) and %s", path, info.Mode().Perm(), why))
	}
}

// cmdUserDelete removes an account and everything that could keep it alive:
// sessions, WebAuthn credentials and invites.
func cmdUserDelete(args []string) {
	fs := flag.NewFlagSet("user-delete", flag.ExitOnError)
	configPath := fs.String("config", defaultConfig, "path to config file")
	confirm := fs.Bool("confirm", false, "confirm deletion")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: signet user-delete [options] --confirm <email>\n")
		os.Exit(1)
	}
	email := fs.Arg(0)

	if !*confirm {
		fmt.Fprintf(os.Stderr, "This will delete %s with its sessions and security keys\n", email)
		fmt.Fprintf(os.Stderr, "Use --confirm to actually delete it\n")
		os.Exit(1)
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	backend, err := csv.New(cfg.CSVPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing CSV backend: %v\n", err)
		os.Exit(1)
	}
	defer backend.Close()

	email = backend.Resolve(email)

	dbStore, err := db.New(cfg.DatabasePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing database: %v\n", err)
		backend.Close()
		os.Exit(1)
	}
	defer dbStore.Close()

	webauthnStore, err := webauthn.NewStore(dbStore.DB())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing WebAuthn store: %v\n", err)
		backend.Close()
		dbStore.Close()
		os.Exit(1)
	}

	// The row goes first, so no new login can start a session during the sweep.
	if err := backend.DeleteUser(email); err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting user: %v\n", err)
		backend.Close()
		dbStore.Close()
		os.Exit(1)
	}

	ctx := context.Background()
	failed := false
	links, err := maillink.NewStore(dbStore.DB())
	if err == nil {
		err = links.DeleteEmail(ctx, email)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: removing recovery links for %s: %v\n", email, err)
	}
	// Reading no secrets, so any key will do here.
	if totpKeys, err := otp.NewTOTPStore(dbStore.DB(), []byte("unused"), "Signet"); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: removing TOTP keys for %s: %v\n", email, err)
	} else if _, err := totpKeys.DeleteAll(ctx, email); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: removing TOTP keys for %s: %v\n", email, err)
	}
	// Any threshold opens the table; the count goes with the account.
	if lockout, err := auth.NewLockout(dbStore.DB(), 1, time.Minute); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: removing failed sign-ins for %s: %v\n", email, err)
	} else if _, err := lockout.Clear(ctx, email); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: removing failed sign-ins for %s: %v\n", email, err)
	}
	if pictures, err := avatar.NewStore(dbStore.DB()); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: removing the picture of %s: %v\n", email, err)
	} else if _, err := pictures.Remove(ctx, email); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: removing the picture of %s: %v\n", email, err)
	}
	if err := session.NewStore(dbStore.DB()).RevokeAll(ctx, email); err != nil {
		fmt.Fprintf(os.Stderr, "Error revoking sessions for %s: %v\n", email, err)
		failed = true
	}
	keys, err := webauthnStore.DeleteUser(ctx, email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error removing security keys for %s: %v\n", email, err)
		failed = true
	}
	if failed {
		fmt.Fprintf(os.Stderr, "The account row is gone but the cleanup above did not finish\n")
		backend.Close()
		dbStore.Close()
		os.Exit(1)
	}

	fmt.Printf("User %s deleted, with %d security key(s) and all sessions\n", email, keys)
}

// cmdWebAuthnInvite prints a one-time link that enrolls a security key without
// a signed-in session, for accounts with no other way to sign in.
func cmdWebAuthnInvite(args []string) {
	fs := flag.NewFlagSet("webauthn-invite", flag.ExitOnError)
	configPath := fs.String("config", defaultConfig, "path to config file")
	ttl := fs.Duration("ttl", 24*time.Hour, "how long the link stays valid")
	origin := fs.String("origin", "", "origin for the link (default: first of webauthn_origins)")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: signet webauthn-invite [options] <email>\n")
		os.Exit(1)
	}
	email := fs.Arg(0)
	if *ttl <= 0 {
		fmt.Fprintf(os.Stderr, "--ttl must be positive\n")
		os.Exit(1)
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	backend, err := csv.New(cfg.CSVPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing CSV backend: %v\n", err)
		os.Exit(1)
	}
	defer backend.Close()

	email = backend.Resolve(email)
	if _, err := backend.GetUser(email); err != nil {
		fmt.Fprintf(os.Stderr, "Error looking up %s: %v\n", email, err)
		backend.Close()
		os.Exit(1)
	}

	dbStore, err := db.New(cfg.DatabasePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing database: %v\n", err)
		backend.Close()
		os.Exit(1)
	}
	defer dbStore.Close()

	webauthnStore, err := webauthn.NewStore(dbStore.DB())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing WebAuthn store: %v\n", err)
		backend.Close()
		dbStore.Close()
		os.Exit(1)
	}

	// A link is no use if this configuration serves no enrollment page.
	problem := "auth_methods.webauthn is not enabled"
	if cfg.MethodEnabled("webauthn") {
		problem = ""
		if _, err := webauthn.NewService(cfg.RPID, cfg.RPDisplayName, cfg.WebAuthnOrigins, webauthnStore); err != nil {
			problem = err.Error()
		}
	}
	if problem != "" {
		fmt.Fprintf(os.Stderr, "WebAuthn is off in %s, so no link was made: %s\n", *configPath, problem)
		backend.Close()
		dbStore.Close()
		os.Exit(1)
	}

	base := *origin
	if base == "" {
		base = cfg.WebAuthnOrigins[0]
	}

	token, err := webauthnStore.CreateInvite(context.Background(), email, *ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating invite: %v\n", err)
		backend.Close()
		dbStore.Close()
		os.Exit(1)
	}

	// The fragment keeps the token out of every access log.
	fmt.Printf("One-time enrollment link for %s, valid for %s (shown once):\n", email, *ttl)
	fmt.Printf("%s%s/webauthn/keys#invite=%s\n", strings.TrimRight(base, "/"), cfg.BasePath, token)
}

func cmdUserList(args []string) {
	fs := flag.NewFlagSet("user-list", flag.ExitOnError)
	configPath := fs.String("config", defaultConfig, "path to config file")
	fs.Parse(args)

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logging
	logger, err := logging.New(cfg.LogSyslog, cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	// Initialize CSV backend
	backend, err := csv.New(cfg.CSVPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing CSV backend: %v\n", err)
		os.Exit(1)
	}
	defer backend.Close()

	// List users
	users, err := backend.ListUsers()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing users: %v\n", err)
		os.Exit(1)
	}

	if len(users) == 0 {
		fmt.Println("No users found")
		return
	}

	fmt.Printf("%-40s %-12s %s\n", "EMAIL", "ALGORITHM", "FLAGS")
	fmt.Println("----------------------------------------------")
	for _, u := range users {
		fmt.Printf("%-40s %-12s %s\n", u.Email, u.HashAlg, flagsToString(u.Flags))
	}
}

func flagsToString(flags []string) string {
	s := ""
	for i, f := range flags {
		if i > 0 {
			s += ","
		}
		s += f
	}
	return s
}

func cmdUserListWebAuthn(args []string) {
	fs := flag.NewFlagSet("user-list-webauthn", flag.ExitOnError)
	configPath := fs.String("config", defaultConfig, "path to config file")
	email := fs.String("email", "", "email address to list credentials for")
	fs.Parse(args)

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logging
	logger, err := logging.New(cfg.LogSyslog, cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	// Initialize database
	dbStore, err := db.New(cfg.DatabasePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing database: %v\n", err)
		os.Exit(1)
	}
	defer dbStore.Close()

	// Initialize WebAuthn store
	webauthnStore, err := webauthn.NewStore(dbStore.DB())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing WebAuthn store: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	var userEmail string
	if *email != "" {
		userEmail = *email
	} else if fs.NArg() > 0 {
		userEmail = fs.Arg(0)
	} else {
		fmt.Fprintf(os.Stderr, "Usage: signet user-list-webauthn [options] [email]\n")
		os.Exit(1)
	}

	userEmail = resolveAddress(cfg, userEmail)

	// List credentials
	creds, err := webauthnStore.GetUserCredentials(ctx, userEmail)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing credentials: %v\n", err)
		os.Exit(1)
	}

	if len(creds) == 0 {
		fmt.Printf("No WebAuthn credentials found for %s\n", userEmail)
		return
	}

	fmt.Printf("WebAuthn credentials for %s (%d total):\n\n", userEmail, len(creds))
	fmt.Printf("%-64s %-30s %-15s %-20s %-10s\n", "ID", "LABEL", "ATTESTATION", "CREATED", "BACKUP-ELIGIBLE")
	fmt.Println("--------------------------------------------------------------------------------")
	for _, c := range creds {
		fmt.Printf("%-64s %-30s %-15s %-20s %-10v\n",
			truncate(c.ID, 64),
			truncate(c.Label, 30),
			c.AttestationFmt,
			c.CreatedAt.Format("2006-01-02 15:04"),
			c.BackupEligible)
	}
}

// cmdUserDeleteTOTP removes every TOTP key and recovery code of an account, for
// someone who has lost their authenticator and their recovery codes.
// resolveAddress answers address as its account in users.csv has it, matched
// without regard to case, since the database records the account's own form.
func resolveAddress(cfg *config.Config, address string) string {
	backend, err := csv.New(cfg.CSVPath)
	if err != nil {
		return address
	}
	defer backend.Close()
	return backend.Resolve(address)
}

func cmdUserDeleteTOTP(args []string) {
	fs := flag.NewFlagSet("user-delete-totp", flag.ExitOnError)
	configPath := fs.String("config", defaultConfig, "path to config file")
	confirm := fs.Bool("confirm", false, "confirm deletion")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: signet user-delete-totp [options] --confirm <email>\n")
		os.Exit(1)
	}
	email := fs.Arg(0)
	if !*confirm {
		fmt.Fprintf(os.Stderr, "This will remove every TOTP key and recovery code of %s,\n", email)
		fmt.Fprintf(os.Stderr, "so signing in will need no code until a new key is added\n")
		fmt.Fprintf(os.Stderr, "Use --confirm to actually remove them\n")
		os.Exit(1)
	}

	dbStore, _ := openAPIStore(*configPath)
	defer dbStore.Close()
	if cfg, err := config.LoadConfig(*configPath); err == nil {
		email = resolveAddress(cfg, email)
	}
	// Reading no secrets, so any key will do here.
	store, err := otp.NewTOTPStore(dbStore.DB(), []byte("unused"), "Signet")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		dbStore.Close()
		os.Exit(1)
	}
	removed, err := store.DeleteAll(context.Background(), email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error removing TOTP keys: %v\n", err)
		dbStore.Close()
		os.Exit(1)
	}
	fmt.Printf("Removed %d TOTP keys of %s\n", removed, email)
}

// cmdUserUnlock clears an account's count of failed sign-ins, ending a lock.
func cmdUserUnlock(args []string) {
	fs := flag.NewFlagSet("user-unlock", flag.ExitOnError)
	configPath := fs.String("config", defaultConfig, "path to config file")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: signet user-unlock [options] <email>\n")
		os.Exit(1)
	}
	email := fs.Arg(0)
	dbStore, _ := openAPIStore(*configPath)
	defer dbStore.Close()
	// Any threshold opens the table.
	lockout, err := auth.NewLockout(dbStore.DB(), 1, time.Minute)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		dbStore.Close()
		os.Exit(1)
	}
	ctx := context.Background()
	failures, err := lockout.Failures(ctx, email)
	if err == nil {
		_, err = lockout.Clear(ctx, email)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error clearing failed sign-ins: %v\n", err)
		dbStore.Close()
		os.Exit(1)
	}
	if failures == 0 {
		fmt.Printf("%s has no failed sign-ins to clear\n", email)
		return
	}
	fmt.Printf("Cleared %d failed sign-ins of %s; it can sign in again\n", failures, email)
}

// cmdAvatarRemove takes down an account's picture, whatever avatars says: one
// set while they were enabled is still served by an instance that has them on.
func cmdAvatarRemove(args []string) {
	fs := flag.NewFlagSet("avatar-remove", flag.ExitOnError)
	configPath := fs.String("config", defaultConfig, "path to config file")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: signet avatar-remove [options] <email>\n")
		os.Exit(1)
	}
	email := fs.Arg(0)
	dbStore, _ := openAPIStore(*configPath)
	defer dbStore.Close()
	pictures, err := avatar.NewStore(dbStore.DB())
	var had bool
	if err == nil {
		had, err = pictures.Remove(context.Background(), email)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error removing the picture: %v\n", err)
		dbStore.Close()
		os.Exit(1)
	}
	if !had {
		fmt.Printf("%s has no picture\n", email)
		return
	}
	fmt.Printf("Removed the picture of %s\n", email)
}

func cmdUserDeleteWebAuthn(args []string) {
	fs := flag.NewFlagSet("user-delete-webauthn", flag.ExitOnError)
	configPath := fs.String("config", defaultConfig, "path to config file")
	credentialID := fs.String("id", "", "credential ID to delete")
	confirm := fs.Bool("confirm", false, "confirm deletion")
	fs.Parse(args)

	if *credentialID == "" {
		fmt.Fprintf(os.Stderr, "Usage: signet user-delete-webauthn [options] --id <credential-id>\n")
		os.Exit(1)
	}

	if !*confirm {
		fmt.Fprintf(os.Stderr, "This will delete the WebAuthn credential %s\n", *credentialID)
		fmt.Fprintf(os.Stderr, "and sign its account out everywhere, whichever way each session signed in\n")
		fmt.Fprintf(os.Stderr, "Use --confirm to actually delete it\n")
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logging
	logger, err := logging.New(cfg.LogSyslog, cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	// Initialize database
	dbStore, err := db.New(cfg.DatabasePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing database: %v\n", err)
		os.Exit(1)
	}
	defer dbStore.Close()

	// Initialize WebAuthn store
	webauthnStore, err := webauthn.NewStore(dbStore.DB())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing WebAuthn store: %v\n", err)
		os.Exit(1)
	}

	userEmail, err := deleteCredentialAndSessions(context.Background(), webauthnStore, session.NewStore(dbStore.DB()), *credentialID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		dbStore.Close()
		os.Exit(1)
	}

	logger.Info(fmt.Sprintf("credential deleted: %s; all sessions of %s ended", *credentialID, userEmail))
	fmt.Printf("Credential %s deleted, and %s is signed out everywhere\n", truncate(*credentialID, 64), userEmail)
}

// deleteCredentialAndSessions removes a key and ends every session of its
// account, so that whoever signed in with it does not stay signed in.  It
// answers the account's address.
func deleteCredentialAndSessions(ctx context.Context, keys *webauthn.Store, sessions *session.Store, credentialID string) (string, error) {
	cred, err := keys.GetCredential(ctx, credentialID)
	if err != nil {
		return "", fmt.Errorf("finding credential: %w", err)
	}
	if err := keys.DeleteCredential(ctx, credentialID); err != nil {
		return "", fmt.Errorf("deleting credential: %w", err)
	}
	if err := sessions.RevokeAll(ctx, cred.UserEmail); err != nil {
		return "", fmt.Errorf("credential deleted, but the sessions of %s could not be ended: %w", cred.UserEmail, err)
	}
	return cred.UserEmail, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func printHelp() {
	fmt.Println(`signet - Web Authentication System

Usage: signet <command> [options]

Commands:
  serve              Start the signet server
  user-add           Add a new user
  user-list          List all users
  user-approve       Approve accounts awaiting approval
  user-delete        Delete an account with its sessions and security keys
  webauthn-invite    Print a one-time link to enroll a security key
  user-list-webauthn List WebAuthn credentials for a user
  user-delete-webauthn Delete a WebAuthn credential
  user-delete-totp   Remove an account's TOTP keys, for a lost authenticator
  user-unlock        Clear an account's failed sign-ins, ending a lockout
  avatar-remove      Remove an account's picture
  client-add         Register an application allowed to call /api/v1/validate
  client-list        List registered applications
  client-revoke      Delete a registered application
  version            Show version information
  help               Show this help message

Flags:
  -config string     Path to configuration file (default "` + defaultConfig + `")
  -hash string       Hash algorithm for user-add (default "argon2id")`)
}

// openAPIStore loads the configuration and opens the database that holds the
// api_clients table.
func openAPIStore(configPath string) (*db.DB, *apiclient.Store) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	dbStore, err := db.New(cfg.DatabasePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	return dbStore, apiclient.NewStore(dbStore.DB())
}

func cmdClientAdd(args []string) {
	fs := flag.NewFlagSet("client-add", flag.ExitOnError)
	configPath := fs.String("config", defaultConfig, "path to config file")
	origins := fs.String("origins", "", "comma-separated browser origins allowed to call the API")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: signet client-add [options] <name>\n")
		os.Exit(1)
	}

	var list []string
	for _, o := range strings.Split(*origins, ",") {
		if o = strings.TrimSpace(o); o != "" {
			list = append(list, o)
		}
	}

	dbStore, store := openAPIStore(*configPath)
	defer dbStore.Close()

	key, err := store.Create(context.Background(), fs.Arg(0), list)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Client %q registered.\n", fs.Arg(0))
	fmt.Printf("API key (shown once, store it now): %s\n", key)
}

func cmdClientList(args []string) {
	fs := flag.NewFlagSet("client-list", flag.ExitOnError)
	configPath := fs.String("config", defaultConfig, "path to config file")
	fs.Parse(args)

	dbStore, store := openAPIStore(*configPath)
	defer dbStore.Close()

	clients, err := store.List(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing clients: %v\n", err)
		os.Exit(1)
	}

	if len(clients) == 0 {
		fmt.Println("No API clients registered.")
		return
	}

	fmt.Printf("%-24s %-40s %s\n", "NAME", "ALLOWED ORIGINS", "CREATED")
	for _, c := range clients {
		origins := strings.Join(c.AllowedOrigins, ",")
		if origins == "" {
			origins = "-"
		}
		fmt.Printf("%-24s %-40s %s\n", c.Name, origins, c.CreatedAt.Format("2006-01-02 15:04"))
	}
}

func cmdClientRevoke(args []string) {
	fs := flag.NewFlagSet("client-revoke", flag.ExitOnError)
	configPath := fs.String("config", defaultConfig, "path to config file")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: signet client-revoke [options] <name>\n")
		os.Exit(1)
	}

	dbStore, store := openAPIStore(*configPath)
	defer dbStore.Close()

	removed, err := store.Revoke(context.Background(), fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error revoking client: %v\n", err)
		os.Exit(1)
	}
	if !removed {
		fmt.Fprintf(os.Stderr, "No client named %q\n", fs.Arg(0))
		os.Exit(1)
	}

	fmt.Printf("Client %q revoked.\n", fs.Arg(0))
}
