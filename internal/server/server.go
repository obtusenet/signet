// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/obtusenet/signet/internal/apiclient"
	"github.com/obtusenet/signet/internal/auth"
	"github.com/obtusenet/signet/internal/avatar"
	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/claims"
	"github.com/obtusenet/signet/internal/clientaddr"
	"github.com/obtusenet/signet/internal/config"
	"github.com/obtusenet/signet/internal/cookie"
	"github.com/obtusenet/signet/internal/db"
	"github.com/obtusenet/signet/internal/email"
	"github.com/obtusenet/signet/internal/logging"
	"github.com/obtusenet/signet/internal/maillink"
	"github.com/obtusenet/signet/internal/otp"
	"github.com/obtusenet/signet/internal/password"
	"github.com/obtusenet/signet/internal/session"
	"github.com/obtusenet/signet/internal/webauthn"
)

// Server is the main HTTP server
type Server struct {
	cfg                *config.Config
	logger             *logging.Logger
	db                 *db.DB
	backend            *csv.Backend
	hasher             *password.Hasher
	cookieMgr          *cookie.CookieManager
	sessionStore       *session.Store
	passwordAuth       *auth.PasswordAuth
	webauthnSvc        *webauthn.Service
	webauthnHandler    *webauthn.Handler
	emailPINAuth       *auth.EmailPINAuth
	emailRateLimiter   *auth.EmailRateLimiter
	mailer             email.Sender
	accounts           *auth.AccountPolicy
	links              *maillink.Store
	totp               *otp.TOTPStore // nil while auth_methods.totp is off
	steps              *otp.TOTPStore // the steps of a sign-in, with TOTP on or off
	totpLimit          *auth.RateLimiter
	lockout            *auth.Lockout // consecutive failed sign-ins; nil when off
	avatars            *avatar.Store // nil while avatars are off
	avatarLimiter      *auth.EmailRateLimiter
	recoveryOn         bool
	registrationOn     bool
	verifyRegistration bool
	linkAddressLimit   *auth.EmailRateLimiter
	linkSourceLimit    *auth.EmailRateLimiter
	mailSlots          chan struct{}
	mailJobs           *sync.WaitGroup // shared with the servers that replace this one
	mux                *http.ServeMux
	srvMu              sync.Mutex // guards srv and fcgiLn: Start and Shutdown run concurrently
	srv                *http.Server
	fcgiLn             net.Listener // set when serving FastCGI
	tmpl               *template.Template
	claimsHook         *claims.ClaimsHook
	apiClients         *apiclient.Store
	apiLimiter         *apiclient.Limiter
	clients            *clientaddr.Resolver
	webauthnLimiter    *auth.EmailRateLimiter
	refreshLimiter     *auth.EmailRateLimiter // claims hook runs by /session, per account
	registerLimiter    *auth.EmailRateLimiter
	housekeeping       []func(context.Context) // periodic upkeep, run by Start
	stopHousekeeping   context.CancelFunc      // guarded by srvMu

	// live answers the requests on this server's listener: the server itself, or
	// the one a reload swapped in.  served is this server's handler, built once.
	live       atomic.Pointer[Server]
	servedOnce sync.Once
	served     http.Handler
}

// pinLockoutDuration is how long wrong PIN guesses count against an address.
const pinLockoutDuration = 30 * time.Minute

// housekeepingInterval is how often expired rows and idle rate-limit keys go.
const housekeepingInterval = time.Hour

// New creates a new Server
func New(cfg *config.Config, logger *logging.Logger, dbStore *db.DB, backend *csv.Backend) *Server {
	s := &Server{
		cfg:     cfg,
		logger:  logger,
		db:      dbStore,
		backend: backend,
	}

	// LoadConfig has validated these; a Server built directly trusts no proxy.
	clients, err := clientaddr.New(cfg.TrustedProxies)
	if err != nil {
		logger.Warn(fmt.Sprintf("trusted_proxies: %v; believing no proxy", err))
		clients = nil
	}
	s.clients = clients
	if network, _ := listenParts(cfg.Listen); network == "unix" && cfg.Protocol != "fastcgi" {
		if !slices.Contains(cfg.TrustedProxies, clientaddr.Unix) {
			logger.Warn("listening on a unix socket without \"unix\" in trusted_proxies: every client shares one rate-limit budget")
		}
	}

	// Initialize password hasher
	s.hasher = password.NewHasher(
		cfg.PasswordHashAlg,
		cfg.BcryptCost,
		password.Argon2idParams{
			Time:       cfg.Argon2idTime,
			Memory:     cfg.Argon2idMemory,
			Parallel:   cfg.Argon2idParallel,
			SaltLength: cfg.Argon2idSaltLen,
			KeyLength:  cfg.Argon2idKeyLen,
		},
	)

	// Initialize cookie manager
	// `serve` refuses to start without cookie_secret.  The fallback is for
	// embedding and tests: an unguessable per-process key, never a blank one.
	secret := []byte(cfg.CookieSecret)
	if len(secret) == 0 {
		secret = generateSecret()
	}
	s.cookieMgr = cookie.NewCookieManager(
		cfg.CookieName,
		cfg.CookieDomain,
		cfg.CookieMaxAge,
		secret,
	)
	s.cookieMgr.Secure = cfg.CookieSecure

	// Initialize session store
	s.sessionStore = session.NewStore(dbStore.DB())
	s.sessionStore.SetIdleTimeout(time.Duration(cfg.SessionIdleTimeout) * time.Second)

	if cfg.BasePath != "" {
		logger.Info(fmt.Sprintf("serving every route under base_path %s", cfg.BasePath))
	}

	// Load templates
	if cfg.TemplatesDir != "" {
		tmpl, err := loadTemplates(cfg.TemplatesDir, cfg.BasePath)
		if err != nil {
			logger.Warn(fmt.Sprintf("failed to load templates: %v", err))
		} else {
			s.tmpl = tmpl
			logger.Info(fmt.Sprintf("loaded %d templates from %s", countTemplates(tmpl), cfg.TemplatesDir))
		}
	}

	// Optional external claims hook, shared by login, email PIN and /session.
	if cfg.ClaimsHook.Enabled && cfg.ClaimsHook.Program != "" {
		s.claimsHook = claims.NewClaimsHook(cfg.ClaimsHook, logger)
		logger.Info(fmt.Sprintf("claims hook enabled: %s", cfg.ClaimsHook.Program))
	}
	var hooks []*claims.ClaimsHook
	if s.claimsHook != nil {
		hooks = append(hooks, s.claimsHook)
	}

	// Who may sign in, whichever method proved their identity.
	accounts := auth.NewAccountPolicy(backend, cfg.ApprovalRequired == "required")
	s.accounts = accounts
	s.mailer = newMailer(cfg, logger)
	s.mailSlots = make(chan struct{}, mailSlots)
	s.mailJobs = &sync.WaitGroup{}

	for _, deprecation := range cfg.Deprecations {
		logger.Warn(deprecation)
	}

	// Initialize WebAuthn.
	if s.authMethodEnabled("webauthn") {
		webauthnStore, err := webauthn.NewStore(dbStore.DB())
		if err != nil {
			logger.Warn(fmt.Sprintf("auth_methods.webauthn is enabled, but security keys are off: %v", err))
		} else {
			webauthnService, err := webauthn.NewService(
				cfg.RPID,
				cfg.RPDisplayName,
				cfg.WebAuthnOrigins,
				webauthnStore,
				cfg.SecondFactorRequired(),
			)
			if err != nil {
				logger.Warn(fmt.Sprintf("auth_methods.webauthn is enabled, but security keys are off: %v", err))
			} else {
				webauthnService.SetDecoySecret(secret)
				s.webauthnSvc = webauthnService
				s.webauthnHandler = webauthn.NewHandler(webauthnService, s.sessionStore, s.cookieMgr, accounts, logger, hooks...)
				s.webauthnHandler.SetAccountChanges(time.Duration(cfg.AccountReauthWindow)*time.Second, s.notifyAccountChange)
				s.webauthnHandler.SetRemovalCheck(func(ctx context.Context, address string) error {
					return s.mayRemoveSecondFactor(ctx, address, "webauthn")
				})
				logger.Info("WebAuthn enabled")
			}
		}
	}

	// Initialize email PIN auth (if enabled in auth_methods)
	if cfg.AuthMethods["email_pin"] == "enabled" {
		pinStore, err := email.NewPINStoreWithTemplate(dbStore.DB(), s.mailer, 10*time.Minute, cfg.TemplatesDir)
		if err != nil {
			logger.Warn(fmt.Sprintf("failed to initialize email PIN store: %v", err))
		} else {
			s.emailRateLimiter = auth.NewEmailRateLimiter(cfg.EmailRateLimit, time.Duration(cfg.EmailRateWindow)*time.Second)
			s.emailPINAuth = auth.NewEmailPINAuth(
				pinStore,
				accounts,
				s.sessionStore,
				s.cookieMgr,
				logger,
				s.emailRateLimiter,
				3, // max retries
				pinLockoutDuration,
				hooks...,
			)
			s.emailPINAuth.SetClientAddr(s.clients)
			s.emailPINAuth.SetBackground(s.mailInBackground)
			logger.Info("Email PIN authentication enabled")
			s.housekeeping = append(s.housekeeping, func(ctx context.Context) {
				s.emailRateLimiter.Cleanup()
				if n, err := pinStore.PurgeExpiredPins(ctx, pinLockoutDuration); err != nil {
					logger.Warn(fmt.Sprintf("removing expired PINs: %v", err))
				} else if n > 0 {
					logger.Info(fmt.Sprintf("removed %d expired PINs", n))
				}
			})
		}
	}

	// Initialize password auth
	s.passwordAuth = auth.NewPasswordAuth(
		accounts,
		s.hasher,
		s.cookieMgr,
		s.sessionStore,
		logger,
		cfg.LoginRateLimit,
		cfg.LoginRateWindow,
		hooks...,
	)

	if cfg.LoginAddressLimit == "disabled" {
		s.passwordAuth.DisableAddressLimit()
	}
	if cfg.LoginSourceLimit == "enabled" {
		s.passwordAuth.SetSourceLimit(cfg.LoginSourceRateLimit, cfg.LoginSourceRateWindow)
	} else if cfg.LoginAddressLimit == "disabled" {
		logger.Warn("login_address_limit and login_source_limit are both disabled: nothing limits password guessing")
	}

	s.startLockout(dbStore)
	s.startMailLinks(dbStore)
	s.startTOTP(dbStore, secret)
	s.startRadius()
	s.startAvatars(dbStore)

	// Per requester, never per address: a budget per address would let anyone
	// lock a user out of their own key.
	s.webauthnLimiter = auth.NewEmailRateLimiter(cfg.WebAuthnRateLimit, time.Duration(cfg.WebAuthnRateWindow)*time.Second)
	s.refreshLimiter = auth.NewEmailRateLimiter(cfg.ClaimsHook.RefreshRateLimit, time.Duration(cfg.ClaimsHook.RefreshRateWindow)*time.Second)
	s.registerLimiter = auth.NewEmailRateLimiter(cfg.RegisterRateLimit, time.Duration(cfg.RegisterRateWindow)*time.Second)

	s.housekeeping = append(s.housekeeping, func(ctx context.Context) {
		s.passwordAuth.PruneRateLimiter()
		s.webauthnLimiter.Cleanup()
		s.refreshLimiter.Cleanup()
		s.registerLimiter.Cleanup()
		if n, err := s.sessionStore.Cleanup(ctx); err != nil {
			logger.Warn(fmt.Sprintf("removing expired sessions: %v", err))
		} else if n > 0 {
			logger.Info(fmt.Sprintf("removed %d expired sessions", n))
		}
	})

	// Applications allowed to call the validation API, and their budget.
	s.apiClients = apiclient.NewStore(dbStore.DB())
	s.apiLimiter = apiclient.NewLimiter(cfg.APIRateLimit, time.Duration(cfg.APIRateWindow)*time.Second)

	// Set up routes
	s.mux = http.NewServeMux()
	s.setupRoutes()

	return s
}

// statusRecorder remembers what was written so the access log can report the
// status code and the number of bytes.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer (Flush,
// deadlines), which a wrapped ResponseWriter would otherwise hide.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// withRequestLog logs one line per request: method, URI, status, size,
// duration and client address, the address as clientaddr reads it
// (X-Forwarded-For only from trusted_proxies, from the right).
func (s *Server) withRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}

		s.logger.Info(fmt.Sprintf(
			"http request method=%s uri=%q status=%d bytes=%d duration=%s remote=%s",
			r.Method, r.URL.RequestURI(), rec.status, rec.bytes,
			time.Since(start).Round(time.Microsecond), s.clients.Addr(r)))
	})
}

// maxRequestBody bounds every request body.  Nothing signet accepts comes close:
// a WebAuthn attestation with its certificates is a few kilobytes.
const maxRequestBody = 128 << 10

// maxRequestHeader bounds the request line and headers, down from Go's 1 MB,
// and with them the URI in the request log.
const maxRequestHeader = 32 << 10

// withLimits applies what holds for every response and every request body, so
// that no handler can forget it.  A body that declares itself too big is refused
// here; one that does not fails when the handler reads past the limit.
func withLimits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.ContentLength > maxRequestBody {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Request too large"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		next.ServeHTTP(w, r)
	})
}

// withOriginCheck refuses a state-changing request that a browser says came from
// another origin, the one thing SameSite=Strict cannot stop: POST /login needs no
// cookie, so another site could sign a visitor into the attacker's account.
// Clients that are not browsers send neither header and are not affected.  A host
// in allowed_redirect_hosts is an application the operator already trusts.
//
// /api/v1/validate is cross-origin by design: an API key authenticates it, and
// each client's allowed_origins decides CORS.
func (s *Server) withOriginCheck(next http.Handler) http.Handler {
	protection := http.NewCrossOriginProtection()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/validate" {
			if err := protection.Check(r); err != nil && !s.originListed(r) {
				s.logger.Warn(fmt.Sprintf("cross-origin request refused: %s %q origin=%q fetch-site=%q from %s",
					r.Method, r.URL.Path, r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site"), s.clients.Addr(r)))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Cross-origin request refused"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// originListed reports whether the request's Origin is in allowed_redirect_hosts.
func (s *Server) originListed(r *http.Request) bool {
	origin, err := url.Parse(r.Header.Get("Origin"))
	return err == nil && origin.Host != "" && s.hostAllowedForReturn(origin)
}

// handler is the whole server, as both transports serve it.
func (s *Server) handler() http.Handler {
	return s.withRequestLog(s.withBasePath(withLimits(s.withOriginCheck(s.mux))))
}

// path is where a route of this instance is, as a browser asks for it.
func (s *Server) path(route string) string {
	if s.cfg == nil {
		return route
	}
	return s.cfg.BasePath + route
}

// withBasePath serves the routes under base_path.  The web server passes the path
// whole; what is outside the base is not this instance's, and answers 404.  So does
// a path with "..", "." or "//": the mux would redirect it to its clean form without
// the base, and browsers never send one.
func (s *Server) withBasePath(next http.Handler) http.Handler {
	base := s.cfg.BasePath
	if base == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if clean := path.Clean(r.URL.Path); clean != r.URL.Path && clean+"/" != r.URL.Path {
			http.NotFound(w, r)
			return
		}
		var rest string
		switch {
		case r.URL.Path == base:
			rest = "/"
		case strings.HasPrefix(r.URL.Path, base+"/"):
			rest = r.URL.Path[len(base):]
		default:
			http.NotFound(w, r)
			return
		}
		r2 := new(http.Request)
		*r2 = *r
		r2.URL = new(url.URL)
		*r2.URL = *r.URL
		r2.URL.Path = rest
		// The base has only unreserved characters, so it reads the same encoded.
		if r.URL.RawPath != "" {
			r2.URL.RawPath = strings.TrimPrefix(r.URL.RawPath, base)
		}
		next.ServeHTTP(w, r2)
	})
}

// setupRoutes configures HTTP routes
func (s *Server) setupRoutes() {
	// Health check
	s.mux.HandleFunc("/health", s.handleHealth)

	// Landing page: reports the signed-in user, or sends you to the form
	s.mux.HandleFunc("/", s.handleRoot)

	// Session inspection and termination
	s.mux.HandleFunc("/session", s.handleSession)
	s.mux.HandleFunc("/logout", s.handleLogout)

	// Auth flows
	s.mux.HandleFunc("/login", s.handleLogin)
	s.mux.HandleFunc("/register", s.handleRegister)
	s.mux.HandleFunc("/recover", s.handleRecover)
	s.mux.HandleFunc("/account", s.handleAccount)
	if s.avatars != nil {
		s.mux.HandleFunc("/avatar/", s.handleAvatar)
	}

	// WebAuthn
	if s.webauthnHandler != nil {
		s.mux.HandleFunc("/webauthn/register/start", s.limitWebAuthn(s.webauthnHandler.HandleBeginRegistration))
		s.mux.HandleFunc("/webauthn/register/finish", s.limitWebAuthn(s.webauthnHandler.HandleFinishRegistration))
		s.mux.HandleFunc("/webauthn/authenticate/start", s.limitWebAuthn(s.webauthnHandler.HandleBeginLogin))
		s.mux.HandleFunc("/webauthn/authenticate/finish", s.limitWebAuthn(s.webauthnHandler.HandleFinishLogin))
		s.mux.HandleFunc("/webauthn/invite", s.limitWebAuthn(s.webauthnHandler.HandleCheckInvite))
		s.mux.HandleFunc("/webauthn/credentials", s.webauthnHandler.HandleListCredentials)
		s.mux.HandleFunc("/webauthn/credentials/", s.webauthnHandler.HandleDeleteCredential)
		s.mux.HandleFunc("/webauthn/keys", s.handleWebAuthnKeys)
	}

	// Email PIN
	if s.emailPINAuth != nil {
		s.mux.HandleFunc("/email-pin/send", s.handleSendPIN)
		s.mux.HandleFunc("/email-pin/verify", s.handleVerifyPIN)
	}

	// API
	s.mux.HandleFunc("/api/v1/validate", s.handleValidate)

	// Static files
	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(filesOnly{http.Dir(s.cfg.StaticDir)})))
}

// Start starts the server per the configuration: listen gives the address
// (TCP, or a Unix socket when it is an absolute path); protocol "fastcgi"
// serves the same handler over the FastCGI protocol instead, as the
// responder side of a web server (nginx, httpd) that connects to it.
func (s *Server) Start() error {
	s.startHousekeeping(housekeepingInterval)
	network, address := listenParts(s.cfg.Listen)
	if s.cfg.Protocol == "fastcgi" {
		return s.startFCGI(network, address)
	}
	srv := &http.Server{
		Handler:        s.front(),
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: maxRequestHeader,
	}
	s.srvMu.Lock()
	s.srv = srv
	s.srvMu.Unlock()

	if network == "unix" {
		ln, err := s.listenUnix(address)
		if err != nil {
			return err
		}
		s.logger.Info(fmt.Sprintf("Starting signet server on unix socket %s", address))
		err = srv.Serve(ln)
		// Leave no stale socket behind for the next start.
		if rmErr := os.Remove(address); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			s.logger.Warn(fmt.Sprintf("removing socket %s: %v", address, rmErr))
		}
		return err
	}

	srv.Addr = address
	s.logger.Info(fmt.Sprintf("Starting signet server on %s", address))
	return srv.ListenAndServe()
}

// startFCGI answers the handler over FastCGI.  The web server is the
// client here, so signet is the receiver: a unix socket gets the same
// stale-socket reclaim and socket_mode rules as the HTTP socket path;
// a TCP address binds as usual.  The socket file is removed when
// serving ends, as for the HTTP socket.
func (s *Server) startFCGI(network, address string) error {
	var ln net.Listener
	var err error
	if network == "unix" {
		ln, err = s.listenUnix(address)
	} else {
		ln, err = net.Listen("tcp", address)
	}
	if err != nil {
		return err
	}
	s.srvMu.Lock()
	s.fcgiLn = ln
	s.srvMu.Unlock()
	s.logger.Info(fmt.Sprintf("Starting signet server on %s FastCGI address %s", network, address))

	err = fcgi.Serve(ln, s.front())

	if network == "unix" {
		if rmErr := os.Remove(address); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			s.logger.Warn(fmt.Sprintf("removing socket %s: %v", address, rmErr))
		}
	}
	// Closing the listener for a graceful Shutdown surfaces as a
	// net.ErrClosed accept error; callers know it as "server closed".
	if errors.Is(err, net.ErrClosed) {
		err = http.ErrServerClosed
	}
	return err
}

// listenParts classifies the listen configuration into a network and an
// address.  An absolute path binds a Unix domain socket; anything else is
// a TCP address, with a bare port normalised to ":port".  Bracketed IPv6
// forms ([::]:9090, [fd00::5]:9090) pass through to net.Listen unchanged.
// Relative paths deliberately do NOT select a socket.
func listenParts(addr string) (network, address string) {
	if filepath.IsAbs(addr) {
		return "unix", addr
	}
	if !strings.Contains(addr, ":") {
		return "tcp", ":" + addr
	}
	return "tcp", addr
}

// socketInUse reports whether something already answers on the socket path.
func socketInUse(path string) bool {
	c, err := net.DialTimeout("unix", path, 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// listenUnix binds path as a Unix socket.  A stale socket file (no listener)
// is removed and rebound; a path with a live listener is an error, so two
// instances can never fight over it.  The socket is chmod'ed to socket_mode.
func (s *Server) listenUnix(path string) (net.Listener, error) {
	ln, err := net.Listen("unix", path)
	if err != nil && socketInUse(path) {
		return nil, fmt.Errorf("socket %s is already in use: %w", path, err)
	} else if err != nil {
		// Only a socket can be stale.  A mistyped listen path must not
		// delete a regular file such as users.csv.
		info, serr := os.Lstat(path)
		if serr != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("listen path %s exists and is not a socket: %w", path, err)
		}
		if rerr := os.Remove(path); rerr != nil {
			return nil, fmt.Errorf("removing stale socket %s: %w", path, rerr)
		}
		if ln, err = net.Listen("unix", path); err != nil {
			return nil, err
		}
	}
	mode, err := strconv.ParseUint(s.socketMode(), 8, 32)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("invalid socket_mode %q: %w", s.socketMode(), err)
	}
	if err := os.Chmod(path, os.FileMode(mode)); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod socket %s: %w", path, err)
	}
	return ln, nil
}

// socketMode is the configured octal mode for the listening socket,
// defaulting to 0660; tighten or open via socket_mode in the configuration.
func (s *Server) socketMode() string {
	if s.cfg != nil && s.cfg.SocketMode != "" {
		return s.cfg.SocketMode
	}
	return "0660"
}

// startHousekeeping runs the upkeep now and then at every interval, until
// Shutdown.  Instances sharing a database may all run it: removing a row that
// another has removed is harmless.
func (s *Server) startHousekeeping(interval time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	s.srvMu.Lock()
	s.stopHousekeeping = cancel
	s.srvMu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			for _, task := range s.housekeeping {
				task(ctx)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down signet server")
	s.srvMu.Lock()
	srv, fcgiLn, stop := s.srv, s.fcgiLn, s.stopHousekeeping
	s.srvMu.Unlock()
	if stop != nil {
		stop()
	}
	if live := s.live.Load(); live != nil && live != s {
		live.haltHousekeeping()
	}
	var err error
	if srv != nil {
		err = srv.Shutdown(ctx)
	} else if fcgiLn != nil {
		err = fcgiLn.Close()
	}

	// Let mail already handed to the background finish.
	finished := make(chan struct{})
	go func() {
		if s.mailJobs != nil {
			s.mailJobs.Wait()
		}
		close(finished)
	}()
	select {
	case <-finished:
	case <-ctx.Done():
		s.logger.Warn("shutting down with mail still in progress")
	}
	return err
}

// handleHealth handles the /health endpoint
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// wantsJSON reports whether the client asked for a JSON response.  The login
// page submits with fetch() and can only parse JSON; a plain HTML form post
// still gets a redirect.
func wantsJSON(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

// loginReply writes either a JSON body (XHR) or a plain-text error.
func (s *Server) loginReply(w http.ResponseWriter, r *http.Request, status int, payload map[string]interface{}, plain string) {
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(payload)
		return
	}
	http.Error(w, plain, status)
}

// handleRoot is the page a browser lands on after signing in.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token, err := s.cookieMgr.ValidateAuthCookie(r)
	if err == nil {
		if sess, serr := s.sessionStore.Get(r.Context(), token); serr == nil && sess != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<!DOCTYPE html>\n<html><head><title>Signet</title></head>"+
				"<body><h1>Signed in</h1><p>%s</p>"+
				"<p><a href=\"%[2]s/account\">Your account</a> | <a href=\"%[2]s/session\">Session</a> | <a href=\"%[2]s/logout\">Sign out</a></p>"+
				"</body></html>\n",
				html.EscapeString(sess.UserEmail), html.EscapeString(s.cfg.BasePath))
			return
		}
	}
	http.Redirect(w, r, s.path("/login"), http.StatusFound)
}

// renderLoginPage shows the login page, or its code step when pending is set.
func (s *Server) renderLoginPage(w http.ResponseWriter, r *http.Request, pending, message string, status int) {
	step := loginStep{Pending: pending, Error: message}
	if pending != "" {
		step.Step = otp.StepCode
	}
	s.renderLoginStep(w, r, step, status)
}

// loginStep is what the login page shows besides its sign-in methods: a second
// step, and what it needs.
type loginStep struct {
	Pending string // the step's token
	Step    string // otp.StepCode, StepMail or StepEnrol
	Error   string
	Message string

	// The enrolment step.
	EnrolTOTP     bool         // an authenticator app may be added
	EnrolKey      bool         // a security key may be added
	TOTPStarted   bool         // the app's key is made, and waits for a code
	TOTPSecret    string       // to type in
	TOTPQR        template.URL // a data: URI made here, never from the request
	RecoveryCodes []string     // shown once, after an app is added
	Continue      string       // where to go after reading them

	radius bool // a RADIUS account, which may not add a key here
}

// renderLoginStep shows the login page with step.
func (s *Server) renderLoginStep(w http.ResponseWriter, r *http.Request, step loginStep, status int) {
	pending, message := step.Pending, step.Error
	data := map[string]interface{}{
		"Step":                 step.Step,
		"Message":              step.Message,
		"EnrolTOTP":            step.EnrolTOTP,
		"EnrolKey":             step.EnrolKey,
		"TOTPStarted":          step.TOTPStarted,
		"TOTPSecret":           step.TOTPSecret,
		"TOTPQR":               step.TOTPQR,
		"RecoveryCodes":        step.RecoveryCodes,
		"Continue":             step.Continue,
		"AllowRegistration":    s.registrationOn,
		"PasswordEnabled":      s.authMethodEnabled("password"),
		"WebAuthnEnabled":      s.webauthnHandler != nil,
		"EmailPINEnabled":      s.emailPINAuth != nil,
		"TOTPEnabled":          s.totp != nil,
		"RadiusEnabled":        s.passwordAuth.RadiusEnabled(),
		"YubikeyEnabled":       s.authMethodEnabled("yubikey"),
		"Referrer":             s.loginReferrer(r),
		"AllowedRedirectHosts": s.allowedRedirectHostsJSON(),
		"Pending":              pending,
		"Error":                message,
	}
	if s.tmpl == nil {
		http.Error(w, "Templates not loaded", http.StatusInternalServerError)
		return
	}
	if pending != "" || len(step.RecoveryCodes) > 0 {
		w.Header().Set("Cache-Control", "no-store")
	}
	if err := s.renderTemplate(w, "login.html", data, status); err != nil {
		s.logger.Error(fmt.Sprintf("rendering login page: %v", err))
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// handleLogin handles /login GET and POST requests
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.renderLoginPage(w, r, "", "", http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// The code step, whichever method passed the first one.
	if r.PostFormValue("pending") != "" {
		s.finishSecondStep(w, r)
		return
	}

	if !s.authMethodEnabled("password") {
		s.logger.Warn(fmt.Sprintf("password login refused from %s: auth_methods.password is disabled", s.clients.Addr(r)))
		s.loginReply(w, r, http.StatusForbidden,
			map[string]interface{}{"success": false, "error": "Password sign-in is disabled"},
			"Password sign-in is disabled")
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if email == "" || password == "" {
		s.loginReply(w, r, http.StatusBadRequest,
			map[string]interface{}{"success": false, "error": "email and password are required"},
			"email and password are required")
		return
	}

	// Not an address, so not an account: answer as for one, without letting it
	// near the limiter's memory or the log.  With RADIUS on, a name is an
	// account the servers may know (exactly as typed).
	if err := csv.ValidateEmail(email); err != nil && !(s.passwordAuth.RadiusEnabled() && validRadiusName(email)) {
		s.logger.Warn(fmt.Sprintf("Login failed from %s: %v", s.clients.Addr(r), err))
		s.loginReply(w, r, http.StatusUnauthorized,
			map[string]interface{}{"success": false, "error": "Invalid email or password"},
			"Invalid email or password")
		return
	}
	email = s.accounts.Resolve(email)

	authCookie, err := s.passwordAuth.Authenticate(r.Context(), email, s.clients.Addr(r), password)
	s.finishPasswordSignIn(w, r, email, authCookie, err, 1)
}

// authMethodEnabled reports whether an auth method listed in the
// auth_methods configuration block is switched on.
func (s *Server) authMethodEnabled(name string) bool {
	return s.cfg.MethodEnabled(name)
}

// referrerParam reads ?referrer= from a raw query string.  Web servers cannot
// URL-encode the address they send here (nginx's $request_uri, Caddy's {uri}),
// so it may arrive as referrer=/page?x=1&y=2.  A literal "?" can only mean that:
// an encoded address has none.  Such a value runs to the end of the query and is
// taken verbatim, because its own escapes belong to the page it names.  Anything
// else is an ordinary query parameter.
func referrerParam(rawQuery string) string {
	raw := rawQuery
	if !strings.HasPrefix(raw, "referrer=") {
		_, after, found := strings.Cut(raw, "&referrer=")
		if !found {
			return ""
		}
		raw = after
	} else {
		raw = strings.TrimPrefix(raw, "referrer=")
	}
	if strings.Contains(raw, "?") {
		return raw
	}
	raw, _, _ = strings.Cut(raw, "&")
	value, err := url.QueryUnescape(raw)
	if err != nil {
		return ""
	}
	return value
}

// loginReferrer is the return location offered to the login page on GET: the
// ?referrer= parameter, else the page that linked here, else "".
func (s *Server) loginReferrer(r *http.Request) string {
	ref := s.offeredReferrer(r)
	if s.signInPage(ref, r) {
		return ""
	}
	return ref
}

func (s *Server) offeredReferrer(r *http.Request) string {
	if ref := referrerParam(r.URL.RawQuery); ref != "" {
		return ref
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil {
			if !s.signInPage(ref, r) && u.Path != "" {
				if q := referrerParam(u.RawQuery); q != "" {
					return q
				}
				return ref
			}
			return referrerParam(u.RawQuery)
		}
	}
	return ""
}

// signInPage reports whether target is one of this instance's pages for getting
// in or out, which are never somewhere to return to: back to /register after
// registering, or to /logout, which would sign the person straight out again.
func (s *Server) signInPage(target string, r *http.Request) bool {
	if target == "" {
		return false
	}
	u, err := url.Parse(target)
	if err != nil || (u.Host != "" && u.Host != r.Host) {
		return false
	}
	for _, page := range []string{"/login", "/register", "/recover", "/logout"} {
		if u.Path == s.path(page) {
			return true
		}
	}
	return false
}

// safeReturnPath normalises a return location and rejects anything that would
// send the browser to an untrusted host.  Local paths and absolute URLs on the
// same host are accepted; absolute URLs on hosts listed in
// allowed_redirect_hosts are returned as full URLs; everything else returns "".
func (s *Server) safeReturnPath(raw string, r *http.Request) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "/") {
		return safeLocalPath(raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if strings.EqualFold(u.Host, r.Host) {
		// RequestURI of http://host//evil is //evil, so it needs the same
		// check as a path given directly.
		return safeLocalPath(u.RequestURI())
	}
	if s.hostAllowedForReturn(u) {
		// A cross-host return target must stay an absolute URL.
		return u.String()
	}
	return ""
}

// safeLocalPath returns path when a browser is certain to read it as a path on
// this host, and "" otherwise.  Browsers treat a backslash as a slash and drop
// tabs and newlines from URLs, so "/\\evil", "/\t/evil" and "//evil" all name
// another host.
func safeLocalPath(path string) string {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return ""
	}
	if strings.ContainsRune(path, '\\') {
		return ""
	}
	for _, c := range path {
		if c < 0x20 || c == 0x7f {
			return ""
		}
	}
	// A browser resolves dot segments, encoded or not, before it reads the
	// result: /.//evil.example/ becomes //evil.example/, another host.  No
	// return address needs them.
	p, _, _ := strings.Cut(path, "?")
	p, _, _ = strings.Cut(p, "#")
	for _, segment := range strings.Split(p, "/") {
		decoded, err := url.PathUnescape(segment)
		if err != nil || decoded == "." || decoded == ".." {
			return ""
		}
	}
	return path
}

// hostAllowedForReturn reports whether an absolute return URL's host is listed
// in the allowed_redirect_hosts configuration.  Hostnames match
// case-insensitively; IP literals are canonicalised, so a full IPv6 entry
// matches its minified URL form and vice versa (bracketed "[fd00::5]:9443"
// carries a port; a bare IPv6 has none).  An entry without a port accepts the
// scheme's default port only, an entry with a port accepts that port only.
func (s *Server) hostAllowedForReturn(u *url.URL) bool {
	if s.cfg == nil || len(s.cfg.AllowedRedirectHosts) == 0 {
		return false
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		port = defaultPort(u.Scheme)
	}
	for _, entry := range s.cfg.AllowedRedirectHosts {
		entryHost, entryPort := splitHostPort(entry)
		if entryHost == "" || !hostsMatch(host, entryHost) {
			continue
		}
		if entryPort == "" {
			if port == defaultPort(u.Scheme) {
				return true
			}
		} else if entryPort == port {
			return true
		}
	}
	return false
}

// splitHostPort separates an allowed_redirect_hosts entry into a lowercase
// host and optional port.  Bracketed IPv6 ("[fd00::5]" or "[fd00::5]:9443")
// keeps its port; a bare IPv6 address (more than one colon) never carries a
// port; "host:port" and plain hosts split as expected.  Malformed bracketed
// entries return an empty host.
func splitHostPort(entry string) (string, string) {
	entry = strings.ToLower(strings.TrimSpace(entry))
	if strings.HasPrefix(entry, "[") {
		end := strings.Index(entry, "]")
		if end < 0 {
			return "", ""
		}
		host := entry[1:end]
		rest := entry[end+1:]
		switch {
		case rest == "":
			return host, ""
		case strings.HasPrefix(rest, ":") && !strings.Contains(rest[1:], ":"):
			return host, rest[1:]
		default:
			return "", ""
		}
	}
	if strings.Count(entry, ":") > 1 {
		return entry, ""
	}
	if h, p, err := net.SplitHostPort(entry); err == nil {
		return h, p
	}
	return entry, ""
}

// hostsMatch compares two lowercase hosts; IP literals are canonicalised
// with netip so full and minified IPv6 forms compare equal.  An IP literal
// never matches a non-IP host.
func hostsMatch(a, b string) bool {
	if a == b {
		return true
	}
	aAddr, aErr := netip.ParseAddr(a)
	bAddr, bErr := netip.ParseAddr(b)
	if aErr == nil && bErr == nil {
		return aAddr == bAddr
	}
	return false
}

// defaultPort is the port a URL's empty port implies for the scheme.
func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// allowedRedirectHostsJSON renders the configured redirect hostnames as a JS
// array literal for the login page's client-side return checks.
func (s *Server) allowedRedirectHostsJSON() template.JS {
	hosts := []string{}
	if s.cfg != nil && s.cfg.AllowedRedirectHosts != nil {
		hosts = s.cfg.AllowedRedirectHosts
	}
	b, err := json.Marshal(hosts)
	if err != nil {
		return template.JS("[]")
	}
	return template.JS(b)
}

// loginRedirect picks where to send the browser after a successful login:
// the posted ?referrer= value, the query parameter, the HTTP Referer, or else the
// account page.  This instance's sign-in pages are never one of them.
func (s *Server) loginRedirect(r *http.Request) string {
	candidates := []string{
		r.PostFormValue("referrer"),
		referrerParam(r.URL.RawQuery),
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil {
			if q := referrerParam(u.RawQuery); q != "" {
				candidates = append(candidates, q)
			}
			candidates = append(candidates, ref)
		}
	}
	for _, c := range candidates {
		p := s.safeReturnPath(c, r)
		if p == "" {
			continue
		}
		if s.signInPage(p, r) {
			continue
		}
		return p
	}
	// Nowhere to return to: the account page, which says who is signed in.
	return s.path("/account")
}

// limitWebAuthn applies the per-requester budget to a ceremony step.  Each step
// costs a database write or a signature check before anyone is authenticated.
func (s *Server) limitWebAuthn(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addr := s.clients.Addr(r)
		if !s.webauthnLimiter.Allow(addr) {
			s.logger.Warn(fmt.Sprintf("rate limited: WebAuthn %s from %s", r.URL.Path, addr))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Rate limit exceeded",
			})
			return
		}
		next(w, r)
	}
}

// handleWebAuthnKeys serves the security-key page.  It carries no account data
// of its own: the script asks /webauthn/credentials, and an enrollment invite
// stays in the URL fragment, which the server never sees.
func (s *Server) handleWebAuthnKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.renderTemplate(w, "webauthn.html", nil); err != nil {
		s.logger.Error(fmt.Sprintf("rendering security-key page: %v", err))
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// claimsObject renders a session's stored claims as a JSON object.  The
// claims are what the external hook returned at login time; an absent or
// malformed value becomes {} so clients always get an object.
func claimsObject(claims string) json.RawMessage {
	if claims == "" || !json.Valid([]byte(claims)) {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(claims)
}

// clearSessionCookie expires the auth cookie in the browser.
func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, s.cookieMgr.ExpiredAuthCookie())
}

// handleSession reports the state of the caller's session cookie.
//
// Valid session (200, application/json):
//
//	{"valid":true,"user":"a@b","email":"a@b","method":"password",
//	 "created_at":"...","expires_at":"...","claims":{...},
//	 "claims_refreshed":false}
//
// Anything else (401, same JSON shape):
//
//	{"valid":false,"error":"session not found"}
//
// With ?claims=refresh and an external hook configured, the hook is re-run,
// the session row is updated and the fresh claims are returned.  Each run starts
// a program, so runs are limited per account (claims_hook.refresh_rate_limit);
// past the limit the stored claims are answered, as when the hook fails.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeValidFalse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	token, err := s.cookieMgr.ValidateAuthCookie(r)
	if err != nil {
		s.writeSessionInvalid(w, err.Error())
		return
	}
	sess, err := s.sessionStore.Get(r.Context(), token)
	if err != nil {
		s.writeSessionInvalid(w, err.Error())
		return
	}

	refreshed := false
	if r.URL.Query().Get("claims") == "refresh" && s.claimsHook != nil {
		if !s.refreshLimiter.Allow(strings.ToLower(sess.UserEmail)) {
			s.logger.Warn(fmt.Sprintf("rate limited: claims refresh for %s (claims_hook.refresh_rate_limit)", sess.UserEmail))
		} else if facts, ferr := claims.ParseFacts(sess.Facts); ferr != nil {
			s.logger.Warn(fmt.Sprintf("refreshing claims for %s: %v", sess.UserEmail, ferr))
		} else if fresh, herr := s.claimsHook.ClaimsFor(r.Context(), sess.UserEmail, facts); herr != nil {
			s.logger.Warn(fmt.Sprintf("refreshing claims for %s: %v", sess.UserEmail, herr))
		} else if encoded, merr := json.Marshal(fresh); merr != nil {
			s.logger.Warn(fmt.Sprintf("encoding refreshed claims: %v", merr))
		} else if uerr := s.sessionStore.UpdateClaims(r.Context(), token, string(encoded)); uerr != nil {
			s.logger.Warn(fmt.Sprintf("storing refreshed claims: %v", uerr))
		} else {
			sess.Claims = string(encoded)
			refreshed = true
		}
	}

	// Headers a reverse proxy can copy onto the upstream request after a
	// forward-auth check (e.g. Caddy's copy_headers).
	w.Header().Set("Remote-User", sess.UserEmail)
	address := ""
	if isAddress(sess.UserEmail) {
		address = sess.UserEmail
		w.Header().Set("Remote-Email", address)
	}
	picture := s.avatarURL(r.Context(), sess.UserEmail)
	if picture != nil {
		w.Header().Set("Remote-Avatar", picture.(string))
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":            true,
		"avatar":           picture,
		"user":             sess.UserEmail,
		"email":            address,
		"method":           sess.AuthMethod,
		"created_at":       sess.CreatedAt.UTC().Format(time.RFC3339),
		"expires_at":       sess.ExpiresAt.UTC().Format(time.RFC3339),
		"claims":           claimsObject(sess.Claims),
		"claims_refreshed": refreshed,
	})
}

// writeSessionInvalid answers 401 with the standard invalid-session body.
func (s *Server) writeSessionInvalid(w http.ResponseWriter, reason string) {
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid": false,
		"error": reason,
	})
}

// handleLogout revokes the session behind the cookie and clears it.  Both GET
// (a plain link) and POST are accepted; the answer is JSON for XHR and a
// redirect to /login otherwise.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		if wantsJSON(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Method not allowed"})
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if token, err := s.cookieMgr.ValidateAuthCookie(r); err == nil {
		if rerr := s.sessionStore.Revoke(r.Context(), token); rerr != nil &&
			!errors.Is(rerr, session.ErrSessionNotFound) {
			s.logger.Warn(fmt.Sprintf("revoking session: %v", rerr))
		}
	}
	s.clearSessionCookie(w)

	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		return
	}
	http.Redirect(w, r, s.path("/login"), http.StatusSeeOther)
}

// writeSuccessFalse answers an action-style failure: JSON with "success":
// false and the status code that describes the failure.
func writeSuccessFalse(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// writeValidFalse answers a validation-style failure: JSON with "valid":
// false, an "error" string, and a status code the caller can branch on.
func writeValidFalse(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid": false,
		"error": message,
	})
}

// handleValidate handles the /api/v1/validate endpoint: a registered
// application presents its API key and a session cookie and learns who the
// cookie belongs to.
//
// The cookie may travel in the Cookie header or in the JSON body as
// {"cookie": "..."}; the body wins when both are present, because an
// application that stores the value itself should not depend on whatever
// cookie the caller's request happened to carry.
func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	// CORS: a preflight has no API key, so match the origin against every
	// registered client's allowed_origins.
	origin := r.Header.Get("Origin")
	originAllowed := false
	if origin != "" && s.apiClients != nil {
		if ok, err := s.apiClients.OriginAllowed(r.Context(), origin); err == nil && ok {
			originAllowed = true
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "X-API-Key, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		}
	}

	if r.Method == http.MethodOptions {
		if !originAllowed {
			writeValidFalse(w, http.StatusForbidden, "origin is not allowed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeValidFalse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	apiKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if apiKey == "" {
		writeValidFalse(w, http.StatusUnauthorized, "X-API-Key header required")
		return
	}
	client, err := s.apiClients.Lookup(r.Context(), apiKey)
	if err != nil {
		s.logger.Warn(fmt.Sprintf("validate: rejected API key: %v", err))
		writeValidFalse(w, http.StatusUnauthorized, "invalid API key")
		return
	}
	if !s.apiLimiter.Allow(client.Name) {
		s.logger.Warn(fmt.Sprintf("rate limited: validation API for client %q from %s",
			client.Name, s.clients.Addr(r)))
		writeValidFalse(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	// Body first, header second.
	cookieValue := ""
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") && r.Body != nil {
		var body struct {
			Cookie string `json:"cookie"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeValidFalse(w, http.StatusBadRequest, "invalid request body")
			return
		}
		cookieValue = strings.TrimSpace(body.Cookie)
	}
	if cookieValue == "" {
		if c, cerr := r.Cookie(s.cookieMgr.Name); cerr == nil {
			cookieValue = c.Value
		}
	}
	if cookieValue == "" {
		writeValidFalse(w, http.StatusUnauthorized, "no session cookie")
		return
	}

	token, err := s.cookieMgr.ValidateCookieValue(cookieValue)
	if err != nil {
		writeValidFalse(w, http.StatusUnauthorized, err.Error())
		return
	}
	sess, err := s.sessionStore.Get(r.Context(), token)
	if err != nil {
		writeValidFalse(w, http.StatusUnauthorized, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":  true,
		"user":   sess.UserEmail,
		"method": sess.AuthMethod,
		"claims": claimsObject(sess.Claims),
		"avatar": s.avatarURL(r.Context(), sess.UserEmail),
	})
}

// generateSecret generates a random 32-byte secret
func generateSecret() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

// GetBackend returns the CSV backend (for CLI usage)
func (s *Server) GetBackend() *csv.Backend {
	return s.backend
}

// GetHasher returns the password hasher (for CLI usage)
func (s *Server) GetHasher() *password.Hasher {
	return s.hasher
}

// Log is a convenience method for structured logging
func (s *Server) Log(msg string, fields ...interface{}) {
	s.logger.Info(fmt.Sprintf("%s %v", msg, fields))
}

// CheckTemplates reports why the pages in dir cannot be served.  `serve` stops on
// it: a server that starts anyway answers /health while every sign-in page fails.
func CheckTemplates(dir string) error {
	if dir == "" {
		return nil
	}
	_, err := loadTemplates(dir, "")
	return err
}

// countTemplates counts the parsed templates, without the empty one that holds the
// functions.
func countTemplates(tmpl *template.Template) int {
	n := 0
	for _, t := range tmpl.Templates() {
		if t.Name() != "" {
			n++
		}
	}
	return n
}

// loadTemplates parses the pages, which call basePath for this instance's
// base_path: "" at the root, else like "/comments-auth".
func loadTemplates(dir, base string) (*template.Template, error) {
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"basePath": func() string { return base },
	}).ParseGlob(dir + "/*.html")
	if err != nil {
		return nil, err
	}
	if tmpl.Lookup("login") == nil && tmpl.Lookup("login.html") == nil {
		return nil, fmt.Errorf("%s has no login.html", dir)
	}
	return tmpl, nil
}

// renderTemplate renders the page called name from the parsed template set
// and writes it to w.
//
// A template file may either be a standalone document named after its file
// (login.html) or a wrapper around a named definition ({{define "login"}}).
// With ParseGlob both always produce a template called login.html, but in the
// second case that template is empty and the content lives in "login", so the
// named definition is preferred when it exists.
func (s *Server) renderTemplate(w http.ResponseWriter, name string, data interface{}, status ...int) error {
	if s.tmpl == nil {
		return errors.New("templates not loaded")
	}

	var tmpl *template.Template
	for _, candidate := range []string{strings.TrimSuffix(name, filepath.Ext(name)), name} {
		if t := s.tmpl.Lookup(candidate); t != nil {
			tmpl = t
			break
		}
	}
	if tmpl == nil {
		return fmt.Errorf("template %q not defined", name)
	}

	// Render into a buffer first: a template that fails halfway must not
	// leave a partial page (and a committed 200) behind.
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if len(status) > 0 && status[0] != 0 {
		w.WriteHeader(status[0])
	}
	_, err := buf.WriteTo(w)
	return err
}

// GetTemplate returns the current template set (for SIGHUP reload)
func (s *Server) GetTemplate() *template.Template {
	return s.tmpl
}

// SetTemplate updates the template set (for SIGHUP reload)
func (s *Server) SetTemplate(tmpl *template.Template) {
	s.tmpl = tmpl
}

// User represents a user for API responses
type User struct {
	Email   string   `json:"email"`
	HashAlg string   `json:"hash_algorithm"`
	Flags   []string `json:"flags"`
}

// ValidateEmail is a helper that delegates to csv.ValidateEmail
func ValidateEmail(email string) error {
	return csv.ValidateEmail(email)
}

// HashPassword hashes a password using the configured algorithm
func HashPassword(hasher *password.Hasher, password string) (string, error) {
	return hasher.Hash(password)
}

// Now returns current time (for testing)
func Now() time.Time {
	return time.Now()
}

// handleSendPIN handles /email-pin/send POST requests
func (s *Server) handleSendPIN(w http.ResponseWriter, r *http.Request) {
	if s.emailPINAuth == nil {
		writeSuccessFalse(w, http.StatusServiceUnavailable, "Email PIN authentication not enabled")
		return
	}
	s.emailPINAuth.SendPINRequest(w, r)
}

// handleVerifyPIN handles /email-pin/verify POST requests
func (s *Server) handleVerifyPIN(w http.ResponseWriter, r *http.Request) {
	if s.emailPINAuth == nil {
		writeSuccessFalse(w, http.StatusServiceUnavailable, "Email PIN authentication not enabled")
		return
	}
	s.emailPINAuth.VerifyPINRequest(w, r)
}

// startLockout caps consecutive failed sign-ins per account, by every method that
// takes a guess.  A security key does not, and clears the count like any finished
// sign-in.
func (s *Server) startLockout(dbStore *db.DB) {
	duration := time.Duration(s.cfg.LockoutDuration) * time.Minute
	lockout, err := auth.NewLockout(dbStore.DB(), s.cfg.LockoutThreshold, duration)
	if err != nil {
		s.logger.Error(fmt.Sprintf("account lockout is off: %v", err))
		return
	}
	if lockout == nil {
		s.logger.Info("account lockout is off: account_lockout_threshold is 0")
		return
	}
	s.lockout = lockout
	lockout.OnLock(func(address string, until time.Time, failures int) {
		s.logger.Warn(fmt.Sprintf("account locked: %s after %d failed sign-ins in a row, until %s",
			address, failures, until.UTC().Format(time.RFC3339)))
		s.notifyAccountChange(address, fmt.Sprintf(
			"After %d failed sign-ins in a row, this account refuses passwords, PINs and codes until %s. "+
				"A security key still signs in, and recovering the password by mail ends the lock.",
			failures, until.UTC().Format("2006-01-02 15:04 MST")))
	})
	s.passwordAuth.SetLockout(lockout)
	if s.emailPINAuth != nil {
		s.emailPINAuth.SetLockout(lockout)
	}
	if s.webauthnHandler != nil {
		s.webauthnHandler.SetSignedIn(func(ctx context.Context, address string) {
			s.clearLockout(ctx, address)
		})
	}
}

// clearLockout forgets an account's failed sign-ins.
func (s *Server) clearLockout(ctx context.Context, address string) {
	if _, err := s.lockout.Clear(ctx, address); err != nil {
		s.logger.Error(fmt.Sprintf("clearing the failed sign-ins of %s: %v", address, err))
	}
}

// filesOnly serves the files under static_dir that a request names, and nothing
// about the directories: a directory is answered 404, never listed, and no
// index.html stands in for it.
type filesOnly struct{ fs http.FileSystem }

func (f filesOnly) Open(name string) (http.File, error) {
	file, err := f.fs.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if info.IsDir() {
		file.Close()
		return nil, fs.ErrNotExist
	}
	return file, nil
}
