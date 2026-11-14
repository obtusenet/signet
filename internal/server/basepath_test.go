// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/config"
)

// basePathServer is a whole instance under /auth, with every page switched on.
func basePathServer(t *testing.T) *Server {
	t.Helper()
	return registrationServer(t, func(c *config.Config) {
		c.BasePath = "/auth"
		c.StaticDir = "../../web/static"
		c.RPID = "signet.example"
		c.WebAuthnOrigins = []string{"https://signet.example"}
		c.AuthMethods = map[string]string{"password": "enabled", "email_pin": "enabled", "totp": "enabled", "webauthn": "enabled"}
	})
}

func basePathRequest(s *Server, method, target string, body url.Values, c *http.Cookie, headers ...string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, "https://signet.example"+target, strings.NewReader(body.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, "https://signet.example"+target, nil)
	}
	if c != nil {
		r.AddCookie(c)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	return w
}

func TestBasePathRoutes(t *testing.T) {
	s := basePathServer(t)
	for target, want := range map[string]int{
		"/auth/health":                http.StatusOK,
		"/auth/login":                 http.StatusOK,
		"/auth/recover":               http.StatusOK,
		"/auth/register":              http.StatusOK,
		"/auth/static/js/webauthn.js": http.StatusOK,
		"/auth/session":               http.StatusUnauthorized,
		"/auth":                       http.StatusFound, // the landing page, signed out
		"/login":                      http.StatusNotFound,
		"/health":                     http.StatusNotFound,
		"/static/js/webauthn.js":      http.StatusNotFound,
		"/authx/login":                http.StatusNotFound,
		"/other/auth/login":           http.StatusNotFound,
		"/auth/login/../../login":     http.StatusNotFound,
		"/auth//login":                http.StatusNotFound,
		"/auth/./login":               http.StatusNotFound,
		"/auth/webauthn/keys":         http.StatusOK,
		"/auth/api/v1/validate":       http.StatusMethodNotAllowed,
		"/auth/email-pin/verify":      http.StatusMethodNotAllowed,
	} {
		if w := basePathRequest(s, http.MethodGet, target, nil, nil); w.Code != want {
			t.Errorf("GET %s: %d, want %d", target, w.Code, want)
		}
	}
}

func TestBasePathRedirects(t *testing.T) {
	s := basePathServer(t)
	for target, want := range map[string]string{
		"/auth":         "/auth/login",
		"/auth/":        "/auth/login",
		"/auth/account": "/auth/login?referrer=%2Fauth%2Faccount",
		"/auth/logout":  "/auth/login",
	} {
		w := basePathRequest(s, http.MethodGet, target, nil, nil)
		if got := w.Header().Get("Location"); got != want {
			t.Errorf("GET %s: Location %q, want %q", target, got, want)
		}
	}

	// A sign-in with no return address goes to the account page, under the base.
	w := basePathRequest(s, http.MethodPost, "/auth/login", url.Values{"email": {recoveryUser}, "password": {recoveryOldPass}}, nil)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/auth/account" {
		t.Errorf("sign-in: %d to %q", w.Code, w.Header().Get("Location"))
	}
	// Nor does one that would come back to this login page.
	w = basePathRequest(s, http.MethodPost, "/auth/login", url.Values{"email": {recoveryUser}, "password": {recoveryOldPass}, "referrer": {"/auth/login"}}, nil)
	if w.Header().Get("Location") != "/auth/account" {
		t.Errorf("sign-in back to the login page: %q", w.Header().Get("Location"))
	}
	// Nor to the base's registration page, after registering.
	w = basePathRequest(s, http.MethodPost, "/auth/login", url.Values{"email": {recoveryUser}, "password": {recoveryOldPass}}, nil,
		"Referer", "https://signet.example/auth/register")
	if w.Header().Get("Location") != "/auth/account" {
		t.Errorf("sign-in back to the registration page: %q", w.Header().Get("Location"))
	}
	// A page of the same name outside the base is the site's, and is somewhere to go.
	w = basePathRequest(s, http.MethodPost, "/auth/login", url.Values{"email": {recoveryUser}, "password": {recoveryOldPass}, "referrer": {"/register"}}, nil)
	if w.Header().Get("Location") != "/register" {
		t.Errorf("sign-in to the site's /register: %q", w.Header().Get("Location"))
	}
	// Coming from this instance's own login page is not a return address.
	w = basePathRequest(s, http.MethodGet, "/auth/login", nil, nil, "Referer", "https://signet.example/auth/login?referrer=%2Fcomments%2F")
	if !strings.Contains(w.Body.String(), `name="referrer" value="/comments/"`) {
		t.Error("the referrer of the login page's own address was not taken")
	}
	w = basePathRequest(s, http.MethodGet, "/auth/login", nil, nil, "Referer", "https://signet.example/auth/login")
	if !strings.Contains(w.Body.String(), `name="referrer" value=""`) {
		t.Error("the login page itself was offered as the return address")
	}
}

// Every address a page names is under the base, or is not a path at all.
var pagePath = regexp.MustCompile(`(?:href|action|src)="(/[^"]*)"`)

func TestBasePathPages(t *testing.T) {
	s := basePathServer(t)
	c := signedIn(t, s, recoveryUser, "tok", 0)
	for target, cookie := range map[string]*http.Cookie{
		"/auth/login":         nil,
		"/auth/recover":       nil,
		"/auth/register":      nil,
		"/auth/account":       c,
		"/auth/webauthn/keys": nil,
		"/auth/":              c,
	} {
		w := basePathRequest(s, http.MethodGet, target, nil, cookie)
		if w.Code != http.StatusOK {
			t.Errorf("%s: %d", target, w.Code)
			continue
		}
		page := w.Body.String()
		for _, m := range pagePath.FindAllStringSubmatch(page, -1) {
			if !strings.HasPrefix(m[1], "/auth/") {
				t.Errorf("%s names %s", target, m[1])
			}
		}
		if strings.Contains(page, "<script>") && !strings.Contains(page, `const signetBase = "/auth";`) {
			t.Errorf("%s: its script does not know the base", target)
		}
		if strings.Contains(page, "webauthn.js") && !strings.Contains(page, `data-base-path="/auth"`) {
			t.Errorf("%s: webauthn.js is not told the base", target)
		}
	}

	// An old sign-in on the account page offers a way back under the base.
	old := signedIn(t, s, recoveryUser, "old", 2*reauthWindowForTest(s))
	page := basePathRequest(s, http.MethodGet, "/auth/account", nil, old).Body.String()
	if !strings.Contains(page, `href="/auth/login?referrer=%2fauth%2Faccount"`) {
		t.Error("the sign-in-again link is not under the base")
	}
}

func TestBasePathMailLinks(t *testing.T) {
	s := basePathServer(t)
	basePathRequest(s, http.MethodPost, "/auth/recover", url.Values{"email": {recoveryUser}}, nil)
	basePathRequest(s, http.MethodPost, "/auth/register", url.Values{"email": {newUser}}, nil)
	basePathRequest(s, http.MethodPost, "/auth/register", url.Values{"email": {recoveryUser}}, nil)
	mail := sentMail(t, s)
	if len(mail) != 3 {
		t.Fatalf("%d messages", len(mail))
	}
	for _, want := range []string{
		"https://signet.example/auth/recover#token=",
		"https://signet.example/auth/register#token=",
		"https://signet.example/auth/login",
	} {
		if !mailSays(t, s, want) {
			t.Errorf("no mail links to %s", want)
		}
	}
	for _, m := range mail {
		if strings.Contains(m.Body, "https://signet.example/recover") || strings.Contains(m.Body, "https://signet.example/register") {
			t.Errorf("a link is outside the base: %s", m.Body)
		}
	}
}

func TestBasePathChecks(t *testing.T) {
	for _, good := range []string{"", "/auth", "/comments-auth", "/a/b", "/x.y_z~1"} {
		if err := checkBasePathForTest(good); err != nil {
			t.Errorf("%q refused: %v", good, err)
		}
	}
	for _, bad := range []string{"auth", "/", "/auth/", "//auth", "/a//b", "/..", "/a/../b", "/a/./b", "/a%2fb", "/a?b", "/a#b", "/a b", "/ä"} {
		if err := checkBasePathForTest(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func checkBasePathForTest(p string) error {
	cfg := config.DefaultConfig()
	cfg.BasePath = p
	return config.Validate(cfg)
}

func reauthWindowForTest(s *Server) time.Duration {
	return time.Duration(s.cfg.AccountReauthWindow) * time.Second
}

// Only files are served from static_dir: a directory is not listed, with or
// without a trailing slash, and no index.html stands in for it.
func TestStaticServesFilesOnly(t *testing.T) {
	s := basePathServer(t)
	for target, want := range map[string]int{
		"/auth/static/js/webauthn.js": http.StatusOK,
		"/auth/static/":               http.StatusNotFound,
		"/auth/static/js/":            http.StatusNotFound,
		"/auth/static/js":             http.StatusNotFound,
		"/auth/static/nothing.js":     http.StatusNotFound,
	} {
		w := basePathRequest(s, http.MethodGet, target, nil, nil)
		if w.Code != want {
			t.Errorf("%s: %d, want %d", target, w.Code, want)
		}
		if strings.Contains(w.Body.String(), "webauthn.js") && w.Code != http.StatusOK {
			t.Errorf("%s: lists the directory", target)
		}
	}
}
