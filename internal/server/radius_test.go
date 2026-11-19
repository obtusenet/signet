// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/config"
	"github.com/obtusenet/signet/internal/radius"
	"github.com/obtusenet/signet/internal/session"
)

const radiusSecret = "testing123"

// fakeRadius is a RADIUS server on loopback that knows:
//   - jdoe / radius-pw, in the groups wiki-admins and staff;
//   - otp-user / radius-pw, then a challenge answered with 123456.
type fakeRadius struct {
	conn  *net.UDPConn
	asked atomic.Int32
	names chan string
}

func newFakeRadius(t *testing.T) *fakeRadius {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRadius{conn: c, names: make(chan string, 64)}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			f.asked.Add(1)
			req, err := radius.CheckRequest(buf[:n], []byte(radiusSecret))
			if err != nil {
				continue
			}
			user, _ := req.Get(radius.AttrUserName)
			select {
			case f.names <- string(user):
			default:
			}
			pw, _ := radius.RecoverPassword(req, []byte(radiusSecret))
			state, challenged := req.Get(radius.AttrState)
			code := byte(radius.CodeAccessReject)
			var attrs []radius.Attribute
			switch {
			case string(user) == "jdoe" && pw == "radius-pw":
				code = radius.CodeAccessAccept
				attrs = []radius.Attribute{
					{Type: radius.AttrFilterID, Value: []byte("wiki-admins")},
					{Type: radius.AttrFilterID, Value: []byte("staff")},
				}
			case string(user) == "timed" && pw == "radius-pw":
				code = radius.CodeAccessAccept
				attrs = []radius.Attribute{
					{Type: radius.AttrSessionTimeout, Value: radius.Uint32(600)},
					{Type: radius.AttrIdleTimeout, Value: radius.Uint32(120)},
				}
			case string(user) == "long" && pw == "radius-pw":
				code = radius.CodeAccessAccept
				attrs = []radius.Attribute{
					{Type: radius.AttrSessionTimeout, Value: radius.Uint32(999999)},
					{Type: radius.AttrIdleTimeout, Value: radius.Uint32(999999)},
				}
			case string(user) == "otp-user" && !challenged && pw == "radius-pw":
				code = radius.CodeAccessChallenge
				attrs = []radius.Attribute{
					{Type: radius.AttrReplyMessage, Value: []byte("Enter the code from your token")},
					{Type: radius.AttrState, Value: []byte("round-1")},
				}
			case string(user) == "otp-user" && challenged && string(state) == "round-1" && pw == "123456":
				code = radius.CodeAccessAccept
				attrs = []radius.Attribute{{Type: radius.AttrFilterID, Value: []byte("tokens")}}
			}
			out, err := radius.Reply(req, code, attrs, []byte(radiusSecret), true)
			if err == nil {
				c.WriteToUDP(out, addr)
			}
		}
	}()
	return f
}

func (f *fakeRadius) addr() string { return f.conn.LocalAddr().String() }

// radiusServer is recoveryServer (a local user@example.com) with RADIUS on.
func radiusServer(t *testing.T, address string, change ...func(*config.Config)) *Server {
	t.Helper()
	return recoveryServer(t, append([]func(*config.Config){func(c *config.Config) {
		c.Radius = config.RadiusConfig{
			Enabled:                     true,
			NASIdentifier:               "wiki",
			Servers:                     []config.RadiusServerConfig{{Address: address, Secret: radiusSecret, Auth: "pap"}},
			TimeoutSec:                  1,
			Retries:                     0,
			GroupAttributes:             []string{"Filter-Id"},
			RequireMessageAuthenticator: true,
		}
	}}, change...)...)
}

func radiusLogin(s *Server, user, password string, headers ...string) *httptest.ResponseRecorder {
	return loginForm(s, url.Values{"email": {user}, "password": {password}, "referrer": {"/next"}}, headers...)
}

// sessionJSON asks /session with the cookie w set.
func sessionJSON(t *testing.T, s *Server, w *httptest.ResponseRecorder, query string) (map[string]interface{}, http.Header) {
	t.Helper()
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == s.cfg.CookieName && c.Value != "" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatalf("no session cookie: %d: %s", w.Code, w.Body)
	}
	r := httptest.NewRequest(http.MethodGet, "https://signet.example/session"+query, nil)
	r.AddCookie(cookie)
	rw := httptest.NewRecorder()
	s.handler().ServeHTTP(rw, r)
	var body map[string]interface{}
	if err := json.Unmarshal(rw.Body.Bytes(), &body); err != nil {
		t.Fatalf("%d: %s", rw.Code, rw.Body)
	}
	return body, rw.Header()
}

func TestRadiusSignIn(t *testing.T) {
	f := newFakeRadius(t)
	s := radiusServer(t, f.addr())
	w := radiusLogin(s, "jdoe", "radius-pw")
	if w.Code != http.StatusFound || !hasSession(s, w) {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if got := <-f.names; got != "jdoe" {
		t.Errorf("User-Name %q", got)
	}
	body, h := sessionJSON(t, s, w, "")
	if body["user"] != "jdoe" || body["email"] != "" || body["method"] != "radius" {
		t.Errorf("session: %v", body)
	}
	if h.Get("Remote-User") != "jdoe" || h.Get("Remote-Email") != "" {
		t.Errorf("headers: user %q, email %q", h.Get("Remote-User"), h.Get("Remote-Email"))
	}
	claims, _ := body["claims"].(map[string]interface{})
	groups, _ := claims["groups"].([]interface{})
	if len(groups) != 2 || groups[0] != "wiki-admins" || groups[1] != "staff" {
		t.Errorf("claims: %v", body["claims"])
	}
}

func TestRadiusWrongPassword(t *testing.T) {
	f := newFakeRadius(t)
	s := radiusServer(t, f.addr())
	w := radiusLogin(s, "jdoe", "wrong", "Accept", "application/json")
	if w.Code != http.StatusUnauthorized || hasSession(s, w) {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
}

// An address users.csv has never goes to RADIUS, right password or wrong.
func TestLocalAccountsNeverReachRadius(t *testing.T) {
	f := newFakeRadius(t)
	s := radiusServer(t, f.addr())
	if w := radiusLogin(s, recoveryUser, recoveryOldPass); w.Code != http.StatusFound {
		t.Fatalf("right password: %d: %s", w.Code, w.Body)
	}
	if w := radiusLogin(s, recoveryUser, "wrong"); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", w.Code)
	}
	if n := f.asked.Load(); n != 0 {
		t.Errorf("RADIUS was asked %d times about a local account", n)
	}
}

func TestRadiusUnavailableFailsClosed(t *testing.T) {
	// A port nobody answers on.
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	s := radiusServer(t, c.LocalAddr().String())
	w := radiusLogin(s, "jdoe", "radius-pw", "Accept", "application/json")
	if w.Code != http.StatusServiceUnavailable || hasSession(s, w) {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), radiusUnavailableMessage) {
		t.Errorf("body: %s", w.Body)
	}
}

func TestRadiusChallenge(t *testing.T) {
	f := newFakeRadius(t)
	s := radiusServer(t, f.addr())

	w := radiusLogin(s, "otp-user", "radius-pw", "Accept", "application/json")
	var step struct {
		Step, Pending, Message string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &step); err != nil || step.Step != "radius" || step.Pending == "" {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if step.Message != "Enter the code from your token" {
		t.Errorf("message %q", step.Message)
	}

	// The page asks with the server's prompt.
	w = radiusLogin(s, "otp-user", "radius-pw")
	if !strings.Contains(w.Body.String(), "Enter the code from your token") {
		t.Errorf("the page does not show the prompt: %s", w.Body)
	}

	// A wrong answer ends the sign-in, and the step is spent.
	if w := secondStep(s, step.Pending, "000000"); w.Code != http.StatusUnauthorized || hasSession(s, w) {
		t.Fatalf("wrong answer: %d", w.Code)
	}
	if w := secondStep(s, step.Pending, "123456"); hasSession(s, w) {
		t.Fatal("a spent step signed in")
	}

	match := pendingField.FindStringSubmatch(radiusLogin(s, "otp-user", "radius-pw").Body.String())
	if match == nil {
		t.Fatal("no step")
	}
	w = secondStep(s, match[1], "123456")
	if w.Code != http.StatusFound || !hasSession(s, w) {
		t.Fatalf("right answer: %d: %s", w.Code, w.Body)
	}
	body, _ := sessionJSON(t, s, w, "")
	if body["user"] != "otp-user" || !strings.Contains(mustJSON(body["claims"]), "tokens") {
		t.Errorf("session: %v", body)
	}
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Without RADIUS a name that is not an address is no account, and is not
// looked up anywhere.
func TestNamesNeedRadius(t *testing.T) {
	s := recoveryServer(t)
	if w := radiusLogin(s, "jdoe", "radius-pw"); w.Code != http.StatusUnauthorized {
		t.Fatalf("%d", w.Code)
	}
	if strings.Contains(renderLogin(t, s), `autocomplete="username"`) {
		t.Error("the login page asks for user names without RADIUS")
	}
	f := newFakeRadius(t)
	if !strings.Contains(renderLogin(t, radiusServer(t, f.addr())), `autocomplete="username"`) {
		t.Error("the login page does not take user names with RADIUS")
	}
}

func renderLogin(t *testing.T, s *Server) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://signet.example/login", nil))
	return w.Body.String()
}

// An authenticator app follows the RADIUS password, and the groups survive the
// step.
func TestRadiusThenCode(t *testing.T) {
	f := newFakeRadius(t)
	s := radiusServer(t, f.addr(), func(c *config.Config) {
		c.AuthMethods = map[string]string{"password": "enabled", "totp": "enabled"}
	})
	w := radiusLogin(s, "jdoe", "radius-pw")
	if !hasSession(s, w) {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	secret, _ := enrollTOTP(t, s, sessionCookie(t, s, w), "phone")

	match := pendingField.FindStringSubmatch(radiusLogin(s, "jdoe", "radius-pw").Body.String())
	if match == nil {
		t.Fatal("no code step after the RADIUS password")
	}
	w = secondStep(s, match[1], nextCode(t, secret))
	if w.Code != http.StatusFound || !hasSession(s, w) {
		t.Fatalf("code: %d: %s", w.Code, w.Body)
	}
	body, _ := sessionJSON(t, s, w, "")
	if body["method"] != "radius+totp" || !strings.Contains(mustJSON(body["claims"]), "wiki-admins") {
		t.Errorf("session: %v", body)
	}
}

func sessionCookie(t *testing.T, s *Server, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == s.cfg.CookieName && c.Value != "" {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

// Required second factor: a RADIUS account adds an app, never a key.
func TestRadiusRequiredSecondFactorOffersOnlyAnApp(t *testing.T) {
	f := newFakeRadius(t)
	s := radiusServer(t, f.addr(), func(c *config.Config) {
		c.SecondFactor = "required"
		c.SecondFactorMethods = []string{"totp", "webauthn", "email_pin"}
		c.AuthMethods = map[string]string{"password": "enabled", "email_pin": "enabled", "totp": "enabled", "webauthn": "enabled"}
		c.RPID = "signet.example"
		c.WebAuthnOrigins = []string{"https://signet.example"}
	})
	w := radiusLogin(s, "jdoe", "radius-pw")
	if hasSession(s, w) || w.Code != http.StatusOK {
		t.Fatalf("%d, session %v", w.Code, hasSession(s, w))
	}
	page := w.Body.String()
	if !strings.Contains(page, `value="totp-begin"`) || strings.Contains(page, `value="key"`) {
		t.Errorf("enrol step offers: %s", page)
	}
	if len(sentMail(t, s)) != 0 {
		t.Error("a PIN was mailed to a RADIUS account")
	}
	match := pendingField.FindStringSubmatch(page)
	if match == nil {
		t.Fatal("no step")
	}
	form := url.Values{"pending": {match[1]}, "action": {"key"}}
	if w := loginForm(s, form); w.Code != http.StatusForbidden {
		t.Errorf("key at the enrol step: %d", w.Code)
	}
}

// The claims hook sees where the account came from and what the server said.
func TestRadiusFactsReachTheHook(t *testing.T) {
	f := newFakeRadius(t)
	dir := t.TempDir()
	got := filepath.Join(dir, "request")
	hook := filepath.Join(dir, "hook.sh")
	body := "#!/bin/sh\ncat > '" + got + "'\necho '{\"type\":\"claim_response\",\"claims\":{\"role\":\"editor\"}}'\n"
	if err := os.WriteFile(hook, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	s := radiusServer(t, f.addr(), func(c *config.Config) {
		c.ClaimsHook = config.ClaimsHookConfig{Enabled: true, Program: hook, TimeoutSec: 5, OnFailure: "fail-closed", RefreshRateLimit: 6, RefreshRateWindow: 60}
	})
	w := radiusLogin(s, "jdoe", "radius-pw")
	if !hasSession(s, w) {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	read, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	var req map[string]interface{}
	if err := json.Unmarshal(read, &req); err != nil {
		t.Fatalf("%s: %v", read, err)
	}
	r, _ := req["radius"].(map[string]interface{})
	if req["source"] != "radius" || req["email"] != "jdoe" || r["nas_identifier"] != "wiki" ||
		mustJSON(r["groups"]) != `["wiki-admins","staff"]` || !strings.Contains(mustJSON(r["attributes"]), `"name":"Filter-Id"`) {
		t.Errorf("hook read %s", read)
	}
	sess, _ := sessionJSON(t, s, w, "")
	if mustJSON(sess["claims"]) != `{"role":"editor"}` {
		t.Errorf("claims %v", sess["claims"])
	}

	// A refresh gives the hook the reply stored at sign-in.
	os.Remove(got)
	sessionJSON(t, s, w, "?claims=refresh")
	again, err := os.ReadFile(got)
	if err != nil || string(again) != string(read) {
		t.Errorf("refresh request %s, %v", again, err)
	}
}

// Without a hook a refresh keeps the groups.
func TestRadiusRefreshKeepsGroups(t *testing.T) {
	f := newFakeRadius(t)
	s := radiusServer(t, f.addr())
	w := radiusLogin(s, "jdoe", "radius-pw")
	body, _ := sessionJSON(t, s, w, "?claims=refresh")
	if !strings.Contains(mustJSON(body["claims"]), "wiki-admins") {
		t.Errorf("claims %v", body["claims"])
	}
}

func TestRadiusAccountPage(t *testing.T) {
	f := newFakeRadius(t)
	s := radiusServer(t, f.addr(), func(c *config.Config) {
		c.AuthMethods = map[string]string{"password": "enabled", "totp": "enabled"}
	})
	w := radiusLogin(s, "jdoe", "radius-pw")
	r := httptest.NewRequest(http.MethodGet, "https://signet.example/account", nil)
	r.AddCookie(sessionCookie(t, s, w))
	rw := httptest.NewRecorder()
	s.handler().ServeHTTP(rw, r)
	page := rw.Body.String()
	if rw.Code != http.StatusOK || !strings.Contains(page, "RADIUS") || strings.Contains(page, `id="current-password"`) {
		t.Errorf("%d: %s", rw.Code, page)
	}
	body, _ := json.Marshal(map[string]string{"action": "password", "current": "x", "new": "a-new-password-1"})
	if w := accountPost(s, sessionCookie(t, s, w), string(body)); w.Code != http.StatusForbidden {
		t.Errorf("password change: %d: %s", w.Code, w.Body)
	}
}

// A server whose secret cannot be read refuses RADIUS sign-ins rather than
// treating the names as unknown.  LoadConfig refuses such a file; this is the
// guard behind it.
func TestRadiusBrokenSourceFailsClosed(t *testing.T) {
	s := radiusServer(t, "127.0.0.1:1812", func(c *config.Config) {
		c.Radius.Servers[0].Secret = ""
		c.Radius.Servers[0].SecretFile = filepath.Join(t.TempDir(), "missing")
	})
	w := radiusLogin(s, "jdoe", "radius-pw", "Accept", "application/json")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
}

// storedSession reads the session w's cookie names.
func storedSession(t *testing.T, s *Server, w *httptest.ResponseRecorder) *session.Session {
	t.Helper()
	token, err := s.cookieMgr.ValidateCookieValue(sessionCookie(t, s, w).Value)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := s.sessionStore.Get(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

// Session-Timeout and Idle-Timeout set the session's lifetime, the cookie's
// Max-Age and the idle limit.
func TestRadiusTimeouts(t *testing.T) {
	f := newFakeRadius(t)
	s := radiusServer(t, f.addr())
	w := radiusLogin(s, "timed", "radius-pw")
	if c := sessionCookie(t, s, w); c.MaxAge != 600 {
		t.Errorf("cookie Max-Age %d, want 600", c.MaxAge)
	}
	sess := storedSession(t, s, w)
	if sess.IdleTimeout != 120 {
		t.Errorf("idle %d, want 120", sess.IdleTimeout)
	}
	if left := time.Until(sess.ExpiresAt); left < 590*time.Second || left > 600*time.Second {
		t.Errorf("expires in %v, want 600s", left)
	}

	// No timeouts: Signet's own.
	w = radiusLogin(s, "jdoe", "radius-pw")
	if c := sessionCookie(t, s, w); c.MaxAge != s.cfg.CookieMaxAge {
		t.Errorf("cookie Max-Age %d, want cookie_max_age %d", c.MaxAge, s.cfg.CookieMaxAge)
	}
	if sess := storedSession(t, s, w); sess.IdleTimeout != 0 {
		t.Errorf("idle %d, want the store's", sess.IdleTimeout)
	}
}

// Unless the ceilings are raised, a server can only shorten a session.
func TestRadiusTimeoutCeilings(t *testing.T) {
	f := newFakeRadius(t)
	s := radiusServer(t, f.addr(), func(c *config.Config) {
		c.CookieMaxAge = 3600
		c.SessionIdleTimeout = 900
	})
	w := radiusLogin(s, "long", "radius-pw")
	if c := sessionCookie(t, s, w); c.MaxAge != 3600 {
		t.Errorf("cookie Max-Age %d, want cookie_max_age 3600", c.MaxAge)
	}
	if sess := storedSession(t, s, w); sess.IdleTimeout != 900 {
		t.Errorf("idle %d, want session_idle_timeout 900", sess.IdleTimeout)
	}

	s = radiusServer(t, f.addr(), func(c *config.Config) {
		c.CookieMaxAge = 3600
		c.Radius.MaxSessionTimeout = 2000000
		c.Radius.MaxIdleTimeout = 5000
	})
	w = radiusLogin(s, "long", "radius-pw")
	if c := sessionCookie(t, s, w); c.MaxAge != 999999 {
		t.Errorf("cookie Max-Age %d, want 999999", c.MaxAge)
	}
	if sess := storedSession(t, s, w); sess.IdleTimeout != 5000 {
		t.Errorf("idle %d, want the 5000 ceiling", sess.IdleTimeout)
	}
}

// session_idle_timeout ends a quiet session of any account.
func TestSessionIdleTimeout(t *testing.T) {
	s := recoveryServer(t, func(c *config.Config) { c.SessionIdleTimeout = 60 })
	w := loginForm(s, passwordForm())
	token, err := s.cookieMgr.ValidateCookieValue(sessionCookie(t, s, w).Value)
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := sessionJSON(t, s, w, ""); body["valid"] != true {
		t.Fatalf("fresh: %v", body)
	}
	if _, err := s.db.DB().Exec(`UPDATE sessions SET last_seen_unix = ? WHERE token = ?`,
		time.Now().Add(-2*time.Minute).Unix(), session.HashToken(token)); err != nil {
		t.Fatal(err)
	}
	if body, _ := sessionJSON(t, s, w, ""); body["valid"] != false || body["error"] != "session expired" {
		t.Errorf("idle two minutes: %v", body)
	}
}
