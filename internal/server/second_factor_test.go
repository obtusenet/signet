// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/obtusenet/signet/internal/config"
	"github.com/obtusenet/signet/internal/webauthn"
)

// requiredServer has second_factor required, with methods and every sign-in
// method on that they need.
func requiredServer(t *testing.T, methods ...string) *Server {
	t.Helper()
	return recoveryServer(t, func(c *config.Config) {
		c.SecondFactor = "required"
		c.SecondFactorMethods = methods
		c.AuthMethods = map[string]string{"password": "enabled", "email_pin": "enabled", "totp": "enabled", "webauthn": "enabled"}
		c.RPID = "signet.example"
		c.WebAuthnOrigins = []string{"https://signet.example"}
	})
}

// loginForm posts form to /login as a plain form.
func loginForm(s *Server, form url.Values, headers ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://signet.example/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	return w
}

func passwordForm() url.Values {
	return url.Values{"email": {recoveryUser}, "password": {recoveryOldPass}, "referrer": {"/next"}}
}

func hasSession(s *Server, w *httptest.ResponseRecorder) bool {
	return strings.Contains(w.Header().Get("Set-Cookie"), s.cfg.CookieName+"=")
}

var (
	enrolPending = regexp.MustCompile(`name="pending" value="([^"]+)">\s*<input type="hidden" name="referrer" value="[^"]*">\s*<input type="hidden" name="action" value="totp-begin">`)
	enrolKey     = regexp.MustCompile(`Key: <code>([A-Z2-7]+)</code>`)
)

// Optional is the default, and an account without an app signs in by password.
func TestSecondFactorOptionalChangesNothing(t *testing.T) {
	s := recoveryServer(t)
	if s.cfg.SecondFactor != "optional" && s.cfg.SecondFactor != "" {
		t.Fatalf("default %q", s.cfg.SecondFactor)
	}
	if w := loginForm(s, passwordForm()); w.Code != http.StatusFound || !hasSession(s, w) {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
}

// Required, an account with no second factor adds an app before the sign-in
// finishes, sees its recovery codes once, and then needs a code.
func TestSecondFactorRequiredEnrolsAnApp(t *testing.T) {
	s := requiredServer(t, "totp", "webauthn")

	w := loginForm(s, passwordForm())
	if w.Code != http.StatusOK || hasSession(s, w) {
		t.Fatalf("the password alone: %d, session %v", w.Code, hasSession(s, w))
	}
	if !strings.Contains(w.Body.String(), `value="key"`) {
		t.Error("no security key offered")
	}
	m := enrolPending.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("no enrolment step: %s", w.Body)
	}
	pending := m[1]

	// Going straight to a code does nothing: there is no app yet.
	if w := loginForm(s, url.Values{"pending": {pending}, "action": {"totp-finish"}, "code": {"000000"}}); hasSession(s, w) {
		t.Fatal("signed in without an app")
	}

	w = loginForm(s, url.Values{"pending": {pending}, "action": {"totp-begin"}})
	k := enrolKey.FindStringSubmatch(w.Body.String())
	if w.Code != http.StatusOK || k == nil || !strings.Contains(w.Body.String(), `src="data:image/png;base64,`) {
		t.Fatalf("begin: %d: %s", w.Code, w.Body)
	}
	if w := loginForm(s, url.Values{"pending": {pending}, "action": {"totp-finish"}, "code": {"000000"}}); w.Code != http.StatusUnauthorized || hasSession(s, w) {
		t.Errorf("a wrong code: %d", w.Code)
	}
	w = loginForm(s, url.Values{"pending": {pending}, "action": {"totp-finish"}, "code": {codeAt(t, k[1], time.Now())}, "referrer": {"/next"}})
	if w.Code != http.StatusOK || !hasSession(s, w) {
		t.Fatalf("finish: %d: %s", w.Code, w.Body)
	}
	if got := sessionMethod(t, s, w); got != "password+totp" {
		t.Errorf("method %q", got)
	}
	if !strings.Contains(w.Body.String(), "recovery codes") || !strings.Contains(w.Body.String(), `href="/next"`) {
		t.Errorf("no recovery codes or way on: %s", w.Body)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("recovery codes may be cached")
	}
	if !mailSays(t, s, "authenticator app was added") {
		t.Error("the owner was not told")
	}
	// The step is spent.
	if w := loginForm(s, url.Values{"pending": {pending}, "action": {"totp-begin"}}); enrolKey.MatchString(w.Body.String()) {
		t.Error("the step was used again")
	}

	// The next sign-in asks for a code.
	next := firstStep(t, s)
	if w := secondStep(s, next, nextCode(t, k[1])); w.Code != http.StatusFound {
		t.Errorf("code step: %d", w.Code)
	}
}

// JSON clients are told which step comes next.
func TestSecondFactorStepInJSON(t *testing.T) {
	s := requiredServer(t, "totp")
	w := loginForm(s, passwordForm(), "Accept", "application/json")
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["step"] != "enrol" || body["pending"] == "" || body["totp_required"] != false || hasSession(s, w) {
		t.Errorf("%d %v", w.Code, body)
	}
}

// With email_pin listed, a password is followed by a mailed PIN.
func TestSecondFactorMailedPIN(t *testing.T) {
	s := requiredServer(t, "email_pin")
	w := loginForm(s, passwordForm())
	if w.Code != http.StatusOK || hasSession(s, w) || !strings.Contains(w.Body.String(), "PIN from the message just sent to you") {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	pending := pendingField.FindStringSubmatch(w.Body.String())[1]
	mails := sentMail(t, s)
	if len(mails) == 0 {
		t.Fatal("no PIN mailed")
	}
	pin := regexp.MustCompile(`\b(\d{6})\b`).FindStringSubmatch(mails[len(mails)-1].Body)
	if pin == nil {
		t.Fatalf("no PIN in %q", mails[len(mails)-1].Body)
	}
	wrong := "000000"
	if pin[1] == wrong {
		wrong = "111111"
	}
	if w := secondStep(s, pending, wrong); w.Code != http.StatusUnauthorized || !pendingField.MatchString(w.Body.String()) {
		t.Errorf("a wrong PIN should keep the step: %d", w.Code)
	}
	w = secondStep(s, pending, pin[1])
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/next" {
		t.Fatalf("%d to %q: %s", w.Code, w.Header().Get("Location"), w.Body)
	}
	if got := sessionMethod(t, s, w); got != "password+email_pin" {
		t.Errorf("method %q", got)
	}
}

// An account whose second factor is a key signs in with the key, not a password.
func TestSecondFactorKeySignsInAlone(t *testing.T) {
	s := requiredServer(t, "totp", "webauthn")
	store, err := webauthn.NewStore(s.db.DB())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUser(context.Background(), &gowebauthn.Credential{ID: []byte("key-1"), PublicKey: []byte{1}}, recoveryUser, "key"); err != nil {
		t.Fatal(err)
	}
	w := loginForm(s, passwordForm())
	if w.Code != http.StatusForbidden || hasSession(s, w) || !strings.Contains(w.Body.String(), "security key") {
		t.Errorf("%d: %s", w.Code, w.Body)
	}
	if s.webauthnSvc == nil {
		t.Fatal("no key service")
	}
	opts, _, err := s.webauthnSvc.BeginLogin(context.Background(), recoveryUser)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Response.UserVerification != "required" {
		t.Errorf("user verification %q", opts.Response.UserVerification)
	}
}

// Adding a key goes through a one-time invite for that account.
func TestSecondFactorEnrolAKey(t *testing.T) {
	s := requiredServer(t, "webauthn")
	m := pendingField.FindStringSubmatch(loginForm(s, passwordForm()).Body.String())
	if m == nil {
		t.Fatal("no step")
	}
	w := loginForm(s, url.Values{"pending": {m[1]}, "action": {"key"}})
	location := w.Header().Get("Location")
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(location, "/webauthn/keys#invite=") {
		t.Fatalf("%d to %q", w.Code, location)
	}
	address, err := s.webauthnSvc.InviteEmail(context.Background(), strings.TrimPrefix(location, "/webauthn/keys#invite="))
	if err != nil || address != recoveryUser {
		t.Errorf("invite for %q: %v", address, err)
	}
	if strings.Contains(loginForm(s, url.Values{"pending": {m[1]}, "action": {"key"}}).Header().Get("Location"), "invite") {
		t.Error("the step made a second invite")
	}
}

// A PIN as the first step is not followed by another PIN.
func TestSecondFactorPINFirstEnrols(t *testing.T) {
	s := requiredServer(t, "totp", "email_pin")
	pending, step, err := s.secondStep(context.Background(), recoveryUser, "email_pin")
	if err != nil || pending == "" || step != "enrol" {
		t.Errorf("%q %q %v", pending, step, err)
	}
	pending, step, err = s.secondStep(context.Background(), recoveryUser, "password")
	if err != nil || pending == "" || step != "mail" {
		t.Errorf("%q %q %v", pending, step, err)
	}
}

// The last second factor stays.
func TestSecondFactorLastOneCannotBeRemoved(t *testing.T) {
	s := requiredServer(t, "totp")
	c := signedIn(t, s, recoveryUser, "tok", 0)
	enrollTOTP(t, s, c, "phone")
	keys, err := s.totp.ListKeys(context.Background(), recoveryUser)
	if err != nil || len(keys) != 1 {
		t.Fatalf("%d keys: %v", len(keys), err)
	}
	body, _ := json.Marshal(map[string]string{"action": "totp-remove", "id": keys[0].ID})
	if w := accountPost(s, c, string(body)); w.Code != http.StatusConflict {
		t.Errorf("removing the last: %d: %s", w.Code, w.Body)
	}

	optional := totpServer(t)
	c = signedIn(t, optional, recoveryUser, "tok", 0)
	enrollTOTP(t, optional, c, "phone")
	keys, _ = optional.totp.ListKeys(context.Background(), recoveryUser)
	body, _ = json.Marshal(map[string]string{"action": "totp-remove", "id": keys[0].ID})
	if w := accountPost(optional, c, string(body)); w.Code != http.StatusOK {
		t.Errorf("optional: %d: %s", w.Code, w.Body)
	}
}

func TestSecondFactorSettings(t *testing.T) {
	for _, tc := range []struct {
		factor  string
		methods []string
		enabled map[string]string
		ok      bool
	}{
		{"optional", []string{"totp", "webauthn"}, nil, true},
		{"required", []string{"totp"}, map[string]string{"totp": "enabled"}, true},
		{"required", []string{"totp"}, map[string]string{"totp": "disabled"}, false},
		{"required", nil, nil, false},
		{"required", []string{"sms"}, nil, false},
		{"required", []string{"totp", "totp"}, map[string]string{"totp": "enabled"}, false},
		{"sometimes", nil, nil, false},
	} {
		cfg := config.DefaultConfig()
		cfg.SecondFactor = tc.factor
		cfg.SecondFactorMethods = tc.methods
		for k, v := range tc.enabled {
			cfg.AuthMethods[k] = v
		}
		if err := config.Validate(cfg); (err == nil) != tc.ok {
			t.Errorf("%s %v %v: %v", tc.factor, tc.methods, tc.enabled, err)
		}
	}
}
