// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/obtusenet/signet/internal/config"
)

// repositoryTemplates parses the templates that ship with the project, so the
// tests exercise the real files rather than copies.
func repositoryTemplates(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := loadTemplates("../../web/templates", "")
	if err != nil {
		t.Fatalf("parsing repository templates: %v", err)
	}
	return tmpl
}

func TestLoginTemplateRendersWithMethodFlags(t *testing.T) {
	tmpl := repositoryTemplates(t)

	cases := []struct {
		name string
		data map[string]interface{}
		want []string
		deny []string
	}{
		{
			name: "all methods",
			data: map[string]interface{}{
				"PasswordEnabled": true, "WebAuthnEnabled": true,
				"EmailPINEnabled": true, "TOTPEnabled": true,
				"YubikeyEnabled": true, "AllowRegistration": true,
				"Referrer":             "/dashboard",
				"AllowedRedirectHosts": template.JS(`["app.example.test"]`),
			},
			want: []string{"login-form", "webauthn-button", "email-pin-form",
				`value="/dashboard"`, "/register"},
		},
		{
			name: "password only",
			data: map[string]interface{}{
				"PasswordEnabled": true, "WebAuthnEnabled": false,
				"EmailPINEnabled": false, "AllowRegistration": false,
				"AllowedRedirectHosts": template.JS("[]"),
			},
			want: []string{`<form id="login-form">`},
			deny: []string{`<button id="webauthn-button"`, `<form id="email-pin-form">`, "/register"},
		},
		{
			name: "email pin only",
			data: map[string]interface{}{
				"PasswordEnabled": false, "WebAuthnEnabled": false,
				"EmailPINEnabled":      true,
				"AllowedRedirectHosts": template.JS("[]"),
			},
			want: []string{`<form id="email-pin-form">`},
			deny: []string{`<form id="login-form">`, `<button id="webauthn-button"`},
		},
	}

	for _, tc := range cases {
		var buf strings.Builder
		if err := tmpl.ExecuteTemplate(&buf, "login", tc.data); err != nil {
			t.Fatalf("%s: executing login template: %v", tc.name, err)
		}
		out := buf.String()
		for _, want := range tc.want {
			if !strings.Contains(out, want) {
				t.Errorf("%s: rendered page lacks %q", tc.name, want)
			}
		}
		for _, deny := range tc.deny {
			if strings.Contains(out, deny) {
				t.Errorf("%s: rendered page should not contain %q", tc.name, deny)
			}
		}
	}
}

func TestSafeReturnPath(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("POST", "http://signet.example/login", nil)
	r.Host = "signet.example"

	cases := map[string]string{
		"":                                    "",
		"/dashboard":                          "/dashboard",
		"/app?tab=1":                          "/app?tab=1",
		"https://signet.example/app":          "/app",
		"https://evil.example/app":            "",
		"//evil.example/app":                  "",
		"javascript:alert(1)":                 "",
		"ftp://signet.example/file":           "",
		"https://signet.example.evil.example": "",
	}
	for in, want := range cases {
		if got := s.safeReturnPath(in, r); got != want {
			t.Errorf("safeReturnPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoginRedirectPrecedence(t *testing.T) {
	s := &Server{}

	// 1. posted field
	r := httptest.NewRequest("POST", "http://signet.example/login?referrer=/from-query", strings.NewReader("referrer=%2Ffrom-form"))
	r.Host = "signet.example"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Referer", "http://signet.example/from-header")
	if got := s.loginRedirect(r); got != "/from-form" {
		t.Errorf("form referrer: got %q", got)
	}

	// 2. query parameter
	r = httptest.NewRequest("POST", "http://signet.example/login?referrer=/from-query", nil)
	r.Host = "signet.example"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if got := s.loginRedirect(r); got != "/from-query" {
		t.Errorf("query referrer: got %q", got)
	}

	// 3. Referer header
	r = httptest.NewRequest("POST", "http://signet.example/login", nil)
	r.Host = "signet.example"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Referer", "http://signet.example/settings?x=1")
	if got := s.loginRedirect(r); got != "/settings?x=1" {
		t.Errorf("Referer header: got %q", got)
	}

	// 4. a login page Referer carrying its own ?referrer=
	r = httptest.NewRequest("POST", "http://signet.example/login", nil)
	r.Host = "signet.example"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Referer", "http://signet.example/login?referrer=%2Fdeep")
	if got := s.loginRedirect(r); got != "/deep" {
		t.Errorf("Referer referrer: got %q", got)
	}

	// 5. nothing usable -> the account page
	r = httptest.NewRequest("POST", "http://signet.example/login", nil)
	r.Host = "signet.example"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Referer", "https://evil.example/steal")
	if got := s.loginRedirect(r); got != "/account" {
		t.Errorf("fallback: got %q", got)
	}

	// 6. a Referer pointing at the login page must not loop
	r = httptest.NewRequest("POST", "http://signet.example/login", nil)
	r.Host = "signet.example"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Referer", "http://signet.example/login")
	if got := s.loginRedirect(r); got != "/account" {
		t.Errorf("login page Referer: got %q, want /account", got)
	}

	// 7. nor at the other pages for getting in or out: back to /register after
	// registering is confusing, and to /logout signs the person out again.
	for _, page := range []string{"/register", "/recover", "/logout", "/register?x=1"} {
		r = httptest.NewRequest("POST", "http://signet.example/login", nil)
		r.Host = "signet.example"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Referer", "http://signet.example"+page)
		if got := s.loginRedirect(r); got != "/account" {
			t.Errorf("%s Referer: got %q, want /account", page, got)
		}
		if got := s.loginReferrer(r); got != "" {
			t.Errorf("%s Referer offered to the page: %q", page, got)
		}
		r = httptest.NewRequest("GET", "http://signet.example/login?referrer="+url.QueryEscape(page), nil)
		r.Host = "signet.example"
		if got := s.loginReferrer(r); got != "" {
			t.Errorf("?referrer=%s offered to the page: %q", page, got)
		}
	}
	// A page of that name on another, allowed host is that application's own.
	s.cfg = &config.Config{AllowedRedirectHosts: []string{"app.example.net"}}
	r = httptest.NewRequest("POST", "http://signet.example/login", nil)
	r.Host = "signet.example"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Referer", "https://app.example.net/register")
	if got := s.loginRedirect(r); got != "https://app.example.net/register" {
		t.Errorf("another application's /register: got %q", got)
	}
}

func TestSafeReturnPathAllowedHosts(t *testing.T) {
	s := &Server{cfg: &config.Config{
		AllowedRedirectHosts: []string{"app.example.test", "vpn.example.test:8443"},
	}}
	r := httptest.NewRequest("POST", "http://signet.example/login", nil)
	r.Host = "signet.example"

	cases := map[string]string{
		"https://app.example.test/protected?x=1": "https://app.example.test/protected?x=1",
		"http://app.example.test/":               "http://app.example.test/",
		"https://app.example.test:8443/x":        "", // portless entry: default port only
		"https://vpn.example.test:8443/x":        "https://vpn.example.test:8443/x",
		"https://vpn.example.test/x":             "", // ported entry: that port only
		"https://APP.Example.TEST/Up":            "https://APP.Example.TEST/Up",
		"//app.example.test/x":                   "",
		"https://app.example.test.evil.test/x":   "",
		"ftp://app.example.test/file":            "",
	}
	for in, want := range cases {
		if got := s.safeReturnPath(in, r); got != want {
			t.Errorf("safeReturnPath(%q) = %q, want %q", in, got, want)
		}
	}

	// Without a configuration the cross-host target is refused again.
	bare := &Server{}
	if got := bare.safeReturnPath("https://app.example.test/x", r); got != "" {
		t.Errorf("no config: got %q, want \"\"", got)
	}

	// Plain IP addresses are valid entries, with or without a port.
	ipS := &Server{cfg: &config.Config{
		AllowedRedirectHosts: []string{"10.0.0.50", "10.0.0.60:9443"},
	}}
	ipCases := map[string]string{
		"https://10.0.0.50/":       "https://10.0.0.50/",
		"http://10.0.0.50/x?y=1":   "http://10.0.0.50/x?y=1",
		"https://10.0.0.50:8443/x": "", // portless entry: default port only
		"https://10.0.0.60:9443/x": "https://10.0.0.60:9443/x",
		"https://10.0.0.60/x":      "", // ported entry: that port only
		"https://10.0.0.501/x":     "", // prefix must not match
	}
	for in, want := range ipCases {
		if got := ipS.safeReturnPath(in, r); got != want {
			t.Errorf("ip safeReturnPath(%q) = %q, want %q", in, got, want)
		}
	}

	// IPv6 entries: bare minified addresses, bracketed with a port, and
	// canonicalisation between full and minified spellings in both the
	// entry and the URL.
	v6S := &Server{cfg: &config.Config{
		AllowedRedirectHosts: []string{"fd00::5", "[fd12:3456:789a::1]:9443"},
	}}
	v6Cases := map[string]string{
		"http://[fd00::5]/x":                       "http://[fd00::5]/x",
		"http://[fd00:0:0:0:0:0:0:5]/x":            "http://[fd00:0:0:0:0:0:0:5]/x", // full URL vs minified entry
		"https://[fd00::5]:8443/x":                 "",                              // portless entry: default port only
		"https://[fd12:3456:789a::1]:9443/x":       "https://[fd12:3456:789a::1]:9443/x",
		"http://[fd12:3456:789a:0:0:0:0:1]:9443/x": "http://[fd12:3456:789a:0:0:0:0:1]:9443/x", // full URL, ported entry
		"https://[fd12:3456:789a::1]/x":            "",                                         // ported entry: that port only
	}
	for in, want := range v6Cases {
		if got := v6S.safeReturnPath(in, r); got != want {
			t.Errorf("ipv6 safeReturnPath(%q) = %q, want %q", in, got, want)
		}
	}

	// Malformed entries never match anything.
	badS := &Server{cfg: &config.Config{AllowedRedirectHosts: []string{"[oops", "[fd00::5]junk", ""}}}
	for _, in := range []string{"http://[fd00::5]/", "https://oops/"} {
		if got := badS.safeReturnPath(in, r); got != "" {
			t.Errorf("malformed entry: safeReturnPath(%q) = %q, want \"\"", in, got)
		}
	}

	// An IPv6 entry must not match an IPv4 or a hostname.
	if got := v6S.safeReturnPath("https://10.0.0.50/", r); got != "" {
		t.Errorf("v6 entry vs v4 url: got %q, want \"\"", got)
	}
	if got := v6S.safeReturnPath("https://fd00.example/", r); got != "" {
		t.Errorf("v6 entry vs hostname: got %q, want \"\"", got)
	}
}

func TestLoginRedirectAllowedHost(t *testing.T) {
	s := &Server{cfg: &config.Config{AllowedRedirectHosts: []string{"app.example.test"}}}
	r := httptest.NewRequest("POST", "http://signet.example/login", nil)
	r.Host = "signet.example"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Referer", "https://app.example.test/protected")
	if got := s.loginRedirect(r); got != "https://app.example.test/protected" {
		t.Errorf("allowed cross-host: got %q", got)
	}

	// Not on the list -> the fallback still applies.
	s2 := &Server{}
	if got := s2.loginRedirect(r); got != "/account" {
		t.Errorf("unlisted cross-host: got %q, want /account", got)
	}
}

func recoverTestServer(t *testing.T, recovery string) *Server {
	t.Helper()
	return recoveryServer(t, func(c *config.Config) { c.PasswordRecovery = recovery })
}

func TestRecoverPageRenders(t *testing.T) {
	s := recoverTestServer(t, "enabled")
	w := httptest.NewRecorder()
	s.handleRecover(w, httptest.NewRequest("GET", "/recover", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
	body := w.Body.String()
	for _, want := range []string{"Password Recovery", `action="/recover"`, "Send Recovery Link"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

func TestRecoverDisabledSaysSo(t *testing.T) {
	s := recoverTestServer(t, "disabled")
	w := httptest.NewRecorder()
	s.handleRecover(w, httptest.NewRequest("GET", "/recover", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "not available") {
		t.Error("disabled page does not say recovery is unavailable")
	}
	if strings.Contains(body, `action="/recover"`) {
		t.Error("disabled page still shows the form")
	}
}

func TestRecoverPostStates(t *testing.T) {
	// disabled -> 403, page with an error
	s := recoverTestServer(t, "disabled")
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/recover", strings.NewReader("email=a@b.c"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleRecover(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("disabled POST status = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "disabled") {
		t.Errorf("disabled POST body = %q", w.Body.String())
	}

	// enabled, empty address -> 400
	s = recoverTestServer(t, "enabled")
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/recover", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleRecover(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty POST status = %d, want 400", w.Code)
	}
}

func TestRecoverRejectsOtherMethods(t *testing.T) {
	s := recoverTestServer(t, "enabled")
	w := httptest.NewRecorder()
	s.handleRecover(w, httptest.NewRequest("DELETE", "/recover", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestReferrerParam(t *testing.T) {
	for _, tc := range []struct{ query, want string }{
		{"", ""},
		{"other=1", ""},
		{"notreferrer=/a", ""},
		{"referrer=", ""},
		// Encoded, as a client should send it: an ordinary query parameter.
		{"referrer=%2Fdeep", "/deep"},
		{"referrer=%2Fa&other=1", "/a"},
		{"other=1&referrer=%2Fa", "/a"},
		{"other=1&referrer=%2Fa&more=2", "/a"},
		{"referrer=%2Fa%3Fx%3D1%26y%3D2", "/a?x=1&y=2"},
		{"referrer=%2Fa%3Fx%3D1&other=1", "/a?x=1"},
		{"referrer=/plain&other=1", "/plain"},
		// Sent by a web server that cannot encode it: the whole address, verbatim.
		{"referrer=/page?x=1&y=2", "/page?x=1&y=2"},
		{"referrer=http://app.example:8080/page?x=1&y=2&z=3", "http://app.example:8080/page?x=1&y=2&z=3"},
		{"other=1&referrer=/page?x=1&y=2", "/page?x=1&y=2"},
		// The page's own escapes are its own: %26 must stay inside its value.
		{"referrer=/search?q=a%26b+c&page=2", "/search?q=a%26b+c&page=2"},
		// Broken encoding gives nothing, not a guess.
		{"referrer=%zz", ""},
	} {
		if got := referrerParam(tc.query); got != tc.want {
			t.Errorf("referrerParam(%q) = %q, want %q", tc.query, got, tc.want)
		}
	}
}

// Reading the address whole must not open a way around the redirect checks.
func TestUnencodedReferrerKeepsItsWholeQueryAndItsChecks(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	redirect := func(query string) string {
		r := httptest.NewRequest("POST", "http://signet.example/login?"+query, nil)
		r.Host = "signet.example"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return s.loginRedirect(r)
	}
	for _, tc := range []struct{ query, want string }{
		{"referrer=/page?x=1&y=2", "/page?x=1&y=2"},
		{"referrer=http://signet.example/page?x=1&y=2", "/page?x=1&y=2"},
		{"referrer=//evil.example/page?x=1&y=2", "/account"},
		{"referrer=http://evil.example/page?x=1&y=2", "/account"},
		{"referrer=/login?referrer=/page&y=2", "/account"},
	} {
		if got := redirect(tc.query); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.query, got, tc.want)
		}
	}

	// The login page hands it on through its hidden field.
	r := httptest.NewRequest("GET", "http://signet.example/login?referrer=/page?x=1&y=2", nil)
	if got := s.loginReferrer(r); got != "/page?x=1&y=2" {
		t.Errorf("login page: got %q", got)
	}
	// A body field wins, and the query no longer reads as one.
	r = httptest.NewRequest("POST", "http://signet.example/login?referrer=/q?x=1&y=2", strings.NewReader("referrer=%2Fbody"))
	r.Host = "signet.example"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if got := s.loginRedirect(r); got != "/body" {
		t.Errorf("posted field: got %q", got)
	}
}

// Every kind of field a page shows must have the page's own look, normal and focused.
func TestPagesStyleTheirPasswordFields(t *testing.T) {
	for _, page := range []string{"login", "recover", "register"} {
		source, err := os.ReadFile("../../web/templates/" + page + ".html")
		if err != nil {
			t.Fatal(err)
		}
		css := string(source)
		css = css[:strings.Index(css, "</style>")]
		for _, selector := range []string{`input[type="password"]`, `input[type="password"]:focus`} {
			if !strings.Contains(css, selector) {
				t.Errorf("%s has no style for %s", page, selector)
			}
		}
	}
}
