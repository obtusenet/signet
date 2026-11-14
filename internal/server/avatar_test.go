// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/config"
)

func avatarServer(t *testing.T, change ...func(*config.Config)) *Server {
	t.Helper()
	return recoveryServer(t, append([]func(*config.Config){func(c *config.Config) {
		c.Avatars = "enabled"
		c.AvatarSize = 64
	}}, change...)...)
}

func picture(t *testing.T, size int, format string) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	for i := range img.Pix {
		img.Pix[i] = byte(i)
	}
	img.Set(0, 0, color.RGBA{255, 0, 0, 255})
	var b bytes.Buffer
	var err error
	if format == "jpeg" {
		err = jpeg.Encode(&b, img, nil)
	} else {
		err = png.Encode(&b, img)
	}
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

func setPicture(s *Server, c *http.Cookie, encoded string) (*httptest.ResponseRecorder, map[string]interface{}) {
	body, _ := json.Marshal(map[string]string{"action": "avatar-set", "image": encoded})
	w := accountPost(s, c, string(body))
	var reply map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &reply)
	return w, reply
}

func get(s *Server, target string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://signet.example"+target, nil))
	return w
}

func sessionReply(t *testing.T, s *Server, c *http.Cookie) (map[string]interface{}, http.Header) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "https://signet.example/session", nil)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	var reply map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || w.Code != http.StatusOK {
		t.Fatalf("/session: %d %v", w.Code, err)
	}
	return reply, w.Header()
}

func TestAvatarSetServeReplaceRemove(t *testing.T) {
	s := avatarServer(t)
	c := signedIn(t, s, recoveryUser, "tok", 0)
	if reply, header := sessionReply(t, s, c); reply["avatar"] != nil || header.Get("Remote-Avatar") != "" {
		t.Fatalf("an account with no picture: %v %q", reply["avatar"], header.Get("Remote-Avatar"))
	}
	pattern := `src="data:image/svg`
	if page := accountGet(s, c).Body.String(); !strings.Contains(page, pattern) || !strings.Contains(page, `id="avatar-edit"`) {
		t.Error("with no picture the page shows no pattern, or no Edit link")
	}

	w, reply := setPicture(s, c, picture(t, 64, "png"))
	if w.Code != http.StatusOK {
		t.Fatalf("set: %d %s", w.Code, w.Body)
	}
	first, _ := reply["avatar"].(string)
	if !strings.HasPrefix(first, "/avatar/") {
		t.Fatalf("the reply names %q", first)
	}
	served := get(s, first)
	if served.Code != http.StatusOK || served.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("serving: %d %q", served.Code, served.Header().Get("Content-Type"))
	}
	for name, want := range map[string]string{
		"Cache-Control":                "public, max-age=31536000, immutable",
		"Content-Security-Policy":      "default-src 'none'",
		"X-Content-Type-Options":       "nosniff",
		"Cross-Origin-Resource-Policy": "cross-origin",
	} {
		if got := served.Header().Get(name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	if _, format, err := image.Decode(served.Body); err != nil || format != "png" {
		t.Errorf("served image: %q %v", format, err)
	}

	// Applications learn it as an absolute URL.
	reply2, header := sessionReply(t, s, c)
	if reply2["avatar"] != "https://signet.example"+first || header.Get("Remote-Avatar") != "https://signet.example"+first {
		t.Errorf("/session: %v %q", reply2["avatar"], header.Get("Remote-Avatar"))
	}
	if page := accountGet(s, c).Body.String(); !strings.Contains(page, `src="`+first+`"`) {
		t.Error("the account page does not show the picture")
	}

	// A new one has a new address; the old one is gone.
	_, reply = setPicture(s, c, picture(t, 64, "jpeg"))
	second, _ := reply["avatar"].(string)
	if second == first || get(s, first).Code != http.StatusNotFound {
		t.Errorf("the replaced picture is still served")
	}
	if got := get(s, second).Header().Get("Content-Type"); got != "image/jpeg" {
		t.Errorf("a JPEG is served as %q", got)
	}

	w = accountPost(s, c, `{"action":"avatar-remove"}`)
	if w.Code != http.StatusOK || get(s, second).Code != http.StatusNotFound {
		t.Errorf("remove: %d, then %d", w.Code, get(s, second).Code)
	}
	if reply, _ := sessionReply(t, s, c); reply["avatar"] != nil {
		t.Errorf("after removal: %v", reply["avatar"])
	}
	if !strings.Contains(accountGet(s, c).Body.String(), pattern) {
		t.Error("after removal the page shows no pattern")
	}
}

func TestAvatarRefusals(t *testing.T) {
	s := avatarServer(t)
	c := signedIn(t, s, recoveryUser, "tok", 0)
	svg := base64.StdEncoding.EncodeToString([]byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`))
	for name, tc := range map[string]struct {
		image string
		want  string
	}{
		"wrong size": {picture(t, 128, "png"), "must be 64 by 64"},
		"svg":        {svg, "PNG or a JPEG"},
		"not base64": {"%%%", "could not be read"},
		"empty":      {"", "PNG or a JPEG"},
	} {
		w, reply := setPicture(s, c, tc.image)
		if w.Code != http.StatusBadRequest || !strings.Contains(reply["error"].(string), tc.want) {
			t.Errorf("%s: %d %v", name, w.Code, reply["error"])
		}
	}
	if id, _ := s.avatars.ID(context.Background(), recoveryUser); id != "" {
		t.Error("a refused upload was stored")
	}
	for _, target := range []string{"/avatar/", "/avatar/nothing", "/avatar/" + strings.Repeat("0", 32), "/avatar/" + strings.Repeat("A", 32)} {
		if w := get(s, target); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", target, w.Code)
		}
	}
}

func TestAvatarNeedsARecentSignIn(t *testing.T) {
	s := avatarServer(t)
	c := signedIn(t, s, recoveryUser, "old", time.Hour)
	if w, _ := setPicture(s, c, picture(t, 64, "png")); w.Code != http.StatusForbidden {
		t.Errorf("set with an old sign-in: %d", w.Code)
	}
	if w := accountPost(s, c, `{"action":"avatar-remove"}`); w.Code != http.StatusForbidden {
		t.Errorf("remove with an old sign-in: %d", w.Code)
	}
	if page := accountGet(s, c).Body.String(); !strings.Contains(page, `id="avatar-image"`) || strings.Contains(page, `id="avatar-edit"`) {
		t.Error("an old sign-in should see the picture and no Edit link")
	}
	if w, _ := setPicture(s, nil, picture(t, 64, "png")); w.Code != http.StatusUnauthorized {
		t.Errorf("set with no session: %d", w.Code)
	}
}

func TestAvatarSendsNoMail(t *testing.T) {
	s := avatarServer(t)
	c := signedIn(t, s, recoveryUser, "tok", 0)
	setPicture(s, c, picture(t, 64, "png"))
	accountPost(s, c, `{"action":"avatar-remove"}`)
	if mailSays(t, s, "picture") || mailSays(t, s, "avatar") {
		t.Error("a picture change sent mail")
	}
}

func TestAvatarRateLimit(t *testing.T) {
	s := avatarServer(t, func(c *config.Config) { c.AvatarRateLimit = 2 })
	c := signedIn(t, s, recoveryUser, "tok", 0)
	img := picture(t, 64, "png")
	for i := 0; i < 2; i++ {
		if w, _ := setPicture(s, c, img); w.Code != http.StatusOK {
			t.Fatalf("upload %d: %d", i+1, w.Code)
		}
	}
	if w, _ := setPicture(s, c, img); w.Code != http.StatusTooManyRequests {
		t.Errorf("over the limit: %d", w.Code)
	}
}

func TestAvatarInTheValidationAPI(t *testing.T) {
	s := avatarServer(t)
	c := signedIn(t, s, recoveryUser, "tok", 0)
	key, err := s.apiClients.Create(context.Background(), "app", nil)
	if err != nil {
		t.Fatal(err)
	}
	validate := func() map[string]interface{} {
		r := httptest.NewRequest(http.MethodPost, "https://signet.example/api/v1/validate", strings.NewReader(`{"cookie":"`+c.Value+`"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-API-Key", key)
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		var reply map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &reply)
		if w.Code != http.StatusOK {
			t.Fatalf("validate: %d %s", w.Code, w.Body)
		}
		return reply
	}
	if reply := validate(); reply["avatar"] != nil {
		t.Errorf("no picture: %v", reply["avatar"])
	}
	_, set := setPicture(s, c, picture(t, 64, "png"))
	if reply := validate(); reply["avatar"] != "https://signet.example"+set["avatar"].(string) {
		t.Errorf("validate names %v", reply["avatar"])
	}
}

// Under a base path, and with no public_url, the picture's address is a path
// under the base.
func TestAvatarUnderABasePath(t *testing.T) {
	s := avatarServer(t, func(c *config.Config) { c.BasePath = "/comments-auth"; c.PublicURL = "" })
	c := signedIn(t, s, recoveryUser, "tok", 0)
	body, _ := json.Marshal(map[string]string{"action": "avatar-set", "image": picture(t, 64, "png")})
	r := httptest.NewRequest(http.MethodPost, "https://signet.example/comments-auth/account", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(c)
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	var reply map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &reply)
	at, _ := reply["avatar"].(string)
	if w.Code != http.StatusOK || !strings.HasPrefix(at, "/comments-auth/avatar/") {
		t.Fatalf("%d %q", w.Code, at)
	}
	if got := get(s, at); got.Code != http.StatusOK {
		t.Errorf("served under the base: %d", got.Code)
	}
	r = httptest.NewRequest(http.MethodGet, "https://signet.example/comments-auth/session", nil)
	r.AddCookie(c)
	w = httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	json.Unmarshal(w.Body.Bytes(), &reply)
	if reply["avatar"] != at {
		t.Errorf("/session without public_url: %v", reply["avatar"])
	}
}

func TestAvatarsSwitchedOff(t *testing.T) {
	s := recoveryServer(t)
	c := signedIn(t, s, recoveryUser, "tok", 0)
	if w, _ := setPicture(s, c, picture(t, 256, "png")); w.Code != http.StatusForbidden {
		t.Errorf("set while off: %d", w.Code)
	}
	if w := get(s, "/avatar/"+strings.Repeat("0", 32)); w.Code == http.StatusOK {
		t.Errorf("the route answers while off: %d", w.Code)
	}
	if page := accountGet(s, c).Body.String(); strings.Contains(page, `id="avatar-section"`) || strings.Contains(page, `id="avatar-image"`) {
		t.Error("the page offers a picture while they are off")
	}
	if reply, _ := sessionReply(t, s, c); reply["avatar"] != nil {
		t.Errorf("/session while off: %v", reply["avatar"])
	}
}
