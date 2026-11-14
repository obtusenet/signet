// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package webauthn

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/auth"
	"github.com/obtusenet/signet/internal/backend/csv"
	"github.com/obtusenet/signet/internal/claims"
	"github.com/obtusenet/signet/internal/config"
	"github.com/obtusenet/signet/internal/cookie"
	"github.com/obtusenet/signet/internal/db"
	"github.com/obtusenet/signet/internal/logging"
	"github.com/obtusenet/signet/internal/session"
)

const (
	testOrigin = "https://signet.example"
	testRPID   = "signet.example"
)

// softKey is a software authenticator: a real P-256 key that produces the same
// bytes a hardware key would, with "none" attestation.
type softKey struct {
	key     *ecdsa.PrivateKey
	id      []byte
	counter uint32
}

func newSoftKey(t *testing.T) *softKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &softKey{key: key, id: id}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// cborBytes encodes a CBOR byte string.
func cborBytes(b []byte) []byte {
	switch {
	case len(b) < 24:
		return append([]byte{0x40 | byte(len(b))}, b...)
	case len(b) < 256:
		return append([]byte{0x58, byte(len(b))}, b...)
	default:
		return append([]byte{0x59, byte(len(b) >> 8), byte(len(b))}, b...)
	}
}

// coseKey is the public key as COSE_Key: EC2, ES256, P-256 (RFC 9053 §7.1.1).
func (k *softKey) coseKey() []byte {
	x := make([]byte, 32)
	y := make([]byte, 32)
	raw, err := k.key.PublicKey.ECDH()
	if err != nil {
		panic(err)
	}
	point := raw.Bytes() // 0x04 || X || Y
	copy(x, point[1:33])
	copy(y, point[33:65])

	var out bytes.Buffer
	out.Write([]byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21})
	out.Write(cborBytes(x))
	out.WriteByte(0x22)
	out.Write(cborBytes(y))
	return out.Bytes()
}

// authData builds authenticator data (WebAuthn L2 §6.1).
func (k *softKey) authData(flags byte, attested bool) []byte {
	rpHash := sha256.Sum256([]byte(testRPID))
	var out bytes.Buffer
	out.Write(rpHash[:])
	out.WriteByte(flags)
	binary.Write(&out, binary.BigEndian, k.counter)
	if attested {
		out.Write(make([]byte, 16)) // AAGUID
		binary.Write(&out, binary.BigEndian, uint16(len(k.id)))
		out.Write(k.id)
		out.Write(k.coseKey())
	}
	return out.Bytes()
}

func clientData(kind, challenge string) []byte {
	b, _ := json.Marshal(map[string]string{"type": kind, "challenge": challenge, "origin": testOrigin})
	return b
}

// attestation is the browser's answer to navigator.credentials.create().
func (k *softKey) attestation(challenge string) []byte {
	var object bytes.Buffer
	object.WriteByte(0xa3)
	object.Write([]byte{0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e'})
	object.Write([]byte{0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0})
	object.Write([]byte{0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a'})
	object.Write(cborBytes(k.authData(0x45, true))) // UP | UV | AT

	body, _ := json.Marshal(map[string]interface{}{
		"id":    b64(k.id),
		"rawId": b64(k.id),
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64(clientData("webauthn.create", challenge)),
			"attestationObject": b64(object.Bytes()),
		},
	})
	return body
}

// assertion is the browser's answer to navigator.credentials.get().
func (k *softKey) assertion(t *testing.T, challenge string) []byte {
	t.Helper()
	k.counter++
	data := k.authData(0x05, false) // UP | UV
	client := clientData("webauthn.get", challenge)
	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, data...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]interface{}{
		"id":    b64(k.id),
		"rawId": b64(k.id),
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64(client),
			"authenticatorData": b64(data),
			"signature":         b64(signature),
		},
	})
	return body
}

type harness struct {
	t        *testing.T
	handler  *Handler
	store    *Store
	backend  *csv.Backend
	sessions *session.Store
	cookies  *cookie.CookieManager
	logger   *logging.Logger
	service  *Service
	accounts *auth.AccountPolicy
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	logger, err := logging.New(false, "error")
	if err != nil {
		t.Fatal(err)
	}
	// db.New is what production uses: it creates the older, shorter
	// webauthn_credentials table, which NewStore must bring up to date.
	database, err := db.New(filepath.Join(dir, "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	backend, err := csv.New(filepath.Join(dir, "users.csv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backend.Close() })
	store, err := NewStore(database.DB())
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(testRPID, "Signet", []string{testOrigin}, store)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		t:        t,
		store:    store,
		backend:  backend,
		sessions: session.NewStore(database.DB()),
		cookies:  cookie.NewCookieManager("signetid", "", 3600, []byte("test-secret-key-for-testing-only")),
		logger:   logger,
		service:  service,
		accounts: auth.NewAccountPolicy(backend, true),
	}
	h.handler = NewHandler(service, h.sessions, h.cookies, h.accounts, logger)
	return h
}

func (h *harness) addUser(addr string, flags ...string) {
	h.t.Helper()
	if err := h.backend.CreateUser(addr, "!", "bcrypt", flags); err != nil {
		h.t.Fatal(err)
	}
}

// signIn creates a session as password login would and returns its cookie.
func (h *harness) signIn(addr string) *http.Cookie {
	h.t.Helper()
	token, err := cookie.GenerateRandomToken()
	if err != nil {
		h.t.Fatal(err)
	}
	now := time.Now()
	if err := h.sessions.Create(context.Background(), &session.Session{
		Token: token, UserEmail: addr, AuthMethod: "password", Claims: "{}",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		h.t.Fatal(err)
	}
	return h.cookies.CreateAuthCookie(token)
}

type call struct {
	path   string
	body   []byte
	cookie *http.Cookie
	invite string
	method string
}

func (h *harness) do(handler http.HandlerFunc, c call) *httptest.ResponseRecorder {
	method := c.method
	if method == "" {
		method = http.MethodPost
	}
	r := httptest.NewRequest(method, c.path, bytes.NewReader(c.body))
	r.Header.Set("Content-Type", "application/json")
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	if c.invite != "" {
		r.Header.Set(InviteHeader, c.invite)
	}
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}

type started struct {
	Success  bool   `json:"success"`
	Ceremony string `json:"ceremony"`
	Options  struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"user"`
			AllowCredentials []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
			ExcludeCredentials []struct {
				ID string `json:"id"`
			} `json:"excludeCredentials"`
		} `json:"publicKey"`
	} `json:"options"`
}

func decodeStarted(t *testing.T, w *httptest.ResponseRecorder) started {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("start: status %d: %s", w.Code, w.Body)
	}
	var s started
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if s.Ceremony == "" || s.Options.PublicKey.Challenge == "" {
		t.Fatalf("start: incomplete reply: %s", w.Body)
	}
	return s
}

// enroll runs a full registration as the given identity.
func (h *harness) enroll(key *softKey, c *http.Cookie, invite string) *httptest.ResponseRecorder {
	h.t.Helper()
	s := decodeStarted(h.t, h.do(h.handler.HandleBeginRegistration,
		call{path: "/webauthn/register/start", cookie: c, invite: invite}))
	return h.do(h.handler.HandleFinishRegistration, call{
		path:   "/webauthn/register/finish?label=test&ceremony=" + url.QueryEscape(s.Ceremony),
		body:   key.attestation(s.Options.PublicKey.Challenge),
		cookie: c,
		invite: invite,
	})
}

// login runs a full login and returns the finishing response.
func (h *harness) login(key *softKey, addr string) *httptest.ResponseRecorder {
	h.t.Helper()
	s := decodeStarted(h.t, h.do(h.handler.HandleBeginLogin,
		call{path: "/webauthn/authenticate/start?email=" + url.QueryEscape(addr)}))
	return h.do(h.handler.HandleFinishLogin, call{
		path: "/webauthn/authenticate/finish?email=" + url.QueryEscape(addr) +
			"&ceremony=" + url.QueryEscape(s.Ceremony),
		body: key.assertion(h.t, s.Options.PublicKey.Challenge),
	})
}

func hasCookie(w *httptest.ResponseRecorder) bool {
	for _, c := range w.Result().Cookies() {
		if c.Name == "signetid" && c.Value != "" {
			return true
		}
	}
	return false
}

func TestEnrollThenLogin(t *testing.T) {
	h := newHarness(t)
	h.addUser("alice@example.com", csv.FlagApproved)
	key := newSoftKey(t)

	w := h.enroll(key, h.signIn("alice@example.com"), "")
	if w.Code != http.StatusOK {
		t.Fatalf("enroll: %d: %s", w.Code, w.Body)
	}

	w = h.login(key, "alice@example.com")
	if w.Code != http.StatusOK || !hasCookie(w) {
		t.Fatalf("login: %d, cookie %v: %s", w.Code, hasCookie(w), w.Body)
	}

	// The cookie must identify the user to the rest of the service.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	token, err := h.cookies.ValidateAuthCookie(r)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := h.sessions.Get(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if sess.UserEmail != "alice@example.com" || sess.AuthMethod != "webauthn" {
		t.Errorf("session = %+v", sess)
	}

	// The counter moved, so a later assertion must keep increasing it.
	cred, err := h.store.GetCredential(context.Background(), hex.EncodeToString(key.id))
	if err != nil {
		t.Fatal(err)
	}
	if cred.Counter != key.counter {
		t.Errorf("stored counter = %d, want %d", cred.Counter, key.counter)
	}

	if w := h.login(key, "alice@example.com"); w.Code != http.StatusOK {
		t.Errorf("second login: %d: %s", w.Code, w.Body)
	}
}

// The core of the review finding: without an identity nothing starts, and the
// address in a request is ignored.
func TestEnrollmentRequiresIdentity(t *testing.T) {
	h := newHarness(t)
	h.addUser("victim@example.com", csv.FlagApproved)

	w := h.do(h.handler.HandleBeginRegistration,
		call{path: "/webauthn/register/start?email=victim@example.com"})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("anonymous start: %d, want 401", w.Code)
	}
	w = h.do(h.handler.HandleFinishRegistration,
		call{path: "/webauthn/register/finish?email=victim@example.com&ceremony=x"})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("anonymous finish: %d, want 401", w.Code)
	}
}

func TestSignedInUserCannotEnrollForSomeoneElse(t *testing.T) {
	h := newHarness(t)
	h.addUser("mallory@example.com", csv.FlagApproved)
	h.addUser("victim@example.com", csv.FlagApproved)
	mallory := h.signIn("mallory@example.com")

	s := decodeStarted(t, h.do(h.handler.HandleBeginRegistration, call{
		path: "/webauthn/register/start?email=victim@example.com", cookie: mallory,
	}))
	if s.Options.PublicKey.User.Name != "mallory@example.com" {
		t.Fatalf("enrolling for %q", s.Options.PublicKey.User.Name)
	}

	key := newSoftKey(t)
	w := h.do(h.handler.HandleFinishRegistration, call{
		path:   "/webauthn/register/finish?email=victim@example.com&ceremony=" + url.QueryEscape(s.Ceremony),
		body:   key.attestation(s.Options.PublicKey.Challenge),
		cookie: mallory,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("finish: %d: %s", w.Code, w.Body)
	}

	// The key landed on Mallory's account, and opens nothing of the victim's.
	if creds, _ := h.store.GetUserCredentials(context.Background(), "victim@example.com"); len(creds) != 0 {
		t.Errorf("victim has %d keys", len(creds))
	}
	if w := h.login(key, "victim@example.com"); w.Code != http.StatusUnauthorized || hasCookie(w) {
		t.Errorf("login as victim: %d, cookie %v", w.Code, hasCookie(w))
	}
}

func TestInviteEnrollsOnceWithoutASession(t *testing.T) {
	h := newHarness(t)
	h.addUser("newbie@example.com", csv.FlagApproved)
	token, err := h.store.CreateInvite(context.Background(), "newbie@example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	key := newSoftKey(t)
	if w := h.enroll(key, nil, token); w.Code != http.StatusOK {
		t.Fatalf("enroll: %d: %s", w.Code, w.Body)
	}
	if w := h.login(key, "newbie@example.com"); w.Code != http.StatusOK {
		t.Errorf("login with invited key: %d: %s", w.Code, w.Body)
	}

	// Spent: starting again must fail.
	w := h.do(h.handler.HandleBeginRegistration, call{path: "/webauthn/register/start", invite: token})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("reused invite: %d, want 401", w.Code)
	}
}

func TestInviteRefusals(t *testing.T) {
	h := newHarness(t)
	h.addUser("a@example.com", csv.FlagApproved)
	h.addUser("locked@example.com", csv.FlagApproved, csv.FlagLocked)
	ctx := context.Background()

	start := func(token string) int {
		return h.do(h.handler.HandleBeginRegistration, call{path: "/webauthn/register/start", invite: token}).Code
	}

	if got := start("not-a-real-token"); got != http.StatusUnauthorized {
		t.Errorf("unknown token: %d", got)
	}

	expired, err := h.store.CreateInvite(ctx, "a@example.com", -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := start(expired); got != http.StatusUnauthorized {
		t.Errorf("expired token: %d", got)
	}

	first, _ := h.store.CreateInvite(ctx, "a@example.com", time.Hour)
	second, _ := h.store.CreateInvite(ctx, "a@example.com", time.Hour)
	if got := start(first); got != http.StatusUnauthorized {
		t.Errorf("superseded token: %d", got)
	}
	if got := start(second); got != http.StatusOK {
		t.Errorf("newest token: %d", got)
	}

	lockedInvite, _ := h.store.CreateInvite(ctx, "locked@example.com", time.Hour)
	if got := start(lockedInvite); got != http.StatusForbidden {
		t.Errorf("locked account: %d", got)
	}

	// The database must not hold a usable form of the token.
	var stored string
	if err := h.store.db.QueryRow(`SELECT token_hash FROM webauthn_invites WHERE user_email = ?`,
		"a@example.com").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == second || strings.Contains(stored, second) {
		t.Error("invite stored in the clear")
	}
}

func TestLoginRejections(t *testing.T) {
	h := newHarness(t)
	h.addUser("alice@example.com", csv.FlagApproved)
	key := newSoftKey(t)
	if w := h.enroll(key, h.signIn("alice@example.com"), ""); w.Code != http.StatusOK {
		t.Fatalf("enroll: %d: %s", w.Code, w.Body)
	}

	begin := func() started {
		return decodeStarted(t, h.do(h.handler.HandleBeginLogin,
			call{path: "/webauthn/authenticate/start?email=alice@example.com"}))
	}
	finish := func(ceremony string, body []byte) *httptest.ResponseRecorder {
		return h.do(h.handler.HandleFinishLogin, call{
			path: "/webauthn/authenticate/finish?email=alice@example.com&ceremony=" + url.QueryEscape(ceremony),
			body: body,
		})
	}

	t.Run("wrong key", func(t *testing.T) {
		s := begin()
		impostor := newSoftKey(t)
		impostor.id = key.id // claims Alice's credential, signs with its own key
		if w := finish(s.Ceremony, impostor.assertion(t, s.Options.PublicKey.Challenge)); w.Code != http.StatusUnauthorized || hasCookie(w) {
			t.Errorf("status %d, cookie %v", w.Code, hasCookie(w))
		}
	})

	t.Run("wrong challenge", func(t *testing.T) {
		s := begin()
		if w := finish(s.Ceremony, key.assertion(t, b64([]byte("not the challenge")))); w.Code != http.StatusUnauthorized || hasCookie(w) {
			t.Errorf("status %d, cookie %v", w.Code, hasCookie(w))
		}
	})

	t.Run("ceremony cannot be replayed", func(t *testing.T) {
		s := begin()
		if w := finish(s.Ceremony, key.assertion(t, s.Options.PublicKey.Challenge)); w.Code != http.StatusOK {
			t.Fatalf("first: %d: %s", w.Code, w.Body)
		}
		// A fresh signature with a higher counter, so only the spent ceremony
		// can be what refuses it.
		if w := finish(s.Ceremony, key.assertion(t, s.Options.PublicKey.Challenge)); w.Code != http.StatusUnauthorized || hasCookie(w) {
			t.Errorf("replay: status %d, cookie %v", w.Code, hasCookie(w))
		}
	})

	t.Run("cloned authenticator", func(t *testing.T) {
		s := begin()
		key.counter = 0 // assertion() makes it 1, at or below the stored counter
		if w := finish(s.Ceremony, key.assertion(t, s.Options.PublicKey.Challenge)); w.Code != http.StatusUnauthorized || hasCookie(w) {
			t.Errorf("status %d, cookie %v", w.Code, hasCookie(w))
		}
		key.counter = 100
	})

	t.Run("ceremony bound to its address", func(t *testing.T) {
		h.addUser("other@example.com", csv.FlagApproved)
		s := begin()
		w := h.do(h.handler.HandleFinishLogin, call{
			path: "/webauthn/authenticate/finish?email=other@example.com&ceremony=" + url.QueryEscape(s.Ceremony),
			body: key.assertion(t, s.Options.PublicKey.Challenge),
		})
		if w.Code != http.StatusUnauthorized || hasCookie(w) {
			t.Errorf("status %d, cookie %v", w.Code, hasCookie(w))
		}
	})

	t.Run("account locked after enrolling", func(t *testing.T) {
		if err := h.backend.AddFlag("alice@example.com", csv.FlagLocked); err != nil {
			t.Fatal(err)
		}
		defer h.backend.RemoveFlag("alice@example.com", csv.FlagLocked)
		s := begin() // answered like any other address, without its real keys
		for _, offered := range s.Options.PublicKey.AllowCredentials {
			if offered.ID == b64(key.id) {
				t.Error("a locked account's real key was offered")
			}
		}
		if w := finish(s.Ceremony, key.assertion(t, s.Options.PublicKey.Challenge)); w.Code != http.StatusUnauthorized || hasCookie(w) {
			t.Errorf("status %d, cookie %v", w.Code, hasCookie(w))
		}
	})
}

// shape is an answer with everything that must differ between requests removed.
func shape(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var reply map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatalf("%d: %s: %v", w.Code, w.Body, err)
	}
	reply["ceremony"] = ""
	public := reply["options"].(map[string]any)["publicKey"].(map[string]any)
	public["challenge"] = ""
	allowed := public["allowCredentials"].([]any)
	public["allowCredentials"] = allowed[0].(map[string]any)["type"]
	out, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%d %s", w.Code, out)
}

func TestLoginStartRevealsNothingAboutTheAddress(t *testing.T) {
	h := newHarness(t)
	h.addUser("haskey@example.com", csv.FlagApproved)
	key := newSoftKey(t)
	if w := h.enroll(key, h.signIn("haskey@example.com"), ""); w.Code != http.StatusOK {
		t.Fatalf("enroll: %d: %s", w.Code, w.Body)
	}
	h.addUser("nokeys@example.com", csv.FlagApproved)
	h.addUser("locked@example.com", csv.FlagApproved, csv.FlagLocked)
	start := func(addr string) *httptest.ResponseRecorder {
		return h.do(h.handler.HandleBeginLogin, call{path: "/webauthn/authenticate/start?email=" + url.QueryEscape(addr)})
	}

	want := shape(t, start("haskey@example.com"))
	for _, addr := range []string{"nokeys@example.com", "locked@example.com", "nobody@example.com"} {
		if got := shape(t, start(addr)); got != want {
			t.Errorf("%s:\n got %s\nwant %s", addr, got, want)
		}
		// A decoy's ceremony is stored as a real one is, which also costs the same.
		s := decodeStarted(t, start(addr))
		if _, err := h.store.takeCeremony(context.Background(), s.Ceremony, ceremonyLogin, addr); err != nil {
			t.Errorf("%s: ceremony not stored: %v", addr, err)
		}
	}
}

func decoyIDs(t *testing.T, h *harness, addr string) []string {
	t.Helper()
	s := decodeStarted(t, h.do(h.handler.HandleBeginLogin, call{path: "/webauthn/authenticate/start?email=" + url.QueryEscape(addr)}))
	var ids []string
	for _, offered := range s.Options.PublicKey.AllowCredentials {
		ids = append(ids, offered.ID)
	}
	if len(ids) == 0 {
		t.Fatalf("%s: no keys offered", addr)
	}
	return ids
}

func TestDecoyKeysAreStableForAnAddress(t *testing.T) {
	h := newHarness(t)
	first := decoyIDs(t, h, "nobody@example.com")
	if second := decoyIDs(t, h, "nobody@example.com"); !reflect.DeepEqual(first, second) {
		t.Error("the same address got different keys, which only a decoy would")
	}
	if other := decoyIDs(t, h, "someone@example.com"); first[0] == other[0] {
		t.Error("two addresses got the same key")
	}
}

func TestDecoyKeysVaryLikeRealOnes(t *testing.T) {
	h := newHarness(t)
	lengths, counts := map[int]bool{}, map[int]bool{}
	for i := 0; i < 60; i++ {
		ids := decoyIDs(t, h, fmt.Sprintf("user%d@example.com", i))
		counts[len(ids)] = true
		for _, id := range ids {
			lengths[len(id)] = true
		}
	}
	if len(lengths) < 2 || !counts[1] || !counts[2] {
		t.Errorf("lengths %v, counts %v", lengths, counts)
	}
}

func TestDecoyKeysFollowTheSecret(t *testing.T) {
	h := newHarness(t)
	h.service.SetDecoySecret([]byte("one"))
	one := decoyIDs(t, h, "nobody@example.com")
	h.service.SetDecoySecret([]byte("two"))
	two := decoyIDs(t, h, "nobody@example.com")
	h.service.SetDecoySecret([]byte("one"))
	if again := decoyIDs(t, h, "nobody@example.com"); !reflect.DeepEqual(one, again) {
		t.Error("the same secret gave different keys")
	}
	if reflect.DeepEqual(one, two) {
		t.Error("another secret gave the same keys")
	}
}

// Nobody can sign in through a decoy, even with a key that claims the ID on offer,
// and the failure is the ordinary one.
func TestDecoyCeremonyNeverSignsIn(t *testing.T) {
	h := newHarness(t)
	h.addUser("nokeys@example.com", csv.FlagApproved)
	for _, addr := range []string{"nokeys@example.com", "nobody@example.com"} {
		s := decodeStarted(t, h.do(h.handler.HandleBeginLogin, call{path: "/webauthn/authenticate/start?email=" + url.QueryEscape(addr)}))
		key := newSoftKey(t)
		id, err := base64.RawURLEncoding.DecodeString(s.Options.PublicKey.AllowCredentials[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		key.id = id
		w := h.do(h.handler.HandleFinishLogin, call{
			path: "/webauthn/authenticate/finish?email=" + url.QueryEscape(addr) + "&ceremony=" + url.QueryEscape(s.Ceremony),
			body: key.assertion(t, s.Options.PublicKey.Challenge),
		})
		if w.Code != http.StatusUnauthorized || hasCookie(w) || !strings.Contains(w.Body.String(), "security key sign-in failed") {
			t.Errorf("%s: %d, cookie %v: %s", addr, w.Code, hasCookie(w), w.Body)
		}
	}
}

func TestFailClosedHookRefusesWebAuthnLogin(t *testing.T) {
	h := newHarness(t)
	h.addUser("alice@example.com", csv.FlagApproved)
	key := newSoftKey(t)
	if w := h.enroll(key, h.signIn("alice@example.com"), ""); w.Code != http.StatusOK {
		t.Fatalf("enroll: %d: %s", w.Code, w.Body)
	}

	script := filepath.Join(t.TempDir(), "hook.sh")
	body := "#!/bin/sh\nread line; echo '{\"type\":\"claim_error\",\"error\":\"no\"}'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	hook := claims.NewClaimsHook(config.ClaimsHookConfig{
		Enabled: true, Program: script, TimeoutSec: 5, OnFailure: "fail-closed",
	}, h.logger)
	h.handler = NewHandler(h.service, h.sessions, h.cookies, h.accounts, h.logger, hook)

	if w := h.login(key, "alice@example.com"); w.Code != http.StatusForbidden || hasCookie(w) {
		t.Errorf("status %d, cookie %v; want 403 and no cookie", w.Code, hasCookie(w))
	}
}

func TestCredentialsAreVisibleOnlyToTheirOwner(t *testing.T) {
	h := newHarness(t)
	h.addUser("alice@example.com", csv.FlagApproved)
	h.addUser("mallory@example.com", csv.FlagApproved)
	key := newSoftKey(t)
	alice := h.signIn("alice@example.com")
	mallory := h.signIn("mallory@example.com")
	if w := h.enroll(key, alice, ""); w.Code != http.StatusOK {
		t.Fatalf("enroll: %d: %s", w.Code, w.Body)
	}
	id := hex.EncodeToString(key.id)

	list := func(c *http.Cookie) *httptest.ResponseRecorder {
		return h.do(h.handler.HandleListCredentials, call{method: http.MethodGet, path: "/webauthn/credentials", cookie: c})
	}
	if w := list(nil); w.Code != http.StatusUnauthorized {
		t.Errorf("anonymous list: %d", w.Code)
	}
	if w := list(mallory); strings.Contains(w.Body.String(), id) {
		t.Errorf("Mallory sees Alice's key: %s", w.Body)
	}
	w := list(alice)
	if !strings.Contains(w.Body.String(), id) {
		t.Errorf("Alice cannot see her key: %s", w.Body)
	}
	if strings.Contains(w.Body.String(), "PublicKey") {
		t.Errorf("reply includes key material: %s", w.Body)
	}

	del := func(c *http.Cookie) int {
		return h.do(h.handler.HandleDeleteCredential, call{method: http.MethodDelete, path: "/webauthn/credentials/" + id, cookie: c}).Code
	}
	if got := del(nil); got != http.StatusUnauthorized {
		t.Errorf("anonymous delete: %d", got)
	}
	if got := del(mallory); got != http.StatusNotFound {
		t.Errorf("Mallory's delete: %d", got)
	}
	if _, err := h.store.GetCredential(context.Background(), id); err != nil {
		t.Fatalf("key removed by a failed delete: %v", err)
	}
	if got := del(alice); got != http.StatusOK {
		t.Errorf("Alice's delete: %d", got)
	}
	if _, err := h.store.GetCredential(context.Background(), id); err == nil {
		t.Error("key still present")
	}
}

func TestDeleteUserRemovesEverything(t *testing.T) {
	h := newHarness(t)
	h.addUser("alice@example.com", csv.FlagApproved)
	if w := h.enroll(newSoftKey(t), h.signIn("alice@example.com"), ""); w.Code != http.StatusOK {
		t.Fatalf("enroll: %d: %s", w.Code, w.Body)
	}
	token, err := h.store.CreateInvite(context.Background(), "alice@example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	removed, err := h.store.DeleteUser(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("removed %d keys", removed)
	}
	if _, err := h.store.InviteEmail(context.Background(), token); err == nil {
		t.Error("invite survived")
	}
}

func TestUserHandleCarriesNoAddress(t *testing.T) {
	handle := generateUserHandle("alice@example.com")
	if len(handle) != 32 {
		t.Errorf("length %d", len(handle))
	}
	if bytes.Contains(handle, []byte("alice")) {
		t.Error("handle contains the address")
	}
}

func TestCheckInviteSpendsNothing(t *testing.T) {
	h := newHarness(t)
	h.addUser("alice@example.com", csv.FlagApproved)
	token, err := h.store.CreateInvite(context.Background(), "alice@example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	check := func(c call) int {
		c.method, c.path = http.MethodGet, "/webauthn/invite"
		return h.do(h.handler.HandleCheckInvite, c).Code
	}

	if got := check(call{}); got != http.StatusBadRequest {
		t.Errorf("no invite: %d", got)
	}
	// A session is not an invite: the page asks only about the link.
	if got := check(call{cookie: h.signIn("alice@example.com")}); got != http.StatusBadRequest {
		t.Errorf("session, no invite: %d", got)
	}
	if got := check(call{invite: "not-a-real-invite"}); got != http.StatusUnauthorized {
		t.Errorf("unknown invite: %d", got)
	}
	for i := 0; i < 2; i++ {
		if got := check(call{invite: token}); got != http.StatusOK {
			t.Fatalf("live invite, check %d: %d", i, got)
		}
	}

	// The checks did not use it up; enrolling does, and then the check refuses.
	if w := h.enroll(newSoftKey(t), nil, token); w.Code != http.StatusOK {
		t.Fatalf("enroll after checks: %d: %s", w.Code, w.Body)
	}
	if got := check(call{invite: token}); got != http.StatusUnauthorized {
		t.Errorf("used invite: %d", got)
	}
	if w := h.do(h.handler.HandleCheckInvite, call{path: "/webauthn/invite", invite: token}); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", w.Code)
	}
}

func TestCheckInviteRefusesALockedAccount(t *testing.T) {
	h := newHarness(t)
	h.addUser("locked@example.com", csv.FlagApproved, csv.FlagLocked)
	token, err := h.store.CreateInvite(context.Background(), "locked@example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	w := h.do(h.handler.HandleCheckInvite, call{method: http.MethodGet, path: "/webauthn/invite", invite: token})
	if w.Code != http.StatusForbidden {
		t.Errorf("locked account: %d", w.Code)
	}
}

// Removing a key ends every session of the account, however it signed in, and
// expires the cookie of the one that asked.  Other accounts are untouched.
func TestDeleteCredentialEndsTheAccountsSessions(t *testing.T) {
	h := newHarness(t)
	h.addUser("alice@example.com", csv.FlagApproved)
	h.addUser("bob@example.com", csv.FlagApproved)
	key := newSoftKey(t)
	asker := h.signIn("alice@example.com")
	other := h.signIn("alice@example.com")
	bob := h.signIn("bob@example.com")
	if w := h.enroll(key, asker, ""); w.Code != http.StatusOK {
		t.Fatalf("enroll: %d: %s", w.Code, w.Body)
	}
	viaKey := h.login(key, "alice@example.com")
	if viaKey.Code != http.StatusOK {
		t.Fatalf("login: %d: %s", viaKey.Code, viaKey.Body)
	}
	keySession := viaKey.Result().Cookies()[0]

	list := func(c *http.Cookie) int {
		return h.do(h.handler.HandleListCredentials, call{method: http.MethodGet, path: "/webauthn/credentials", cookie: c}).Code
	}

	w := h.do(h.handler.HandleDeleteCredential, call{method: http.MethodDelete,
		path: "/webauthn/credentials/" + hex.EncodeToString(key.id), cookie: asker})
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `"signed_out":true`) {
		t.Errorf("reply does not say so: %s", w.Body)
	}
	expired := false
	for _, c := range w.Result().Cookies() {
		expired = expired || (c.Name == "signetid" && c.MaxAge < 0)
	}
	if !expired {
		t.Error("the caller's cookie was not expired")
	}

	for name, c := range map[string]*http.Cookie{"the caller": asker, "another browser": other, "the key's own session": keySession} {
		if got := list(c); got != http.StatusUnauthorized {
			t.Errorf("%s is still signed in: %d", name, got)
		}
	}
	if got := list(bob); got != http.StatusOK {
		t.Errorf("another account was signed out: %d", got)
	}
}

// A failed delete must not sign anyone out.
func TestRefusedDeleteEndsNoSessions(t *testing.T) {
	h := newHarness(t)
	h.addUser("alice@example.com", csv.FlagApproved)
	alice := h.signIn("alice@example.com")
	w := h.do(h.handler.HandleDeleteCredential, call{method: http.MethodDelete, path: "/webauthn/credentials/nonexistent", cookie: alice})
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete: %d", w.Code)
	}
	if got := h.do(h.handler.HandleListCredentials, call{method: http.MethodGet, path: "/webauthn/credentials", cookie: alice}).Code; got != http.StatusOK {
		t.Errorf("signed out by a failed delete: %d", got)
	}
}

// The account keeps another key, so the ceremony starts and the deleted key's
// signature itself must be refused.
func TestDeletedKeyIsRefusedWhileAnotherRemains(t *testing.T) {
	h := newHarness(t)
	h.addUser("alice@example.com", csv.FlagApproved)
	alice := h.signIn("alice@example.com")
	gone, kept := newSoftKey(t), newSoftKey(t)
	for _, key := range []*softKey{gone, kept} {
		if w := h.enroll(key, alice, ""); w.Code != http.StatusOK {
			t.Fatalf("enroll: %d: %s", w.Code, w.Body)
		}
	}
	const addr = "alice@example.com"
	start := func() started {
		return decodeStarted(t, h.do(h.handler.HandleBeginLogin, call{path: "/webauthn/authenticate/start?email=" + url.QueryEscape(addr)}))
	}
	finish := func(key *softKey, s started) *httptest.ResponseRecorder {
		return h.do(h.handler.HandleFinishLogin, call{
			path: "/webauthn/authenticate/finish?email=" + url.QueryEscape(addr) + "&ceremony=" + url.QueryEscape(s.Ceremony),
			body: key.assertion(t, s.Options.PublicKey.Challenge),
		})
	}

	// One sign-in is under way when the key goes.
	inFlight := start()
	if err := h.service.DeleteUserCredential(context.Background(), addr, hex.EncodeToString(gone.id)); err != nil {
		t.Fatal(err)
	}

	if w := finish(gone, inFlight); w.Code != http.StatusUnauthorized || hasCookie(w) {
		t.Errorf("deleted key, ceremony begun before the delete: %d: %s", w.Code, w.Body)
	}
	s := start()
	if len(s.Options.PublicKey.AllowCredentials) != 1 {
		t.Errorf("offered %d keys, want the one left", len(s.Options.PublicKey.AllowCredentials))
	}
	if w := finish(gone, s); w.Code != http.StatusUnauthorized || hasCookie(w) {
		t.Errorf("deleted key: %d: %s", w.Code, w.Body)
	}
	if w := h.login(kept, addr); w.Code != http.StatusOK || !hasCookie(w) {
		t.Errorf("remaining key: %d: %s", w.Code, w.Body)
	}
}

func TestInvalidAddressIsAnOrdinaryLoginFailure(t *testing.T) {
	h := newHarness(t)
	const bad = "x%40example.com%0AINFO:%20forged"
	finished := h.do(h.handler.HandleFinishLogin, call{path: "/webauthn/authenticate/finish?ceremony=x&email=nobody%40example.com"})
	for name, handler := range map[string]http.HandlerFunc{
		"/webauthn/authenticate/start":  h.handler.HandleBeginLogin,
		"/webauthn/authenticate/finish": h.handler.HandleFinishLogin,
	} {
		w := h.do(handler, call{path: name + "?ceremony=x&email=" + bad})
		if w.Code != http.StatusUnauthorized || w.Body.String() != finished.Body.String() {
			t.Errorf("%s: %d: %s", name, w.Code, w.Body)
		}
	}
}

func TestLabelRefusesControlCharacters(t *testing.T) {
	h := newHarness(t)
	h.addUser("alice@example.com", csv.FlagApproved)
	alice := h.signIn("alice@example.com")
	s := decodeStarted(t, h.do(h.handler.HandleBeginRegistration, call{path: "/webauthn/register/start", cookie: alice}))
	w := h.do(h.handler.HandleFinishRegistration, call{
		path:   "/webauthn/register/finish?label=" + url.QueryEscape("key\x1b[31m") + "&ceremony=" + url.QueryEscape(s.Ceremony),
		body:   newSoftKey(t).attestation(s.Options.PublicKey.Challenge),
		cookie: alice,
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("label with an escape: %d: %s", w.Code, w.Body)
	}
}

func TestKeyChangesNotifyTheAccount(t *testing.T) {
	h := newHarness(t)
	var notices []string
	h.handler.SetAccountChanges(time.Hour, func(address, change string) {
		notices = append(notices, address+": "+change)
	})
	h.addUser("alice@example.com", csv.FlagApproved)
	c := h.signIn("alice@example.com")
	key := newSoftKey(t)
	if w := h.enroll(key, c, ""); w.Code != http.StatusOK {
		t.Fatalf("enroll: %d: %s", w.Code, w.Body)
	}
	if len(notices) != 1 || !strings.Contains(notices[0], "alice@example.com: A security key was added") {
		t.Errorf("after adding: %v", notices)
	}
	if w := h.do(h.handler.HandleDeleteCredential, call{method: http.MethodDelete, path: "/webauthn/credentials/" + hex.EncodeToString(key.id), cookie: c}); w.Code != http.StatusOK {
		t.Fatalf("delete: %d: %s", w.Code, w.Body)
	}
	if len(notices) != 2 || !strings.Contains(notices[1], "was removed") {
		t.Errorf("after removing: %v", notices)
	}
}

// An invite proves nothing about a session, so a stale one does not stop it.
func TestInviteNeedsNoRecentSignIn(t *testing.T) {
	h := newHarness(t)
	h.handler.SetAccountChanges(time.Nanosecond, nil)
	h.addUser("alice@example.com", csv.FlagApproved)
	invite, err := h.store.CreateInvite(context.Background(), "alice@example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if w := h.enroll(newSoftKey(t), nil, invite); w.Code != http.StatusOK {
		t.Errorf("%d: %s", w.Code, w.Body)
	}
}

// A finished sign-in by security key is reported, so the account's count of
// failed sign-ins can be cleared; a refused one is not.
func TestSignInIsReported(t *testing.T) {
	h := newHarness(t)
	h.addUser("alice@example.com", csv.FlagApproved)
	key := newSoftKey(t)
	if w := h.enroll(key, h.signIn("alice@example.com"), ""); w.Code != http.StatusOK {
		t.Fatalf("enroll: %d: %s", w.Code, w.Body)
	}
	var reported []string
	h.handler.SetSignedIn(func(_ context.Context, address string) { reported = append(reported, address) })

	if w := h.login(newSoftKey(t), "alice@example.com"); w.Code == http.StatusOK {
		t.Fatal("an unknown key signed in")
	}
	if len(reported) != 0 {
		t.Fatalf("a refused sign-in was reported: %v", reported)
	}
	if w := h.login(key, "alice@example.com"); w.Code != http.StatusOK {
		t.Fatalf("login: %d: %s", w.Code, w.Body)
	}
	if len(reported) != 1 || reported[0] != "alice@example.com" {
		t.Errorf("reported %v", reported)
	}
}
