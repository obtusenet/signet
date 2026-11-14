// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package webauthn

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	ceremonyRegistration = "registration"
	ceremonyLogin        = "login"

	// ceremonyTTL bounds how long a challenge stays answerable; it comfortably
	// exceeds the browser's own ceremony timeout.
	ceremonyTTL = 5 * time.Minute
)

// ErrNoCredentials is returned when a login starts for an address without keys.
var ErrNoCredentials = errors.New("no webauthn credentials registered")

// ErrClonedAuthenticator is returned when a signature counter went backwards,
// which means a second copy of the key may exist (WebAuthn L2 §6.1.1).
var ErrClonedAuthenticator = errors.New("signature counter did not increase: possible cloned authenticator")

// Service manages WebAuthn registration and authentication
type Service struct {
	webauthn    *webauthn.WebAuthn
	store       *Store
	decoySecret []byte
}

// NewService creates a new WebAuthn service
//
// With requireVerification, a key must check its user, with a PIN or a
// fingerprint, both when it is enrolled and at each sign-in, so that a key is two
// factors by itself.  Without it, verification is asked for where the key can do
// it, and a key without a PIN signs in on possession alone.
func NewService(rpID, rpDisplayName string, origins []string, store *Store, requireVerification ...bool) (*Service, error) {
	if rpID == "" {
		return nil, errors.New("webauthn_rpid is not set")
	}
	if len(origins) == 0 {
		return nil, errors.New("webauthn_origins is not set")
	}
	verification := protocol.VerificationPreferred
	if len(requireVerification) > 0 && requireVerification[0] {
		verification = protocol.VerificationRequired
	}
	waConfig := &webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: verification,
		},
	}

	wa, err := webauthn.New(waConfig)
	if err != nil {
		return nil, fmt.Errorf("creating webauthn instance: %w", err)
	}

	decoySecret := make([]byte, sha256.Size)
	if _, err := rand.Read(decoySecret); err != nil {
		return nil, fmt.Errorf("generating decoy secret: %w", err)
	}

	return &Service{
		webauthn:    wa,
		store:       store,
		decoySecret: decoySecret,
	}, nil
}

// SetDecoySecret keeps decoy key IDs the same across restarts, and between
// instances sharing a database.  Without it they last as long as the process, and
// a change between two answers would show that an address has no real key.
func (s *Service) SetDecoySecret(secret []byte) {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("signet webauthn decoy secret"))
	s.decoySecret = mac.Sum(nil)
}

// loadUser builds the library's view of a user from the stored credentials.
func (s *Service) loadUser(ctx context.Context, userEmail string) (*WebAuthnUser, error) {
	creds, err := s.store.GetUserCredentials(ctx, userEmail)
	if err != nil {
		return nil, fmt.Errorf("getting user credentials: %w", err)
	}
	return NewWebAuthnUser(userEmail, creds)
}

// saveSession stores the library's ceremony state and returns the ceremony ID.
func (s *Service) saveSession(ctx context.Context, kind, userEmail string, session *webauthn.SessionData) (string, error) {
	data, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("encoding ceremony: %w", err)
	}
	return s.store.saveCeremony(ctx, kind, userEmail, data, ceremonyTTL)
}

// takeSession returns and removes the state of a ceremony.
func (s *Service) takeSession(ctx context.Context, id, kind, userEmail string) (*webauthn.SessionData, error) {
	data, err := s.store.takeCeremony(ctx, id, kind, userEmail)
	if err != nil {
		return nil, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("decoding ceremony: %w", err)
	}
	return &session, nil
}

// BeginRegistration starts the WebAuthn registration ceremony and returns the
// browser options plus the ceremony ID to present when finishing.
func (s *Service) BeginRegistration(ctx context.Context, userEmail string) (*protocol.CredentialCreation, string, error) {
	user, err := s.loadUser(ctx, userEmail)
	if err != nil {
		return nil, "", err
	}

	// Stops the same authenticator being enrolled twice for this account.
	exclude := make([]protocol.CredentialDescriptor, 0, len(user.credentials))
	for _, c := range user.credentials {
		exclude = append(exclude, c.Descriptor())
	}

	creation, session, err := s.webauthn.BeginRegistration(user, webauthn.WithExclusions(exclude))
	if err != nil {
		return nil, "", fmt.Errorf("beginning registration: %w", err)
	}

	id, err := s.saveSession(ctx, ceremonyRegistration, userEmail, session)
	if err != nil {
		return nil, "", fmt.Errorf("storing ceremony: %w", err)
	}
	return creation, id, nil
}

// FinishRegistration completes the registration ceremony.  beforeStore, when
// set, runs once the response has been verified and before the credential is
// saved; returning an error stops it being saved (spending an invite).
func (s *Service) FinishRegistration(ctx context.Context, userEmail, ceremonyID string, r *http.Request, label string, beforeStore func() error) (*WebAuthnCredential, error) {
	session, err := s.takeSession(ctx, ceremonyID, ceremonyRegistration, userEmail)
	if err != nil {
		return nil, err
	}

	user, err := s.loadUser(ctx, userEmail)
	if err != nil {
		return nil, err
	}

	cred, err := s.webauthn.FinishRegistration(user, *session, r)
	if err != nil {
		return nil, fmt.Errorf("finishing registration: %w", err)
	}

	if beforeStore != nil {
		if err := beforeStore(); err != nil {
			return nil, err
		}
	}

	if err := s.store.CreateUser(ctx, cred, userEmail, label); err != nil {
		return nil, fmt.Errorf("storing credential: %w", err)
	}

	storedCred, err := s.store.GetCredential(ctx, hex.EncodeToString(cred.ID))
	if err != nil {
		return nil, fmt.Errorf("getting stored credential: %w", err)
	}
	return storedCred, nil
}

// BeginLogin starts the login ceremony and returns the browser options plus
// the ceremony ID to present when finishing.
func (s *Service) BeginLogin(ctx context.Context, userEmail string) (*protocol.CredentialAssertion, string, error) {
	user, err := s.loadUser(ctx, userEmail)
	if err != nil {
		return nil, "", err
	}
	if len(user.credentials) == 0 {
		return nil, "", ErrNoCredentials
	}

	assertion, session, err := s.webauthn.BeginLogin(user)
	if err != nil {
		return nil, "", fmt.Errorf("beginning login: %w", err)
	}

	id, err := s.saveSession(ctx, ceremonyLogin, userEmail, session)
	if err != nil {
		return nil, "", fmt.Errorf("storing ceremony: %w", err)
	}
	return assertion, id, nil
}

// decoyShapes are the key ID lengths and transports a decoy can have, so that
// decoys do not all look alike.
var decoyShapes = []struct {
	idLength   int
	transports []protocol.AuthenticatorTransport
}{
	{16, []protocol.AuthenticatorTransport{protocol.Internal, protocol.Hybrid}},
	{16, []protocol.AuthenticatorTransport{protocol.Hybrid, protocol.Internal}},
	{32, []protocol.AuthenticatorTransport{protocol.Internal, protocol.Hybrid}},
	{32, []protocol.AuthenticatorTransport{protocol.Hybrid, protocol.Internal}},
	{32, []protocol.AuthenticatorTransport{protocol.USB}},
	{64, []protocol.AuthenticatorTransport{protocol.NFC, protocol.USB}},
}

// decoyCredentials invents the keys an address has when it has none: one or two,
// always the same ones for that address.  Nothing can sign for them.
func (s *Service) decoyCredentials(userEmail string) []webauthn.Credential {
	block := func(n byte) []byte {
		mac := hmac.New(sha256.New, s.decoySecret)
		mac.Write([]byte(userEmail))
		mac.Write([]byte{0, n})
		return mac.Sum(nil)
	}
	choice := block(0)
	creds := make([]webauthn.Credential, 1+int(choice[0]%4)/3)
	for i := range creds {
		shape := decoyShapes[int(choice[i+1])%len(decoyShapes)]
		id := append(block(byte(2*i+1)), block(byte(2*i+2))...)
		creds[i] = webauthn.Credential{ID: id[:shape.idLength], Transport: shape.transports}
	}
	return creds
}

// BeginDecoyLogin answers for an address that cannot sign in with a key as
// BeginLogin answers for one that can, by the same steps, so that the reply does
// not show which accounts have a key.  The ceremony it starts can never finish:
// FinishLogin finds no real key among the ones it offered.
func (s *Service) BeginDecoyLogin(ctx context.Context, userEmail string) (*protocol.CredentialAssertion, string, error) {
	user := &WebAuthnUser{
		email:       userEmail,
		userHandle:  generateUserHandle(userEmail),
		userName:    userEmail,
		displayName: userEmail,
		credentials: s.decoyCredentials(userEmail),
	}
	assertion, session, err := s.webauthn.BeginLogin(user)
	if err != nil {
		return nil, "", fmt.Errorf("beginning login: %w", err)
	}
	id, err := s.saveSession(ctx, ceremonyLogin, userEmail, session)
	if err != nil {
		return nil, "", fmt.Errorf("storing ceremony: %w", err)
	}
	return assertion, id, nil
}

// FinishLogin completes the login ceremony and returns the credential's ID.
func (s *Service) FinishLogin(ctx context.Context, userEmail, ceremonyID string, r *http.Request) (string, error) {
	session, err := s.takeSession(ctx, ceremonyID, ceremonyLogin, userEmail)
	if err != nil {
		return "", err
	}

	user, err := s.loadUser(ctx, userEmail)
	if err != nil {
		return "", err
	}

	cred, err := s.webauthn.FinishLogin(user, *session, r)
	if err != nil {
		return "", fmt.Errorf("finishing login: %w", err)
	}
	if cred.Authenticator.CloneWarning {
		return "", ErrClonedAuthenticator
	}

	credID := hex.EncodeToString(cred.ID)
	if err := s.store.UpdateCounter(ctx, credID, cred.Authenticator.SignCount); err != nil {
		return "", fmt.Errorf("updating counter: %w", err)
	}
	return credID, nil
}

// ListUserCredentials returns all WebAuthn credentials for a user
func (s *Service) ListUserCredentials(ctx context.Context, userEmail string) ([]WebAuthnCredential, error) {
	return s.store.GetUserCredentials(ctx, userEmail)
}

// DeleteUserCredential removes a credential when it belongs to the address.
// Someone else's credential is reported as not found, not as forbidden, so the
// call cannot be used to discover which credential IDs exist.
func (s *Service) DeleteUserCredential(ctx context.Context, userEmail, credentialID string) error {
	cred, err := s.store.GetCredential(ctx, credentialID)
	if err != nil {
		return err
	}
	if cred.UserEmail != userEmail {
		return ErrCredentialNotFound
	}
	return s.store.DeleteCredential(ctx, credentialID)
}

// CreateInvite issues a one-time enrollment token for an address, for ttl.
func (s *Service) CreateInvite(ctx context.Context, userEmail string, ttl time.Duration) (string, error) {
	return s.store.CreateInvite(ctx, userEmail, ttl)
}

// InviteEmail returns the address a live invite belongs to.
func (s *Service) InviteEmail(ctx context.Context, token string) (string, error) {
	return s.store.InviteEmail(ctx, token)
}

// ConsumeInvite spends an invite.
func (s *Service) ConsumeInvite(ctx context.Context, token string) error {
	return s.store.ConsumeInvite(ctx, token)
}

// WebAuthnUser implements the webauthn.User interface for our user model
type WebAuthnUser struct {
	email       string
	userHandle  []byte
	userName    string
	displayName string
	credentials []webauthn.Credential
}

// NewWebAuthnUser creates a new WebAuthnUser
func NewWebAuthnUser(email string, credentials []WebAuthnCredential) (*WebAuthnUser, error) {
	creds := make([]webauthn.Credential, len(credentials))
	for i := range credentials {
		cred, err := credentials[i].ToWebAuthnCredential()
		if err != nil {
			return nil, err
		}
		creds[i] = cred
	}
	return &WebAuthnUser{
		email:       email,
		userHandle:  generateUserHandle(email),
		userName:    email,
		displayName: email,
		credentials: creds,
	}, nil
}

// WebAuthnID returns the user handle
func (u *WebAuthnUser) WebAuthnID() []byte {
	return u.userHandle
}

// WebAuthnName returns the user name
func (u *WebAuthnUser) WebAuthnName() string {
	return u.userName
}

// WebAuthnDisplayName returns the display name
func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.displayName
}

// WebAuthnCredentials returns the user's credentials
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

// generateUserHandle derives the opaque user handle.  It is stable for an
// address and carries no personal information (WebAuthn L2 §14.6.1).
func generateUserHandle(email string) []byte {
	sum := sha256.Sum256([]byte(email))
	return sum[:]
}
