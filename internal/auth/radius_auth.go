// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/obtusenet/signet/internal/claims"
	"github.com/obtusenet/signet/internal/config"
	"github.com/obtusenet/signet/internal/radius"
)

// MethodRadius is how a session records a sign-in a RADIUS server accepted.
const MethodRadius = "radius"

// ErrRadiusUnavailable reports that no RADIUS server gave a valid answer, so
// the password could not be checked.  The sign-in fails closed.
var ErrRadiusUnavailable = errors.New("the RADIUS servers could not check the password")

// RadiusChallenge reports that the server wants one more answer before it
// decides (Access-Challenge): Message is its prompt, and State and Server must
// go back with the answer.
type RadiusChallenge struct {
	UserName string
	Message  string
	State    []byte
	Server   int
}

func (e *RadiusChallenge) Error() string {
	return "the RADIUS server asks for one more answer"
}

// RadiusSource checks the passwords of accounts users.csv does not have.
type RadiusSource struct {
	client *radius.Client
	groups []radius.GroupAttribute
	nasID  string
	broken error // why it cannot be used; every sign-in fails closed
}

// BrokenRadiusSource is RADIUS switched on but unusable: every sign-in through
// it fails closed with ErrRadiusUnavailable and err.
func BrokenRadiusSource(err error) *RadiusSource {
	return &RadiusSource{broken: err}
}

// NewRadiusSource makes the client from the radius settings, reading each
// server's secret_file.  It contacts no server.
func NewRadiusSource(cfg config.RadiusConfig) (*RadiusSource, error) {
	rc := radius.Config{
		NASIdentifier:               cfg.NASIdentifier,
		Timeout:                     time.Duration(cfg.TimeoutSec) * time.Second,
		Retries:                     cfg.Retries,
		RequireMessageAuthenticator: cfg.RequireMessageAuthenticator,
	}
	for _, s := range cfg.Servers {
		secret := s.Secret
		if s.SecretFile != "" {
			b, err := os.ReadFile(s.SecretFile)
			if err != nil {
				return nil, fmt.Errorf("radius server %s: reading secret_file: %w", s.Address, err)
			}
			secret = strings.TrimRight(string(b), "\r\n")
			if secret == "" {
				return nil, fmt.Errorf("radius server %s: secret_file %s is empty", s.Address, s.SecretFile)
			}
		}
		rc.Servers = append(rc.Servers, radius.Server{Address: s.Address, Secret: []byte(secret), Auth: s.Auth})
	}
	client, err := radius.NewClient(rc)
	if err != nil {
		return nil, err
	}
	src := &RadiusSource{client: client, nasID: cfg.NASIdentifier}
	for _, a := range cfg.GroupAttributes {
		ga, err := radius.ParseGroupAttribute(a)
		if err != nil {
			return nil, err
		}
		src.groups = append(src.groups, ga)
	}
	return src, nil
}

// SetRadius turns RADIUS on for addresses users.csv does not have, or off with
// nil.
func (pa *PasswordAuth) SetRadius(src *RadiusSource) {
	pa.radius = src
}

// RadiusEnabled reports whether RADIUS checks unknown addresses.
func (pa *PasswordAuth) RadiusEnabled() bool {
	return pa.radius != nil
}

// AnswerRadiusChallenge sends the answer to a challenge, to the server that
// asked, under the same limits as a password.  It answers as Authenticate
// does, and may bring another challenge.
func (pa *PasswordAuth) AnswerRadiusChallenge(ctx context.Context, user, source, answer string, state []byte, server int) (*http.Cookie, error) {
	if pa.radius == nil {
		return nil, ErrRadiusUnavailable
	}
	done, err := pa.admit(ctx, user, source)
	if err != nil {
		return nil, err
	}
	return pa.radiusSignIn(ctx, done, radius.Request{
		UserName: user, Password: answer, CallingStationID: source, State: state, Server: server,
	})
}

// radiusSignIn asks the servers and acts on the answer.  done ends the attempt
// admit began.
//
// A reject counts as a failed sign-in.  A challenge counts against the rate
// limits but not the lockout, since the password may well have been right.  No
// answer counts as nothing: an outage is not the person's failure.
func (pa *PasswordAuth) radiusSignIn(ctx context.Context, done func(bool), req radius.Request) (*http.Cookie, error) {
	user := req.UserName
	if pa.radius.broken != nil {
		done(true)
		return nil, fmt.Errorf("%w: %v", ErrRadiusUnavailable, pa.radius.broken)
	}
	res, err := pa.radius.client.Authenticate(ctx, req)
	switch {
	case errors.Is(err, radius.ErrPasswordTooLong):
		pa.countFailure(ctx, user)
		done(false)
		return nil, fmt.Errorf("invalid email or password: %w", err)
	case err != nil:
		done(true)
		return nil, fmt.Errorf("%w: %v", ErrRadiusUnavailable, err)
	}

	server := res.Server
	switch res.Outcome {
	case radius.Reject:
		pa.countFailure(ctx, user)
		done(false)
		if res.Message != "" {
			return nil, fmt.Errorf("invalid email or password: RADIUS server %d rejected it: %q", server+1, res.Message)
		}
		return nil, fmt.Errorf("invalid email or password: RADIUS server %d rejected it", server+1)
	case radius.Challenge:
		done(false)
		return nil, &RadiusChallenge{UserName: user, Message: res.Message, State: res.State, Server: server}
	}

	done(true)
	if pa.rateLimiter != nil {
		pa.rateLimiter.Reset(user)
	}
	groups, skipped := radius.Groups(res.Reply, pa.radius.groups)
	if skipped > 0 && pa.logger != nil {
		pa.logger.Warn(fmt.Sprintf("RADIUS accepted %s with %d group values that are not text; they were left out", user, skipped))
	}
	facts := claims.Facts{Source: claims.SourceRadius, Radius: &claims.RadiusFacts{
		NASIdentifier: pa.radius.nasID,
		Groups:        groups,
		Attributes:    radius.Describe(res.Reply),
	}}
	if facts.Radius.Groups == nil {
		facts.Radius.Groups = []string{}
	}
	if pa.secondStep != nil {
		pending, step, err := pa.secondStep(ctx, user, MethodRadius, facts)
		if err != nil {
			return nil, err
		}
		if pending != "" {
			return nil, &SecondStepRequired{Pending: pending, Step: step}
		}
	}
	return pa.CreateSessionFacts(ctx, user, MethodRadius, facts)
}
