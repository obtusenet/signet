// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"fmt"

	"github.com/obtusenet/signet/internal/backend/csv"
)

// ErrAccountLocked reports an account carrying the locked flag.
var ErrAccountLocked = errors.New("account is locked")

// ErrAccountPending reports a self-registered account still awaiting approval.
var ErrAccountPending = errors.New("account is awaiting approval")

// ErrClaimsRefused reports that the credentials were good but the claims hook
// failed or denied the user under on_failure: fail-closed, so no session may
// be issued.
var ErrClaimsRefused = errors.New("refused by the claims hook")

// AccountPolicy decides whether an account may sign in at all.  Every
// authentication method asks it, so a credential only ever proves who the
// caller is, never that the account is allowed in.
type AccountPolicy struct {
	backend         *csv.Backend
	requireApproval bool
}

// NewAccountPolicy creates a policy over the user backend.  requireApproval
// mirrors self_registration_approval: required.
func NewAccountPolicy(backend *csv.Backend, requireApproval bool) *AccountPolicy {
	return &AccountPolicy{backend: backend, requireApproval: requireApproval}
}

// Resolve answers the address as its account has it, when one matches apart from
// case, and otherwise address unchanged.  Every place an address comes in from a
// request resolves it before using it, so one account is never two.
func (p *AccountPolicy) Resolve(address string) string {
	if p == nil {
		return address
	}
	return p.backend.Resolve(address)
}

// Check returns the user when the account may sign in.  It answers
// csv.ErrUserNotFound for an unknown address, ErrAccountLocked for a locked
// account and ErrAccountPending for a self-registered account nobody has
// approved.  Accounts an administrator created without self_registered need
// no approval.
func (p *AccountPolicy) Check(email string) (*csv.User, error) {
	user, err := p.backend.GetUser(email)
	if err != nil {
		return nil, err
	}
	if user.HasFlag(csv.FlagLocked) {
		return nil, fmt.Errorf("%s: %w", email, ErrAccountLocked)
	}
	if p.requireApproval && user.HasFlag(csv.FlagSelfRegistered) && !user.HasFlag(csv.FlagApproved) {
		return nil, fmt.Errorf("%s: %w", email, ErrAccountPending)
	}
	return user, nil
}
