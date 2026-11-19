// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package claims

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"

	"github.com/obtusenet/signet/internal/config"
	"github.com/obtusenet/signet/internal/logging"
	"github.com/obtusenet/signet/internal/radius"
)

// ClaimsHook represents the external claims hook
type ClaimsHook struct {
	cfg     config.ClaimsHookConfig
	logger  *logging.Logger
	timeout time.Duration
}

// ClaimRequest is sent to the child process.  It carries no session token: the
// token is a bearer secret, and a hook decides from the account alone.
type ClaimRequest struct {
	Type   string       `json:"type"`
	Email  string       `json:"email"`
	Source string       `json:"source"`
	Radius *RadiusFacts `json:"radius,omitempty"`
}

// Sources of an account, as Facts.Source and the hook's "source" name them.
const (
	SourceLocal  = "local"  // users.csv
	SourceRadius = "radius" // a RADIUS server accepted it
)

// Facts are what a sign-in learned about the account besides who it is.  A
// session keeps them, so a claims refresh sees what the sign-in saw.
type Facts struct {
	Source string       `json:"source"`
	Radius *RadiusFacts `json:"radius,omitempty"`
}

// RadiusFacts are what a RADIUS server's Access-Accept said.
type RadiusFacts struct {
	NASIdentifier string                 `json:"nas_identifier"`
	Groups        []string               `json:"groups"`
	Attributes    []radius.AttributeView `json:"attributes"`
	// The reply's Session-Timeout and Idle-Timeout, in seconds; 0 when it
	// had none.  The session's limits are these, up to the radius ceilings.
	SessionTimeout uint32 `json:"session_timeout,omitempty"`
	IdleTimeout    uint32 `json:"idle_timeout,omitempty"`
}

// LocalFacts are the facts of a users.csv account: none.
var LocalFacts = Facts{Source: SourceLocal}

// ParseFacts reads facts a session or a sign-in step stored; "" is a local
// account, as sessions made before RADIUS support are.
func ParseFacts(s string) (Facts, error) {
	if s == "" {
		return LocalFacts, nil
	}
	var f Facts
	if err := json.Unmarshal([]byte(s), &f); err != nil {
		return LocalFacts, fmt.Errorf("reading sign-in facts: %w", err)
	}
	if f.Source == "" {
		f.Source = SourceLocal
	}
	return f, nil
}

// String encodes facts for storing; a local account's are "".
func (f Facts) String() string {
	if f.Source == "" || f.Source == SourceLocal {
		return ""
	}
	b, err := json.Marshal(f)
	if err != nil {
		return ""
	}
	return string(b)
}

// DefaultClaims are the claims without a hook: a RADIUS account's groups, and
// nothing for a local one.
func (f Facts) DefaultClaims() map[string]interface{} {
	if f.Radius != nil {
		groups := f.Radius.Groups
		if groups == nil {
			groups = []string{}
		}
		return map[string]interface{}{"groups": groups}
	}
	return map[string]interface{}{}
}

// ClaimResponse is received from the child process
type ClaimResponse struct {
	Type   string                 `json:"type"`
	Claims map[string]interface{} `json:"claims,omitempty"`
	Error  string                 `json:"error,omitempty"`
}

// NewClaimsHook creates a new claims hook
func NewClaimsHook(cfg config.ClaimsHookConfig, logger *logging.Logger) *ClaimsHook {
	return &ClaimsHook{
		cfg:     cfg,
		logger:  logger,
		timeout: time.Duration(cfg.TimeoutSec) * time.Second,
	}
}

// GetClaims answers the claims of a local account.
func (h *ClaimsHook) GetClaims(ctx context.Context, email string) (map[string]interface{}, error) {
	return h.ClaimsFor(ctx, email, LocalFacts)
}

// ClaimsFor answers an account's claims: the hook's, when it is on, and the
// facts' default claims otherwise.  The hook is given the facts.
func (h *ClaimsHook) ClaimsFor(ctx context.Context, email string, facts Facts) (map[string]interface{}, error) {
	if h == nil || !h.cfg.Enabled {
		return facts.DefaultClaims(), nil
	}
	if facts.Source == "" {
		facts.Source = SourceLocal
	}

	// Create request
	req := ClaimRequest{
		Type:   "claim_request",
		Email:  email,
		Source: facts.Source,
		Radius: facts.Radius,
	}

	// Marshal request
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return h.failedClaims(fmt.Errorf("marshaling claim request: %w", err))
	}
	// The protocol is JSON over lines; a hook using read(1) or readline()
	// sees nothing until the newline arrives.
	reqBytes = append(reqBytes, '\n')

	// Start the child process
	cmd := exec.CommandContext(ctx, h.cfg.Program)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	// Its own process group, so what the hook started goes when it does.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}

	// Create pipes
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return h.failedClaims(fmt.Errorf("creating stdin pipe: %w", err))
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return h.failedClaims(fmt.Errorf("creating stdout pipe: %w", err))
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		return h.failedClaims(fmt.Errorf("starting hook process: %w", err))
	}

	// Once there is an outcome the hook has nothing left to give, and waiting
	// for it to exit would hold the login open with no limit.  The group stays
	// valid until Wait, even if the hook has already exited.
	stop := func() {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		cmd.Wait()
	}

	// Write request to stdin
	if _, err := stdin.Write(reqBytes); err != nil {
		stop()
		return h.failedClaims(fmt.Errorf("writing to stdin: %w", err))
	}
	stdin.Close()

	// Read response from stdout with timeout
	respCh := make(chan *ClaimResponse, 1)
	errCh := make(chan error, 1)

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			var resp ClaimResponse
			if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
				errCh <- fmt.Errorf("unmarshaling response: %w", err)
				return
			}

			if resp.Type == "claim_response" {
				respCh <- &resp
				return
			} else if resp.Type == "claim_error" {
				errCh <- errors.New(resp.Error)
				return
			}
		}
		if err := scanner.Err(); err != nil {
			errCh <- fmt.Errorf("reading stdout: %w", err)
			return
		}
		// A hook that exits without answering is a failure now, not after
		// the full timeout.
		errCh <- errors.New("hook exited without a response")
	}()

	// Wait for response or timeout
	select {
	case resp := <-respCh:
		stop()
		return resp.Claims, nil
	case err := <-errCh:
		stop()
		return h.failedClaims(err)
	case <-time.After(h.timeout):
		stop()
		return h.failedClaims(errors.New("hook timed out"))
	case <-ctx.Done():
		stop()
		return h.failedClaims(ctx.Err())
	}
}

// failedClaims applies on_failure to a hook failure: fail-open answers empty
// claims and no error, fail-closed answers the error so the caller refuses
// the login.
func (h *ClaimsHook) failedClaims(err error) (map[string]interface{}, error) {
	if hookErr := h.handleHookFailure(err); hookErr != nil {
		return nil, hookErr
	}
	return map[string]interface{}{}, nil
}

// handleHookFailure handles hook failures based on on_failure config
func (h *ClaimsHook) handleHookFailure(err error) error {
	h.logger.Warn(fmt.Sprintf("claims hook failure: %v", err))

	if h.cfg.OnFailure == "fail-open" {
		h.logger.Info("claims hook failing open, returning empty claims")
		return nil
	}

	// fail-closed (default)
	return err
}

// Reload re-reads the hook configuration
func (h *ClaimsHook) Reload(cfg config.ClaimsHookConfig) {
	h.cfg = cfg
	h.timeout = time.Duration(cfg.TimeoutSec) * time.Second
	h.logger.Info("claims hook configuration reloaded")
}

// IsEnabled returns whether the claims hook is enabled
func (h *ClaimsHook) IsEnabled() bool {
	return h.cfg.Enabled
}

// GetConfig returns the current configuration
func (h *ClaimsHook) GetConfig() config.ClaimsHookConfig {
	return h.cfg
}
