// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package claims

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/config"
	"github.com/obtusenet/signet/internal/logging"
	"github.com/obtusenet/signet/internal/radius"
)

func TestClaimsHookDisabled(t *testing.T) {
	logger, err := logging.New(false, "debug")
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	cfg := config.ClaimsHookConfig{
		Enabled:    false,
		Program:    "",
		TimeoutSec: 5,
		OnFailure:  "fail-closed",
	}

	hook := NewClaimsHook(cfg, logger)

	claims, err := hook.GetClaims(context.Background(), "test@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if claims == nil {
		t.Fatal("expected empty claims, got nil")
	}

	if len(claims) != 0 {
		t.Errorf("expected 0 claims, got %d", len(claims))
	}
}

func TestClaimsHookEnabled(t *testing.T) {
	logger, err := logging.New(false, "debug")
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Create a simple test script that responds to claim requests
	tmpDir, err := os.MkdirTemp("", "signet-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	scriptPath := filepath.Join(tmpDir, "hook.sh")
	scriptContent := `#!/bin/sh
# Read claim request
read line
echo '{"type":"claim_response","claims":{"role":"admin","dept":"engineering"}}'
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}

	cfg := config.ClaimsHookConfig{
		Enabled:    true,
		Program:    scriptPath,
		TimeoutSec: 5,
		OnFailure:  "fail-closed",
	}

	hook := NewClaimsHook(cfg, logger)

	claims, err := hook.GetClaims(context.Background(), "test@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if claims["role"] != "admin" {
		t.Errorf("expected role=admin, got %v", claims["role"])
	}

	if claims["dept"] != "engineering" {
		t.Errorf("expected dept=engineering, got %v", claims["dept"])
	}
}

func TestClaimsHookTimeout(t *testing.T) {
	logger, err := logging.New(false, "debug")
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Create a script that hangs
	tmpDir, err := os.MkdirTemp("", "signet-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	scriptPath := filepath.Join(tmpDir, "hook.sh")
	scriptContent := `#!/bin/sh
# Hang forever
sleep 3600
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}

	cfg := config.ClaimsHookConfig{
		Enabled:    true,
		Program:    scriptPath,
		TimeoutSec: 1, // 1 second timeout
		OnFailure:  "fail-closed",
	}

	hook := NewClaimsHook(cfg, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = hook.GetClaims(ctx, "test@example.com")
	if err == nil {
		t.Fatal("expected error due to timeout, got nil")
	}

	if !strings.Contains(err.Error(), "hook timed out") {
		t.Errorf("expected timeout error, got: %v", err)
	}
}

func TestClaimsHookFailOpen(t *testing.T) {
	logger, err := logging.New(false, "debug")
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Create a script that returns claim_error and exits
	tmpDir, err := os.MkdirTemp("", "signet-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	scriptPath := filepath.Join(tmpDir, "hook.sh")
	scriptContent := `#!/bin/sh
# Read claim request
read line
# Return claim_error and exit
echo '{"type":"claim_error","error":"test error"}'
exit 0
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}

	cfg := config.ClaimsHookConfig{
		Enabled:    true,
		Program:    scriptPath,
		TimeoutSec: 5,
		OnFailure:  "fail-open",
	}

	hook := NewClaimsHook(cfg, logger)

	// Should return empty claims, not error
	claims, err := hook.GetClaims(context.Background(), "test@example.com")
	if err != nil {
		t.Fatalf("expected empty claims, got error: %v", err)
	}

	if claims == nil {
		t.Fatal("expected empty claims, got nil")
	}

	if len(claims) != 0 {
		t.Errorf("expected 0 claims, got %d", len(claims))
	}
}

func TestClaimsHookFailClosed(t *testing.T) {
	logger, err := logging.New(false, "debug")
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Create a script that returns claim_error and exits
	tmpDir, err := os.MkdirTemp("", "signet-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	scriptPath := filepath.Join(tmpDir, "hook.sh")
	scriptContent := `#!/bin/sh
# Read claim request
read line
# Return claim_error and exit
echo '{"type":"claim_error","error":"test error"}'
exit 0
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}

	cfg := config.ClaimsHookConfig{
		Enabled:    true,
		Program:    scriptPath,
		TimeoutSec: 5,
		OnFailure:  "fail-closed",
	}

	hook := NewClaimsHook(cfg, logger)

	// Should return error
	_, err = hook.GetClaims(context.Background(), "test@example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestClaimsHookInvalidProgram(t *testing.T) {
	logger, err := logging.New(false, "debug")
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	cfg := config.ClaimsHookConfig{
		Enabled:    true,
		Program:    "/nonexistent/hook.sh",
		TimeoutSec: 5,
		OnFailure:  "fail-closed",
	}

	hook := NewClaimsHook(cfg, logger)

	_, err = hook.GetClaims(context.Background(), "test@example.com")
	if err == nil {
		t.Fatal("expected error for nonexistent program, got nil")
	}

	if !strings.Contains(err.Error(), "starting hook process") {
		t.Errorf("expected 'starting hook process' error, got: %v", err)
	}
}

func TestClaimsHookInvalidJSON(t *testing.T) {
	logger, err := logging.New(false, "debug")
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Create a script that returns invalid JSON
	tmpDir, err := os.MkdirTemp("", "signet-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	scriptPath := filepath.Join(tmpDir, "hook.sh")
	scriptContent := `#!/bin/sh
# Read and discard input
read line
# Return invalid JSON
echo 'not valid json'
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}

	cfg := config.ClaimsHookConfig{
		Enabled:    true,
		Program:    scriptPath,
		TimeoutSec: 5,
		OnFailure:  "fail-closed",
	}

	hook := NewClaimsHook(cfg, logger)

	_, err = hook.GetClaims(context.Background(), "test@example.com")
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestClaimsHookClaimError(t *testing.T) {
	logger, err := logging.New(false, "debug")
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Create a script that returns claim_error
	tmpDir, err := os.MkdirTemp("", "signet-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	scriptPath := filepath.Join(tmpDir, "hook.sh")
	scriptContent := `#!/bin/sh
# Read claim request
read line
# Return claim_error
echo '{"type":"claim_error","error":"something went wrong"}'
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}

	cfg := config.ClaimsHookConfig{
		Enabled:    true,
		Program:    scriptPath,
		TimeoutSec: 5,
		OnFailure:  "fail-closed",
	}

	hook := NewClaimsHook(cfg, logger)

	_, err = hook.GetClaims(context.Background(), "test@example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "something went wrong") {
		t.Errorf("expected 'something went wrong' error, got: %v", err)
	}
}

func TestClaimsHookReload(t *testing.T) {
	logger, err := logging.New(false, "debug")
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	cfg := config.ClaimsHookConfig{
		Enabled:    false,
		Program:    "",
		TimeoutSec: 5,
		OnFailure:  "fail-closed",
	}

	hook := NewClaimsHook(cfg, logger)

	if hook.IsEnabled() {
		t.Error("expected hook to be disabled")
	}

	newCfg := config.ClaimsHookConfig{
		Enabled:    true,
		Program:    "/bin/echo",
		TimeoutSec: 10,
		OnFailure:  "fail-open",
	}

	hook.Reload(newCfg)

	if !hook.IsEnabled() {
		t.Error("expected hook to be enabled after reload")
	}

	if hook.GetConfig().TimeoutSec != 10 {
		t.Errorf("expected timeout 10, got %d", hook.GetConfig().TimeoutSec)
	}
}

// The request names the account and its source, and nothing else: the session
// token is a bearer secret and never reaches the hook.
func TestClaimRequestJSON(t *testing.T) {
	data, err := json.Marshal(ClaimRequest{Type: "claim_request", Email: "test@example.com", Source: SourceLocal})
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if want := `{"type":"claim_request","email":"test@example.com","source":"local"}`; string(data) != want {
		t.Errorf("got %s, want %s", data, want)
	}
}

// A RADIUS account's request carries what the server said.
func TestClaimRequestRadius(t *testing.T) {
	f := Facts{Source: SourceRadius, Radius: &RadiusFacts{
		NASIdentifier: "wiki", Groups: []string{"wiki-admins"},
		Attributes: []radius.AttributeView{{Type: 11, Name: "Filter-Id", Value: "wiki-admins"}},
	}}
	data, err := json.Marshal(ClaimRequest{Type: "claim_request", Email: "jdoe", Source: f.Source, Radius: f.Radius})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"claim_request","email":"jdoe","source":"radius","radius":{"nas_identifier":"wiki","groups":["wiki-admins"],"attributes":[{"type":11,"name":"Filter-Id","value":"wiki-admins"}]}}`
	if string(data) != want {
		t.Errorf("got  %s\nwant %s", data, want)
	}
}

func TestFacts(t *testing.T) {
	if LocalFacts.String() != "" {
		t.Error("local facts are stored as something")
	}
	if f, err := ParseFacts(""); err != nil || f.Source != SourceLocal || len(f.DefaultClaims()) != 0 {
		t.Errorf("empty facts: %+v, %v", f, err)
	}
	r := Facts{Source: SourceRadius, Radius: &RadiusFacts{NASIdentifier: "wiki"}}
	back, err := ParseFacts(r.String())
	if err != nil || back.Source != SourceRadius || back.Radius.NASIdentifier != "wiki" {
		t.Errorf("round trip: %+v, %v", back, err)
	}
	if g, ok := back.DefaultClaims()["groups"].([]string); !ok || g == nil || len(g) != 0 {
		t.Errorf("no groups should be [], got %#v", back.DefaultClaims())
	}
	if _, err := ParseFacts("{"); err == nil {
		t.Error("bad facts parsed")
	}
}

// Without a hook, a RADIUS account's claims are its groups.
func TestClaimsForWithoutHook(t *testing.T) {
	logger, err := logging.New(false, "debug")
	if err != nil {
		t.Fatal(err)
	}
	hook := NewClaimsHook(config.ClaimsHookConfig{}, logger)
	f := Facts{Source: SourceRadius, Radius: &RadiusFacts{Groups: []string{"a", "b"}}}
	got, err := hook.ClaimsFor(context.Background(), "jdoe", f)
	if err != nil {
		t.Fatal(err)
	}
	if g, _ := got["groups"].([]string); len(g) != 2 {
		t.Errorf("got %#v", got)
	}
}

func TestClaimResponseJSON(t *testing.T) {
	resp := ClaimResponse{
		Type: "claim_response",
		Claims: map[string]interface{}{
			"role": "admin",
			"dept": "engineering",
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed ClaimResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.Type != "claim_response" {
		t.Errorf("expected type=claim_response, got %s", parsed.Type)
	}

	if parsed.Claims["role"] != "admin" {
		t.Errorf("expected role=admin, got %v", parsed.Claims["role"])
	}

	if parsed.Claims["dept"] != "engineering" {
		t.Errorf("expected dept=engineering, got %v", parsed.Claims["dept"])
	}
}

// Ensure cmd is used
var _ = exec.Command

func writeHook(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hook.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// A hook using read(1) only sees the request once the newline arrives; its
// read then fails at EOF without one and the script answers nothing useful.
func TestClaimRequestEndsWithNewline(t *testing.T) {
	logger, err := logging.New(false, "error")
	if err != nil {
		t.Fatal(err)
	}
	program := writeHook(t, `read line && echo '{"type":"claim_response","claims":{"saw_line":true}}'`)
	hook := NewClaimsHook(config.ClaimsHookConfig{
		Enabled: true, Program: program, TimeoutSec: 5, OnFailure: "fail-closed",
	}, logger)

	got, err := hook.GetClaims(context.Background(), "a@b")
	if err != nil {
		t.Fatalf("GetClaims: %v", err)
	}
	if got["saw_line"] != true {
		t.Errorf("claims = %v", got)
	}
}

// A hook that exits silently must fail at once, not after the whole timeout.
func TestHookExitingSilentlyFailsFast(t *testing.T) {
	logger, err := logging.New(false, "error")
	if err != nil {
		t.Fatal(err)
	}
	hook := NewClaimsHook(config.ClaimsHookConfig{
		Enabled: true, Program: writeHook(t, "exit 0"), TimeoutSec: 30, OnFailure: "fail-closed",
	}, logger)

	start := time.Now()
	_, err = hook.GetClaims(context.Background(), "a@b")
	if err == nil {
		t.Fatal("expected an error under fail-closed")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %s", elapsed)
	}
}

// A hook that lingers must not hold the login, whatever it answered.
func TestHookIsKilledOnceThereIsAnOutcome(t *testing.T) {
	logger, err := logging.New(false, "error")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, answer string
		wantErr      bool
	}{
		{"claim_response", `{"type":"claim_response","claims":{"a":1}}`, false},
		{"claim_error", `{"type":"claim_error","error":"no"}`, true},
		{"not JSON", `not json`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			program := writeHook(t, "echo '"+tc.answer+"'\nsleep 3\n")
			hook := NewClaimsHook(config.ClaimsHookConfig{
				Enabled: true, Program: program, TimeoutSec: 30, OnFailure: "fail-closed",
			}, logger)

			start := time.Now()
			_, err := hook.GetClaims(context.Background(), "a@example.com")
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Errorf("held the login for %v", elapsed)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestKilledHookDoesNotRunOn(t *testing.T) {
	logger, err := logging.New(false, "error")
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "survived")
	program := writeHook(t, "echo '{\"type\":\"claim_response\"}'\nsleep 1\ntouch "+marker+"\n")
	hook := NewClaimsHook(config.ClaimsHookConfig{
		Enabled: true, Program: program, TimeoutSec: 30, OnFailure: "fail-closed",
	}, logger)
	if _, err := hook.GetClaims(context.Background(), "a@example.com"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Error("the hook kept running after it answered")
	}
}

// A process the hook started would otherwise run on with signet's privileges and
// nothing to wait for it.
func TestProcessesStartedByAHookGoWithIt(t *testing.T) {
	logger, err := logging.New(false, "error")
	if err != nil {
		t.Fatal(err)
	}
	for name, answer := range map[string]string{
		"after an answer": `{"type":"claim_response"}`,
		"after an error":  `{"type":"claim_error","error":"no"}`,
	} {
		t.Run(name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "survived")
			program := writeHook(t, "(sleep 1; touch "+marker+") &\necho '"+answer+"'\nsleep 30\n")
			hook := NewClaimsHook(config.ClaimsHookConfig{
				Enabled: true, Program: program, TimeoutSec: 30, OnFailure: "fail-open",
			}, logger)
			if _, err := hook.GetClaims(context.Background(), "a@example.com"); err != nil {
				t.Fatal(err)
			}
			time.Sleep(1500 * time.Millisecond)
			if _, err := os.Stat(marker); err == nil {
				t.Error("a process the hook started kept running")
			}
		})
	}
}

// A client going away has to stop the whole group too, not just the hook.
func TestCancelledRequestStopsTheProcessGroup(t *testing.T) {
	logger, err := logging.New(false, "error")
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "survived")
	program := writeHook(t, "(sleep 1; touch "+marker+") &\nsleep 30\n")
	hook := NewClaimsHook(config.ClaimsHookConfig{
		Enabled: true, Program: program, TimeoutSec: 30, OnFailure: "fail-open",
	}, logger)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := hook.GetClaims(ctx, "a@example.com"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Error("a process the hook started kept running")
	}
}

// What a hook reads on its standard input is the request line, whole.
func TestHookReadsOnlyTheAddress(t *testing.T) {
	logger, err := logging.New(false, "error")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	got := filepath.Join(dir, "request")
	script := filepath.Join(dir, "hook.sh")
	body := "#!/bin/sh\ncat > '" + got + "'\necho '{\"type\":\"claim_response\",\"claims\":{}}'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	hook := NewClaimsHook(config.ClaimsHookConfig{Enabled: true, Program: script, TimeoutSec: 5, OnFailure: "fail-closed"}, logger)
	if _, err := hook.GetClaims(context.Background(), "a@example.com"); err != nil {
		t.Fatal(err)
	}
	read, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"type\":\"claim_request\",\"email\":\"a@example.com\",\"source\":\"local\"}\n"; string(read) != want {
		t.Errorf("the hook read %q, want %q", read, want)
	}
}
