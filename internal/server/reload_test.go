// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/obtusenet/signet/internal/config"
)

func unixGet(t *testing.T, path, target string) int {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get("http://signet.example" + target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// A reload builds a new server and swaps it in on the same listener: what the new
// configuration says holds from the next request, and nothing is closed.
func TestSwapServesTheNewConfiguration(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "signet.sock")
	s := recoveryServer(t, func(c *config.Config) { c.Listen = sock })
	done := make(chan error, 1)
	go func() { done <- s.Start() }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the socket never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := unixGet(t, sock, "/health"); got != http.StatusOK {
		t.Fatalf("before: %d", got)
	}

	cfg := *s.cfg
	cfg.BasePath = "/auth"
	next := New(&cfg, s.logger, s.db, s.backend)
	s.Swap(next)
	if got := unixGet(t, sock, "/health"); got != http.StatusNotFound {
		t.Errorf("the old configuration still answers: %d", got)
	}
	if got := unixGet(t, sock, "/auth/health"); got != http.StatusOK {
		t.Errorf("the new configuration does not answer: %d", got)
	}
	if next.mailJobs != s.mailJobs {
		t.Error("the new server has a mail queue of its own, which Shutdown would not wait for")
	}
	s.srvMu.Lock()
	oldUpkeep := s.stopHousekeeping
	s.srvMu.Unlock()
	next.srvMu.Lock()
	newUpkeep := next.stopHousekeeping
	next.srvMu.Unlock()
	if oldUpkeep != nil || newUpkeep == nil {
		t.Errorf("housekeeping did not move to the new server: old %v, new %v", oldUpkeep != nil, newUpkeep != nil)
	}

	// A second reload replaces the first.
	cfg2 := cfg
	cfg2.BasePath = ""
	s.Swap(New(&cfg2, s.logger, s.db, s.backend))
	if got := unixGet(t, sock, "/health"); got != http.StatusOK {
		t.Errorf("after a second reload: %d", got)
	}
	next.srvMu.Lock()
	if next.stopHousekeeping != nil {
		t.Error("the replaced server still runs its housekeeping")
	}
	next.srvMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil && err != http.ErrServerClosed {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Shutdown")
	}
}

func TestKeepRestartOnly(t *testing.T) {
	running := config.DefaultConfig()
	running.Listen = ":9090"
	next := *running
	next.Listen = ":9091"
	next.CSVPath = "/elsewhere/users.csv"
	next.LogSyslog = !running.LogSyslog
	next.BasePath = "/auth"
	changed := config.KeepRestartOnly(running, &next)
	want := []string{"listen", "csv_path", "log_syslog"}
	if len(changed) != len(want) {
		t.Fatalf("changed %v, want %v", changed, want)
	}
	for i := range want {
		if changed[i] != want[i] {
			t.Errorf("changed %v, want %v", changed, want)
		}
	}
	if next.Listen != ":9090" || next.CSVPath != running.CSVPath || next.LogSyslog != running.LogSyslog {
		t.Error("a restart-only setting was not kept")
	}
	if next.BasePath != "/auth" {
		t.Error("a reloadable setting was put back")
	}
}
