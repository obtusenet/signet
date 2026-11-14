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
	"github.com/obtusenet/signet/internal/logging"
)

func TestListenParts(t *testing.T) {
	cases := []struct {
		addr, net_, host string
	}{
		{":9090", "tcp", ":9090"},
		{"0.0.0.0:9090", "tcp", "0.0.0.0:9090"},
		{"1.2.3.4:9000", "tcp", "1.2.3.4:9000"},
		{"9090", "tcp", ":9090"},
		{"[::]:9090", "tcp", "[::]:9090"},
		{"[fd00::5]:9090", "tcp", "[fd00::5]:9090"},
		{"/var/www/signet/signet.sock", "unix", "/var/www/signet/signet.sock"},
		{"/tmp/s", "unix", "/tmp/s"},
		{"./relative.sock", "tcp", ":./relative.sock"}, // relative paths are not sockets
	}
	for _, c := range cases {
		n, a := listenParts(c.addr)
		if n != c.net_ || a != c.host {
			t.Errorf("listenParts(%q) = %q,%q want %q,%q", c.addr, n, a, c.net_, c.host)
		}
	}
}

// newSocketTestServer builds the lightest Server that can actually Serve:
// config, logger and a mux with /health wired.
func newSocketTestServer(t *testing.T, path string) *Server {
	t.Helper()
	logger, err := logging.New(false, "error")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	s := &Server{
		cfg:    &config.Config{Listen: path},
		logger: logger,
	}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/health", s.handleHealth)
	return s
}

func TestListenUnixStaleSocketReclaimed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signet.sock")
	// Leave a stale socket behind: bind, then close without removing.
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()

	s := newSocketTestServer(t, path)
	ln2, err := s.listenUnix(path)
	if err != nil {
		t.Fatalf("stale socket not reclaimed: %v", err)
	}
	defer ln2.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0660 {
		t.Errorf("default socket mode = %o, want 660", perm)
	}
}

func TestListenUnixLiveSocketRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signet.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	s := newSocketTestServer(t, path)
	if _, err := s.listenUnix(path); err == nil {
		t.Fatal("bind over a live socket should fail")
	}
}

func TestListenUnixSocketModeConfigured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signet.sock")
	s := newSocketTestServer(t, path)
	s.cfg.SocketMode = "0666"
	ln, err := s.listenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0666 {
		t.Errorf("socket mode = %o, want 666", fi.Mode().Perm())
	}
}

func TestServeOverUnixSocketAndCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signet.sock")
	s := newSocketTestServer(t, path)
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.Start() }()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
	}}
	resp, err := client.Get("http://unix/health")
	if err != nil {
		t.Fatalf("health over socket: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status %d", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	select {
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("serve returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Shutdown")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("socket file left behind after shutdown")
	}
}
