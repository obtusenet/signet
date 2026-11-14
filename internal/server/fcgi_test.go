// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Minimal FastCGI RESPONDER client, just enough to drive one request:
// BEGIN_REQUEST, PARAMS, empty STDIN, then collect STDOUT until
// END_REQUEST.  Mirrors the framing the stdlib net/http/fcgi expects.
type fcgiClient struct {
	t    *testing.T
	conn net.Conn
	id   uint16
}

func fcgiDial(t *testing.T, network, address string) *fcgiClient {
	t.Helper()
	c, err := net.Dial(network, address)
	if err != nil {
		t.Fatalf("fcgi dial %s %s: %v", network, address, err)
	}
	t.Cleanup(func() { c.Close() })
	return &fcgiClient{t: t, conn: c, id: 1}
}

func (c *fcgiClient) send(typ uint8, body []byte) {
	pad := (8 - len(body)%8) % 8
	h := make([]byte, 8)
	h[0] = 1 // FCGI_VERSION
	h[1] = typ
	binary.BigEndian.PutUint16(h[2:4], c.id)
	binary.BigEndian.PutUint16(h[4:6], uint16(len(body)))
	h[6] = uint8(pad)
	if _, err := c.conn.Write(h); err != nil {
		c.t.Fatalf("fcgi write header: %v", err)
	}
	if len(body) > 0 {
		if _, err := c.conn.Write(body); err != nil {
			c.t.Fatalf("fcgi write body: %v", err)
		}
	}
	if pad > 0 {
		if _, err := c.conn.Write(make([]byte, pad)); err != nil {
			c.t.Fatalf("fcgi write pad: %v", err)
		}
	}
}

func fcgiParam(name, value string) []byte {
	// FastCGI pair encoding: both length bytes first, then the name and
	// the value (single length byte below 128; else MSB-flagged 4-byte
	// big-endian length).
	var b bytes.Buffer
	b.WriteByte(byte(len(name)))
	if l := len(value); l < 128 {
		b.WriteByte(byte(l))
	} else {
		b.WriteByte(byte(l>>24 | 0x80))
		b.WriteByte(byte(l >> 16))
		b.WriteByte(byte(l >> 8))
		b.WriteByte(byte(l))
	}
	b.WriteString(name)
	b.WriteString(value)
	return b.Bytes()
}

// get issues one GET and returns the CGI response (status line, headers,
// body) that the responder wrote to FCGI_STDOUT.
func (c *fcgiClient) get(uri, host string) (string, string) {
	// BEGIN_REQUEST: role=RESPONDER(1) big-endian, flags=0, 5 reserved bytes.
	c.send(1, []byte{0, 1, 0, 0, 0, 0, 0, 0})

	var params bytes.Buffer
	for _, kv := range [][2]string{
		{"REQUEST_METHOD", "GET"},
		{"REQUEST_URI", uri},
		{"QUERY_STRING", ""},
		{"SERVER_PROTOCOL", "HTTP/1.1"},
		{"GATEWAY_INTERFACE", "FastCGI/1.0"},
		{"SERVER_NAME", host},
		{"SERVER_PORT", "80"},
		{"REMOTE_ADDR", "127.0.0.1"},
		{"REMOTE_PORT", "12345"},
		{"HTTP_HOST", host},
		{"CONTENT_LENGTH", "0"},
	} {
		params.Write(fcgiParam(kv[0], kv[1]))
	}
	c.send(4, params.Bytes()) // FCGI_PARAMS
	c.send(4, nil)            // end of params
	c.send(5, nil)            // FCGI_STDIN empty

	var stdout bytes.Buffer
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(c.conn, hdr); err != nil {
			c.t.Fatalf("read record header: %v", err)
		}
		clen := int(binary.BigEndian.Uint16(hdr[4:6]))
		padlen := int(hdr[6])
		body := make([]byte, clen+padlen)
		if clen+padlen > 0 {
			if _, err := io.ReadFull(c.conn, body); err != nil {
				c.t.Fatalf("read record body: %v", err)
			}
		}
		switch hdr[1] {
		case 6: // FCGI_STDOUT
			stdout.Write(body[:clen])
		case 7: // FCGI_STDERR
			c.t.Logf("fcgi stderr: %s", body[:clen])
		case 3: // FCGI_END_REQUEST
			out := stdout.String()
			i := strings.Index(out, "\r\n\r\n")
			if i < 0 {
				return out, ""
			}
			return out[:i], out[i+4:]
		}
	}
}

func TestServeOverFCGISocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fcgi.sock")
	s := newSocketTestServer(t, path)
	s.cfg.Protocol = "fastcgi"
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.Start() }()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if fi, err := os.Stat(path); err == nil {
			if perm := fi.Mode().Perm(); perm != 0660 {
				t.Errorf("fcgi socket mode = %o, want 660", perm)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fcgi socket never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}

	c := fcgiDial(t, "unix", path)
	headers, body := c.get("/health", "unix")
	if !strings.Contains(headers, "Status: 200") {
		t.Fatalf("status line: %q", headers)
	}
	if !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("body: %q", body)
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
		t.Fatal("fcgi socket file left behind after shutdown")
	}
}

func TestServeOverFCGITCP(t *testing.T) {
	s := newSocketTestServer(t, "127.0.0.1:0")
	s.cfg.Protocol = "fastcgi"
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.Start() }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	}()

	listener := func() net.Listener {
		s.srvMu.Lock()
		defer s.srvMu.Unlock()
		return s.fcgiLn
	}
	deadline := time.Now().Add(3 * time.Second)
	for listener() == nil {
		if time.Now().After(deadline) {
			t.Fatal("listener never bound")
		}
		time.Sleep(5 * time.Millisecond)
	}
	addr := listener().Addr().String()

	c := fcgiDial(t, "tcp", addr)
	headers, body := c.get("/health", "localhost")
	if !strings.Contains(headers, "Status: 200") || !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("fcgi over tcp: headers=%q body=%q", headers, body)
	}
}

// Over FastCGI the web server reports the path whole, in REQUEST_URI, as httpd(8)
// does, so base_path works there as over HTTP.
func TestFCGIUnderBasePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fcgi.sock")
	s := newSocketTestServer(t, path)
	s.cfg.Protocol = "fastcgi"
	s.cfg.BasePath = "/auth"
	go func() { _ = s.Start() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fcgi socket never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for uri, want := range map[string]string{"/auth/health": "Status: 200", "/health": "Status: 404"} {
		headers, _ := fcgiDial(t, "unix", path).get(uri, "unix")
		if !strings.Contains(headers, want) {
			t.Errorf("%s: %q, want %s", uri, headers, want)
		}
	}
}
