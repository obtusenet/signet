// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package radius

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Auth methods a server can be asked with.
const (
	AuthPAP      = "pap"
	AuthMSCHAPv2 = "mschapv2"
)

// Server is one RADIUS server.
type Server struct {
	Address string // host:port
	Secret  []byte
	Auth    string // AuthPAP or AuthMSCHAPv2
}

// Config is what a Client needs.
type Config struct {
	Servers       []Server // tried in order
	NASIdentifier string   // the application (RFC 2865 §5.32)
	Timeout       time.Duration
	Retries       int // more tries per server after the first
	// RequireMessageAuthenticator drops a reply without one (RFC 3579 §3.2,
	// CVE-2024-3596).
	RequireMessageAuthenticator bool
}

// Outcome is how the server answered.
type Outcome int

const (
	Accept Outcome = iota
	Reject
	Challenge
)

func (o Outcome) String() string {
	switch o {
	case Accept:
		return "Access-Accept"
	case Reject:
		return "Access-Reject"
	case Challenge:
		return "Access-Challenge"
	}
	return "unknown"
}

// Request is one password check, or the answer to a challenge.
type Request struct {
	UserName         string
	Password         string // or the answer to a challenge
	CallingStationID string // the client address
	// State and Server answer a challenge: the State it sent, and the index
	// of the server that sent it, which alone can take the answer.
	State  []byte
	Server int
}

// Result is a server's answer.
type Result struct {
	Outcome Outcome
	Reply   *Packet
	Server  int    // index in Config.Servers
	Message string // Reply-Message, its parts joined by newlines
	State   []byte // with Challenge
}

// ErrUnavailable reports that no server gave a valid answer.  Its error text
// says what each server did.
var ErrUnavailable = errors.New("no RADIUS server answered")

// ErrChallengeMSCHAP reports a challenge from a server asked with MS-CHAPv2,
// whose answer has no defined form.
var ErrChallengeMSCHAP = errors.New("Access-Challenge from a server asked with MS-CHAPv2")

// Client asks RADIUS servers.
type Client struct {
	cfg Config
}

// NewClient makes a client.  It checks the configuration but contacts nobody.
func NewClient(cfg Config) (*Client, error) {
	if len(cfg.Servers) == 0 {
		return nil, errors.New("no RADIUS servers")
	}
	if cfg.NASIdentifier == "" {
		return nil, errors.New("no NAS-Identifier")
	}
	if len(cfg.NASIdentifier) > maxValue {
		return nil, errors.New("NAS-Identifier is over 253 bytes")
	}
	for _, s := range cfg.Servers {
		if len(s.Secret) == 0 {
			return nil, fmt.Errorf("RADIUS server %s has no secret", s.Address)
		}
		if _, _, err := net.SplitHostPort(s.Address); err != nil {
			return nil, fmt.Errorf("RADIUS server %q: %w", s.Address, err)
		}
		if s.Auth != AuthPAP && s.Auth != AuthMSCHAPv2 {
			return nil, fmt.Errorf("RADIUS server %s: auth %q is not %q or %q", s.Address, s.Auth, AuthPAP, AuthMSCHAPv2)
		}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	}
	return &Client{cfg: cfg}, nil
}

// Authenticate asks the servers, in order, until one gives a valid answer.  A
// challenge's answer goes to the server that sent it, and only there.  It
// answers ErrUnavailable, wrapped with what went wrong, when none does.
func (c *Client) Authenticate(ctx context.Context, req Request) (*Result, error) {
	if len(req.UserName) == 0 || len(req.UserName) > maxValue {
		return nil, errors.New("user name must be 1 to 253 bytes")
	}
	order := make([]int, 0, len(c.cfg.Servers))
	if req.State != nil {
		if req.Server < 0 || req.Server >= len(c.cfg.Servers) {
			return nil, errors.New("challenge answer names no server")
		}
		if c.cfg.Servers[req.Server].Auth != AuthPAP {
			return nil, ErrChallengeMSCHAP
		}
		order = append(order, req.Server)
	} else {
		for i := range c.cfg.Servers {
			order = append(order, i)
		}
	}
	var problems []string
	for _, i := range order {
		res, err := c.ask(ctx, i, req)
		if err == nil {
			res.Server = i
			return res, nil
		}
		if errors.Is(err, ErrPasswordTooLong) || errors.Is(err, ErrChallengeMSCHAP) {
			return nil, err
		}
		problems = append(problems, fmt.Sprintf("%s: %v", c.cfg.Servers[i].Address, err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrUnavailable, strings.Join(problems, "; "))
}

// ask sends one request to server i, again on each timeout, and reads until a
// valid reply comes.  Replies that fail a check are dropped, as RFC 2865 §3
// says, and named in the error when no valid one follows.
func (c *Client) ask(ctx context.Context, i int, req Request) (*Result, error) {
	srv := c.cfg.Servers[i]
	pkt, ms, err := c.build(srv, req)
	if err != nil {
		return nil, err
	}
	raw, err := pkt.Encode()
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", srv.Address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var dropped []string
	buf := make([]byte, maxLen+1)
	for try := 0; try <= c.cfg.Retries; try++ {
		// A retransmission keeps the identifier and authenticator (RFC 5080 §2.2.1).
		if _, err := conn.Write(raw); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(c.cfg.Timeout)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		conn.SetReadDeadline(deadline)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					break
				}
				// A refused port shows up here on a connected socket.
				return nil, err
			}
			reply, err := checkReply(pkt, buf[:n], srv.Secret, c.cfg.RequireMessageAuthenticator)
			if err != nil {
				dropped = append(dropped, err.Error())
				continue
			}
			return c.result(reply, ms)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if len(dropped) > 0 {
		return nil, fmt.Errorf("no valid reply in %d tries; dropped: %s", c.cfg.Retries+1, strings.Join(dropped, ", "))
	}
	return nil, fmt.Errorf("no reply in %d tries", c.cfg.Retries+1)
}

// build makes the Access-Request.  Message-Authenticator comes first, as RFC
// 3579 §3.2 and the BlastRADIUS advice ask.
func (c *Client) build(srv Server, req Request) (*Packet, *mschap, error) {
	p := &Packet{Code: CodeAccessRequest}
	var id [1]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, nil, err
	}
	p.ID = id[0]
	if _, err := rand.Read(p.Authenticator[:]); err != nil {
		return nil, nil, err
	}
	p.Add(AttrMessageAuthenticator, make([]byte, 16))
	p.Add(AttrUserName, []byte(req.UserName))
	var ms *mschap
	switch srv.Auth {
	case AuthPAP:
		hidden, err := hidePassword([]byte(req.Password), srv.Secret, p.Authenticator)
		if err != nil {
			return nil, nil, err
		}
		p.Add(AttrUserPassword, hidden)
	case AuthMSCHAPv2:
		auth := make([]byte, 16)
		peer := make([]byte, 16)
		if _, err := rand.Read(auth); err != nil {
			return nil, nil, err
		}
		if _, err := rand.Read(peer); err != nil {
			return nil, nil, err
		}
		m, err := newMSCHAP(req.UserName, req.Password, p.ID, auth, peer)
		if err != nil {
			return nil, nil, err
		}
		ms = m
		p.Add(AttrVendorSpecific, VendorAttribute(VendorMicrosoft, MSCHAPChallenge, m.challenge))
		p.Add(AttrVendorSpecific, VendorAttribute(VendorMicrosoft, MSCHAP2Response, m.response))
	}
	p.Add(AttrNASIdentifier, []byte(c.cfg.NASIdentifier))
	// The client's IP address; nothing for a client on a unix socket.
	if net.ParseIP(req.CallingStationID) != nil {
		p.Add(AttrCallingStationID, []byte(req.CallingStationID))
	}
	p.Add(AttrNASPortType, Uint32(NASPortTypeVirtual))
	p.Add(AttrServiceType, Uint32(ServiceTypeLogin))
	if req.State != nil {
		p.Add(AttrState, req.State)
	}
	if err := sign(p, srv.Secret); err != nil {
		return nil, nil, err
	}
	return p, ms, nil
}

func (c *Client) result(reply *Packet, ms *mschap) (*Result, error) {
	res := &Result{Reply: reply}
	var msgs []string
	for _, m := range reply.All(AttrReplyMessage) {
		msgs = append(msgs, string(m))
	}
	res.Message = strings.Join(msgs, "\n")
	switch reply.Code {
	case CodeAccessAccept:
		res.Outcome = Accept
		if ms != nil {
			if err := ms.verify(reply); err != nil {
				return nil, err
			}
		}
	case CodeAccessReject:
		res.Outcome = Reject
	case CodeAccessChallenge:
		if ms != nil {
			return nil, ErrChallengeMSCHAP
		}
		res.Outcome = Challenge
		res.State, _ = reply.Get(AttrState)
	}
	return res, nil
}
