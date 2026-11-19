// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package radius

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 2759 §9.2.
func TestMSCHAPv2Vectors(t *testing.T) {
	auth := unhex(t, "5B5D7C7D7B3F2F3E3C2C602132262628")
	peer := unhex(t, "21402324255E262A28295F2B3A337C7E")
	if got := challengeHash(peer, auth, "User"); !bytes.Equal(got, unhex(t, "D02E4386BCE91226")) {
		t.Errorf("ChallengeHash = %X", got)
	}
	ph, err := ntPasswordHash("clientPass")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ph, unhex(t, "44EBBA8D5312B8D611474411F56989AE")) {
		t.Errorf("PasswordHash = %X", ph)
	}
	nt := challengeResponse(unhex(t, "D02E4386BCE91226"), ph)
	if !bytes.Equal(nt, unhex(t, "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")) {
		t.Errorf("NT-Response = %X", nt)
	}
	if got := authenticatorResponse(ph, nt, peer, auth, "User"); got != "S=407A5589115FD0D6209F510FE9C04566932CDA56" {
		t.Errorf("AuthenticatorResponse = %s", got)
	}
}

func TestMSCHAPUser(t *testing.T) {
	for in, want := range map[string]string{"User": "User", `DOM\jdoe`: "jdoe", "a@example.com": "a@example.com"} {
		if got := mschapUser(in); got != want {
			t.Errorf("mschapUser(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPAPHiding(t *testing.T) {
	secret := []byte("xyzzy5461")
	for _, n := range []int{0, 1, 15, 16, 17, 100, 128} {
		pw := strings.Repeat("p", n)
		p := &Packet{Code: CodeAccessRequest}
		copy(p.Authenticator[:], "0123456789abcdef")
		h, err := hidePassword([]byte(pw), secret, p.Authenticator)
		if err != nil {
			t.Fatal(err)
		}
		if len(h)%16 != 0 || len(h) == 0 || (n > 0 && bytes.Contains(h, []byte(pw))) {
			t.Errorf("%d: hidden is %d bytes", n, len(h))
		}
		p.Add(AttrUserPassword, h)
		got, err := RecoverPassword(p, secret)
		if err != nil || got != pw {
			t.Errorf("%d: recovered %q, %v", n, got, err)
		}
	}
	if _, err := hidePassword(bytes.Repeat([]byte("p"), 129), secret, [16]byte{}); !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("129 bytes: %v", err)
	}
}

func TestEncodeDecode(t *testing.T) {
	p := &Packet{Code: CodeAccessAccept, ID: 7}
	p.Add(AttrFilterID, []byte("admins"))
	p.Add(AttrVendorSpecific, VendorAttribute(12356, 1, []byte("ops")))
	b, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	q, err := Decode(append(b, 0, 0, 0)) // padding after Length is ignored
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := q.Encode()
	if !bytes.Equal(b, b2) {
		t.Error("decode and encode changed the packet")
	}
	if v := q.Vendor(12356, 1); len(v) != 1 || string(v[0]) != "ops" {
		t.Errorf("vendor attribute: %q", v)
	}

	bad := map[string][]byte{
		"short":            b[:10],
		"length too big":   append([]byte{2, 7, 0x10, 0x01}, make([]byte, 16)...),
		"length too small": append([]byte{2, 7, 0, 5}, make([]byte, 16)...),
		"attr length 1":    append(append([]byte{2, 7, 0, 22}, make([]byte, 16)...), 11, 1),
		"attr past end":    append(append([]byte{2, 7, 0, 23}, make([]byte, 16)...), 11, 9, 'a'),
	}
	for name, raw := range bad {
		if _, err := Decode(raw); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := (&Packet{Attributes: []Attribute{{Type: 1, Value: make([]byte, 254)}}}).Encode(); err == nil {
		t.Error("a 254-byte value was encoded")
	}
}

func FuzzDecode(f *testing.F) {
	p := &Packet{Code: CodeAccessAccept}
	p.Add(AttrFilterID, []byte("g"))
	p.Add(AttrVendorSpecific, VendorAttribute(311, 26, []byte("xS=00")))
	b, _ := p.Encode()
	f.Add(b)
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := Decode(raw)
		if err != nil {
			return
		}
		Describe(p)
		Groups(p, []GroupAttribute{{Type: AttrFilterID}, {Type: AttrVendorSpecific, Vendor: 311, VendorType: 26}})
		if _, err := p.Encode(); err != nil {
			t.Errorf("a decoded packet does not encode: %v", err)
		}
	})
}

// fake is a RADIUS server on loopback.  handle answers each request, or nil to
// stay silent.
type fake struct {
	conn   *net.UDPConn
	secret []byte
	got    atomic.Int32
}

func newFake(t *testing.T, secret string, handle func(req *Packet, try int) []byte) *fake {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &fake{conn: c, secret: []byte(secret)}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			try := int(f.got.Add(1))
			req, err := CheckRequest(buf[:n], f.secret)
			if err != nil {
				t.Errorf("fake server: %v", err)
				continue
			}
			if out := handle(req, try); out != nil {
				c.WriteToUDP(out, addr)
			}
		}
	}()
	return f
}

func (f *fake) addr() string { return f.conn.LocalAddr().String() }

func reply(t *testing.T, req *Packet, code byte, secret string, attrs ...Attribute) []byte {
	t.Helper()
	b, err := Reply(req, code, attrs, []byte(secret), true)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func client(t *testing.T, servers ...Server) *Client {
	t.Helper()
	c, err := NewClient(Config{
		Servers: servers, NASIdentifier: "wiki", Timeout: 200 * time.Millisecond,
		Retries: 1, RequireMessageAuthenticator: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// papServer accepts jdoe/secret-pw, with groups, and rejects anything else.
func papServer(t *testing.T, secret string) *fake {
	return newFake(t, secret, func(req *Packet, _ int) []byte {
		pw, err := RecoverPassword(req, []byte(secret))
		user, _ := req.Get(AttrUserName)
		if err == nil && string(user) == "jdoe" && pw == "secret-pw" {
			return reply(t, req, CodeAccessAccept, secret,
				Attribute{AttrFilterID, []byte("wiki-admins")},
				Attribute{AttrFilterID, []byte("staff")},
				Attribute{AttrReplyMessage, []byte("welcome")})
		}
		return reply(t, req, CodeAccessReject, secret)
	})
}

func TestPAPAcceptAndReject(t *testing.T) {
	f := papServer(t, "s3cret")
	c := client(t, Server{Address: f.addr(), Secret: []byte("s3cret"), Auth: AuthPAP})
	res, err := c.Authenticate(context.Background(), Request{UserName: "jdoe", Password: "secret-pw", CallingStationID: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != Accept || res.Message != "welcome" {
		t.Errorf("got %v %q", res.Outcome, res.Message)
	}
	groups, skipped := Groups(res.Reply, []GroupAttribute{{Type: AttrFilterID}})
	if strings.Join(groups, ",") != "wiki-admins,staff" || skipped != 0 {
		t.Errorf("groups %q, skipped %d", groups, skipped)
	}
	res, err = c.Authenticate(context.Background(), Request{UserName: "jdoe", Password: "wrong"})
	if err != nil || res.Outcome != Reject {
		t.Errorf("wrong password: %v, %v", res, err)
	}
}

func TestRequestAttributes(t *testing.T) {
	got := make(chan *Packet, 1)
	f := newFake(t, "s", func(req *Packet, _ int) []byte {
		got <- req
		return reply(t, req, CodeAccessReject, "s")
	})
	c := client(t, Server{Address: f.addr(), Secret: []byte("s"), Auth: AuthPAP})
	if _, err := c.Authenticate(context.Background(), Request{UserName: "jdoe", Password: "x", CallingStationID: "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	seen := <-got
	if seen.Attributes[0].Type != AttrMessageAuthenticator {
		t.Error("Message-Authenticator is not first")
	}
	check := func(name string, typ byte, want []byte) {
		if v, ok := seen.Get(typ); !ok || !bytes.Equal(v, want) {
			t.Errorf("%s = %q", name, v)
		}
	}
	check("NAS-Identifier", AttrNASIdentifier, []byte("wiki"))
	check("Calling-Station-Id", AttrCallingStationID, []byte("192.0.2.10"))
	check("NAS-Port-Type", AttrNASPortType, Uint32(NASPortTypeVirtual))
	check("Service-Type", AttrServiceType, Uint32(ServiceTypeLogin))
	check("User-Name", AttrUserName, []byte("jdoe"))
	if _, ok := seen.Get(AttrState); ok {
		t.Error("State sent without a challenge")
	}
}

func TestMSCHAPv2(t *testing.T) {
	const secret = "s3cret"
	var tamper atomic.Bool
	f := newFake(t, secret, func(req *Packet, _ int) []byte {
		success, err := CheckMSCHAPv2(req, "secret-pw")
		if err != nil {
			return reply(t, req, CodeAccessReject, secret)
		}
		if tamper.Load() {
			success[5] ^= 1
		}
		return reply(t, req, CodeAccessAccept, secret,
			Attribute{AttrVendorSpecific, VendorAttribute(VendorMicrosoft, MSCHAP2Success, success)})
	})
	c := client(t, Server{Address: f.addr(), Secret: []byte(secret), Auth: AuthMSCHAPv2})
	res, err := c.Authenticate(context.Background(), Request{UserName: "jdoe", Password: "secret-pw"})
	if err != nil || res.Outcome != Accept {
		t.Fatalf("right password: %v, %v", res, err)
	}
	res, err = c.Authenticate(context.Background(), Request{UserName: "jdoe", Password: "nope"})
	if err != nil || res.Outcome != Reject {
		t.Errorf("wrong password: %v, %v", res, err)
	}
	// An Accept that does not prove the server knew the password is no Accept.
	tamper.Store(true)
	if _, err := c.Authenticate(context.Background(), Request{UserName: "jdoe", Password: "secret-pw"}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("bad MS-CHAP2-Success: %v", err)
	}
}

func TestReplyChecks(t *testing.T) {
	const secret = "s3cret"
	cases := map[string]func(req *Packet) []byte{
		"no Message-Authenticator": func(req *Packet) []byte {
			b, _ := Reply(req, CodeAccessAccept, nil, []byte(secret), false)
			return b
		},
		"wrong Message-Authenticator": func(req *Packet) []byte {
			p, _ := Decode(reply(t, req, CodeAccessAccept, secret))
			p.Attributes[0].Value[0] ^= 1
			// The Response Authenticator is right; only the HMAC is wrong.
			b, _ := Reply(req, CodeAccessAccept, p.Attributes, []byte(secret), false)
			return b
		},
		"wrong secret": func(req *Packet) []byte {
			return reply(t, req, CodeAccessAccept, "other")
		},
		"wrong identifier": func(req *Packet) []byte {
			b := reply(t, req, CodeAccessAccept, secret)
			b[1]++
			return b
		},
		"two Message-Authenticators": func(req *Packet) []byte {
			b, _ := Reply(req, CodeAccessAccept, []Attribute{{AttrMessageAuthenticator, make([]byte, 16)}}, []byte(secret), true)
			return b
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, secret, func(req *Packet, _ int) []byte { return mk(req) })
			c := client(t, Server{Address: f.addr(), Secret: []byte(secret), Auth: AuthPAP})
			_, err := c.Authenticate(context.Background(), Request{UserName: "jdoe", Password: "x"})
			if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "dropped") {
				t.Errorf("got %v", err)
			}
		})
	}
}

func TestMessageAuthenticatorOptional(t *testing.T) {
	f := newFake(t, "s", func(req *Packet, _ int) []byte {
		b, _ := Reply(req, CodeAccessAccept, nil, []byte("s"), false)
		return b
	})
	c, _ := NewClient(Config{Servers: []Server{{Address: f.addr(), Secret: []byte("s"), Auth: AuthPAP}}, NASIdentifier: "wiki", Timeout: 200 * time.Millisecond})
	res, err := c.Authenticate(context.Background(), Request{UserName: "jdoe", Password: "x"})
	if err != nil || res.Outcome != Accept {
		t.Errorf("got %v, %v", res, err)
	}
}

func TestRetryAndFailover(t *testing.T) {
	// Answers only the second try of each request.
	slow := newFake(t, "s", func(req *Packet, try int) []byte {
		if try%2 == 1 {
			return nil
		}
		return reply(t, req, CodeAccessReject, "s")
	})
	c := client(t, Server{Address: slow.addr(), Secret: []byte("s"), Auth: AuthPAP})
	if res, err := c.Authenticate(context.Background(), Request{UserName: "jdoe", Password: "x"}); err != nil || res.Outcome != Reject {
		t.Errorf("retry: %v, %v", res, err)
	}

	silent := newFake(t, "s", func(*Packet, int) []byte { return nil })
	good := papServer(t, "t")
	c = client(t,
		Server{Address: silent.addr(), Secret: []byte("s"), Auth: AuthPAP},
		Server{Address: good.addr(), Secret: []byte("t"), Auth: AuthPAP})
	res, err := c.Authenticate(context.Background(), Request{UserName: "jdoe", Password: "secret-pw"})
	if err != nil || res.Outcome != Accept || res.Server != 1 {
		t.Errorf("failover: %+v, %v", res, err)
	}
	if n := silent.got.Load(); n != 2 {
		t.Errorf("the silent server got %d tries, want 2", n)
	}

	c = client(t, Server{Address: silent.addr(), Secret: []byte("s"), Auth: AuthPAP})
	_, err = c.Authenticate(context.Background(), Request{UserName: "jdoe", Password: "x"})
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "no reply in 2 tries") {
		t.Errorf("all silent: %v", err)
	}
}

func TestChallenge(t *testing.T) {
	const secret = "s"
	f := newFake(t, secret, func(req *Packet, _ int) []byte {
		pw, _ := RecoverPassword(req, []byte(secret))
		if st, ok := req.Get(AttrState); ok {
			if string(st) == "round-1" && pw == "123456" {
				return reply(t, req, CodeAccessAccept, secret)
			}
			return reply(t, req, CodeAccessReject, secret)
		}
		if pw == "secret-pw" {
			return reply(t, req, CodeAccessChallenge, secret,
				Attribute{AttrReplyMessage, []byte("Enter your code")},
				Attribute{AttrState, []byte("round-1")})
		}
		return reply(t, req, CodeAccessReject, secret)
	})
	other := papServer(t, "x")
	c := client(t,
		Server{Address: f.addr(), Secret: []byte(secret), Auth: AuthPAP},
		Server{Address: other.addr(), Secret: []byte("x"), Auth: AuthPAP})
	res, err := c.Authenticate(context.Background(), Request{UserName: "jdoe", Password: "secret-pw"})
	if err != nil || res.Outcome != Challenge || res.Message != "Enter your code" || string(res.State) != "round-1" {
		t.Fatalf("challenge: %+v, %v", res, err)
	}
	res, err = c.Authenticate(context.Background(), Request{UserName: "jdoe", Password: "123456", State: res.State, Server: res.Server})
	if err != nil || res.Outcome != Accept {
		t.Errorf("answer: %+v, %v", res, err)
	}
	if other.got.Load() != 0 {
		t.Error("the answer went to another server")
	}
}

func TestChallengeUnderMSCHAPv2(t *testing.T) {
	f := newFake(t, "s", func(req *Packet, _ int) []byte {
		return reply(t, req, CodeAccessChallenge, "s", Attribute{AttrState, []byte("x")})
	})
	c := client(t, Server{Address: f.addr(), Secret: []byte("s"), Auth: AuthMSCHAPv2})
	if _, err := c.Authenticate(context.Background(), Request{UserName: "jdoe", Password: "x"}); !errors.Is(err, ErrChallengeMSCHAP) {
		t.Errorf("got %v", err)
	}
}

func TestNewClientRefuses(t *testing.T) {
	ok := Server{Address: "192.0.2.1:1812", Secret: []byte("s"), Auth: AuthPAP}
	cases := map[string]Config{
		"no servers":   {NASIdentifier: "wiki"},
		"no NAS-Id":    {Servers: []Server{ok}},
		"no secret":    {NASIdentifier: "wiki", Servers: []Server{{Address: ok.Address, Auth: AuthPAP}}},
		"no port":      {NASIdentifier: "wiki", Servers: []Server{{Address: "192.0.2.1", Secret: []byte("s"), Auth: AuthPAP}}},
		"unknown auth": {NASIdentifier: "wiki", Servers: []Server{{Address: ok.Address, Secret: []byte("s"), Auth: "chap"}}},
		"long NAS-Id":  {NASIdentifier: strings.Repeat("a", 254), Servers: []Server{ok}},
	}
	for name, cfg := range cases {
		if _, err := NewClient(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGroupAttributes(t *testing.T) {
	good := map[string]GroupAttribute{
		"Filter-Id":      {Type: AttrFilterID},
		"class":          {Type: AttrClass},
		"vendor:12356:1": {Type: AttrVendorSpecific, Vendor: 12356, VendorType: 1},
		"18":             {Type: 18},
	}
	for in, want := range good {
		if got, err := ParseGroupAttribute(in); err != nil || got != want {
			t.Errorf("%q: %+v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "Groups", "26", "0", "vendor:0:1", "vendor:1", "vendor:x:1", "vendor:1:256"} {
		if _, err := ParseGroupAttribute(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}

	p := &Packet{}
	p.Add(AttrFilterID, []byte("a"))
	p.Add(AttrClass, []byte{0x00, 0xff})
	p.Add(AttrClass, []byte("b"))
	p.Add(AttrFilterID, []byte("a"))
	p.Add(AttrVendorSpecific, VendorAttribute(12356, 1, []byte("c")))
	groups, skipped := Groups(p, []GroupAttribute{{Type: AttrFilterID}, {Type: AttrClass}, {Type: AttrVendorSpecific, Vendor: 12356, VendorType: 1}})
	if strings.Join(groups, ",") != "a,b,c" || skipped != 1 {
		t.Errorf("groups %q, skipped %d", groups, skipped)
	}
}

func TestDescribe(t *testing.T) {
	p := &Packet{}
	p.Add(AttrMessageAuthenticator, make([]byte, 16))
	p.Add(AttrFilterID, []byte("admins"))
	p.Add(27, Uint32(3600))
	p.Add(8, []byte{192, 0, 2, 7})
	p.Add(AttrState, []byte("st"))
	p.Add(AttrVendorSpecific, VendorAttribute(12356, 1, []byte("ops")))
	p.Add(AttrVendorSpecific, []byte{0, 0})
	got := Describe(p)
	want := []AttributeView{
		{Type: 11, Name: "Filter-Id", Value: "admins"},
		{Type: 27, Name: "Session-Timeout", Value: uint32(3600)},
		{Type: 8, Name: "Framed-IP-Address", Value: "192.0.2.7"},
		{Type: 24, Name: "State", Hex: "7374"},
		{Type: 26, Vendor: 12356, VendorType: 1, Value: "ops"},
		{Type: 26, Name: "Vendor-Specific", Hex: "0000"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d attributes: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}
