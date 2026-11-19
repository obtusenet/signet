// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package radius

import (
	"bytes"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// ErrPasswordTooLong reports a password no RADIUS request can carry: over 128
// bytes for PAP (RFC 2865 §5.2), or 256 characters for MS-CHAPv2 (RFC 2759 §4).
var ErrPasswordTooLong = errors.New("password too long for RADIUS")

// hidePassword hides a PAP password with the shared secret and the Request
// Authenticator (RFC 2865 §5.2).
func hidePassword(password, secret []byte, authenticator [16]byte) ([]byte, error) {
	if len(password) > 128 {
		return nil, ErrPasswordTooLong
	}
	n := (len(password) + 15) / 16 * 16
	if n == 0 {
		n = 16
	}
	out := make([]byte, n)
	copy(out, password)
	prev := authenticator[:]
	for i := 0; i < n; i += 16 {
		h := md5.New()
		h.Write(secret)
		h.Write(prev)
		b := h.Sum(nil)
		for j := 0; j < 16; j++ {
			out[i+j] ^= b[j]
		}
		prev = out[i : i+16]
	}
	return out, nil
}

// messageAuthenticator is HMAC-MD5 over the packet with the attribute's value
// zeroed (RFC 3579 §3.2).  A reply is signed with the request's authenticator in
// place of its own.
func messageAuthenticator(p *Packet, secret []byte, authenticator [16]byte) ([]byte, error) {
	c := *p
	c.Authenticator = authenticator
	c.Attributes = make([]Attribute, len(p.Attributes))
	for i, a := range p.Attributes {
		if a.Type == AttrMessageAuthenticator {
			a = Attribute{Type: a.Type, Value: make([]byte, len(a.Value))}
		}
		c.Attributes[i] = a
	}
	b, err := c.Encode()
	if err != nil {
		return nil, err
	}
	m := hmac.New(md5.New, secret)
	m.Write(b)
	return m.Sum(nil), nil
}

// sign fills in a request's Message-Authenticator, which must already be there
// as 16 zero bytes.
func sign(p *Packet, secret []byte) error {
	mac, err := messageAuthenticator(p, secret, p.Authenticator)
	if err != nil {
		return err
	}
	for i := range p.Attributes {
		if p.Attributes[i].Type == AttrMessageAuthenticator {
			p.Attributes[i].Value = mac
			return nil
		}
	}
	return errors.New("request has no Message-Authenticator")
}

// checkReply proves that raw answers req and came from a holder of the secret:
// the identifier, the code, the Response Authenticator (RFC 2865 §3) and the
// Message-Authenticator (RFC 3579 §3.2), which must be there when required.
func checkReply(req *Packet, raw, secret []byte, requireMA bool) (*Packet, error) {
	p, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	if p.ID != req.ID {
		return nil, fmt.Errorf("identifier %d does not answer %d", p.ID, req.ID)
	}
	switch p.Code {
	case CodeAccessAccept, CodeAccessReject, CodeAccessChallenge:
	default:
		return nil, fmt.Errorf("unexpected code %d", p.Code)
	}
	n := int(raw[2])<<8 | int(raw[3])
	h := md5.New()
	h.Write(raw[0:4])
	h.Write(req.Authenticator[:])
	h.Write(raw[20:n])
	h.Write(secret)
	if !hmac.Equal(h.Sum(nil), raw[4:20]) {
		return nil, errors.New("wrong Response Authenticator (is the secret right?)")
	}
	mas := p.All(AttrMessageAuthenticator)
	switch {
	case len(mas) > 1:
		return nil, errors.New("more than one Message-Authenticator")
	case len(mas) == 0 && requireMA:
		return nil, errors.New("no Message-Authenticator, which is required")
	case len(mas) == 1:
		if len(mas[0]) != 16 {
			return nil, errors.New("Message-Authenticator is not 16 bytes")
		}
		want, err := messageAuthenticator(p, secret, req.Authenticator)
		if err != nil {
			return nil, err
		}
		if !hmac.Equal(want, mas[0]) {
			return nil, errors.New("wrong Message-Authenticator")
		}
	}
	return p, nil
}

// MS-CHAPv2 (RFC 2759).

var (
	magic1 = []byte("Magic server to client signing constant")
	magic2 = []byte("Pad to make it do more than one iteration")
)

// mschapUser is the name the challenge hash covers: without a Windows domain
// ("DOMAIN\user"), as RFC 2759 §4 has the peer send it.
func mschapUser(name string) string {
	if i := strings.LastIndexByte(name, '\\'); i >= 0 {
		return name[i+1:]
	}
	return name
}

func challengeHash(peer, auth []byte, user string) []byte {
	h := sha1.New()
	h.Write(peer)
	h.Write(auth)
	h.Write([]byte(user))
	return h.Sum(nil)[:8]
}

// ntPasswordHash is MD4 of the password in UTF-16LE (RFC 2759 §8.3).
func ntPasswordHash(password string) ([]byte, error) {
	u := utf16.Encode([]rune(password))
	if len(u) > 256 {
		return nil, ErrPasswordTooLong
	}
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i] = byte(c)
		b[2*i+1] = byte(c >> 8)
	}
	h := md4.New()
	h.Write(b)
	return h.Sum(nil), nil
}

// desKey spreads 7 bytes over the 8 a DES key has, leaving the parity bits.
func desKey(k []byte) []byte {
	return []byte{
		k[0] & 0xfe,
		k[0]<<7 | k[1]>>1,
		k[1]<<6 | k[2]>>2,
		k[2]<<5 | k[3]>>3,
		k[3]<<4 | k[4]>>4,
		k[4]<<3 | k[5]>>5,
		k[5]<<2 | k[6]>>6,
		k[6] << 1,
	}
}

// challengeResponse encrypts the 8-byte challenge with the three DES keys cut
// from the password hash (RFC 2759 §8.5).
func challengeResponse(challenge, passwordHash []byte) []byte {
	z := make([]byte, 21)
	copy(z, passwordHash)
	out := make([]byte, 24)
	for i := 0; i < 3; i++ {
		c, _ := des.NewCipher(desKey(z[7*i : 7*i+7])) // 8 bytes: cannot fail
		c.Encrypt(out[8*i:], challenge)
	}
	return out
}

// authenticatorResponse is what the server must send back in MS-CHAP2-Success
// (RFC 2759 §8.7): "S=" and 40 hex digits.
func authenticatorResponse(passwordHash, ntResponse, peer, auth []byte, user string) string {
	hh := md4.New()
	hh.Write(passwordHash)
	h := sha1.New()
	h.Write(hh.Sum(nil))
	h.Write(ntResponse)
	h.Write(magic1)
	d := h.Sum(nil)
	h = sha1.New()
	h.Write(d)
	h.Write(challengeHash(peer, auth, user))
	h.Write(magic2)
	return "S=" + strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

// mschap is one MS-CHAPv2 exchange: what goes in the request, and what the
// server must answer.
type mschap struct {
	ident     byte
	challenge []byte // MS-CHAP-Challenge, the authenticator challenge
	response  []byte // MS-CHAP2-Response
	success   string // the expected authenticator response
}

func newMSCHAP(user, password string, ident byte, auth, peer []byte) (*mschap, error) {
	ph, err := ntPasswordHash(password)
	if err != nil {
		return nil, err
	}
	name := mschapUser(user)
	nt := challengeResponse(challengeHash(peer, auth, name), ph)
	resp := make([]byte, 0, 50)
	resp = append(resp, ident, 0)
	resp = append(resp, peer...)
	resp = append(resp, make([]byte, 8)...)
	resp = append(resp, nt...)
	return &mschap{
		ident:     ident,
		challenge: auth,
		response:  resp,
		success:   authenticatorResponse(ph, nt, peer, auth, name),
	}, nil
}

// verify checks an Access-Accept's MS-CHAP2-Success: the server proves it knew
// the password, so a server that only holds the shared secret cannot accept.
func (m *mschap) verify(p *Packet) error {
	vs := p.Vendor(VendorMicrosoft, MSCHAP2Success)
	if len(vs) != 1 {
		return fmt.Errorf("Access-Accept has %d MS-CHAP2-Success attributes, not 1", len(vs))
	}
	v := vs[0]
	if len(v) < 43 || v[0] != m.ident {
		return errors.New("MS-CHAP2-Success is malformed")
	}
	if !hmac.Equal(bytes.ToUpper(v[1:43]), []byte(m.success)) {
		return errors.New("MS-CHAP2-Success does not prove the server knew the password")
	}
	return nil
}
