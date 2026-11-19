// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package radius

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"errors"
	"fmt"
)

// The server side of an exchange.  Signet is only a client; these exist for the
// fake servers its tests run.

// CheckRequest decodes an Access-Request and checks its Message-Authenticator,
// which it must have.
func CheckRequest(raw, secret []byte) (*Packet, error) {
	p, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	if p.Code != CodeAccessRequest {
		return nil, fmt.Errorf("code %d is not Access-Request", p.Code)
	}
	mas := p.All(AttrMessageAuthenticator)
	if len(mas) != 1 || len(mas[0]) != 16 {
		return nil, errors.New("no single Message-Authenticator")
	}
	want, err := messageAuthenticator(p, secret, p.Authenticator)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(want, mas[0]) {
		return nil, errors.New("wrong Message-Authenticator")
	}
	return p, nil
}

// RecoverPassword reverses PAP hiding (RFC 2865 §5.2), dropping the padding.
func RecoverPassword(req *Packet, secret []byte) (string, error) {
	hidden, ok := req.Get(AttrUserPassword)
	if !ok || len(hidden) == 0 || len(hidden)%16 != 0 {
		return "", errors.New("no User-Password")
	}
	out := make([]byte, len(hidden))
	prev := req.Authenticator[:]
	for i := 0; i < len(hidden); i += 16 {
		h := md5.New()
		h.Write(secret)
		h.Write(prev)
		b := h.Sum(nil)
		for j := 0; j < 16; j++ {
			out[i+j] = hidden[i+j] ^ b[j]
		}
		prev = hidden[i : i+16]
	}
	return string(bytes.TrimRight(out, "\x00")), nil
}

// CheckMSCHAPv2 checks a request's MS-CHAP2-Response against password, and
// answers the MS-CHAP2-Success value an Access-Accept carries.
func CheckMSCHAPv2(req *Packet, password string) ([]byte, error) {
	chs := req.Vendor(VendorMicrosoft, MSCHAPChallenge)
	rs := req.Vendor(VendorMicrosoft, MSCHAP2Response)
	if len(chs) != 1 || len(rs) != 1 || len(chs[0]) != 16 || len(rs[0]) != 50 {
		return nil, errors.New("no MS-CHAPv2 attributes")
	}
	user, _ := req.Get(AttrUserName)
	r := rs[0]
	peer := r[2:18]
	m, err := newMSCHAP(string(user), password, r[0], chs[0], peer)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(m.response, r) {
		return nil, errors.New("wrong password")
	}
	return append([]byte{r[0]}, m.success...), nil
}

// Reply makes a reply's bytes: Message-Authenticator (when withMA) and the
// Response Authenticator, both over the request's authenticator.
func Reply(req *Packet, code byte, attrs []Attribute, secret []byte, withMA bool) ([]byte, error) {
	p := &Packet{Code: code, ID: req.ID, Authenticator: req.Authenticator}
	if withMA {
		p.Add(AttrMessageAuthenticator, make([]byte, 16))
	}
	p.Attributes = append(p.Attributes, attrs...)
	if withMA {
		mac, err := messageAuthenticator(p, secret, req.Authenticator)
		if err != nil {
			return nil, err
		}
		p.Attributes[0].Value = mac
	}
	b, err := p.Encode()
	if err != nil {
		return nil, err
	}
	h := md5.New()
	h.Write(b)
	h.Write(secret)
	copy(b[4:20], h.Sum(nil))
	return b, nil
}
