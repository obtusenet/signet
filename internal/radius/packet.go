// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

// Package radius is a RADIUS client (RFC 2865) for checking a password with
// PAP or MS-CHAPv2.  It sends and requires Message-Authenticator (RFC 3579
// §3.2) and checks every reply's Response Authenticator.
package radius

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Packet codes (RFC 2865 §3).
const (
	CodeAccessRequest   = 1
	CodeAccessAccept    = 2
	CodeAccessReject    = 3
	CodeAccessChallenge = 11
)

// Attribute types (RFC 2865 §5, RFC 3579 §3.2).
const (
	AttrUserName             = 1
	AttrUserPassword         = 2
	AttrServiceType          = 6
	AttrFilterID             = 11
	AttrReplyMessage         = 18
	AttrState                = 24
	AttrClass                = 25
	AttrVendorSpecific       = 26
	AttrCalledStationID      = 30
	AttrCallingStationID     = 31
	AttrNASIdentifier        = 32
	AttrNASPortType          = 61
	AttrMessageAuthenticator = 80
)

// Values sent in every request.
const (
	ServiceTypeLogin   = 1 // Service-Type (§5.6)
	NASPortTypeVirtual = 5 // NAS-Port-Type (§5.41)
)

// Microsoft vendor attributes (RFC 2548).
const (
	VendorMicrosoft = 311
	MSCHAPError     = 2
	MSCHAPChallenge = 11
	MSCHAP2Response = 25
	MSCHAP2Success  = 26
)

const (
	headerLen = 20
	maxLen    = 4096 // RFC 2865 §3
	maxValue  = 253
)

// ErrMalformed reports bytes that are not a RADIUS packet.
var ErrMalformed = errors.New("malformed RADIUS packet")

// Attribute is one attribute as it travels: a type and up to 253 bytes.
type Attribute struct {
	Type  byte
	Value []byte
}

// Packet is a RADIUS packet.  Attributes keep their order, so encoding a
// decoded packet gives back the same bytes.
type Packet struct {
	Code          byte
	ID            byte
	Authenticator [16]byte
	Attributes    []Attribute
}

// Add appends an attribute.
func (p *Packet) Add(t byte, value []byte) {
	p.Attributes = append(p.Attributes, Attribute{Type: t, Value: value})
}

// Get answers the first attribute of type t.
func (p *Packet) Get(t byte) ([]byte, bool) {
	for _, a := range p.Attributes {
		if a.Type == t {
			return a.Value, true
		}
	}
	return nil, false
}

// All answers every attribute of type t, in order.
func (p *Packet) All(t byte) [][]byte {
	var out [][]byte
	for _, a := range p.Attributes {
		if a.Type == t {
			out = append(out, a.Value)
		}
	}
	return out
}

// Vendor answers every value of the vendor attribute vendor/vtype.
func (p *Packet) Vendor(vendor uint32, vtype byte) [][]byte {
	var out [][]byte
	for _, a := range p.Attributes {
		if a.Type != AttrVendorSpecific {
			continue
		}
		id, subs, ok := ParseVendor(a.Value)
		if !ok || id != vendor {
			continue
		}
		for _, s := range subs {
			if s.Type == vtype {
				out = append(out, s.Value)
			}
		}
	}
	return out
}

// Encode answers the packet's bytes.
func (p *Packet) Encode() ([]byte, error) {
	n := headerLen
	for _, a := range p.Attributes {
		if len(a.Value) > maxValue {
			return nil, fmt.Errorf("attribute %d is %d bytes, over %d", a.Type, len(a.Value), maxValue)
		}
		n += 2 + len(a.Value)
	}
	if n > maxLen {
		return nil, fmt.Errorf("packet is %d bytes, over %d", n, maxLen)
	}
	b := make([]byte, n)
	b[0] = p.Code
	b[1] = p.ID
	binary.BigEndian.PutUint16(b[2:4], uint16(n))
	copy(b[4:20], p.Authenticator[:])
	off := headerLen
	for _, a := range p.Attributes {
		b[off] = a.Type
		b[off+1] = byte(2 + len(a.Value))
		copy(b[off+2:], a.Value)
		off += 2 + len(a.Value)
	}
	return b, nil
}

// Decode reads a packet.  Bytes after the Length field are padding and are
// ignored (RFC 2865 §3).
func Decode(b []byte) (*Packet, error) {
	if len(b) < headerLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrMalformed, len(b))
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if n < headerLen || n > maxLen || n > len(b) {
		return nil, fmt.Errorf("%w: length %d in %d bytes", ErrMalformed, n, len(b))
	}
	p := &Packet{Code: b[0], ID: b[1]}
	copy(p.Authenticator[:], b[4:20])
	for off := headerLen; off < n; {
		if n-off < 2 {
			return nil, fmt.Errorf("%w: attribute header cut short", ErrMalformed)
		}
		l := int(b[off+1])
		if l < 2 || off+l > n {
			return nil, fmt.Errorf("%w: attribute %d has length %d", ErrMalformed, b[off], l)
		}
		v := make([]byte, l-2)
		copy(v, b[off+2:off+l])
		p.Attributes = append(p.Attributes, Attribute{Type: b[off], Value: v})
		off += l
	}
	return p, nil
}

// SubAttribute is one attribute inside a Vendor-Specific attribute.
type SubAttribute struct {
	Type  byte
	Value []byte
}

// ParseVendor reads a Vendor-Specific value in the format RFC 2865 §5.26
// recommends: a vendor id, then type, length and value.  ok is false when the
// value does not follow it.
func ParseVendor(v []byte) (vendor uint32, subs []SubAttribute, ok bool) {
	if len(v) < 4 {
		return 0, nil, false
	}
	vendor = binary.BigEndian.Uint32(v[:4])
	for off := 4; off < len(v); {
		if len(v)-off < 2 {
			return vendor, nil, false
		}
		l := int(v[off+1])
		if l < 2 || off+l > len(v) {
			return vendor, nil, false
		}
		subs = append(subs, SubAttribute{Type: v[off], Value: v[off+2 : off+l]})
		off += l
	}
	return vendor, subs, true
}

// VendorAttribute makes a Vendor-Specific value holding one sub-attribute.
func VendorAttribute(vendor uint32, vtype byte, value []byte) []byte {
	b := make([]byte, 6+len(value))
	binary.BigEndian.PutUint32(b[:4], vendor)
	b[4] = vtype
	b[5] = byte(2 + len(value))
	copy(b[6:], value)
	return b
}

// Uint32 encodes an integer attribute value.
func Uint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}
