// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package radius

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// GroupAttribute names a reply attribute whose values are group names: a
// standard attribute, or a vendor attribute (Type 26).
type GroupAttribute struct {
	Type       byte
	Vendor     uint32
	VendorType byte
}

// ParseGroupAttribute reads "Filter-Id", "Class", an attribute number, or
// "vendor:<vendor id>:<type>".
func ParseGroupAttribute(s string) (GroupAttribute, error) {
	switch strings.ToLower(s) {
	case "filter-id":
		return GroupAttribute{Type: AttrFilterID}, nil
	case "class":
		return GroupAttribute{Type: AttrClass}, nil
	}
	if rest, ok := strings.CutPrefix(strings.ToLower(s), "vendor:"); ok {
		id, t, ok := strings.Cut(rest, ":")
		vid, err1 := strconv.ParseUint(id, 10, 32)
		vt, err2 := strconv.ParseUint(t, 10, 8)
		if !ok || err1 != nil || err2 != nil || vid == 0 {
			return GroupAttribute{}, fmt.Errorf("group attribute %q: want vendor:<vendor id>:<type>", s)
		}
		return GroupAttribute{Type: AttrVendorSpecific, Vendor: uint32(vid), VendorType: byte(vt)}, nil
	}
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil || n == 0 || n == AttrVendorSpecific {
		return GroupAttribute{}, fmt.Errorf("group attribute %q: want Filter-Id, Class, a number, or vendor:<vendor id>:<type>", s)
	}
	return GroupAttribute{Type: byte(n)}, nil
}

// Groups answers the group names in a reply, in order and without repeats.
// Values that are not printable UTF-8 are skipped, and counted.
func Groups(p *Packet, attrs []GroupAttribute) (groups []string, skipped int) {
	seen := map[string]bool{}
	for _, ga := range attrs {
		var vals [][]byte
		if ga.Type == AttrVendorSpecific {
			vals = p.Vendor(ga.Vendor, ga.VendorType)
		} else {
			vals = p.All(ga.Type)
		}
		for _, v := range vals {
			s, ok := text(v)
			if !ok || s == "" {
				skipped++
				continue
			}
			if !seen[s] {
				seen[s] = true
				groups = append(groups, s)
			}
		}
	}
	return groups, skipped
}

func text(v []byte) (string, bool) {
	if !utf8.Valid(v) {
		return "", false
	}
	s := string(v)
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return "", false
		}
	}
	return s, true
}

// AttributeView is one reply attribute for a claims hook: text, integer and
// address values decoded into Value, anything else as Hex.
type AttributeView struct {
	Type       byte   `json:"type"`
	Name       string `json:"name,omitempty"`
	Vendor     uint32 `json:"vendor,omitempty"`
	VendorType byte   `json:"vendor_type,omitempty"`
	Value      any    `json:"value,omitempty"`
	Hex        string `json:"hex,omitempty"`
}

type kind int

const (
	kindOctets kind = iota
	kindText
	kindInteger
	kindAddress
)

// The RFC 2865 attributes a reply may carry, with their types (§5).
var known = map[byte]struct {
	name string
	kind kind
}{
	AttrServiceType:  {"Service-Type", kindInteger},
	7:                {"Framed-Protocol", kindInteger},
	8:                {"Framed-IP-Address", kindAddress},
	9:                {"Framed-IP-Netmask", kindAddress},
	AttrFilterID:     {"Filter-Id", kindText},
	12:               {"Framed-MTU", kindInteger},
	AttrReplyMessage: {"Reply-Message", kindText},
	AttrState:        {"State", kindOctets},
	AttrClass:        {"Class", kindText}, // octets, but usually a name
	27:               {"Session-Timeout", kindInteger},
	28:               {"Idle-Timeout", kindInteger},
	AttrUserName:     {"User-Name", kindText},
}

// Describe lists a reply's attributes for a claims hook, without the
// Message-Authenticator, which means nothing outside the packet.  Vendor
// attributes are split into their parts; one that does not follow RFC 2865
// §5.26's format is given whole, as hex.
func Describe(p *Packet) []AttributeView {
	var out []AttributeView
	for _, a := range p.Attributes {
		switch a.Type {
		case AttrMessageAuthenticator:
			continue
		case AttrVendorSpecific:
			vid, subs, ok := ParseVendor(a.Value)
			if !ok {
				out = append(out, AttributeView{Type: a.Type, Name: "Vendor-Specific", Hex: hex.EncodeToString(a.Value)})
				continue
			}
			for _, s := range subs {
				v := AttributeView{Type: a.Type, Vendor: vid, VendorType: s.Type}
				if t, ok := text(s.Value); ok && t != "" {
					v.Value = t
				} else {
					v.Hex = hex.EncodeToString(s.Value)
				}
				out = append(out, v)
			}
			continue
		}
		v := AttributeView{Type: a.Type}
		k, isKnown := known[a.Type]
		if isKnown {
			v.Name = k.name
		}
		switch {
		case isKnown && k.kind == kindInteger && len(a.Value) == 4:
			v.Value = binary.BigEndian.Uint32(a.Value)
		case isKnown && k.kind == kindAddress && len(a.Value) == 4:
			v.Value = net.IP(a.Value).String()
		case isKnown && k.kind == kindText:
			if t, ok := text(a.Value); ok {
				v.Value = t
			} else {
				v.Hex = hex.EncodeToString(a.Value)
			}
		default:
			if t, ok := text(a.Value); ok && !isKnown && t != "" {
				v.Value = t
			} else {
				v.Hex = hex.EncodeToString(a.Value)
			}
		}
		out = append(out, v)
	}
	return out
}
