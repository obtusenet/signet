// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

// Package clientaddr works out which address a request came from.
//
// X-Forwarded-For is only a claim, and any client can send one.  It is believed
// only from a connection the configuration names as a trusted proxy, and then
// only as far as the chain of trusted proxies goes.
package clientaddr

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Unix is the trusted_proxies entry for a peer on a unix socket, and the address
// reported for one.  Such a peer has no address of its own.
const Unix = "unix"

// Resolver holds the trusted proxies.  A nil Resolver trusts none.
type Resolver struct {
	prefixes []netip.Prefix
	unix     bool
}

// New builds a Resolver from trusted_proxies entries: an IP address, a CIDR
// range, or Unix.
func New(entries []string) (*Resolver, error) {
	res := &Resolver{}
	for _, entry := range entries {
		if entry == Unix {
			res.unix = true
			continue
		}
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			res.prefixes = append(res.prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address, a CIDR range or %q", entry, Unix)
		}
		addr = addr.Unmap()
		res.prefixes = append(res.prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return res, nil
}

// Addr returns the address a request came from, without a port, so that every
// connection from a host shares one rate-limit budget.
//
// The header is read from the right, because each proxy appends the address it
// saw: the first entry that is not a trusted proxy is the client, and anything to
// the left of it is whatever that client chose to send.
func (res *Resolver) Addr(r *http.Request) string {
	peer := peerAddr(r.RemoteAddr)
	if !res.trusted(peer) {
		return peer
	}
	client := peer
	entries := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(entries) - 1; i >= 0; i-- {
		entry := strings.TrimSpace(entries[i])
		if entry == "" {
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			// A trusted proxy wrote no usable address here, so what lies to
			// the left of it cannot be attributed to anyone.
			return client
		}
		client = addr.Unmap().String()
		if !res.trusted(client) {
			return client
		}
	}
	return client
}

// peerAddr strips the port from a connection's address.  Over FastCGI this is
// the client the web server reported, not the web server.
func peerAddr(remote string) string {
	if remote == "" || remote == "@" {
		return Unix
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return host
}

func (res *Resolver) trusted(peer string) bool {
	if res == nil {
		return false
	}
	if peer == Unix {
		return res.unix
	}
	addr, err := netip.ParseAddr(peer)
	if err != nil {
		return false
	}
	addr = addr.WithZone("")
	for _, prefix := range res.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
