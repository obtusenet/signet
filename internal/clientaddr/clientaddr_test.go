// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package clientaddr

import (
	"net/http/httptest"
	"testing"
)

func TestAddr(t *testing.T) {
	cases := []struct {
		name    string
		trusted []string
		remote  string
		xff     []string
		want    string
	}{
		{"no proxies: the header is ignored", nil, "203.0.113.7:4000", []string{"198.51.100.1"}, "203.0.113.7"},
		{"unlisted peer: the header is ignored", []string{"10.0.0.1"}, "203.0.113.7:4000", []string{"198.51.100.1"}, "203.0.113.7"},
		{"no port", nil, "203.0.113.7", nil, "203.0.113.7"},
		{"IPv6 peer", nil, "[2001:db8::1]:4000", nil, "2001:db8::1"},
		{"IPv4-mapped peer", nil, "[::ffff:203.0.113.7]:4000", nil, "203.0.113.7"},

		{"trusted peer, one hop", []string{"10.0.0.1"}, "10.0.0.1:4000", []string{"203.0.113.7"}, "203.0.113.7"},
		{"trusted peer, no header", []string{"10.0.0.1"}, "10.0.0.1:4000", nil, "10.0.0.1"},
		{"CIDR range", []string{"10.0.0.0/8"}, "10.9.8.7:4000", []string{"203.0.113.7"}, "203.0.113.7"},
		{"mapped trusted peer", []string{"10.0.0.1"}, "[::ffff:10.0.0.1]:4000", []string{"203.0.113.7"}, "203.0.113.7"},

		// What the client sent is on the left; the proxy appended the rest.
		{"forged entry to the left", []string{"10.0.0.1"}, "10.0.0.1:4000", []string{"198.51.100.1, 203.0.113.7"}, "203.0.113.7"},
		{"two trusted hops", []string{"10.0.0.0/8"}, "10.0.0.1:4000", []string{"198.51.100.1, 203.0.113.7, 10.0.0.2"}, "203.0.113.7"},
		{"separate header lines", []string{"10.0.0.1"}, "10.0.0.1:4000", []string{"198.51.100.1", "203.0.113.7"}, "203.0.113.7"},
		{"all trusted", []string{"10.0.0.0/8"}, "10.0.0.1:4000", []string{"10.0.0.3, 10.0.0.2"}, "10.0.0.3"},
		{"garbage to the left is never reached", []string{"10.0.0.1"}, "10.0.0.1:4000", []string{"nonsense, 203.0.113.7"}, "203.0.113.7"},
		{"garbage from the proxy", []string{"10.0.0.1"}, "10.0.0.1:4000", []string{"198.51.100.1, nonsense"}, "10.0.0.1"},
		{"blank header", []string{"10.0.0.1"}, "10.0.0.1:4000", []string{" "}, "10.0.0.1"},

		{"socket peer, not trusted", []string{"10.0.0.1"}, "@", []string{"198.51.100.1"}, Unix},
		{"socket peer with an empty address", nil, "", []string{"198.51.100.1"}, Unix},
		{"socket peer, trusted", []string{Unix}, "@", []string{"203.0.113.7"}, "203.0.113.7"},
		{"socket peer, trusted, no header", []string{Unix}, "@", nil, Unix},
		{"unix does not trust TCP", []string{Unix}, "203.0.113.7:4000", []string{"198.51.100.1"}, "203.0.113.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := New(tc.trusted)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remote
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := res.Addr(r); got != tc.want {
				t.Errorf("Addr = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNilResolverTrustsNothing(t *testing.T) {
	var res *Resolver
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:4000"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	if got := res.Addr(r); got != "203.0.113.7" {
		t.Errorf("Addr = %q", got)
	}
}

func TestNewRejectsWhatItCannotRead(t *testing.T) {
	for _, entry := range []string{"", "proxy.example.com", "10.0.0.1:80", "10.0.0.0/99", "UNIX"} {
		if _, err := New([]string{entry}); err == nil {
			t.Errorf("%q was accepted", entry)
		}
	}
}
