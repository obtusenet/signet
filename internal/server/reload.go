// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
)

// front is what the listener serves: whichever server is live, so a reload can
// put a new one in without closing the listener.
func (s *Server) front() http.Handler {
	s.live.CompareAndSwap(nil, s)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.live.Load().servedHandler().ServeHTTP(w, r)
	})
}

func (s *Server) servedHandler() http.Handler {
	s.servedOnce.Do(func() { s.served = s.handler() })
	return s.served
}

// Swap makes next answer every request that arrives from now on, on this server's
// listener, which stays open.  A request already being answered finishes on the
// server it started on.  next takes over the housekeeping, and the mail queue, so
// that Shutdown still waits for every message.  next must not have served yet.
func (s *Server) Swap(next *Server) {
	s.live.CompareAndSwap(nil, s)
	next.mailJobs, next.mailSlots = s.mailJobs, s.mailSlots
	next.startHousekeeping(housekeepingInterval)
	old := s.live.Swap(next)
	old.haltHousekeeping()
}

// haltHousekeeping stops this server's upkeep; the listener is not touched.
func (s *Server) haltHousekeeping() {
	s.srvMu.Lock()
	stop := s.stopHousekeeping
	s.stopHousekeeping = nil
	s.srvMu.Unlock()
	if stop != nil {
		stop()
	}
}
