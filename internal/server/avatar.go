// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/obtusenet/signet/internal/auth"
	"github.com/obtusenet/signet/internal/avatar"
	"github.com/obtusenet/signet/internal/db"
	"github.com/obtusenet/signet/internal/session"
)

// startAvatars opens the image store when avatars are enabled.
func (s *Server) startAvatars(dbStore *db.DB) {
	if s.cfg.Avatars != "enabled" {
		return
	}
	store, err := avatar.NewStore(dbStore.DB())
	if err != nil {
		s.logger.Error(fmt.Sprintf("avatars are off: %v", err))
		return
	}
	s.avatars = store
	s.avatarLimiter = auth.NewEmailRateLimiter(s.cfg.AvatarRateLimit, time.Duration(s.cfg.AvatarRateWindow)*time.Second)
	s.housekeeping = append(s.housekeeping, func(context.Context) { s.avatarLimiter.Cleanup() })
	s.logger.Info(fmt.Sprintf("avatars enabled, %d pixels a side", s.cfg.AvatarSize))
}

// handleAvatar serves an image by its id, to anyone: the id is random and new with
// each upload, so it says nothing about the account, and it never changes what it
// names, so it may be cached for good.
func (s *Server) handleAvatar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/avatar/")
	if !avatar.ValidID(id) {
		http.NotFound(w, r)
		return
	}
	img, contentType, err := s.avatars.Get(r.Context(), id)
	if errors.Is(err, avatar.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.logger.Error(fmt.Sprintf("reading avatar %s: %v", id, err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(img)))
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	// Other sites' pages show it: that is what it is for.
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	if r.Method == http.MethodGet {
		w.Write(img)
	}
}

// avatarPath is where the account's image is, as a path on this host, or "".
func (s *Server) avatarPath(ctx context.Context, address string) string {
	if s.avatars == nil {
		return ""
	}
	id, err := s.avatars.ID(ctx, address)
	if err != nil {
		s.logger.Error(fmt.Sprintf("reading the avatar of %s: %v", address, err))
		return ""
	}
	if id == "" {
		return ""
	}
	return s.path("/avatar/" + id)
}

// avatarURL is the account's image for applications: an absolute URL when
// public_url says where this instance is, else a path on this host; null when
// there is none.
func (s *Server) avatarURL(ctx context.Context, address string) interface{} {
	p := s.avatarPath(ctx, address)
	if p == "" {
		return nil
	}
	return strings.TrimRight(s.cfg.PublicURL, "/") + p
}

// setAvatar takes the image the page made: a square of avatar_size, as base64.
func (s *Server) setAvatar(w http.ResponseWriter, r *http.Request, sess *session.Session, encoded string) {
	if s.avatars == nil {
		accountError(w, http.StatusForbidden, "Avatars are disabled for this installation.")
		return
	}
	address := sess.UserEmail
	if !s.avatarLimiter.Allow(strings.ToLower(address)) {
		s.logger.Warn(fmt.Sprintf("rate limited: avatar upload for %s from %s", address, s.clients.Addr(r)))
		accountError(w, http.StatusTooManyRequests, "Too many new images. Try again later.")
		return
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		accountError(w, http.StatusBadRequest, "The image could not be read.")
		return
	}
	img, contentType, err := avatar.Normalize(data, s.cfg.AvatarSize)
	switch {
	case errors.Is(err, avatar.ErrSize):
		accountError(w, http.StatusBadRequest, fmt.Sprintf("The image must be %d by %d pixels.", s.cfg.AvatarSize, s.cfg.AvatarSize))
		return
	case err != nil:
		accountError(w, http.StatusBadRequest, "The image must be a PNG or a JPEG.")
		return
	}
	id, err := s.avatars.Set(r.Context(), address, img, contentType)
	if err != nil {
		s.logger.Error(fmt.Sprintf("storing the avatar of %s: %v", address, err))
		accountError(w, http.StatusInternalServerError, "The image could not be saved.")
		return
	}
	s.logger.Info(fmt.Sprintf("avatar set by %s from %s (%s, %d bytes)", address, s.clients.Addr(r), contentType, len(img)))
	accountReply(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Your picture has been changed.",
		"avatar":  s.path("/avatar/" + id),
	})
}

func (s *Server) removeAvatar(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	if s.avatars == nil {
		accountError(w, http.StatusForbidden, "Avatars are disabled for this installation.")
		return
	}
	had, err := s.avatars.Remove(r.Context(), sess.UserEmail)
	if err != nil {
		s.logger.Error(fmt.Sprintf("removing the avatar of %s: %v", sess.UserEmail, err))
		accountError(w, http.StatusInternalServerError, "The picture could not be removed.")
		return
	}
	if had {
		s.logger.Info(fmt.Sprintf("avatar removed by %s from %s", sess.UserEmail, s.clients.Addr(r)))
	}
	accountReply(w, http.StatusOK, map[string]interface{}{"success": true, "message": "Your picture has been removed."})
}
