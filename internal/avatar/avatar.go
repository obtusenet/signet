// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

// Package avatar keeps the image each account may set, and serves it by an id
// that says nothing about the account.
//
// An upload is never kept as sent.  It must be a PNG or JPEG of exactly the
// configured size, which is checked from its header before the pixels are
// decoded, and it is then encoded again.  So metadata such as a photo's position
// is dropped, and a file that is also something else (SVG, HTML, a polyglot)
// never comes back out.
package avatar

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"regexp"
	"strings"
	"time"
)

var (
	// ErrNotImage is an upload that is not a PNG or a JPEG.
	ErrNotImage = errors.New("not a PNG or JPEG image")
	// ErrSize is an image that is not the configured square.
	ErrSize = errors.New("wrong image size")
	// ErrNotFound is an id with no image.
	ErrNotFound = errors.New("no such avatar")
)

// jpegQuality is what a JPEG is encoded again at.
const jpegQuality = 85

// Normalize checks an upload and encodes it again, in its own format.  It
// returns the new bytes and their content type.
func Normalize(data []byte, size int) ([]byte, string, error) {
	config, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || (format != "png" && format != "jpeg") {
		return nil, "", ErrNotImage
	}
	if config.Width != size || config.Height != size {
		return nil, "", fmt.Errorf("%w: %dx%d, want %dx%d", ErrSize, config.Width, config.Height, size, size)
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, "", ErrNotImage
	}
	var out bytes.Buffer
	if format == "jpeg" {
		err = jpeg.Encode(&out, img, &jpeg.Options{Quality: jpegQuality})
		return out.Bytes(), "image/jpeg", err
	}
	err = (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&out, img)
	return out.Bytes(), "image/png", err
}

var idPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidID reports whether id could be an avatar's.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// Store keeps one image per account.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// NewStore keeps its images in db.
func NewStore(db *sql.DB) (*Store, error) {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS avatars (
		email TEXT PRIMARY KEY,
		id TEXT NOT NULL UNIQUE,
		content_type TEXT NOT NULL,
		image BLOB NOT NULL,
		updated_unix INTEGER NOT NULL
	)`); err != nil {
		return nil, fmt.Errorf("creating the avatar table: %w", err)
	}
	return &Store{db: db, now: time.Now}, nil
}

func key(address string) string { return strings.ToLower(address) }

// Set stores the account's image in place of any earlier one, under a new id, so
// the earlier one's address stops working.  img must have come from Normalize.
func (s *Store) Set(ctx context.Context, address string, img []byte, contentType string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	id := hex.EncodeToString(raw)
	_, err := s.db.ExecContext(ctx, `INSERT INTO avatars (email, id, content_type, image, updated_unix) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(email) DO UPDATE SET id = excluded.id, content_type = excluded.content_type,
			image = excluded.image, updated_unix = excluded.updated_unix`,
		key(address), id, contentType, img, s.now().Unix())
	if err != nil {
		return "", err
	}
	return id, nil
}

// ID is the account's image id, or "" when it has none.
func (s *Store) ID(ctx context.Context, address string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM avatars WHERE email = ?`, key(address)).Scan(&id)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return id, err
}

// Get is the image with this id and its content type.
func (s *Store) Get(ctx context.Context, id string) ([]byte, string, error) {
	var img []byte
	var contentType string
	err := s.db.QueryRowContext(ctx, `SELECT image, content_type FROM avatars WHERE id = ?`, id).Scan(&img, &contentType)
	if err == sql.ErrNoRows {
		return nil, "", ErrNotFound
	}
	return img, contentType, err
}

// Remove deletes the account's image, and reports whether it had one.
func (s *Store) Remove(ctx context.Context, address string) (bool, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM avatars WHERE email = ?`, key(address))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n > 0, err
}
