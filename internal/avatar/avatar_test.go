// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package avatar

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"path/filepath"
	"strings"
	"testing"

	"github.com/obtusenet/signet/internal/db"
)

func square(size int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), 128, 255})
		}
	}
	return img
}

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func encodeJPEG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, nil); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// exifJPEG puts an APP1 (EXIF) segment with a marker string after the SOI.
func exifJPEG(t *testing.T, marker string) []byte {
	plain := encodeJPEG(t, square(64))
	payload := append([]byte("Exif\x00\x00"), []byte(marker)...)
	n := len(payload) + 2
	segment := append([]byte{0xFF, 0xE1, byte(n >> 8), byte(n)}, payload...)
	return append(append(append([]byte{}, plain[:2]...), segment...), plain[2:]...)
}

func TestNormalizeKeepsTheFormat(t *testing.T) {
	out, contentType, err := Normalize(encodePNG(t, square(64)), 64)
	if err != nil || contentType != "image/png" {
		t.Fatalf("png: %q %v", contentType, err)
	}
	if _, format, err := image.Decode(bytes.NewReader(out)); err != nil || format != "png" {
		t.Errorf("png out: %q %v", format, err)
	}
	out, contentType, err = Normalize(encodeJPEG(t, square(64)), 64)
	if err != nil || contentType != "image/jpeg" {
		t.Fatalf("jpeg: %q %v", contentType, err)
	}
	if _, format, err := image.Decode(bytes.NewReader(out)); err != nil || format != "jpeg" {
		t.Errorf("jpeg out: %q %v", format, err)
	}
}

func TestNormalizeDropsMetadata(t *testing.T) {
	const marker = "GPSLatitude-48.8584"
	in := exifJPEG(t, marker)
	if !bytes.Contains(in, []byte(marker)) {
		t.Fatal("the test image has no metadata")
	}
	out, _, err := Normalize(in, 64)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte(marker)) || bytes.Contains(out, []byte("Exif")) {
		t.Error("the metadata came back out")
	}
}

func TestNormalizeRefuses(t *testing.T) {
	var gifData bytes.Buffer
	if err := gif.Encode(&gifData, square(64), nil); err != nil {
		t.Fatal(err)
	}
	pngData := encodePNG(t, square(64))
	for name, tc := range map[string]struct {
		data []byte
		want error
	}{
		"svg":        {[]byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`), ErrNotImage},
		"html":       {[]byte("<html><script>alert(1)</script></html>"), ErrNotImage},
		"gif":        {gifData.Bytes(), ErrNotImage},
		"empty":      {nil, ErrNotImage},
		"truncated":  {pngData[:len(pngData)/2], ErrNotImage},
		"too small":  {encodePNG(t, square(32)), ErrSize},
		"not square": {encodePNG(t, image.NewRGBA(image.Rect(0, 0, 64, 48))), ErrSize},
		// A header claiming a vast image is refused before any pixel is decoded.
		"bomb": {claimSize(encodePNG(t, square(64)), 20000), ErrSize},
	} {
		if _, _, err := Normalize(tc.data, 64); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

func TestStore(t *testing.T) {
	ctx := context.Background()
	store, err := db.New(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s, err := NewStore(store.DB())
	if err != nil {
		t.Fatal(err)
	}
	if id, err := s.ID(ctx, "a@example.com"); id != "" || err != nil {
		t.Fatalf("an account with no image: %q %v", id, err)
	}
	first, err := s.Set(ctx, "A@Example.com", []byte("one"), "image/png")
	if err != nil || !ValidID(first) {
		t.Fatalf("set: %q %v", first, err)
	}
	if id, _ := s.ID(ctx, "a@example.com"); id != first {
		t.Errorf("id %q, want %q", id, first)
	}
	second, _ := s.Set(ctx, "a@example.com", []byte("two"), "image/jpeg")
	if second == first {
		t.Error("a new image kept the old id")
	}
	if _, _, err := s.Get(ctx, first); !errors.Is(err, ErrNotFound) {
		t.Errorf("the replaced image is still served: %v", err)
	}
	img, contentType, err := s.Get(ctx, second)
	if err != nil || string(img) != "two" || contentType != "image/jpeg" {
		t.Errorf("get: %q %q %v", img, contentType, err)
	}
	if had, err := s.Remove(ctx, "a@example.com"); !had || err != nil {
		t.Fatalf("remove: %v %v", had, err)
	}
	if _, _, err := s.Get(ctx, second); !errors.Is(err, ErrNotFound) {
		t.Errorf("a removed image is still served: %v", err)
	}
	if had, _ := s.Remove(ctx, "a@example.com"); had {
		t.Error("a second remove found something")
	}
	if ValidID("../etc/passwd") || ValidID(first[:31]) || ValidID(strings32('G')) {
		t.Error("ValidID accepts what no id looks like")
	}
}

// claimSize rewrites a PNG's header to claim a size its data does not have.
func claimSize(data []byte, size uint32) []byte {
	out := append([]byte{}, data...)
	ihdr := out[12 : 12+4+13] // chunk type and data, after the 8-byte signature and the length
	binary.BigEndian.PutUint32(ihdr[4:], size)
	binary.BigEndian.PutUint32(ihdr[8:], size)
	binary.BigEndian.PutUint32(out[12+4+13:], crc32.ChecksumIEEE(ihdr))
	return out
}

func strings32(c byte) string { return string(bytes.Repeat([]byte{c}, 32)) }

func TestIdenticon(t *testing.T) {
	a := Identicon("a@example.com")
	if a != Identicon("A@Example.com") {
		t.Error("the same address in other case gives another pattern")
	}
	if a == Identicon("b@example.com") {
		t.Error("two addresses give the same pattern")
	}
	if !strings.HasPrefix(a, "<svg ") || !strings.HasSuffix(a, "</svg>") || strings.Contains(a, "example") {
		t.Errorf("not a plain SVG, or it names the address: %s", a)
	}
	// Mirrored: a cell on the left has its twin on the right.
	for row := 0; row < 5; row++ {
		for col := 0; col < 2; col++ {
			left := strings.Contains(a, fmt.Sprintf(`x="%d" y="%d"`, col, row))
			right := strings.Contains(a, fmt.Sprintf(`x="%d" y="%d"`, 4-col, row))
			if left != right {
				t.Errorf("row %d, column %d is not mirrored", row, col)
			}
		}
	}
	if !strings.HasPrefix(IdenticonURL("a@example.com"), "data:image/svg+xml;base64,") {
		t.Error("IdenticonURL")
	}
}
