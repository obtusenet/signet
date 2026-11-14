// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package avatar

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// Identicon is the picture shown for an account with none: a five-by-five
// pattern, mirrored left to right, in a colour taken from a hash of the address.
// It is SVG, and the same for an address every time.
func Identicon(address string) string {
	sum := sha256.Sum256([]byte(key(address)))
	hue := (int(sum[0])<<8 | int(sum[1])) % 360
	colour := fmt.Sprintf("hsl(%d,%d%%,%d%%)", hue, 45+int(sum[2])%25, 45+int(sum[3])%15)
	var b strings.Builder
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="-1.5 -1.5 8 8" shape-rendering="crispEdges">`)
	b.WriteString(`<rect x="-1.5" y="-1.5" width="8" height="8" fill="#f0f0f0"/>`)
	fmt.Fprintf(&b, `<g fill="%s">`, colour)
	for row := 0; row < 5; row++ {
		for col := 0; col < 3; col++ {
			bit := row*3 + col
			if sum[4+bit/8]>>(bit%8)&1 == 0 {
				continue
			}
			fmt.Fprintf(&b, `<rect x="%d" y="%d" width="1" height="1"/>`, col, row)
			if col != 2 {
				fmt.Fprintf(&b, `<rect x="%d" y="%d" width="1" height="1"/>`, 4-col, row)
			}
		}
	}
	b.WriteString(`</g></svg>`)
	return b.String()
}

// IdenticonURL is Identicon as a data: URL, for an img element.
func IdenticonURL(address string) string {
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(Identicon(address)))
}
