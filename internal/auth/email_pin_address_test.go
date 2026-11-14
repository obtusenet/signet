// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package auth

import (
	"strings"
	"testing"

	"github.com/obtusenet/signet/internal/backend/csv"
)

// The routes rely on this to keep a caller's text out of the log.
func TestValidateEmailStopsWhatForgesALogLine(t *testing.T) {
	for _, address := range []string{
		"x@example.com\nINFO: forged",
		"x@example.com\r\nINFO: forged",
		"x@example.com\u2028INFO: forged",
		"x@example.com\x1b[31m",
		strings.Repeat("a", 300) + "@example.com",
	} {
		if err := csv.ValidateEmail(address); err == nil {
			t.Errorf("%.30q was accepted", address)
		} else if strings.Contains(err.Error(), "forged") {
			t.Errorf("the error repeats the address: %v", err)
		}
	}
}
