// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package cookie

import (
	"net/http"
	"testing"
)

func TestCookieSecureDefaultsToTrue(t *testing.T) {
	cm := NewCookieManager("signetid", "", 3600, []byte("secret"))
	c := cm.CreateAuthCookie("token")
	if !c.Secure {
		t.Error("cookies must be Secure by default")
	}
	if !c.HttpOnly {
		t.Error("cookies must be HttpOnly")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", c.SameSite)
	}
}

func TestCookieSecureCanBeDisabled(t *testing.T) {
	cm := NewCookieManager("signetid", "", 3600, []byte("secret"))
	cm.Secure = false
	if c := cm.CreateAuthCookie("token"); c.Secure {
		t.Error("Secure flag was not cleared for a plain-HTTP deployment")
	}
}
