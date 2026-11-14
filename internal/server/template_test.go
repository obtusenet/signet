// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

package server

import (
	"html/template"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A template file that wraps its content in {{define "login"}} leaves the
// file-named template (login.html) empty.  Rendering must pick the definition,
// otherwise the page comes back blank.
func TestRenderTemplatePrefersNamedDefinition(t *testing.T) {
	set := template.New("set")
	if _, err := set.New("login.html").Parse(""); err != nil {
		t.Fatalf("parsing empty file template: %v", err)
	}
	if _, err := set.Parse(`{{define "login"}}<h1>Sign in as {{.Email}}</h1>{{end}}`); err != nil {
		t.Fatalf("parsing definition: %v", err)
	}

	s := &Server{tmpl: set}
	w := httptest.NewRecorder()
	if err := s.renderTemplate(w, "login.html", map[string]interface{}{"Email": "a@b.c"}); err != nil {
		t.Fatalf("renderTemplate: %v", err)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Sign in as a@b.c") {
		t.Errorf("body does not contain rendered definition: %q", body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
}

// A standalone login.html (no {{define}}) must still render by file name.
func TestRenderTemplateStandaloneFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "login.html"),
		[]byte("<p>standalone {{.Email}}</p>"), 0o644); err != nil {
		t.Fatalf("writing template: %v", err)
	}
	set, err := template.ParseGlob(filepath.Join(dir, "*.html"))
	if err != nil {
		t.Fatalf("ParseGlob: %v", err)
	}

	s := &Server{tmpl: set}
	w := httptest.NewRecorder()
	if err := s.renderTemplate(w, "login.html", map[string]interface{}{"Email": "x@y.z"}); err != nil {
		t.Fatalf("renderTemplate: %v", err)
	}
	if !strings.Contains(w.Body.String(), "standalone x@y.z") {
		t.Errorf("unexpected body: %q", w.Body.String())
	}
}

func TestRenderTemplateMissing(t *testing.T) {
	s := &Server{tmpl: template.New("set")}
	w := httptest.NewRecorder()
	if err := s.renderTemplate(w, "login.html", nil); err == nil {
		t.Fatal("expected an error for a missing template")
	}
	if w.Body.Len() != 0 {
		t.Errorf("error path wrote a body: %q", w.Body.String())
	}
}

func TestRenderTemplateNotLoaded(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	if err := s.renderTemplate(w, "login.html", nil); err == nil {
		t.Fatal("expected an error when no templates are loaded")
	}
	if w.Body.Len() != 0 {
		t.Errorf("error path wrote a body: %q", w.Body.String())
	}
}

// A template that fails while executing must not emit a partial page.
func TestRenderTemplateExecutionErrorWritesNothing(t *testing.T) {
	set := template.New("set")
	if _, err := set.Parse(`{{define "login"}}<p>{{.Count.Bogus}}</p>{{end}}`); err != nil {
		t.Fatalf("parsing template: %v", err)
	}
	s := &Server{tmpl: set}
	w := httptest.NewRecorder()
	// A field lookup on an int fails at execution time, after the template
	// has already started writing.
	if err := s.renderTemplate(w, "login.html", map[string]interface{}{"Count": 1}); err == nil {
		t.Fatal("expected an execution error")
	}
	if w.Body.Len() != 0 {
		t.Errorf("partial page written: %q", w.Body.String())
	}
}

func TestCheckTemplates(t *testing.T) {
	const login = `<html>sign in</html>`
	tests := []struct {
		name    string
		files   map[string]string
		wantErr string
	}{
		{"login page", map[string]string{"login.html": login}, ""},
		{"named definition", map[string]string{"page.html": `{{define "login"}}x{{end}}`}, ""},
		{"empty directory", nil, "matches no files"},
		{"no login page", map[string]string{"recover.html": login}, "no login.html"},
		{"broken template", map[string]string{"login.html": login, "recover.html": `{{`}, "recover.html"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range tt.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			err := CheckTemplates(dir)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckTemplates: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("CheckTemplates = %v, want an error about %q", err, tt.wantErr)
			}
		})
	}
}

func TestCheckTemplatesUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "login.html")
	if err := os.WriteFile(path, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := CheckTemplates(dir); err == nil {
		t.Fatal("an unreadable template passed the check")
	}
}
