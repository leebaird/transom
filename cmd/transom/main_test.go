package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"version"}, &out, &errBuf); code != 0 {
		t.Fatalf("code %d %s", code, errBuf.String())
	}
	if out.String() != "Transom\n" {
		t.Fatalf("%q", out.String())
	}
}

func TestUsage(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"-h"}, &out, &errBuf); code != 1 {
		t.Fatalf("code %d", code)
	}
	text := errBuf.String()
	if !strings.HasPrefix(text, "Transom\nby Lee Baird\n") {
		t.Fatalf("%q", text)
	}
	if !strings.HasSuffix(text, "-o path           Write a JSON or HTML report\n\n") {
		t.Fatalf("%q", text)
	}
	if strings.Contains(text, "Inspired by Nikto") || strings.Contains(text, "authorized to scan") || strings.Contains(text, "allowed to scan") {
		t.Fatalf("%q", text)
	}
}

func TestScanURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		switch {
		case strings.Contains(r.URL.Path, "transom-"), r.URL.Path == "/robots.txt":
			http.NotFound(w, r)
		case r.URL.Path == "/.env":
			_, _ = io.WriteString(w, "DB_PASSWORD=x\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	checks := filepath.Join(dir, "checks")
	if err := os.Mkdir(checks, 0o755); err != nil {
		t.Fatal(err)
	}
	raw := `[{"id":"env-file","path":"/.env","statuses":[200],"body":"DB_PASSWORD","message":"env exposed"}]`
	if err := os.WriteFile(filepath.Join(checks, "a.json"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "report.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"--checks", checks, "--follow", "off", "-o", outPath, srv.URL}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d stderr %s stdout %s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "env-file") || !strings.Contains(stdout.String(), "env exposed") {
		t.Fatalf("stdout %s", stdout.String())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"id": "env-file"`) {
		t.Fatalf("json %s", data)
	}
	if _, err := os.Stat(outPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp report remains")
	}
}

func TestPortsErrorStillWritesReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.URL.Path == "/.env" {
			_, _ = io.WriteString(w, "DB_PASSWORD=x\n")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dir := t.TempDir()
	checks := filepath.Join(dir, "checks")
	if err := os.Mkdir(checks, 0o755); err != nil {
		t.Fatal(err)
	}
	raw := `[{"id":"env-file","path":"/.env","statuses":[200],"body":"DB_PASSWORD","message":"env exposed"}]`
	if err := os.WriteFile(filepath.Join(checks, "a.json"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "report.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"--checks", checks, "--follow", "off", "-o", outPath, srv.URL, "missing.example"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "ports.txt") {
		t.Fatalf("stderr %s", stderr.String())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"id": "env-file"`) {
		t.Fatalf("json %s", data)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestWriteTextErrorStillWritesReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	dir := t.TempDir()
	checks := filepath.Join(dir, "checks")
	if err := os.Mkdir(checks, 0o755); err != nil {
		t.Fatal(err)
	}
	raw := `[{"id":"env-file","path":"/.env","statuses":[200],"body":"DB_PASSWORD","message":"env exposed"}]`
	if err := os.WriteFile(filepath.Join(checks, "a.json"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "report.json")
	var stderr bytes.Buffer
	code := run([]string{"--checks", checks, "--follow", "off", "-o", outPath, srv.URL}, failWriter{}, &stderr)
	if code != 1 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"id": "header-csp"`) {
		t.Fatalf("json %s", data)
	}
}

func TestScanHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		switch {
		case strings.Contains(r.URL.Path, "transom-"), r.URL.Path == "/robots.txt":
			http.NotFound(w, r)
		case r.URL.Path == "/.env":
			_, _ = io.WriteString(w, "DB_PASSWORD=x\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	checks := filepath.Join(dir, "checks")
	if err := os.Mkdir(checks, 0o755); err != nil {
		t.Fatal(err)
	}
	raw := `[{"id":"env-file","path":"/.env","statuses":[200],"body":"DB_PASSWORD","message":"env exposed"}]`
	if err := os.WriteFile(filepath.Join(checks, "a.json"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "report.htm")
	var stdout, stderr bytes.Buffer
	code := run([]string{"--checks", checks, "--follow", "off", "-o", outPath, srv.URL}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if !strings.Contains(body, "<!DOCTYPE html>") || !strings.Contains(body, "env-file") || !strings.Contains(body, "Lee Baird") {
		t.Fatalf("%s", body)
	}
}
