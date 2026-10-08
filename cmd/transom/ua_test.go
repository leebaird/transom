package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadDiscoverUA(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "user-agent.txt")
	body := "# comment\n\nMozilla/5.0 Edge\nMozilla/5.0 ignored\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readDiscoverUA(path); got != "Mozilla/5.0 Edge" {
		t.Fatalf("%q", got)
	}
	if got := readDiscoverUA(filepath.Join(dir, "missing")); got != "" {
		t.Fatalf("%q", got)
	}
}

func TestReadDiscoverUARejectsNonMozilla(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "user-agent.txt")
	if err := os.WriteFile(path, []byte("NotMozilla\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readDiscoverUA(path); got != "" {
		t.Fatalf("%q", got)
	}
}

func TestDiscoverUserAgentUsesEnv(t *testing.T) {
	t.Setenv("USER_AGENT", "Mozilla/5.0 from-env")
	if got := discoverUserAgent(); got != "Mozilla/5.0 from-env" {
		t.Fatalf("%q", got)
	}
}

func TestDiscoverUserAgentRejectsPlainEnv(t *testing.T) {
	t.Setenv("USER_AGENT", "curl/8.0")
	t.Setenv("DISCOVER", "")
	t.Setenv("HOME", t.TempDir())
	if got := discoverUserAgent(); got != discoverUAFallback {
		t.Fatalf("%q", got)
	}
	t.Setenv("USER_AGENT", "Mozilla/5.0\nbad")
	if got := discoverUserAgent(); got != discoverUAFallback {
		t.Fatalf("%q", got)
	}
}

func TestDiscoverUserAgentReadsDiscoverFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USER_AGENT", "")
	t.Setenv("DISCOVER", "")
	dir := filepath.Join(home, "discover", "resource")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/154.0.0.0"
	body := "# Discover scanner User-Agent\n" + ua + "\n"
	if err := os.WriteFile(filepath.Join(dir, "user-agent.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := discoverUserAgent()
	if got != ua {
		t.Fatalf("%q", got)
	}
	if strings.Contains(got, "Transom/") {
		t.Fatal(got)
	}
}
