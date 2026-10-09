package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/leebaird/transom"
	"github.com/leebaird/transom/internal/discover"
)

func TestVersion(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"version"}, &out, &errBuf); code != 0 {
		t.Fatalf("code %d %s", code, errBuf.String())
	}
	if !strings.HasPrefix(out.String(), "Transom") || !strings.HasSuffix(out.String(), "\n") {
		t.Fatalf("%q", out.String())
	}
}

func TestVersionLine(t *testing.T) {
	tagged := &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}
	for _, tc := range []struct {
		name string
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{"tagged", tagged, true, "Transom v1.2.3"},
		{"no version", &debug.BuildInfo{}, true, "Transom"},
		{"no build info", nil, false, "Transom"},
	} {
		if got := versionLine(tc.info, tc.ok); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
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

// envServer serves a readable /.env and answers 404 for every other path.
func envServer(t *testing.T) *httptest.Server {
	t.Helper()
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
	t.Cleanup(srv.Close)
	return srv
}

// envChecks writes a checks directory under dir holding one check, for /.env.
func envChecks(t *testing.T, dir string) string {
	t.Helper()
	checks := filepath.Join(dir, "checks")
	if err := os.Mkdir(checks, 0o750); err != nil {
		t.Fatal(err)
	}
	raw := `[{"id":"env-file","path":"/.env","statuses":[200],"body":"DB_PASSWORD","message":"env exposed"}]`
	if err := os.WriteFile(filepath.Join(checks, "a.json"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return checks
}

func TestParseFlagsRejects(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--follow", "always", "example.com"}, "follow must be off or same-host"},
		{[]string{"--concurrency", "0", "example.com"}, "concurrency must be at least 1"},
		{[]string{"--timeout", "0s", "example.com"}, "timeout must be positive"},
		{[]string{"--max-body", "-1", "example.com"}, "max-body must be zero or positive"},
		{[]string{"--header", "no-colon", "example.com"}, "header must be Name: value"},
		{nil, "Usage:"},
	} {
		var stderr bytes.Buffer
		if _, ok := parseFlags(tc.args, &stderr); ok {
			t.Errorf("%v: accepted", tc.args)
		}
		if !strings.Contains(stderr.String(), tc.want) {
			t.Errorf("%v: stderr %q, want %q", tc.args, stderr.String(), tc.want)
		}
	}
}

func TestParseFlags(t *testing.T) {
	var stderr bytes.Buffer
	cfg, ok := parseFlags([]string{
		"--ports", "80,8080", "--timeout", "5s", "--concurrency", "3", "--follow", "off",
		"--max-body", "10", "--user-agent", "Mozilla/5.0 test", "--header", "X-A: 1", "--header", "X-A: 2",
		"-o", "r.htm", "a.example", "b.example",
	}, &stderr)
	if !ok {
		t.Fatalf("rejected: %s", stderr.String())
	}
	if len(cfg.targets) != 2 || cfg.ports != "80,8080" || cfg.output != "r.htm" || cfg.concurrency != 3 {
		t.Fatalf("%+v", cfg)
	}
	f := cfg.fetch
	if f.Timeout != 5*time.Second || f.Concurrency != 3 || f.Follow != "off" || f.MaxBody != 10 || f.UserAgent != "Mozilla/5.0 test" {
		t.Fatalf("%+v", f)
	}
	if got := f.Headers.Values("X-A"); len(got) != 2 || got[0] != "1" || got[1] != "2" {
		t.Fatalf("headers %v", f.Headers)
	}
}

func TestScanURL(t *testing.T) {
	srv := envServer(t)

	dir := t.TempDir()
	checks := envChecks(t, dir)
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
	if left, _ := filepath.Glob(outPath + ".*.tmp"); len(left) > 0 {
		t.Fatalf("temp report remains: %v", left)
	}
}

func TestPortsErrorStillWritesReport(t *testing.T) {
	srv := envServer(t)

	dir := t.TempDir()
	checks := envChecks(t, dir)
	// A ports.txt in the current directory wins over the embedded list.
	if err := os.WriteFile(filepath.Join(dir, "ports.txt"), []byte("# none\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
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

func TestEmbeddedDefaults(t *testing.T) {
	// Nothing on disk here, so both lookups miss and the binary's copy is used.
	t.Chdir(t.TempDir())
	if found := overrides("checks", true); len(found) > 0 {
		t.Fatalf("found checks at %+v", found)
	}
	var stderr bytes.Buffer
	checks, err := loadChecks("", &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) == 0 || stderr.Len() > 0 {
		t.Fatalf("%d embedded checks, stderr %q", len(checks), stderr.String())
	}
	if found := overrides("ports.txt", false); len(found) > 0 {
		t.Fatalf("found ports at %+v", found)
	}
	ports, err := discover.ParsePortList("built-in ports.txt", transom.Ports)
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) == 0 {
		t.Fatal("no embedded ports")
	}
}

func TestChecksInCurrentDirectory(t *testing.T) {
	builtIn, err := loadChecks("", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Chdir(dir)

	// A directory that only shares the name is not a corpus.
	if err := os.Mkdir("checks", 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("checks", "notes.txt"), []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	checks, err := loadChecks("", &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != len(builtIn) || stderr.Len() > 0 {
		t.Fatalf("%d checks, want the %d built in; stderr %q", len(checks), len(builtIn), stderr.String())
	}

	// One that holds checks is used, and said to be.
	raw := `[{"id":"only","path":"/only","message":"m"}]`
	if err := os.WriteFile(filepath.Join("checks", "a.json"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	checks, err = loadChecks("", &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 || checks[0].ID != "only" {
		t.Fatalf("%+v", checks)
	}
	if !strings.Contains(stderr.String(), "using ./checks in the current directory") {
		t.Fatalf("stderr %q", stderr.String())
	}

	// One that fails to load is an error, with the same notice.
	stderr.Reset()
	if err := os.WriteFile(filepath.Join("checks", "b.json"), []byte(`{"not":"checks"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadChecks("", &stderr); err == nil || !strings.Contains(stderr.String(), "using ./checks") {
		t.Fatalf("err %v stderr %q", err, stderr.String())
	}

	// --checks is taken as given, with no notice.
	stderr.Reset()
	empty := filepath.Join(dir, "empty")
	if err := os.Mkdir(empty, 0o750); err != nil {
		t.Fatal(err)
	}
	checks, err = loadChecks(empty, &stderr)
	if err != nil || len(checks) != 0 || stderr.Len() > 0 {
		t.Fatalf("%d checks err %v stderr %q", len(checks), err, stderr.String())
	}
}

func TestPortsInCurrentDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("ports.txt", []byte("22/tcp open ssh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	s := &scanner{stderr: &stderr}
	err := s.loadPorts()
	if err == nil || !strings.Contains(err.Error(), "ports.txt: invalid port") {
		t.Fatalf("err %v", err)
	}
	if !strings.Contains(stderr.String(), "using ./ports.txt in the current directory") {
		t.Fatalf("stderr %q", stderr.String())
	}

	if err := os.WriteFile("ports.txt", []byte("8080\n8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.loadPorts(); err != nil || len(s.ports) != 2 {
		t.Fatalf("ports %v err %v", s.ports, err)
	}

	// --ports wins and reads no file.
	stderr.Reset()
	flagged := &scanner{stderr: &stderr, cfg: config{ports: "81"}}
	if err := flagged.loadPorts(); err != nil || len(flagged.ports) != 1 || stderr.Len() > 0 {
		t.Fatalf("ports %v err %v stderr %q", flagged.ports, err, stderr.String())
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
	checks := envChecks(t, dir)
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
	srv := envServer(t)

	dir := t.TempDir()
	checks := envChecks(t, dir)
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
