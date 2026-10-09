package discover

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProbeHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	host, port := split(t, srv.Listener.Addr().String())
	scheme, err := Probe(t.Context(), host, port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if scheme != "http" {
		t.Fatalf("scheme %q", scheme)
	}
}

func TestProbeHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	host, port := split(t, srv.Listener.Addr().String())
	scheme, err := Probe(t.Context(), host, port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if scheme != "https" {
		t.Fatalf("scheme %q", scheme)
	}
}

func TestProbeDropsSSH(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-test\r\n"))
			_ = c.Close()
		}
	}()
	host, port := split(t, ln.Addr().String())
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	scheme, err := Probe(ctx, host, port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if scheme != "" {
		t.Fatalf("scheme %q", scheme)
	}
}

func TestLoadPorts(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/ports.txt"
	body := "# web ports\n80\n443  # https\n\n8080, 8081\n80\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPorts(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[0] != 80 || got[1] != 443 || got[2] != 8080 || got[3] != 8081 {
		t.Fatalf("%v", got)
	}
}

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("80, 443,80")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != 80 || got[1] != 443 {
		t.Fatalf("%v", got)
	}
	if _, err := ParsePorts("80,70000"); err == nil {
		t.Fatal("expected error")
	}
}

func TestProbeRefusedIsMiss(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, port := split(t, ln.Addr().String())
	ln.Close()
	scheme, err := Probe(t.Context(), host, port, time.Second)
	if err != nil || scheme != "" {
		t.Fatalf("scheme %q err %v", scheme, err)
	}
}

func TestProbeLookupError(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_, err := Probe(ctx, "no-such-host.invalid", 80, time.Second)
	if err == nil {
		t.Fatal("expected lookup error")
	}
}

func TestProbeHonorsTimeout(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(2 * time.Second)
	}()
	host, port := split(t, ln.Addr().String())
	start := time.Now()
	scheme, err := Probe(t.Context(), host, port, 200*time.Millisecond)
	if err != nil || scheme != "" {
		t.Fatalf("scheme %q err %v", scheme, err)
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("probe took %s", time.Since(start))
	}
}

func TestProbeCancelDoesNotWaitForTimeout(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// Hangs up on the TLS hello, then accepts the plaintext request and says
	// nothing: an open port that is not HTTP.
	go func() {
		for first := true; ; first = false {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if first {
				c.Close()
				continue
			}
			defer c.Close()
		}
	}()
	host, port := split(t, ln.Addr().String())
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	if _, err := Probe(ctx, host, port, 30*time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("probe took %s after cancel", took)
	}
}

func TestParsePortListNamesFile(t *testing.T) {
	_, err := ParsePortList("ports.txt", []byte("80\n22/tcp\n"))
	if err == nil || !strings.Contains(err.Error(), "ports.txt: invalid port") {
		t.Fatalf("err %v", err)
	}
}

func TestDiscoverCancelKeepsHits(t *testing.T) {
	var once sync.Once
	seen := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(seen) })
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	host, port := split(t, srv.Listener.Addr().String())
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(io.Discard, c)
	}()
	_, slow := split(t, ln.Addr().String())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		select {
		case <-seen:
			time.Sleep(200 * time.Millisecond)
			cancel()
		case <-time.After(3 * time.Second):
			cancel()
		}
	}()
	got, err := Discover(ctx, host, []int{port, slow}, 2, 5*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if len(got) != 1 || got[0].Port != port || got[0].Scheme != "http" {
		t.Fatalf("%+v", got)
	}
}

func TestProxyFromEnvironment(t *testing.T) {
	// net/http caches ProxyFromEnvironment on first use, and earlier tests
	// already dialed. Check the environment in a fresh process.
	if os.Getenv("TRANSOM_PROXY_SUB") != "1" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestProxyFromEnvironment$")
		cmd.Env = append(os.Environ(),
			"TRANSOM_PROXY_SUB=1",
			"HTTP_PROXY=http://proxy.example:8080",
			"HTTPS_PROXY=http://proxy.example:8443",
			"NO_PROXY=",
			"REQUEST_METHOD=",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return
	}
	httpProxy, err := proxyFor(t.Context(), "http", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	if httpProxy == nil || httpProxy.Host != "proxy.example:8080" {
		t.Fatalf("http proxy %+v", httpProxy)
	}
	httpsProxy, err := proxyFor(t.Context(), "https", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if httpsProxy == nil || httpsProxy.Host != "proxy.example:8443" {
		t.Fatalf("https proxy %+v", httpsProxy)
	}
	// Two proxies are two routes, so a miss through one still tries the other.
	if sameRoute(t.Context(), "example.com:8080") {
		t.Fatal("different proxies reported as one route")
	}
	if dials := missDials(t, "example.com"); len(dials) != 2 || dials[0] != "https" || dials[1] != "http" {
		t.Fatalf("dials %v", dials)
	}
}

// missDials probes a port where every dial is a miss and returns the scheme
// of each dial made.
func missDials(t *testing.T, host string) []string {
	t.Helper()
	var dials []string
	miss := func(_ context.Context, _, scheme string, _ time.Duration) (net.Conn, error) {
		dials = append(dials, scheme)
		return nil, nil //nolint:nilnil // a miss, as dial reports it
	}
	scheme, err := probe(t.Context(), host, 8080, time.Second, miss)
	if err != nil || scheme != "" {
		t.Fatalf("scheme %q err %v", scheme, err)
	}
	return dials
}

func TestProbeMissDialsOnce(t *testing.T) {
	// A loopback address is never proxied, so both dials would take one route.
	if dials := missDials(t, "127.0.0.1"); len(dials) != 1 || dials[0] != "https" {
		t.Fatalf("dials %v", dials)
	}
}

func TestConnectProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "want CONNECT", http.StatusBadRequest)
			return
		}
		dest, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer dest.Close()
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		client, _, err := hj.Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		go func() { _, _ = io.Copy(dest, client) }()
		_, _ = io.Copy(client, dest)
	}))
	defer proxy.Close()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxy.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	host, port := split(t, backend.Listener.Addr().String())
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	conn, err := connectProxy(ctx, req.URL, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET / HTTP/1.0\r\nHost: "+host+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if n < 8 || (string(buf[:8]) != "HTTP/1.1" && string(buf[:8]) != "HTTP/1.0") {
		t.Fatalf("tunneled response %q err %v", buf[:n], err)
	}
}

func split(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
