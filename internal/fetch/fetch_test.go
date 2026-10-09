package fetch

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leebaird/transom/internal/target"
)

func opts() Options {
	return Options{Timeout: 2 * time.Second, Follow: "same-host", MaxBody: 1 << 20, UserAgent: "Transom/test"}
}

func TestHostIncludesNonDefaultPort(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	tg := mustParse(t, srv.URL)
	c, err := New(tg, opts())
	if err != nil {
		t.Fatal(err)
	}
	resp := c.Do(t.Context(), http.MethodGet, "/")
	if resp.Err != nil {
		t.Fatal(resp.Err)
	}
	if got != tg.HostPort() {
		t.Fatalf("Host %q want %q", got, tg.HostPort())
	}
}

func TestSeeOtherBecomesGET(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/final", http.StatusSeeOther)
		default:
			got = r.Method
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	c, err := New(mustParse(t, srv.URL), opts())
	if err != nil {
		t.Fatal(err)
	}
	resp := c.Do(t.Context(), http.MethodPost, "/start")
	if resp.Err != nil {
		t.Fatal(resp.Err)
	}
	if resp.Status != http.StatusNoContent {
		t.Fatalf("status %d", resp.Status)
	}
	if got != http.MethodGet {
		t.Fatalf("method %s", got)
	}
}

func TestOffHostRedirectStops(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/landed", http.StatusFound)
	}))
	defer srv.Close()
	c, err := New(mustParse(t, srv.URL), opts())
	if err != nil {
		t.Fatal(err)
	}
	resp := c.Do(t.Context(), http.MethodGet, "/")
	if resp.Err != nil {
		t.Fatal(resp.Err)
	}
	if resp.Status != http.StatusFound {
		t.Fatalf("status %d", resp.Status)
	}
	if hits.Load() != 0 {
		t.Fatalf("off-host hits %d", hits.Load())
	}
}

func TestCookieJarsAreSeparate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/set":
			http.SetCookie(w, &http.Cookie{Name: "a", Value: "b", Path: "/"})
		default:
			_, _ = io.WriteString(w, r.Header.Get("Cookie"))
		}
	}))
	defer srv.Close()
	tg := mustParse(t, srv.URL)
	a, err := New(tg, opts())
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(tg, opts())
	if err != nil {
		t.Fatal(err)
	}
	if resp := a.Do(t.Context(), http.MethodGet, "/set"); resp.Err != nil {
		t.Fatal(resp.Err)
	}
	echoA := a.Do(t.Context(), http.MethodGet, "/echo")
	echoB := b.Do(t.Context(), http.MethodGet, "/echo")
	if echoA.Err != nil || echoB.Err != nil {
		t.Fatalf("a %v b %v", echoA.Err, echoB.Err)
	}
	if !strings.Contains(echoA.Body, "a=b") {
		t.Fatalf("client A cookie %q", echoA.Body)
	}
	if echoB.Body != "" {
		t.Fatalf("client B cookie %q", echoB.Body)
	}
}

func TestBodyCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 50))
	}))
	defer srv.Close()
	o := opts()
	o.MaxBody = 10
	c, err := New(mustParse(t, srv.URL), o)
	if err != nil {
		t.Fatal(err)
	}
	resp := c.Do(t.Context(), http.MethodGet, "/")
	if resp.Err != nil {
		t.Fatal(resp.Err)
	}
	if !resp.Truncated || len(resp.Body) != 10 {
		t.Fatalf("truncated %v len %d", resp.Truncated, len(resp.Body))
	}
}

func TestShortReadKeepsStatus(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 2048)
		_, _ = conn.Read(buf)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nX-Test: yes\r\n\r\nshort")
		conn.Close()
	}()
	c, err := New(mustParse(t, "http://"+ln.Addr().String()+"/"), opts())
	if err != nil {
		t.Fatal(err)
	}
	resp := c.Do(t.Context(), http.MethodGet, "/")
	if resp.Err != nil {
		t.Fatal(resp.Err)
	}
	if resp.Status != 200 || resp.Body != "short" || !resp.Truncated || resp.Header.Get("X-Test") != "yes" {
		t.Fatalf("%+v", resp)
	}
}

func TestRetriesAnyMethodOnClosedIdleConn(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var conns atomic.Int64
	var keySent atomic.Bool
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			first := conns.Add(1) == 1
			go func() {
				defer conn.Close()
				br := bufio.NewReader(conn)
				for served := 0; ; served++ {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					if _, ok := req.Header["Idempotency-Key"]; ok {
						keySent.Store(true)
					}
					// The first connection answers once, then drops the next
					// request unanswered, as a server does when its keep-alive
					// timer fires just as the request arrives.
					if first && served == 1 {
						return
					}
					_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				}
			}()
		}
	}()
	c, err := New(mustParse(t, "http://"+ln.Addr().String()), opts())
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if resp := c.Do(t.Context(), http.MethodPost, "/"); resp.Err != nil || resp.Body != "ok" {
			t.Fatalf("request %d: %+v", i, resp)
		}
	}
	if conns.Load() != 2 {
		t.Fatalf("%d connections, want a retry on a second", conns.Load())
	}
	if keySent.Load() {
		t.Fatal("Idempotency-Key was sent on the wire")
	}
}

func TestClientPoolMatchesConcurrency(t *testing.T) {
	for _, tc := range []struct{ concurrency, want int }{
		{0, http.DefaultMaxIdleConnsPerHost},
		{1, http.DefaultMaxIdleConnsPerHost},
		{8, 8},
		{500, 500},
	} {
		o := opts()
		o.Concurrency = tc.concurrency
		c, err := New(mustParse(t, "https://example.com"), o)
		if err != nil {
			t.Fatal(err)
		}
		tr, ok := c.http.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("transport %T", c.http.Transport)
		}
		if tr.MaxIdleConnsPerHost != tc.want || tr.MaxIdleConns < tc.want {
			t.Errorf("concurrency %d: per host %d, total %d", tc.concurrency, tr.MaxIdleConnsPerHost, tr.MaxIdleConns)
		}
	}
}

func TestClientAllowsTLS10(t *testing.T) {
	c, err := New(mustParse(t, "https://example.com"), opts())
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport %T", c.http.Transport)
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS10 {
		t.Fatalf("min version %x", tr.TLSClientConfig.MinVersion)
	}
}

func TestSameTargetRequiresScheme(t *testing.T) {
	tg := target.Target{Host: "example.com", Port: 8443, Scheme: "https", Root: "/"}
	down, err := url.Parse("http://example.com:8443/")
	if err != nil {
		t.Fatal(err)
	}
	if sameTarget(tg, down) {
		t.Fatal("https to http on the same port was allowed")
	}
	same, err := url.Parse("https://example.com:8443/next")
	if err != nil {
		t.Fatal(err)
	}
	if !sameTarget(tg, same) {
		t.Fatal("same-scheme redirect was rejected")
	}
}

func mustParse(t *testing.T, raw string) target.Target {
	t.Helper()
	tg, err := target.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}
