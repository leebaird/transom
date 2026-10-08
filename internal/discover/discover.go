// Package discover finds which ports on a host speak HTTP or HTTPS.
package discover

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/leebaird/transom/internal/target"
)

var statusLine = regexp.MustCompile(`^HTTP/1\.[0-9] [0-9]{3}`)

// LoadPorts reads ports.txt. Blank lines and # comments are ignored.
// Each remaining line is one port, or several ports separated by commas.
func LoadPorts(path string) ([]int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ports: %w", err)
	}
	var parts []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		for _, part := range strings.Split(line, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				parts = append(parts, part)
			}
		}
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("%s: no ports", path)
	}
	return ParsePorts(strings.Join(parts, ","))
}

// ParsePorts parses a comma-separated list of ports.
func ParsePorts(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty port list")
	}
	parts := strings.Split(s, ",")
	out := make([]int, 0, len(parts))
	seen := map[int]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out, nil
}

// Discover probes each port and returns one target per port that speaks HTTP.
// Order follows ports. timeout is the deadline for one dial and its handshake.
// A canceled context returns the error and any hits found. When every port
// fails with a lookup or network error, that error is returned. A refused or
// unanswered port is a miss.
func Discover(ctx context.Context, host string, ports []int, concurrency int, timeout time.Duration) ([]target.Target, error) {
	if concurrency < 1 {
		concurrency = 1
	}
	schemes := make([]string, len(ports))
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	var firstErr error
	var errMu sync.Mutex
	for i, port := range ports {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(i, port int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			scheme, err := Probe(ctx, host, port, timeout)
			if err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				return
			}
			schemes[i] = scheme
		}(i, port)
	}
	wg.Wait()
	var out []target.Target
	for i, scheme := range schemes {
		if scheme == "" {
			continue
		}
		out = append(out, target.Target{
			Host:   host,
			Port:   ports[i],
			Scheme: scheme,
			Root:   "/",
		})
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if len(out) > 0 {
		return out, nil
	}
	return out, firstErr
}

// Probe reports "https" or "http" when port speaks that protocol.
// An empty scheme and a nil error means the port is closed or not HTTP.
// timeout is the deadline for each dial. Lookup and network errors are returned.
// A refused connection or a dial that hits timeout is a miss.
func Probe(ctx context.Context, host string, port int, timeout time.Duration) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	ok, err := tlsHello(ctx, addr, host, timeout)
	if err != nil {
		return "", err
	}
	if ok {
		return "https", nil
	}
	ok, err = httpHello(ctx, addr, host, port, timeout)
	if err != nil {
		return "", err
	}
	if ok {
		return "http", nil
	}
	return "", nil
}

func tlsHello(ctx context.Context, addr, host string, timeout time.Duration) (bool, error) {
	conn, err := dial(ctx, addr, "https", timeout)
	if err != nil {
		return false, err
	}
	if conn == nil {
		return false, nil
	}
	defer conn.Close()
	name := host
	if net.ParseIP(host) != nil {
		name = ""
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         name,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	ok, err := handshake(ctx, tlsConn)
	if err != nil {
		return false, err
	}
	return ok, nil
}

func handshake(ctx context.Context, conn *tls.Conn) (bool, error) {
	errc := make(chan error, 1)
	go func() { errc <- conn.Handshake() }()
	select {
	case <-ctx.Done():
		conn.Close()
		return false, ctx.Err()
	case err := <-errc:
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			return false, nil
		}
		return true, nil
	}
}

func httpHello(ctx context.Context, addr, host string, port int, timeout time.Duration) (bool, error) {
	conn, err := dial(ctx, addr, "http", timeout)
	if err != nil {
		return false, err
	}
	if conn == nil {
		return false, nil
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	req := "GET / HTTP/1.0\r\nHost: " + hostHeader(host, port) + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	return statusLine.MatchString(strings.TrimRight(line, "\r\n")), nil
}

func hostHeader(host string, port int) string {
	if port == 80 {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// Dial opens a TCP connection to host:port. HTTP_PROXY and HTTPS_PROXY are
// honored the same way as the scan client, including NO_PROXY. A nil
// connection and a nil error means the port refused the connection or did
// not answer before timeout.
func Dial(ctx context.Context, scheme, host string, port int, timeout time.Duration) (net.Conn, error) {
	if scheme != "https" {
		scheme = "http"
	}
	return dial(ctx, net.JoinHostPort(host, strconv.Itoa(port)), scheme, timeout)
}

func dial(ctx context.Context, addr, scheme string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dialContext(pctx, addr, scheme)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if missErr(err) {
			return nil, nil
		}
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if d, ok := pctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	return conn, nil
}

func dialContext(ctx context.Context, addr, scheme string) (net.Conn, error) {
	proxyURL, err := proxyFor(ctx, scheme, addr)
	if err != nil {
		return nil, err
	}
	if proxyURL == nil {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	return connectProxy(ctx, proxyURL, addr)
}

func proxyFor(ctx context.Context, scheme, addr string) (*url.URL, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+addr, nil)
	if err != nil {
		return nil, err
	}
	return http.ProxyFromEnvironment(req)
}

func connectProxy(ctx context.Context, proxy *url.URL, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddr(proxy))
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(proxy.Scheme, "https") {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: proxy.Hostname()})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	}
	var b strings.Builder
	b.WriteString("CONNECT " + addr + " HTTP/1.1\r\n")
	b.WriteString("Host: " + addr + "\r\n")
	if proxy.User != nil {
		user := proxy.User.Username()
		pass, _ := proxy.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		b.WriteString("Proxy-Authorization: Basic " + token + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	if err := readProxyStatus(br); err != nil {
		conn.Close()
		return nil, err
	}
	return &bufConn{Conn: conn, r: br}, nil
}

func readProxyStatus(r *bufio.Reader) error {
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(line, " 200 ") {
		return fmt.Errorf("proxy CONNECT: %s", strings.TrimSpace(line))
	}
	for {
		line, err = r.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" || line == "\n" {
			return nil
		}
	}
}

func proxyAddr(u *url.URL) string {
	if u.Port() != "" {
		return net.JoinHostPort(u.Hostname(), u.Port())
	}
	if strings.EqualFold(u.Scheme, "https") {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return net.JoinHostPort(u.Hostname(), "80")
}

// bufConn replays bytes http.Read-style buffering already pulled past the
// proxy status line, so the tunnel's first bytes are not dropped.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func missErr(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}
