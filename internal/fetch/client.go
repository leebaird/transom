package fetch

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/leebaird/transom/internal/target"
)

// Options controls one target's client. Each target gets its own jar.
type Options struct {
	Timeout     time.Duration
	Follow      string
	MaxBody     int64
	UserAgent   string
	Headers     http.Header
	Concurrency int
}

// Client talks to a single target. It is safe for concurrent use.
type Client struct {
	http    *http.Client
	target  target.Target
	timeout time.Duration
	maxBody int64
	ua      string
	headers http.Header
	// Observe, if set, runs after every Do, including transport errors.
	// Set it before the first request and do not change it during a scan.
	// The callback must be safe for concurrent use.
	Observe func(Response)
}

// New builds a client whose cookie jar is not shared with any other target.
func New(t target.Target, opts Options) (*Client, error) {
	if opts.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be positive")
	}
	if opts.MaxBody < 0 {
		return nil, fmt.Errorf("max body must be >= 0")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	c := &Client{
		target:  t,
		timeout: opts.Timeout,
		maxBody: opts.MaxBody,
		ua:      opts.UserAgent,
		headers: opts.Headers,
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// Certificate problems are reported as findings. A failed verify must not
	// abort the scan of a port discovery already accepted. MinVersion matches
	// discovery, which still completes a TLS 1.0 handshake.
	tr.TLSClientConfig = &tls.Config{
		ServerName:         serverName(t.Host),
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}
	c.http = &http.Client{
		Transport: tr,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// via counts requests already made. Allow the original plus five redirects.
			if len(via) >= 6 {
				return http.ErrUseLastResponse
			}
			if opts.Follow == "off" {
				return http.ErrUseLastResponse
			}
			if !sameTarget(t, req.URL) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return c, nil
}

// Timeout is the per-request deadline. Raw probes use it too.
func (c *Client) Timeout() time.Duration { return c.timeout }

func serverName(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

func sameTarget(t target.Target, u *url.URL) bool {
	// Scheme is part of the target. An https-to-http hop on the same port
	// would drop the certificate and can forward Authorization.
	if u == nil || !strings.EqualFold(u.Scheme, t.Scheme) {
		return false
	}
	if !strings.EqualFold(u.Hostname(), t.Host) {
		return false
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return port == strconv.Itoa(t.Port)
}
