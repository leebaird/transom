// Package target parses a hostname, host:port, or URL into one scan origin.
package target

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Target is one scheme, host, and port. Discover is set for a bare hostname,
// which has no port until the discovery pass fills one origin per open web port.
type Target struct {
	Host     string
	Port     int
	Scheme   string
	Root     string
	Discover bool
}

// Parse accepts example.com, example.com:8443, [2001:db8::1]:8443,
// or an http(s) URL. A URL path other than / becomes Root and is joined
// onto check paths once.
func Parse(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, fmt.Errorf("empty target")
	}
	if strings.Contains(raw, "://") {
		return parseURL(raw)
	}
	return parseHost(raw)
}

func parseURL(raw string) (Target, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, fmt.Errorf("parse URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return Target{}, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return Target{}, fmt.Errorf("URL has no host")
	}
	port := 80
	if scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Target{}, fmt.Errorf("invalid port %q", p)
		}
		port = n
	}
	root := cleanRoot(u.Path)
	if err := validateRoot(root); err != nil {
		return Target{}, err
	}
	return Target{
		Host:   host,
		Port:   port,
		Scheme: scheme,
		Root:   root,
	}, nil
}

func parseHost(raw string) (Target, error) {
	host := raw
	port := 0
	discover := true

	switch {
	case strings.HasPrefix(raw, "["):
		h, p, ok, err := splitBracket(raw)
		if err != nil {
			return Target{}, err
		}
		host = h
		if ok {
			port = p
			discover = false
		}
	default:
		h, p, ok, err := splitHostPort(raw)
		if err != nil {
			return Target{}, err
		}
		host = h
		if ok {
			port = p
			discover = false
		}
	}
	if host == "" {
		return Target{}, fmt.Errorf("empty host")
	}
	if ip := net.ParseIP(host); ip == nil && strings.Contains(host, ":") {
		return Target{}, fmt.Errorf("use [ipv6]:port for %q", raw)
	}
	return Target{Host: host, Port: port, Root: "/", Discover: discover}, nil
}

func splitBracket(raw string) (host string, port int, hasPort bool, err error) {
	end := strings.IndexByte(raw, ']')
	if end < 0 {
		return "", 0, false, fmt.Errorf("missing ] in %q", raw)
	}
	host = raw[1:end]
	if net.ParseIP(host) == nil {
		return "", 0, false, fmt.Errorf("invalid IPv6 address %q", host)
	}
	rest := raw[end+1:]
	if rest == "" {
		return host, 0, false, nil
	}
	if !strings.HasPrefix(rest, ":") {
		return "", 0, false, fmt.Errorf("invalid target %q", raw)
	}
	n, err := strconv.Atoi(rest[1:])
	if err != nil || n < 1 || n > 65535 {
		return "", 0, false, fmt.Errorf("invalid port %q", rest[1:])
	}
	return host, n, true, nil
}

func splitHostPort(raw string) (host string, port int, hasPort bool, err error) {
	colon := strings.LastIndexByte(raw, ':')
	if colon < 0 {
		return raw, 0, false, nil
	}
	if strings.Count(raw, ":") > 1 {
		return "", 0, false, fmt.Errorf("use [ipv6]:port for %q", raw)
	}
	suffix := raw[colon+1:]
	n, conv := strconv.Atoi(suffix)
	if conv != nil || n < 1 || n > 65535 {
		return "", 0, false, fmt.Errorf("invalid port %q", suffix)
	}
	host = raw[:colon]
	if host == "" {
		return "", 0, false, fmt.Errorf("empty host")
	}
	return host, n, true, nil
}

func cleanRoot(path string) string {
	if path == "" || path == "/" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimSuffix(path, "/")
}

// A decoded root with a space or a line break cannot be put on a request
// line safely, even after the normal client percent-encodes it for itself.
func validateRoot(path string) error {
	if strings.ContainsAny(path, " \r\n") {
		return fmt.Errorf("invalid path")
	}
	return nil
}

// RequestURI is the encoded request target for path. The path is
// percent-encoded. A query that still contains a line break is rejected
// because RawQuery is copied through as written.
func (t Target) RequestURI(path string) (string, error) {
	rawPath, rawQuery, _ := strings.Cut(path, "?")
	if rawPath == "" {
		rawPath = "/"
	}
	u := url.URL{Path: rawPath, RawQuery: rawQuery}
	uri := u.RequestURI()
	if strings.ContainsAny(uri, " \r\n") {
		return "", fmt.Errorf("invalid request target")
	}
	return uri, nil
}

// Join appends a check path to Root once. A check path that already begins
// with Root is returned unchanged.
func (t Target) Join(checkPath string) string {
	if checkPath == "" {
		checkPath = "/"
	}
	if !strings.HasPrefix(checkPath, "/") {
		checkPath = "/" + checkPath
	}
	root := t.Root
	if root == "" || root == "/" {
		return checkPath
	}
	if checkPath == root || strings.HasPrefix(checkPath, root+"/") {
		return checkPath
	}
	return root + checkPath
}

// HostPort is host:port with IPv6 brackets.
func (t Target) HostPort() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// RequestHost is the Host header value. Default ports are omitted so the
// header matches what net/http derives from the URL.
func (t Target) RequestHost() string {
	if (t.Scheme == "https" && t.Port == 443) || (t.Scheme == "http" && t.Port == 80) || t.Port == 0 {
		if strings.Contains(t.Host, ":") {
			return "[" + t.Host + "]"
		}
		return t.Host
	}
	return t.HostPort()
}

// URL is the absolute URL for an already-joined path. A ? in path is the query string.
func (t Target) URL(path string) string {
	rawPath, rawQuery, _ := strings.Cut(path, "?")
	u := url.URL{
		Scheme:   t.Scheme,
		Host:     t.RequestHost(),
		Path:     rawPath,
		RawQuery: rawQuery,
	}
	return u.String()
}

// BaseURL is the origin plus Root, used as the finding's target field.
func (t Target) BaseURL() string {
	if t.Root == "" || t.Root == "/" {
		return t.URL("/")
	}
	return t.URL(t.Root)
}
