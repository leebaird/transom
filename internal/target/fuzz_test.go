package target

import (
	"strings"
	"testing"
)

// FuzzParse checks what every accepted target promises the rest of the
// scanner: a host and root that are safe to write onto a request line.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"example.com",
		"example.com:8443",
		"[2001:db8::1]:8443",
		"[::1]",
		"192.0.2.1:80",
		"https://example.com:8443/app/",
		"http://[::1]/a?b=c",
		"https://user:pass@example.com",
		"",
		":80",
		"a:b:c",
		"[::1",
		"ftp://example.com",
		"https://example.com/a b",
		"exa mple.com",
		"example.com\r\nX-Injected: 1",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		tg, err := Parse(raw)
		if err != nil {
			return
		}
		if tg.Host == "" {
			t.Fatalf("%q: empty host", raw)
		}
		if strings.ContainsFunc(tg.Host, unsafeHostRune) {
			t.Fatalf("%q: host %q has whitespace or a control character", raw, tg.Host)
		}
		if tg.Discover {
			if tg.Port != 0 || tg.Scheme != "" {
				t.Fatalf("%q: discover target has port %d scheme %q", raw, tg.Port, tg.Scheme)
			}
		} else if tg.Port < 1 || tg.Port > 65535 {
			t.Fatalf("%q: port %d", raw, tg.Port)
		}
		if tg.Scheme != "" && tg.Scheme != "http" && tg.Scheme != "https" {
			t.Fatalf("%q: scheme %q", raw, tg.Scheme)
		}
		if !strings.HasPrefix(tg.Root, "/") || strings.ContainsAny(tg.Root, " \r\n") {
			t.Fatalf("%q: root %q", raw, tg.Root)
		}
		if strings.ContainsAny(tg.RequestHost(), " \r\n") {
			t.Fatalf("%q: Host header %q", raw, tg.RequestHost())
		}
		if uri, err := tg.RequestURI(tg.Join("/")); err == nil && strings.ContainsAny(uri, " \r\n") {
			t.Fatalf("%q: request target %q", raw, uri)
		}
	})
}
