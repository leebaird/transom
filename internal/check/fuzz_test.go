package check

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/leebaird/transom/internal/fetch"
)

// FuzzParseFile checks that an accepted check file holds only checks that
// can run: each has an id, a path, a method, and a message.
func FuzzParseFile(f *testing.F) {
	for _, seed := range []string{
		`[{"id":"env-file","path":"/.env","method":"GET","statuses":[200],"body":"(?m)^[A-Z_]+=","message":"m"}]`,
		`[{"id":"gz","path":"/a.gz","body":"^\\x1f\\x8b","message":"m","raw":true}]`,
		`[{"id":"h","path":"/","headers":{"Server":"(?i)apache"},"message":"m","ignoreSoft404":true}]`,
		`[{"id":"x","path":"/x","message":"m","nope":true}]`,
		`[{"id":"x","path":"/x","message":"m","body":"("}]`,
		`[] []`,
		`[]`,
		`{}`,
		``,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		checks, err := parseFile("fuzz.json", data)
		if err != nil {
			return
		}
		for _, c := range checks {
			if c.ID == "" || c.Path == "" || c.Method == "" || c.Message == "" {
				t.Fatalf("accepted an incomplete check: %+v", c)
			}
			// A compiled check must be able to judge any response.
			c.match(http.StatusOK, "body", http.Header{"Server": {"x"}}, false, "", false)
		}
	})
}

// FuzzOutdatedBanner checks the version comparison behind the outdated-*
// findings: a banner is reported exactly when its version is below the
// current release, however large the numbers a server sends.
func FuzzOutdatedBanner(f *testing.F) {
	f.Add(uint64(1), uint64(18), uint64(0))
	f.Add(uint64(1), uint64(31), uint64(6))
	f.Add(uint64(1), uint64(31), uint64(5))
	f.Add(uint64(2), uint64(0), uint64(0))
	f.Add(uint64(0), uint64(0), uint64(0))
	f.Add(uint64(1<<63), uint64(0), uint64(0))
	f.Add(uint64(1<<64-1), uint64(1<<64-1), uint64(1<<64-1))
	f.Fuzz(func(t *testing.T, major, minor, patch uint64) {
		floor := currentRelease["nginx"]
		got := [3]uint64{major, minor, patch}
		want := false
		for i := range got {
			if got[i] != uint64(floor[i]) {
				want = got[i] < uint64(floor[i])
				break
			}
		}
		resp := fetch.Response{Header: http.Header{
			"Server": {fmt.Sprintf("nginx/%d.%d.%d", major, minor, patch)},
		}}
		outdated := false
		for _, finding := range bannerFindings("http://example.com/", resp) {
			if finding.ID == "outdated-nginx" {
				outdated = true
			}
		}
		if outdated != want {
			t.Fatalf("nginx/%d.%d.%d: outdated %v, want %v", major, minor, patch, outdated, want)
		}
	})
}

// FuzzBannerHeaders feeds arbitrary Server and X-Powered-By values through
// every header check. The headers come from the scanned server.
func FuzzBannerHeaders(f *testing.F) {
	f.Add("Apache/2.4.29 (Ubuntu)", "PHP/7.4.3")
	f.Add("Microsoft-IIS/8.5", "ASP.NET")
	f.Add("nginx/1.18.0", "")
	f.Add("cloudflare", "")
	f.Add("Apache/2.4.29 PHP/5.6.40 Apache/99999999999999999999.1.1", "PHP/8..1")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, server, powered string) {
		resp := fetch.Response{Status: http.StatusOK, URL: "http://example.com/", Header: http.Header{
			"Server":       {server},
			"X-Powered-By": {powered},
		}}
		for _, finding := range headerFindings(mustTarget(t, "http://example.com"), resp) {
			if finding.ID == "" || finding.Message == "" {
				t.Fatalf("incomplete finding %+v", finding)
			}
		}
	})
}

// FuzzDisallowPaths checks the paths taken from a robots.txt body before
// they are fetched: each is rooted, none is the site root or an absolute
// URL, and none repeats.
func FuzzDisallowPaths(f *testing.F) {
	for _, seed := range []string{
		"User-agent: *\nDisallow: /admin\nDisallow: /private/ # staff\n",
		"disallow:secret\nDISALLOW: /\nDisallow:\n",
		"Disallow: https://other.example/x\nDisallow: /a\nDisallow: /a\n",
		"Disallow: /a\rb\r\nDisallow: //evil.example/\n",
		"Disallow: 0\nDisallow: /0\n",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		seen := map[string]bool{}
		for _, p := range disallowPaths(body) {
			if !strings.HasPrefix(p, "/") || p == "/" {
				t.Fatalf("path %q", p)
			}
			if strings.Contains(p, "://") {
				t.Fatalf("absolute URL %q", p)
			}
			if seen[p] {
				t.Fatalf("path %q listed twice", p)
			}
			seen[p] = true
		}
	})
}
