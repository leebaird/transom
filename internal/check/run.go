package check

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/leebaird/transom/internal/fetch"
	"github.com/leebaird/transom/internal/target"
)

// Run checks one origin. A transport error on the base URL is returned and no
// path checks are issued. A canceled context returns whatever was collected.
func Run(ctx context.Context, t target.Target, client *fetch.Client, checks []Check, concurrency int) ([]Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	banners := &bannerWatch{base: t.BaseURL()}
	client.Observe = banners.observe
	base := client.Do(ctx, http.MethodGet, t.Join("/"))
	if base.Err != nil {
		return nil, base.Err
	}
	findings := headerFindings(t, base)
	findings = append(findings, ipLinkFindings(ctx, t, base, client.Timeout())...)
	findings = append(findings, optionsFindings(ctx, client, t)...)
	findings = append(findings, junkMethodFindings(ctx, client, t, base)...)
	findings = append(findings, traceFindings(ctx, client, t)...)
	findings = append(findings, etagFindings(ctx, client, t, base)...)
	findings = append(findings, negotiationFindings(ctx, client, t)...)
	findings = append(findings, phpCreditFindings(ctx, client, t)...)
	findings = append(findings, acaoFindings(ctx, client, t, base)...)
	findings = append(findings, cloudflareTraceFindings(ctx, client, t, base)...)
	findings = append(findings, cookieFindings(t, base)...)
	if resp, ok := hostlessMethod(ctx, t, "TRACK", client.Timeout()); ok {
		banners.observe(resp)
		findings = append(findings, unseenCookies(findings, cookieFindings(t, resp))...)
	}
	findings = append(findings, aspnetFindings(ctx, client, t, base)...)
	findings = append(findings, internalIPFindings(ctx, t, client.Timeout())...)
	findings = append(findings, defaultIISFindings(ctx, t, client.Timeout())...)
	if t.Scheme == "https" {
		findings = append(findings, certFindings(t.Host, base.TLS, time.Now(), t.BaseURL(), base.URL, base.Status)...)
	}

	softResp := client.Do(ctx, http.MethodGet, t.Join(softPath()))
	soft := ""
	softOK := softResp.Err == nil && softResp.Status == http.StatusOK
	if softOK {
		soft = fingerprint(softResp.Body)
	}

	pathFindings := runPaths(ctx, t, client, checks, concurrency, soft, softOK)
	findings = append(findings, pathFindings...)
	if ctx.Err() == nil {
		findings = append(findings, robotsFindings(ctx, client, t, soft, softOK)...)
	}
	findings = append(findings, banners.finding()...)
	sort.Slice(findings, func(i, j int) bool {
		return findingLess(findings[i], findings[j])
	})
	if err := ctx.Err(); err != nil {
		return findings, err
	}
	return findings, nil
}

func findingRank(id string) int {
	switch {
	case id == "db-sql":
		return 0
	case id == "outdated-nginx":
		return 3
	case strings.HasPrefix(id, "outdated-"), strings.HasPrefix(id, "eol-"):
		return 1
	case id == "internal-ip":
		return 2
	case strings.HasPrefix(id, "header-"), strings.HasPrefix(id, "cookie-"), strings.HasPrefix(id, "tls-"), strings.HasPrefix(id, "options-"):
		return 4
	default:
		return 3
	}
}

// Lower numbers are more severe and are listed first.
var fileSeverity = map[string]int{
	"env-file":            0,
	"db-sql":              0,
	"git-head":            0,
	"svn-entries":         0,
	"ws-ftp-log":          0,
	"actuator-heapdump":   0,
	"backup-zip":          1,
	"backup-gzip":         1,
	"web-config":          1,
	"composer-installed":  1,
	"composer-lock":       1,
	"phpinfo":             2,
	"phpinfo-php":         2,
	"php-credits":         2,
	"dir-php-error":       2,
	"etag-inode":          2,
	"cloudflare-trace":    3,
	"server-status":       3,
	"actuator":            3,
	"actuator-health":     3,
	"composer-json":       3,
	"test-index":          4,
	"icons-index":         4,
	"python-samples":      4,
	"robots-disallow":     4,
	"sitemap-xml":         3,
	"admin-login":         5,
	"cpanel":              5,
	"securecontrolpanel":  5,
	"webmail":             5,
	"home-dir":            5,
	"homepage-dir":        5,
	"user-dir":            5,
	"test-txt":            5,
	"apache-icons-readme": 6,
	"iis-default":         6,
	"iisstart":            6,
	"console":             6,
	"db-dir":              6,
	"info-dir":            6,
	"public-dir":          6,
	"users-dir":           6,
	"outdated-nginx":      7,
	"trace-enabled":       8,
	"multiviews":          8,
	"banner-change":       8,
}

func cookieName(message string) string {
	const prefix = "The '"
	if !strings.HasPrefix(message, prefix) {
		return strings.ToLower(message)
	}
	name, _, ok := strings.Cut(message[len(prefix):], "'")
	if !ok {
		return strings.ToLower(message)
	}
	return strings.ToLower(name)
}

func severityOf(id string) int {
	if s, ok := fileSeverity[id]; ok {
		return s
	}
	return 4
}

// A /user/ login form is listed after exposed config files and before
// robots.txt, sitemap, and other readable directories.
func severityOfFinding(f Finding) int {
	if f.ID == "user-dir" && f.Message == "Login page" {
		return 2
	}
	return severityOf(f.ID)
}

func findingLess(a, b Finding) bool {
	ra, rb := findingRank(a.ID), findingRank(b.ID)
	if ra != rb {
		return ra < rb
	}
	if ra == 3 {
		if sa, sb := severityOfFinding(a), severityOfFinding(b); sa != sb {
			return sa < sb
		}
	}
	if strings.HasPrefix(a.ID, "cookie-") && strings.HasPrefix(b.ID, "cookie-") {
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if an, bn := cookieName(a.Message), cookieName(b.Message); an != bn {
			return an < bn
		}
	}
	if ra == 3 || (strings.HasPrefix(a.ID, "header-") && strings.HasPrefix(b.ID, "header-")) {
		if am, bm := strings.ToLower(a.Message), strings.ToLower(b.Message); am != bm {
			return am < bm
		}
	}
	if a.ID != b.ID {
		return a.ID < b.ID
	}
	return a.URL < b.URL
}

func runPaths(ctx context.Context, t target.Target, client *fetch.Client, checks []Check, concurrency int, soft string, softOK bool) []Finding {
	if len(checks) == 0 {
		return nil
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(checks) {
		concurrency = len(checks)
	}
	jobs := make(chan Check)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []Finding
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				if ctx.Err() != nil {
					continue
				}
				path := t.Join(c.Path)
				var resp fetch.Response
				if c.Raw {
					resp = client.DoIdentity(ctx, c.Method, path)
				} else {
					resp = client.Do(ctx, c.Method, path)
				}
				if !c.match(resp.Status, resp.Body, resp.Header, resp.Err != nil, soft, softOK) {
					continue
				}
				// A redirect onto the base URL is the site itself. A check that
				// asked for that URL, such as the default page at /, is kept.
				asked := t.URL(path)
				if !sameBaseURL(asked, t.BaseURL()) && sameBaseURL(resp.URL, t.BaseURL()) {
					continue
				}
				msg := c.Message
				if c.ID == "user-dir" && loginPage(resp.Body) {
					msg = "Login page"
				}
				mu.Lock()
				out = append(out, Finding{
					ID: c.ID, Target: t.BaseURL(), URL: resp.URL, Status: resp.Status, Message: msg,
				})
				mu.Unlock()
			}
		}()
	}
	for _, c := range checks {
		select {
		case <-ctx.Done():
		case jobs <- c:
		}
	}
	close(jobs)
	wg.Wait()
	return out
}
