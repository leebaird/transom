package check

import (
	"context"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/leebaird/transom/internal/fetch"
	"github.com/leebaird/transom/internal/parallel"
	"github.com/leebaird/transom/internal/target"
)

// scan is what every built-in check is given: the origin, its client, and
// the base response the others are compared against.
type scan struct {
	t       target.Target
	client  *fetch.Client
	base    fetch.Response
	banners *bannerWatch

	robotsOnce sync.Once
	robotsResp fetch.Response
}

// robots is the /robots.txt response, fetched once for every check that
// reads it.
func (s *scan) robots(ctx context.Context) fetch.Response {
	s.robotsOnce.Do(func() {
		s.robotsResp = s.client.Do(ctx, http.MethodGet, s.t.Join("/robots.txt"))
	})
	return s.robotsResp
}

// builtins are the checks compiled into the program. They run at the same
// time, before the path checks, so none may depend on another having
// finished. Their findings are collected in this order.
var builtins = []func(ctx context.Context, s *scan) []Finding{
	func(_ context.Context, s *scan) []Finding {
		return headerFindings(s.t, s.base)
	},
	func(ctx context.Context, s *scan) []Finding {
		return ipLinkFindings(ctx, s.t, s.base, s.client.Timeout())
	},
	func(ctx context.Context, s *scan) []Finding {
		return optionsFindings(ctx, s.client, s.t)
	},
	func(ctx context.Context, s *scan) []Finding {
		return junkMethodFindings(ctx, s.client, s.t, s.base)
	},
	func(ctx context.Context, s *scan) []Finding {
		return traceFindings(ctx, s.client, s.t)
	},
	func(ctx context.Context, s *scan) []Finding {
		return etagFindings(s.t, s.base, s.robots(ctx))
	},
	func(ctx context.Context, s *scan) []Finding {
		return negotiationFindings(ctx, s.client, s.t)
	},
	func(ctx context.Context, s *scan) []Finding {
		return phpCreditFindings(ctx, s.client, s.t)
	},
	func(ctx context.Context, s *scan) []Finding {
		return acaoFindings(ctx, s.client, s.t, s.base)
	},
	func(ctx context.Context, s *scan) []Finding {
		return cloudflareTraceFindings(ctx, s.client, s.t, s.base)
	},
	func(_ context.Context, s *scan) []Finding {
		return cookieFindings(s.t, s.base)
	},
	// TRACK with no Host header.
	func(ctx context.Context, s *scan) []Finding {
		resp, ok := hostlessMethod(ctx, s.t, "TRACK", s.client.Timeout())
		if !ok {
			return nil
		}
		s.banners.observe(resp)
		// Only cookies the base response did not already set.
		return unseenCookies(cookieFindings(s.t, s.base), cookieFindings(s.t, resp))
	},
	func(ctx context.Context, s *scan) []Finding {
		return aspnetFindings(ctx, s.client, s.t, s.base)
	},
	func(ctx context.Context, s *scan) []Finding {
		return internalIPFindings(ctx, s.t, s.client.Timeout())
	},
	func(ctx context.Context, s *scan) []Finding {
		return defaultIISFindings(ctx, s.t, s.client.Timeout())
	},
	func(_ context.Context, s *scan) []Finding {
		if s.t.Scheme != "https" {
			return nil
		}
		return certFindings(s.t.Host, s.base.TLS, time.Now(), s.t.BaseURL(), s.base.URL, s.base.Status)
	},
}

// Run checks one origin. A transport error on the base URL is returned and no
// path checks are issued. A canceled context returns whatever was collected.
func Run(ctx context.Context, t target.Target, client *fetch.Client, checks []Check, concurrency int) ([]Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client.Observe = nil
	base := client.Do(ctx, http.MethodGet, t.Join("/"))
	if base.Err != nil {
		return nil, base.Err
	}
	banners := newBannerWatch(t.BaseURL(), base)
	client.Observe = banners.observe
	s := &scan{t: t, client: client, base: base, banners: banners}
	found := make([][]Finding, len(builtins))
	parallel.Each(len(builtins), concurrency, func(i int) {
		found[i] = builtins[i](ctx, s)
	})
	findings := slices.Concat(found...)

	softResp := client.Do(ctx, http.MethodGet, t.Join(softPath()))
	soft := ""
	softOK := softResp.Err == nil && softResp.Status == http.StatusOK
	if softOK {
		soft = fingerprint(softResp.Body)
	}

	pathFindings := runPaths(ctx, t, client, checks, concurrency, soft, softOK)
	findings = append(findings, pathFindings...)
	if ctx.Err() == nil {
		findings = append(findings, robotsFindings(ctx, client, t, s.robots(ctx), concurrency, soft, softOK)...)
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
	// A check that does not match leaves its slot empty.
	found := make([]Finding, len(checks))
	parallel.Each(len(checks), concurrency, func(i int) {
		if ctx.Err() != nil {
			return
		}
		c := checks[i]
		path := t.Join(c.Path)
		var resp fetch.Response
		if c.Raw {
			resp = client.DoIdentity(ctx, c.Method, path)
		} else {
			resp = client.Do(ctx, c.Method, path)
		}
		if !c.match(resp.Status, resp.Body, resp.Header, resp.Err != nil, soft, softOK) {
			return
		}
		// A redirect onto the base URL is the site itself. A check that
		// asked for that URL, such as the default page at /, is kept.
		asked := t.URL(path)
		if !sameBaseURL(asked, t.BaseURL()) && sameBaseURL(resp.URL, t.BaseURL()) {
			return
		}
		msg := c.Message
		if c.ID == "user-dir" && loginPage(resp.Body) {
			msg = "Login page"
		}
		found[i] = Finding{
			ID: c.ID, Target: t.BaseURL(), URL: resp.URL, Status: resp.Status, Message: msg,
		}
	})
	return withoutEmpty(found)
}

// withoutEmpty drops the slots a concurrent pass left unfilled.
func withoutEmpty(found []Finding) []Finding {
	return slices.DeleteFunc(found, func(f Finding) bool { return f.ID == "" })
}
