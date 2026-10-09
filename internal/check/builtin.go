package check

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/leebaird/transom/internal/discover"
	"github.com/leebaird/transom/internal/fetch"
	"github.com/leebaird/transom/internal/parallel"
	"github.com/leebaird/transom/internal/target"
)

const robotsCap = 20

func softPath() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "/transom-" + hex.EncodeToString(b[:])
}

func headerFindings(t target.Target, resp fetch.Response) []Finding {
	if resp.Err != nil {
		return nil
	}
	base := t.BaseURL()
	need := []struct {
		id, name, message string
		httpsOnly         bool
	}{
		{"header-xcto", "X-Content-Type-Options", "X-Content-Type-Options is missing", false},
		{"header-csp", "Content-Security-Policy", "Content-Security-Policy is missing", false},
		{"header-referrer", "Referrer-Policy", "Referrer-Policy is missing", false},
		{"header-permissions", "Permissions-Policy", "Permissions-Policy is missing", false},
		{"header-hsts", "Strict-Transport-Security", "Strict-Transport-Security is missing", false},
	}
	var out []Finding
	for _, h := range need {
		if h.httpsOnly && t.Scheme != "https" {
			continue
		}
		if resp.Header.Get(h.name) == "" {
			out = append(out, Finding{ID: h.id, Target: base, URL: resp.URL, Status: resp.Status, Message: h.message})
		}
	}
	out = append(out, bannerFindings(base, resp)...)
	out = append(out, viaFindings(base, resp)...)
	out = append(out, linkFindings(base, resp)...)
	out = append(out, uncommonHeaderFindings(base, resp)...)
	return out
}

func viaFindings(base string, resp fetch.Response) []Finding {
	if resp.Err != nil {
		return nil
	}
	via := strings.TrimSpace(strings.Join(resp.Header.Values("Via"), ", "))
	if via == "" {
		return nil
	}
	return []Finding{{
		ID: "header-via", Target: base, URL: resp.URL, Status: resp.Status,
		Message: "Via header: " + via,
	}}
}

func linkFindings(base string, resp fetch.Response) []Finding {
	if resp.Err != nil {
		return nil
	}
	link := strings.TrimSpace(strings.Join(resp.Header.Values("Link"), ", "))
	if link == "" {
		return nil
	}
	return []Finding{{
		ID: "header-link", Target: base, URL: resp.URL, Status: resp.Status,
		Message: "Link header: " + link,
	}}
}

// commonHeaders are standard response fields, or headers that already have their own finding.
var commonHeaders = map[string]bool{
	"accept-ranges": true, "access-control-allow-credentials": true, "access-control-allow-headers": true,
	"access-control-allow-methods": true, "access-control-allow-origin": true, "access-control-expose-headers": true,
	"access-control-max-age": true, "age": true, "allow": true, "alt-svc": true, "alternates": true, "cache-control": true,
	"connection": true, "content-disposition": true, "content-encoding": true, "content-language": true,
	"content-length": true, "content-location": true, "content-range": true, "content-security-policy": true,
	"content-type": true, "cross-origin-embedder-policy": true, "cross-origin-opener-policy": true,
	"cross-origin-resource-policy": true, "date": true, "etag": true, "expires": true, "keep-alive": true, "last-modified": true,
	"link": true, "location": true, "nel": true, "permissions-policy": true, "pragma": true, "referrer-policy": true,
	"report-to": true,
	"server":    true, "set-cookie": true, "strict-transport-security": true, "tcn": true, "transfer-encoding": true,
	"vary": true, "via": true, "www-authenticate": true, "x-aspnet-version": true, "x-aspnetmvc-version": true,
	"x-content-type-options": true, "x-frame-options": true, "x-powered-by": true,
}

func uncommonHeaderFindings(base string, resp fetch.Response) []Finding {
	if resp.Err != nil {
		return nil
	}
	var out []Finding
	for name := range resp.Header {
		if commonHeaders[strings.ToLower(name)] {
			continue
		}
		out = append(out, Finding{
			ID: "header-uncommon", Target: base, URL: resp.URL, Status: resp.Status,
			Message: "Uncommon header " + strings.ToLower(name) + ": " + strings.Join(resp.Header.Values(name), ", "),
		})
	}
	return out
}

// Current releases as of September 2026. A parsed banner older than these is reported.
var currentRelease = map[string][3]int{
	"apache": {2, 4, 68},
	"php":    {8, 5, 11},
	"iis":    {10, 0, 0},
	"nginx":  {1, 31, 6},
}

var productVersion = regexp.MustCompile(`(?i)(Apache|PHP)/(\d+)\.(\d+)\.(\d+)`)
var iisVersion = regexp.MustCompile(`(?i)Microsoft-IIS/(\d+)\.(\d+)`)
var nginxVersion = regexp.MustCompile(`(?i)nginx/(\d+)\.(\d+)\.(\d+)`)
var privateIP = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`)
var iisDefaultPage = regexp.MustCompile(`(?i)IIS\s+Windows\s+Server`)

func bannerFindings(base string, resp fetch.Response) []Finding {
	var out []Finding
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		out = append(out, Finding{
			ID: "header-powered-by", Target: base, URL: resp.URL, Status: resp.Status,
			Message: "X-Powered-By discloses " + powered,
		})
	}
	if server := strings.TrimSpace(resp.Header.Get("Server")); strings.Contains(strings.ToLower(server), "cloudflare") {
		out = append(out, Finding{
			ID: "header-cloudflare", Target: base, URL: resp.URL, Status: resp.Status,
			Message: "Server banner is Cloudflare",
		})
	}
	if finding, ok := xfoFinding(base, resp); ok {
		out = append(out, finding)
	}
	if nginx := nginxVersion.FindStringSubmatch(resp.Header.Get("Server")); nginx != nil {
		got := [3]int{atoi(nginx[1]), atoi(nginx[2]), atoi(nginx[3])}
		if versionLess(got, currentRelease["nginx"]) {
			out = append(out, Finding{
				ID: "outdated-nginx", Target: base, URL: resp.URL, Status: resp.Status,
				Message: "nginx/" + nginx[1] + "." + nginx[2] + "." + nginx[3] + " is older than the current release 1.31.6",
			})
		}
	}
	if iis := iisVersion.FindStringSubmatch(resp.Header.Get("Server")); iis != nil {
		got := [3]int{atoi(iis[1]), atoi(iis[2]), 0}
		if versionLess(got, currentRelease["iis"]) {
			out = append(out, Finding{
				ID: "outdated-iis", Target: base, URL: resp.URL, Status: resp.Status,
				Message: "Microsoft-IIS/" + iis[1] + "." + iis[2] + " is older than the current release 10.0",
			})
		}
	}
	seen := map[string]bool{}
	for _, header := range []string{resp.Header.Get("Server"), resp.Header.Get("X-Powered-By")} {
		for _, match := range productVersion.FindAllStringSubmatch(header, -1) {
			name := strings.ToLower(match[1])
			if seen[name] {
				continue
			}
			floor, ok := currentRelease[name]
			if !ok {
				continue
			}
			got := [3]int{atoi(match[2]), atoi(match[3]), atoi(match[4])}
			if versionLess(got, floor) {
				seen[name] = true
				out = append(out, Finding{
					ID: "outdated-" + name, Target: base, URL: resp.URL, Status: resp.Status,
					Message: match[1] + "/" + match[2] + "." + match[3] + "." + match[4] +
						" is older than the current release " +
						itoa(floor[0]) + "." + itoa(floor[1]) + "." + itoa(floor[2]),
				})
			}
		}
	}
	return out
}

func versionLess(got, floor [3]int) bool {
	for i := range 3 {
		if got[i] != floor[i] {
			return got[i] < floor[i]
		}
	}
	return false
}

// atoi reads a run of ASCII digits. A number too large for an int stops at
// the largest one, so an absurd version in a banner still compares as newer
// than any release instead of wrapping around to an old one.
func atoi(s string) int {
	n := 0
	for _, c := range s {
		if n > (math.MaxInt-9)/10 {
			return math.MaxInt
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func optionsFindings(ctx context.Context, c *fetch.Client, t target.Target) []Finding {
	resp := c.Do(ctx, http.MethodOptions, t.Join("/"))
	if resp.Err != nil {
		return nil
	}
	allow := methodsFrom(resp.Header.Values("Allow"))
	if allow == "" {
		return nil
	}
	return []Finding{{
		ID: "options-allow", Target: t.BaseURL(), URL: resp.URL, Status: resp.Status,
		Message: "Allowed HTTP Methods: " + allow,
	}}
}

var inodeETagField = regexp.MustCompile(`(?i)^[0-9a-f]+(?:\.[0-9a-f]+)?$`)

func inodeETag(header http.Header) bool {
	etag := strings.TrimSpace(header.Get("ETag"))
	etag = strings.TrimPrefix(strings.TrimPrefix(etag, "W/"), "w/")
	etag = strings.Trim(etag, `"`)
	parts := strings.Split(etag, "-")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if !inodeETagField.MatchString(part) {
			return false
		}
	}
	return true
}

// etagFindings looks for an inode-shaped ETag on the base response, then on
// /robots.txt.
func etagFindings(t target.Target, base, robots fetch.Response) []Finding {
	for _, resp := range []fetch.Response{base, robots} {
		if finding, ok := inodeETagFinding(t, resp); ok {
			return []Finding{finding}
		}
	}
	return nil
}

func inodeETagFinding(t target.Target, resp fetch.Response) (Finding, bool) {
	if resp.Err != nil || resp.Status != http.StatusOK || !inodeETag(resp.Header) {
		return Finding{}, false
	}
	if strings.HasSuffix(strings.ToLower(resp.URL), "favicon.ico") {
		return Finding{}, false
	}
	return Finding{
		ID: "etag-inode", Target: t.BaseURL(), URL: resp.URL, Status: resp.Status,
		Message: "ETag leaks an inode",
	}, true
}

func traceFindings(ctx context.Context, c *fetch.Client, t target.Target) []Finding {
	resp := c.Do(ctx, http.MethodTrace, t.Join("/"))
	if resp.Err != nil || resp.Status != http.StatusOK {
		return nil
	}
	kind := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(kind), "message/http") && !strings.HasPrefix(resp.Body, "TRACE ") {
		return nil
	}
	return []Finding{{
		ID: "trace-enabled", Target: t.BaseURL(), URL: resp.URL, Status: resp.Status,
		Message: "TRACE is enabled",
	}}
}

func negotiationFindings(ctx context.Context, c *fetch.Client, t target.Target) []Finding {
	page := c.Do(ctx, http.MethodGet, t.Join("/index"))
	if page.Err != nil {
		return nil
	}
	var out []Finding
	tcn := strings.ToLower(strings.TrimSpace(page.Header.Get("TCN")))
	if tcn == "choice" || tcn == "list" {
		msg := "mod_negotiation MultiViews is enabled"
		if loc := page.Header.Get("Content-Location"); loc != "" {
			msg += " and offers " + loc
		}
		out = append(out, Finding{
			ID: "multiviews", Target: t.BaseURL(), URL: page.URL, Status: page.Status, Message: msg,
		})
	}
	return out
}

// httpAPIBanner is what IIS sends when a request misses the site binding, so
// it is not a change of server.
const httpAPIBanner = "Microsoft-HTTPAPI/2.0"

// bannerWatch reports a Server value that differs from the base response's.
// Responses arrive in any order during a scan, so the choice is made at the
// end from everything seen: the differing value on the lowest URL. When the
// base response sent no Server header, the value on the lowest URL stands in
// for it.
type bannerWatch struct {
	mu   sync.Mutex
	base string
	// first is the base response's Server value, or empty.
	first string
	// seen holds, for each other Server value, the response with the lowest
	// URL that carried it.
	seen map[string]Finding
}

func newBannerWatch(base string, resp fetch.Response) *bannerWatch {
	return &bannerWatch{
		base:  base,
		first: strings.TrimSpace(resp.Header.Get("Server")),
		seen:  map[string]Finding{},
	}
}

func (b *bannerWatch) observe(resp fetch.Response) {
	if resp.Err != nil {
		return
	}
	server := strings.TrimSpace(resp.Header.Get("Server"))
	if server == "" || server == httpAPIBanner {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if server == b.first {
		return
	}
	at := Finding{URL: resp.URL, Status: resp.Status}
	if have, ok := b.seen[server]; !ok || bannerBefore(at, have) {
		b.seen[server] = at
	}
}

func bannerBefore(a, b Finding) bool {
	if a.URL != b.URL {
		return a.URL < b.URL
	}
	return a.Status < b.Status
}

func (b *bannerWatch) finding() []Finding {
	b.mu.Lock()
	defer b.mu.Unlock()
	servers := slices.SortedFunc(maps.Keys(b.seen), func(x, y string) int {
		switch {
		case bannerBefore(b.seen[x], b.seen[y]):
			return -1
		case bannerBefore(b.seen[y], b.seen[x]):
			return 1
		}
		return strings.Compare(x, y)
	})
	from := b.first
	if from == "" && len(servers) > 0 {
		from, servers = servers[0], servers[1:]
	}
	if len(servers) == 0 {
		return nil
	}
	to := servers[0]
	return []Finding{{
		ID: "banner-change", Target: b.base, URL: b.seen[to].URL, Status: b.seen[to].Status,
		Message: "Server banner changed from '" + from + "' to '" + to + "'",
	}}
}

var phpCreditIDs = []string{
	"PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000",
}

func phpCreditFindings(ctx context.Context, c *fetch.Client, t target.Target) []Finding {
	var out []Finding
	for _, id := range phpCreditIDs {
		if ctx.Err() != nil {
			return out
		}
		resp := c.Do(ctx, http.MethodGet, t.Join("/?="+id))
		if resp.Err != nil || resp.Status != http.StatusOK || !strings.Contains(resp.Body, "PHP Credits") {
			continue
		}
		out = append(out, Finding{
			ID: "php-credits", Target: t.BaseURL(), URL: resp.URL, Status: resp.Status,
			Message: "PHP Credits page is publicly readable",
		})
	}
	return out
}

func junkMethodFindings(ctx context.Context, c *fetch.Client, t target.Target, base fetch.Response) []Finding {
	junk := c.Do(ctx, "QWERTZUI", t.Join("/"))
	var out []Finding
	if junk.Err == nil && junk.Status == http.StatusOK && !samePage(base, junk) {
		out = append(out, Finding{
			ID: "options-junk", Target: t.BaseURL(), URL: junk.URL, Status: junk.Status,
			Message: "The server accepts a junk HTTP method",
		})
	}
	debug := c.Do(ctx, "DEBUG", t.Join("/"))
	if debug.Err != nil || debug.Status != http.StatusOK {
		return out
	}
	// A DEBUG response that is the same page as the junk method is not a second finding.
	if junk.Err == nil && junk.Status == http.StatusOK && fingerprint(debug.Body) == fingerprint(junk.Body) {
		return out
	}
	out = append(out, Finding{
		ID: "options-debug", Target: t.BaseURL(), URL: debug.URL, Status: debug.Status,
		Message: "DEBUG HTTP method may show server debugging information",
	})
	return out
}

func samePage(a, b fetch.Response) bool {
	if a.Err != nil || b.Err != nil {
		return false
	}
	return fingerprint(a.Body) == fingerprint(b.Body)
}

// ipLinkFindings reports a Link header from an address-based virtual host
// when the hostname response did not send one.
func ipLinkFindings(ctx context.Context, t target.Target, baseResp fetch.Response, timeout time.Duration) []Finding {
	if len(linkFindings(t.BaseURL(), baseResp)) > 0 || net.ParseIP(t.Host) != nil {
		return nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip4", t.Host)
	if err != nil {
		return nil
	}
	if len(ips) > 4 {
		ips = ips[:4]
	}
	for _, ip := range ips {
		resp, ok := fetchWithHost(ctx, t, ip.String(), timeout)
		if !ok {
			continue
		}
		if found := linkFindings(t.BaseURL(), resp); len(found) > 0 {
			return found
		}
	}
	return nil
}

// fetchWithHost dials the original host and sets Host to address, so a
// name-based site and its address-based virtual host can be compared.
func fetchWithHost(ctx context.Context, t target.Target, host string, timeout time.Duration) (fetch.Response, bool) {
	path := t.Join("/")
	asked := t
	asked.Host = host
	resp, err := rawExchange(ctx, t, rawRequest{method: http.MethodGet, path: path, host: asked.RequestHost()}, timeout)
	if err != nil {
		return fetch.Response{}, false
	}
	return fetch.Response{Status: resp.status, Header: resp.header, URL: asked.URL(path)}, true
}

func acaoFindings(ctx context.Context, c *fetch.Client, t target.Target, baseResp fetch.Response) []Finding {
	base := t.BaseURL()
	if finding, ok := wildcardACAO(base, baseResp); ok {
		return []Finding{finding}
	}
	page := c.Do(ctx, http.MethodGet, t.Join("/contact.php"))
	if finding, ok := wildcardACAO(base, page); ok {
		return []Finding{finding}
	}
	return nil
}

// cloudflareTraceFindings reports Cloudflare's /cdn-cgi/trace page. The trace
// response can also carry wildcard CORS or X-Frame-Options that the base
// response did not.
func cloudflareTraceFindings(ctx context.Context, c *fetch.Client, t target.Target, baseResp fetch.Response) []Finding {
	resp := c.Do(ctx, http.MethodGet, t.Join("/cdn-cgi/trace"))
	if resp.Err != nil {
		return nil
	}
	base := t.BaseURL()
	var out []Finding
	if cloudflareTrace(resp.Body) {
		out = append(out, Finding{
			ID: "cloudflare-trace", Target: base, URL: resp.URL, Status: resp.Status,
			Message: "Cloudflare trace output",
		})
	}
	if _, ok := wildcardACAO(base, baseResp); !ok {
		if finding, ok := wildcardACAO(base, resp); ok {
			out = append(out, finding)
		}
	}
	if strings.TrimSpace(baseResp.Header.Get("X-Frame-Options")) == "" {
		if finding, ok := xfoFinding(base, resp); ok {
			out = append(out, finding)
		}
	}
	return out
}

func cloudflareTrace(body string) bool {
	need := []string{"h=", "ip=", "colo=", "visit_scheme="}
	got := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		for _, key := range need {
			if strings.HasPrefix(line, key) {
				got[key] = true
			}
		}
	}
	for _, key := range need {
		if !got[key] {
			return false
		}
	}
	return true
}

func xfoFinding(base string, resp fetch.Response) (Finding, bool) {
	if resp.Err != nil || strings.TrimSpace(resp.Header.Get("X-Frame-Options")) == "" {
		return Finding{}, false
	}
	return Finding{
		ID: "header-xfo", Target: base, URL: resp.URL, Status: resp.Status,
		Message: "X-Frame-Options is set; Content-Security-Policy frame-ancestors replaced it",
	}, true
}

func wildcardACAO(base string, resp fetch.Response) (Finding, bool) {
	if resp.Err != nil || strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin")) != "*" {
		return Finding{}, false
	}
	return Finding{
		ID: "header-acao", Target: base, URL: resp.URL, Status: resp.Status,
		Message: "Access-Control-Allow-Origin is *",
	}, true
}

func methodsFrom(values []string) string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		for part := range strings.SplitSeq(v, ",") {
			method := strings.TrimSpace(part)
			if method == "" {
				continue
			}
			key := strings.ToUpper(method)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, method)
		}
	}
	return strings.Join(out, ", ")
}

func aspnetFindings(ctx context.Context, c *fetch.Client, t target.Target, baseResp fetch.Response) []Finding {
	base := t.BaseURL()
	if finding, ok := aspnetVersion(base, baseResp); ok {
		return []Finding{finding}
	}
	page := c.Do(ctx, http.MethodGet, t.Join("/index.aspx"))
	if finding, ok := aspnetVersion(base, page); ok {
		return []Finding{finding}
	}
	return nil
}

func aspnetVersion(base string, resp fetch.Response) (Finding, bool) {
	if resp.Err != nil {
		return Finding{}, false
	}
	for _, name := range []string{"X-AspNet-Version", "X-AspNetMvc-Version"} {
		if value := resp.Header.Get(name); value != "" {
			return Finding{
				ID: "header-aspnet-version", Target: base, URL: resp.URL, Status: resp.Status,
				Message: name + " discloses " + value,
			}, true
		}
	}
	return Finding{}, false
}

func defaultIISFindings(ctx context.Context, t target.Target, timeout time.Duration) []Finding {
	if t.Scheme != "http" {
		return nil
	}
	status, _, body, err := http10NoHost(ctx, t, t.Join("/"), timeout)
	if err != nil || status != http.StatusOK || !iisDefaultPage.MatchString(body) {
		return nil
	}
	return []Finding{{
		ID: "iis-default", Target: t.BaseURL(), URL: t.BaseURL(), Status: status,
		Message: "the server returns the default IIS page",
	}}
}

func internalIPFindings(ctx context.Context, t target.Target, timeout time.Duration) []Finding {
	if t.Scheme != "http" {
		return nil
	}
	path := t.Join("/aspnet_client")
	status, header, _, err := http10NoHost(ctx, t, path, timeout)
	if err != nil || status < 300 || status > 399 || header == nil {
		return nil
	}
	ips := privateIP.FindAllString(header.Get("Location"), -1)
	if len(ips) == 0 {
		return nil
	}
	return []Finding{{
		ID: "internal-ip", Target: t.BaseURL(), URL: t.URL(path), Status: status,
		Message: "Location discloses internal address " + ips[0],
	}}
}

// hostlessMethod sends an HTTP/1.0 request with no Host header. A front
// door that requires Host can hand that request to a different origin,
// which may set a session cookie and use its own Server banner.
func hostlessMethod(ctx context.Context, t target.Target, method string, timeout time.Duration) (fetch.Response, bool) {
	resp, err := rawExchange(ctx, t, rawRequest{method: method, path: t.Join("/")}, timeout)
	if err != nil {
		return fetch.Response{}, false
	}
	return fetch.Response{Status: resp.status, Header: resp.header, URL: t.BaseURL()}, true
}

func unseenCookies(have, extra []Finding) []Finding {
	seen := map[string]bool{}
	for _, f := range have {
		if strings.HasPrefix(f.ID, "cookie-") {
			seen[f.ID+"\x00"+f.Message] = true
		}
	}
	var out []Finding
	for _, f := range extra {
		key := f.ID + "\x00" + f.Message
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func http10NoHost(ctx context.Context, t target.Target, path string, timeout time.Duration) (status int, header http.Header, body string, err error) {
	resp, err := rawExchange(ctx, t, rawRequest{method: http.MethodGet, path: path}, timeout)
	if err != nil {
		return 0, nil, "", err
	}
	if resp.bodyErr != nil && resp.body == "" {
		return 0, nil, "", resp.bodyErr
	}
	return resp.status, resp.header, resp.body, nil
}

// rawBodyCap is how much of a raw probe's body is read.
const rawBodyCap = 4096

// rawRequest is one request written straight to the socket, for the probes
// net/http will not send as asked: no Host header at all, or a Host that
// differs from the name that was dialed.
type rawRequest struct {
	method string
	// path is already joined to the target root.
	path string
	// host is the Host header of an HTTP/1.1 request. Empty sends HTTP/1.0
	// with no Host header.
	host string
}

type rawResponse struct {
	status int
	header http.Header
	// body is at most rawBodyCap bytes. bodyErr is the read error, if any;
	// the status and header are still what the server sent.
	body    string
	bodyErr error
}

// rawExchange dials t, completes TLS for an https target, sends req, and
// reads one response.
func rawExchange(ctx context.Context, t target.Target, req rawRequest, timeout time.Duration) (rawResponse, error) {
	uri, err := t.RequestURI(req.path)
	if err != nil {
		return rawResponse{}, err
	}
	conn, err := discover.Dial(ctx, t.Scheme, t.Host, t.Port, timeout)
	if err != nil {
		return rawResponse{}, err
	}
	if conn == nil {
		return rawResponse{}, fmt.Errorf("no connection")
	}
	defer conn.Close()
	defer discover.OnCancel(ctx, conn)()
	if t.Scheme == "https" {
		tlsConn := tls.Client(conn, discover.TLSConfig(t.Host))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return rawResponse{}, err
		}
		conn = tlsConn
	}
	head := req.method + " " + uri + " HTTP/1.0\r\n\r\n"
	if req.host != "" {
		head = req.method + " " + uri + " HTTP/1.1\r\nHost: " + req.host + "\r\nConnection: close\r\n\r\n"
	}
	if _, err := io.WriteString(conn, head); err != nil {
		return rawResponse{}, err
	}
	parsed, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return rawResponse{}, err
	}
	defer parsed.Body.Close()
	buf, readErr := io.ReadAll(io.LimitReader(parsed.Body, rawBodyCap))
	return rawResponse{
		status:  parsed.StatusCode,
		header:  parsed.Header.Clone(),
		body:    string(buf),
		bodyErr: readErr,
	}, nil
}

func cookieFindings(t target.Target, resp fetch.Response) []Finding {
	if resp.Err != nil {
		return nil
	}
	base := t.BaseURL()
	parsed := (&http.Response{Header: resp.Header}).Cookies()
	var out []Finding
	for _, cookie := range parsed {
		if cookie.Name == "" {
			continue
		}
		if t.Scheme == "https" && !cookie.Secure {
			out = append(out, Finding{
				ID: "cookie-secure", Target: base, URL: resp.URL, Status: resp.Status,
				Message: "The '" + cookie.Name + "' cookie is missing a Secure flag",
			})
		}
		if !cookie.HttpOnly {
			out = append(out, Finding{
				ID: "cookie-httponly", Target: base, URL: resp.URL, Status: resp.Status,
				Message: "The '" + cookie.Name + "' cookie is missing an HttpOnly flag",
			})
		}
	}
	return out
}

// certFindings reports hostname and lifetime problems on the leaf certificate.
// An untrusted issuer alone is not a finding.
func certFindings(host string, state *tls.ConnectionState, now time.Time, base, page string, status int) []Finding {
	if state == nil {
		return nil
	}
	var out []Finding
	if state.Version > 0 && state.Version < tls.VersionTLS12 {
		out = append(out, Finding{
			ID: "tls-version", Target: base, URL: page, Status: status,
			Message: "negotiated " + tlsVersionName(state.Version),
		})
	}
	if len(state.PeerCertificates) == 0 {
		return out
	}
	leaf := state.PeerCertificates[0]
	if now.Before(leaf.NotBefore) {
		out = append(out, Finding{ID: "tls-not-yet-valid", Target: base, URL: page, Status: status, Message: "certificate is not valid yet"})
	}
	if now.After(leaf.NotAfter) {
		out = append(out, Finding{ID: "tls-expired", Target: base, URL: page, Status: status, Message: "The certificate is expired"})
	} else if !now.Before(leaf.NotBefore) && now.Add(30*24*time.Hour).After(leaf.NotAfter) {
		out = append(out, Finding{ID: "tls-expiring", Target: base, URL: page, Status: status, Message: "certificate expires within 30 days"})
	}
	if err := leaf.VerifyHostname(host); err != nil {
		out = append(out, Finding{ID: "tls-hostname", Target: base, URL: page, Status: status, Message: "The certificate hostname does not match"})
	}
	if name := wildcardDNS(leaf); name != "" {
		out = append(out, Finding{ID: "tls-wildcard", Target: base, URL: page, Status: status, Message: "The certificate is a wildcard: " + name})
	}
	return out
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", v)
	}
}

func wildcardDNS(leaf *x509.Certificate) string {
	if strings.HasPrefix(leaf.Subject.CommonName, "*.") {
		return leaf.Subject.CommonName
	}
	for _, name := range leaf.DNSNames {
		if strings.HasPrefix(name, "*.") {
			return name
		}
	}
	return ""
}

// robotsFindings fetches the Disallow paths in resp, the /robots.txt response.
func robotsFindings(ctx context.Context, c *fetch.Client, t target.Target, resp fetch.Response, concurrency int, soft string, softOK bool) []Finding {
	if resp.Err != nil || resp.Status != http.StatusOK {
		return nil
	}
	paths := disallowPaths(resp.Body)
	if len(paths) > robotsCap {
		paths = paths[:robotsCap]
	}
	base := t.BaseURL()
	var out []Finding
	if len(paths) > 0 {
		out = append(out, Finding{
			ID: "robots-disallow", Target: base, URL: resp.URL, Status: resp.Status,
			Message: "A robots.txt page is readable",
		})
	}
	// Fetched together, reported in robots.txt order. A path that is not
	// readable leaves its slot empty.
	pages := make([]Finding, len(paths))
	parallel.Each(len(paths), concurrency, func(i int) {
		if ctx.Err() != nil {
			return
		}
		page := c.Do(ctx, http.MethodGet, t.Join(paths[i]))
		if page.Err != nil || page.Status != http.StatusOK {
			return
		}
		if softOK && fingerprint(page.Body) == soft {
			return
		}
		pages[i] = Finding{
			ID: "robots-disallow", Target: base, URL: page.URL, Status: page.Status,
			Message: "A robots.txt page is readable",
		}
	})
	return append(out, withoutEmpty(pages)...)
}

func disallowPaths(body string) []string {
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		lower := strings.ToLower(line)
		const key = "disallow:"
		if !strings.HasPrefix(lower, key) {
			continue
		}
		path := strings.TrimSpace(line[len(key):])
		if path == "" || strings.Contains(path, "://") {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		// "/" is the site itself, so it is not a hidden path worth a second fetch.
		if path == "/" || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}
