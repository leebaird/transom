package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/leebaird/transom/internal/fetch"
	"github.com/leebaird/transom/internal/target"
)

func TestStarterCorpus(t *testing.T) {
	checks, err := LoadDir("../../checks")
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 38 {
		t.Fatalf("got %d checks", len(checks))
	}
	var web Check
	for _, c := range checks {
		if c.ID == "web-config" {
			web = c
		}
	}
	if web.ID == "" {
		t.Fatal("missing web-config")
	}
	if !web.match(200, "<?xml version=\"1.0\"?><configuration>", nil, false, "", false) {
		t.Fatal("web.config body did not match")
	}
	if web.match(404, "<configuration>", nil, false, "", false) || web.match(200, "<html>", nil, false, "", false) {
		t.Fatal("web.config matched a non-config response")
	}
	var gzip, zip Check
	for _, c := range checks {
		switch c.ID {
		case "backup-gzip":
			gzip = c
		case "backup-zip":
			zip = c
		}
	}
	if !gzip.Raw || !gzip.match(200, string([]byte{0x1f, 0x8b, 0x08}), nil, false, "", false) {
		t.Fatal("backup-gzip did not match gzip magic")
	}
	if gzip.match(200, string([]byte{0x1f, 0xc2, 0x8b}), nil, false, "", false) {
		t.Fatal("backup-gzip matched the UTF-8 encoding of U+008B")
	}
	if !zip.Raw || !zip.match(200, "PK\x03\x04", nil, false, "", false) {
		t.Fatal("backup-zip did not match zip magic")
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	body := `[{"id":"x","path":"/x","message":"m","nope":true}]`
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadRejectsBadRegex(t *testing.T) {
	dir := t.TempDir()
	body := `[{"id":"x","path":"/x","message":"m","body":"("}]`
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected error")
	}
}

func TestSoft404SuppressesMatchingBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		_, _ = w.Write([]byte("missing page"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	raw := `[{"id":"secret","path":"/secret","statuses":[200],"body":"missing","message":"secret is exposed"}]`
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	checks, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	tg := mustTarget(t, srv.URL)
	client := mustClient(t, tg)
	findings, err := Run(context.Background(), tg, client, checks, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.ID == "secret" {
			t.Fatalf("soft 404 reported: %+v", f)
		}
	}
}

func TestPathCheckAndRootJoin(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		paths = append(paths, r.URL.Path)
		if strings.Contains(r.URL.Path, "transom-") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("SECRET"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	raw := `[{"id":"secret","path":"/health","statuses":[200],"body":"SECRET","message":"health is exposed"}]`
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	checks, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	tg := mustTarget(t, srv.URL)
	tg.Root = "/app"
	client := mustClient(t, tg)
	findings, err := Run(context.Background(), tg, client, checks, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPath(paths, "/app/health") {
		t.Fatalf("paths %v", paths)
	}
	if !hasID(findings, "secret") {
		t.Fatalf("findings %+v", findings)
	}
}

func TestMissingSecurityHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	client := mustClient(t, tg)
	findings, err := Run(context.Background(), tg, client, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"header-xcto", "header-csp", "header-referrer", "header-permissions", "header-hsts"} {
		if !hasID(findings, id) {
			t.Fatalf("missing %s in %+v", id, findings)
		}
	}
}

func TestBannerFindings(t *testing.T) {
	resp := fetch.Response{
		Status: 200,
		URL:    "http://example.com/",
		Header: http.Header{
			"Server":          {"Apache/2.4.25 (Debian)"},
			"X-Powered-By":    {"PHP/7.1.26"},
			"X-Frame-Options": {"SAMEORIGIN"},
		},
	}
	findings := bannerFindings("http://example.com/", resp)
	for _, id := range []string{"header-powered-by", "header-xfo", "outdated-apache", "outdated-php"} {
		if !hasID(findings, id) {
			t.Fatalf("missing %s in %+v", id, findings)
		}
	}
	iis := bannerFindings("http://example.com/", fetch.Response{
		Status: 200,
		URL:    "http://example.com/",
		Header: http.Header{"Server": {"Microsoft-IIS/8.5"}},
	})
	nginx := bannerFindings("http://example.com/", fetch.Response{
		Status: 200,
		URL:    "http://example.com/",
		Header: http.Header{"Server": {"nginx/1.14.0 (Ubuntu)"}},
	})
	uncommon := headerFindings(target.Target{Host: "example.com", Port: 80, Scheme: "http", Root: "/"}, fetch.Response{
		Status: 200,
		URL:    "http://example.com/",
		Header: http.Header{
			"X-Backend":    {"abc"},
			"Content-Type": {"text/html"},
			"X-Powered-By": {"Express"},
		},
	})
	if !hasID(uncommon, "header-uncommon") {
		t.Fatalf("uncommon findings %+v", uncommon)
	}
	if !hasID(nginx, "outdated-nginx") {
		t.Fatalf("nginx findings %+v", nginx)
	}
	if !hasID(iis, "outdated-iis") {
		t.Fatalf("iis findings %+v", iis)
	}
	current := bannerFindings("http://example.com/", fetch.Response{
		Status: 200,
		URL:    "http://example.com/",
		Header: http.Header{"Server": {"Apache/2.4.68"}},
	})
	if hasID(current, "outdated-apache") {
		t.Fatalf("current apache flagged: %+v", current)
	}
}

func TestInodeETag(t *testing.T) {
	header := func(v string) http.Header {
		h := make(http.Header)
		h.Set("ETag", v)
		return h
	}
	if !inodeETag(header(`"1700164080.9118829-15406-2525694601"`)) {
		t.Fatal("dotted inode etag")
	}
	if !inodeETag(header(`W/"1a2b-3c-4d"`)) {
		t.Fatal("weak hex etag")
	}
	if inodeETag(header(`"64a1b2c3-1234"`)) || inodeETag(header(`"hello-world-etag"`)) {
		t.Fatal("non-inode etag matched")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.Header().Set("ETag", `"1700164080.9118829-15406-2525694601"`)
		}
		if strings.HasSuffix(r.URL.Path, "favicon.ico") {
			w.Header().Set("ETag", `"1700164080.9118829-15406-2525694601"`)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	client := mustClient(t, tg)
	findings, err := Run(context.Background(), tg, client, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	var got []Finding
	for _, f := range findings {
		if f.ID == "etag-inode" {
			got = append(got, f)
		}
	}
	if len(got) != 1 || got[0].Message != "ETag leaks an inode" || !strings.HasSuffix(got[0].URL, "/robots.txt") {
		t.Fatalf("%+v", got)
	}
}

func TestViaHeader(t *testing.T) {
	tg := target.Target{Host: "example.com", Port: 80, Scheme: "http", Root: "/"}
	findings := headerFindings(tg, fetch.Response{
		Status: 200,
		URL:    "http://example.com/",
		Header: http.Header{
			"Via":          {"1.1 heroku-router"},
			"Content-Type": {"text/html"},
		},
	})
	var via Finding
	for _, f := range findings {
		if f.ID == "header-via" {
			via = f
		}
		if f.ID == "header-uncommon" && strings.Contains(strings.ToLower(f.Message), "via") {
			t.Fatalf("via also reported as uncommon: %+v", f)
		}
	}
	if via.Message != "Via header: 1.1 heroku-router" {
		t.Fatalf("via findings %+v", findings)
	}
}

func TestLinkHeader(t *testing.T) {
	tg := target.Target{Host: "example.com", Port: 443, Scheme: "https", Root: "/"}
	findings := headerFindings(tg, fetch.Response{
		Status: 200,
		URL:    "https://example.com/",
		Header: http.Header{
			"Link":         {`</assets/app.css>; rel=preload; as=style`},
			"Content-Type": {"text/html"},
		},
	})
	var link Finding
	for _, f := range findings {
		if f.ID == "header-link" {
			link = f
		}
		if f.ID == "header-uncommon" && strings.Contains(strings.ToLower(f.Message), "link") {
			t.Fatalf("link also reported as uncommon: %+v", f)
		}
	}
	if link.Message != "Link header: </assets/app.css>; rel=preload; as=style" {
		t.Fatalf("%+v", findings)
	}
}

func TestCloudflareBanner(t *testing.T) {
	findings := bannerFindings("https://example.com/", fetch.Response{
		Status: 200,
		URL:    "https://example.com/",
		Header: http.Header{"Server": {"cloudflare"}},
	})
	if len(findings) != 1 || findings[0].ID != "header-cloudflare" || findings[0].Message != "Server banner is Cloudflare" {
		t.Fatalf("%+v", findings)
	}
}

func TestCloudflareTrace(t *testing.T) {
	if !cloudflareTrace("fl=1\nh=example.com\nip=1.2.3.4\ncolo=ATL\nvisit_scheme=https\n") {
		t.Fatal("trace body")
	}
	if cloudflareTrace("<html><body>not a trace</body></html>") {
		t.Fatal("html matched trace")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=()")
		w.Header().Set("Strict-Transport-Security", "max-age=1")
		if r.URL.Path == "/cdn-cgi/trace" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			_, _ = w.Write([]byte("fl=1\nh=example.com\nip=1.2.3.4\ncolo=ATL\nvisit_scheme=http\n"))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	client := mustClient(t, tg)
	findings, err := Run(context.Background(), tg, client, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	var trace, acao, xfo Finding
	for _, f := range findings {
		switch f.ID {
		case "cloudflare-trace":
			trace = f
		case "header-acao":
			acao = f
		case "header-xfo":
			xfo = f
		}
	}
	if trace.Message != "Cloudflare trace output" || !strings.HasSuffix(trace.URL, "/cdn-cgi/trace") {
		t.Fatalf("trace %+v", trace)
	}
	if acao.Message != "Access-Control-Allow-Origin is *" || !strings.HasSuffix(acao.URL, "/cdn-cgi/trace") {
		t.Fatalf("acao %+v", acao)
	}
	if xfo.Message != "X-Frame-Options is set; Content-Security-Policy frame-ancestors replaced it" || !strings.HasSuffix(xfo.URL, "/cdn-cgi/trace") {
		t.Fatalf("xfo %+v", xfo)
	}
}

func TestBannerWatch(t *testing.T) {
	w := &bannerWatch{base: "http://example.com/"}
	w.observe(fetch.Response{Status: 200, URL: "http://example.com/", Header: http.Header{"Server": {"Heroku"}}})
	w.observe(fetch.Response{Status: 404, URL: "http://example.com/missing", Header: http.Header{"Server": {"Microsoft-HTTPAPI/2.0"}}})
	if got := w.finding(); got != nil {
		t.Fatalf("httpapi counted as a change: %+v", got)
	}
	w.observe(fetch.Response{Status: 403, URL: "http://example.com/.git/HEAD", Header: http.Header{"Server": {"Apache/2.4.68 (Unix)"}}})
	w.observe(fetch.Response{Status: 200, URL: "http://example.com/other", Header: http.Header{"Server": {"BigIP"}}})
	got := w.finding()
	if len(got) != 1 || got[0].Message != "Server banner changed from 'Heroku' to 'Apache/2.4.68 (Unix)'" || got[0].URL != "http://example.com/.git/HEAD" {
		t.Fatalf("%+v", got)
	}
}

func TestBannerChangeDuringScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/HEAD" {
			w.Header().Set("Server", "Apache/2.4.68 (Unix)")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Server", "Heroku")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	client := mustClient(t, tg)
	checks := []Check{{
		ID: "git-head", Path: "/.git/HEAD", Method: http.MethodGet, Statuses: []int{http.StatusOK}, Message: "Exposes git ref",
	}}
	findings, err := Run(context.Background(), tg, client, checks, 2)
	if err != nil {
		t.Fatal(err)
	}
	if hasID(findings, "git-head") {
		t.Fatalf("403 git head reported: %+v", findings)
	}
	var changes []Finding
	for _, f := range findings {
		if f.ID == "banner-change" {
			changes = append(changes, f)
		}
	}
	if len(changes) != 1 || changes[0].Message != "Server banner changed from 'Heroku' to 'Apache/2.4.68 (Unix)'" || !strings.HasSuffix(changes[0].URL, "/.git/HEAD") {
		t.Fatalf("%+v", changes)
	}
}

func TestHostlessTrackOrigin(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "TRACK" && r.Host == "" {
			w.Header().Set("Server", "Jetty(9.2.9.v20150224)")
			w.Header().Set("Set-Cookie", "JSESSIONID=abc; Path=/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Server", "nginx")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=()")
		w.Header().Set("Strict-Transport-Security", "max-age=1")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	client := mustClient(t, tg)
	findings, err := Run(context.Background(), tg, client, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	var banner string
	var cookies []string
	for _, f := range findings {
		switch f.ID {
		case "banner-change":
			banner = f.Message
		case "cookie-httponly", "cookie-secure":
			cookies = append(cookies, f.Message)
		}
	}
	if banner != "Server banner changed from 'nginx' to 'Jetty(9.2.9.v20150224)'" {
		t.Fatalf("banner %q findings %+v", banner, findings)
	}
	want := []string{
		"The 'JSESSIONID' cookie is missing an HttpOnly flag",
		"The 'JSESSIONID' cookie is missing a Secure flag",
	}
	if strings.Join(cookies, "\n") != strings.Join(want, "\n") {
		t.Fatalf("cookies %v", cookies)
	}
}

func TestCertHostnameAndExpiry(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	client := mustClient(t, tg)
	resp := client.Do(context.Background(), http.MethodGet, "/")
	if resp.Err != nil {
		t.Fatal(resp.Err)
	}
	now := time.Now()
	hostMiss := certFindings("not-a-real-host.invalid", resp.TLS, now, tg.BaseURL(), resp.URL, resp.Status)
	if !hasID(hostMiss, "tls-hostname") {
		t.Fatalf("hostname findings %+v", hostMiss)
	}
	expiredState := certState(resp.TLS, now.Add(-time.Hour), now.Add(-time.Minute))
	expired := certFindings(tg.Host, expiredState, now, tg.BaseURL(), resp.URL, resp.Status)
	if !hasID(expired, "tls-expired") || hasID(expired, "tls-expiring") {
		t.Fatalf("expired findings %+v", expired)
	}
	soonState := certState(resp.TLS, now.Add(-time.Hour), now.Add(10*24*time.Hour))
	soon := certFindings(tg.Host, soonState, now, tg.BaseURL(), resp.URL, resp.Status)
	if !hasID(soon, "tls-expiring") {
		t.Fatalf("expiring findings %+v", soon)
	}
	wild := *soonState.PeerCertificates[0]
	wild.DNSNames = []string{"*.appspot.com", "appspot.com"}
	wild.Subject.CommonName = "*.appspot.com"
	wildState := *soonState
	wildState.PeerCertificates = []*x509.Certificate{&wild}
	wildcard := certFindings(tg.Host, &wildState, now, tg.BaseURL(), resp.URL, resp.Status)
	if !hasID(wildcard, "tls-wildcard") {
		t.Fatalf("wildcard findings %+v", wildcard)
	}
}

func certState(src *tls.ConnectionState, notBefore, notAfter time.Time) *tls.ConnectionState {
	state := *src
	leaf := *state.PeerCertificates[0]
	leaf.NotBefore = notBefore
	leaf.NotAfter = notAfter
	state.PeerCertificates = []*x509.Certificate{&leaf}
	return &state
}

func TestOptionsAllow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "POST, OPTIONS, GET, HEAD")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	client := mustClient(t, tg)
	findings, err := Run(context.Background(), tg, client, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, f := range findings {
		if f.ID == "options-allow" {
			got = f.Message
		}
	}
	if got != "Allowed HTTP Methods: POST, OPTIONS, GET, HEAD" {
		t.Fatalf("findings %+v", findings)
	}
}

func TestFindingOrder(t *testing.T) {
	findings := []Finding{
		{ID: "header-hsts", URL: "http://example/", Message: "Strict-Transport-Security is missing"},
		{ID: "header-csp", URL: "http://example/", Message: "Content-Security-Policy is missing"},
		{ID: "apache-icons-readme", URL: "http://example/icons/README", Message: "Default Apache file"},
		{ID: "phpinfo", URL: "http://example/info.php", Message: "phpinfo() output"},
		{ID: "db-sql", URL: "http://example/db.sql", Message: "Exposed database dump"},
		{ID: "composer-json", URL: "http://example/composer.json", Message: "PHP package requirements"},
		{ID: "composer-lock", URL: "http://example/composer.lock", Message: "Installed PHP packages"},
		{ID: "composer-installed", URL: "http://example/vendor/composer/installed.json", Message: "Installed PHP packages"},
		{ID: "internal-ip", URL: "http://example/aspnet_client"},
		{ID: "outdated-iis", URL: "http://example/"},
		{ID: "options-allow", URL: "http://example/"},
		{ID: "header-permissions", URL: "http://example/", Message: "Permissions-Policy is missing"},
	}
	sortFindings(findings)
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.ID)
	}
	want := []string{"db-sql", "outdated-iis", "internal-ip", "composer-installed", "composer-lock", "phpinfo", "composer-json", "apache-icons-readme", "header-csp", "header-permissions", "header-hsts", "options-allow"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("%v", ids)
	}
}

func TestLoginPageAfterWebConfig(t *testing.T) {
	findings := []Finding{
		{ID: "robots-disallow", Message: "A robots.txt page is readable"},
		{ID: "home-dir", Message: "Readable"},
		{ID: "user-dir", Message: "Login page"},
		{ID: "sitemap-xml", Message: "Sitemap"},
		{ID: "web-config", Message: "ASP config file is accessible"},
		{ID: "user-dir", Message: "Readable"},
	}
	sortFindings(findings)
	var got []string
	for _, f := range findings {
		got = append(got, f.ID+":"+f.Message)
	}
	want := []string{
		"web-config:ASP config file is accessible",
		"user-dir:Login page",
		"sitemap-xml:Sitemap",
		"robots-disallow:A robots.txt page is readable",
		"home-dir:Readable",
		"user-dir:Readable",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%v", got)
	}
}

func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		return findingLess(findings[i], findings[j])
	})
}

func TestHTTPCookieMissingHttpOnly(t *testing.T) {
	tg := target.Target{Host: "example.com", Port: 80, Scheme: "http", Root: "/"}
	resp := fetch.Response{
		Status: 200,
		URL:    "http://example.com/",
		Header: http.Header{"Set-Cookie": {"ASPSESSIONID=abc; path=/"}},
	}
	findings := cookieFindings(tg, resp)
	if !hasID(findings, "cookie-httponly") || hasID(findings, "cookie-secure") {
		t.Fatalf("%+v", findings)
	}
	if findings[0].Message != "The 'ASPSESSIONID' cookie is missing an HttpOnly flag" {
		t.Fatalf("%+v", findings)
	}
}

func TestHTTPSCookieMissingSecure(t *testing.T) {
	tg := target.Target{Host: "example.com", Port: 443, Scheme: "https", Root: "/"}
	resp := fetch.Response{
		Status: 200,
		URL:    "https://example.com/",
		Header: http.Header{"Set-Cookie": {"session=abc; path=/"}},
	}
	findings := cookieFindings(tg, resp)
	var secure Finding
	for _, f := range findings {
		if f.ID == "cookie-secure" {
			secure = f
		}
	}
	if secure.Message != "The 'session' cookie is missing a Secure flag" {
		t.Fatalf("%+v", findings)
	}
}

func TestNginxAfterControlPanels(t *testing.T) {
	findings := []Finding{
		{ID: "outdated-nginx", Message: "nginx/1.29.8 is older than the current release 1.31.6"},
		{ID: "cpanel", Message: "Web-based control panel"},
		{ID: "info-dir", Message: "This might be interesting"},
		{ID: "public-dir", Message: "This might be interesting"},
		{ID: "webmail", Message: "Web based mail package installed"},
		{ID: "securecontrolpanel", Message: "Web server control panel"},
		{ID: "banner-change", Message: "Server banner changed"},
		{ID: "outdated-apache", Message: "Apache/2.4.25 is older than the current release 2.4.68"},
	}
	sortFindings(findings)
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.ID)
	}
	want := []string{"outdated-apache", "webmail", "securecontrolpanel", "cpanel", "info-dir", "public-dir", "outdated-nginx", "banner-change"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("%v", ids)
	}
}

func TestCookieNameOrder(t *testing.T) {
	findings := []Finding{
		{ID: "cookie-secure", Message: "The 'security' cookie is missing a Secure flag"},
		{ID: "cookie-httponly", Message: "The 'PHPSESSID' cookie is missing an HttpOnly flag"},
		{ID: "header-csp", Message: "Content-Security-Policy is missing"},
		{ID: "cookie-httponly", Message: "The 'security' cookie is missing an HttpOnly flag"},
		{ID: "cookie-secure", Message: "The 'PHPSESSID' cookie is missing a Secure flag"},
	}
	sortFindings(findings)
	var got []string
	for _, f := range findings {
		got = append(got, f.Message)
	}
	want := []string{
		"The 'PHPSESSID' cookie is missing an HttpOnly flag",
		"The 'security' cookie is missing an HttpOnly flag",
		"The 'PHPSESSID' cookie is missing a Secure flag",
		"The 'security' cookie is missing a Secure flag",
		"Content-Security-Policy is missing",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("%v", got)
	}
}

func TestInternalIP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		_, _ = io.WriteString(conn, "HTTP/1.1 301 Moved\r\nLocation: http://10.0.0.14/aspnet_client/\r\nContent-Length: 0\r\n\r\n")
	}()
	host, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	tg := target.Target{Host: host, Port: port, Scheme: "http", Root: "/"}
	findings := internalIPFindings(context.Background(), tg, 2*time.Second)
	if len(findings) != 1 || findings[0].Status != 301 || findings[0].Message != "Location discloses internal address 10.0.0.14" {
		t.Fatalf("%+v", findings)
	}
}

func TestInternalIPIgnoresBody(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\nsee 10.1.2.3 here")
	}()
	host, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	findings := internalIPFindings(context.Background(), target.Target{Host: host, Port: port, Scheme: "http", Root: "/"}, 2*time.Second)
	if len(findings) != 0 {
		t.Fatalf("%+v", findings)
	}
}

func TestDefaultIISPage(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\nIIS Windows Server")
	}()
	host, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	findings := defaultIISFindings(context.Background(), target.Target{Host: host, Port: port, Scheme: "http", Root: "/"}, 2*time.Second)
	if len(findings) != 1 || findings[0].ID != "iis-default" || findings[0].Status != 200 {
		t.Fatalf("%+v", findings)
	}
}

func TestDefaultIISRequires200(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		_, _ = io.WriteString(conn, "HTTP/1.1 404 Not Found\r\nContent-Length: 18\r\n\r\nIIS Windows Server")
	}()
	host, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	findings := defaultIISFindings(context.Background(), target.Target{Host: host, Port: port, Scheme: "http", Root: "/"}, 2*time.Second)
	if len(findings) != 0 {
		t.Fatalf("%+v", findings)
	}
}

func TestRobotsReadablePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		switch r.URL.Path {
		case "/robots.txt":
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /secret\nDisallow: /\n"))
		case "/secret":
			_, _ = w.Write([]byte("top secret"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	client := mustClient(t, tg)
	findings, err := Run(context.Background(), tg, client, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	var urls []string
	for _, f := range findings {
		if f.ID == "robots-disallow" {
			if f.Message != "A robots.txt page is readable" {
				t.Fatalf("%+v", f)
			}
			urls = append(urls, f.URL)
		}
	}
	if len(urls) != 2 {
		t.Fatalf("%v", urls)
	}
	var sawFile, sawSecret bool
	for _, u := range urls {
		sawFile = sawFile || strings.HasSuffix(u, "/robots.txt")
		sawSecret = sawSecret || strings.HasSuffix(u, "/secret")
	}
	if !sawFile || !sawSecret {
		t.Fatalf("%v", urls)
	}
}

func TestHomeDirRedirectToBaseNotReported(t *testing.T) {
	home := Check{
		ID: "home-dir", Path: "/home/", Method: "GET", Statuses: []int{200},
		IgnoreSoft404: true, Message: "Readable",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/home" || r.URL.Path == "/home/" {
			http.Redirect(w, r, "/", http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<h1>home</h1>"))
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	client, err := fetch.New(tg, fetch.Options{Timeout: 2 * time.Second, Follow: "same-host", MaxBody: 1 << 20, UserAgent: "Transom/test"})
	if err != nil {
		t.Fatal(err)
	}
	findings, err := Run(context.Background(), tg, client, []Check{home}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if hasID(findings, "home-dir") {
		t.Fatalf("%+v", findings)
	}
}

func TestUserDirLoginPage(t *testing.T) {
	login := Check{
		ID: "user-dir", Path: "/user/", Method: "GET", Statuses: []int{200},
		IgnoreSoft404: true, Message: "Readable",
	}
	page := `<form id="user-login" action="/user"><input type="password" name="pass"></form>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" || r.URL.Path == "/user/" {
			_, _ = w.Write([]byte(page))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	client := mustClient(t, tg)
	findings, err := Run(context.Background(), tg, client, []Check{login}, 1)
	if err != nil {
		t.Fatal(err)
	}
	var got []Finding
	for _, f := range findings {
		if f.ID == "user-dir" {
			got = append(got, f)
		}
	}
	if len(got) != 1 || got[0].Message != "Login page" {
		t.Fatalf("%+v", got)
	}

	dir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user/" {
			_, _ = w.Write([]byte("<h1>Users</h1>"))
			return
		}
		http.NotFound(w, r)
	}))
	defer dir.Close()
	tg = mustTarget(t, dir.URL)
	client = mustClient(t, tg)
	findings, err = Run(context.Background(), tg, client, []Check{login}, 1)
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	for _, f := range findings {
		if f.ID == "user-dir" {
			got = append(got, f)
		}
	}
	if len(got) != 1 || got[0].Message != "Readable" {
		t.Fatalf("%+v", got)
	}
}

func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

func hasID(findings []Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func mustTarget(t *testing.T, raw string) target.Target {
	t.Helper()
	tg, err := target.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func mustClient(t *testing.T, tg target.Target) *fetch.Client {
	t.Helper()
	c, err := fetch.New(tg, fetch.Options{Timeout: 2 * time.Second, Follow: "off", MaxBody: 1 << 20, UserAgent: "Transom/test"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDebugMethodDistinctFromJunk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "QWERTZUI":
			_, _ = w.Write([]byte("junk page"))
		case "DEBUG":
			_, _ = w.Write([]byte("debug page"))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	client := mustClient(t, tg)
	findings, err := Run(context.Background(), tg, client, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(findings, "options-junk") || !hasID(findings, "options-debug") {
		t.Fatalf("%+v", findings)
	}
}

func TestDebugMethodSameBodySkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "QWERTZUI" || r.Method == "DEBUG" {
			_, _ = w.Write([]byte("same page"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	client := mustClient(t, tg)
	findings, err := Run(context.Background(), tg, client, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(findings, "options-junk") || hasID(findings, "options-debug") {
		t.Fatalf("%+v", findings)
	}
}

func TestJunkSameAsGetSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("home page"))
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	client := mustClient(t, tg)
	findings, err := Run(context.Background(), tg, client, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if hasID(findings, "options-junk") {
		t.Fatalf("%+v", findings)
	}
}

func TestRootPathCheckKept(t *testing.T) {
	c := Check{
		ID: "iis-default", Path: "/", Method: "GET", Statuses: []int{200},
		Body: "(?i)IIS\\s+Windows\\s+Server", Message: "Default IIS page",
	}
	if err := c.compile(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = io.WriteString(w, "IIS Windows Server")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	client := mustClient(t, tg)
	findings, err := Run(context.Background(), tg, client, []Check{c}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(findings, "iis-default") {
		t.Fatalf("%+v", findings)
	}
}

func TestPHPCreditsUnderRoot(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.RequestURI
		if strings.HasPrefix(r.URL.Path, "/app") && strings.Contains(r.URL.RawQuery, "PHPB") {
			_, _ = io.WriteString(w, "PHP Credits")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	tg.Root = "/app"
	client := mustClient(t, tg)
	findings := phpCreditFindings(context.Background(), client, tg)
	if len(findings) != 1 || findings[0].ID != "php-credits" {
		t.Fatalf("%+v got %s", findings, got)
	}
	if !strings.HasPrefix(got, "/app/?=") {
		t.Fatalf("request %s", got)
	}
}

func TestRawProbeEncodesPath(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	gotLine := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		gotLine <- string(buf[:n])
		_, _ = io.WriteString(conn, "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
	}()
	host, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	tg := target.Target{Host: host, Port: port, Scheme: "http", Root: "/"}
	if _, _, _, err := http10NoHost(context.Background(), tg, "/my file", 2*time.Second); err != nil {
		t.Fatal(err)
	}
	line := <-gotLine
	if !strings.HasPrefix(line, "GET /my%20file HTTP/1.0\r\n") {
		t.Fatalf("%q", line)
	}
}

func TestIdentityMagicFetch(t *testing.T) {
	c := Check{
		ID: "backup-gzip", Path: "/backup.tar.gz", Method: "GET", Statuses: []int{200},
		Body: "^\\x1f\\x8b", Raw: true, Message: "gzip data",
	}
	if err := c.compile(); err != nil {
		t.Fatal(err)
	}
	magic := string([]byte{0x1f, 0x8b, 0x08})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/backup.tar.gz" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Accept-Encoding") != "identity" {
			_, _ = io.WriteString(w, "decoded")
			return
		}
		_, _ = io.WriteString(w, magic)
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	client := mustClient(t, tg)
	findings, err := Run(context.Background(), tg, client, []Check{c}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(findings, "backup-gzip") {
		t.Fatalf("%+v", findings)
	}
}

func TestShortBodyStillScans(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Type: text/plain\r\n\r\nshort")
		conn.Close()
		ln.Close()
	}()
	host, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	raw := "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/"
	tg := mustTarget(t, raw)
	client := mustClient(t, tg)
	findings, err := Run(context.Background(), tg, client, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(findings, "header-csp") {
		t.Fatalf("%+v", findings)
	}
}

func TestCommonSecurityHeaders(t *testing.T) {
	resp := fetch.Response{
		Status: 200,
		URL:    "http://example.com/",
		Header: http.Header{
			"Alt-Svc":                      {"h3=\":443\""},
			"Content-Disposition":          {"inline"},
			"Cross-Origin-Opener-Policy":   {"same-origin"},
			"Cross-Origin-Resource-Policy": {"same-origin"},
			"Cross-Origin-Embedder-Policy": {"require-corp"},
			"Report-To":                    {"{}"},
			"Nel":                          {"{}"},
			"X-Custom":                     {"yes"},
		},
	}
	findings := uncommonHeaderFindings("http://example.com/", resp)
	if len(findings) != 1 || !strings.Contains(findings[0].Message, "x-custom") {
		t.Fatalf("%+v", findings)
	}
}

func TestOldTLSVersion(t *testing.T) {
	state := &tls.ConnectionState{Version: tls.VersionTLS10}
	got := certFindings("example.com", state, time.Now(), "https://example.com/", "https://example.com/", 200)
	if len(got) != 1 || got[0].ID != "tls-version" || !strings.Contains(got[0].Message, "TLS 1.0") {
		t.Fatalf("%+v", got)
	}
	current := &tls.ConnectionState{Version: tls.VersionTLS13}
	if extra := certFindings("example.com", current, time.Now(), "https://example.com/", "https://example.com/", 200); extra != nil {
		t.Fatalf("%+v", extra)
	}
}

func TestIPLinkWhenHostnameOmitsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Host, "127.0.0.1") {
			w.Header().Set("Link", `<http://127.0.0.1/>; rel="canonical"`)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tg := mustTarget(t, srv.URL)
	tg.Host = "localhost"
	base := fetch.Response{Status: 200, URL: tg.BaseURL(), Header: make(http.Header)}
	found := ipLinkFindings(context.Background(), tg, base, 2*time.Second)
	if len(found) != 1 || found[0].ID != "header-link" || !strings.Contains(found[0].Message, `rel="canonical"`) {
		t.Fatalf("%+v", found)
	}
	if !strings.Contains(found[0].URL, "127.0.0.1") {
		t.Fatalf("url %s", found[0].URL)
	}
	base.Header.Set("Link", `</>; rel="canonical"`)
	if extra := ipLinkFindings(context.Background(), tg, base, 2*time.Second); extra != nil {
		t.Fatalf("duplicate link: %+v", extra)
	}
}
