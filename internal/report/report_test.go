package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leebaird/transom/internal/check"
)

func TestWriteJSONReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	started := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	doc := Document{
		Started:  started,
		Finished: started.Add(time.Second),
		Targets:  []Target{{Host: "example.com", Port: 8443, Scheme: "https", Root: "/"}},
		Findings: []check.Finding{{
			ID: "header-hsts", Target: "https://example.com:8443/", URL: "https://example.com:8443/",
			Status: 200, Message: "Strict-Transport-Security is missing",
		}},
	}
	if err := WriteJSON(path, doc); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file still present: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got Document
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 || got.Findings[0].ID != "header-hsts" {
		t.Fatalf("%s", data)
	}
	if got.Interrupted {
		t.Fatal("interrupted")
	}
}

func TestWriteHTML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.htm")
	started := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	doc := Document{
		Command:  "./transom -o scanme.htm scanme.nmap.org",
		Started:  started,
		Finished: started.Add(1500 * time.Millisecond),
		Targets: []Target{
			{Host: "example.com", Port: 8443, Scheme: "https", Root: "/"},
			{Host: "example.com", Port: 80, Scheme: "http", Root: "/"},
		},
		Findings: []check.Finding{{
			ID: "outdated-apache", Target: "https://example.com:8443/", URL: "https://example.com:8443/",
			Status: 200, Message: "Apache/2.4.29 is older than the current release 2.4.68",
		}, {
			ID: "env-file", Target: "https://example.com:8443/", URL: "https://example.com:8443/.env",
			Status: 200, Message: `<script>alert("x")</script>`,
		}, {
			ID: "robots-disallow", Target: "https://example.com:8443/", URL: "https://example.com:8443/deny",
			Status: 200, Message: "A robots.txt page is readable",
		}, {
			ID: "robots-disallow", Target: "https://example.com:8443/", URL: "https://example.com:8443/robots.txt",
			Status: 200, Message: "A robots.txt page is readable",
		}},
	}
	if err := WriteHTML(path, doc); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file still present: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	for _, want := range []string{
		"<!DOCTYPE html>",
		"background: #0f1114",
		"table-layout: fixed",
		"th { width: 7rem;",
		"table.summary { width: max-content; table-layout: fixed; }",
		`table class="summary"`,
		"Scan summary",
		">Start time<",
		">Finding<",
		">Check<",
		">Link<",
		"outdated-apache",
		"env-file",
		">Base<",
		"https://example.com:8443/.env",
		`target="_blank"`,
		"&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;",
		"Lee Baird",
		"09/27/2026 - 12:00 Z",
		"2s",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in\n%s", want, body)
		}
	}
	if strings.Contains(body, "Inspired by Nikto") || strings.Contains(body, "<footer>") {
		t.Fatal("footer still present")
	}
	if strings.Contains(body, "Software") || strings.Contains(body, "<th>Author</th>") {
		t.Fatal("summary still has author or version")
	}
	if strings.Contains(body, "HTTP status") {
		t.Fatal("finding still shows HTTP status")
	}
	if strings.Contains(body, ">URI<") || strings.Contains(body, ">Description<") {
		t.Fatal("finding still shows URI or description")
	}
	if strings.Contains(body, ">Root<") {
		t.Fatal("host table still shows root")
	}
	if !strings.Contains(body, "<th>Service</th>") || strings.Contains(body, "<th>Scheme</th>") {
		t.Fatal("host table label is not Service")
	}
	findingAt := strings.Index(body, ">Finding<")
	checkAt := strings.Index(body, ">Check<")
	linkAt := strings.Index(body, ">Link<")
	if findingAt < 0 || checkAt < findingAt || linkAt < checkAt {
		t.Fatal("finding rows are not Finding, Check, Link")
	}
	if !strings.Contains(body, "<th>Link</th><td>Base</td>") {
		t.Fatal("base finding link is not Base")
	}
	if strings.Count(body, ">robots-disallow<") != 1 {
		t.Fatal("repeated robots findings were not combined")
	}
	if !strings.Contains(body, ">2 robots.txt pages are readable<") || strings.Contains(body, "A robots.txt page is readable") {
		t.Fatal("robots finding was not counted")
	}
	combined := `<th>Links</th><td><a href="https://example.com:8443/deny" target="_blank" rel="noopener">https://example.com:8443/deny</a><br><a href="https://example.com:8443/robots.txt" target="_blank" rel="noopener">https://example.com:8443/robots.txt</a></td>`
	if !strings.Contains(body, combined) {
		t.Fatal("robots links are not in one cell")
	}
	if strings.Contains(body, "Site link") {
		t.Fatal("host table still has a site link")
	}
	if strings.Count(body, `hr class="port"`) != 1 {
		t.Fatal("expected one divider between ports")
	}
	if !strings.Contains(body, "<h1>Transom Report</h1>\n<p class=\"byline\">by Lee Baird</p>") {
		t.Fatal("byline missing")
	}
	if strings.Contains(body, ">Command<") || strings.Contains(body, "./transom -o scanme.htm") {
		t.Fatal("scan summary still shows the command")
	}
	if strings.Contains(body, "example.com port 8443") {
		t.Fatal("host heading still present")
	}
	if strings.Index(body, "https://example.com:8443/.env") > strings.Index(body, "Scan summary") {
		t.Fatal("scan summary is not at the bottom")
	}
	if strings.Contains(body, "<script>alert") {
		t.Fatal("message was not escaped")
	}
}

func TestWriteText(t *testing.T) {
	var b strings.Builder
	err := WriteText(&b, []check.Finding{{
		URL: "https://example.com:8443/", ID: "header-hsts", Message: "Strict-Transport-Security is missing",
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := "https://example.com:8443/  header-hsts  Strict-Transport-Security is missing\n"
	if b.String() != want {
		t.Fatalf("%q", b.String())
	}
}
