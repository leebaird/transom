package report

import (
	"bytes"
	"html"
	"strings"
	"testing"

	"github.com/leebaird/transom/internal/check"
)

// FuzzHTMLLinks checks that no finding URL, whatever the scanned server
// sent, becomes a link a browser would run or a way out of its attribute.
func FuzzHTMLLinks(f *testing.F) {
	for _, seed := range []string{
		"https://example.com/.env",
		"http://example.com/?a=1&b=2",
		"javascript:alert(1)",
		"JaVaScRiPt:alert(1)",
		" javascript:alert(1)",
		"java\tscript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
		`https://example.com/" onmouseover="alert(1)`,
		`https://example.com/?q="><script>x</script>`,
		"//example.com/path",
		"/relative",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, link string) {
		doc := normalize(Document{Findings: []check.Finding{
			{ID: "fuzz", Target: "https://example.com/", URL: link, Message: "m"},
		}})
		var out bytes.Buffer
		if err := htmlReport.Execute(&out, htmlView(doc)); err != nil {
			t.Fatal(err)
		}
		body := out.String()
		if strings.Count(body, "<a ") > 1 || strings.Contains(body, "<script") {
			t.Fatalf("%q added markup:\n%s", link, body)
		}
		_, rest, ok := strings.Cut(body, `<a href="`)
		if !ok {
			return
		}
		attr, rest, _ := strings.Cut(rest, `"`)
		if !strings.HasPrefix(rest, ` target="_blank" rel="noopener">`) {
			t.Fatalf("%q broke out of href:\n%s", link, body)
		}
		// A colon before any /, ? or # makes what precedes it a scheme.
		href := html.UnescapeString(attr)
		if i := strings.IndexAny(href, ":/?#"); i >= 0 && href[i] == ':' {
			switch strings.ToLower(href[:i]) {
			case "http", "https", "mailto":
			default:
				t.Fatalf("%q kept scheme %q in href %q", link, href[:i], href)
			}
		}
	})
}
