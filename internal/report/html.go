package report

import (
	"fmt"
	"html"
	"html/template"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/leebaird/transom/internal/check"
	"github.com/leebaird/transom/internal/target"
)

// WriteHTML writes a browser report: a scan summary, one section per host,
// and one table per finding. Repeated checks with the same message share a
// table, and each URL is a link in that table. The file is replaced by
// renaming a temp file.
func WriteHTML(path string, doc Document) error {
	doc = normalize(doc)
	return writeAtomic(path, func(w io.Writer) error {
		return htmlReport.Execute(w, htmlView(doc))
	})
}

type htmlViewData struct {
	Started      string
	Finished     string
	Duration     string
	FindingCount int
	Interrupted  bool
	Sections     []htmlSection
}

type htmlSection struct {
	Title    string
	Host     string
	Port     int
	Scheme   string
	Findings []htmlFinding
}

// htmlFinding is one report table. URLs lists every page for that check and message.
type htmlFinding struct {
	Message string
	ID      string
	Target  string
	URLs    []string
}

// discoverStamp matches Discover's human UTC stamp: mm/dd/yyyy - hh:mm Z.
func discoverStamp(t time.Time) string {
	return t.UTC().Format("01/02/2006 - 15:04 Z")
}

func htmlView(doc Document) htmlViewData {
	elapsed := doc.Finished.Sub(doc.Started)
	if elapsed < 0 {
		elapsed = 0
	}
	sections := make([]htmlSection, 0, len(doc.Targets))
	used := make([]bool, len(doc.Findings))
	for _, tg := range doc.Targets {
		base := target.Target{Host: tg.Host, Port: tg.Port, Scheme: tg.Scheme, Root: tg.Root}.BaseURL()
		var raw []check.Finding
		for i, f := range doc.Findings {
			if f.Target == base {
				raw = append(raw, f)
				used[i] = true
			}
		}
		sections = append(sections, htmlSection{
			Title:    tg.Host + " port " + strconv.Itoa(tg.Port),
			Host:     tg.Host,
			Port:     tg.Port,
			Scheme:   tg.Scheme,
			Findings: groupFindings(raw),
		})
	}
	var extra []check.Finding
	for i, f := range doc.Findings {
		if !used[i] {
			extra = append(extra, f)
		}
	}
	if len(extra) > 0 {
		sections = append(sections, htmlSection{Title: "Other findings", Findings: groupFindings(extra)})
	}
	return htmlViewData{
		Started:      discoverStamp(doc.Started),
		Finished:     discoverStamp(doc.Finished),
		Duration:     elapsed.Round(time.Second).String(),
		FindingCount: len(doc.Findings),
		Interrupted:  doc.Interrupted,
		Sections:     sections,
	}
}

func sameBase(page, base string) bool {
	return strings.TrimRight(page, "/") == strings.TrimRight(base, "/")
}

// groupFindings keeps scan order and folds repeated check-and-message rows
// into one table. The links stay in that same order.
func groupFindings(findings []check.Finding) []htmlFinding {
	var out []htmlFinding
	index := map[string]int{}
	for _, f := range findings {
		key := f.ID + "\x00" + f.Message
		if i, ok := index[key]; ok {
			out[i].URLs = append(out[i].URLs, f.URL)
			continue
		}
		index[key] = len(out)
		out = append(out, htmlFinding{
			Message: f.Message,
			ID:      f.ID,
			Target:  f.Target,
			URLs:    []string{f.URL},
		})
	}
	for i := range out {
		out[i].Message = robotsLabel(out[i].Message, len(out[i].URLs))
	}
	return out
}

func robotsLabel(message string, n int) string {
	if message != "A robots.txt page is readable" || n < 2 {
		return message
	}
	return fmt.Sprintf("%d robots.txt pages are readable", n)
}

func linkList(urls []string, base string) template.HTML {
	var b strings.Builder
	for i, page := range urls {
		if i > 0 {
			b.WriteString("<br>")
		}
		if sameBase(page, base) {
			b.WriteString("Base")
			continue
		}
		esc := html.EscapeString(page)
		b.WriteString(`<a href="`)
		b.WriteString(esc)
		b.WriteString(`" target="_blank" rel="noopener">`)
		b.WriteString(esc)
		b.WriteString(`</a>`)
	}
	return template.HTML(b.String())
}

var htmlReport = template.Must(template.New("report").Funcs(template.FuncMap{
	"linkList": linkList,
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Transom Report</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: sans-serif; color: #e8eaed; background: #0f1114; margin: 2rem; }
  h1 { font-size: 1.6rem; }
  p.byline { margin-bottom: 2rem; }
  h2 { font-size: 1.15rem; margin-top: 2rem; }
  a { color: #8ab4f8; }
  table { border-collapse: collapse; width: 100%; max-width: 56rem; margin: 0 0 1rem; table-layout: fixed; }
  table.summary { width: max-content; table-layout: fixed; }
  table.summary td { white-space: nowrap; min-width: 14rem; overflow-wrap: normal; }
  th, td { border: 1px solid #2a3340; padding: 0.35rem 0.6rem; vertical-align: top; text-align: left; }
  th { width: 7rem; background: #151a20; color: #cfd6df; }
  td { background: #12161c; overflow-wrap: anywhere; }
  .finding { margin-bottom: 0.75rem; }
  hr.port { border: 0; border-top: 4px solid #8ab4f8; margin: 2rem 0; max-width: 56rem; }
</style>
</head>
<body>
<h1>Transom Report</h1>
<p class="byline">by Lee Baird</p>
{{range $i, $s := .Sections}}
{{if and .Host (gt $i 0)}}<hr class="port">{{end}}
{{if not .Host}}<h2>{{.Title}}</h2>{{end}}
{{if .Host}}
<table>
  <tr><th>Hostname</th><td>{{.Host}}</td></tr>
  <tr><th>Port</th><td>{{.Port}}</td></tr>
  <tr><th>Service</th><td>{{.Scheme}}</td></tr>
</table>
{{end}}
{{if .Findings}}
{{range .Findings}}
<table class="finding">
  <tr><th>Finding</th><td>{{.Message}}</td></tr>
  <tr><th>Check</th><td>{{.ID}}</td></tr>
  <tr><th>{{if gt (len .URLs) 1}}Links{{else}}Link{{end}}</th><td>{{linkList .URLs .Target}}</td></tr>
</table>
{{end}}
{{else}}
<p>No findings.</p>
{{end}}
{{end}}
<h2>Scan summary</h2>
<table class="summary">
  <tr><th>Start time</th><td>{{.Started}}</td></tr>
  <tr><th>End time</th><td>{{.Finished}}</td></tr>
  <tr><th>Duration</th><td>{{.Duration}}</td></tr>
  <tr><th>Findings</th><td>{{.FindingCount}}</td></tr>
  {{if .Interrupted}}<tr><th>Interrupted</th><td>yes</td></tr>{{end}}
</table>
</body>
</html>
`))
