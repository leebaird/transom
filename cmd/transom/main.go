package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/leebaird/transom/internal/check"
	"github.com/leebaird/transom/internal/discover"
	"github.com/leebaird/transom/internal/fetch"
	"github.com/leebaird/transom/internal/report"
	"github.com/leebaird/transom/internal/target"
)

const usageText = `Transom
by Lee Baird

Usage:
  transom [flags] <target>...
  transom version

A hostname is probed on common web ports. host:port probes that socket.
A full URL scans that origin only.

If --user-agent is omitted, USER_AGENT is used when it starts with Mozilla/.
Otherwise Transom reads $DISCOVER/resource/user-agent.txt, then
~/discover/resource/user-agent.txt, then Discover's latest Edge UA.

Discovery and the raw probes use the same deadline and the same
HTTP_PROXY, HTTPS_PROXY, and NO_PROXY rules as path fetches.

Flags:
  --ports ports     Comma-separated ports, instead of ports.txt
  --timeout 10s     Deadline for one request or port probe
  --concurrency 8   In-flight requests
  --header value    Repeatable Name: value header
  --user-agent ua   User-Agent (default Discover's latest Edge UA)
  --follow mode     off or same-host (default same-host)
  --max-body bytes  Stop reading a body after this many bytes
  --checks dir      JSON check directory
  --format kind     json or htm (default follows the -o extension)
  -o path           Write a JSON or HTML report

`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type headerFlag struct{ h http.Header }

func (f *headerFlag) String() string { return "" }

func (f *headerFlag) Set(s string) error {
	name, value, ok := strings.Cut(s, ":")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		return fmt.Errorf("header must be Name: value")
	}
	if f.h == nil {
		f.h = http.Header{}
	}
	f.h.Add(name, strings.TrimSpace(value))
	return nil
}

func run(args []string, stdout, stderr io.Writer) int {
	for _, a := range args {
		if a == "version" || a == "--version" || a == "-version" {
			fmt.Fprintln(stdout, "Transom")
			return 0
		}
	}

	fs := flag.NewFlagSet("transom", flag.ContinueOnError)
	fs.SetOutput(stderr)
	portsFlag := fs.String("ports", "", "comma-separated discovery ports")
	timeout := fs.Duration("timeout", 10*time.Second, "deadline for one request or port probe")
	concurrency := fs.Int("concurrency", 8, "in-flight requests")
	uaFlag := fs.String("user-agent", "", "User-Agent (default Discover's latest Edge UA)")
	follow := fs.String("follow", "same-host", "off or same-host")
	maxBody := fs.Int64("max-body", 1<<20, "maximum response body")
	checksDir := fs.String("checks", "", "JSON check directory")
	formatFlag := fs.String("format", "", "json or htm")
	output := fs.String("o", "", "report path")
	var headers headerFlag
	fs.Var(&headers, "header", "repeatable Name: value")
	fs.Usage = func() { fmt.Fprint(stderr, usageText) }
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *follow != "off" && *follow != "same-host" {
		fmt.Fprintln(stderr, "follow must be off or same-host")
		return 1
	}
	if *concurrency < 1 {
		fmt.Fprintln(stderr, "concurrency must be at least 1")
		return 1
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "timeout must be positive")
		return 1
	}
	if *maxBody < 0 {
		fmt.Fprintln(stderr, "max-body must be zero or positive")
		return 1
	}
	targets := fs.Args()
	if len(targets) == 0 {
		fs.Usage()
		return 1
	}
	var ports []int
	loadPorts := func() ([]int, error) {
		if ports != nil {
			return ports, nil
		}
		if *portsFlag != "" {
			parsed, err := discover.ParsePorts(*portsFlag)
			if err != nil {
				return nil, err
			}
			ports = parsed
			return ports, nil
		}
		path, err := resolveFile("ports.txt")
		if err != nil {
			return nil, err
		}
		parsed, err := discover.LoadPorts(path)
		if err != nil {
			return nil, err
		}
		ports = parsed
		return ports, nil
	}
	dir, err := resolveChecks(*checksDir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	checks, err := check.LoadDir(dir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	started := time.Now()
	doc := report.Document{
		Command: formatCommand(append([]string{os.Args[0]}, args...)),
		Started: started,
	}
	var failed bool
	interrupted := false

	ua := *uaFlag
	if ua == "" {
		ua = discoverUserAgent()
	}
	opts := fetch.Options{
		Timeout:     *timeout,
		Follow:      *follow,
		MaxBody:     *maxBody,
		UserAgent:   ua,
		Headers:     headers.h,
		Concurrency: *concurrency,
	}

targets:
	for _, raw := range targets {
		if ctx.Err() != nil {
			interrupted = true
			break
		}
		tg, err := target.Parse(raw)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", raw, err)
			failed = true
			continue
		}
		var origins []target.Target
		var probed bool
		if tg.Discover {
			ports, err = loadPorts()
			if err != nil {
				fmt.Fprintln(stderr, err)
				failed = true
				break
			}
		}
		origins, probed, err = resolve(ctx, tg, ports, *concurrency, *timeout)
		if errors.Is(err, context.Canceled) {
			interrupted = true
		}
		if err != nil && !interrupted && len(origins) == 0 {
			fmt.Fprintf(stderr, "%s: %v\n", raw, err)
			failed = true
			continue
		}
		if len(origins) == 0 {
			if interrupted {
				break
			}
			fmt.Fprintf(stderr, "%s: no HTTP service\n", raw)
			failed = true
			continue
		}
		if probed {
			for _, o := range origins {
				fmt.Fprintf(stdout, "%s %s\n", o.HostPort(), o.Scheme)
			}
		}
		for _, o := range origins {
			doc.Targets = append(doc.Targets, report.Target{Host: o.Host, Port: o.Port, Scheme: o.Scheme, Root: o.Root})
			if interrupted || ctx.Err() != nil {
				interrupted = true
				break targets
			}
			client, err := fetch.New(o, opts)
			if err != nil {
				fmt.Fprintf(stderr, "%s: %v\n", o.HostPort(), err)
				failed = true
				continue
			}
			findings, err := check.Run(ctx, o, client, checks, *concurrency)
			if werr := report.WriteText(stdout, findings); werr != nil {
				fmt.Fprintln(stderr, werr)
				doc.Findings = append(doc.Findings, findings...)
				failed = true
				break targets
			}
			doc.Findings = append(doc.Findings, findings...)
			if errors.Is(err, context.Canceled) {
				interrupted = true
				break targets
			}
			if err != nil {
				fmt.Fprintf(stderr, "%s: %v\n", o.HostPort(), err)
				failed = true
			}
		}
		if interrupted {
			break
		}
	}

	doc.Finished = time.Now()
	doc.Interrupted = interrupted
	if *output != "" {
		kind, err := reportFormat(*formatFlag, *output)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		var werr error
		if kind == "htm" {
			werr = report.WriteHTML(*output, doc)
		} else {
			werr = report.WriteJSON(*output, doc)
		}
		if werr != nil {
			fmt.Fprintf(stderr, "write report: %v\n", werr)
			return 1
		}
	}
	if interrupted {
		return 2
	}
	if failed {
		return 1
	}
	return 0
}

// resolve returns origins and whether the scheme was learned by a probe.
func resolve(ctx context.Context, tg target.Target, ports []int, concurrency int, timeout time.Duration) ([]target.Target, bool, error) {
	if tg.Scheme != "" {
		return []target.Target{tg}, false, nil
	}
	if tg.Discover {
		found, err := discover.Discover(ctx, tg.Host, ports, concurrency, timeout)
		for i := range found {
			found[i].Root = tg.Root
		}
		return found, true, err
	}
	scheme, err := discover.Probe(ctx, tg.Host, tg.Port, timeout)
	if err != nil || scheme == "" {
		return nil, true, err
	}
	tg.Scheme = scheme
	tg.Discover = false
	return []target.Target{tg}, true, nil
}

func formatCommand(argv []string) string {
	var b strings.Builder
	for i, a := range argv {
		if i > 0 {
			b.WriteByte(' ')
		}
		if a == "" || strings.ContainsAny(a, " \t\n\"'") {
			b.WriteString(strconv.Quote(a))
			continue
		}
		b.WriteString(a)
	}
	return b.String()
}

func reportFormat(flag, path string) (string, error) {
	switch strings.ToLower(flag) {
	case "", "json", "htm", "html":
	default:
		return "", fmt.Errorf("format must be json or htm")
	}
	kind := strings.ToLower(flag)
	if kind == "html" {
		kind = "htm"
	}
	if kind == "" {
		switch strings.ToLower(filepath.Ext(path)) {
		case ".htm", ".html":
			kind = "htm"
		default:
			kind = "json"
		}
	}
	return kind, nil
}

func resolveFile(name string) (string, error) {
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), name)
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	if st, err := os.Stat(name); err == nil && !st.IsDir() {
		return name, nil
	}
	return "", fmt.Errorf("no %s next to the program or in the current directory", name)
}

func resolveChecks(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "checks")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate, nil
		}
	}
	if st, err := os.Stat("checks"); err == nil && st.IsDir() {
		return "checks", nil
	}
	return "", fmt.Errorf("no checks directory; pass --checks")
}
