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
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/leebaird/transom"
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
	if slices.ContainsFunc(args, isVersionArg) {
		fmt.Fprintln(stdout, versionLine(debug.ReadBuildInfo()))
		return 0
	}
	cfg, ok := parseFlags(args, stderr)
	if !ok {
		return 1
	}
	checks, err := loadChecks(cfg.checksDir, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The first signal winds the scan down and writes the report. Handing
	// signals back then lets a second one end the program at once.
	context.AfterFunc(ctx, stop)

	s := &scanner{cfg: cfg, checks: checks, stdout: stdout, stderr: stderr}
	s.doc.Command = formatCommand(append([]string{os.Args[0]}, args...))
	s.doc.Started = time.Now()
	for _, raw := range cfg.targets {
		if ctx.Err() != nil {
			s.interrupted = true
			break
		}
		if !s.scanTarget(ctx, raw) {
			break
		}
	}
	s.doc.Finished = time.Now()
	s.doc.Interrupted = s.interrupted

	if err := writeReport(cfg, s.doc); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if s.interrupted {
		return 2
	}
	if s.failed {
		return 1
	}
	return 0
}

func isVersionArg(a string) bool {
	return a == "version" || a == "--version" || a == "-version"
}

// versionLine is the program name and the module version the Go toolchain
// stamped into the binary: a tag, or a pseudo-version naming the commit. A
// binary with no build information prints the name alone.
func versionLine(info *debug.BuildInfo, ok bool) string {
	if !ok || info.Main.Version == "" {
		return "Transom"
	}
	return "Transom " + info.Main.Version
}

// config is the parsed command line.
type config struct {
	targets     []string
	ports       string
	checksDir   string
	timeout     time.Duration
	concurrency int
	fetch       fetch.Options
	format      string
	output      string
}

// parseFlags reports a bad command line on stderr and returns false.
func parseFlags(args []string, stderr io.Writer) (config, bool) {
	var cfg config
	fs := flag.NewFlagSet("transom", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.ports, "ports", "", "comma-separated discovery ports")
	fs.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "deadline for one request or port probe")
	fs.IntVar(&cfg.concurrency, "concurrency", 8, "in-flight requests")
	fs.StringVar(&cfg.fetch.UserAgent, "user-agent", "", "User-Agent (default Discover's latest Edge UA)")
	fs.StringVar(&cfg.fetch.Follow, "follow", "same-host", "off or same-host")
	fs.Int64Var(&cfg.fetch.MaxBody, "max-body", 1<<20, "maximum response body")
	fs.StringVar(&cfg.checksDir, "checks", "", "JSON check directory")
	fs.StringVar(&cfg.format, "format", "", "json or htm")
	fs.StringVar(&cfg.output, "o", "", "report path")
	var headers headerFlag
	fs.Var(&headers, "header", "repeatable Name: value")
	fs.Usage = func() { fmt.Fprint(stderr, usageText) }
	if err := fs.Parse(args); err != nil {
		return config{}, false
	}
	var problem string
	switch {
	case cfg.fetch.Follow != "off" && cfg.fetch.Follow != "same-host":
		problem = "follow must be off or same-host"
	case cfg.concurrency < 1:
		problem = "concurrency must be at least 1"
	case cfg.timeout <= 0:
		problem = "timeout must be positive"
	case cfg.fetch.MaxBody < 0:
		problem = "max-body must be zero or positive"
	}
	if problem != "" {
		fmt.Fprintln(stderr, problem)
		return config{}, false
	}
	cfg.targets = fs.Args()
	if len(cfg.targets) == 0 {
		fs.Usage()
		return config{}, false
	}
	if cfg.fetch.UserAgent == "" {
		cfg.fetch.UserAgent = discoverUserAgent()
	}
	cfg.fetch.Timeout = cfg.timeout
	cfg.fetch.Concurrency = cfg.concurrency
	cfg.fetch.Headers = headers.h
	return cfg, true
}

// scanner carries one run: the findings so far and how the run has gone.
type scanner struct {
	cfg            config
	checks         []check.Check
	stdout, stderr io.Writer
	// ports is the discovery list, loaded on the first target that needs it.
	ports       []int
	doc         report.Document
	failed      bool
	interrupted bool
}

func (s *scanner) failf(format string, args ...any) {
	fmt.Fprintf(s.stderr, format, args...)
	s.failed = true
}

// scanTarget scans one command-line target. It returns false when the run
// should stop instead of moving on to the next target.
func (s *scanner) scanTarget(ctx context.Context, raw string) bool {
	tg, err := target.Parse(raw)
	if err != nil {
		s.failf("%s: %v\n", raw, err)
		return true
	}
	if tg.Discover {
		if err := s.loadPorts(); err != nil {
			s.failf("%v\n", err)
			return false
		}
	}
	origins, probed, err := resolve(ctx, tg, s.ports, s.cfg.concurrency, s.cfg.timeout)
	if errors.Is(err, context.Canceled) {
		s.interrupted = true
	}
	if len(origins) == 0 {
		switch {
		case s.interrupted:
			return false
		case err != nil:
			s.failf("%s: %v\n", raw, err)
		default:
			s.failf("%s: no HTTP service\n", raw)
		}
		return true
	}
	if probed {
		for _, o := range origins {
			fmt.Fprintf(s.stdout, "%s %s\n", o.HostPort(), o.Scheme)
		}
	}
	for _, o := range origins {
		s.doc.Targets = append(s.doc.Targets, report.Target{Host: o.Host, Port: o.Port, Scheme: o.Scheme, Root: o.Root})
		if s.interrupted || ctx.Err() != nil {
			s.interrupted = true
			return false
		}
		if !s.scanOrigin(ctx, o) {
			return false
		}
	}
	return true
}

// scanOrigin runs every check against one origin and prints its findings.
// It returns false when the run should stop.
func (s *scanner) scanOrigin(ctx context.Context, o target.Target) bool {
	client, err := fetch.New(o, s.cfg.fetch)
	if err != nil {
		s.failf("%s: %v\n", o.HostPort(), err)
		return true
	}
	defer client.Close()
	findings, err := check.Run(ctx, o, client, s.checks, s.cfg.concurrency)
	s.doc.Findings = append(s.doc.Findings, findings...)
	if werr := report.WriteText(s.stdout, findings); werr != nil {
		s.failf("%v\n", werr)
		return false
	}
	if errors.Is(err, context.Canceled) {
		s.interrupted = true
		return false
	}
	if err != nil {
		s.failf("%s: %v\n", o.HostPort(), err)
	}
	return true
}

// loadPorts fills s.ports from --ports, then a ports.txt next to the program
// or in the current directory, then the list built into the binary. One taken
// from the current directory is announced on stderr.
func (s *scanner) loadPorts() error {
	if s.ports != nil {
		return nil
	}
	var err error
	if s.cfg.ports != "" {
		s.ports, err = discover.ParsePorts(s.cfg.ports)
	} else if found := overrides("ports.txt", false); len(found) > 0 {
		if found[0].inCwd {
			fmt.Fprintf(s.stderr, "using ./%s in the current directory, not the built-in ports\n", found[0].path)
		}
		s.ports, err = discover.LoadPorts(found[0].path)
	} else {
		s.ports, err = discover.ParsePortList("built-in ports.txt", transom.Ports)
	}
	return err
}

// writeReport writes the -o file, if one was asked for.
func writeReport(cfg config, doc report.Document) error {
	if cfg.output == "" {
		return nil
	}
	kind, err := reportFormat(cfg.format, cfg.output)
	if err != nil {
		return err
	}
	if kind == "htm" {
		err = report.WriteHTML(cfg.output, doc)
	} else {
		err = report.WriteJSON(cfg.output, doc)
	}
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
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

// override is a file or directory on disk that replaces a built-in default.
type override struct {
	path string
	// inCwd is set for one found in the current directory, where a file
	// with the right name may have nothing to do with Transom.
	inCwd bool
}

// overrides lists what replaces the built-in name, in the order to try them:
// next to the program, then in the current directory. dir asks for
// directories and skips files, or the reverse.
func overrides(name string, dir bool) []override {
	var found []override
	if exe, err := os.Executable(); err == nil {
		found = append(found, override{path: filepath.Join(filepath.Dir(exe), name)})
	}
	found = append(found, override{path: name, inCwd: true})
	return slices.DeleteFunc(found, func(o override) bool {
		st, err := os.Stat(o.path)
		return err != nil || st.IsDir() != dir
	})
}

// loadChecks reads --checks, then a checks directory next to the program or
// in the current directory, then the corpus built into the binary. A
// directory found by name that holds no checks is passed over, and one taken
// from the current directory is announced on stderr.
func loadChecks(flag string, stderr io.Writer) ([]check.Check, error) {
	if flag != "" {
		return check.LoadDir(flag)
	}
	for _, o := range overrides("checks", true) {
		checks, err := check.LoadDir(o.path)
		if err == nil && len(checks) == 0 {
			continue
		}
		if o.inCwd {
			fmt.Fprintf(stderr, "using ./%s in the current directory, not the built-in checks\n", o.path)
		}
		return checks, err
	}
	return check.LoadFS(transom.Checks, transom.ChecksDir)
}
