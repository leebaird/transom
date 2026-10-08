# Transom

A Go web server scanner. Give it a hostname and it probes a short list of common web ports, keeps each port that speaks HTTP or HTTPS, and checks that origin on its own. A full URL scans only that origin. It fetches paths and reads headers, certificates, cookies, and `robots.txt`. It does not send exploit payloads, try passwords, or upload files. Inspired by Nikto, by Chris Sullo (https://cirt.net/Nikto2).

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

* [![Twitter Follow](https://img.shields.io/twitter/follow/discoverscripts.svg?style=social&label=Follow)](https://twitter.com/discoverscripts) Lee Baird @discoverscripts

----------------------------------------------------------------------------------------------

## Build

```bash
go build -o transom ./cmd/transom && echo "Build successful: ./transom"
```

`go build` prints nothing on its own. The `echo` runs only after the compiler succeeds, so a failed build stops at the compiler error. Go 1.22 or newer. The module has no third-party dependencies.

## Use

```bash
./transom example.com
./transom example.com:8443
./transom https://example.com:8443/app
./transom --ports 80,8080 --timeout 5s -o report.json example.com
./transom -o report.htm example.com
./transom version
```

A bare hostname is probed using the ports in `ports.txt`, one port per line. Edit that file to change the list. Transom reads `ports.txt` next to the program, or in the current directory. It does not run Nmap.

A port is kept only when a TLS handshake completes or a plaintext response starts with an HTTP status line. `--ports` replaces `ports.txt` for that run. `host:port` probes that socket only, and a full URL skips discovery. `--timeout` is the deadline for each request and for each port probe. Discovery, path fetches, and the raw probes honor `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`.

If `--user-agent` is omitted, Transom uses `USER_AGENT` when that value starts with `Mozilla/` and contains no control characters. Otherwise it reads `$DISCOVER/resource/user-agent.txt`, then `~/discover/resource/user-agent.txt`, and falls back to Discover's latest Edge UA. A file line is used only when it starts with `Mozilla/`.

Text findings go to stdout. Target errors go to stderr. `-o` also writes a report, replaced atomically when the run finishes. An interrupt still writes that file. JSON includes `"interrupted": true`. A path ending in `.htm` or `.html` is HTML; anything else is JSON. `--format htm` or `--format json` overrides the extension. The HTML report has a scan summary, one section per host, and one table per finding.

`--checks` is a directory of JSON files. Each file is an array of checks:

```json
{
  "id": "env-file",
  "path": "/.env",
  "method": "GET",
  "statuses": [200],
  "body": "(?m)^[A-Za-z_][A-Za-z0-9_]*=",
  "message": "/.env contains assignment-style lines"
}
```

The starter corpus is `checks/paths.json`. Header, cookie, TLS, and `robots.txt` checks are built in. Set `"raw": true` on a check that matches file magic so the body is fetched with `Accept-Encoding: identity`.

This tool should only be used against targets that you are authorized to scan.
